// Raincoat — egress attack round 3 (isolation + leak + forwarding integrity).
//
// This suite pins three properties that the wired-in egress bridge must uphold and
// that earlier rounds did not cover:
//
//   1. CL.CL request-smuggling hygiene. A request with MULTIPLE, DIFFERING
//      Content-Length header fields must NOT be forwarded to the upstream: the bridge
//      frames the body by the first value while the upstream might frame it by a later
//      one, and because the bridge injects credentials + forces Connection: close, a
//      desync would let an untrusted child sneak a second authenticated request past
//      the bridge. The bridge already rejects CL.TE; this closes the sibling CL.CL hole.
//      (Regression: before the fix, build_upstream_head() re-emitted BOTH Content-Length
//      headers verbatim to the upstream and handle_connection() forwarded the request.)
//
//   2. Fail-closed startup. When a bridge's child_endpoint port is already in use,
//      EgressServer::start() must FAIL (so the runner aborts rather than silently run
//      the child with no bridge). Verified at the library level here and end-to-end
//      against the raincoat binary (skip-gated on bwrap).
//
//   3. Clean teardown. After start()+stop(), the child_endpoint port is released and
//      can be re-bound — no leftover listening socket.
//
// Plus an honesty pin: when the bridge is active the audit must DISCLOSE that the
// sandbox shares the host network namespace and the child is not network-jailed, so
// the (documented, inherent) upstream-IP visibility via /proc/net/tcp is never a
// SILENT leak.
#include <gtest/gtest.h>

#include <atomic>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <functional>
#include <map>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include "config.hpp"
#include "egress.hpp"

using namespace raincoat;

namespace {

namespace fs = std::filesystem;

// --- socket helpers ---------------------------------------------------------

void send_all(int fd, const std::string& s) {
    size_t off = 0;
    while (off < s.size()) {
        ssize_t n = ::send(fd, s.data() + off, s.size() - off, MSG_NOSIGNAL);
        if (n <= 0) return;
        off += static_cast<size_t>(n);
    }
}

std::string client_roundtrip(int port, const std::string& request) {
    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return "";
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(static_cast<uint16_t>(port));
    timeval tv{5, 0};
    ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    if (::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        ::close(fd);
        return "";
    }
    send_all(fd, request);
    std::string resp;
    char buf[4096];
    for (;;) {
        ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
        if (n <= 0) break;
        resp.append(buf, static_cast<size_t>(n));
    }
    ::close(fd);
    return resp;
}

// A localhost upstream that COUNTS how many connections it accepts and always answers
// 200. Lets a test prove that a rejected request never reached the upstream.
class CountingUpstream {
public:
    bool start() {
        fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
        if (fd_ < 0) return false;
        int one = 1;
        ::setsockopt(fd_, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = 0;
        if (::bind(fd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) return false;
        if (::listen(fd_, 8) < 0) return false;
        socklen_t sl = sizeof(addr);
        ::getsockname(fd_, reinterpret_cast<sockaddr*>(&addr), &sl);
        port_ = ntohs(addr.sin_port);
        thread_ = std::thread([this] { run(); });
        return true;
    }
    int port() const { return port_; }
    std::string url() const { return "http://127.0.0.1:" + std::to_string(port_); }
    int connections() const { return conns_.load(); }
    void stop() {
        stop_.store(true);
        if (fd_ >= 0) {
            ::shutdown(fd_, SHUT_RDWR);
            ::close(fd_);
            fd_ = -1;
        }
        if (thread_.joinable()) thread_.join();
    }
    ~CountingUpstream() { stop(); }

private:
    void run() {
        while (!stop_.load()) {
            int c = ::accept(fd_, nullptr, nullptr);
            if (c < 0) return;
            conns_.fetch_add(1);
            std::string buf;
            char tmp[2048];
            while (buf.find("\r\n\r\n") == std::string::npos) {
                ssize_t n = ::recv(c, tmp, sizeof(tmp), 0);
                if (n <= 0) break;
                buf.append(tmp, static_cast<size_t>(n));
            }
            send_all(c, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
            ::close(c);
        }
    }
    std::atomic<bool> stop_{false};
    std::atomic<int> conns_{0};
    int fd_ = -1;
    int port_ = 0;
    std::thread thread_;
};

EgressConfig make_cfg(const std::string& upstream_url,
                      const std::string& child_endpoint = "http://127.0.0.1:0",
                      const std::string& name = "primary") {
    EgressConfig cfg;
    cfg.enabled = true;
    cfg.mode = "bridge";
    cfg.timeout_seconds = 5;
    EgressBridge b;
    b.name = name;
    b.env = "SOME_BASE_URL";
    b.child_endpoint = child_endpoint;
    b.upstream_endpoint = upstream_url;
    b.preserve_host = false;
    cfg.bridges.push_back(b);
    return cfg;
}

// Bind an ephemeral loopback listener; return {fd, port}. fd stays OPEN (caller closes).
bool bind_hold(int& fd_out, int& port_out) {
    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return false;
    int one = 1;
    ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = 0;
    if (::bind(fd, reinterpret_cast<sockaddr*>(&a), sizeof(a)) != 0) { ::close(fd); return false; }
    if (::listen(fd, 8) != 0) { ::close(fd); return false; }
    socklen_t l = sizeof(a);
    ::getsockname(fd, reinterpret_cast<sockaddr*>(&a), &l);
    fd_out = fd;
    port_out = ntohs(a.sin_port);
    return true;
}

}  // namespace

// ===========================================================================
// 1. CL.CL request-smuggling hygiene (pure builder)
// ===========================================================================

// Regression for the fix: a request head with two DIFFERING Content-Length headers must
// yield AT MOST ONE Content-Length line in the head sent upstream. Before the fix this
// emitted both ("Content-Length: 5" and "Content-Length: 100"), the classic CL.CL shape.
TEST(EgressAttack3Smuggling, BuildUpstreamHeadCollapsesDuplicateContentLength) {
    HttpRequestHead req;
    req.method = "POST";
    req.target = "/v1/chat";
    req.version = "HTTP/1.1";
    req.headers = {{"Host", "x"}, {"Content-Length", "5"}, {"Content-Length", "100"}};

    Url up;
    std::string e;
    ASSERT_TRUE(parse_url("http://up.example.com/", up, e)) << e;
    EgressBridge b;  // defaults
    std::string head = build_upstream_head(req, b, up);

    // Count Content-Length occurrences (case-insensitive not needed; builder preserves case).
    int count = 0;
    for (size_t p = head.find("Content-Length"); p != std::string::npos;
         p = head.find("Content-Length", p + 1)) {
        ++count;
    }
    EXPECT_EQ(count, 1) << "duplicate Content-Length forwarded upstream (CL.CL smuggling):\n"
                        << head;
    // The FIRST value wins (matches what content_length() frames the relayed body by).
    EXPECT_NE(head.find("Content-Length: 5\r\n"), std::string::npos) << head;
    EXPECT_EQ(head.find("Content-Length: 100"), std::string::npos) << head;
}

// A single Content-Length is untouched (no false positive from the dedupe).
TEST(EgressAttack3Smuggling, BuildUpstreamHeadKeepsSingleContentLength) {
    HttpRequestHead req;
    req.method = "POST";
    req.target = "/";
    req.version = "HTTP/1.1";
    req.headers = {{"Host", "x"}, {"Content-Length", "7"}};
    Url up;
    std::string e;
    ASSERT_TRUE(parse_url("http://up.example.com/", up, e)) << e;
    EgressBridge b;
    std::string head = build_upstream_head(req, b, up);
    EXPECT_NE(head.find("Content-Length: 7\r\n"), std::string::npos) << head;
}

// End-to-end through the live EgressServer: a request with conflicting Content-Length
// values is answered 400 by the bridge and is NEVER forwarded to the upstream.
TEST(EgressAttack3Smuggling, ConflictingContentLengthRejectedNotForwarded) {
    CountingUpstream up;
    ASSERT_TRUE(up.start());

    EgressServer server;
    std::string err;
    ASSERT_TRUE(server.start(make_cfg(up.url()), err)) << err;
    int port = server.port_for("primary");
    ASSERT_GT(port, 0);

    // Two Content-Length headers with DIFFERENT values + a body. Classic CL.CL.
    std::string req =
        "POST /v1/chat HTTP/1.1\r\nHost: 127.0.0.1\r\n"
        "Content-Length: 5\r\nContent-Length: 100\r\n\r\nhello";
    std::string resp = client_roundtrip(port, req);

    server.stop();
    int conns = up.connections();
    up.stop();

    EXPECT_NE(resp.find("400"), std::string::npos)
        << "bridge did not reject conflicting Content-Length; response:\n" << resp;
    EXPECT_EQ(conns, 0)
        << "an ambiguously-framed (CL.CL) request was forwarded to the upstream";
}

// ===========================================================================
// 2. Fail-closed startup: port already in use
// ===========================================================================

TEST(EgressAttack3Teardown, StartFailsWhenChildPortInUse) {
    int held_fd = -1, port = -1;
    ASSERT_TRUE(bind_hold(held_fd, port));

    CountingUpstream up;
    ASSERT_TRUE(up.start());

    EgressServer server;
    std::string err;
    const std::string child_ep = "http://127.0.0.1:" + std::to_string(port);
    bool ok = server.start(make_cfg(up.url(), child_ep), err);

    EXPECT_FALSE(ok) << "start() succeeded despite the child_endpoint port being in use "
                        "(would let the runner proceed unbridged)";
    EXPECT_FALSE(err.empty());
    if (ok) server.stop();  // safety
    ::close(held_fd);
    up.stop();
}

// ===========================================================================
// 3. Clean teardown: the child_endpoint port is released after stop()
// ===========================================================================

TEST(EgressAttack3Teardown, PortReleasedAfterStopRebindable) {
    CountingUpstream up;
    ASSERT_TRUE(up.start());

    EgressServer server;
    std::string err;
    ASSERT_TRUE(server.start(make_cfg(up.url()), err)) << err;
    int port = server.port_for("primary");
    ASSERT_GT(port, 0);
    server.stop();

    // After stop(), the listener must be gone: a fresh bind() on the same port succeeds.
    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    ASSERT_GE(fd, 0);
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = htons(static_cast<uint16_t>(port));
    int rc = ::bind(fd, reinterpret_cast<sockaddr*>(&a), sizeof(a));
    int e = errno;
    ::close(fd);
    up.stop();
    EXPECT_EQ(rc, 0) << "child_endpoint port " << port
                     << " still bound after stop() (leftover listener): " << std::strerror(e);
}

// port_for() reports nothing once the server is stopped (listeners cleared).
TEST(EgressAttack3Teardown, PortForUnknownAfterStop) {
    CountingUpstream up;
    ASSERT_TRUE(up.start());
    EgressServer server;
    std::string err;
    ASSERT_TRUE(server.start(make_cfg(up.url()), err)) << err;
    ASSERT_GT(server.port_for("primary"), 0);
    server.stop();
    up.stop();
    EXPECT_EQ(server.port_for("primary"), -1);
}

// ===========================================================================
// 4. End-to-end against the raincoat binary (skip-gated on bwrap)
// ===========================================================================

namespace {

std::string raincoat_bin() {
    const char* e = std::getenv("RAINCOAT_BIN");
    if (e && *e) return std::string(e);
    return "/home/zach/Develop/Raincoat/build/raincoat";
}

struct RunResult {
    int exit_code = -1;
    bool spawn_ok = false;
    std::string output;
};

RunResult run_proc(const std::string& bin, const std::vector<std::string>& args,
                   const std::map<std::string, std::string>& env, const std::string& cwd) {
    RunResult r;
    int fds[2];
    if (::pipe(fds) != 0) return r;
    pid_t pid = ::fork();
    if (pid < 0) { ::close(fds[0]); ::close(fds[1]); return r; }
    if (pid == 0) {
        if (::chdir(cwd.c_str()) != 0) _exit(126);
        ::dup2(fds[1], STDOUT_FILENO);
        ::dup2(fds[1], STDERR_FILENO);
        ::close(fds[0]);
        ::close(fds[1]);
        std::vector<std::string> as;
        as.push_back(bin);
        for (const auto& a : args) as.push_back(a);
        std::vector<char*> argv;
        for (auto& s : as) argv.push_back(const_cast<char*>(s.c_str()));
        argv.push_back(nullptr);
        std::vector<std::string> es;
        for (const auto& kv : env) es.push_back(kv.first + "=" + kv.second);
        std::vector<char*> envp;
        for (auto& s : es) envp.push_back(const_cast<char*>(s.c_str()));
        envp.push_back(nullptr);
        ::execve(bin.c_str(), argv.data(), envp.data());
        _exit(127);
    }
    r.spawn_ok = true;
    ::close(fds[1]);
    char buf[4096];
    ssize_t n;
    while ((n = ::read(fds[0], buf, sizeof(buf))) > 0) r.output.append(buf, static_cast<size_t>(n));
    ::close(fds[0]);
    int status = 0;
    while (::waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
    if (WIFEXITED(status)) r.exit_code = WEXITSTATUS(status);
    else if (WIFSIGNALED(status)) r.exit_code = 128 + WTERMSIG(status);
    return r;
}

std::string mk_tmp(const std::string& tag) {
    static std::atomic<unsigned> c{0};
    fs::path d = fs::temp_directory_path() / "rc-egress-a3" /
                 (tag + "-" + std::to_string(::getpid()) + "-" + std::to_string(c.fetch_add(1)));
    fs::create_directories(d);
    return d.string();
}

bool have_bin_and_bwrap(std::string& bin, std::string& why) {
    bin = raincoat_bin();
    if (::access(bin.c_str(), X_OK) != 0) { why = "raincoat binary missing: " + bin; return false; }
    if (::access("/usr/bin/bwrap", X_OK) != 0) { why = "bwrap missing"; return false; }
    return true;
}

}  // namespace

// Port-in-use must make the RUN abort (exit != 0) and the child must NOT run — raincoat
// must never silently proceed unbridged.
TEST(EgressAttack3E2E, PortInUseAbortsRunNotSilentlyUnbridged) {
    std::string bin, why;
    if (!have_bin_and_bwrap(bin, why)) GTEST_SKIP() << why;

    int held_fd = -1, port = -1;
    ASSERT_TRUE(bind_hold(held_fd, port));
    const std::string child_ep = "http://127.0.0.1:" + std::to_string(port);

    std::string profile_dir = mk_tmp("profile");
    std::string profile_path = (fs::path(profile_dir) / "egress.toml").string();
    {
        std::ofstream p(profile_path);
        p << "[egress]\nmode = \"bridge\"\nisolate_netns = \"off\"\n\n"
          << "[[egress.bridge]]\nname = \"api\"\nenv = \"BASE_URL\"\n"
          << "child_endpoint = \"" << child_ep << "\"\n"
          << "upstream_endpoint = \"http://127.0.0.1:1\"\n";
    }

    std::string cwd = mk_tmp("cwd");
    std::string home = mk_tmp("home");
    std::map<std::string, std::string> env = {
        {"PATH", "/usr/bin:/bin"}, {"TERM", "xterm"}, {"HOME", home}};

    // The child would print this sentinel if it ever ran; it must NOT appear.
    RunResult r = run_proc(
        bin, {"--profile", profile_path, "--", "/bin/echo", "CHILD_RAN_SENTINEL_XYZ"}, env, cwd);
    ::close(held_fd);

    ASSERT_TRUE(r.spawn_ok);
    EXPECT_NE(r.exit_code, 0)
        << "raincoat did not abort when the bridge port was in use. Output:\n" << r.output;
    EXPECT_EQ(r.output.find("CHILD_RAN_SENTINEL_XYZ"), std::string::npos)
        << "child ran even though the bridge failed to bind (silently unbridged!). Output:\n"
        << r.output;
    EXPECT_NE(r.output.find("could not start egress bridge"), std::string::npos) << r.output;
}

// Honesty pin: an active bridge run must DISCLOSE (in the audit) that the sandbox shares
// the host network namespace and the child is not network-jailed. This is the documented
// mitigation for the inherent /proc/net/tcp upstream-IP visibility — it must never be a
// silent leak.
TEST(EgressAttack3E2E, ActiveBridgeAuditDisclosesSharedNetNamespace) {
    std::string bin, why;
    if (!have_bin_and_bwrap(bin, why)) GTEST_SKIP() << why;

    int cfd = -1, cport = -1;
    ASSERT_TRUE(bind_hold(cfd, cport));
    ::close(cfd);  // free it for raincoat (tiny TOCTOU, localhost-only)
    const std::string child_ep = "http://127.0.0.1:" + std::to_string(cport);

    std::string profile_dir = mk_tmp("profile");
    std::string profile_path = (fs::path(profile_dir) / "egress.toml").string();
    {
        std::ofstream p(profile_path);
        p << "[egress]\nmode = \"bridge\"\nisolate_netns = \"off\"\n\n"
          << "[[egress.bridge]]\nname = \"api\"\nenv = \"BASE_URL\"\n"
          << "child_endpoint = \"" << child_ep << "\"\n"
          << "upstream_endpoint = \"http://127.0.0.1:1\"\n";
    }
    std::string cwd = mk_tmp("cwd");
    std::string home = mk_tmp("home");
    std::map<std::string, std::string> env = {
        {"PATH", "/usr/bin:/bin"}, {"TERM", "xterm"}, {"HOME", home}};

    RunResult r = run_proc(bin, {"--profile", profile_path, "--", "/bin/true"}, env, cwd);
    ASSERT_TRUE(r.spawn_ok);

    std::string audit_path = (fs::path(cwd) / ".raincoat" / "audit.log").string();
    ASSERT_TRUE(fs::exists(audit_path)) << "no audit at " << audit_path << "; output:\n" << r.output;
    std::ifstream ifs(audit_path, std::ios::binary);
    std::ostringstream ss;
    ss << ifs.rdbuf();
    std::string audit = ss.str();

    EXPECT_NE(audit.find("SHARES the host network namespace"), std::string::npos)
        << "audit did not disclose the shared-net-namespace model:\n" << audit;
    EXPECT_NE(audit.find("NOT network-jailed"), std::string::npos) << audit;
    // The strengthened disclosure must also name the inherent /proc/net/tcp IP:port leak,
    // so the "hides the upstream URL" claim is never mistaken for hiding the IP:port.
    EXPECT_NE(audit.find("/proc/net/tcp"), std::string::npos)
        << "audit did not disclose the shared-net /proc/net/tcp IP:port visibility:\n" << audit;
}

// Finding 3 regression: the per-bridge [[egress.bridge]].hide_upstream knob must be LIVE,
// not inert. With the GLOBAL redact_upstreams_in_audit disabled and a non-child-readable
// audit (the default masked .raincoat/ location), a bridge with hide_upstream=true must
// still record "Upstream endpoint: hidden" while a sibling bridge with hide_upstream=false
// exposes its real upstream. Before the fix the runner used a single global redact flag for
// every bridge, so hide_upstream was silently ignored and BOTH upstreams would have been
// exposed (the hidden-* upstream string would leak into the audit).
TEST(EgressAttack3E2E, PerBridgeHideUpstreamHonoredInAudit) {
    std::string bin, why;
    if (!have_bin_and_bwrap(bin, why)) GTEST_SKIP() << why;

    // Two free child_endpoint ports for the two bridges.
    int fd1 = -1, p1 = -1, fd2 = -1, p2 = -1;
    ASSERT_TRUE(bind_hold(fd1, p1));
    ASSERT_TRUE(bind_hold(fd2, p2));
    ::close(fd1);
    ::close(fd2);
    ASSERT_NE(p1, p2);
    const std::string child_ep1 = "http://127.0.0.1:" + std::to_string(p1);
    const std::string child_ep2 = "http://127.0.0.1:" + std::to_string(p2);

    // Distinctive, never-contacted upstream URLs (child is /bin/true, so no connection is
    // ever made; these only need to parse). Unique host labels make the assertions exact.
    const std::string hidden_upstream = "http://hidden-upstream.invalid:9443";
    const std::string shown_upstream  = "http://shown-upstream.invalid:8443";

    std::string profile_dir = mk_tmp("profile");
    std::string profile_path = (fs::path(profile_dir) / "egress.toml").string();
    {
        std::ofstream p(profile_path);
        p << "[egress]\nmode = \"bridge\"\nisolate_netns = \"off\"\n"
          << "redact_upstreams_in_audit = false\n\n"  // global redaction OFF
          << "[[egress.bridge]]\nname = \"hidden-api\"\nenv = \"HID_URL\"\n"
          << "child_endpoint = \"" << child_ep1 << "\"\n"
          << "upstream_endpoint = \"" << hidden_upstream << "\"\n"
          << "hide_upstream = true\n\n"                 // per-bridge override: keep hidden
          << "[[egress.bridge]]\nname = \"shown-api\"\nenv = \"SHOWN_URL\"\n"
          << "child_endpoint = \"" << child_ep2 << "\"\n"
          << "upstream_endpoint = \"" << shown_upstream << "\"\n"
          << "hide_upstream = false\n";                 // per-bridge: expose this one
    }
    std::string cwd = mk_tmp("cwd");
    std::string home = mk_tmp("home");
    std::map<std::string, std::string> env = {
        {"PATH", "/usr/bin:/bin"}, {"TERM", "xterm"}, {"HOME", home}};

    RunResult r = run_proc(bin, {"--profile", profile_path, "--", "/bin/true"}, env, cwd);
    ASSERT_TRUE(r.spawn_ok);

    std::string audit_path = (fs::path(cwd) / ".raincoat" / "audit.log").string();
    ASSERT_TRUE(fs::exists(audit_path)) << "no audit at " << audit_path << "; output:\n" << r.output;
    std::ifstream ifs(audit_path, std::ios::binary);
    std::ostringstream ss;
    ss << ifs.rdbuf();
    std::string audit = ss.str();

    // hide_upstream=true bridge: upstream must be redacted despite global redact=false.
    EXPECT_EQ(audit.find("hidden-upstream.invalid"), std::string::npos)
        << "per-bridge hide_upstream=true was ignored; hidden upstream leaked into audit:\n"
        << audit;
    EXPECT_NE(audit.find("Upstream endpoint: hidden"), std::string::npos)
        << "expected the hidden-api bridge to record 'Upstream endpoint: hidden':\n" << audit;
    // hide_upstream=false bridge with global redact off: its real upstream IS recorded.
    EXPECT_NE(audit.find("shown-upstream.invalid"), std::string::npos)
        << "expected the shown-api bridge (hide_upstream=false, global redact off) to record "
           "its real upstream:\n"
        << audit;
}
