// Real end-to-end integration test for the WIRED egress bridge.
//
// Unlike test_egress.cpp (which unit-tests the pure helpers and the EgressServer
// in isolation), this drives the *actual* compiled `raincoat` binary end-to-end:
//
//   local HTTP upstream (std::thread on 127.0.0.1)
//        ^ private forward
//   raincoat egress bridge  (loopback listener, started by the binary)
//        ^ injected MY_BASE_URL
//   sandboxed child (/usr/bin/python3) --- urllib GET --> bridge --> upstream
//
// It proves the four contract guarantees the wiring must uphold:
//   1. The bridge forwards: the child receives the upstream's sentinel body
//      (and the upstream sees the child's method + path preserved).
//   2. The child is handed ONLY the generic child_endpoint via MY_BASE_URL.
//   3. The real upstream URL/host:port never appears in the child's environment.
//   4. The audit records "Egress bridge enabled" + "Upstream endpoint: hidden"
//      and never leaks the upstream host:port.
//
// Guarded by GTEST_SKIP when /usr/bin/bwrap or the raincoat binary is missing.
// Localhost-only and non-flaky: the child retries the connect with backoff, and
// the upstream server runs on a kernel-assigned ephemeral port held open for the
// duration of the test (no bind race for the upstream).
#include <gtest/gtest.h>

#include <atomic>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <map>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

namespace {

namespace fs = std::filesystem;

// ---------------------------------------------------------------------------
// Prerequisite detection + binary location (mirrors test_integration.cpp)
// ---------------------------------------------------------------------------

std::string raincoat_bin() {
    const char* e = std::getenv("RAINCOAT_BIN");
    if (e && *e) return std::string(e);
    return "/home/zach/Develop/Raincoat/build/raincoat";
}

constexpr const char* kBwrapPath = "/usr/bin/bwrap";
constexpr const char* kPython = "/usr/bin/python3";

bool have_prereqs(std::string& bin, std::string& why) {
    bin = raincoat_bin();
    if (::access(bin.c_str(), X_OK) != 0) {
        why = "raincoat binary not found/executable at " + bin;
        return false;
    }
    if (::access(kBwrapPath, X_OK) != 0) {
        why = std::string("bwrap not found/executable at ") + kBwrapPath;
        return false;
    }
    if (::access(kPython, X_OK) != 0) {
        why = std::string("python3 not found/executable at ") + kPython;
        return false;
    }
    return true;
}

#define SKIP_UNLESS_SANDBOXABLE(binvar)                       \
    std::string binvar;                                       \
    do {                                                      \
        std::string why;                                      \
        if (!have_prereqs(binvar, why)) GTEST_SKIP() << why;  \
    } while (0)

// ---------------------------------------------------------------------------
// Process runner: fork/exec with a controlled env + cwd, capture combined output
// ---------------------------------------------------------------------------

struct RunResult {
    int exit_code = -1;
    bool signaled = false;
    bool spawn_ok = false;
    std::string output;
};

RunResult run_proc(const std::string& bin, const std::vector<std::string>& args,
                   const std::map<std::string, std::string>& env,
                   const std::string& cwd) {
    RunResult r;

    int fds[2];
    if (::pipe(fds) != 0) return r;

    pid_t pid = ::fork();
    if (pid < 0) {
        ::close(fds[0]);
        ::close(fds[1]);
        return r;
    }

    if (pid == 0) {
        if (::chdir(cwd.c_str()) != 0) _exit(126);
        ::dup2(fds[1], STDOUT_FILENO);
        ::dup2(fds[1], STDERR_FILENO);
        ::close(fds[0]);
        ::close(fds[1]);

        std::vector<std::string> argv_str;
        argv_str.reserve(args.size() + 1);
        argv_str.push_back(bin);
        for (const auto& a : args) argv_str.push_back(a);
        std::vector<char*> argv;
        argv.reserve(argv_str.size() + 1);
        for (auto& s : argv_str) argv.push_back(const_cast<char*>(s.c_str()));
        argv.push_back(nullptr);

        std::vector<std::string> env_str;
        env_str.reserve(env.size());
        for (const auto& kv : env) env_str.push_back(kv.first + "=" + kv.second);
        std::vector<char*> envp;
        envp.reserve(env_str.size() + 1);
        for (auto& s : env_str) envp.push_back(const_cast<char*>(s.c_str()));
        envp.push_back(nullptr);

        ::execve(bin.c_str(), argv.data(), envp.data());
        _exit(127);
    }

    r.spawn_ok = true;
    ::close(fds[1]);
    char buf[4096];
    ssize_t n;
    while ((n = ::read(fds[0], buf, sizeof(buf))) > 0) {
        r.output.append(buf, static_cast<size_t>(n));
    }
    ::close(fds[0]);

    int status = 0;
    while (::waitpid(pid, &status, 0) < 0) {
        if (errno != EINTR) break;
    }
    if (WIFEXITED(status)) {
        r.exit_code = WEXITSTATUS(status);
    } else if (WIFSIGNALED(status)) {
        r.signaled = true;
        r.exit_code = 128 + WTERMSIG(status);
    }
    return r;
}

// ---------------------------------------------------------------------------
// Temp-dir + file helpers
// ---------------------------------------------------------------------------

std::string make_temp_dir(const std::string& tag) {
    static std::atomic<unsigned> counter{0};
    fs::path base = fs::temp_directory_path() / "rc-egress-e2e";
    fs::create_directories(base);
    fs::path dir = base / (tag + "-" + std::to_string(::getpid()) + "-" +
                           std::to_string(counter.fetch_add(1)));
    fs::create_directories(dir);
    return dir.string();
}

std::string read_file(const std::string& path) {
    std::ifstream ifs(path, std::ios::binary);
    if (!ifs) return {};
    std::ostringstream ss;
    ss << ifs.rdbuf();
    return ss.str();
}

std::map<std::string, std::string> base_env(const std::string& real_home) {
    return {
        {"PATH", "/usr/bin:/bin"},
        {"TERM", "xterm"},
        {"HOME", real_home},
    };
}

// Pick a free loopback TCP port by binding to :0, reading the assignment, and
// closing. There is a tiny TOCTOU window before raincoat rebinds it; acceptable
// for a localhost-only test.
int pick_free_port() {
    int s = ::socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) return -1;
    int one = 1;
    ::setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = 0;
    if (::bind(s, reinterpret_cast<sockaddr*>(&a), sizeof(a)) != 0) {
        ::close(s);
        return -1;
    }
    socklen_t len = sizeof(a);
    if (::getsockname(s, reinterpret_cast<sockaddr*>(&a), &len) != 0) {
        ::close(s);
        return -1;
    }
    int port = ntohs(a.sin_port);
    ::close(s);
    return port;
}

// ---------------------------------------------------------------------------
// Minimal local HTTP upstream: returns a known sentinel body and echoes the
// request method + path so the test can prove the bridge preserved them.
// ---------------------------------------------------------------------------

constexpr const char* kSentinel = "RAINCOAT_EGRESS_SENTINEL_7Z9Q";

class UpstreamServer {
public:
    // Bind an ephemeral loopback port and listen. Returns false on failure.
    bool start() {
        listen_fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
        if (listen_fd_ < 0) return false;
        int one = 1;
        ::setsockopt(listen_fd_, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        sockaddr_in a{};
        a.sin_family = AF_INET;
        a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        a.sin_port = 0;
        if (::bind(listen_fd_, reinterpret_cast<sockaddr*>(&a), sizeof(a)) != 0) return false;
        socklen_t len = sizeof(a);
        if (::getsockname(listen_fd_, reinterpret_cast<sockaddr*>(&a), &len) != 0) return false;
        port_ = ntohs(a.sin_port);
        if (::listen(listen_fd_, 16) != 0) return false;
        thread_ = std::thread([this] { loop(); });
        return true;
    }

    void stop() {
        stop_.store(true);
        if (thread_.joinable()) thread_.join();
        if (listen_fd_ >= 0) {
            ::close(listen_fd_);
            listen_fd_ = -1;
        }
    }

    int port() const { return port_; }

private:
    void loop() {
        while (!stop_.load()) {
            pollfd pfd{};
            pfd.fd = listen_fd_;
            pfd.events = POLLIN;
            int pr = ::poll(&pfd, 1, 200);
            if (pr <= 0) continue;
            int c = ::accept(listen_fd_, nullptr, nullptr);
            if (c < 0) continue;
            serve_one(c);
            ::close(c);
        }
    }

    void serve_one(int fd) {
        // Read the request head (up to CRLFCRLF). A GET has no body.
        std::string req;
        char buf[2048];
        for (int i = 0; i < 64; ++i) {
            if (req.find("\r\n\r\n") != std::string::npos) break;
            ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
            if (n <= 0) break;
            req.append(buf, static_cast<size_t>(n));
        }
        std::string method = "?", path = "?";
        {
            std::size_t sp1 = req.find(' ');
            if (sp1 != std::string::npos) {
                method = req.substr(0, sp1);
                std::size_t sp2 = req.find(' ', sp1 + 1);
                if (sp2 != std::string::npos)
                    path = req.substr(sp1 + 1, sp2 - (sp1 + 1));
            }
        }
        std::string body = std::string(kSentinel) + "\n" + "method=" + method +
                           "\n" + "path=" + path + "\n";
        std::string resp = "HTTP/1.1 200 OK\r\n";
        resp += "Content-Type: text/plain\r\n";
        resp += "Content-Length: " + std::to_string(body.size()) + "\r\n";
        resp += "Connection: close\r\n\r\n";
        resp += body;
        std::size_t off = 0;
        while (off < resp.size()) {
            ssize_t w = ::send(fd, resp.data() + off, resp.size() - off, 0);
            if (w <= 0) break;
            off += static_cast<size_t>(w);
        }
    }

    int listen_fd_ = -1;
    int port_ = -1;
    std::atomic<bool> stop_{false};
    std::thread thread_;
};

}  // namespace

// ---------------------------------------------------------------------------
// The end-to-end test
// ---------------------------------------------------------------------------

TEST(EgressE2E, BridgeForwardsToUpstreamAndHidesItFromChild) {
    SKIP_UNLESS_SANDBOXABLE(bin);

    // 1) Local upstream on an ephemeral loopback port.
    UpstreamServer upstream;
    ASSERT_TRUE(upstream.start()) << "failed to start local upstream server";
    const int uport = upstream.port();
    ASSERT_GT(uport, 0);
    const std::string upstream_url =
        "http://127.0.0.1:" + std::to_string(uport);
    const std::string upstream_hostport = "127.0.0.1:" + std::to_string(uport);

    // A free port for raincoat's bridge to bind (the child-visible endpoint).
    const int cport = pick_free_port();
    ASSERT_GT(cport, 0);
    ASSERT_NE(cport, uport);
    const std::string child_url = "http://127.0.0.1:" + std::to_string(cport);

    // 2) Temp profile written OUTSIDE the mounted cwd (its own temp dir) so it
    //    carries the upstream_endpoint value the leak guard must keep from the child.
    std::string profile_dir = make_temp_dir("profile");
    std::string profile_path = (fs::path(profile_dir) / "egress.toml").string();
    {
        std::ofstream p(profile_path);
        p << "[egress]\n"
          << "mode = \"bridge\"\n"
          << "hide_upstreams_from_child = true\n"
          << "redact_upstreams_in_audit = true\n"
          << "\n"
          << "[[egress.bridge]]\n"
          << "name = \"local-api\"\n"
          << "env = \"MY_BASE_URL\"\n"
          << "child_endpoint = \"" << child_url << "\"\n"
          << "upstream_endpoint = \"" << upstream_url << "\"\n"
          << "preserve_host = false\n";
    }
    ASSERT_TRUE(fs::exists(profile_path));

    std::string real_home = make_temp_dir("realhome");
    std::string cwd = make_temp_dir("cwd");
    auto env = base_env(real_home);

    // 3) The sandboxed child: read MY_BASE_URL, GET it (retry/backoff to avoid a
    //    startup race), print the body, and a full env dump for independent
    //    verification. The child is DELIBERATELY never told the upstream string
    //    (that would end up in argv, which raincoat audits). Instead it self-reports
    //    whether ANY http(s) URL other than its own child_endpoint is present in
    //    os.environ — the upstream is a different URL, so a leak would show up as
    //    OTHER_URLS_IN_ENV=yes without the test having to name the upstream.
    const char* pyscript =
        "import os, sys, time, urllib.request\n"
        "base = os.environ['MY_BASE_URL']\n"
        "body = None\n"
        "for _ in range(50):\n"
        "    try:\n"
        "        with urllib.request.urlopen(base + '/probe/path', timeout=2) as r:\n"
        "            body = r.read().decode()\n"
        "        break\n"
        "    except Exception:\n"
        "        time.sleep(0.1)\n"
        "if body is None:\n"
        "    print('FETCH_FAILED')\n"
        "    sys.exit(3)\n"
        "print('MY_BASE_URL=' + base)\n"
        "print('BODY_BEGIN')\n"
        "sys.stdout.write(body)\n"
        "print('BODY_END')\n"
        "others = [v for v in os.environ.values()\n"
        "          if ('http://' in v or 'https://' in v) and v != base]\n"
        "print('OTHER_URLS_IN_ENV=' + ('yes' if others else 'no'))\n"
        "for k, v in sorted(os.environ.items()):\n"
        "    print('ENV::%s=%s' % (k, v))\n";

    RunResult r = run_proc(
        bin, {"--profile", profile_path, "--", kPython, "-c", pyscript}, env, cwd);

    upstream.stop();

    ASSERT_TRUE(r.spawn_ok);
    ASSERT_EQ(r.exit_code, 0) << "raincoat/child failed. Combined output:\n" << r.output;

    // --- Assertion 1: the bridge forwarded; child got the upstream sentinel body.
    EXPECT_NE(r.output.find(kSentinel), std::string::npos)
        << "child did not receive the upstream sentinel body; bridge did not "
           "forward. Output:\n"
        << r.output;
    // Method + path were preserved end-to-end through the bridge.
    EXPECT_NE(r.output.find("method=GET"), std::string::npos) << r.output;
    EXPECT_NE(r.output.find("path=/probe/path"), std::string::npos) << r.output;

    // --- Assertion 2: MY_BASE_URL is exactly the child-visible endpoint.
    EXPECT_NE(r.output.find("MY_BASE_URL=" + child_url), std::string::npos)
        << "MY_BASE_URL was not the injected child_endpoint. Output:\n"
        << r.output;

    // --- Assertion 3: the real upstream URL / host:port is absent from the child env.
    // Child self-report: its ONLY env URL is its own child_endpoint (no upstream URL).
    EXPECT_NE(r.output.find("OTHER_URLS_IN_ENV=no"), std::string::npos)
        << "child found an http(s) URL other than its child_endpoint in os.environ "
           "(the upstream leaked). Output:\n"
        << r.output;
    // Independent check on the full env dump the child printed (lines "ENV::...").
    {
        std::istringstream ss(r.output);
        std::string line;
        while (std::getline(ss, line)) {
            if (line.rfind("ENV::", 0) != 0) continue;
            EXPECT_EQ(line.find(upstream_url), std::string::npos)
                << "upstream URL leaked into child env: " << line;
            EXPECT_EQ(line.find(upstream_hostport), std::string::npos)
                << "upstream host:port leaked into child env: " << line;
        }
    }

    // --- Assertion 4: the audit log is honest and leak-free.
    std::string audit_path = (fs::path(cwd) / ".raincoat" / "audit.log").string();
    ASSERT_TRUE(fs::exists(audit_path)) << "expected audit log at " << audit_path;
    std::string audit = read_file(audit_path);

    EXPECT_NE(audit.find("Egress bridge enabled"), std::string::npos) << audit;
    EXPECT_NE(audit.find("Upstream endpoint: hidden"), std::string::npos) << audit;
    // The audit records the child-visible endpoint but never the real upstream.
    EXPECT_NE(audit.find(child_url), std::string::npos) << audit;
    EXPECT_EQ(audit.find(upstream_url), std::string::npos)
        << "audit leaked the upstream URL:\n" << audit;
    EXPECT_EQ(audit.find(upstream_hostport), std::string::npos)
        << "audit leaked the upstream host:port:\n" << audit;
}

// ---------------------------------------------------------------------------
// Attack round 1 (isolation+leak): a hardlink alias of the --profile file that
// lives inside the auto-mounted cwd must NOT leak the real upstream to the child.
//
// The profile-leak guard shadows the profile by PATH (a bind mount over its
// canonical name). A second hardlink to the same inode under a different name in
// a mounted path is a distinct directory entry the path-based mask does NOT cover,
// so — before the fix — the child could read the real upstream_endpoint straight
// out of the alias even though the canonical profile name reads empty.
//
// The security property this test pins: the real upstream host must never be
// visible to the child via ANY name in the mounted cwd. (raincoat satisfies this
// by failing closed — refusing to run a reachable multi-hardlink profile — so the
// child never starts; a mask-every-alias fix would instead run with both names
// emptied. Either way the token must be absent from the child's view.)
TEST(EgressE2E, HardlinkedProfileAliasDoesNotLeakUpstreamToChild) {
    SKIP_UNLESS_SANDBOXABLE(bin);

    // A distinctive, non-routable upstream host token. No network is needed: the
    // leak is about READING the profile file, not forwarding a request.
    const std::string kUpstreamToken = "SECRET-UPSTREAM-HOST-Q7X9.invalid";
    const std::string upstream_url = "http://" + kUpstreamToken + ":9443";

    const int cport = pick_free_port();
    ASSERT_GT(cport, 0);
    const std::string child_url = "http://127.0.0.1:" + std::to_string(cport);

    // Profile written INSIDE the auto-mounted cwd (so the leak-guard engages), plus
    // a second hardlink to the very same inode under an innocuous name.
    std::string cwd = make_temp_dir("hlcwd");
    std::string profile_path = (fs::path(cwd) / "egress.toml").string();
    {
        std::ofstream p(profile_path);
        p << "[egress]\n"
          << "mode = \"bridge\"\n"
          << "hide_upstreams_from_child = true\n"
          << "\n"
          << "[[egress.bridge]]\n"
          << "name = \"local-api\"\n"
          << "env = \"MY_BASE_URL\"\n"
          << "child_endpoint = \"" << child_url << "\"\n"
          << "upstream_endpoint = \"" << upstream_url << "\"\n";
    }
    ASSERT_TRUE(fs::exists(profile_path));
    std::string alias_path = (fs::path(cwd) / "innocent-notes.txt").string();
    ASSERT_EQ(::link(profile_path.c_str(), alias_path.c_str()), 0)
        << "failed to create hardlink alias for the test";

    std::string real_home = make_temp_dir("hlhome");
    auto env = base_env(real_home);

    // Child dumps every regular file in its cwd; a leak surfaces as the upstream
    // token appearing via either the masked profile name or the hardlink alias.
    const char* py =
        "import os\n"
        "for name in sorted(os.listdir('.')):\n"
        "    try:\n"
        "        with open(name) as f: data = f.read()\n"
        "        print('FILE::%s::%s' % (name, data))\n"
        "    except Exception as e:\n"
        "        print('FILE::%s::ERR::%r' % (name, e))\n";

    RunResult r = run_proc(
        bin, {"--profile", profile_path, "--", kPython, "-c", py}, env, cwd);
    ASSERT_TRUE(r.spawn_ok);

    // The real upstream host must be absent from everything the child could see.
    EXPECT_EQ(r.output.find(kUpstreamToken), std::string::npos)
        << "upstream endpoint leaked to the child through a hardlink alias of the "
           "masked --profile file. Combined output:\n"
        << r.output;
}

// ---------------------------------------------------------------------------
// Attack round 1 (audit leak under double opt-out): redact_upstreams_in_audit=false
// AND a custom --audit-log redirected into the child-writable cwd. The audit "start"
// block is written before the fork, so an un-redacted upstream there would be readable
// by the child straight out of the on-disk audit file. raincoat must FORCE upstream
// redaction for a child-reachable audit regardless of the opt-out, and disclose that it
// did so — never leak silently.
//
// No forwarding is exercised (the upstream token is a non-routable sentinel); the leak
// under test is READING the on-disk audit, not a request.
TEST(EgressE2E, ChildReachableAuditForcesUpstreamRedactionDespiteOptOut) {
    SKIP_UNLESS_SANDBOXABLE(bin);

    const std::string kUpstreamToken = "SECRET-UPSTREAM-AUDIT-K3P8.invalid";
    const std::string upstream_url = "http://" + kUpstreamToken + ":9443";

    const int cport = pick_free_port();
    ASSERT_GT(cport, 0);
    const std::string child_url = "http://127.0.0.1:" + std::to_string(cport);

    // Profile OUTSIDE the mounted cwd (so the profile-leak guard does not itself refuse
    // the run) but with redaction of the audit EXPLICITLY disabled.
    std::string profile_dir = make_temp_dir("auditprofile");
    std::string profile_path = (fs::path(profile_dir) / "egress.toml").string();
    {
        std::ofstream p(profile_path);
        p << "[egress]\n"
          << "mode = \"bridge\"\n"
          << "hide_upstreams_from_child = true\n"
          << "redact_upstreams_in_audit = false\n"
          << "\n"
          << "[[egress.bridge]]\n"
          << "name = \"local-api\"\n"
          << "env = \"MY_BASE_URL\"\n"
          << "child_endpoint = \"" << child_url << "\"\n"
          << "upstream_endpoint = \"" << upstream_url << "\"\n";
    }
    ASSERT_TRUE(fs::exists(profile_path));

    std::string real_home = make_temp_dir("audithome");
    std::string cwd = make_temp_dir("auditcwd");
    auto env = base_env(real_home);

    // --audit-log points DIRECTLY into the auto-mounted (writable) cwd, not .raincoat,
    // so the audit dir is child-reachable and NOT masked.
    std::string audit_path = (fs::path(cwd) / "audit.log").string();

    RunResult r = run_proc(
        bin,
        {"--profile", profile_path, "--audit-log", audit_path, "--",
         kPython, "-c", "print('child-ran')"},
        env, cwd);
    ASSERT_TRUE(r.spawn_ok);

    // The child ran; the audit exists at the custom location.
    ASSERT_TRUE(fs::exists(audit_path)) << "expected audit log at " << audit_path
                                        << "\nOutput:\n" << r.output;
    std::string audit = read_file(audit_path);

    // The on-disk audit must NOT carry the real upstream despite the opt-out: redaction
    // was forced because the child can read this file.
    EXPECT_EQ(audit.find(kUpstreamToken), std::string::npos)
        << "child-reachable audit leaked the real upstream despite the forced-redaction "
           "guard. Audit:\n"
        << audit;
    EXPECT_NE(audit.find("Upstream endpoint: hidden"), std::string::npos)
        << "expected forced 'Upstream endpoint: hidden' in a child-reachable audit. "
           "Audit:\n"
        << audit;

    // raincoat must DISCLOSE that it forced redaction rather than leak silently.
    EXPECT_NE(r.output.find("upstream redaction is being FORCED"), std::string::npos)
        << "expected a stderr disclosure that upstream redaction was forced. Output:\n"
        << r.output;
}
