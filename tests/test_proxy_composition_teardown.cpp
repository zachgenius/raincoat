// Raincoat — guarded-proxy composition/teardown END-TO-END gap coverage (attack round 2).
//
// The existing binary-level integration test (test_proxy_integration.cpp) exercises only the
// plain-HTTP GET path and never asserts what happens to the guarded proxy AFTER raincoat exits.
// Two real gaps are closed here by driving the compiled `raincoat` binary:
//
//   1. TEARDOWN / no orphan port. The runner starts the filtering forward proxy on a host
//      loopback ephemeral port for the lifetime of the run and must tear it down when the run
//      ends (ProxyServer::stop via the stack object's destructor). If teardown regressed, the
//      listener would leak: the ephemeral port would stay bound after the process exits. We
//      read the actual proxy port out of the audit log and then PROVE the port is free by
//      bind()ing it ourselves (a live LISTEN socket makes bind() fail EADDRINUSE; a freed port
//      binds cleanly). This is the observable, deterministic signal for "no orphan listener".
//
//   2. CONNECT (HTTPS tunnel) policy enforcement THROUGH THE REAL BINARY. The integration test
//      never drives the CONNECT path end-to-end, so nothing proves the runner wires a
//      CONNECT-capable proxy and injects an https_proxy the child can use. A proxy-aware child
//      issues a raw CONNECT (no TLS needed — we assert on the proxy's CONNECT reply line):
//        * CONNECT to the ALLOWED host establishes ("200 Connection Established");
//        * CONNECT to the cloud-metadata IP 169.254.169.254 is refused ("403 Forbidden") and
//          NO tunnel is established — the metadata guard holds on the CONNECT path too.
//      Localhost-only and deterministic; needs no real external internet.
//
// Guarded by GTEST_SKIP when the raincoat binary, bwrap, or python3 is missing.
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

std::string raincoat_bin() {
    const char* e = std::getenv("RAINCOAT_BIN");
    if (e && *e) return std::string(e);
    return "/home/zach/Develop/Raincoat/build/raincoat";
}

constexpr const char* kBwrapPath = "/usr/bin/bwrap";
constexpr const char* kPython = "/usr/bin/python3";
constexpr const char* kSentinel = "RAINCOAT_COMPOSITION_TEARDOWN_SENTINEL";

bool have_base_prereqs(std::string& bin, std::string& why) {
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

#define SKIP_UNLESS_RUNNABLE(binvar)                              \
    std::string binvar;                                          \
    do {                                                        \
        std::string why;                                        \
        if (!have_base_prereqs(binvar, why)) GTEST_SKIP() << why; \
    } while (0)

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
    while ((n = ::read(fds[0], buf, sizeof(buf))) > 0)
        r.output.append(buf, static_cast<size_t>(n));
    ::close(fds[0]);
    int status = 0;
    while (::waitpid(pid, &status, 0) < 0) {
        if (errno != EINTR) break;
    }
    if (WIFEXITED(status)) r.exit_code = WEXITSTATUS(status);
    else if (WIFSIGNALED(status)) r.exit_code = 128 + WTERMSIG(status);
    return r;
}

std::string make_temp_dir(const std::string& tag) {
    static std::atomic<unsigned> counter{0};
    fs::path base = fs::temp_directory_path() / "rc-proxy-composition";
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
    return {{"PATH", "/usr/bin:/bin"}, {"TERM", "xterm"}, {"HOME", real_home}};
}

// Extract the value of a "KEY value" line the child printed.
std::string field(const std::string& out, const std::string& key) {
    std::istringstream ss(out);
    std::string line;
    while (std::getline(ss, line)) {
        if (line.find(key) == 0) {
            std::string v = line.substr(key.size());
            while (!v.empty() && (v.front() == ' ' || v.front() == '\t')) v.erase(v.begin());
            while (!v.empty() && (v.back() == '\r' || v.back() == '\n' || v.back() == ' '))
                v.pop_back();
            return v;
        }
    }
    return {};
}

// Pull the guarded proxy port out of the audit line "Guarded proxy: http://127.0.0.1:<port>".
int proxy_port_from_audit(const std::string& audit) {
    const std::string key = "Guarded proxy: http://127.0.0.1:";
    size_t p = audit.rfind(key);
    if (p == std::string::npos) return -1;
    p += key.size();
    int port = 0;
    bool any = false;
    while (p < audit.size() && audit[p] >= '0' && audit[p] <= '9') {
        port = port * 10 + (audit[p] - '0');
        ++p;
        any = true;
    }
    return any ? port : -1;
}

// A minimal loopback TCP origin: an HTTP GET gets the sentinel body; for the CONNECT tunnel it
// simply accepts the connection (enough for the proxy to reply "200 Connection Established").
class LoopbackHttp {
public:
    explicit LoopbackHttp(std::string body) : body_(std::move(body)) {}
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
    ~LoopbackHttp() { stop(); }
    int port() const { return port_; }

private:
    void loop() {
        while (!stop_.load()) {
            pollfd pfd{};
            pfd.fd = listen_fd_;
            pfd.events = POLLIN;
            if (::poll(&pfd, 1, 200) <= 0) continue;
            int c = ::accept(listen_fd_, nullptr, nullptr);
            if (c < 0) continue;
            serve_one(c);
            ::close(c);
        }
    }
    void serve_one(int fd) {
        std::string req;
        char buf[2048];
        for (int i = 0; i < 64; ++i) {
            if (req.find("\r\n\r\n") != std::string::npos) break;
            ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
            if (n <= 0) break;
            req.append(buf, static_cast<size_t>(n));
        }
        std::string resp = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n";
        resp += "Content-Length: " + std::to_string(body_.size()) + "\r\n";
        resp += "Connection: close\r\n\r\n" + body_;
        std::size_t off = 0;
        while (off < resp.size()) {
            ssize_t w = ::send(fd, resp.data() + off, resp.size() - off, MSG_NOSIGNAL);
            if (w <= 0) break;
            off += static_cast<size_t>(w);
        }
    }
    std::string body_;
    int listen_fd_ = -1;
    int port_ = -1;
    std::atomic<bool> stop_{false};
    std::thread thread_;
};

// Try to bind 127.0.0.1:<port> WITHOUT SO_REUSEADDR. Succeeds (returns true) only when no live
// LISTEN socket holds the port — the observable proof the guarded proxy's listener was torn
// down. A leaked/orphaned listener makes bind() fail EADDRINUSE.
bool loopback_port_is_free(int port) {
    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return false;
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = htons(static_cast<uint16_t>(port));
    bool ok = ::bind(fd, reinterpret_cast<sockaddr*>(&a), sizeof(a)) == 0;
    ::close(fd);
    return ok;
}

}  // namespace

// ---------------------------------------------------------------------------
// TEARDOWN: after raincoat exits, the guarded proxy loopback port is FREE (no orphan
// listener). Read the actual port from the audit, then prove it binds cleanly.
// ---------------------------------------------------------------------------
TEST(ProxyCompositionTeardown, ProxyPortIsFreedAfterRunExits) {
    SKIP_UNLESS_RUNNABLE(bin);

    std::string profile_dir = make_temp_dir("profile");
    std::string profile_path = (fs::path(profile_dir) / "netpolicy.toml").string();
    {
        std::ofstream p(profile_path);
        p << "[network_policy]\n"
          << "enabled = true\n"
          << "default_action = \"deny\"\n"
          << "allow_hosts = [\"localhost\"]\n"
          << "\n"
          << "[egress]\n"
          << "isolate_netns = \"off\"\n";
    }
    ASSERT_TRUE(fs::exists(profile_path));

    std::string real_home = make_temp_dir("home");
    std::string cwd = make_temp_dir("cwd");
    auto env = base_env(real_home);

    // Trivial child: the run just needs to start (and tear down) the proxy.
    RunResult r =
        run_proc(bin, {"--profile", profile_path, "--", kPython, "-c", "print('done')"}, env, cwd);
    ASSERT_TRUE(r.spawn_ok);
    ASSERT_EQ(r.exit_code, 0) << "raincoat/child failed. Output:\n" << r.output;

    std::string audit_path = (fs::path(cwd) / ".raincoat" / "audit.log").string();
    ASSERT_TRUE(fs::exists(audit_path)) << "expected audit at " << audit_path;
    const int port = proxy_port_from_audit(read_file(audit_path));
    ASSERT_GT(port, 0) << "could not find the guarded proxy port in the audit";

    // raincoat has already exited (waitpid returned). The ephemeral listener must be gone: a
    // clean bind() on the same port proves no orphaned proxy listener survived the run.
    EXPECT_TRUE(loopback_port_is_free(port))
        << "guarded proxy port " << port
        << " is STILL bound after raincoat exited — the proxy listener was orphaned (teardown "
           "leak). ProxyServer::stop() must close the listener and join every worker.";
}

// ---------------------------------------------------------------------------
// CONNECT path enforced end-to-end THROUGH THE BINARY: allowed host tunnels (200);
// the cloud-metadata IP is refused (403) with no tunnel. Exercises the injected
// https_proxy + the runner's CONNECT-capable proxy wiring, not just ProxyServer directly.
// ---------------------------------------------------------------------------
TEST(ProxyCompositionTeardown, ConnectPathEnforcedThroughBinary) {
    SKIP_UNLESS_RUNNABLE(bin);

    LoopbackHttp origin{std::string(kSentinel)};
    ASSERT_TRUE(origin.start()) << "failed to start origin";
    const int oport = origin.port();
    ASSERT_GT(oport, 0);

    std::string profile_dir = make_temp_dir("profile");
    std::string profile_path = (fs::path(profile_dir) / "netpolicy.toml").string();
    {
        std::ofstream p(profile_path);
        // default deny + allow only localhost; metadata blocking defaults ON. Shared net so
        // the child can reach the loopback proxy deterministically.
        p << "[network_policy]\n"
          << "enabled = true\n"
          << "default_action = \"deny\"\n"
          << "allow_hosts = [\"localhost\"]\n"
          << "\n"
          << "[egress]\n"
          << "isolate_netns = \"off\"\n";
    }
    ASSERT_TRUE(fs::exists(profile_path));

    std::string real_home = make_temp_dir("home");
    std::string cwd = make_temp_dir("cwd");
    auto env = base_env(real_home);

    // The child reads its injected proxy endpoint, then issues raw CONNECTs and reports the
    // proxy's reply status line. No TLS is needed: we assert on the CONNECT handshake result.
    std::ostringstream py;
    py << "import os, socket\n"
       << "pu = os.environ.get('https_proxy') or os.environ.get('http_proxy') or ''\n"
       << "print('proxy:', pu)\n"
       << "hostport = pu.split('://',1)[-1]\n"
       << "phost, pport = hostport.split(':')\n"
       << "def do_connect(target):\n"
       << "    try:\n"
       << "        s = socket.create_connection((phost, int(pport)), timeout=4)\n"
       << "        s.settimeout(4)\n"
       << "        s.sendall(('CONNECT ' + target + ' HTTP/1.1\\r\\nHost: ' + target +\n"
       << "                   '\\r\\n\\r\\n').encode())\n"
       << "        data = b''\n"
       << "        while b'\\r\\n\\r\\n' not in data:\n"
       << "            chunk = s.recv(1024)\n"
       << "            if not chunk: break\n"
       << "            data += chunk\n"
       << "        s.close()\n"
       << "        line = data.split(b'\\r\\n',1)[0].decode('latin1')\n"
       << "        if '200' in line: return 'ESTABLISHED'\n"
       << "        if '403' in line: return 'FORBIDDEN'\n"
       << "        return 'OTHER:' + line\n"
       << "    except Exception as e:\n"
       << "        return 'ERR_' + type(e).__name__\n"
       << "print('ALLOWED_CONNECT:', do_connect('localhost:" << oport << "'))\n"
       << "print('METADATA_CONNECT:', do_connect('169.254.169.254:443'))\n";

    RunResult r =
        run_proc(bin, {"--profile", profile_path, "--", kPython, "-c", py.str()}, env, cwd);
    origin.stop();

    ASSERT_TRUE(r.spawn_ok);
    ASSERT_EQ(r.exit_code, 0) << "raincoat/child failed. Output:\n" << r.output;

    // The child was handed an https_proxy/http_proxy pointing at the guarded loopback proxy.
    EXPECT_NE(field(r.output, "proxy:").find("http://127.0.0.1:"), std::string::npos) << r.output;

    // ALLOWED host: the CONNECT handshake completes through the guarded proxy.
    EXPECT_EQ(field(r.output, "ALLOWED_CONNECT:"), "ESTABLISHED")
        << "CONNECT to the allow-listed host must establish a tunnel through the guarded "
           "proxy. Output:\n"
        << r.output;

    // METADATA IP: the CONNECT is refused with 403 and NO tunnel is established — the SSRF /
    // metadata guard holds on the CONNECT path when driven through the real binary.
    EXPECT_EQ(field(r.output, "METADATA_CONNECT:"), "FORBIDDEN")
        << "CONNECT to the cloud-metadata IP must be 403'd (no tunnel) through the guarded "
           "proxy. Output:\n"
        << r.output;
}
