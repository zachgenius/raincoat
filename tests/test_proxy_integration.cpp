// Real end-to-end integration test for the GUARDED-PROXY runtime wiring (phase 4).
//
// This drives the actual compiled `raincoat` binary with a [network_policy] profile and a
// local HTTP origin on 127.0.0.1. raincoat starts its filtering forward proxy on a host
// loopback port BEFORE the sandbox and injects http_proxy/https_proxy/all_proxy into the
// child pointing at it. The child (a proxy-aware urllib client) then:
//
//   * reaches http://localhost:<origin>/ (ALLOWED by default_action="deny" +
//     allow_hosts=["localhost"]) through the proxy and receives the sentinel body;
//   * gets HTTP 403 for a host NOT on the allow-list (default deny), and for the cloud
//     metadata IP 169.254.169.254 — both short-circuited by the proxy WITHOUT dialing, so
//     the test needs no real external internet and is non-flaky.
//
// A second test composes the STRICT netns jail ([egress].isolate_netns = "strict"). There
// the proxy is the child's ONLY egress: the allowed host is still reachable THROUGH the
// proxy, but a DIRECT (non-proxy) connection from the child to the origin port is blocked —
// proving the allow/block list is a real domain-level egress firewall, not just a
// proxy-aware hint. That test is skipped when pasta is absent.
//
// Guarded by GTEST_SKIP when the raincoat binary, bwrap, or python3 is missing (and,
// additionally, pasta for the strict-jail test).
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
constexpr const char* kSentinel = "RAINCOAT_PROXY_SENTINEL_ORIGIN";

std::string find_pasta_path() {
    for (const char* p : {"/usr/bin/pasta", "/bin/pasta", "/usr/local/bin/pasta",
                          "/usr/sbin/pasta", "/sbin/pasta"}) {
        if (::access(p, X_OK) == 0) return p;
    }
    return {};
}

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

#define SKIP_UNLESS_JAILABLE(binvar)                             \
    std::string binvar;                                         \
    do {                                                        \
        std::string why;                                        \
        if (!have_base_prereqs(binvar, why)) GTEST_SKIP() << why; \
        if (find_pasta_path().empty())                          \
            GTEST_SKIP() << "pasta not found — strict netns jail unavailable";  \
    } while (0)

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
    while ((n = ::read(fds[0], buf, sizeof(buf))) > 0)
        r.output.append(buf, static_cast<size_t>(n));
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

std::string make_temp_dir(const std::string& tag) {
    static std::atomic<unsigned> counter{0};
    fs::path base = fs::temp_directory_path() / "rc-proxy-int";
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

// A minimal loopback HTTP server that returns a fixed sentinel body. Used as the ALLOWED
// origin the child reaches THROUGH raincoat's guarded proxy.
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
            ssize_t w = ::send(fd, resp.data() + off, resp.size() - off, 0);
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

// Extract the value of a "KEY value" line the child printed (KEY includes any trailing ':').
std::string field(const std::string& out, const std::string& key) {
    std::istringstream ss(out);
    std::string line;
    while (std::getline(ss, line)) {
        auto pos = line.find(key);
        if (pos == 0) {
            std::string v = line.substr(key.size());
            while (!v.empty() && (v.front() == ' ' || v.front() == '\t')) v.erase(v.begin());
            while (!v.empty() && (v.back() == '\r' || v.back() == '\n' || v.back() == ' '))
                v.pop_back();
            return v;
        }
    }
    return {};
}

}  // namespace

// ---------------------------------------------------------------------------
// Shared-network model (no jail): the guarded proxy enforces allow/block for the
// proxy-aware child. ALLOWED host succeeds through the proxy; unlisted + metadata
// hosts get 403 (short-circuited, no real network). Audit + stderr disclose honestly.
// ---------------------------------------------------------------------------
TEST(ProxyIntegration, SharedNetEnforcesAllowBlockForProxyAwareChild) {
    SKIP_UNLESS_RUNNABLE(bin);

    LoopbackHttp origin{std::string(kSentinel)};
    ASSERT_TRUE(origin.start()) << "failed to start origin";
    const int oport = origin.port();
    ASSERT_GT(oport, 0);

    std::string profile_dir = make_temp_dir("profile");
    std::string profile_path = (fs::path(profile_dir) / "netpolicy.toml").string();
    {
        std::ofstream p(profile_path);
        // isolate_netns="off" pins the SHARED-loopback model deterministically (this host
        // may have pasta, which would otherwise activate an Auto NAT jail): the point of
        // this test is the honest shared-net disclosure + proxy-aware enforcement.
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

    std::ostringstream py;
    py << "import os, urllib.request, urllib.error, time\n"
       << "print('http_proxy:', os.environ.get('http_proxy',''))\n"
       << "def fetch(url):\n"
       << "    try:\n"
       << "        r = urllib.request.urlopen(url, timeout=3)\n"
       << "        return 'OK:' + r.read().decode()\n"
       << "    except urllib.error.HTTPError as e:\n"
       << "        return 'HTTP_' + str(e.code)\n"
       << "    except Exception as e:\n"
       << "        return 'ERR_' + type(e).__name__\n"
       << "res = 'ERR_none'\n"
       << "for _ in range(80):\n"
       << "    res = fetch('http://localhost:" << oport << "/probe')\n"
       << "    if not res.startswith('ERR_'):\n"
       << "        break\n"
       << "    time.sleep(0.1)\n"
       << "print('ALLOWED:', res)\n"
       << "print('BLOCKED_OTHER:', fetch('http://denied.example.com/'))\n"
       << "print('BLOCKED_METADATA:', fetch('http://169.254.169.254/latest/'))\n";

    RunResult r = run_proc(
        bin, {"--profile", profile_path, "--", kPython, "-c", py.str()}, env, cwd);
    origin.stop();

    ASSERT_TRUE(r.spawn_ok);
    ASSERT_EQ(r.exit_code, 0) << "raincoat/child failed. Output:\n" << r.output;

    // The child was handed a loopback proxy endpoint.
    EXPECT_NE(field(r.output, "http_proxy:").find("http://127.0.0.1:"), std::string::npos)
        << r.output;

    // ALLOWED host reached the origin THROUGH the proxy.
    EXPECT_EQ(field(r.output, "ALLOWED:"), std::string("OK:") + kSentinel) << r.output;

    // A host not on the allow-list (default deny) and the metadata IP both get 403 — proof
    // the proxy is in-path and enforcing, with no real external network required.
    EXPECT_EQ(field(r.output, "BLOCKED_OTHER:"), "HTTP_403") << r.output;
    EXPECT_EQ(field(r.output, "BLOCKED_METADATA:"), "HTTP_403") << r.output;

    // Audit discloses the policy with COUNTS + endpoint (never the host names / a secret).
    std::string audit_path = (fs::path(cwd) / ".raincoat" / "audit.log").string();
    ASSERT_TRUE(fs::exists(audit_path)) << "expected audit at " << audit_path;
    std::string audit = read_file(audit_path);
    EXPECT_NE(audit.find("Network policy: enabled (default deny)"), std::string::npos) << audit;
    EXPECT_NE(audit.find("Guarded proxy: http://127.0.0.1:"), std::string::npos) << audit;
    EXPECT_NE(audit.find("allow hosts: 1"), std::string::npos) << audit;
    EXPECT_NE(audit.find("block hosts: 0"), std::string::npos) << audit;
    EXPECT_NE(audit.find("metadata endpoints blocked: yes"), std::string::npos) << audit;

    // Honest limitation disclosed (shared net): only proxy-aware clients are constrained.
    EXPECT_NE(r.output.find("only proxy-aware clients are constrained"), std::string::npos)
        << r.output;
    EXPECT_NE(audit.find("only proxy-aware clients are constrained"), std::string::npos)
        << audit;

    // The audit must NEVER overclaim a real firewall in shared-net mode (that phrasing is
    // reserved for the strict-jail composition, where a direct egress is actually blocked).
    EXPECT_EQ(audit.find("REAL domain-level egress firewall"), std::string::npos) << audit;
}

// ---------------------------------------------------------------------------
// STRICT netns jail composition: the guarded proxy is the child's ONLY egress. The
// allowed host is still reachable THROUGH the proxy, but a DIRECT (non-proxy) connection
// from the child to the origin port is BLOCKED — so the allow/block list is a real
// domain-level egress firewall. Requires pasta.
// ---------------------------------------------------------------------------
TEST(ProxyIntegration, StrictJailMakesPolicyARealFirewallAndBlocksDirectEgress) {
    SKIP_UNLESS_JAILABLE(bin);

    LoopbackHttp origin{std::string(kSentinel)};
    ASSERT_TRUE(origin.start()) << "failed to start origin";
    const int oport = origin.port();
    ASSERT_GT(oport, 0);

    std::string profile_dir = make_temp_dir("profile");
    std::string profile_path = (fs::path(profile_dir) / "netpolicy-strict.toml").string();
    {
        std::ofstream p(profile_path);
        p << "[network_policy]\n"
          << "enabled = true\n"
          << "default_action = \"deny\"\n"
          << "allow_hosts = [\"localhost\"]\n"
          << "\n"
          << "[egress]\n"
          << "isolate_netns = \"strict\"\n";
    }
    ASSERT_TRUE(fs::exists(profile_path));

    std::string real_home = make_temp_dir("home");
    std::string cwd = make_temp_dir("cwd");
    auto env = base_env(real_home);

    std::ostringstream py;
    py << "import os, socket, urllib.request, urllib.error, time\n"
       << "print('http_proxy:', os.environ.get('http_proxy',''))\n"
       << "def fetch(url):\n"
       << "    try:\n"
       << "        r = urllib.request.urlopen(url, timeout=4)\n"
       << "        return 'OK:' + r.read().decode()\n"
       << "    except urllib.error.HTTPError as e:\n"
       << "        return 'HTTP_' + str(e.code)\n"
       << "    except Exception as e:\n"
       << "        return 'ERR_' + type(e).__name__\n"
       << "res = 'ERR_none'\n"
       << "for _ in range(80):\n"
       << "    res = fetch('http://localhost:" << oport << "/probe')\n"
       << "    if not res.startswith('ERR_'):\n"
       << "        break\n"
       << "    time.sleep(0.1)\n"
       << "print('ALLOWED:', res)\n"
       << "print('BLOCKED_OTHER:', fetch('http://denied.example.com/'))\n"
       // DIRECT (non-proxy) connection to the origin must be blocked by the strict jail:
       // only the proxy port is forwarded into the netns, so this port is unreachable.
       << "try:\n"
       << "    s = socket.create_connection(('127.0.0.1', " << oport << "), timeout=3)\n"
       << "    s.close()\n"
       << "    print('DIRECT:', 'REACHABLE')\n"
       << "except Exception as e:\n"
       << "    print('DIRECT:', 'BLOCKED_' + type(e).__name__)\n";

    RunResult r = run_proc(
        bin, {"--profile", profile_path, "--", kPython, "-c", py.str()}, env, cwd);
    origin.stop();

    ASSERT_TRUE(r.spawn_ok);
    ASSERT_EQ(r.exit_code, 0) << "raincoat/child failed. Output:\n" << r.output;

    // The allowed host is reachable ONLY through the proxy (direct is jailed off), so an
    // OK here proves the request genuinely traversed the guarded proxy.
    EXPECT_EQ(field(r.output, "ALLOWED:"), std::string("OK:") + kSentinel) << r.output;

    // Unlisted host still 403 via the proxy.
    EXPECT_EQ(field(r.output, "BLOCKED_OTHER:"), "HTTP_403") << r.output;

    // The core firewall assertion: a direct, non-proxy connection from the child is blocked.
    const std::string direct = field(r.output, "DIRECT:");
    EXPECT_EQ(direct.rfind("BLOCKED_", 0), 0u)
        << "STRICT jail + network_policy must block a direct (non-proxy) egress from the "
           "child; only the guarded proxy port is forwarded. Output:\n"
        << r.output;

    // Audit + stderr must claim the REAL firewall honestly (only valid because direct is
    // blocked, which the assertion above independently confirmed).
    std::string audit_path = (fs::path(cwd) / ".raincoat" / "audit.log").string();
    ASSERT_TRUE(fs::exists(audit_path)) << "expected audit at " << audit_path;
    std::string audit = read_file(audit_path);
    EXPECT_NE(audit.find("Network policy: enabled (default deny)"), std::string::npos) << audit;
    EXPECT_NE(audit.find("REAL domain-level egress firewall"), std::string::npos) << audit;
    EXPECT_NE(r.output.find("REAL domain-level egress firewall"), std::string::npos) << r.output;
}
