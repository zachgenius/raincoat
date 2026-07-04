// Raincoat — network-policy (phase 4) REGRESSION + HONESTY attack tests (round 1).
//
// These drive the real compiled `raincoat` binary and assert two families of contract:
//
//  A. NO REGRESSION when [network_policy] is DISABLED (the default). Phase 4 added a guarded
//     forward proxy + http_proxy/https_proxy/all_proxy injection, but ALL of that must be gated
//     behind network_policy.enabled. A plain MVP run (no profile) must therefore inject NO proxy
//     env vars and its audit must carry NO "Network policy: enabled" line — i.e. the default path
//     is byte-for-byte the pre-phase-4 behavior. A regression that unconditionally started the
//     proxy / injected http_proxy would flip these.
//
//  B. HONESTY: without the STRICT netns jail the guarded proxy is NOT a hard firewall — it only
//     constrains proxy-aware clients. The existing integration test asserts the DISCLOSURE TEXT;
//     these tests additionally give that claim TEETH by DEMONSTRATING the bypass:
//       * SharedNetRawClientBypassesPolicy — in isolate_netns="off" (shared host loopback) a child
//         that IGNORES http_proxy and opens a RAW socket reaches an origin directly, even under
//         default_action="deny". Direct egress is NOT blocked (the exact inverse of the strict-jail
//         test), and the audit must NOT overclaim a "REAL domain-level egress firewall".
//       * DefaultAutoJailDiscloseProxyAwareOnly — with pasta present and isolate_netns UNSET (the
//         default "auto"), the child runs in a NAT jail that still routes general outbound, so the
//         policy is STILL proxy-aware-only. The audit must say so and must NOT claim a real firewall.
//         This covers the default-jail case the existing tests skip (they pin "off" or "strict").
//
// Localhost-only and non-flaky: no test depends on real external internet. Guarded by GTEST_SKIP
// when raincoat/bwrap/python3 (and, for the auto-jail test, pasta) are missing.
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
constexpr const char* kSentinel = "RAINCOAT_NP_REGRESSION_SENTINEL";

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
    fs::path base = fs::temp_directory_path() / "rc-np-regress";
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

// A minimal loopback HTTP server returning a fixed sentinel body. Used both as the ALLOWED
// origin (reached through the proxy) and as the DIRECT-egress target for the raw-socket bypass.
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
    std::istringstream iss(out);
    std::string line;
    while (std::getline(iss, line)) {
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

// ===========================================================================
// A. REGRESSION — network_policy DISABLED (default) leaves the MVP env untouched.
// ===========================================================================
//
// A plain run with NO profile must NOT start the guarded proxy and must NOT inject
// http_proxy/https_proxy/all_proxy. A regression that unconditionally wired phase 4 would
// leak a "http://127.0.0.1:<port>" proxy into the child and stamp the audit with a network
// policy line. This test fails loudly in that case.
TEST(NetworkPolicyRegression, DisabledByDefaultInjectsNoProxyEnvAndNoAuditLine) {
    SKIP_UNLESS_RUNNABLE(bin);

    std::string real_home = make_temp_dir("home");
    std::string cwd = make_temp_dir("cwd");
    auto env = base_env(real_home);

    // The child echoes whatever proxy env it received. On the MVP default path these are
    // unset, so the child inherits none (base_env sets none either).
    std::ostringstream py;
    py << "import os\n"
       << "print('http_proxy:', os.environ.get('http_proxy',''))\n"
       << "print('https_proxy:', os.environ.get('https_proxy',''))\n"
       << "print('all_proxy:', os.environ.get('all_proxy',''))\n"
       << "print('CHILD_OK:', 'yes')\n";

    // No --profile at all: pure MVP invocation.
    RunResult r = run_proc(bin, {"--", kPython, "-c", py.str()}, env, cwd);
    ASSERT_TRUE(r.spawn_ok);
    ASSERT_EQ(r.exit_code, 0) << "raincoat/child failed. Output:\n" << r.output;

    // Child ran (MVP still works) and received NO injected proxy env.
    EXPECT_EQ(field(r.output, "CHILD_OK:"), "yes") << r.output;
    EXPECT_EQ(field(r.output, "http_proxy:"), "") << r.output;
    EXPECT_EQ(field(r.output, "https_proxy:"), "") << r.output;
    EXPECT_EQ(field(r.output, "all_proxy:"), "") << r.output;

    // A guarded proxy endpoint must never appear anywhere in output when policy is disabled.
    EXPECT_EQ(r.output.find("Guarded proxy:"), std::string::npos) << r.output;
    EXPECT_EQ(r.output.find("network policy"), std::string::npos) << r.output;

    // Audit exists (MVP always audits) but carries NO network-policy line.
    std::string audit_path = (fs::path(cwd) / ".raincoat" / "audit.log").string();
    ASSERT_TRUE(fs::exists(audit_path)) << "expected audit at " << audit_path;
    std::string audit = read_file(audit_path);
    EXPECT_EQ(audit.find("Network policy: enabled"), std::string::npos) << audit;
    EXPECT_EQ(audit.find("Guarded proxy:"), std::string::npos) << audit;
    EXPECT_EQ(audit.find("REAL domain-level egress firewall"), std::string::npos) << audit;
}

// ===========================================================================
// B1. HONESTY (teeth) — shared net: a RAW, non-proxy-aware client bypasses the policy.
// ===========================================================================
//
// isolate_netns="off" shares the host loopback, so a child that opens a RAW socket (never
// consulting http_proxy) reaches an origin DIRECTLY even under default_action="deny". This is
// the concrete proof that the guarded proxy is NOT a hard firewall here — the exact inverse of
// the strict-jail test where a direct connection is blocked. The audit must disclose the
// proxy-aware-only limitation and must NOT overclaim a real domain-level egress firewall.
TEST(NetworkPolicyHonesty, SharedNetRawClientBypassesPolicy) {
    SKIP_UNLESS_RUNNABLE(bin);

    LoopbackHttp origin{std::string(kSentinel)};
    ASSERT_TRUE(origin.start()) << "failed to start origin";
    const int oport = origin.port();
    ASSERT_GT(oport, 0);

    std::string profile_dir = make_temp_dir("profile");
    std::string profile_path = (fs::path(profile_dir) / "np-shared.toml").string();
    {
        std::ofstream p(profile_path);
        // default_action="deny" with only "localhost" allowed: a raw connection to 127.0.0.1
        // is NOT proxied at all, so it is neither allow-listed nor blocked — it just goes
        // straight out on the shared loopback. isolate_netns="off" pins the shared model even
        // though this host has pasta.
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
    py << "import os, socket, urllib.request, urllib.error\n"
       << "print('http_proxy:', os.environ.get('http_proxy',''))\n"
       << "# RAW direct connection — deliberately ignores http_proxy.\n"
       << "def raw_get(host, port):\n"
       << "    try:\n"
       << "        s = socket.create_connection((host, port), timeout=3)\n"
       << "        s.sendall(b'GET /raw HTTP/1.0\\r\\nHost: x\\r\\n\\r\\n')\n"
       << "        data = b''\n"
       << "        while True:\n"
       << "            chunk = s.recv(4096)\n"
       << "            if not chunk: break\n"
       << "            data += chunk\n"
       << "        s.close()\n"
       << "        return data.decode('latin1')\n"
       << "    except Exception as e:\n"
       << "        return 'ERR_' + type(e).__name__\n"
       << "raw = raw_get('127.0.0.1', " << oport << ")\n"
       << "print('RAW_DIRECT:', 'OK' if '" << kSentinel << "' in raw else raw)\n"
       << "# Proxy-aware path to a denied host is still blocked (proxy is in-path).\n"
       << "def proxied(url):\n"
       << "    try:\n"
       << "        r = urllib.request.urlopen(url, timeout=3); return 'OK'\n"
       << "    except urllib.error.HTTPError as e: return 'HTTP_' + str(e.code)\n"
       << "    except Exception as e: return 'ERR_' + type(e).__name__\n"
       << "print('PROXIED_DENIED:', proxied('http://denied.example.com/'))\n";

    RunResult r = run_proc(
        bin, {"--profile", profile_path, "--", kPython, "-c", py.str()}, env, cwd);
    origin.stop();

    ASSERT_TRUE(r.spawn_ok);
    ASSERT_EQ(r.exit_code, 0) << "raincoat/child failed. Output:\n" << r.output;

    // The child WAS handed a guarded proxy (policy is active for proxy-aware clients)...
    EXPECT_NE(field(r.output, "http_proxy:").find("http://127.0.0.1:"), std::string::npos)
        << r.output;
    // ...yet a RAW socket reached the origin DIRECTLY, bypassing the policy entirely. This is
    // the honest, disclosed limitation made concrete: direct egress is NOT blocked in shared net.
    EXPECT_EQ(field(r.output, "RAW_DIRECT:"), "OK")
        << "raw direct egress should succeed in shared-net mode (no hard firewall)\n"
        << r.output;
    // The proxy still enforces for a client that DOES honor it.
    EXPECT_EQ(field(r.output, "PROXIED_DENIED:"), "HTTP_403") << r.output;

    // Audit must disclose the proxy-aware-only limitation and must NOT overclaim a firewall.
    std::string audit_path = (fs::path(cwd) / ".raincoat" / "audit.log").string();
    ASSERT_TRUE(fs::exists(audit_path)) << "expected audit at " << audit_path;
    std::string audit = read_file(audit_path);
    EXPECT_NE(audit.find("only proxy-aware clients are constrained"), std::string::npos)
        << audit;
    EXPECT_EQ(audit.find("REAL domain-level egress firewall"), std::string::npos) << audit;
    EXPECT_NE(r.output.find("only proxy-aware clients are constrained"), std::string::npos)
        << r.output;
}

// ===========================================================================
// B2. HONESTY — default "auto" NAT jail (pasta present) is STILL proxy-aware-only.
// ===========================================================================
//
// With isolate_netns UNSET (default "auto") and pasta available, network_policy runs the child
// inside a pasta NAT jail that still routes general outbound traffic. That is a jail, but NOT a
// per-destination firewall: a raw-IP / proxy-ignoring client still reaches the internet. The
// audit + stderr must say "only proxy-aware clients are constrained" and must NOT claim a real
// egress firewall (that phrasing is reserved for isolate_netns="strict"). This is the default
// case the existing integration tests skip (they pin "off" or "strict"). Skipped without pasta.
TEST(NetworkPolicyHonesty, DefaultAutoJailDiscloseProxyAwareOnlyNotFirewall) {
    SKIP_UNLESS_RUNNABLE(bin);
    if (find_pasta_path().empty())
        GTEST_SKIP() << "pasta not found — default auto NAT jail unavailable";

    std::string profile_dir = make_temp_dir("profile");
    std::string profile_path = (fs::path(profile_dir) / "np-auto.toml").string();
    {
        std::ofstream p(profile_path);
        // NOTE: no [egress].isolate_netns key => default "auto". With pasta present this is a
        // NAT jail (jail_active but NOT strict).
        p << "[network_policy]\n"
          << "enabled = true\n"
          << "default_action = \"allow\"\n"
          << "block_hosts = [\"denied.example.com\"]\n";
    }
    ASSERT_TRUE(fs::exists(profile_path));

    std::string real_home = make_temp_dir("home");
    std::string cwd = make_temp_dir("cwd");
    auto env = base_env(real_home);

    // Trivial child: we only care about the runner's honesty disclosure, not child egress.
    RunResult r = run_proc(
        bin, {"--profile", profile_path, "--", kPython, "-c", "print('CHILD_OK: yes')"}, env,
        cwd);

    ASSERT_TRUE(r.spawn_ok);
    // The run may legitimately fail to enter the jail on a constrained CI kernel; only assert
    // honesty when the child actually ran. (A non-zero exit here is an environment issue, not a
    // policy overclaim, so skip rather than fail.)
    if (r.exit_code != 0) {
        GTEST_SKIP() << "auto NAT jail did not run on this host (env), output:\n" << r.output;
    }
    EXPECT_EQ(field(r.output, "CHILD_OK:"), "yes") << r.output;

    std::string audit_path = (fs::path(cwd) / ".raincoat" / "audit.log").string();
    ASSERT_TRUE(fs::exists(audit_path)) << "expected audit at " << audit_path;
    std::string audit = read_file(audit_path);

    EXPECT_NE(audit.find("Network policy: enabled (default allow)"), std::string::npos) << audit;
    // The NAT jail must be disclosed as proxy-aware-only, NOT a real firewall.
    EXPECT_NE(audit.find("only constrains proxy-aware clients"), std::string::npos) << audit;
    EXPECT_EQ(audit.find("REAL domain-level egress firewall"), std::string::npos) << audit;
    EXPECT_NE(r.output.find("only constrains proxy-aware clients"), std::string::npos)
        << r.output;
}
