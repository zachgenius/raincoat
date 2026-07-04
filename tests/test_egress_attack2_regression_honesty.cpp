// Attack round 2 — egress wiring: REGRESSION + HONESTY, end-to-end.
//
// Round 1 (test_egress_regression_honesty_attack.cpp) pinned resolve_config's
// decisions. This round drives the ACTUAL compiled `raincoat` binary through bwrap
// and observes real runtime behavior + the on-disk audit, attacking four claims the
// egress wiring must keep true:
//
//   (A) HONESTY: an ACTIVE egress bridge audit + stderr must state that the sandbox
//       SHARES the host network namespace and the child is NOT network-jailed, and
//       must NOT overclaim ("only reach the bridge", "network is jailed", ...).
//
//   (B) HONESTY, behaviorally proven: in bridge mode the child really CAN reach a
//       loopback service that is NOT one of its bridges — proving the "not a network
//       jail / general host network remains reachable" disclosure is truthful and not
//       an overclaim in the other direction.
//
//   (C) REGRESSION: a flat `--net off` run (no profile, no egress) must STILL unshare
//       the network — the child cannot reach a host loopback service, and the audit
//       still headlines "Network: off".
//
//   (D) REGRESSION / fail-closed: a profile with [egress] mode="bridge" but ZERO
//       bridges must fail closed to net-off end-to-end (child network blocked, audit
//       "Network: off" + honest "fails closed" note, NO "Egress bridge enabled"), NOT
//       silently share the host net.
//
//   (E) REGRESSION: a flat run still scrubs a secret env var — its VALUE never reaches
//       the child and never appears in the audit; the audit lists the NAME as scrubbed.
//
// Guarded by GTEST_SKIP when bwrap / raincoat / python3 are missing.
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

std::string make_temp_dir(const std::string& tag) {
    static std::atomic<unsigned> counter{0};
    fs::path base = fs::temp_directory_path() / "rc-egress-attack2";
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

// A minimal loopback HTTP server returning a fixed sentinel body. Used both as a
// bridge upstream and as a NON-bridge "elsewhere on the host" service.
class LoopbackServer {
public:
    explicit LoopbackServer(std::string sentinel) : sentinel_(std::move(sentinel)) {}

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
        std::string req;
        char buf[2048];
        for (int i = 0; i < 64; ++i) {
            if (req.find("\r\n\r\n") != std::string::npos) break;
            ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
            if (n <= 0) break;
            req.append(buf, static_cast<size_t>(n));
        }
        std::string body = sentinel_ + "\n";
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

    std::string sentinel_;
    int listen_fd_ = -1;
    int port_ = -1;
    std::atomic<bool> stop_{false};
    std::thread thread_;
};

// A python one-liner that connects to 127.0.0.1:<port>, sends a GET, and prints
// either CONNECT_OK + the reply or CONNECT_FAIL::<err>. The port is embedded at
// build time (it is a plain test service, never a hidden upstream).
std::string connect_probe(int port) {
    std::ostringstream s;
    s << "import socket,sys\n"
      << "s=socket.socket(); s.settimeout(3)\n"
      << "try:\n"
      << "    s.connect(('127.0.0.1'," << port << "))\n"
      << "    s.sendall(b'GET /x HTTP/1.0\\r\\n\\r\\n')\n"
      << "    d=s.recv(1024).decode('latin1')\n"
      << "    print('CONNECT_OK'); print(d)\n"
      << "except Exception as e:\n"
      << "    print('CONNECT_FAIL::%r' % e)\n";
    return s.str();
}

std::string audit_at(const std::string& cwd) {
    return read_file((fs::path(cwd) / ".raincoat" / "audit.log").string());
}

}  // namespace

// ===========================================================================
// (A) HONESTY: active bridge audit + stderr disclose shared host net, no overclaim
// ===========================================================================
TEST(EgressAttack2Honesty, ActiveBridgeAuditAndStderrDiscloseSharedNetNoOverclaim) {
    SKIP_UNLESS_SANDBOXABLE(bin);

    LoopbackServer upstream("UPSTREAM_A_SENTINEL");
    ASSERT_TRUE(upstream.start());
    const std::string upstream_url = "http://127.0.0.1:" + std::to_string(upstream.port());
    const int cport = pick_free_port();
    ASSERT_GT(cport, 0);
    const std::string child_url = "http://127.0.0.1:" + std::to_string(cport);

    std::string profile_dir = make_temp_dir("profile");
    std::string profile_path = (fs::path(profile_dir) / "egress.toml").string();
    {
        std::ofstream p(profile_path);
        p << "[egress]\nmode = \"bridge\"\nisolate_netns = \"off\"\n\n"
          << "[[egress.bridge]]\n"
          << "name = \"api\"\n"
          << "env = \"MY_BASE_URL\"\n"
          << "child_endpoint = \"" << child_url << "\"\n"
          << "upstream_endpoint = \"" << upstream_url << "\"\n";
    }
    std::string real_home = make_temp_dir("home");
    std::string cwd = make_temp_dir("cwd");
    auto env = base_env(real_home);

    RunResult r = run_proc(
        bin, {"--profile", profile_path, "--", kPython, "-c", "print('ran')"}, env, cwd);
    upstream.stop();
    ASSERT_TRUE(r.spawn_ok);
    ASSERT_EQ(r.exit_code, 0) << r.output;

    std::string audit = audit_at(cwd);
    ASSERT_FALSE(audit.empty());

    // Honest disclosure present in the audit.
    EXPECT_NE(audit.find("SHARES the host network namespace"), std::string::npos) << audit;
    EXPECT_NE(audit.find("NOT network-jailed"), std::string::npos) << audit;
    // Honest disclosure present on stderr (a user who never reads the audit).
    EXPECT_NE(r.output.find("SHARES the host network namespace"), std::string::npos)
        << r.output;
    EXPECT_NE(r.output.find("NOT network-jailed"), std::string::npos) << r.output;

    // Network headline is honestly "full" (shared host net; no --unshare-net).
    EXPECT_NE(audit.find("Network:      full"), std::string::npos) << audit;

    // NO dishonest OVERCLAIM in either the audit or stderr.
    for (const std::string& lie : {std::string("only reach the bridge"),
                                   std::string("can only reach"),
                                   std::string("cannot reach the network"),
                                   std::string("network is jailed"),
                                   std::string("blocks all other network")}) {
        EXPECT_EQ(audit.find(lie), std::string::npos)
            << "audit overclaims network jailing: '" << lie << "'\n" << audit;
        EXPECT_EQ(r.output.find(lie), std::string::npos)
            << "stderr overclaims network jailing: '" << lie << "'\n" << r.output;
    }
}

// ===========================================================================
// (B) HONESTY, behaviorally proven: bridge mode is NOT a network jail — the child
//     can reach a loopback service that is NOT one of its bridges.
// ===========================================================================
TEST(EgressAttack2Honesty, ActiveBridgeChildCanReachNonBridgeLoopback) {
    SKIP_UNLESS_SANDBOXABLE(bin);

    // A service the child was NEVER told about via any bridge. If the audit's
    // "general host network remains reachable" disclosure is truthful, the child
    // reaches this directly by 127.0.0.1:<port>.
    const std::string kOther = "OTHER_HOST_SERVICE_NOT_A_BRIDGE_9F3K";
    LoopbackServer other(kOther);
    ASSERT_TRUE(other.start());
    const int oport = other.port();
    ASSERT_GT(oport, 0);

    // A bridge that is active but points at an unrelated (unused) upstream — the
    // child never connects to it here; we only need egress to be ACTIVE so the
    // sandbox shares the host net.
    const int cport = pick_free_port();
    ASSERT_GT(cport, 0);
    ASSERT_NE(cport, oport);
    const std::string child_url = "http://127.0.0.1:" + std::to_string(cport);

    std::string profile_dir = make_temp_dir("profile");
    std::string profile_path = (fs::path(profile_dir) / "egress.toml").string();
    {
        std::ofstream p(profile_path);
        p << "[egress]\nmode = \"bridge\"\nisolate_netns = \"off\"\n\n"
          << "[[egress.bridge]]\n"
          << "name = \"unused\"\n"
          << "env = \"MY_BASE_URL\"\n"
          << "child_endpoint = \"" << child_url << "\"\n"
          << "upstream_endpoint = \"http://127.0.0.1:9\"\n";
    }
    std::string real_home = make_temp_dir("home");
    std::string cwd = make_temp_dir("cwd");
    auto env = base_env(real_home);

    RunResult r = run_proc(
        bin, {"--profile", profile_path, "--", kPython, "-c", connect_probe(oport)},
        env, cwd);
    other.stop();
    ASSERT_TRUE(r.spawn_ok);

    // The child reached the non-bridge host service directly => not jailed. This is
    // exactly what the honest disclosure promises (and would catch a silent change
    // that jailed the network while still claiming "not network-jailed").
    EXPECT_NE(r.output.find("CONNECT_OK"), std::string::npos)
        << "bridge-mode child could NOT reach a non-bridge host loopback service; "
           "the 'not a network jail / general host network reachable' disclosure "
           "would then be an OVERCLAIM. Output:\n"
        << r.output;
    EXPECT_NE(r.output.find(kOther), std::string::npos) << r.output;
}

// ===========================================================================
// (C) REGRESSION: flat `--net off` (no egress) still unshares the network.
// ===========================================================================
TEST(EgressAttack2Regression, FlatNetOffStillBlocksHostLoopback) {
    SKIP_UNLESS_SANDBOXABLE(bin);

    LoopbackServer srv("SHOULD_BE_UNREACHABLE_UNDER_NET_OFF");
    ASSERT_TRUE(srv.start());
    const int port = srv.port();
    ASSERT_GT(port, 0);

    std::string real_home = make_temp_dir("home");
    std::string cwd = make_temp_dir("cwd");
    auto env = base_env(real_home);

    RunResult r = run_proc(
        bin, {"--net", "off", "--", kPython, "-c", connect_probe(port)}, env, cwd);
    srv.stop();
    ASSERT_TRUE(r.spawn_ok);

    // Network genuinely unshared: the child cannot reach the host loopback service.
    EXPECT_NE(r.output.find("CONNECT_FAIL"), std::string::npos)
        << "--net off did NOT isolate the network; the child reached a host loopback "
           "service. This is a regression in the net-off path. Output:\n"
        << r.output;
    EXPECT_EQ(r.output.find("CONNECT_OK"), std::string::npos) << r.output;

    // Audit still honestly headlines off, with no egress noise.
    std::string audit = audit_at(cwd);
    EXPECT_NE(audit.find("Network:      off"), std::string::npos) << audit;
    EXPECT_EQ(audit.find("Egress bridge enabled"), std::string::npos) << audit;
    EXPECT_EQ(audit.find("SHARES the host network namespace"), std::string::npos) << audit;
}

// ===========================================================================
// (D) REGRESSION / fail-closed: mode="bridge" with ZERO bridges => net off e2e.
// ===========================================================================
TEST(EgressAttack2Regression, BridgeModeZeroBridgesFailsClosedOffEndToEnd) {
    SKIP_UNLESS_SANDBOXABLE(bin);

    LoopbackServer srv("SHOULD_BE_UNREACHABLE_FAILCLOSED");
    ASSERT_TRUE(srv.start());
    const int port = srv.port();
    ASSERT_GT(port, 0);

    // A profile that asks for bridge egress but supplies NO bridges. This is a
    // restrictive intent that never activated; it must fail closed to off, NOT
    // silently share the host net.
    std::string profile_dir = make_temp_dir("profile");
    std::string profile_path = (fs::path(profile_dir) / "egress.toml").string();
    {
        std::ofstream p(profile_path);
        p << "[egress]\nmode = \"bridge\"\nisolate_netns = \"off\"\n";
    }
    std::string real_home = make_temp_dir("home");
    std::string cwd = make_temp_dir("cwd");
    auto env = base_env(real_home);

    RunResult r = run_proc(
        bin, {"--profile", profile_path, "--", kPython, "-c", connect_probe(port)},
        env, cwd);
    srv.stop();
    ASSERT_TRUE(r.spawn_ok);

    // The child's network must be blocked (fail-closed to off), not shared.
    EXPECT_NE(r.output.find("CONNECT_FAIL"), std::string::npos)
        << "zero-bridge bridge mode did NOT fail closed; the child reached a host "
           "loopback service (silent host-net share). Output:\n"
        << r.output;
    EXPECT_EQ(r.output.find("CONNECT_OK"), std::string::npos) << r.output;

    // Honest audit + stderr: off, fail-closed note, and NO active-bridge claim.
    std::string audit = audit_at(cwd);
    EXPECT_NE(audit.find("Network:      off"), std::string::npos) << audit;
    EXPECT_NE(audit.find("fails closed"), std::string::npos) << audit;
    EXPECT_EQ(audit.find("Egress bridge enabled"), std::string::npos) << audit;
    EXPECT_EQ(audit.find("SHARES the host network namespace"), std::string::npos) << audit;
    EXPECT_NE(r.output.find("not yet enforced"), std::string::npos) << r.output;
}

// ===========================================================================
// (E) REGRESSION: flat run still scrubs a secret env var (value + audit).
// ===========================================================================
TEST(EgressAttack2Regression, FlatRunScrubsSecretEnvValueAndAudit) {
    SKIP_UNLESS_SANDBOXABLE(bin);

    const std::string kSecret = "SUPER-SECRET-VALUE-A2Z9-do-not-leak";
    std::string real_home = make_temp_dir("home");
    std::string cwd = make_temp_dir("cwd");
    auto env = base_env(real_home);
    env["AWS_SECRET_ACCESS_KEY"] = kSecret;

    // Child dumps its whole env so we can prove the secret's VALUE never arrived.
    RunResult r = run_proc(
        bin,
        {"--", kPython, "-c",
         "import os\nfor k,v in sorted(os.environ.items()): print('ENV::%s=%s'%(k,v))\n"},
        env, cwd);
    ASSERT_TRUE(r.spawn_ok);
    ASSERT_EQ(r.exit_code, 0) << r.output;

    // The secret value never reached the child.
    EXPECT_EQ(r.output.find(kSecret), std::string::npos)
        << "secret env VALUE leaked into the child. Output:\n" << r.output;
    // The variable itself is absent (default allowlist is PATH/TERM only).
    EXPECT_EQ(r.output.find("ENV::AWS_SECRET_ACCESS_KEY="), std::string::npos)
        << r.output;

    // The audit records the NAME as scrubbed and never the value.
    std::string audit = audit_at(cwd);
    EXPECT_EQ(audit.find(kSecret), std::string::npos)
        << "secret VALUE leaked into the audit:\n" << audit;
    EXPECT_NE(audit.find("AWS_SECRET_ACCESS_KEY"), std::string::npos)
        << "expected the scrubbed secret NAME in the audit:\n" << audit;
}
