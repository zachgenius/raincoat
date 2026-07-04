// Real end-to-end integration test for the ISOLATED-NETNS egress mode (pasta jail).
//
// This drives the actual compiled `raincoat` binary with an egress-bridge profile that
// opts IN to the isolated network namespace ([egress].isolate_netns = "on"). When pasta
// is present, raincoat wraps the sandbox as
//
//     pasta --config-net -t none -T <bridge-port> -- bwrap ... <child>
//
// so bwrap JOINS pasta's private netns. The test asserts the MEASURED honest contract of
// that mode (confirmed by direct experiment on this host):
//
//   1. The child reaches the upstream via the injected loopback bridge at its
//      child_endpoint (127.0.0.1:<child_port>) — child_endpoint is unchanged.
//   2. The /proc-net LEAK IS FIXED: the child's /proc/net/tcp does NOT contain the real
//      upstream port. The host-side bridge's upstream socket lives in the HOST network
//      namespace, invisible from inside the pasta netns. (In the shared-loopback mode
//      that same socket IS observable — this test pins the difference.)
//   3. `-t none` makes the jail TIGHTER than shared mode: a second host-loopback service
//      that is NOT one of the child's bridges is NOT reachable from inside the netns.
//   4. The child is NOT fully network-jailed: pasta NATs general outbound traffic, so it
//      retains general outbound internet by IP. This is RECORDED (printed) rather than
//      hard-asserted, so the test is not flaky on hosts without internet — the honest
//      contract says "NAT, not a per-destination firewall".
//   5. The audit + stderr disclose the isolated-netns reality and never overclaim.
//
// Guarded by GTEST_SKIP when bwrap, python3, the raincoat binary, OR pasta is missing.
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

// Locate pasta the same way the runner does (PATH + conventional dirs), so the test
// is skipped exactly when the runner would fall back to shared-loopback mode.
std::string find_pasta_path() {
    for (const char* p : {"/usr/bin/pasta", "/bin/pasta", "/usr/local/bin/pasta",
                          "/usr/sbin/pasta", "/sbin/pasta"}) {
        if (::access(p, X_OK) == 0) return p;
    }
    return {};
}

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
    if (find_pasta_path().empty()) {
        why = "pasta not found — isolated-netns egress mode is unavailable on this host";
        return false;
    }
    return true;
}

#define SKIP_UNLESS_JAILABLE(binvar)                          \
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
    fs::path base = fs::temp_directory_path() / "rc-egress-jail";
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

// A minimal loopback HTTP server that returns a fixed sentinel body. Used both as the
// real upstream (reached THROUGH raincoat's bridge) and as an unrelated "other" host
// service (which the jailed child must NOT be able to reach directly).
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

// Extract the value of a "KEY: value" line the child printed (trimmed).
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

constexpr const char* kSentinel = "RAINCOAT_JAIL_SENTINEL_UPSTREAM";
constexpr const char* kOtherSentinel = "RAINCOAT_JAIL_OTHER_HOST_SVC";

}  // namespace

// ---------------------------------------------------------------------------
// The isolated-netns end-to-end test: encodes the MEASURED honest contract.
// ---------------------------------------------------------------------------
TEST(EgressJailNetns, IsolatedNetnsReachesBridgeFixesProcNetLeakAndStaysHonest) {
    SKIP_UNLESS_JAILABLE(bin);

    // (1) The real upstream, reached only THROUGH raincoat's host-side bridge.
    LoopbackHttp upstream{std::string(kSentinel)};
    ASSERT_TRUE(upstream.start()) << "failed to start upstream";
    const int uport = upstream.port();
    ASSERT_GT(uport, 0);
    const std::string upstream_url = "http://127.0.0.1:" + std::to_string(uport);

    // (2) An unrelated host-loopback service the child is NEVER told about. In the
    //     shared-loopback model the child could reach it; in the pasta jail (-t none) it
    //     must NOT be reachable — proving the jail is genuinely tighter.
    LoopbackHttp other{std::string(kOtherSentinel)};
    ASSERT_TRUE(other.start()) << "failed to start other host service";
    const int oport = other.port();
    ASSERT_GT(oport, 0);
    ASSERT_NE(oport, uport);

    // Free port for raincoat's bridge (the child-visible endpoint).
    const int cport = pick_free_port();
    ASSERT_GT(cport, 0);
    ASSERT_NE(cport, uport);
    ASSERT_NE(cport, oport);
    const std::string child_url = "http://127.0.0.1:" + std::to_string(cport);

    // Profile OUTSIDE the mounted cwd, opting in to the isolated netns jail.
    std::string profile_dir = make_temp_dir("profile");
    std::string profile_path = (fs::path(profile_dir) / "egress.toml").string();
    {
        std::ofstream p(profile_path);
        p << "[egress]\n"
          << "mode = \"bridge\"\n"
          << "isolate_netns = \"on\"\n"
          << "\n"
          << "[[egress.bridge]]\n"
          << "name = \"api\"\n"
          << "env = \"MY_BASE_URL\"\n"
          << "child_endpoint = \"" << child_url << "\"\n"
          << "upstream_endpoint = \"" << upstream_url << "\"\n";
    }
    ASSERT_TRUE(fs::exists(profile_path));

    std::string real_home = make_temp_dir("home");
    std::string cwd = make_temp_dir("cwd");
    auto env = base_env(real_home);

    // The child probe. uport/oport are embedded as literals (the child's env is scrubbed
    // and the upstream string is deliberately never handed to it).
    std::ostringstream py;
    py << "import os, socket, time, urllib.request\n"
       << "base = os.environ['MY_BASE_URL']\n"
       << "print('MY_BASE_URL:', base)\n"
       << "body = None\n"
       << "for _ in range(80):\n"
       << "    try:\n"
       << "        body = urllib.request.urlopen(base + '/probe', timeout=2).read().decode()\n"
       << "        break\n"
       << "    except Exception:\n"
       << "        time.sleep(0.1)\n"
       << "print('REACHED_BRIDGE:', body)\n"
       // /proc/net leak check: is the real upstream port present anywhere in the child's
       // TCP table? (bridge->upstream socket lives in the HOST ns, so it must be absent.)
       << "uport = " << uport << "\n"
       << "leak = False\n"
       << "for fn in ('/proc/net/tcp', '/proc/net/tcp6'):\n"
       << "    try:\n"
       << "        for l in open(fn).readlines()[1:]:\n"
       << "            p = l.split()\n"
       << "            for f in (p[1], p[2]):\n"
       << "                if int(f.split(':')[1], 16) == uport:\n"
       << "                    leak = True\n"
       << "    except Exception:\n"
       << "        pass\n"
       << "print('UPSTREAM_PORT_VISIBLE_IN_PROCNET:', leak)\n"
       // Tighter-jail check: an unrelated host-loopback service must NOT be reachable.
       << "oport = " << oport << "\n"
       << "try:\n"
       << "    s = socket.create_connection(('127.0.0.1', oport), timeout=3)\n"
       << "    s.close()\n"
       << "    print('OTHER_HOST_LOOPBACK_REACHABLE:', 'yes')\n"
       << "except Exception:\n"
       << "    print('OTHER_HOST_LOOPBACK_REACHABLE:', 'no')\n"
       // General internet via NAT: RECORDED only (not asserted — CI may lack internet).
       << "try:\n"
       << "    s = socket.create_connection(('1.1.1.1', 443), timeout=4)\n"
       << "    s.close()\n"
       << "    print('GENERAL_INTERNET:', 'connected')\n"
       << "except Exception as e:\n"
       << "    print('GENERAL_INTERNET:', type(e).__name__)\n";

    RunResult r = run_proc(
        bin, {"--profile", profile_path, "--", kPython, "-c", py.str()}, env, cwd);
    upstream.stop();
    other.stop();

    ASSERT_TRUE(r.spawn_ok);
    ASSERT_EQ(r.exit_code, 0) << "raincoat/child failed. Output:\n" << r.output;

    // --- Contract 1: the child reached the upstream via the bridge at 127.0.0.1:<cport>.
    EXPECT_EQ(field(r.output, "MY_BASE_URL:"), child_url) << r.output;
    EXPECT_NE(r.output.find(kSentinel), std::string::npos)
        << "child did not receive the upstream sentinel through the jailed bridge:\n"
        << r.output;

    // --- Contract 2: the /proc-net LEAK IS FIXED — upstream port not in the child's table.
    EXPECT_EQ(field(r.output, "UPSTREAM_PORT_VISIBLE_IN_PROCNET:"), "False")
        << "isolated-netns mode MUST hide the host-side bridge->upstream socket from the "
           "child's /proc/net/tcp. Output:\n"
        << r.output;

    // --- Contract 3: the jail is tighter than shared mode — an unrelated host-loopback
    //     service is NOT reachable from inside the netns (pasta -t none).
    EXPECT_EQ(field(r.output, "OTHER_HOST_LOOPBACK_REACHABLE:"), "no")
        << "a non-bridge host-loopback service was reachable from the jailed child; the "
           "isolated netns should only forward the bridge port(s). Output:\n"
        << r.output;

    // --- Contract 4: general internet is RECORDED (honest 'NAT, not a firewall'). We do
    //     not fail the test on its value (hosts without internet are valid), but the child
    //     must have reported one of the two states so the contract is observed.
    const std::string internet = field(r.output, "GENERAL_INTERNET:");
    EXPECT_FALSE(internet.empty()) << r.output;
    RecordProperty("general_internet_from_jailed_child", internet);

    // --- Contract 5: the audit + stderr disclose the isolated-netns reality, name that
    //     the /proc-net leak is FIXED, record the child-visible endpoint, and never leak
    //     or overclaim.
    std::string audit_path = (fs::path(cwd) / ".raincoat" / "audit.log").string();
    ASSERT_TRUE(fs::exists(audit_path)) << "expected audit at " << audit_path;
    std::string audit = read_file(audit_path);

    EXPECT_NE(audit.find("ISOLATED-NETNS"), std::string::npos) << audit;
    EXPECT_NE(audit.find("/proc-net leak is FIXED"), std::string::npos) << audit;
    EXPECT_NE(audit.find(child_url), std::string::npos) << audit;
    EXPECT_EQ(audit.find(upstream_url), std::string::npos)
        << "audit leaked the real upstream URL:\n" << audit;

    // stderr disclosure for a user who never opens the audit.
    EXPECT_NE(r.output.find("ISOLATED-NETNS mode"), std::string::npos) << r.output;

    // No dishonest overclaim of a per-destination firewall / full jail.
    for (const std::string& lie : {std::string("per-destination firewall blocks"),
                                   std::string("network is fully jailed"),
                                   std::string("cannot reach the internet")}) {
        EXPECT_EQ(audit.find(lie), std::string::npos)
            << "audit overclaims: '" << lie << "'\n" << audit;
    }
}
