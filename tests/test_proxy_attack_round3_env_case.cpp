// Raincoat — guarded-proxy ATTACK ROUND 3 (env-var CASE bypass of the proxy hardening).
//
// The runner injects the guarded proxy and, to keep a proxy-aware child from being TOLD to
// skip it, deliberately sanitises the standard proxy env vars: it OVERRIDES http_proxy /
// https_proxy / all_proxy to the loopback guarded proxy and DROPS no_proxy (runner.cpp:
// "Drop any no_proxy bypass list ... so a proxy-aware client cannot be instructed to skip the
// guarded proxy for some hosts, which would punch a hole in the policy.").
//
// DEFECT: that sanitisation is CASE-SENSITIVE and only touches the LOWERCASE spellings. Real
// HTTP clients ALSO honour the UPPERCASE names — Python urllib (getproxies_environment /
// proxy_bypass both fold case and check NO_PROXY), curl (HTTPS_PROXY/ALL_PROXY/NO_PROXY),
// wget, and Go net/http all do. So an UPPERCASE `NO_PROXY=*` that reaches the child (via
// --set-env, --allow-env of an ambient NO_PROXY, or a profile) is NOT dropped, and a
// proxy-aware client reads it and bypasses the guarded proxy entirely — defeating the network
// policy for every host. (The sibling hole: an uppercase HTTPS_PROXY the runner never
// overrides points a curl/Go https client at an ATTACKER proxy.)
//
// This is localhost-only and deterministic: the "blocked" host is a local origin on 127.0.0.1
// that the policy denies (default_action=deny, allow_hosts=[]). Through the guarded proxy the
// child must get 403; if it instead retrieves the origin's sentinel, it reached a
// policy-blocked host DIRECTLY because the leftover uppercase NO_PROXY told it to skip the
// proxy. Shared-net (isolate_netns=off) so the direct path is reachable and the bypass is
// observable without any real external network.
#include <gtest/gtest.h>

#include <atomic>
#include <cerrno>
#include <cstdlib>
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
constexpr const char* kSentinel = "RAINCOAT_R3_ENVCASE_SENTINEL";

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
    fs::path base = fs::temp_directory_path() / "rc-proxy-r3-envcase";
    fs::create_directories(base);
    fs::path dir = base / (tag + "-" + std::to_string(::getpid()) + "-" +
                           std::to_string(counter.fetch_add(1)));
    fs::create_directories(dir);
    return dir.string();
}

std::map<std::string, std::string> base_env(const std::string& real_home) {
    return {{"PATH", "/usr/bin:/bin"}, {"TERM", "xterm"}, {"HOME", real_home}};
}

// Minimal loopback HTTP origin returning a fixed sentinel body — the host the policy DENIES.
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
            std::string req;
            char buf[2048];
            for (int i = 0; i < 64; ++i) {
                if (req.find("\r\n\r\n") != std::string::npos) break;
                ssize_t n = ::recv(c, buf, sizeof(buf), 0);
                if (n <= 0) break;
                req.append(buf, static_cast<size_t>(n));
            }
            std::string resp = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n";
            resp += "Content-Length: " + std::to_string(body_.size()) + "\r\n";
            resp += "Connection: close\r\n\r\n" + body_;
            std::size_t off = 0;
            while (off < resp.size()) {
                ssize_t w = ::send(c, resp.data() + off, resp.size() - off, 0);
                if (w <= 0) break;
                off += static_cast<size_t>(w);
            }
            ::close(c);
        }
    }
    std::string body_;
    int listen_fd_ = -1;
    int port_ = -1;
    std::atomic<bool> stop_{false};
    std::thread thread_;
};

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

// Build the child program: report the proxy env it received, then fetch the DENIED origin.
std::string child_program(int origin_port) {
    std::ostringstream py;
    py << "import os, urllib.request, urllib.error\n"
       << "print('http_proxy:', os.environ.get('http_proxy',''))\n"
       << "print('NO_PROXY:', os.environ.get('NO_PROXY','<unset>'))\n"
       << "def fetch(url):\n"
       << "    try:\n"
       << "        r = urllib.request.urlopen(url, timeout=3)\n"
       << "        return 'OK:' + r.read().decode()\n"
       << "    except urllib.error.HTTPError as e:\n"
       << "        return 'HTTP_' + str(e.code)\n"
       << "    except Exception as e:\n"
       << "        return 'ERR_' + type(e).__name__\n"
       << "print('RESULT:', fetch('http://localhost:" << origin_port << "/x'))\n";
    return py.str();
}

}  // namespace

// ---------------------------------------------------------------------------
// An UPPERCASE NO_PROXY that reaches the child defeats the guarded proxy.
//
// SECURE behavior: the guarded proxy's env hardening drops EVERY case spelling of a no_proxy
// bypass list, so a proxy-aware child cannot be told to skip the proxy. Then a policy-DENIED
// host must get 403 through the proxy. The runner only drops lowercase `no_proxy`, so the
// UPPERCASE `NO_PROXY=*` survives, urllib honours it, and the child reaches the denied origin
// DIRECTLY — this test asserts the secure outcome (RESULT == HTTP_403) and currently FAILS
// (observed RESULT == OK:<sentinel>), pinning the bypass.
// ---------------------------------------------------------------------------
TEST(ProxyAttackR3EnvCase, UppercaseNoProxyBypassesGuardedProxy) {
    SKIP_UNLESS_RUNNABLE(bin);

    LoopbackHttp origin{std::string(kSentinel)};
    ASSERT_TRUE(origin.start()) << "failed to start origin";
    const int oport = origin.port();
    ASSERT_GT(oport, 0);

    std::string profile_dir = make_temp_dir("profile");
    std::string profile_path = (fs::path(profile_dir) / "netpolicy-denyall.toml").string();
    {
        std::ofstream p(profile_path);
        // default deny with an EMPTY allow-list: NO host is permitted through the proxy, so
        // localhost (the origin) must be refused with 403 — unless the client skips the proxy.
        p << "[network_policy]\n"
          << "enabled = true\n"
          << "default_action = \"deny\"\n"
          << "allow_hosts = []\n"
          << "\n"
          << "[egress]\n"
          << "isolate_netns = \"off\"\n";
    }
    ASSERT_TRUE(fs::exists(profile_path));

    std::string real_home = make_temp_dir("home");
    std::string cwd = make_temp_dir("cwd");
    auto env = base_env(real_home);

    // The attacker-influenced env var reaches the child. --set-env is the deterministic vector;
    // --allow-env of an ambient NO_PROXY (common in corporate setups) is equally effective.
    RunResult r = run_proc(bin,
                           {"--profile", profile_path, "--set-env", "NO_PROXY=*", "--", kPython,
                            "-c", child_program(oport)},
                           env, cwd);
    origin.stop();

    ASSERT_TRUE(r.spawn_ok);
    ASSERT_EQ(r.exit_code, 0) << "raincoat/child failed. Output:\n" << r.output;

    // The guarded proxy was injected (machinery ran) ...
    EXPECT_NE(field(r.output, "http_proxy:").find("http://127.0.0.1:"), std::string::npos)
        << r.output;
    // ... but the uppercase NO_PROXY was NOT stripped: it is still visible to the child. This
    // line documents the root cause; it is expected to show "*" until the runner strips every
    // case of the proxy env names.
    EXPECT_EQ(field(r.output, "NO_PROXY:"), "<unset>")
        << "runner must strip an uppercase NO_PROXY too (it only drops lowercase no_proxy), "
           "otherwise a proxy-aware client is told to skip the guarded proxy. Output:\n"
        << r.output;

    // Core assertion: a policy-DENIED host must NOT be reachable. Through the guarded proxy it
    // is a 403; a direct (proxy-skipped) hit returns the origin sentinel, proving the policy
    // was defeated by the surviving uppercase NO_PROXY.
    const std::string result = field(r.output, "RESULT:");
    EXPECT_NE(result, std::string("OK:") + kSentinel)
        << "SECURITY: a network_policy-DENIED host was reached DIRECTLY because an uppercase "
           "NO_PROXY survived the guarded-proxy env hardening (runner only drops lowercase "
           "no_proxy). The proxy bypass defeats the policy for every host. Output:\n"
        << r.output;
    EXPECT_EQ(result, "HTTP_403")
        << "denied host must be 403'd through the guarded proxy. Output:\n"
        << r.output;
}
