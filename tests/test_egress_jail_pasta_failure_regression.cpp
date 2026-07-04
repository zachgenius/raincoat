// Regression tests for the ISOLATED-NETNS (pasta jail) feature — attack round 1.
//
// The pasta network-jail was bolted onto the runner AFTER the shared-loopback egress
// MVP. These tests pin the promise that the jail feature did NOT regress the paths that
// do NOT use pasta, and that when the jail IS requested but pasta fails to start the run
// degrades gracefully (a clear failure, never a crash / signal).
//
// Concretely they lock in:
//   A. A plain run with NO egress is unchanged: the child is not wrapped in pasta, the
//      audit carries zero jail/ISOLATED-NETNS noise, secrets are scrubbed, USER is the
//      generic identity. (Deterministic; needs only raincoat + bwrap.)
//   B. `--net off` still unshares the network namespace even though the jail path forces
//      shared networking on the egress path — the two must not have crossed wires.
//   C. When [egress].isolate_netns opts INTO the jail but the `pasta` binary on PATH
//      fails to start, raincoat surfaces the failure and exits non-zero WITHOUT crashing
//      and WITHOUT the child command ever running. A deliberately-broken fake pasta is
//      placed first on PATH so this runs even on hosts without a real pasta.
//
// These would FAIL if a future change: re-wrapped non-egress runs in pasta, leaked jail
// prose into a plain audit, broke `--net off` isolation, stopped scrubbing secrets, or
// turned a pasta start failure into a crash / swallowed error.
#include <gtest/gtest.h>

#include <atomic>
#include <cerrno>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <map>
#include <sstream>
#include <string>
#include <vector>

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
    return true;
}

#define SKIP_UNLESS_BASE(binvar)                                \
    std::string binvar;                                         \
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
    fs::path base = fs::temp_directory_path() / "rc-jail-regress";
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

void write_file(const std::string& path, const std::string& content) {
    std::ofstream ofs(path, std::ios::binary | std::ios::trunc);
    ofs << content;
}

std::map<std::string, std::string> base_env(const std::string& home) {
    return {{"PATH", "/usr/bin:/bin"}, {"TERM", "xterm"}, {"HOME", home}};
}

}  // namespace

// ---------------------------------------------------------------------------
// A. A plain (no-egress) run is not wrapped in pasta and stays clean.
// ---------------------------------------------------------------------------
TEST(JailPastaFailureRegression, PlainRunNotPastaWrappedAndSecretsScrubbed) {
    SKIP_UNLESS_BASE(bin);

    const std::string dir = make_temp_dir("plain");
    const std::string audit = dir + "/audit.log";

    auto env = base_env(dir);
    // A secret the built-in sensitive-name heuristic must drop from the child.
    env["AWS_SECRET_ACCESS_KEY"] = "TOP-SECRET-VALUE-DO-NOT-LEAK";

    RunResult r = run_proc(
        bin,
        {"run", "--audit-log", audit, "--",
         "sh", "-c",
         "echo U=$USER; echo SEC=[${AWS_SECRET_ACCESS_KEY:-GONE}]"},
        env, dir);

    ASSERT_TRUE(r.spawn_ok);
    ASSERT_FALSE(r.signaled) << "plain run should never crash. Output:\n" << r.output;
    EXPECT_EQ(r.exit_code, 0) << r.output;

    // Generic identity + secret scrub survived the jail feature.
    EXPECT_NE(r.output.find("U=user"), std::string::npos) << r.output;
    EXPECT_NE(r.output.find("SEC=[GONE]"), std::string::npos) << r.output;
    EXPECT_EQ(r.output.find("TOP-SECRET-VALUE-DO-NOT-LEAK"), std::string::npos)
        << "the secret VALUE leaked into the child:\n" << r.output;

    // The audit for a no-egress run must carry ZERO jail/pasta prose and the value
    // must never appear (tamper-evidence + no-secret guarantee).
    const std::string log = read_file(audit);
    ASSERT_FALSE(log.empty()) << "no audit written at " << audit;
    EXPECT_EQ(log.find("pasta"), std::string::npos) << log;
    EXPECT_EQ(log.find("ISOLATED-NETNS"), std::string::npos) << log;
    EXPECT_EQ(log.find("TOP-SECRET-VALUE-DO-NOT-LEAK"), std::string::npos) << log;
    // The child is exec'd directly under bwrap, never re-wrapped by pasta.
    EXPECT_NE(log.find("/usr/bin/bwrap"), std::string::npos) << log;
}

// ---------------------------------------------------------------------------
// B. `--net off` still unshares the network namespace.
// ---------------------------------------------------------------------------
TEST(JailPastaFailureRegression, NetOffStillUnsharesNetwork) {
    SKIP_UNLESS_BASE(bin);

    const std::string dir = make_temp_dir("netoff");
    const std::string audit = dir + "/audit.log";

    RunResult r = run_proc(bin,
                           {"run", "--net", "off", "--audit-log", audit, "--", "true"},
                           base_env(dir), dir);

    ASSERT_TRUE(r.spawn_ok);
    ASSERT_FALSE(r.signaled) << r.output;
    EXPECT_EQ(r.exit_code, 0) << r.output;

    const std::string log = read_file(audit);
    ASSERT_FALSE(log.empty()) << "no audit written at " << audit;
    EXPECT_NE(log.find("--unshare-net"), std::string::npos)
        << "--net off must still emit --unshare-net. Audit:\n" << log;
    EXPECT_NE(log.find("Network:      off"), std::string::npos) << log;
}

// ---------------------------------------------------------------------------
// C. Jail requested but pasta fails to start -> graceful failure, not a crash.
// ---------------------------------------------------------------------------
TEST(JailPastaFailureRegression, BrokenPastaDegradesGracefullyNoCrash) {
    SKIP_UNLESS_BASE(bin);

    const std::string dir = make_temp_dir("brokenpasta");

    // A fake `pasta` first on PATH that fails exactly the way a rootless setup failure
    // looks ("child failed(1)") and NEVER execs its bwrap tail. find_on_path checks PATH
    // dirs in order before the conventional fallbacks, so this shadows any real pasta.
    const std::string fakebin = dir + "/fakebin";
    fs::create_directories(fakebin);
    write_file(fakebin + "/pasta",
               "#!/bin/sh\necho 'pasta: setup failed: child failed(1)' >&2\nexit 1\n");
    fs::permissions(fakebin + "/pasta", fs::perms::owner_all | fs::perms::group_read |
                                            fs::perms::group_exec | fs::perms::others_read |
                                            fs::perms::others_exec);

    // Egress profile that opts INTO the jail. Upstream points nowhere real — the child
    // never runs because pasta dies first, so no upstream server is needed.
    const std::string profile = dir + "/jail.toml";
    write_file(profile,
               "strict = false\n"
               "network = \"full\"\n"
               "allow_read = [\".\"]\n"
               "allow_write = [\".\"]\n"
               "allow_env = []\n"
               "[egress]\n"
               "mode = \"bridge\"\n"
               "isolate_netns = \"on\"\n"
               "[[egress.bridge]]\n"
               "name = \"primary\"\n"
               "env = \"API_BASE_URL\"\n"
               "child_endpoint = \"http://127.0.0.1:0\"\n"
               "upstream_endpoint = \"http://127.0.0.1:9\"\n");

    auto env = base_env(dir);
    env["PATH"] = fakebin + ":/usr/bin:/bin";

    RunResult r = run_proc(
        bin,
        {"run", "--profile", profile, "--", "sh", "-c", "echo CHILD_MARKER_RAN_XYZ"},
        env, dir);

    ASSERT_TRUE(r.spawn_ok);
    // The core promise: raincoat itself must not crash (no SIGSEGV/SIGABRT) when the
    // network jail helper fails to start.
    ASSERT_FALSE(r.signaled)
        << "raincoat crashed (signal) on pasta start failure. Output:\n" << r.output;
    // It must report failure, not pretend success.
    EXPECT_NE(r.exit_code, 0) << "expected non-zero exit on pasta failure:\n" << r.output;
    // The child command must NOT have run — pasta died before exec'ing bwrap.
    EXPECT_EQ(r.output.find("CHILD_MARKER_RAN_XYZ"), std::string::npos)
        << "child ran despite the jail helper failing:\n" << r.output;
    // The failure is surfaced (pasta's own diagnostic reaches the operator), and the
    // isolated-netns intent was disclosed on stderr before launch.
    EXPECT_NE(r.output.find("child failed(1)"), std::string::npos)
        << "pasta's failure was swallowed rather than surfaced:\n" << r.output;
    EXPECT_NE(r.output.find("ISOLATED-NETNS"), std::string::npos) << r.output;
}
