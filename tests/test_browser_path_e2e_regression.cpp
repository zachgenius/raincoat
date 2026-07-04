// Raincoat — end-to-end regression guards for browser PATH handling (attack round 1).
//
// These are REAL runs of the compiled binary driving bubblewrap, guarded by
// GTEST_SKIP() when bwrap or the binary is unavailable (so the suite is a no-op, not
// a failure, on hosts that cannot sandbox).
//
// Contract under test:
//   * DISABLED (the default): the child's PATH is exactly what was injected — the
//     browser shim dir is NEVER prepended, and no "Browser isolation" note appears.
//     MVP behaviour (audit written, command runs) is unchanged.
//   * ENABLED with launch shims: the shim dir is PREPENDED to PATH but the original
//     PATH entries are RETAINED, so a non-browser binary (sh) still resolves outside
//     the shim dir — the prepend augments, never replaces or shadows, the base PATH.
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
    return true;
}

struct RunResult {
    int exit_code = -1;
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
        argv_str.push_back(bin);
        for (const auto& a : args) argv_str.push_back(a);
        std::vector<char*> argv;
        for (auto& s : argv_str) argv.push_back(const_cast<char*>(s.c_str()));
        argv.push_back(nullptr);
        std::vector<std::string> env_str;
        for (const auto& kv : env) env_str.push_back(kv.first + "=" + kv.second);
        std::vector<char*> envp;
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
    return r;
}

std::string make_temp_dir(const std::string& tag) {
    static std::atomic<unsigned> counter{0};
    fs::path base = fs::temp_directory_path() / "rc-browser-e2e";
    fs::create_directories(base);
    fs::path dir = base / (tag + "-" + std::to_string(::getpid()) + "-" +
                           std::to_string(counter.fetch_add(1)));
    fs::create_directories(dir);
    return dir.string();
}

std::map<std::string, std::string> base_env(const std::string& real_home) {
    return {
        {"PATH", "/usr/bin:/bin"},
        {"TERM", "xterm"},
        {"HOME", real_home},
    };
}

std::string read_file(const std::string& path) {
    std::ifstream ifs(path, std::ios::binary);
    if (!ifs) return {};
    std::ostringstream ss;
    ss << ifs.rdbuf();
    return ss.str();
}

std::string write_profile(const std::string& cwd, const std::string& content) {
    std::string p = cwd + "/browser.toml";
    std::ofstream ofs(p, std::ios::binary | std::ios::trunc);
    ofs << content;
    ofs.close();
    return p;
}

// Extract the value of `VAR=` from a line of `env` output (returns "" if absent).
std::string env_value(const std::string& out, const std::string& var) {
    const std::string key = var + "=";
    std::size_t pos = out.find("\n" + key);
    std::size_t start;
    if (pos != std::string::npos) {
        start = pos + 1 + key.size();
    } else if (out.rfind(key, 0) == 0) {  // first line
        start = key.size();
    } else {
        return {};
    }
    std::size_t eol = out.find('\n', start);
    return out.substr(start, eol == std::string::npos ? std::string::npos : eol - start);
}

#define SKIP_UNLESS_SANDBOXABLE(binvar)                       \
    std::string binvar;                                       \
    do {                                                      \
        std::string why;                                      \
        if (!have_prereqs(binvar, why)) GTEST_SKIP() << why;  \
    } while (0)

}  // namespace

// ---------------------------------------------------------------------------
// DISABLED (default): child PATH is untouched; no shim dir; no browser note.
// ---------------------------------------------------------------------------
TEST(BrowserPathE2ERegression, DisabledLeavesChildPathUnchanged) {
    SKIP_UNLESS_SANDBOXABLE(bin);

    std::string real_home = make_temp_dir("realhome");
    std::string cwd = make_temp_dir("cwd");
    auto env = base_env(real_home);

    RunResult r = run_proc(bin, {"--", "/usr/bin/env"}, env, cwd);
    ASSERT_TRUE(r.spawn_ok);
    EXPECT_EQ(r.exit_code, 0) << r.output;

    // The child PATH is exactly the injected base PATH — no shim dir was prepended.
    EXPECT_EQ(env_value(r.output, "PATH"), "/usr/bin:/bin") << r.output;
    EXPECT_EQ(r.output.find("/browser/shims"), std::string::npos)
        << "a browser shim dir leaked onto the child PATH while browser is disabled:\n"
        << r.output;

    // MVP unchanged: the audit is written and carries no Browser isolation note.
    std::string audit = read_file((fs::path(cwd) / ".raincoat" / "audit.log").string());
    ASSERT_FALSE(audit.empty());
    EXPECT_NE(audit.find("Mode:"), std::string::npos) << audit;
    EXPECT_EQ(audit.find("Browser isolation"), std::string::npos)
        << "disabled browser isolation still emitted an audit note:\n"
        << audit;
}

// A disabled [browser] section (enabled=false) present in a profile is still a no-op:
// PATH untouched, no shim dir, and the command runs normally.
TEST(BrowserPathE2ERegression, DisabledSectionInProfileIsNoOp) {
    SKIP_UNLESS_SANDBOXABLE(bin);

    std::string real_home = make_temp_dir("realhome");
    std::string cwd = make_temp_dir("cwd");
    auto env = base_env(real_home);

    std::string profile = write_profile(cwd,
        "[browser]\n"
        "enabled = false\n"
        "use_launch_shims = true\n"
        "locale = \"en-US\"\n");

    RunResult r =
        run_proc(bin, {"--profile", profile, "--", "/usr/bin/env"}, env, cwd);
    ASSERT_TRUE(r.spawn_ok);
    EXPECT_EQ(r.exit_code, 0) << r.output;
    EXPECT_EQ(env_value(r.output, "PATH"), "/usr/bin:/bin") << r.output;
    EXPECT_EQ(r.output.find("/browser/shims"), std::string::npos) << r.output;
}

// ---------------------------------------------------------------------------
// ENABLED with shims: shim dir PREPENDED, base PATH RETAINED, sh still resolves.
// ---------------------------------------------------------------------------
TEST(BrowserPathE2ERegression, ShimsPrependPathButKeepBaseDirsResolvable) {
    SKIP_UNLESS_SANDBOXABLE(bin);

    std::string real_home = make_temp_dir("realhome");
    std::string cwd = make_temp_dir("cwd");
    auto env = base_env(real_home);

    std::string profile = write_profile(cwd,
        "[browser]\n"
        "enabled = true\n"
        "use_launch_shims = true\n"
        "locale = \"en-US\"\n"
        "viewport = \"1280x720\"\n");

    // Ask the child to print its PATH and where a NON-browser tool (sh) resolves.
    RunResult r = run_proc(
        bin,
        {"--profile", profile, "--", "sh", "-c",
         "echo P=$PATH; command -v sh"},
        env, cwd);
    ASSERT_TRUE(r.spawn_ok);
    EXPECT_EQ(r.exit_code, 0) << r.output;

    const std::string path = env_value(r.output, "P");
    // The shim dir is prepended, and it comes BEFORE the base dirs (it wins for
    // browser names) — augmenting, not replacing, the base PATH.
    const std::size_t shim_pos = path.find("/browser/shims:");
    const std::size_t usrbin_pos = path.find("/usr/bin");
    ASSERT_NE(shim_pos, std::string::npos)
        << "shim dir was not prepended to the child PATH:\n"
        << r.output;
    ASSERT_NE(usrbin_pos, std::string::npos) << r.output;
    EXPECT_LT(shim_pos, usrbin_pos)
        << "shim dir must precede the base dirs on PATH:\n"
        << r.output;
    // The original base dirs are RETAINED (augmented, not replaced), so non-browser
    // binaries stay resolvable.
    EXPECT_NE(path.find("/bin"), std::string::npos) << r.output;

    // sh is a non-browser binary: it must still resolve to a real bin dir, NOT be
    // shadowed by the browser shim dir.
    EXPECT_EQ(r.output.find("/browser/shims/sh"), std::string::npos)
        << "the browser shim dir shadowed sh:\n"
        << r.output;
    const bool sh_ok = r.output.find("/usr/bin/sh") != std::string::npos ||
                       r.output.find("/bin/sh") != std::string::npos;
    EXPECT_TRUE(sh_ok) << "sh did not resolve to a real bin dir:\n" << r.output;
}
