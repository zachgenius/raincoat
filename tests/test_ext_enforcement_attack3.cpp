// Raincoat — attack-round-3 enforcement tests for ExtendedConfig wiring.
//
// Rounds 1 & 2 pinned fs_deny ancestor-exposure and env scrub over-veto defects
// that have since been fixed. This round pins a NEW, still-live defect found by
// running the real ./build/raincoat binary against crafted profiles. It is expected
// to FAIL against the current tree; the failing assertion IS the bug report. No
// production code is changed in this round.
//
// Defect D (security / honesty, runner hostname masking): the runner UNCONDITIONALLY
//   injects a generic HOSTNAME into the child env (cfg.ext.hostname.value_or("sandbox"))
//   and states the invariant "the real host name can never reach the child" (runner.cpp
//   ~L294-299). But the ONLY mechanism that actually hides the kernel/UTS host name is
//   bwrap's `--hostname`, which build_bwrap_argv gates on `--unshare-uts`. The runner
//   force-restores UTS isolation in exactly TWO cases — when `net = "off"` and when
//   `[identity].hostname` is EXPLICITLY set — but NOT for the plain default-hostname
//   case. So a profile with `[backend].unshare_uts = false` and no `[identity].hostname`
//   inherits the HOST UTS namespace: `$HOSTNAME` is masked to "sandbox" (giving false
//   assurance) while `gethostname()` / `/bin/hostname` / `uname -n` return the REAL host
//   name. The env masking is dishonest and the stated invariant is violated.
//
//   Reproduced end-to-end against ./build/raincoat: with such a profile,
//   `sh -c 'echo $HOSTNAME; hostname'` prints `sandbox` for the env but the real host
//   name for the syscall.

#include <gtest/gtest.h>

#include <cerrno>
#include <cstdlib>
#include <cstring>
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

bool have_prereqs(std::string& bin) {
    bin = raincoat_bin();
    if (::access(bin.c_str(), X_OK) != 0) return false;
    if (::access(kBwrapPath, X_OK) != 0) return false;
    return true;
}

struct RunResult {
    int exit_code = -1;
    bool spawn_ok = false;
    std::string output;  // combined stdout + stderr
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
    while ((n = ::read(fds[0], buf, sizeof(buf))) > 0) {
        r.output.append(buf, static_cast<size_t>(n));
    }
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
    static int counter = 0;
    fs::path base = fs::temp_directory_path() / "rc-attack3";
    fs::create_directories(base);
    fs::path dir = base / (tag + "-" + std::to_string(::getpid()) + "-" +
                           std::to_string(counter++));
    fs::remove_all(dir);
    fs::create_directories(dir);
    return dir.string();
}

}  // namespace

// ---------------------------------------------------------------------------
// Defect D: a profile that disables the UTS namespace ([backend].unshare_uts =
// false) without setting [identity].hostname must NOT leak the real host name to
// the child. The env HOSTNAME is masked to "sandbox" (claiming isolation), so the
// kernel host name the child reads via gethostname()/`hostname` must match that
// masked value — never the real machine name. Today it leaks the real host name.
// ---------------------------------------------------------------------------
TEST(ExtEnforcementAttack3, HostnameMaskingIsHonestWhenUtsNamespaceDisabled) {
    std::string bin;
    if (!have_prereqs(bin)) {
        GTEST_SKIP() << "raincoat binary or bwrap unavailable";
    }

    char host_buf[256] = {0};
    ::gethostname(host_buf, sizeof(host_buf) - 1);
    const std::string real_host(host_buf);
    if (real_host.empty() || real_host == "sandbox") {
        GTEST_SKIP() << "real host name is empty or already 'sandbox'";
    }

    const std::string real_home = make_temp_dir("realhome");
    const std::string cwd = make_temp_dir("cwd");

    // Profile disables the UTS namespace but does NOT set a custom hostname. The
    // runner still injects the generic HOSTNAME=sandbox into the env, but nothing
    // hides the real UTS host name from gethostname().
    const std::string prof = cwd + "/prof.toml";
    {
        std::ofstream ofs(prof);
        ofs << "strict = false\n"
               "network = \"full\"\n"
               "[backend]\n"
               "unshare_uts = false\n";
    }

    std::map<std::string, std::string> env = {
        {"PATH", "/usr/bin:/bin"},
        {"TERM", "xterm"},
        {"HOME", real_home},
    };

    RunResult r = run_proc(
        bin, {"--profile", prof, "--", "sh", "-c", "echo ENV=$HOSTNAME; hostname"},
        env, cwd);
    ASSERT_TRUE(r.spawn_ok);
    ASSERT_EQ(r.exit_code, 0) << r.output;

    // The env masks the host name -> the runner is asserting isolation to the child.
    ASSERT_NE(r.output.find("ENV=sandbox"), std::string::npos)
        << "expected env HOSTNAME to be masked to 'sandbox':\n"
        << r.output;

    // The stated invariant ("the real host name can never reach the child") requires
    // the kernel/UTS host name to be masked too. It is not: /bin/hostname returns the
    // real machine name, so the masked env is dishonest and the host name leaks.
    EXPECT_EQ(r.output.find(real_host), std::string::npos)
        << "the real host name leaked to the child via the UTS namespace even though "
           "the env HOSTNAME was masked to 'sandbox'. A profile that sets "
           "[backend].unshare_uts=false (without [identity].hostname) must still be "
           "prevented from exposing the real host name — mirror the net=off / "
           "hostname-set honesty overrides, or do not claim masking in the env.\n"
        << r.output;
}
