// Regression test for sandbox-tree cleanup on a terminating signal (SIGINT).
//
// The runner claims (runner.cpp, "Terminating-signal handling for sandbox
// cleanup") that an interrupt causes the /tmp/raincoat-* sandbox tree to be torn
// down instead of leaked. This test verifies that end-to-end by fork/exec'ing the
// REAL raincoat binary and delivering SIGINT.
//
// THE GAP THIS EXPOSES: the SIGINT/SIGTERM/SIGHUP handlers are installed only just
// before fork() (runner.cpp step 11), whereas the sandbox root is created much
// earlier by mkdtemp() (step 1). Between those two points raincoat does font setup,
// mount planning, and the audit "start" write — a wide window in which the default
// SIGINT disposition terminates raincoat before any handler (and thus before
// cleanup_root()) runs, leaking the whole sandbox tree under $TMPDIR.
//
// To hit that window deterministically the test delivers SIGINT the instant the
// sandbox dir appears (i.e. right after mkdtemp returns, at the START of the
// unprotected window), and repeats across several attempts. A correct fix (install
// the handlers, or an equivalent cleanup guard, BEFORE mkdtemp) leaves zero
// leftover dirs. The test is skipped (not failed) on hosts that cannot sandbox.
#include <gtest/gtest.h>

#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <string>
#include <vector>

#include <dirent.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>

#include <filesystem>

namespace {

namespace fs = std::filesystem;

std::string raincoat_bin() {
    const char* e = std::getenv("RAINCOAT_BIN");
    if (e && *e) return std::string(e);
    return "/home/zach/Develop/Raincoat/build/raincoat";
}

constexpr const char* kBwrapPath = "/usr/bin/bwrap";

// Count entries named "raincoat-*" directly inside `dir`.
int count_sandbox_dirs(const std::string& dir) {
    int n = 0;
    DIR* d = ::opendir(dir.c_str());
    if (!d) return 0;
    while (struct dirent* e = ::readdir(d)) {
        if (std::strncmp(e->d_name, "raincoat-", 9) == 0) ++n;
    }
    ::closedir(d);
    return n;
}

void tiny_sleep_us(long us) {
    struct timespec ts;
    ts.tv_sec = us / 1000000;
    ts.tv_nsec = (us % 1000000) * 1000L;
    ::nanosleep(&ts, nullptr);
}

}  // namespace

// One SIGINT-during-startup attempt: spawn raincoat with a private TMPDIR, fire
// SIGINT the moment its sandbox dir materializes, reap it, and return the number
// of sandbox dirs still present (0 == cleaned up, >0 == leaked).
static int leftover_after_startup_sigint(const std::string& bin,
                                         const std::string& tmpdir,
                                         const std::string& cwd) {
    pid_t pid = ::fork();
    if (pid == 0) {
        // ---- child: become the raincoat process under a controlled env ----
        if (::chdir(cwd.c_str()) != 0) _exit(126);
        // Quiet: send stdio to /dev/null so the test log stays clean.
        if (int nul = ::open("/dev/null", O_WRONLY); nul >= 0) {
            ::dup2(nul, STDOUT_FILENO);
            ::dup2(nul, STDERR_FILENO);
        }
        ::setenv("TMPDIR", tmpdir.c_str(), 1);
        ::setenv("PATH", "/usr/bin:/bin", 1);
        ::setenv("TERM", "xterm", 1);
        ::setenv("HOME", cwd.c_str(), 1);
        std::vector<char*> argv;
        argv.push_back(const_cast<char*>(bin.c_str()));
        char a1[] = "--";
        char a2[] = "sh";
        char a3[] = "-c";
        char a4[] = "sleep 5";
        argv.push_back(a1);
        argv.push_back(a2);
        argv.push_back(a3);
        argv.push_back(a4);
        argv.push_back(nullptr);
        ::execv(bin.c_str(), argv.data());
        _exit(127);
    }

    // ---- parent: wait for the sandbox dir to appear, then SIGINT at once ----
    bool appeared = false;
    for (int i = 0; i < 200000; ++i) {  // ~ up to a few seconds of tight polling
        if (count_sandbox_dirs(tmpdir) > 0) {
            ::kill(pid, SIGINT);  // fired at the very start of the unprotected window
            appeared = true;
            break;
        }
        // If raincoat already exited (e.g. exec failure) stop early.
        int st = 0;
        if (::waitpid(pid, &st, WNOHANG) == pid) {
            return count_sandbox_dirs(tmpdir);
        }
        tiny_sleep_us(20);
    }
    if (!appeared) ::kill(pid, SIGINT);

    int status = 0;
    while (::waitpid(pid, &status, 0) < 0 && errno == EINTR) {
    }
    return count_sandbox_dirs(tmpdir);
}

TEST(SigintCleanup, SandboxTreeRemovedWhenInterruptedDuringStartup) {
    const std::string bin = raincoat_bin();
    if (::access(bin.c_str(), X_OK) != 0) {
        GTEST_SKIP() << "raincoat binary not found/executable at " << bin;
    }
    if (::access(kBwrapPath, X_OK) != 0) {
        GTEST_SKIP() << "bwrap not found/executable at " << kBwrapPath;
    }

    // Private TMPDIR so we only ever observe THIS test's sandbox dirs, and a
    // private cwd so the auto-mounted-cwd audit log never touches the project.
    fs::path base = fs::temp_directory_path() / "rc-sigint-test";
    std::error_code ec;
    fs::remove_all(base, ec);
    fs::create_directories(base / "tmp", ec);
    fs::create_directories(base / "cwd", ec);
    const std::string tmpdir = (base / "tmp").string();
    const std::string cwd = (base / "cwd").string();

    // Repeat: the window is timing-dependent, so a single attempt could miss it.
    // Any leftover across the attempts is a real, unrecoverable /tmp leak.
    constexpr int kAttempts = 12;
    int total_leaked = 0;
    for (int i = 0; i < kAttempts; ++i) {
        total_leaked += leftover_after_startup_sigint(bin, tmpdir, cwd);
        // Clean between attempts so each attempt is measured independently; the
        // running total is what the assertion below checks.
        for (const auto& entry : fs::directory_iterator(tmpdir, ec)) {
            if (entry.path().filename().string().rfind("raincoat-", 0) == 0) {
                fs::remove_all(entry.path(), ec);
            }
        }
    }

    fs::remove_all(base, ec);

    EXPECT_EQ(total_leaked, 0)
        << "raincoat leaked " << total_leaked << " sandbox tree(s) under TMPDIR "
        << "across " << kAttempts << " SIGINT-during-startup attempts. A "
        << "terminating signal arriving after mkdtemp() (runner.cpp step 1) but "
        << "before the signal handlers install (step 11) kills raincoat with the "
        << "default disposition, so cleanup_root() never runs.";
}
