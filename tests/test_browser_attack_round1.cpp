// Raincoat — browser isolation, ATTACK ROUND 1.
//
// Adversarial tests that probe the launch-shim mechanism for real defects, using only
// FAKE browser stubs (a script that prints its argv). No real browser is ever launched.
//
// Two tests are EXPECTED TO FAIL against the current implementation — they demonstrate
// genuine defects:
//   * RecursionGuardIsSpellingFragile  — the loop-prevention guard is a single exact
//     string compare of the shim dir; a trivially-equivalent spelling of that dir on
//     PATH (here: a trailing slash) defeats it and the shim exec-recurses into itself
//     forever. There is no re-entry sentinel as defense-in-depth.
//   * IsolateProfileFalseIsHonored     — BrowserConfig.isolate_profile is parsed and
//     stored (and round-trip-tested in test_profile) but setup_browser never reads it;
//     isolate_profile=false still injects --user-data-dir=<throwaway>. A dead knob.
//
// The remaining tests PASS and lock in the honest/correct behavior the attack verified:
// absolute-path bypass is real AND admitted in the shim text; args with spaces are not
// mangled; malformed viewports never crash and never emit a flag.

#include <gtest/gtest.h>
#include "rc_test_timeout.h"
#include <sys/wait.h>
#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>

#include "browser.hpp"
#include "config.hpp"

namespace fs = std::filesystem;
using namespace raincoat;

namespace {

std::string make_root() {
    static int counter = 0;
    fs::path p = fs::temp_directory_path() /
                 ("rc_battack_" + std::to_string(::getpid()) + "_" +
                  std::to_string(counter++));
    fs::create_directories(p);
    return p.string();
}

std::string read_file(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    std::ostringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

// popen capture (stdout+stderr), wrapped in a hard timeout.
std::string run_capture(const std::string& cmd) {
    std::string full = rc_timeout(10) + cmd + " 2>&1";
    std::string out;
    FILE* p = ::popen(full.c_str(), "r");
    if (!p) return out;
    char buf[4096];
    size_t n;
    while ((n = ::fread(buf, 1, sizeof(buf), p)) > 0) out.append(buf, n);
    ::pclose(p);
    return out;
}

BrowserConfig enabled_cfg() {
    BrowserConfig c;
    c.enabled = true;
    c.use_launch_shims = true;
    c.locale = "en-US";
    c.viewport = "1280x720";
    c.disable_gpu = true;
    c.disable_extensions = true;
    c.disable_sync = true;
    c.timezone = "UTC";
    return c;
}

// Write a fake browser stub that prints each received arg on its own delimited line, so
// an arg containing spaces is distinguishable from two separate args.
void write_arg_dumping_stub(const std::string& path) {
    std::ofstream f(path);
    f << "#!/bin/sh\n"
      << "echo REAL-BROWSER-INVOKED\n"
      << "for a in \"$@\"; do echo \"ARG<$a>\"; done\n";
    f.close();
    fs::permissions(path, fs::perms::owner_all | fs::perms::group_read |
                              fs::perms::group_exec | fs::perms::others_read |
                              fs::perms::others_exec);
}

}  // namespace

// ---------------------------------------------------------------------------
// DEFECT 1 (EXPECTED FAIL): the recursion guard is defeated by an equivalent
// spelling of the shim dir on PATH, causing infinite self-exec recursion.
// ---------------------------------------------------------------------------
TEST(BrowserAttack1, RecursionGuardIsSpellingFragile) {
    BrowserConfig c = enabled_cfg();
    std::string err;
    std::string root = make_root();
    BrowserSetup s = setup_browser(c, root, err);
    ASSERT_FALSE(s.shim_dir.empty());

    const std::string shim = (fs::path(s.shim_dir) / "chromium").string();
    // PATH contains the shim dir spelled with a TRAILING SLASH (an equivalent path that
    // the exact-string guard does not recognize) and no real browser anywhere else. A
    // robust guard (canonicalized compare or a re-entry sentinel env var) would still
    // refuse to resolve itself and would fall through to "could not find real". The
    // current guard resolves the shim as if it were the real browser and exec-loops.
    // `timeout` SIGKILLs a hung (recursing) shim; a correct shim exits fast on its own.
    const std::string cmd = rc_timeout(5, true) + "env PATH='" + s.shim_dir +
                            "/:/raincoat-no-such-dir' '" + shim + "' probe";
    int rc = std::system((cmd + " >/dev/null 2>&1").c_str());
    int code = WIFEXITED(rc) ? WEXITSTATUS(rc) : -1;
    // GNU timeout reports 124 (or 128+9=137 when it must SIGKILL) after a timeout.
    EXPECT_TRUE(code != 124 && code != 137)
        << "shim recursed infinitely on a trailing-slash spelling of its own dir "
           "(killed by timeout, exit " << code << "); the exact-string recursion guard "
           "is spelling-fragile and there is no re-entry sentinel";
}

// ---------------------------------------------------------------------------
// DEFECT 2 (EXPECTED FAIL): isolate_profile=false is silently ignored; the
// throwaway --user-data-dir is injected regardless.
// ---------------------------------------------------------------------------
TEST(BrowserAttack1, IsolateProfileFalseIsHonored) {
    BrowserConfig c = enabled_cfg();
    c.isolate_profile = false;  // user asks NOT to swap in a throwaway profile
    std::string err;
    std::string root = make_root();
    BrowserSetup s = setup_browser(c, root, err);
    ASSERT_TRUE(err.empty());
    ASSERT_FALSE(s.shim_dir.empty());
    const std::string body = read_file((fs::path(s.shim_dir) / "chromium").string());
    EXPECT_EQ(body.find("--user-data-dir="), std::string::npos)
        << "isolate_profile=false must not inject an isolated --user-data-dir, but the "
           "flag is present: the isolate_profile knob is parsed but never consumed";
}

// ---------------------------------------------------------------------------
// HONESTY (PASS): a launch by ABSOLUTE path bypasses the shim entirely, and the
// generated shim admits exactly this limitation in its own text.
// ---------------------------------------------------------------------------
TEST(BrowserAttack1, AbsolutePathBypassIsRealAndAdmitted) {
    BrowserConfig c = enabled_cfg();
    std::string err;
    std::string root = make_root();
    BrowserSetup s = setup_browser(c, root, err);
    ASSERT_FALSE(s.shim_dir.empty());

    const std::string fake_dir = root + "/fakebin";
    fs::create_directories(fake_dir);
    const std::string fake = fake_dir + "/chromium";
    write_arg_dumping_stub(fake);

    // Even with the shim dir first on PATH, invoking the browser by its ABSOLUTE path
    // skips PATH resolution and therefore the shim: no isolation flags are injected.
    const std::string cmd = "env PATH='" + s.shim_dir + ":" + fake_dir + "' '" + fake +
                            "' user-only-arg";
    const std::string out = run_capture(cmd);
    EXPECT_NE(out.find("REAL-BROWSER-INVOKED"), std::string::npos) << out;
    EXPECT_EQ(out.find("--user-data-dir="), std::string::npos)
        << "absolute-path launch must bypass the shim (no injected flags):\n" << out;

    // The shim script text must ADMIT this limitation (honesty).
    const std::string body = read_file((fs::path(s.shim_dir) / "chromium").string());
    EXPECT_NE(body.find("absolute-path launch is not caught"), std::string::npos)
        << "the generated shim must document the absolute-path bypass";
}

// ---------------------------------------------------------------------------
// CORRECTNESS (PASS): an argument containing spaces survives as ONE argument
// (flags prepended, caller args verbatim, nothing split or dropped).
// ---------------------------------------------------------------------------
TEST(BrowserAttack1, ArgsWithSpacesAreNotMangled) {
    BrowserConfig c = enabled_cfg();
    std::string err;
    std::string root = make_root();
    BrowserSetup s = setup_browser(c, root, err);
    ASSERT_FALSE(s.shim_dir.empty());

    const std::string fake_dir = root + "/fakebin";
    fs::create_directories(fake_dir);
    write_arg_dumping_stub(fake_dir + "/chromium");

    const std::string shim = (fs::path(s.shim_dir) / "chromium").string();
    // A spacey arg, an empty arg, and a glob metachar arg — none may be split, dropped,
    // or glob-expanded.
    const std::string cmd = "env PATH='" + s.shim_dir + ":" + fake_dir + "' '" + shim +
                            "' '--user-agent=Mozilla 5.0 (X11)' '' '*'";
    const std::string out = run_capture(cmd);
    EXPECT_NE(out.find("ARG<--user-agent=Mozilla 5.0 (X11)>"), std::string::npos)
        << "spacey arg must arrive as a single argument:\n" << out;
    EXPECT_NE(out.find("ARG<>"), std::string::npos) << "empty arg must be preserved:\n" << out;
    EXPECT_NE(out.find("ARG<*>"), std::string::npos)
        << "glob metachar must not be expanded:\n" << out;
    // Isolation flags still prepended.
    EXPECT_NE(out.find("ARG<--user-data-dir=" + s.profile_dir + ">"), std::string::npos)
        << out;
}

// ---------------------------------------------------------------------------
// ROBUSTNESS (PASS): malformed viewports never crash and never emit a flag.
// ---------------------------------------------------------------------------
TEST(BrowserAttack1, MalformedViewportIsSafe) {
    for (const char* vp : {"abc", "1280X720", "1280x", "x720", "12x34x56", "-5x-6",
                           " 12x34", ""}) {
        BrowserConfig c = enabled_cfg();
        c.viewport = vp;
        std::string err;
        std::string root = make_root();
        BrowserSetup s = setup_browser(c, root, err);
        EXPECT_TRUE(err.empty()) << "viewport '" << vp << "' set err: " << err;
        ASSERT_FALSE(s.shim_dir.empty()) << "viewport '" << vp << "'";
        const std::string body = read_file((fs::path(s.shim_dir) / "chromium").string());
        EXPECT_EQ(body.find("--window-size="), std::string::npos)
            << "malformed viewport '" << vp << "' must not emit --window-size";
    }
}
