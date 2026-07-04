// Raincoat — tests for the browser isolation module (setup_browser + shim mechanism).
//
// Unit: setup_browser writes EXECUTABLE shims that carry the right isolation flags, and
// its PATH-resolution EXCLUDES the shim dir (recursion guard).
// Integration: a FAKE 'chromium' stub (prints its argv) is placed on PATH ahead of the
// real one; the generated chromium shim must exec the fake (never loop) with the
// isolation flags PREPENDED before the caller's arguments.
//
// No real browser is ever launched — the stub stands in for it.

#include <gtest/gtest.h>
#include "rc_test_timeout.h"
#include <unistd.h>

#include <cstdio>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>

#include "browser.hpp"
#include "config.hpp"

namespace fs = std::filesystem;
using namespace raincoat;

namespace {

// A fresh, unique, absolute sandbox-root dir for one test.
std::string make_root() {
    static int counter = 0;
    fs::path p = fs::temp_directory_path() /
                 ("rc_browser_" + std::to_string(::getpid()) + "_" +
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

bool is_executable(const std::string& path) {
    return ::access(path.c_str(), X_OK) == 0;
}

// Run `cmd` under a shell, returning captured stdout+stderr. Wrapped in `timeout` so a
// regressed shim that recursed into itself fails the test instead of hanging forever.
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

}  // namespace

// ---------------------------------------------------------------------------
// Disabled / minimal behavior.
// ---------------------------------------------------------------------------
TEST(Browser, DisabledDoesNothing) {
    BrowserConfig c;  // enabled defaults false
    std::string err;
    BrowserSetup s = setup_browser(c, make_root(), err);
    EXPECT_TRUE(err.empty());
    EXPECT_TRUE(s.shim_dir.empty());
    EXPECT_TRUE(s.profile_dir.empty());
    EXPECT_TRUE(s.env.empty());
}

TEST(Browser, RelativeRootIsRejected) {
    BrowserConfig c = enabled_cfg();
    std::string err;
    BrowserSetup s = setup_browser(c, "relative/root", err);
    EXPECT_FALSE(err.empty());
    EXPECT_TRUE(s.shim_dir.empty());
}

TEST(Browser, NoShimsWhenDisabledButProfileAndEnvStillSet) {
    BrowserConfig c = enabled_cfg();
    c.use_launch_shims = false;
    std::string err;
    std::string root = make_root();
    BrowserSetup s = setup_browser(c, root, err);
    EXPECT_TRUE(err.empty());
    EXPECT_TRUE(s.shim_dir.empty());
    ASSERT_FALSE(s.profile_dir.empty());
    EXPECT_TRUE(fs::is_directory(s.profile_dir));
    EXPECT_EQ(s.env.count("TZ"), 1u);
    EXPECT_EQ(s.env["TZ"], "UTC");
}

TEST(Browser, DefaultProfileDirIsUnderSandboxRoot) {
    BrowserConfig c = enabled_cfg();
    c.use_launch_shims = false;
    std::string err;
    std::string root = make_root();
    BrowserSetup s = setup_browser(c, root, err);
    ASSERT_FALSE(s.profile_dir.empty());
    EXPECT_EQ(s.profile_dir.rfind(root, 0), 0u)
        << "default profile dir must live under the sandbox root: " << s.profile_dir;
}

TEST(Browser, ExplicitProfileDirIsHonored) {
    BrowserConfig c = enabled_cfg();
    c.use_launch_shims = false;
    std::string root = make_root();
    c.profile_dir = root + "/custom-profile";
    std::string err;
    BrowserSetup s = setup_browser(c, root, err);
    EXPECT_EQ(s.profile_dir, root + "/custom-profile");
    EXPECT_TRUE(fs::is_directory(s.profile_dir));
}

// ---------------------------------------------------------------------------
// Shim generation: executable + carries the right flags.
// ---------------------------------------------------------------------------
TEST(Browser, WritesExecutableShimsForAllKnownNames) {
    BrowserConfig c = enabled_cfg();
    std::string err;
    std::string root = make_root();
    BrowserSetup s = setup_browser(c, root, err);
    ASSERT_TRUE(err.empty());
    ASSERT_FALSE(s.shim_dir.empty());

    for (const char* name : {"google-chrome", "google-chrome-stable", "chromium",
                             "chromium-browser", "chrome", "msedge", "firefox"}) {
        const std::string path = (fs::path(s.shim_dir) / name).string();
        EXPECT_TRUE(fs::is_regular_file(path)) << "missing shim: " << name;
        EXPECT_TRUE(is_executable(path)) << "shim not executable: " << name;
    }
}

TEST(Browser, ChromiumShimContainsIsolationFlags) {
    BrowserConfig c = enabled_cfg();
    std::string err;
    std::string root = make_root();
    BrowserSetup s = setup_browser(c, root, err);
    ASSERT_FALSE(s.shim_dir.empty());
    const std::string body = read_file((fs::path(s.shim_dir) / "chromium").string());

    EXPECT_NE(body.find("--user-data-dir=" + s.profile_dir), std::string::npos);
    EXPECT_NE(body.find("--lang=en-US"), std::string::npos);
    EXPECT_NE(body.find("--window-size=1280,720"), std::string::npos);
    EXPECT_NE(body.find("--disable-gpu"), std::string::npos);
    EXPECT_NE(body.find("--disable-extensions"), std::string::npos);
    EXPECT_NE(body.find("--disable-sync"), std::string::npos);
    EXPECT_NE(body.find("\"$@\""), std::string::npos) << "must forward caller args";
}

TEST(Browser, ChromiumShimOmitsUnsetOptionalFlags) {
    BrowserConfig c = enabled_cfg();
    c.locale.clear();       // no --lang
    c.viewport.clear();     // no --window-size
    c.disable_gpu = false;  // no --disable-gpu
    std::string err;
    std::string root = make_root();
    BrowserSetup s = setup_browser(c, root, err);
    ASSERT_FALSE(s.shim_dir.empty());
    const std::string body = read_file((fs::path(s.shim_dir) / "chromium").string());
    EXPECT_EQ(body.find("--lang="), std::string::npos);
    EXPECT_EQ(body.find("--window-size="), std::string::npos);
    EXPECT_EQ(body.find("--disable-gpu"), std::string::npos);
    // The required user-data-dir is always present.
    EXPECT_NE(body.find("--user-data-dir="), std::string::npos);
}

TEST(Browser, FirefoxShimUsesProfileFlag) {
    BrowserConfig c = enabled_cfg();
    std::string err;
    std::string root = make_root();
    BrowserSetup s = setup_browser(c, root, err);
    ASSERT_FALSE(s.shim_dir.empty());
    const std::string body = read_file((fs::path(s.shim_dir) / "firefox").string());
    EXPECT_NE(body.find("-profile"), std::string::npos);
    EXPECT_NE(body.find(s.profile_dir), std::string::npos);
}

TEST(Browser, ShimExcludesItsOwnDirFromPathResolution) {
    // The generated shim must skip its own dir when scanning PATH, or it would resolve
    // itself and recurse. Assert the guard is present in the script text.
    BrowserConfig c = enabled_cfg();
    std::string err;
    std::string root = make_root();
    BrowserSetup s = setup_browser(c, root, err);
    ASSERT_FALSE(s.shim_dir.empty());
    const std::string body = read_file((fs::path(s.shim_dir) / "chromium").string());
    EXPECT_NE(body.find("_rc_shim_dir=" ), std::string::npos);
    EXPECT_NE(body.find(s.shim_dir), std::string::npos);
    EXPECT_NE(body.find("continue"), std::string::npos)
        << "the shim must `continue` past its own dir when scanning PATH";
}

// ---------------------------------------------------------------------------
// Integration: run the generated chromium shim against a FAKE chromium stub.
// ---------------------------------------------------------------------------
TEST(Browser, ShimExecsFakeBrowserWithFlagsPrependedThenArgs) {
    BrowserConfig c = enabled_cfg();
    std::string err;
    std::string root = make_root();
    BrowserSetup s = setup_browser(c, root, err);
    ASSERT_FALSE(s.shim_dir.empty());

    // Place a FAKE 'chromium' on PATH in a DIFFERENT directory. It prints its argv so we
    // can observe exactly what the shim execed it with.
    const std::string fake_dir = root + "/fakebin";
    fs::create_directories(fake_dir);
    const std::string fake = fake_dir + "/chromium";
    {
        std::ofstream f(fake);
        f << "#!/bin/sh\n"
          << "printf 'REAL-BROWSER argv:'\n"
          << "for a in \"$@\"; do printf ' %s' \"$a\"; done\n"
          << "printf '\\n'\n";
    }
    fs::permissions(fake, fs::perms::owner_all | fs::perms::group_read |
                              fs::perms::group_exec | fs::perms::others_read |
                              fs::perms::others_exec);

    // PATH puts the SHIM DIR FIRST, then the fake dir. If the shim failed to exclude its
    // own dir it would resolve itself (loop); correct behavior resolves the fake.
    const std::string shim = (fs::path(s.shim_dir) / "chromium").string();
    const std::string cmd = "env PATH='" + s.shim_dir + ":" + fake_dir + "' '" + shim +
                            "' hello world";
    const std::string out = run_capture(cmd);

    // Execed the FAKE exactly once (no loop): one REAL-BROWSER line.
    EXPECT_NE(out.find("REAL-BROWSER argv:"), std::string::npos) << out;
    EXPECT_EQ(out.find("REAL-BROWSER argv:"), out.rfind("REAL-BROWSER argv:"))
        << "the shim must exec the real browser exactly once (no recursion):\n" << out;

    // Isolation flags are present...
    const auto p_udd = out.find("--user-data-dir=" + s.profile_dir);
    const auto p_lang = out.find("--lang=en-US");
    const auto p_ws = out.find("--window-size=1280,720");
    EXPECT_NE(p_udd, std::string::npos) << out;
    EXPECT_NE(p_lang, std::string::npos) << out;
    EXPECT_NE(p_ws, std::string::npos) << out;
    EXPECT_NE(out.find("--disable-gpu"), std::string::npos) << out;

    // ...and the caller's args come AFTER the injected flags.
    const auto p_hello = out.find("hello");
    const auto p_world = out.find("world");
    ASSERT_NE(p_hello, std::string::npos) << out;
    ASSERT_NE(p_world, std::string::npos) << out;
    EXPECT_LT(p_udd, p_hello) << "flags must be PREPENDED before caller args:\n" << out;
    EXPECT_LT(p_hello, p_world) << "caller arg order must be preserved:\n" << out;
}

TEST(Browser, ShimFallsBackToKnownPathWhenNotOnPath) {
    // With NOTHING resolvable on PATH (empty PATH, only the shim dir excluded), the shim
    // falls back to known absolute paths; when none exist it exits 127 with a clear
    // message rather than looping.
    BrowserConfig c = enabled_cfg();
    std::string err;
    std::string root = make_root();
    BrowserSetup s = setup_browser(c, root, err);
    ASSERT_FALSE(s.shim_dir.empty());
    const std::string shim = (fs::path(s.shim_dir) / "msedge").string();
    // Point PATH only at the shim dir (excluded) so nothing else resolves; msedge is
    // very unlikely to exist at the fallback paths in CI.
    const std::string cmd = "env PATH='" + s.shim_dir + "' '" + shim + "' arg";
    const std::string out = run_capture(cmd);
    // Either it found a real msedge (won't in CI) or it reported it could not — never
    // looped. Assert the honest not-found message when absent.
    EXPECT_NE(out.find("could not find real"), std::string::npos) << out;
}
