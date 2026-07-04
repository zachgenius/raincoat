// Raincoat — regression guards for the browser isolation feature (attack round 1).
//
// The [browser] feature ADDS an isolated temp profile + optional PATH launch shims.
// It MUST be a no-op when disabled (the default), and when enabled its shim dir must
// only ever intercept the handful of KNOWN browser names — prepending it to the child
// PATH must never shadow an unrelated (non-browser) binary the user relies on.
//
// These are pure/mechanism tests: no bwrap and no REAL browser is launched. The shim
// mechanism is exercised against a fake stub that prints its argv.

#include <gtest/gtest.h>
#include <unistd.h>

#include <cstdio>
#include <filesystem>
#include <fstream>
#include <set>
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
                 ("rc_browser_reg_" + std::to_string(::getpid()) + "_" +
                  std::to_string(counter++));
    fs::create_directories(p);
    return p.string();
}

BrowserConfig enabled_shims_cfg() {
    BrowserConfig c;
    c.enabled = true;
    c.use_launch_shims = true;
    c.locale = "en-US";
    c.viewport = "1280x720";
    c.timezone = "UTC";
    return c;
}

// Run `cmd` under a shell (with a hard `timeout` so a regressed shim that recursed
// cannot hang the suite), returning captured stdout+stderr.
std::string run_capture(const std::string& cmd) {
    std::string full = "timeout 10 " + cmd + " 2>&1";
    std::string out;
    FILE* p = ::popen(full.c_str(), "r");
    if (!p) return out;
    char buf[4096];
    size_t n;
    while ((n = ::fread(buf, 1, sizeof(buf), p)) > 0) out.append(buf, n);
    ::pclose(p);
    return out;
}

// The complete set of names the browser module is allowed to shim. Anything OUTSIDE
// this set appearing in the shim dir would silently shadow a real binary on PATH.
const std::set<std::string> kKnownBrowserNames = {
    "google-chrome", "google-chrome-stable", "chromium", "chromium-browser",
    "chrome",        "msedge",               "firefox"};

}  // namespace

// ---------------------------------------------------------------------------
// Disabled (the DEFAULT) is a strict no-op: no dirs, no env, no shim dir.
// ---------------------------------------------------------------------------

// A default-constructed BrowserConfig (enabled=false) must touch NOTHING on disk —
// not even the `<root>/browser` parent that the enabled path would create. A
// regression that ran setup unconditionally would leave that dir behind.
TEST(BrowserDisabledRegression, DisabledCreatesNoFilesUnderRoot) {
    BrowserConfig c;  // default: disabled
    std::string root = make_root();
    std::string err;
    BrowserSetup s = setup_browser(c, root, err);

    EXPECT_TRUE(err.empty()) << err;
    EXPECT_TRUE(s.shim_dir.empty());
    EXPECT_TRUE(s.profile_dir.empty());
    EXPECT_TRUE(s.env.empty());
    // The strong regression assertion: the browser subtree was never materialized.
    EXPECT_FALSE(fs::exists(fs::path(root) / "browser"))
        << "disabled browser isolation created a <root>/browser subtree";
}

// ---------------------------------------------------------------------------
// The shim dir may ONLY contain known browser names (non-shadowing invariant).
// ---------------------------------------------------------------------------

// Every file the browser module writes into the shim dir must be a recognized
// browser launcher name. If a future change wrote a generic helper (or a catch-all)
// into the shim dir, prepending that dir to PATH would shadow the real binary of the
// same name — this test fails the moment an unexpected name appears.
TEST(BrowserDisabledRegression, ShimDirContainsOnlyKnownBrowserNames) {
    BrowserConfig c = enabled_shims_cfg();
    std::string root = make_root();
    std::string err;
    BrowserSetup s = setup_browser(c, root, err);
    ASSERT_TRUE(err.empty()) << err;
    ASSERT_FALSE(s.shim_dir.empty());

    std::size_t count = 0;
    for (const auto& ent : fs::directory_iterator(s.shim_dir)) {
        const std::string name = ent.path().filename().string();
        ++count;
        EXPECT_TRUE(kKnownBrowserNames.count(name) == 1)
            << "shim dir contains an unexpected (non-browser) name that would shadow a "
               "real binary on PATH: "
            << name;
    }
    EXPECT_EQ(count, kKnownBrowserNames.size())
        << "shim dir should hold exactly the known browser launcher names";

    // Common, unrelated tools a user relies on must NOT be present in the shim dir.
    for (const char* tool : {"sh", "bash", "env", "ls", "cat", "python3", "node",
                             "git", "curl", "wget"}) {
        EXPECT_FALSE(fs::exists(fs::path(s.shim_dir) / tool))
            << "browser shim dir shadows a non-browser tool: " << tool;
    }
}

// ---------------------------------------------------------------------------
// Prepending the shim dir to PATH must NOT shadow a non-browser binary.
// ---------------------------------------------------------------------------

// This mirrors how the runner uses the shim dir: it PREPENDS it to the child PATH.
// A non-browser tool ("mytool") living in a later PATH entry must still resolve to
// its real location — the shim dir has no entry for it, so PATH resolution falls
// through. A browser name, by contrast, DOES resolve to the shim (positive control),
// proving the interception is name-scoped and never a blanket override.
TEST(BrowserDisabledRegression, ShimPrependDoesNotShadowNonBrowserBinary) {
    BrowserConfig c = enabled_shims_cfg();
    std::string root = make_root();
    std::string err;
    BrowserSetup s = setup_browser(c, root, err);
    ASSERT_FALSE(s.shim_dir.empty());

    // A separate "real bin" dir holding an unrelated tool AND a fake chromium.
    const std::string realbin = root + "/realbin";
    fs::create_directories(realbin);
    auto write_stub = [&](const std::string& name, const std::string& tag) {
        const std::string p = realbin + "/" + name;
        std::ofstream f(p);
        f << "#!/bin/sh\necho " << tag << "\n";
        f.close();
        fs::permissions(p, fs::perms::owner_all | fs::perms::group_read |
                               fs::perms::group_exec | fs::perms::others_read |
                               fs::perms::others_exec);
    };
    write_stub("mytool", "REAL-MYTOOL");
    write_stub("chromium", "REAL-CHROMIUM");

    // PATH with the shim dir PREPENDED (exactly the runner's ordering).
    const std::string path = s.shim_dir + ":" + realbin + ":/usr/bin:/bin";

    // The non-browser tool resolves to its REAL location (NOT shadowed by the shim dir).
    const std::string resolved =
        run_capture("env PATH='" + path + "' sh -c 'command -v mytool'");
    EXPECT_NE(resolved.find(realbin + "/mytool"), std::string::npos)
        << "prepended shim dir shadowed a non-browser binary; command -v mytool -> "
        << resolved;
    EXPECT_EQ(resolved.find(s.shim_dir + "/mytool"), std::string::npos) << resolved;

    // And actually executing it runs the real tool, not anything from the shim dir.
    const std::string ran =
        run_capture("env PATH='" + path + "' sh -c mytool");
    EXPECT_NE(ran.find("REAL-MYTOOL"), std::string::npos) << ran;

    // Positive control: a browser NAME does resolve to the shim, which in turn execs
    // the real chromium in realbin (name-scoped interception works).
    const std::string chromium_resolved =
        run_capture("env PATH='" + path + "' sh -c 'command -v chromium'");
    EXPECT_NE(chromium_resolved.find(s.shim_dir + "/chromium"), std::string::npos)
        << "browser name should resolve to the shim: " << chromium_resolved;
}
