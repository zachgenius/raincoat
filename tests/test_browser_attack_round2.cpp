// Raincoat — browser isolation, ATTACK ROUND 2.
//
// Adversarial tests that probe the launch-shim recursion / own-dir guard again, this
// time along the axis round 1 did not exercise: what the guard depends on. Only FAKE
// browser stubs (a script that prints its argv) are used — no real browser is launched.
//
// Background: the shim excludes its OWN dir from the PATH rescan two ways —
//   (1) an EXACT-STRING compare of the shim dir, and
//   (2) a canonicalized compare via `readlink -f` that is meant to recognize an
//       EQUIVALENT spelling of the shim dir (trailing slash, '.', '//', a symlink).
// Round 1 proved a trailing-slash spelling is caught... but only because its harness
// ran with `readlink` reachable. Guard (2) is gated on `command -v readlink`: when the
// child's PATH does not contain a dir holding `readlink` (a minimal/hardened sandbox
// PATH, or a PATH the child itself trimmed), guard (2) SILENTLY becomes a no-op and only
// the spelling-fragile guard (1) remains.
//
// DEFECT (EXPECTED FAIL): with the shim dir present on PATH under an equivalent spelling
// (trailing slash) AND `readlink` NOT on PATH, the shim resolves ITSELF as the "real"
// browser, self-execs, and the re-entry sentinel then routes to the hard-coded fallbacks
// — BYPASSING the real browser that was actually sitting on PATH. The user's configured
// browser is never launched (here: exit 127), even though it was resolvable.
//
// The remaining tests PASS and lock in the honest boundary: the SAME degraded spelling is
// handled correctly WHEN readlink is reachable (guard 2 works), and the degraded case
// never HANGS — the sentinel prevents an infinite self-exec loop (it is a wrong-browser
// bug, not a hang).

#include <gtest/gtest.h>
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
                 ("rc_battack2_" + std::to_string(::getpid()) + "_" +
                  std::to_string(counter++));
    fs::create_directories(p);
    return p.string();
}

// popen capture (stdout+stderr), wrapped in a hard timeout so a regressed shim that
// truly recursed cannot hang the suite.
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

// A fake "real browser" that announces itself and dumps its argv.
void write_marker_stub(const std::string& path, const std::string& marker) {
    std::ofstream f(path);
    f << "#!/bin/sh\n"
      << "echo " << marker << "\n"
      << "for a in \"$@\"; do echo \"ARG<$a>\"; done\n";
    f.close();
    fs::permissions(path, fs::perms::owner_all | fs::perms::group_read |
                              fs::perms::group_exec | fs::perms::others_read |
                              fs::perms::others_exec);
}

}  // namespace

// ---------------------------------------------------------------------------
// DEFECT (EXPECTED FAIL): the own-dir guard degrades to a spelling-fragile
// string compare whenever `readlink` is not reachable on the child PATH. A
// trailing-slash spelling of the shim dir then makes the shim resolve ITSELF,
// so the REAL browser on PATH is never launched.
//
// We use `msedge`, whose hard-coded fallbacks (/opt/microsoft/..., microsoft-edge)
// are absent on CI, so the failure is deterministic: a correct shim execs the fake
// msedge on PATH; the buggy shim self-resolves, hits no fallback, and exits 127.
// ---------------------------------------------------------------------------
TEST(BrowserAttack2, SpellingFragileWithoutReadlinkMissesRealBrowser) {
    BrowserConfig c = enabled_cfg();
    std::string err;
    std::string root = make_root();
    BrowserSetup s = setup_browser(c, root, err);
    ASSERT_TRUE(err.empty()) << err;
    ASSERT_FALSE(s.shim_dir.empty());

    // A FAKE real msedge on PATH in its own dir.
    const std::string fake_dir = root + "/fakebin";
    fs::create_directories(fake_dir);
    write_marker_stub(fake_dir + "/msedge", "REAL-FAKE-MSEDGE");

    // Invoke msedge BY NAME with a child PATH that (a) spells the shim dir with a
    // TRAILING SLASH and (b) contains NO dir holding `readlink` (no /usr/bin, /bin).
    // `/usr/bin/env` is called by absolute path so the harness itself is unaffected;
    // it resolves `msedge` to <shim>//msedge first (the shim), whose $0 therefore carries
    // the trailing-slash spelling. A correct guard would still skip its own dir and reach
    // <fake_dir>/msedge; the current guard cannot (readlink is unreachable) and self-resolves.
    const std::string cmd = "/usr/bin/env PATH='" + s.shim_dir + "/:" + fake_dir +
                            "' msedge probe-arg";
    const std::string out = run_capture(cmd);

    EXPECT_NE(out.find("REAL-FAKE-MSEDGE"), std::string::npos)
        << "the real msedge on PATH was never launched; the own-dir guard self-resolved "
           "because `readlink` was not reachable and the trailing-slash spelling defeated "
           "the exact-string compare:\n"
        << out;
    // When correct, the isolation flags are prepended before the user's arg.
    EXPECT_NE(out.find("ARG<--user-data-dir=" + s.profile_dir + ">"), std::string::npos)
        << out;
    EXPECT_NE(out.find("ARG<probe-arg>"), std::string::npos) << out;
}

// ---------------------------------------------------------------------------
// BOUNDARY (PASS): the SAME trailing-slash spelling is handled correctly when
// `readlink` IS reachable — guard (2) canonicalizes and skips the shim's own dir,
// so the real browser on PATH is found. This proves the defect above is exactly the
// readlink dependency, and that a readlink-independent fix is what is missing.
// ---------------------------------------------------------------------------
TEST(BrowserAttack2, TrailingSlashIsHandledWhenReadlinkReachable) {
    BrowserConfig c = enabled_cfg();
    std::string err;
    std::string root = make_root();
    BrowserSetup s = setup_browser(c, root, err);
    ASSERT_FALSE(s.shim_dir.empty());

    const std::string fake_dir = root + "/fakebin";
    fs::create_directories(fake_dir);
    write_marker_stub(fake_dir + "/msedge", "REAL-FAKE-MSEDGE");

    // Identical to the defect case but WITH /usr/bin:/bin on PATH so `readlink` resolves.
    const std::string cmd = "/usr/bin/env PATH='" + s.shim_dir + "/:" + fake_dir +
                            ":/usr/bin:/bin' msedge probe-arg";
    const std::string out = run_capture(cmd);

    EXPECT_NE(out.find("REAL-FAKE-MSEDGE"), std::string::npos)
        << "with readlink reachable the canonical guard must skip the shim's own dir and "
           "reach the real msedge on PATH:\n"
        << out;
    EXPECT_NE(out.find("ARG<--user-data-dir=" + s.profile_dir + ">"), std::string::npos)
        << out;
}

// ---------------------------------------------------------------------------
// NO-HANG (PASS): even in the degraded (readlink-absent, trailing-slash) case the
// shim must NOT infinite-loop. The re-entry sentinel (_RC_BROWSER_SHIM) guarantees
// termination — so the defect above is a wrong-browser / failed-launch bug, never a
// hang. msedge has no CI fallback, so the degraded run exits promptly (127), not 124/137.
// ---------------------------------------------------------------------------
TEST(BrowserAttack2, DegradedGuardNeverInfiniteLoops) {
    BrowserConfig c = enabled_cfg();
    std::string err;
    std::string root = make_root();
    BrowserSetup s = setup_browser(c, root, err);
    ASSERT_FALSE(s.shim_dir.empty());

    // Trailing-slash shim dir, no readlink on PATH, no real msedge anywhere. A regressed
    // (sentinel-less) shim would self-exec forever; `timeout` would then SIGKILL it.
    const std::string cmd = "timeout -s KILL 5 /usr/bin/env PATH='" + s.shim_dir +
                            "/:/raincoat-no-such-dir' msedge probe";
    int rc = std::system((cmd + " >/dev/null 2>&1").c_str());
    int code = WIFEXITED(rc) ? WEXITSTATUS(rc) : -1;
    EXPECT_TRUE(code != 124 && code != 137)
        << "shim self-exec-looped in the degraded guard case (killed by timeout, exit "
        << code << "); the re-entry sentinel must guarantee termination";
}
