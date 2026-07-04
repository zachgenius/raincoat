// Raincoat — attack round 3 REGRESSION: the /usr/local/share/fonts mask must not
// break the run on hosts where that directory does not exist.
//
// BACKGROUND. Round 1 fixed a fingerprint leak by ALSO masking
// /usr/local/share/fonts (it sits under the base `--ro-bind /usr /usr` and is scanned
// by the shipped fonts.conf + the pinned XDG_DATA_DIRS). The fix emitted an
// UNCONDITIONAL `--tmpfs /usr/local/share/fonts` whenever any curated font dir exists.
//
// THE REGRESSION. Unlike /usr/share/fonts (guaranteed to exist because every curated
// dir — /usr/share/fonts/truetype/dejavu, .../noto, /usr/share/fonts/opentype/noto —
// lives beneath it), /usr/local/share/fonts sits under /usr/local, an FHS "local admin
// install" tree that NO distro package populates (verified: `dpkg -S /usr/local/share`
// finds nothing). It is therefore frequently ABSENT — minimal servers, CI runners,
// containers, fresh dev boxes — even while fonts-dejavu is installed under
// /usr/share/fonts. When it is absent, bwrap cannot create the tmpfs mountpoint under
// the read-only /usr bind and ABORTS THE WHOLE RUN:
//
//     bwrap: Can't mkdir /usr/local/share/fonts: Read-only file system
//
// That breaks EVERY raincoat invocation on such a host, including plain
// `raincoat -- env` — a core-MVP regression. bwrap has no `--tmpfs-try`, so the guard
// must be host-side: the runner passes mask_usr_local_fonts only when the dir exists.
//
// These tests lock the guard: with mask_usr_local_fonts=false the /usr/local/share/
// fonts tmpfs is NOT emitted (while /usr/share/fonts and the curated re-binds stay
// intact); with it true (the default) both masks are emitted. A live bwrap test
// reproduces the exact failure mode + proves that dropping the mask fixes it.
#include <gtest/gtest.h>

#include <cstdlib>
#include <string>
#include <vector>

#include "bwrap.hpp"
#include "config.hpp"

using namespace raincoat;
using Argv = std::vector<std::string>;

namespace {

int countTok(const Argv& a, const std::string& tok) {
    int c = 0;
    for (const auto& s : a)
        if (s == tok) ++c;
    return c;
}
bool hasPair(const Argv& a, const std::string& x, const std::string& y) {
    for (int i = 0; i + 1 < static_cast<int>(a.size()); ++i)
        if (a[i] == x && a[i + 1] == y) return true;
    return false;
}
bool hasTriple(const Argv& a, const std::string& x, const std::string& y,
               const std::string& z) {
    for (int i = 0; i + 2 < static_cast<int>(a.size()); ++i)
        if (a[i] == x && a[i + 1] == y && a[i + 2] == z) return true;
    return false;
}

const std::vector<std::string> kCurated = {
    "/usr/share/fonts/truetype/dejavu",
    "/usr/share/fonts/opentype/noto",
};

Config baseCfg() {
    Config c;
    c.net = NetMode::Full;
    c.workdir = "/work";
    c.command = {"cmd"};
    return c;
}
EnvResolution env1() {
    EnvResolution e;
    e.resolved = {{"PATH", "/usr/bin"}};
    return e;
}

// Font-only invocation with an explicit mask_usr_local_fonts flag.
Argv buildFontOnly(bool mask_local) {
    return build_bwrap_argv("/usr/bin/bwrap", baseCfg(), {}, env1(), "/fh", "/tmp",
                            /*bind_resolv_conf=*/true, /*font_dir=*/"", /*audit_mask_dir=*/"",
                            /*sandbox_out=*/"", /*mask_empty_file=*/"", /*mask_files=*/{},
                            kCurated, mask_local);
}

}  // namespace

// CORE FIX: when the runner determines /usr/local/share/fonts is absent it passes
// mask_usr_local_fonts=false, and build_bwrap_argv must then emit NO tmpfs for it —
// while still masking /usr/share/fonts and re-binding the curated set. An emitted
// `--tmpfs /usr/local/share/fonts` here is exactly the token that aborts bwrap on such
// a host, so its absence is what keeps `raincoat -- env` working there.
TEST(FontLocalMaskMissingDir, NoUsrLocalTmpfsWhenDirAbsent) {
    Argv a = buildFontOnly(/*mask_local=*/false);
    EXPECT_FALSE(hasPair(a, "--tmpfs", "/usr/local/share/fonts"))
        << "unconditional /usr/local/share/fonts tmpfs breaks bwrap when the dir is "
           "absent (Read-only file system), aborting even `raincoat -- env`";
    // The real isolation is unaffected: /usr/share/fonts is still masked (it is
    // guaranteed present) and the curated dirs are still re-bound read-only.
    EXPECT_TRUE(hasPair(a, "--tmpfs", "/usr/share/fonts"));
    for (const auto& d : kCurated) EXPECT_TRUE(hasTriple(a, "--ro-bind", d, d)) << d;
    // Exactly ONE font tmpfs in this shape (no audit/egress masks passed here).
    EXPECT_EQ(countTok(a, "--tmpfs"), 1);
}

// When the dir EXISTS the runner passes true and both masks are emitted (the round-1
// leak fix stays live). This is also the parameter default, so every existing call
// site keeps masking /usr/local/share/fonts.
TEST(FontLocalMaskMissingDir, BothMasksWhenDirPresent) {
    Argv a = buildFontOnly(/*mask_local=*/true);
    EXPECT_TRUE(hasPair(a, "--tmpfs", "/usr/share/fonts"));
    EXPECT_TRUE(hasPair(a, "--tmpfs", "/usr/local/share/fonts"));
    EXPECT_EQ(countTok(a, "--tmpfs"), 2);
}

// The parameter DEFAULTS to true: a call that omits it (every pre-existing call site
// and argv-ordering test) still emits the /usr/local mask, so the leak fix is not
// silently dropped where the dir is present.
TEST(FontLocalMaskMissingDir, DefaultKeepsUsrLocalMask) {
    Argv a = build_bwrap_argv("/usr/bin/bwrap", baseCfg(), {}, env1(), "/fh", "/tmp",
                              /*bind_resolv_conf=*/true, "", "", "", "", {}, kCurated);
    EXPECT_TRUE(hasPair(a, "--tmpfs", "/usr/local/share/fonts"));
}

// The guard only affects /usr/local: the base /usr view and the /usr/share/fonts mask
// are identical whether or not the /usr/local mask is emitted.
TEST(FontLocalMaskMissingDir, UsrShareMaskUnaffectedByGuard) {
    Argv on = buildFontOnly(true);
    Argv off = buildFontOnly(false);
    for (const Argv* a : {&on, &off}) {
        EXPECT_TRUE(hasTriple(*a, "--ro-bind", "/usr", "/usr"));
        EXPECT_TRUE(hasPair(*a, "--tmpfs", "/usr/share/fonts"));
    }
}

// ---------------------------------------------------------------------------
// Live bwrap reproduction of the failure mode + proof the guard fixes it.
// Skips gracefully when bwrap is unavailable / userns is denied.
// ---------------------------------------------------------------------------

namespace {
bool bwrapUsable() {
    // Same smoke shape doctor uses: if a trivial sandbox cannot run, skip.
    int rc = std::system(
        "bwrap --ro-bind /usr /usr --symlink usr/lib /lib --symlink usr/lib64 /lib64 "
        "--symlink usr/bin /bin /usr/bin/true >/dev/null 2>&1");
    return rc == 0;
}
}  // namespace

// Emulate a host WITHOUT /usr/local/share/fonts: target a guaranteed-nonexistent
// sibling under the read-only /usr bind. The unconditional mask (a `--tmpfs` on a
// missing path under ro /usr) must FAIL — this is the exact abort raincoat inflicted
// on every run of such a host.
TEST(FontLocalMaskMissingDir, LiveUnconditionalTmpfsAbortsWhenDirMissing) {
    if (!bwrapUsable()) GTEST_SKIP() << "bwrap not usable in this environment";
    int rc = std::system(
        "bwrap --ro-bind /usr /usr --symlink usr/lib /lib --symlink usr/lib64 /lib64 "
        "--symlink usr/bin /bin --tmpfs /usr/share/fonts/__rc_missing_sibling__ "
        "/usr/bin/true >/dev/null 2>&1");
    EXPECT_NE(rc, 0)
        << "a --tmpfs on a nonexistent path under the read-only /usr bind should abort "
           "bwrap; this is why the /usr/local/share/fonts mask must be guarded on "
           "existence";
}

// The SAME base mounts WITHOUT the offending tmpfs succeed — proving that dropping the
// mask when the dir is absent (the fix) restores a working sandbox.
TEST(FontLocalMaskMissingDir, LiveWithoutOffendingTmpfsSucceeds) {
    if (!bwrapUsable()) GTEST_SKIP() << "bwrap not usable in this environment";
    int rc = std::system(
        "bwrap --ro-bind /usr /usr --symlink usr/lib /lib --symlink usr/lib64 /lib64 "
        "--symlink usr/bin /bin --tmpfs /usr/share/fonts "
        "--ro-bind /usr/share/fonts /usr/share/fonts /usr/bin/true >/dev/null 2>&1");
    EXPECT_EQ(rc, 0) << "base font mask without the missing-dir tmpfs must run cleanly";
}
