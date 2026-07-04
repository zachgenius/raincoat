// Raincoat — attack round 1 REGRESSION GUARD for the curated-font mask.
//
// The font mask (curated_font_dirs -> `--tmpfs /usr/share/fonts` + read-only
// re-binds of exactly the curated dirs) was the most recent addition to
// build_bwrap_argv. It slots BETWEEN the base `--ro-bind /usr /usr` and the rest
// of the argv, so a careless reorder could silently:
//   * defeat the mask itself (tmpfs emitted before/at the same point as the /usr
//     bind, or a curated re-bind emitted before the tmpfs that then wipes it),
//   * disturb the /etc/ssl + /etc/resolv.conf binds (TLS / DNS), or
//   * collide with the runner-appended /etc/hostname, /etc/hosts, /etc/localtime
//     user mounts, or with the egress profile-leak mask / audit-log tmpfs.
//
// These are PURE, host-independent argv-ordering assertions (no bwrap needed).
// They lock the exact relative order proven correct against ./build/raincoat and
// integration test #19, so a future regression trips here in milliseconds instead
// of only in the heavier, host-dependent live-sandbox tests.
//
// The `curated_font_dirs` parameter of build_bwrap_argv previously had NO
// deterministic coverage at all (only the runtime integration test exercised it);
// this file closes that gap.
#include <gtest/gtest.h>

#include <string>
#include <vector>

#include "bwrap.hpp"
#include "config.hpp"

using namespace raincoat;
using Argv = std::vector<std::string>;

namespace {

int indexOf(const Argv& a, const std::string& tok) {
    for (int i = 0; i < static_cast<int>(a.size()); ++i)
        if (a[i] == tok) return i;
    return -1;
}
bool has(const Argv& a, const std::string& tok) { return indexOf(a, tok) >= 0; }
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
int indexOfTriple(const Argv& a, const std::string& x, const std::string& y,
                  const std::string& z) {
    for (int i = 0; i + 2 < static_cast<int>(a.size()); ++i)
        if (a[i] == x && a[i + 1] == y && a[i + 2] == z) return i;
    return -1;
}
// Index of the `--tmpfs <target>` pair whose target is exactly `target`; -1 if none.
int indexOfTmpfs(const Argv& a, const std::string& target) {
    for (int i = 0; i + 1 < static_cast<int>(a.size()); ++i)
        if (a[i] == "--tmpfs" && a[i + 1] == target) return i;
    return -1;
}

Config baseCfg(NetMode net = NetMode::Full) {
    Config c;
    c.net = net;
    c.workdir = "/work";
    c.command = {"cmd"};
    return c;
}
Mount mnt(std::string host, std::string sbx, MountMode m) {
    Mount x;
    x.host_path = std::move(host);
    x.sandbox_path = std::move(sbx);
    x.mode = m;
    return x;
}
EnvResolution env1() {
    EnvResolution e;
    e.resolved = {{"PATH", "/usr/bin"}};
    return e;
}

const std::vector<std::string> kCurated = {
    "/usr/share/fonts/truetype/dejavu",
    "/usr/share/fonts/opentype/noto",
};

// Font-only invocation (no /etc mounts, egress, or audit mask): isolates the mask.
Argv buildFontOnly(const std::vector<std::string>& curated = kCurated) {
    return build_bwrap_argv("/usr/bin/bwrap", baseCfg(), {}, env1(), "/fh", "/tmp",
                            /*bind_resolv_conf=*/true, /*font_dir=*/"", /*audit_mask_dir=*/"",
                            /*sandbox_out=*/"", /*mask_empty_file=*/"", /*mask_files=*/{},
                            curated);
}

// The full runner shape: curated fonts + the three runner-appended /etc mounts +
// audit tmpfs + egress profile mask, all in one call (mirrors runner.cpp).
Argv buildFull() {
    std::vector<Mount> mounts = {
        mnt("/host/cwd", "/host/cwd", MountMode::ReadWrite),  // auto-mounted cwd
        // runner step 5b appends the generic /etc files AFTER plan_mounts:
        mnt("/r/etc/hostname", "/etc/hostname", MountMode::ReadOnly),
        mnt("/r/etc/hosts", "/etc/hosts", MountMode::ReadOnly),
        mnt("/usr/share/zoneinfo/UTC", "/etc/localtime", MountMode::ReadOnly),
    };
    return build_bwrap_argv("/usr/bin/bwrap", baseCfg(), mounts, env1(), "/fh", "/tmp",
                            /*bind_resolv_conf=*/true, /*font_dir=*/"/fh-fc",
                            /*audit_mask_dir=*/"/host/cwd/.raincoat", /*sandbox_out=*/"/out",
                            /*mask_empty_file=*/"/root/.rc-empty",
                            /*mask_files=*/{"/host/cwd/profile.toml"}, kCurated);
}

}  // namespace

// ---------------------------------------------------------------------------
// Core mask shape + the defeat-the-mask ordering invariants.
// ---------------------------------------------------------------------------

// The mask is a SINGLE tmpfs on exactly /usr/share/fonts.
TEST(FontMaskRegression, TmpfsMasksUsrShareFontsExactlyOnce) {
    Argv a = buildFontOnly();
    EXPECT_TRUE(hasPair(a, "--tmpfs", "/usr/share/fonts"));
    EXPECT_EQ(countTok(a, "/usr/share/fonts"), 1);  // the /usr/share/fonts mask, exactly once
    // Two font masks are emitted: /usr/share/fonts and /usr/local/share/fonts. Both
    // sit under the base --ro-bind /usr and are scanned by the shipped fonts.conf +
    // XDG_DATA_DIRS, so both must be neutralized.
    EXPECT_EQ(countTok(a, "--tmpfs"), 2);
}

// SECURITY-CRITICAL ordering: the tmpfs must come AFTER `--ro-bind /usr /usr`, else
// the whole-/usr bind re-shadows the fresh tmpfs and the host font list leaks back.
TEST(FontMaskRegression, TmpfsFollowsUsrRoBind) {
    Argv a = buildFontOnly();
    int usr = indexOfTriple(a, "--ro-bind", "/usr", "/usr");
    int tmpfs = indexOfTmpfs(a, "/usr/share/fonts");
    ASSERT_GE(usr, 0);
    ASSERT_GE(tmpfs, 0);
    EXPECT_LT(usr, tmpfs) << "font tmpfs must overlay the /usr bind, not precede it";
}

// Each curated re-bind must come AFTER the tmpfs, or the tmpfs would wipe it.
TEST(FontMaskRegression, CuratedRebindsFollowTheTmpfs) {
    Argv a = buildFontOnly();
    int tmpfs = indexOfTmpfs(a, "/usr/share/fonts");
    ASSERT_GE(tmpfs, 0);
    for (const auto& d : kCurated) {
        int idx = indexOfTriple(a, "--ro-bind", d, d);
        ASSERT_GE(idx, 0) << "curated dir not re-bound: " << d;
        EXPECT_GT(idx, tmpfs) << "curated re-bind emitted before the tmpfs wipes it: " << d;
    }
}

// The curated dirs are re-bound read-only, at their identity path, in the given order.
TEST(FontMaskRegression, CuratedRebindsAreReadOnlyIdentityInOrder) {
    Argv a = buildFontOnly();
    int prev = -1;
    for (const auto& d : kCurated) {
        EXPECT_TRUE(hasTriple(a, "--ro-bind", d, d)) << d;
        EXPECT_FALSE(hasTriple(a, "--bind", d, d)) << d << " must be read-only";
        int idx = indexOfTriple(a, "--ro-bind", d, d);
        EXPECT_GT(idx, prev) << "curated order not preserved at " << d;
        prev = idx;
    }
}

// DISABLED-mask path: an empty curated list must emit NO tmpfs on /usr/share/fonts
// and no curated re-binds — the documented "fontconfig disabled leaves host fonts
// untouched" behavior.
TEST(FontMaskRegression, NoTmpfsOrRebindsWhenCuratedEmpty) {
    Argv a = buildFontOnly(/*curated=*/{});
    EXPECT_EQ(indexOfTmpfs(a, "/usr/share/fonts"), -1);
    EXPECT_FALSE(has(a, "/usr/share/fonts"));
    for (const auto& d : kCurated) EXPECT_FALSE(has(a, d)) << d;
    // The base /usr view is still fully present (mask absence != /usr absence).
    EXPECT_TRUE(hasTriple(a, "--ro-bind", "/usr", "/usr"));
}

// The default (no curated arg supplied) must also be the untouched-host behavior:
// the older 7-arg call sites keep their exact pre-font-mask argv.
TEST(FontMaskRegression, DefaultCallSiteEmitsNoFontMask) {
    Argv a = build_bwrap_argv("/usr/bin/bwrap", baseCfg(), {}, env1(), "/fh", "/tmp", true);
    EXPECT_EQ(indexOfTmpfs(a, "/usr/share/fonts"), -1);
    EXPECT_FALSE(has(a, "/usr/share/fonts"));
}

// ---------------------------------------------------------------------------
// The mask must NOT disturb the TLS / DNS binds.
// ---------------------------------------------------------------------------

// /etc/ssl and /etc/resolv.conf survive the mask, exactly once each, and land AFTER
// the font mask (so the mask never shadows or duplicates them).
TEST(FontMaskRegression, EtcSslAndResolvIntactAfterMask) {
    Argv a = buildFontOnly();
    EXPECT_TRUE(hasTriple(a, "--ro-bind-try", "/etc/ssl", "/etc/ssl"));
    EXPECT_TRUE(hasTriple(a, "--ro-bind-try", "/etc/resolv.conf", "/etc/resolv.conf"));
    EXPECT_EQ(countTok(a, "/etc/resolv.conf"), 2);  // one --ro-bind-try triple only
    int tmpfs = indexOfTmpfs(a, "/usr/share/fonts");
    int ssl = indexOfTriple(a, "--ro-bind-try", "/etc/ssl", "/etc/ssl");
    int resolv = indexOfTriple(a, "--ro-bind-try", "/etc/resolv.conf", "/etc/resolv.conf");
    ASSERT_GE(tmpfs, 0);
    EXPECT_LT(tmpfs, ssl);
    EXPECT_LT(tmpfs, resolv);
}

// The font mask must never touch /etc: no --tmpfs or bind whose target is under /etc.
TEST(FontMaskRegression, MaskNeverTargetsEtc) {
    Argv a = buildFontOnly();
    EXPECT_EQ(indexOfTmpfs(a, "/etc"), -1);
    EXPECT_EQ(indexOfTmpfs(a, "/etc/fonts"), -1);
}

// ---------------------------------------------------------------------------
// Full runner shape: /etc user mounts do not collide with ssl/resolv, and the
// mask coexists with the egress profile mask + the audit-log tmpfs.
// ---------------------------------------------------------------------------

// The five /etc binds (ssl, resolv.conf + the three generic files) all have DISTINCT
// sandbox targets — no two binds fight over the same path.
TEST(FontMaskRegression, EtcBindsHaveDistinctTargetsNoCollision) {
    Argv a = buildFull();
    for (const char* t : {"/etc/ssl", "/etc/resolv.conf", "/etc/hostname", "/etc/hosts",
                          "/etc/localtime"}) {
        // Each target appears exactly once as a bind DESTINATION. ssl/resolv use
        // --ro-bind-try (target repeated as src==dst); the generic files use --ro-bind
        // with a distinct host source, so the target token appears exactly once.
        int dest_hits = 0;
        for (int i = 0; i + 1 < static_cast<int>(a.size()); ++i) {
            const std::string& flag = a[i];
            if (flag == "--ro-bind" || flag == "--bind" || flag == "--ro-bind-try") {
                if (i + 2 < static_cast<int>(a.size()) && a[i + 2] == t) ++dest_hits;
            }
        }
        EXPECT_EQ(dest_hits, 1) << "target collided or missing: " << t;
    }
}

// The generic /etc files are bound (as user mounts) AFTER the base ssl/resolv binds,
// so if they ever shared a path the generic file would win — and after the font mask.
TEST(FontMaskRegression, GenericEtcMountsFollowSslResolvAndMask) {
    Argv a = buildFull();
    int tmpfs = indexOfTmpfs(a, "/usr/share/fonts");
    int ssl = indexOfTriple(a, "--ro-bind-try", "/etc/ssl", "/etc/ssl");
    int hostname = indexOfTriple(a, "--ro-bind", "/r/etc/hostname", "/etc/hostname");
    int hosts = indexOfTriple(a, "--ro-bind", "/r/etc/hosts", "/etc/hosts");
    int localtime = indexOfTriple(a, "--ro-bind", "/usr/share/zoneinfo/UTC", "/etc/localtime");
    for (int idx : {tmpfs, ssl, hostname, hosts, localtime}) ASSERT_GE(idx, 0);
    EXPECT_LT(tmpfs, ssl);
    EXPECT_LT(ssl, hostname);
    EXPECT_LT(ssl, hosts);
    EXPECT_LT(ssl, localtime);
}

// Font mask + egress profile mask + audit tmpfs coexist: TWO distinct --tmpfs (fonts
// then audit), and the egress empty-file bind is present and lands AFTER the user
// mounts (so it overlays them) while the font re-binds land BEFORE them.
TEST(FontMaskRegression, MaskCoexistsWithEgressAndAuditMasks) {
    Argv a = buildFull();
    int font_tmpfs = indexOfTmpfs(a, "/usr/share/fonts");
    int audit_tmpfs = indexOfTmpfs(a, "/host/cwd/.raincoat");
    ASSERT_GE(font_tmpfs, 0);
    ASSERT_GE(audit_tmpfs, 0);
    EXPECT_EQ(countTok(a, "--tmpfs"), 3)
        << "the two font masks (/usr/share/fonts + /usr/local/share/fonts) + audit tmpfs";
    EXPECT_LT(font_tmpfs, audit_tmpfs) << "font mask precedes the audit mask";

    // Egress profile-leak mask: empty file bound over the reachable profile, AFTER the
    // cwd user mount it shadows and AFTER the audit tmpfs.
    int egress = indexOfTriple(a, "--ro-bind", "/root/.rc-empty", "/host/cwd/profile.toml");
    int cwd_mount = indexOfTriple(a, "--bind", "/host/cwd", "/host/cwd");
    ASSERT_GE(egress, 0);
    ASSERT_GE(cwd_mount, 0);
    EXPECT_LT(cwd_mount, egress) << "egress mask must overlay the cwd mount";
    EXPECT_LT(audit_tmpfs, egress);

    // The curated font re-binds precede the user cwd mount (they sit in the base view).
    int dejavu = indexOfTriple(a, "--ro-bind", kCurated[0], kCurated[0]);
    ASSERT_GE(dejavu, 0);
    EXPECT_LT(dejavu, cwd_mount);
}

// Whole-argv sanity: the mask changes nothing downstream — env, chdir and the command
// tail are still emitted last and intact alongside the font mask.
TEST(FontMaskRegression, EnvChdirCommandStillTrailAfterMask) {
    Argv a = buildFull();
    int clearenv = indexOf(a, "--clearenv");
    int chdir = indexOf(a, "--chdir");
    int font_tmpfs = indexOfTmpfs(a, "/usr/share/fonts");
    ASSERT_GE(clearenv, 0);
    ASSERT_GE(chdir, 0);
    ASSERT_GE(font_tmpfs, 0);
    EXPECT_LT(font_tmpfs, clearenv);
    EXPECT_LT(clearenv, chdir);
    EXPECT_EQ(a.back(), "cmd");
}
