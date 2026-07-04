// Raincoat — attack round 2 REGRESSION GUARD for build_bwrap_argv assembly.
//
// Round 1 (test_bwrap_font_mask_regression.cpp) locked the curated-font mask and
// its coexistence with the egress profile mask + audit tmpfs — but ONLY on the
// net=Full path (bind_resolv_conf=true) and ONLY with a SINGLE egress mask target.
// This file closes the round-2 gaps a careless refactor of the mount ordering could
// silently reopen:
//
//   * net=Off shape: `--unshare-net` present, /etc/resolv.conf NOT bound (DNS is
//     gated on bind_resolv_conf), yet /etc/ssl STILL bound (TLS trust store is
//     UNCONDITIONAL) and the font mask + generic /etc files still correct. A
//     regression that gated ssl on the net mode, or that leaked a resolv.conf bind
//     while offline, or that dropped the font mask when offline, trips here.
//   * multi-target egress mask: MORE than one reachable profile alias must each be
//     shadowed by the SAME read-only empty file, in order, all AFTER the user mounts
//     and AFTER both tmpfs masks. A regression that masked only the first, used
//     --bind (writable) instead of --ro-bind, or reordered the mask before the user
//     mounts (so it no longer overlays them) trips here.
//   * whole-argv destination uniqueness: across the full runner shape (curated fonts
//     + ssl/resolv + the three generic /etc user mounts + audit tmpfs + egress mask),
//     no two binds fight over the same destination path. This is the "/etc binds
//     don't collide with resolv.conf/ssl" guarantee, generalized to every dest.
//
// PURE, host-independent argv-ordering assertions (no bwrap needed).
#include <gtest/gtest.h>

#include <set>
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
int indexOfTmpfs(const Argv& a, const std::string& target) {
    for (int i = 0; i + 1 < static_cast<int>(a.size()); ++i)
        if (a[i] == "--tmpfs" && a[i + 1] == target) return i;
    return -1;
}

Config baseCfg(NetMode net) {
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

// The runner-appended generic /etc files (same order runner.cpp step 5b emits them).
std::vector<Mount> etcMounts() {
    return {
        mnt("/host/cwd", "/host/cwd", MountMode::ReadWrite),
        mnt("/r/etc/hostname", "/etc/hostname", MountMode::ReadOnly),
        mnt("/r/etc/hosts", "/etc/hosts", MountMode::ReadOnly),
        mnt("/usr/share/zoneinfo/UTC", "/etc/localtime", MountMode::ReadOnly),
    };
}

}  // namespace

// ---------------------------------------------------------------------------
// net=Off shape: DNS omitted, TLS retained, font mask + /etc all intact.
// ---------------------------------------------------------------------------

// binds_resolv_conf(Off)==false → the caller passes false → NO resolv.conf bind.
TEST(Attack2Regression, NetOffOmitsResolvConf) {
    Argv a = build_bwrap_argv("/usr/bin/bwrap", baseCfg(NetMode::Off), etcMounts(), env1(),
                              "/fh", "/tmp", /*bind_resolv_conf=*/false, "/fh-fc", "", "/out",
                              "", {}, kCurated);
    EXPECT_FALSE(hasTriple(a, "--ro-bind-try", "/etc/resolv.conf", "/etc/resolv.conf"));
    EXPECT_EQ(countTok(a, "/etc/resolv.conf"), 0);
}

// SECURITY/HONESTY: net=Off must genuinely isolate — `--unshare-net` present.
TEST(Attack2Regression, NetOffEmitsUnshareNet) {
    Argv a = build_bwrap_argv("/usr/bin/bwrap", baseCfg(NetMode::Off), etcMounts(), env1(),
                              "/fh", "/tmp", /*bind_resolv_conf=*/false, "/fh-fc", "", "/out",
                              "", {}, kCurated);
    EXPECT_TRUE(has(a, "--unshare-net"));
}

// The TLS trust store (/etc/ssl) is UNCONDITIONAL: it must be bound even offline
// (no resolv.conf), so a regression that folded ssl into the DNS gate is caught.
TEST(Attack2Regression, EtcSslBoundEvenWhenOfflineAndDnsAbsent) {
    Argv a = build_bwrap_argv("/usr/bin/bwrap", baseCfg(NetMode::Off), etcMounts(), env1(),
                              "/fh", "/tmp", /*bind_resolv_conf=*/false, "/fh-fc", "", "/out",
                              "", {}, kCurated);
    EXPECT_TRUE(hasTriple(a, "--ro-bind-try", "/etc/ssl", "/etc/ssl"));
    EXPECT_FALSE(has(a, "/etc/resolv.conf")) << "ssl must not drag DNS in when offline";
}

// The font mask is independent of the net mode: offline runs still mask the host
// font tree and re-bind exactly the curated set.
TEST(Attack2Regression, FontMaskIntactWhenOffline) {
    Argv a = build_bwrap_argv("/usr/bin/bwrap", baseCfg(NetMode::Off), etcMounts(), env1(),
                              "/fh", "/tmp", /*bind_resolv_conf=*/false, "/fh-fc", "", "/out",
                              "", {}, kCurated);
    int usr = indexOfTriple(a, "--ro-bind", "/usr", "/usr");
    int tmpfs = indexOfTmpfs(a, "/usr/share/fonts");
    ASSERT_GE(usr, 0);
    ASSERT_GE(tmpfs, 0);
    EXPECT_LT(usr, tmpfs);
    for (const auto& d : kCurated) {
        int idx = indexOfTriple(a, "--ro-bind", d, d);
        ASSERT_GE(idx, 0) << "curated dir not re-bound offline: " << d;
        EXPECT_GT(idx, tmpfs);
    }
}

// The generic /etc files survive offline and land AFTER the (still-present) ssl bind.
TEST(Attack2Regression, GenericEtcIntactWhenOffline) {
    Argv a = build_bwrap_argv("/usr/bin/bwrap", baseCfg(NetMode::Off), etcMounts(), env1(),
                              "/fh", "/tmp", /*bind_resolv_conf=*/false, "/fh-fc", "", "/out",
                              "", {}, kCurated);
    int ssl = indexOfTriple(a, "--ro-bind-try", "/etc/ssl", "/etc/ssl");
    int hostname = indexOfTriple(a, "--ro-bind", "/r/etc/hostname", "/etc/hostname");
    int hosts = indexOfTriple(a, "--ro-bind", "/r/etc/hosts", "/etc/hosts");
    int localtime = indexOfTriple(a, "--ro-bind", "/usr/share/zoneinfo/UTC", "/etc/localtime");
    for (int idx : {ssl, hostname, hosts, localtime}) ASSERT_GE(idx, 0);
    EXPECT_LT(ssl, hostname);
    EXPECT_LT(ssl, hosts);
    EXPECT_LT(ssl, localtime);
}

// ---------------------------------------------------------------------------
// Multi-target egress profile mask (more than one reachable alias).
// ---------------------------------------------------------------------------

// Two reachable profile paths → each shadowed by the SAME empty file, both AFTER
// the user cwd mount they overlay and AFTER both tmpfs masks, both read-only.
TEST(Attack2Regression, MultiTargetEgressMaskShadowsEachAliasReadOnly) {
    const std::vector<std::string> mask_files = {
        "/host/cwd/profile.toml",
        "/host/cwd/nested/alias.toml",
    };
    Argv a = build_bwrap_argv(
        "/usr/bin/bwrap", baseCfg(NetMode::Full), etcMounts(), env1(), "/fh", "/tmp",
        /*bind_resolv_conf=*/true, "/fh-fc", /*audit_mask_dir=*/"/host/cwd/.raincoat", "/out",
        /*mask_empty_file=*/"/root/.rc-empty", mask_files, kCurated);

    int cwd_mount = indexOfTriple(a, "--bind", "/host/cwd", "/host/cwd");
    int font_tmpfs = indexOfTmpfs(a, "/usr/share/fonts");
    int audit_tmpfs = indexOfTmpfs(a, "/host/cwd/.raincoat");
    ASSERT_GE(cwd_mount, 0);
    ASSERT_GE(font_tmpfs, 0);
    ASSERT_GE(audit_tmpfs, 0);

    for (const auto& f : mask_files) {
        // Shadowed with the ONE empty file, read-only (never --bind).
        EXPECT_TRUE(hasTriple(a, "--ro-bind", "/root/.rc-empty", f)) << f;
        EXPECT_FALSE(hasTriple(a, "--bind", "/root/.rc-empty", f)) << f << " must be read-only";
        int idx = indexOfTriple(a, "--ro-bind", "/root/.rc-empty", f);
        ASSERT_GE(idx, 0) << f;
        EXPECT_GT(idx, cwd_mount) << "mask must overlay the cwd mount: " << f;
        EXPECT_GT(idx, font_tmpfs) << f;
        EXPECT_GT(idx, audit_tmpfs) << f;
    }
    // The single empty-file source is reused, not duplicated per target beyond the
    // two mask binds (source token appears exactly once per mask target).
    EXPECT_EQ(countTok(a, "/root/.rc-empty"), static_cast<int>(mask_files.size()));
}

// Mask targets preserve the given order (deterministic, matches runner intent).
TEST(Attack2Regression, MultiTargetEgressMaskPreservesOrder) {
    const std::vector<std::string> mask_files = {
        "/host/cwd/a.toml", "/host/cwd/b.toml", "/host/cwd/c.toml"};
    Argv a = build_bwrap_argv(
        "/usr/bin/bwrap", baseCfg(NetMode::Full), etcMounts(), env1(), "/fh", "/tmp", true,
        "/fh-fc", "/host/cwd/.raincoat", "/out", "/root/.rc-empty", mask_files, kCurated);
    int prev = -1;
    for (const auto& f : mask_files) {
        int idx = indexOfTriple(a, "--ro-bind", "/root/.rc-empty", f);
        ASSERT_GE(idx, 0) << f;
        EXPECT_GT(idx, prev) << "mask order not preserved at " << f;
        prev = idx;
    }
}

// An empty mask_files list (or empty mask_empty_file) emits NO mask bind — the
// no-egress / opted-out path leaves the profile untouched.
TEST(Attack2Regression, NoEgressMaskWhenListEmpty) {
    Argv a = build_bwrap_argv("/usr/bin/bwrap", baseCfg(NetMode::Full), etcMounts(), env1(),
                              "/fh", "/tmp", true, "/fh-fc", "/host/cwd/.raincoat", "/out",
                              /*mask_empty_file=*/"", /*mask_files=*/{}, kCurated);
    EXPECT_FALSE(has(a, "/root/.rc-empty"));
    // --ro-bind (exact token, NOT --ro-bind-try): /usr + 2 curated + font_dir +
    // 3 generic /etc files == 7. ssl/resolv use --ro-bind-try and are not counted.
    EXPECT_EQ(countTok(a, "--ro-bind"), 7);
}

// ---------------------------------------------------------------------------
// Whole-argv destination uniqueness across the full runner shape.
// ---------------------------------------------------------------------------

// No two bind flags share the same DESTINATION path. This is the general form of
// "the /etc binds don't collide with resolv.conf/ssl": scanning every
// --bind/--ro-bind/--ro-bind-try triple, each destination is unique EXCEPT the
// deliberate egress-mask overlay (empty file over a profile that also sits under a
// user mount) — which is an intentional shadow, not an accidental collision.
TEST(Attack2Regression, NoAccidentalDuplicateBindDestinations) {
    const std::vector<std::string> mask_files = {"/host/cwd/profile.toml"};
    Argv a = build_bwrap_argv(
        "/usr/bin/bwrap", baseCfg(NetMode::Full), etcMounts(), env1(), "/fh", "/tmp", true,
        "/fh-fc", "/host/cwd/.raincoat", "/out", "/root/.rc-empty", mask_files, kCurated);

    std::multiset<std::string> dests;
    for (int i = 0; i + 2 < static_cast<int>(a.size()); ++i) {
        const std::string& f = a[i];
        if (f == "--bind" || f == "--ro-bind" || f == "--ro-bind-try") dests.insert(a[i + 2]);
    }
    // Only the egress overlay legitimately targets an already-bound dest
    // (/host/cwd/profile.toml sits under the /host/cwd cwd mount). Every OTHER
    // destination must be unique.
    for (const auto& d : dests) {
        if (d == "/host/cwd/profile.toml") continue;  // intentional overlay
        EXPECT_EQ(dests.count(d), 1u) << "duplicate bind destination (collision): " << d;
    }
}

// The five canonical /etc destinations are each a bind dest exactly once (ssl and
// resolv via --ro-bind-try src==dst; the three generic files via --ro-bind).
TEST(Attack2Regression, EtcDestinationsEachBoundExactlyOnce) {
    Argv a = build_bwrap_argv("/usr/bin/bwrap", baseCfg(NetMode::Full), etcMounts(), env1(),
                              "/fh", "/tmp", true, "/fh-fc", "/host/cwd/.raincoat", "/out",
                              "/root/.rc-empty", {"/host/cwd/profile.toml"}, kCurated);
    for (const char* t : {"/etc/ssl", "/etc/resolv.conf", "/etc/hostname", "/etc/hosts",
                          "/etc/localtime"}) {
        int dest_hits = 0;
        for (int i = 0; i + 2 < static_cast<int>(a.size()); ++i) {
            const std::string& f = a[i];
            if ((f == "--bind" || f == "--ro-bind" || f == "--ro-bind-try") && a[i + 2] == t)
                ++dest_hits;
        }
        EXPECT_EQ(dest_hits, 1) << "/etc dest collided or missing: " << t;
    }
}
