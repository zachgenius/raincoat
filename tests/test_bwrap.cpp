// Raincoat — comprehensive tests for bwrap::build_bwrap_argv (PURE argv assembly).
//
// These tests are derived directly from docs/DESIGN.md ("bwrap" section) and docs/SPEC.md.
// They exercise the required behaviours AND edge cases. The module is still a stub, so this
// suite is EXPECTED TO FAIL (TDD red). It must, however, COMPILE against the stub header.
#include <gtest/gtest.h>

#include <algorithm>
#include <functional>
#include <map>
#include <string>
#include <vector>

#include "bwrap.hpp"
#include "config.hpp"

using namespace raincoat;
using Argv = std::vector<std::string>;

// ---------------------------------------------------------------------------
// Small argv-inspection helpers (kept dumb + explicit so failures are legible)
// ---------------------------------------------------------------------------

// First index of `tok` at/after `from`; -1 if absent.
static int indexOf(const Argv& a, const std::string& tok, int from = 0) {
    for (int i = from; i < static_cast<int>(a.size()); ++i)
        if (a[i] == tok) return i;
    return -1;
}

static bool has(const Argv& a, const std::string& tok) { return indexOf(a, tok) >= 0; }

static int countTok(const Argv& a, const std::string& tok) {
    int c = 0;
    for (const auto& s : a)
        if (s == tok) ++c;
    return c;
}

// Is there some i with a[i]==x && a[i+1]==y (adjacent pair)?
static bool hasPair(const Argv& a, const std::string& x, const std::string& y) {
    for (int i = 0; i + 1 < static_cast<int>(a.size()); ++i)
        if (a[i] == x && a[i + 1] == y) return true;
    return false;
}

// Is there some i with a[i]==x && a[i+1]==y && a[i+2]==z (adjacent triple)?
static bool hasTriple(const Argv& a, const std::string& x, const std::string& y,
                      const std::string& z) {
    for (int i = 0; i + 2 < static_cast<int>(a.size()); ++i)
        if (a[i] == x && a[i + 1] == y && a[i + 2] == z) return true;
    return false;
}

// Index of the flag-triple <x,y,z> start; -1 if absent.
static int indexOfTriple(const Argv& a, const std::string& x, const std::string& y,
                         const std::string& z) {
    for (int i = 0; i + 2 < static_cast<int>(a.size()); ++i)
        if (a[i] == x && a[i + 1] == y && a[i + 2] == z) return i;
    return -1;
}

// Extract every --setenv K V pair, in the order they appear.
static std::vector<std::pair<std::string, std::string>> setenvPairs(const Argv& a) {
    std::vector<std::pair<std::string, std::string>> out;
    for (int i = 0; i < static_cast<int>(a.size()); ++i) {
        if (a[i] == "--setenv" && i + 2 < static_cast<int>(a.size())) {
            out.emplace_back(a[i + 1], a[i + 2]);
            i += 2;
        }
    }
    return out;
}

// ---------------------------------------------------------------------------
// Fixture builders
// ---------------------------------------------------------------------------

static Config makeConfig(NetMode net, std::string workdir, std::vector<std::string> command) {
    Config c;
    c.net = net;
    c.workdir = std::move(workdir);
    c.command = std::move(command);
    return c;
}

static EnvResolution makeEnv(std::map<std::string, std::string> resolved) {
    EnvResolution e;
    e.resolved = std::move(resolved);
    return e;
}

static Mount mnt(std::string host, std::string sandbox, MountMode mode) {
    Mount m;
    m.host_path = std::move(host);
    m.sandbox_path = std::move(sandbox);
    m.mode = mode;
    return m;
}

// A convenient "typical" invocation used by many tests.
static Argv buildTypical(NetMode net = NetMode::Full, bool bind_resolv = true) {
    Config cfg = makeConfig(net, "/work", {"/bin/echo", "hi"});
    std::vector<Mount> mounts = {
        mnt("/host/ro", "/host/ro", MountMode::ReadOnly),
        mnt("/host/rw", "/host/rw", MountMode::ReadWrite),
    };
    EnvResolution env = makeEnv({{"HOME", "/fake/home/user"}, {"PATH", "/usr/bin"}});
    return build_bwrap_argv("/usr/bin/bwrap", cfg, mounts, env, "/fake/home/user", "/fake/tmp",
                            bind_resolv);
}

// ---------------------------------------------------------------------------
// argv[0] and core flags
// ---------------------------------------------------------------------------

TEST(Bwrap, Argv0IsBwrapPath) {
    Config cfg = makeConfig(NetMode::Full, "/work", {"true"});
    Argv a = build_bwrap_argv("/opt/custom/bwrap", cfg, {}, makeEnv({}), "/fh", "/tmp", false);
    ASSERT_FALSE(a.empty());
    EXPECT_EQ(a.front(), "/opt/custom/bwrap");
}

TEST(Bwrap, DieWithParentPresent) {
    Argv a = buildTypical();
    EXPECT_TRUE(has(a, "--die-with-parent"));
}

TEST(Bwrap, NamespaceUnshareFlagsPresent) {
    Argv a = buildTypical();
    EXPECT_TRUE(has(a, "--unshare-pid"));
    EXPECT_TRUE(has(a, "--unshare-uts"));
    EXPECT_TRUE(has(a, "--unshare-ipc"));
}

TEST(Bwrap, NamespaceUnshareFlagsOrdered) {
    Argv a = buildTypical();
    int pid = indexOf(a, "--unshare-pid");
    int uts = indexOf(a, "--unshare-uts");
    int ipc = indexOf(a, "--unshare-ipc");
    ASSERT_GE(pid, 0);
    ASSERT_GE(uts, 0);
    ASSERT_GE(ipc, 0);
    EXPECT_LT(pid, uts);
    EXPECT_LT(uts, ipc);
}

TEST(Bwrap, DieWithParentPrecedesUnshareFlags) {
    Argv a = buildTypical();
    int die = indexOf(a, "--die-with-parent");
    int pid = indexOf(a, "--unshare-pid");
    ASSERT_GE(die, 0);
    ASSERT_GE(pid, 0);
    EXPECT_LT(die, pid);
}

// ---------------------------------------------------------------------------
// Network: --unshare-net ONLY when net == Off
// ---------------------------------------------------------------------------

TEST(Bwrap, UnshareNetPresentWhenNetOff) {
    Argv a = buildTypical(NetMode::Off);
    EXPECT_TRUE(has(a, "--unshare-net"));
}

TEST(Bwrap, NoUnshareNetWhenNetFull) {
    Argv a = buildTypical(NetMode::Full);
    EXPECT_FALSE(has(a, "--unshare-net"));
}

TEST(Bwrap, UnshareNetOrderedAfterIpcWhenOff) {
    Argv a = buildTypical(NetMode::Off);
    int ipc = indexOf(a, "--unshare-ipc");
    int net = indexOf(a, "--unshare-net");
    ASSERT_GE(ipc, 0);
    ASSERT_GE(net, 0);
    EXPECT_LT(ipc, net);
}

TEST(Bwrap, UnshareNetOccursOnce) {
    Argv a = buildTypical(NetMode::Off);
    EXPECT_EQ(countTok(a, "--unshare-net"), 1);
}

// Allowlist / Ask are reserved enum values; the MVP only unshares net for Off.
TEST(Bwrap, NoUnshareNetForReservedNetModes) {
    EXPECT_FALSE(has(buildTypical(NetMode::Allowlist), "--unshare-net"));
    EXPECT_FALSE(has(buildTypical(NetMode::Ask), "--unshare-net"));
}

// ---------------------------------------------------------------------------
// Base system view: /usr ro-bind + symlinks + proc + dev
// ---------------------------------------------------------------------------

TEST(Bwrap, BaseRoBindUsr) {
    Argv a = buildTypical();
    EXPECT_TRUE(hasTriple(a, "--ro-bind", "/usr", "/usr"));
}

TEST(Bwrap, BaseSymlinks) {
    Argv a = buildTypical();
    EXPECT_TRUE(hasTriple(a, "--symlink", "usr/bin", "/bin"));
    EXPECT_TRUE(hasTriple(a, "--symlink", "usr/lib", "/lib"));
    EXPECT_TRUE(hasTriple(a, "--symlink", "usr/lib64", "/lib64"));
    EXPECT_TRUE(hasTriple(a, "--symlink", "usr/sbin", "/sbin"));
}

TEST(Bwrap, BaseProcAndDev) {
    Argv a = buildTypical();
    EXPECT_TRUE(hasPair(a, "--proc", "/proc"));
    EXPECT_TRUE(hasPair(a, "--dev", "/dev"));
}

// ---------------------------------------------------------------------------
// /proc/cpuinfo mask (fake_cpuinfo_file)
// ---------------------------------------------------------------------------

// Rebuild buildTypical with an explicit fake-cpuinfo file passed positionally.
static Argv buildWithCpuinfo(const std::string& cpuinfo_file, bool mount_proc = true) {
    Config cfg = makeConfig(NetMode::Full, "/work", {"/bin/echo", "hi"});
    cfg.ext.backend.mount_proc = mount_proc;
    EnvResolution env = makeEnv({{"HOME", "/fake/home/user"}, {"PATH", "/usr/bin"}});
    return build_bwrap_argv("/usr/bin/bwrap", cfg, {}, env, "/fake/home/user", "/fake/tmp",
                            true, "", "", "", "", {}, {}, true, cpuinfo_file);
}

TEST(Bwrap, NoCpuinfoBindByDefault) {
    // Default fake_cpuinfo_file is "" => cpuinfo is never bound (backward compatible).
    Argv a = buildTypical();
    EXPECT_FALSE(hasTriple(a, "--ro-bind", "/fake/cpuinfo", "/proc/cpuinfo"));
    EXPECT_EQ(indexOf(a, "/proc/cpuinfo"), -1);
}

TEST(Bwrap, CpuinfoBoundWhenFilePassed) {
    Argv a = buildWithCpuinfo("/sbx/.rc-cpuinfo");
    EXPECT_TRUE(hasTriple(a, "--ro-bind", "/sbx/.rc-cpuinfo", "/proc/cpuinfo"));
}

TEST(Bwrap, CpuinfoBindOrderedAfterProcMount) {
    // The overlay is meaningless unless it lands after --proc /proc mounts procfs.
    Argv a = buildWithCpuinfo("/sbx/.rc-cpuinfo");
    // --proc /proc is a pair, not a triple; find its index directly.
    int procIdx = -1;
    for (int i = 0; i + 1 < static_cast<int>(a.size()); ++i)
        if (a[i] == "--proc" && a[i + 1] == "/proc") { procIdx = i; break; }
    int bindIdx = indexOfTriple(a, "--ro-bind", "/sbx/.rc-cpuinfo", "/proc/cpuinfo");
    ASSERT_GE(procIdx, 0);
    ASSERT_GE(bindIdx, 0);
    EXPECT_LT(procIdx, bindIdx);
}

TEST(Bwrap, NoCpuinfoBindWhenProcNotMounted) {
    // With proc unmounted there is no /proc to overlay, so the bind is suppressed.
    Argv a = buildWithCpuinfo("/sbx/.rc-cpuinfo", /*mount_proc=*/false);
    EXPECT_FALSE(has(a, "--proc"));
    EXPECT_FALSE(hasTriple(a, "--ro-bind", "/sbx/.rc-cpuinfo", "/proc/cpuinfo"));
}

TEST(Bwrap, RoBindUsrPrecedesSymlinks) {
    Argv a = buildTypical();
    int usr = indexOfTriple(a, "--ro-bind", "/usr", "/usr");
    int bin = indexOfTriple(a, "--symlink", "usr/bin", "/bin");
    ASSERT_GE(usr, 0);
    ASSERT_GE(bin, 0);
    EXPECT_LT(usr, bin);
}

// ---------------------------------------------------------------------------
// /etc/ssl always; /etc/resolv.conf only when bind_resolv_conf
// ---------------------------------------------------------------------------

TEST(Bwrap, EtcSslAlwaysBound) {
    EXPECT_TRUE(hasTriple(buildTypical(NetMode::Full, true), "--ro-bind-try", "/etc/ssl", "/etc/ssl"));
    EXPECT_TRUE(hasTriple(buildTypical(NetMode::Off, false), "--ro-bind-try", "/etc/ssl", "/etc/ssl"));
}

TEST(Bwrap, ResolvConfBoundWhenFlagTrue) {
    Argv a = buildTypical(NetMode::Full, /*bind_resolv=*/true);
    EXPECT_TRUE(hasTriple(a, "--ro-bind-try", "/etc/resolv.conf", "/etc/resolv.conf"));
}

TEST(Bwrap, ResolvConfNotBoundWhenFlagFalse) {
    Argv a = buildTypical(NetMode::Off, /*bind_resolv=*/false);
    EXPECT_FALSE(hasTriple(a, "--ro-bind-try", "/etc/resolv.conf", "/etc/resolv.conf"));
    EXPECT_FALSE(has(a, "/etc/resolv.conf"));
}

// bind_resolv_conf is an independent parameter: it governs resolv.conf even if net==Off.
TEST(Bwrap, ResolvConfFollowsFlagNotNetMode) {
    Argv a = buildTypical(NetMode::Off, /*bind_resolv=*/true);
    EXPECT_TRUE(hasTriple(a, "--ro-bind-try", "/etc/resolv.conf", "/etc/resolv.conf"));
}

// ---------------------------------------------------------------------------
// Fake home + sandbox tmp binds (read-write)
// ---------------------------------------------------------------------------

TEST(Bwrap, FakeHomeBind) {
    Config cfg = makeConfig(NetMode::Full, "/work", {"true"});
    Argv a = build_bwrap_argv("/usr/bin/bwrap", cfg, {}, makeEnv({}), "/sbx/home/user",
                              "/sbx/tmp", false);
    EXPECT_TRUE(hasTriple(a, "--bind", "/sbx/home/user", "/sbx/home/user"));
}

TEST(Bwrap, SandboxTmpBind) {
    Config cfg = makeConfig(NetMode::Full, "/work", {"true"});
    Argv a = build_bwrap_argv("/usr/bin/bwrap", cfg, {}, makeEnv({}), "/sbx/home/user",
                              "/sbx/tmp", false);
    EXPECT_TRUE(hasTriple(a, "--bind", "/sbx/tmp", "/sbx/tmp"));
}

// ---------------------------------------------------------------------------
// Generic hostname: a fresh UTS namespace must carry a generic host name so the
// real machine name never leaks through.
// ---------------------------------------------------------------------------

TEST(Bwrap, GenericHostnameSet) {
    Argv a = buildTypical();
    // --unshare-uts is required for --hostname to take effect.
    EXPECT_TRUE(has(a, "--unshare-uts"));
    EXPECT_TRUE(hasPair(a, "--hostname", "sandbox"));
    // The host's real name must not be what we hand bwrap.
    EXPECT_EQ(countTok(a, "--hostname"), 1);
}

// ---------------------------------------------------------------------------
// Writable scratch `out` dir: bound read-write when supplied, absent otherwise.
// ---------------------------------------------------------------------------

TEST(Bwrap, OutScratchDirBoundWhenSupplied) {
    Config cfg = makeConfig(NetMode::Full, "/work", {"true"});
    Argv a = build_bwrap_argv("/usr/bin/bwrap", cfg, {}, makeEnv({}), "/sbx/home/user",
                              "/sbx/tmp", false, /*font_dir=*/"", /*audit_mask_dir=*/"",
                              /*sandbox_out=*/"/sbx/out");
    EXPECT_TRUE(hasTriple(a, "--bind", "/sbx/out", "/sbx/out"));
    // Scratch is writable, never read-only.
    EXPECT_FALSE(hasTriple(a, "--ro-bind", "/sbx/out", "/sbx/out"));
}

TEST(Bwrap, OutScratchDirAbsentWhenEmpty) {
    Config cfg = makeConfig(NetMode::Full, "/work", {"true"});
    Argv a = build_bwrap_argv("/usr/bin/bwrap", cfg, {}, makeEnv({}), "/sbx/home/user",
                              "/sbx/tmp", false);  // sandbox_out defaults to ""
    EXPECT_FALSE(has(a, "/sbx/out"));
}

// ---------------------------------------------------------------------------
// Curated fontconfig dir: bound read-only when supplied so FONTCONFIG_FILE/PATH
// actually resolve inside the sandbox.
// ---------------------------------------------------------------------------

TEST(Bwrap, FontDirBoundReadOnlyWhenSupplied) {
    Config cfg = makeConfig(NetMode::Full, "/work", {"true"});
    Argv a = build_bwrap_argv("/usr/bin/bwrap", cfg, {}, makeEnv({}), "/sbx/home/user",
                              "/sbx/tmp", false, /*font_dir=*/"/sbx/fontconfig");
    EXPECT_TRUE(hasTriple(a, "--ro-bind", "/sbx/fontconfig", "/sbx/fontconfig"));
}

TEST(Bwrap, FontDirAbsentWhenEmpty) {
    Config cfg = makeConfig(NetMode::Full, "/work", {"true"});
    Argv a = build_bwrap_argv("/usr/bin/bwrap", cfg, {}, makeEnv({}), "/sbx/home/user",
                              "/sbx/tmp", false);  // font_dir defaults to ""
    EXPECT_FALSE(has(a, "/sbx/fontconfig"));
}

// ---------------------------------------------------------------------------
// Audit-log directory masking: a --tmpfs shadows the audit dir so the untrusted
// child cannot read/forge/erase the host audit log. It must come AFTER the user
// mounts (its parent mount must already exist).
// ---------------------------------------------------------------------------

TEST(Bwrap, AuditMaskTmpfsEmittedWhenSupplied) {
    Config cfg = makeConfig(NetMode::Full, "/work", {"true"});
    std::vector<Mount> mounts = {mnt("/host/cwd", "/host/cwd", MountMode::ReadWrite)};
    Argv a = build_bwrap_argv("/usr/bin/bwrap", cfg, mounts, makeEnv({}), "/fh", "/tmp",
                              false, /*font_dir=*/"", /*audit_mask_dir=*/"/host/cwd/.raincoat");
    EXPECT_TRUE(hasPair(a, "--tmpfs", "/host/cwd/.raincoat"));
    // The tmpfs mask must be emitted AFTER the writable cwd mount it shadows.
    int mnt_idx = indexOfTriple(a, "--bind", "/host/cwd", "/host/cwd");
    int mask_idx = indexOf(a, "--tmpfs");
    ASSERT_GE(mnt_idx, 0);
    ASSERT_GE(mask_idx, 0);
    EXPECT_LT(mnt_idx, mask_idx);
}

TEST(Bwrap, AuditMaskAbsentWhenEmpty) {
    Argv a = buildTypical();  // audit_mask_dir defaults to ""
    EXPECT_FALSE(has(a, "--tmpfs"));
}

// ---------------------------------------------------------------------------
// Per-Mount binds: RO -> --ro-bind, RW -> --bind, using host+sandbox pair
// ---------------------------------------------------------------------------

TEST(Bwrap, ReadOnlyMountUsesRoBind) {
    Config cfg = makeConfig(NetMode::Full, "/work", {"true"});
    std::vector<Mount> mounts = {mnt("/host/data", "/host/data", MountMode::ReadOnly)};
    Argv a = build_bwrap_argv("/usr/bin/bwrap", cfg, mounts, makeEnv({}), "/fh", "/tmp", false);
    EXPECT_TRUE(hasTriple(a, "--ro-bind", "/host/data", "/host/data"));
    EXPECT_FALSE(hasTriple(a, "--bind", "/host/data", "/host/data"));
}

TEST(Bwrap, ReadWriteMountUsesBind) {
    Config cfg = makeConfig(NetMode::Full, "/work", {"true"});
    std::vector<Mount> mounts = {mnt("/host/out", "/host/out", MountMode::ReadWrite)};
    Argv a = build_bwrap_argv("/usr/bin/bwrap", cfg, mounts, makeEnv({}), "/fh", "/tmp", false);
    EXPECT_TRUE(hasTriple(a, "--bind", "/host/out", "/host/out"));
    EXPECT_FALSE(hasTriple(a, "--ro-bind", "/host/out", "/host/out"));
}

// Distinct host vs sandbox paths must both appear in the emitted triple, in order.
TEST(Bwrap, MountHonorsHostAndSandboxPaths) {
    Config cfg = makeConfig(NetMode::Full, "/work", {"true"});
    std::vector<Mount> mounts = {mnt("/host/src", "/sbx/src", MountMode::ReadOnly)};
    Argv a = build_bwrap_argv("/usr/bin/bwrap", cfg, mounts, makeEnv({}), "/fh", "/tmp", false);
    EXPECT_TRUE(hasTriple(a, "--ro-bind", "/host/src", "/sbx/src"));
}

// The ReadWrite branch must ALSO honor differing host/sandbox paths: --bind with
// the host path first and the (distinct) sandbox path second. This covers the RW
// arm of the per-mount branch that the ReadOnly test above cannot.
TEST(Bwrap, ReadWriteMountHonorsDifferingHostAndSandboxPaths) {
    Config cfg = makeConfig(NetMode::Full, "/work", {"true"});
    std::vector<Mount> mounts = {mnt("/host/out", "/sbx/out", MountMode::ReadWrite)};
    Argv a = build_bwrap_argv("/usr/bin/bwrap", cfg, mounts, makeEnv({}), "/fh", "/tmp", false);
    EXPECT_TRUE(hasTriple(a, "--bind", "/host/out", "/sbx/out"));
    // Must NOT collapse the sandbox path to the host path, nor use --ro-bind.
    EXPECT_FALSE(hasTriple(a, "--bind", "/host/out", "/host/out"));
    EXPECT_FALSE(hasTriple(a, "--ro-bind", "/host/out", "/sbx/out"));
}

TEST(Bwrap, MountsPreserveOrder) {
    Config cfg = makeConfig(NetMode::Full, "/work", {"true"});
    std::vector<Mount> mounts = {
        mnt("/m/a", "/m/a", MountMode::ReadOnly),
        mnt("/m/b", "/m/b", MountMode::ReadWrite),
        mnt("/m/c", "/m/c", MountMode::ReadOnly),
    };
    Argv a = build_bwrap_argv("/usr/bin/bwrap", cfg, mounts, makeEnv({}), "/fh", "/tmp", false);
    int ia = indexOfTriple(a, "--ro-bind", "/m/a", "/m/a");
    int ib = indexOfTriple(a, "--bind", "/m/b", "/m/b");
    int ic = indexOfTriple(a, "--ro-bind", "/m/c", "/m/c");
    ASSERT_GE(ia, 0);
    ASSERT_GE(ib, 0);
    ASSERT_GE(ic, 0);
    EXPECT_LT(ia, ib);
    EXPECT_LT(ib, ic);
}

TEST(Bwrap, NoMountsIsValid) {
    Config cfg = makeConfig(NetMode::Full, "/work", {"true"});
    Argv a = build_bwrap_argv("/usr/bin/bwrap", cfg, {}, makeEnv({{"PATH", "/usr/bin"}}), "/fh",
                              "/tmp", false);
    // Still fully-formed: base view + clearenv + chdir + command present.
    EXPECT_TRUE(hasTriple(a, "--ro-bind", "/usr", "/usr"));
    EXPECT_TRUE(has(a, "--clearenv"));
    EXPECT_TRUE(hasPair(a, "--chdir", "/work"));
}

// ---------------------------------------------------------------------------
// Env: --clearenv precedes all --setenv; one --setenv per resolved entry
// ---------------------------------------------------------------------------

TEST(Bwrap, ClearenvPresentExactlyOnce) {
    Argv a = buildTypical();
    EXPECT_EQ(countTok(a, "--clearenv"), 1);
}

TEST(Bwrap, ClearenvPrecedesAllSetenv) {
    Argv a = buildTypical();
    int clear = indexOf(a, "--clearenv");
    ASSERT_GE(clear, 0);
    for (int i = 0; i < static_cast<int>(a.size()); ++i) {
        if (a[i] == "--setenv") {
            EXPECT_GT(i, clear) << "--setenv at " << i << " before --clearenv";
        }
    }
}

TEST(Bwrap, OneSetenvPerResolvedEntry) {
    std::map<std::string, std::string> resolved = {
        {"HOME", "/fake/home/user"}, {"PATH", "/usr/bin"}, {"TZ", "UTC"}, {"TERM", "xterm"}};
    Config cfg = makeConfig(NetMode::Full, "/work", {"true"});
    Argv a = build_bwrap_argv("/usr/bin/bwrap", cfg, {}, makeEnv(resolved), "/fh", "/tmp", false);
    EXPECT_EQ(countTok(a, "--setenv"), static_cast<int>(resolved.size()));

    auto pairs = setenvPairs(a);
    std::map<std::string, std::string> got(pairs.begin(), pairs.end());
    EXPECT_EQ(got, resolved);
}

TEST(Bwrap, SetenvValueImmediatelyFollowsKey) {
    std::map<std::string, std::string> resolved = {{"LANG", "en_US.UTF-8"}};
    Config cfg = makeConfig(NetMode::Full, "/work", {"true"});
    Argv a = build_bwrap_argv("/usr/bin/bwrap", cfg, {}, makeEnv(resolved), "/fh", "/tmp", false);
    EXPECT_TRUE(hasTriple(a, "--setenv", "LANG", "en_US.UTF-8"));
}

// std::map iterates in sorted key order — the emitted --setenv keys must match that order.
TEST(Bwrap, SetenvKeysAreDeterministicSortedOrder) {
    std::map<std::string, std::string> resolved = {
        {"ZED", "1"}, {"ALPHA", "2"}, {"MID", "3"}, {"BETA", "4"}};
    Config cfg = makeConfig(NetMode::Full, "/work", {"true"});
    Argv a = build_bwrap_argv("/usr/bin/bwrap", cfg, {}, makeEnv(resolved), "/fh", "/tmp", false);

    std::vector<std::string> emitted;
    for (const auto& kv : setenvPairs(a)) emitted.push_back(kv.first);

    std::vector<std::string> expected;
    for (const auto& kv : resolved) expected.push_back(kv.first);  // map == sorted
    EXPECT_EQ(emitted, expected);
    // Sanity: expected really is sorted.
    EXPECT_TRUE(std::is_sorted(expected.begin(), expected.end()));
}

TEST(Bwrap, EmptyResolvedProducesNoSetenv) {
    Config cfg = makeConfig(NetMode::Full, "/work", {"true"});
    Argv a = build_bwrap_argv("/usr/bin/bwrap", cfg, {}, makeEnv({}), "/fh", "/tmp", false);
    EXPECT_TRUE(has(a, "--clearenv"));
    EXPECT_EQ(countTok(a, "--setenv"), 0);
}

// The audit-only lists (allowed/set/scrubbed) must NOT influence argv: only `resolved`
// drives --setenv, so no value outside `resolved` may leak.
TEST(Bwrap, NoSetenvLeaksValuesOutsideResolved) {
    EnvResolution env;
    env.resolved = {{"PATH", "/usr/bin"}};
    env.allowed = {"SHOULD_NOT_APPEAR_ALLOWED"};
    env.set = {"SHOULD_NOT_APPEAR_SET"};
    env.scrubbed = {"AWS_SECRET_ACCESS_KEY", "GITHUB_TOKEN"};
    Config cfg = makeConfig(NetMode::Full, "/work", {"true"});
    Argv a = build_bwrap_argv("/usr/bin/bwrap", cfg, {}, env, "/fh", "/tmp", false);

    EXPECT_EQ(countTok(a, "--setenv"), 1);
    for (const auto& kv : setenvPairs(a)) {
        EXPECT_EQ(env.resolved.count(kv.first), 1u)
            << "--setenv leaked key not in resolved: " << kv.first;
    }
    // No trace of the audit-only or scrubbed names anywhere in argv.
    EXPECT_FALSE(has(a, "SHOULD_NOT_APPEAR_ALLOWED"));
    EXPECT_FALSE(has(a, "SHOULD_NOT_APPEAR_SET"));
    EXPECT_FALSE(has(a, "AWS_SECRET_ACCESS_KEY"));
    EXPECT_FALSE(has(a, "GITHUB_TOKEN"));
}

// Values are emitted verbatim, even with spaces / empty strings.
TEST(Bwrap, SetenvPreservesTrickyValues) {
    std::map<std::string, std::string> resolved = {{"EMPTY", ""}, {"SPACED", "a b c"}};
    Config cfg = makeConfig(NetMode::Full, "/work", {"true"});
    Argv a = build_bwrap_argv("/usr/bin/bwrap", cfg, {}, makeEnv(resolved), "/fh", "/tmp", false);
    EXPECT_TRUE(hasTriple(a, "--setenv", "EMPTY", ""));
    EXPECT_TRUE(hasTriple(a, "--setenv", "SPACED", "a b c"));
}

// ---------------------------------------------------------------------------
// --chdir workdir, then command tokens LAST
// ---------------------------------------------------------------------------

TEST(Bwrap, ChdirWorkdir) {
    Config cfg = makeConfig(NetMode::Full, "/my/workdir", {"true"});
    Argv a = build_bwrap_argv("/usr/bin/bwrap", cfg, {}, makeEnv({}), "/fh", "/tmp", false);
    EXPECT_TRUE(hasPair(a, "--chdir", "/my/workdir"));
}

TEST(Bwrap, CommandTokensAreLastInOrder) {
    Config cfg = makeConfig(NetMode::Full, "/work", {"python3", "-c", "print('hi there')"});
    Argv a = build_bwrap_argv("/usr/bin/bwrap", cfg, {}, makeEnv({{"PATH", "/usr/bin"}}), "/fh",
                              "/tmp", false);
    ASSERT_GE(static_cast<int>(a.size()), 3);
    Argv tail(a.end() - 3, a.end());
    EXPECT_EQ(tail, (Argv{"python3", "-c", "print('hi there')"}));
}

TEST(Bwrap, SingleTokenCommandIsLast) {
    Config cfg = makeConfig(NetMode::Full, "/work", {"true"});
    Argv a = build_bwrap_argv("/usr/bin/bwrap", cfg, {}, makeEnv({}), "/fh", "/tmp", false);
    ASSERT_FALSE(a.empty());
    EXPECT_EQ(a.back(), "true");
}

TEST(Bwrap, ChdirComesAfterSetenvAndBeforeCommand) {
    Config cfg = makeConfig(NetMode::Full, "/work", {"mycmd", "arg"});
    Argv a = build_bwrap_argv("/usr/bin/bwrap", cfg, {}, makeEnv({{"PATH", "/usr/bin"}}), "/fh",
                              "/tmp", false);
    int setenv = indexOf(a, "--setenv");
    int chdir = indexOf(a, "--chdir");
    int cmd = indexOf(a, "mycmd");
    ASSERT_GE(setenv, 0);
    ASSERT_GE(chdir, 0);
    ASSERT_GE(cmd, 0);
    EXPECT_LT(setenv, chdir);
    EXPECT_LT(chdir, cmd);
}

// ---------------------------------------------------------------------------
// Full end-to-end relative ordering of every section
// ---------------------------------------------------------------------------

TEST(Bwrap, OverallSectionOrdering) {
    Config cfg = makeConfig(NetMode::Off, "/work", {"cmd0", "cmd1"});
    std::vector<Mount> mounts = {mnt("/host/rw", "/host/rw", MountMode::ReadWrite)};
    EnvResolution env = makeEnv({{"PATH", "/usr/bin"}});
    Argv a = build_bwrap_argv("/usr/bin/bwrap", cfg, mounts, env, "/fake/home", "/fake/tmp", true);

    int die = indexOf(a, "--die-with-parent");
    int pid = indexOf(a, "--unshare-pid");
    int net = indexOf(a, "--unshare-net");
    int usr = indexOfTriple(a, "--ro-bind", "/usr", "/usr");
    int proc = indexOf(a, "--proc");
    int ssl = indexOfTriple(a, "--ro-bind-try", "/etc/ssl", "/etc/ssl");
    int home = indexOfTriple(a, "--bind", "/fake/home", "/fake/home");
    int tmp = indexOfTriple(a, "--bind", "/fake/tmp", "/fake/tmp");
    int mount = indexOfTriple(a, "--bind", "/host/rw", "/host/rw");
    int clear = indexOf(a, "--clearenv");
    int setenv = indexOf(a, "--setenv");
    int chdir = indexOf(a, "--chdir");
    int cmd = indexOf(a, "cmd0");

    for (int idx : {die, pid, net, usr, proc, ssl, home, tmp, mount, clear, setenv, chdir, cmd})
        ASSERT_GE(idx, 0) << "a required section token is missing";

    EXPECT_LT(die, pid);
    EXPECT_LT(pid, net);
    EXPECT_LT(net, usr);
    EXPECT_LT(usr, proc);
    EXPECT_LT(proc, ssl);
    EXPECT_LT(ssl, home);
    EXPECT_LT(home, tmp);
    EXPECT_LT(tmp, mount);
    EXPECT_LT(mount, clear);
    EXPECT_LT(clear, setenv);
    EXPECT_LT(setenv, chdir);
    EXPECT_LT(chdir, cmd);
    EXPECT_EQ(cmd, static_cast<int>(a.size()) - 2);  // cmd0 cmd1 are the final two tokens
}

// ---------------------------------------------------------------------------
// redact_argv_for_audit — structural, display-safe rendering for the audit log.
//
// SECURITY: every --setenv VALUE in the options region must become "<redacted>";
// no secret value may survive. Over-redaction is acceptable; under-redaction is a
// vulnerability. Command tokens (the final num_command_tokens) are verbatim.
// ---------------------------------------------------------------------------

TEST(RedactArgv, RedactsSetenvValueShowsName) {
    Argv argv = {"/usr/bin/bwrap", "--setenv", "OPENAI_API_KEY", "sk-SECRETVALUE123",
                 "--chdir", "/work", "python", "train.py"};
    std::string out = redact_argv_for_audit(argv, /*num_command_tokens=*/2);
    EXPECT_NE(out.find("OPENAI_API_KEY"), std::string::npos);   // NAME shown
    EXPECT_NE(out.find("<redacted>"), std::string::npos);       // value redacted
    EXPECT_EQ(out.find("sk-SECRETVALUE123"), std::string::npos) << out;  // value gone
}

TEST(RedactArgv, RedactsMultiWordValueWithSpaces) {
    // A value containing spaces is a single argv element; it must be fully redacted.
    Argv argv = {"/usr/bin/bwrap", "--setenv", "APP_PASSPHRASE", "hunter2 top secret",
                 "--chdir", "/work", "run"};
    std::string out = redact_argv_for_audit(argv, 1);
    EXPECT_EQ(out.find("hunter2"), std::string::npos) << out;
    EXPECT_EQ(out.find("top secret"), std::string::npos) << out;
    EXPECT_NE(out.find("APP_PASSPHRASE"), std::string::npos);
    EXPECT_NE(out.find("<redacted>"), std::string::npos);
}

TEST(RedactArgv, RedactsValueStartingWithDashes) {
    // A value whose text begins with "--" must NOT be mistaken for an option.
    Argv argv = {"/usr/bin/bwrap", "--setenv", "WEIRD", "--not-a-flag=secret",
                 "run"};
    std::string out = redact_argv_for_audit(argv, 1);
    EXPECT_EQ(out.find("--not-a-flag=secret"), std::string::npos) << out;
    EXPECT_NE(out.find("WEIRD"), std::string::npos);
    EXPECT_NE(out.find("<redacted>"), std::string::npos);
}

TEST(RedactArgv, RedactsPemPrivateKeyBody) {
    // The single most common leak shape: a PEM/OpenSSH key whose value begins with
    // "-----BEGIN ...". As one argv element the whole body must be redacted.
    Argv argv = {
        "/usr/bin/bwrap", "--setenv", "SSH_PRIVATE_KEY",
        "-----BEGIN OPENSSH PRIVATE KEY-----\nMIIUNIQUESECRETMARKER42body\n-----END OPENSSH PRIVATE KEY-----",
        "--chdir", "/work", "deploy"};
    std::string out = redact_argv_for_audit(argv, 1);
    EXPECT_EQ(out.find("UNIQUESECRETMARKER42"), std::string::npos) << out;
    EXPECT_EQ(out.find("BEGIN OPENSSH PRIVATE KEY"), std::string::npos) << out;
    EXPECT_NE(out.find("SSH_PRIVATE_KEY"), std::string::npos);
    EXPECT_NE(out.find("<redacted>"), std::string::npos);
}

TEST(RedactArgv, RedactsEmptyValue) {
    Argv argv = {"/usr/bin/bwrap", "--setenv", "EMPTY", "", "--chdir", "/work", "run"};
    std::string out = redact_argv_for_audit(argv, 1);
    EXPECT_NE(out.find("EMPTY"), std::string::npos);
    EXPECT_NE(out.find("<redacted>"), std::string::npos);
    // The NAME after --setenv is EMPTY's placeholder, then <redacted> for the value.
    EXPECT_NE(out.find("EMPTY <redacted>"), std::string::npos) << out;
}

TEST(RedactArgv, RedactsMultipleSetenv) {
    Argv argv = {"/usr/bin/bwrap", "--clearenv",
                 "--setenv", "A", "secretA",
                 "--setenv", "B", "secretB",
                 "--setenv", "C", "secretC",
                 "--chdir", "/work", "cmd"};
    std::string out = redact_argv_for_audit(argv, 1);
    EXPECT_EQ(out.find("secretA"), std::string::npos) << out;
    EXPECT_EQ(out.find("secretB"), std::string::npos) << out;
    EXPECT_EQ(out.find("secretC"), std::string::npos) << out;
    EXPECT_NE(out.find("A"), std::string::npos);
    EXPECT_NE(out.find("B"), std::string::npos);
    EXPECT_NE(out.find("C"), std::string::npos);
    // Three redactions, one per --setenv.
    int count = 0;
    for (std::size_t p = out.find("<redacted>"); p != std::string::npos;
         p = out.find("<redacted>", p + 1))
        ++count;
    EXPECT_EQ(count, 3);
}

TEST(RedactArgv, LiteralSetenvInCommandRegionIsNotRedacted) {
    // A literal "--setenv NAME VALUE" appearing INSIDE the user's command must be
    // preserved verbatim — it is not a bwrap option, it is the command's own argv.
    Argv argv = {"/usr/bin/bwrap", "--chdir", "/work",
                 "mytool", "--setenv", "FOO", "barvalue"};
    std::string out = redact_argv_for_audit(argv, /*num_command_tokens=*/4);
    EXPECT_NE(out.find("--setenv"), std::string::npos);
    EXPECT_NE(out.find("FOO"), std::string::npos);
    EXPECT_NE(out.find("barvalue"), std::string::npos) << out;  // command arg, not a secret
    EXPECT_EQ(out.find("<redacted>"), std::string::npos) << out;  // nothing redacted
}

TEST(RedactArgv, NonSetenvOptionValuesArePreserved) {
    // Values of non-setenv options (paths, chdir target, bind targets) are not
    // secrets and must survive verbatim.
    Argv argv = {"/usr/bin/bwrap", "--ro-bind", "/usr", "/usr",
                 "--bind", "/host/out", "/sbx/out",
                 "--chdir", "/work/proj", "run"};
    std::string out = redact_argv_for_audit(argv, 1);
    EXPECT_NE(out.find("--ro-bind /usr /usr"), std::string::npos) << out;
    EXPECT_NE(out.find("--bind /host/out /sbx/out"), std::string::npos) << out;
    EXPECT_NE(out.find("--chdir /work/proj"), std::string::npos) << out;
    EXPECT_EQ(out.find("<redacted>"), std::string::npos);
}

TEST(RedactArgv, CommandTokensAppendedVerbatim) {
    Argv argv = {"/usr/bin/bwrap", "--setenv", "TOKEN", "secretz",
                 "--chdir", "/work", "python", "-c", "print('hi there')"};
    std::string out = redact_argv_for_audit(argv, /*num_command_tokens=*/3);
    EXPECT_EQ(out.find("secretz"), std::string::npos) << out;
    // The command's own tokens are verbatim; the spaced one is display-quoted.
    EXPECT_NE(out.find("python -c 'print('hi there')'"), std::string::npos) << out;
}

TEST(RedactArgv, QuotesEmptyAndSpacedCommandTokens) {
    Argv argv = {"/usr/bin/bwrap", "--chdir", "/work", "echo", "", "a b"};
    std::string out = redact_argv_for_audit(argv, /*num_command_tokens=*/3);
    EXPECT_NE(out.find("echo '' 'a b'"), std::string::npos) << out;
}

// End-to-end: feed the real build_bwrap_argv output through the redactor and prove
// no resolved secret VALUE survives while every NAME does.
TEST(RedactArgv, EndToEndFromBuildBwrapArgvLeaksNoSecret) {
    std::map<std::string, std::string> resolved = {
        {"OPENAI_API_KEY", "sk-LEAKMARKER-abc"},
        {"APP_PASSPHRASE", "spaced secret value"},
        {"PATH", "/opt/LEAKPATH-marker/bin"}};
    Config cfg = makeConfig(NetMode::Full, "/work", {"python", "train.py"});
    Argv a = build_bwrap_argv("/usr/bin/bwrap", cfg, {}, makeEnv(resolved), "/fh", "/tmp", false);
    std::string out = redact_argv_for_audit(a, cfg.command.size());

    EXPECT_EQ(out.find("sk-LEAKMARKER-abc"), std::string::npos) << out;
    EXPECT_EQ(out.find("spaced secret value"), std::string::npos) << out;
    EXPECT_EQ(out.find("/opt/LEAKPATH-marker/bin"), std::string::npos) << out;  // PATH's value
    // Names still visible.
    EXPECT_NE(out.find("OPENAI_API_KEY"), std::string::npos);
    EXPECT_NE(out.find("APP_PASSPHRASE"), std::string::npos);
    EXPECT_NE(out.find("PATH"), std::string::npos);
    // Command survived verbatim at the tail.
    EXPECT_NE(out.find("python train.py"), std::string::npos) << out;
}

// ---------------------------------------------------------------------------
// Backend toggles ([backend]) + configurable hostname (ext.hostname).
// A default-constructed Config reproduces the MVP argv (covered above); these
// tests exercise the profile overrides carried in cfg.ext.
// ---------------------------------------------------------------------------

// Build a Config whose ext.backend / ext.hostname are populated for the toggle tests.
static Config makeBackendConfig(std::function<void(Config&)> tweak) {
    Config c = makeConfig(NetMode::Off, "/work", {"true"});
    tweak(c);
    return c;
}

static Argv buildWith(const Config& cfg) {
    return build_bwrap_argv("/usr/bin/bwrap", cfg, {}, makeEnv({}), "/fh", "/tmp", false);
}

TEST(BwrapBackend, HostnameComesFromExtWhenSet) {
    Config cfg = makeBackendConfig([](Config& c) { c.ext.hostname = "workstation"; });
    Argv a = buildWith(cfg);
    EXPECT_TRUE(hasPair(a, "--hostname", "workstation"));
    EXPECT_FALSE(hasPair(a, "--hostname", "sandbox"));
    EXPECT_EQ(countTok(a, "--hostname"), 1);
}

TEST(BwrapBackend, HostnameDefaultsToSandboxWhenExtUnset) {
    Argv a = buildWith(makeConfig(NetMode::Off, "/work", {"true"}));
    EXPECT_TRUE(hasPair(a, "--hostname", "sandbox"));
}

TEST(BwrapBackend, UnshareUserEmittedOnlyWhenEnabled) {
    EXPECT_FALSE(has(buildWith(makeConfig(NetMode::Off, "/w", {"true"})), "--unshare-user"));
    Config cfg = makeBackendConfig([](Config& c) { c.ext.backend.unshare_user = true; });
    Argv a = buildWith(cfg);
    EXPECT_TRUE(has(a, "--unshare-user"));
    // Must sit before the base /usr bind, alongside the other namespace flags.
    EXPECT_LT(indexOf(a, "--unshare-user"), indexOfTriple(a, "--ro-bind", "/usr", "/usr"));
}

TEST(BwrapBackend, UnshareCgroupEmittedOnlyWhenEnabled) {
    EXPECT_FALSE(has(buildWith(makeConfig(NetMode::Off, "/w", {"true"})), "--unshare-cgroup"));
    Config cfg = makeBackendConfig([](Config& c) { c.ext.backend.unshare_cgroup = true; });
    EXPECT_TRUE(has(buildWith(cfg), "--unshare-cgroup"));
}

TEST(BwrapBackend, DieWithParentSuppressible) {
    Config cfg = makeBackendConfig([](Config& c) { c.ext.backend.die_with_parent = false; });
    EXPECT_FALSE(has(buildWith(cfg), "--die-with-parent"));
}

TEST(BwrapBackend, MountProcAndDevSuppressible) {
    Config cfg = makeBackendConfig([](Config& c) {
        c.ext.backend.mount_proc = false;
        c.ext.backend.mount_dev = false;
    });
    Argv a = buildWith(cfg);
    EXPECT_FALSE(hasPair(a, "--proc", "/proc"));
    EXPECT_FALSE(hasPair(a, "--dev", "/dev"));
}

TEST(BwrapBackend, TmpfsTmpBindSuppressible) {
    Config cfg = makeBackendConfig([](Config& c) { c.ext.backend.mount_tmpfs_tmp = false; });
    Argv a = build_bwrap_argv("/usr/bin/bwrap", cfg, {}, makeEnv({}), "/fh", "/sbx/tmp", false);
    EXPECT_FALSE(hasTriple(a, "--bind", "/sbx/tmp", "/sbx/tmp"));
    // The fake home is still bound — only the temp scratch is gated.
    EXPECT_TRUE(hasTriple(a, "--bind", "/fh", "/fh"));
}

TEST(BwrapBackend, UnshareUtsFalseDropsUnshareUtsAndHostname) {
    Config cfg = makeBackendConfig([](Config& c) { c.ext.backend.unshare_uts = false; });
    Argv a = buildWith(cfg);
    EXPECT_FALSE(has(a, "--unshare-uts"));
    EXPECT_FALSE(has(a, "--hostname"));  // hostname needs the UTS namespace
}

TEST(BwrapBackend, UnshareNetSuppressedWhenToggleOffEvenWhenNetOff) {
    Config cfg = makeBackendConfig(
        [](Config& c) { c.ext.backend.unshare_net_when_off = false; });
    EXPECT_FALSE(has(buildWith(cfg), "--unshare-net"));
}

TEST(BwrapBackend, UnshareNetStillEmittedByDefaultWhenNetOff) {
    Argv a = buildWith(makeConfig(NetMode::Off, "/work", {"true"}));
    EXPECT_TRUE(has(a, "--unshare-net"));
}
