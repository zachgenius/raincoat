// Raincoat — Seatbelt (SBPL) generator tests. macOS-ONLY.
//
// CMake gates this suite to APPLE (RC_MACOS_ONLY_TESTS): it links seatbelt.cpp +
// backend_macos.cpp, which are compiled only on macOS. These are PURE unit tests of the
// SBPL profile generator (build_seatbelt_profile), the sbpl_str escaper, and the macOS
// Capabilities descriptor. Every path fed in is ALREADY canonical — the generator
// documents that the CALLER (backend_macos.cpp) realpath's everything first, so the tests
// hand it kernel-canonical spellings directly and never touch the filesystem.
#include <gtest/gtest.h>

#include <cstddef>
#include <string>
#include <vector>

#include "backend.hpp"
#include "seatbelt.hpp"

using namespace raincoat;

namespace {

bool contains(const std::string& hay, const std::string& needle) {
    return hay.find(needle) != std::string::npos;
}

bool ends_with(const std::string& s, const std::string& suf) {
    return s.size() >= suf.size() &&
           s.compare(s.size() - suf.size(), suf.size(), suf) == 0;
}

// Count non-overlapping occurrences of `needle` in `hay`.
std::size_t count_occurrences(const std::string& hay, const std::string& needle) {
    std::size_t n = 0, pos = 0;
    while ((pos = hay.find(needle, pos)) != std::string::npos) {
        ++n;
        pos += needle.size();
    }
    return n;
}

// A baseline Config + LaunchInputs with canonical, existing-looking paths. The Config is
// a member so `in.cfg` stays valid for the fixture's lifetime; tests tweak fields then
// call build_seatbelt_profile(in, err).
struct Fixture {
    Config cfg;
    LaunchInputs in;

    Fixture() {
        cfg.strict = false;
        cfg.net = NetMode::Full;
        cfg.workdir = "/Users/tester/project";

        in.cfg = &cfg;
        in.real_home = "/Users/tester";
        in.fake_home = "/Users/tester/.raincoat/home";
        in.sandbox_tmp = "/private/tmp/raincoat.tmp";
        in.sandbox_out = "/private/tmp/raincoat.out";
        in.audit_mask_dir = "/private/tmp/raincoat.audit";
        in.profile_path = "/private/tmp/raincoat.sb";
    }

    std::string build(std::string& err) { return build_seatbelt_profile(in, err); }
};

}  // namespace

// ===========================================================================
// backend_capabilities() — the macOS (Seatbelt) descriptor
// ===========================================================================

TEST(Seatbelt, MacOsCapabilities) {
    Capabilities c = backend_capabilities();
    EXPECT_EQ(c.fs_hiding, FsHiding::Filter);
    EXPECT_EQ(c.net_off, NetOff::PolicyDeny);
    EXPECT_EQ(c.env_apply, EnvApply::ViaExec);
    EXPECT_TRUE(c.net_firewall_kernel);
    EXPECT_FALSE(c.supports_fontconfig_isolation);
    EXPECT_FALSE(c.supports_uts_hostname);
    EXPECT_FALSE(c.supports_minimal_etc);
    EXPECT_FALSE(c.supports_curated_fonts);
    EXPECT_FALSE(c.supports_netns_jail);
    EXPECT_FALSE(c.supports_proc_overlays);
    EXPECT_FALSE(c.supports_seccomp_identity);
    EXPECT_FALSE(c.supports_path_remap);
    EXPECT_TRUE(c.supports_dyld_interpose);  // in-process sandbox_init preserves DYLD injection
    EXPECT_EQ(c.label, "Seatbelt (sandbox-exec, best-effort)");
}

// The generated profile must re-allow reading the injected interposer dylib (last-match-wins,
// after the denies) so dyld can load it even when it lives under a denied path.
TEST(Seatbelt, InterposeDylibReAllowed) {
    Fixture f;
    f.in.interpose_dylib = "/opt/raincoat/rc_interpose.dylib";
    std::string err;
    std::string p = f.build(err);
    EXPECT_TRUE(err.empty());
    EXPECT_NE(p.find("(allow file-read* (subpath \"/opt/raincoat/rc_interpose.dylib\"))"),
              std::string::npos);
    // Empty interpose_dylib -> no such allow rule emitted.
    f.in.interpose_dylib.clear();
    std::string p2 = f.build(err);
    EXPECT_EQ(p2.find("rc_interpose.dylib"), std::string::npos);
}

// ===========================================================================
// sbpl_str() — the SBPL string-literal escaper
// ===========================================================================

TEST(Seatbelt, SbplStrWrapsAndEscapes) {
    bool ok = false;

    ok = false;
    EXPECT_EQ(sbpl_str("plain", ok), "\"plain\"");
    EXPECT_TRUE(ok);

    // A double-quote is backslash-escaped: a"b -> "a\"b"
    ok = false;
    EXPECT_EQ(sbpl_str("a\"b", ok), "\"a\\\"b\"");
    EXPECT_TRUE(ok);

    // A backslash is doubled: a\b -> "a\\b"
    ok = false;
    EXPECT_EQ(sbpl_str("a\\b", ok), "\"a\\\\b\"");
    EXPECT_TRUE(ok);
}

TEST(Seatbelt, SbplStrFailsOnNewline) {
    bool ok = true;
    std::string out = sbpl_str("a\nb", ok);
    EXPECT_FALSE(ok);
    EXPECT_TRUE(out.empty());
}

TEST(Seatbelt, SbplStrFailsOnNul) {
    bool ok = true;
    std::string with_nul("a\0b", 3);  // embedded NUL, length 3
    std::string out = sbpl_str(with_nul, ok);
    EXPECT_FALSE(ok);
    EXPECT_TRUE(out.empty());
}

// ===========================================================================
// build_seatbelt_profile() — non-strict profile shape
// ===========================================================================

TEST(Seatbelt, NonStrictProfileShape) {
    Fixture f;
    f.in.mounts = {
        {"/Users/tester/ro", "/Users/tester/ro", MountMode::ReadOnly},
        {"/Users/tester/rw", "/Users/tester/rw", MountMode::ReadWrite},
    };
    f.in.fs_deny_resolved = {"/Users/tester/.ssh"};

    std::string err;
    std::string p = f.build(err);
    ASSERT_TRUE(err.empty()) << err;
    ASSERT_FALSE(p.empty());

    // Filter model: start permissive.
    EXPECT_TRUE(contains(p, "(allow default)")) << p;

    // Hide the real home (read+write deny) and block /Users enumeration (read deny).
    EXPECT_TRUE(contains(
        p, "(deny file-read* file-write* (subpath \"/Users/tester\"))")) << p;
    EXPECT_TRUE(contains(p, "(deny file-read* (subpath \"/Users\"))")) << p;

    // Re-allow the sandbox-private writable dirs.
    EXPECT_TRUE(contains(
        p, "(allow file-read* file-write* (subpath \"/Users/tester/.raincoat/home\"))")) << p;
    EXPECT_TRUE(contains(
        p, "(allow file-read* file-write* (subpath \"/private/tmp/raincoat.tmp\"))")) << p;
    EXPECT_TRUE(contains(
        p, "(allow file-read* file-write* (subpath \"/private/tmp/raincoat.out\"))")) << p;

    // RO mount -> read-only allow (NO file-write*).
    EXPECT_TRUE(contains(p, "(allow file-read* (subpath \"/Users/tester/ro\"))")) << p;
    EXPECT_FALSE(contains(
        p, "(allow file-read* file-write* (subpath \"/Users/tester/ro\"))")) << p;

    // RW mount -> read+write allow.
    EXPECT_TRUE(contains(
        p, "(allow file-read* file-write* (subpath \"/Users/tester/rw\"))")) << p;

    // fs-deny set re-denied.
    EXPECT_TRUE(contains(
        p, "(deny file-read* file-write* (subpath \"/Users/tester/.ssh\"))")) << p;

    // Audit dir denied (child cannot read/forge/erase the log).
    EXPECT_TRUE(contains(
        p, "(deny file-read* file-write* (subpath \"/private/tmp/raincoat.audit\"))")) << p;

    // The generated profile self-denies (it names the real home / username).
    EXPECT_TRUE(contains(
        p, "(deny file-read* (literal \"/private/tmp/raincoat.sb\"))")) << p;
}

// An RO mount must be genuinely read-only under (allow default): read allowed AND writes
// explicitly denied, with the write-deny emitted AFTER every RW allow so an --allow-read
// subdir of an auto-mounted RW cwd stays read-only (Linux gives each its own mount point).
TEST(Seatbelt, ReadOnlyMountDeniesWrite) {
    Fixture f;
    f.in.mounts = {
        {"/data/ro", "/data/ro", MountMode::ReadOnly},
        {"/data/rw", "/data/rw", MountMode::ReadWrite},
    };
    std::string err;
    std::string p = f.build(err);
    ASSERT_TRUE(err.empty()) << err;
    EXPECT_TRUE(contains(p, "(allow file-read* (subpath \"/data/ro\"))")) << p;
    EXPECT_TRUE(contains(p, "(deny file-write* (subpath \"/data/ro\"))")) << p;
    // The RO write-deny must come AFTER the RW allow (so a broad RW mount cannot re-grant it).
    EXPECT_LT(p.find("(allow file-read* file-write* (subpath \"/data/rw\"))"),
              p.find("(deny file-write* (subpath \"/data/ro\"))")) << p;
}

// fs_deny_early is emitted BEFORE the sandbox re-allows, so a broad temp deny (host /tmp,
// Darwin TEMP) coexists with the scratch dirs nested under it (the re-allows win).
TEST(Seatbelt, EarlyDenyPrecedesSandboxReAllows) {
    Fixture f;
    f.in.fs_deny_early = {"/private/tmp"};
    std::string err;
    std::string p = f.build(err);
    ASSERT_TRUE(err.empty()) << err;
    EXPECT_TRUE(contains(p, "(deny file-read* file-write* (subpath \"/private/tmp\"))")) << p;
    // Early deny precedes the sandbox_tmp re-allow (which lives under it and must win).
    EXPECT_LT(p.find("(deny file-read* file-write* (subpath \"/private/tmp\"))"),
              p.find("(allow file-read* file-write* (subpath \"/private/tmp/raincoat.tmp\")")) << p;
}

// The effective working directory is re-allowed when it is NOT already covered.
TEST(Seatbelt, WorkdirAllowedWhenNotCovered) {
    Fixture f;  // workdir = /Users/tester/project, no mounts
    std::string err;
    std::string p = f.build(err);
    ASSERT_TRUE(err.empty()) << err;
    EXPECT_TRUE(contains(
        p, "(allow file-read* file-write* (subpath \"/Users/tester/project\"))")) << p;
}

// Workdir dedup: when the workdir equals a mount's host_path it is NOT emitted twice.
TEST(Seatbelt, WorkdirDedupWhenEqualsMount) {
    Fixture f;
    f.cfg.workdir = "/Users/tester/project";
    f.in.mounts = {
        {"/Users/tester/project", "/Users/tester/project", MountMode::ReadWrite},
    };

    std::string err;
    std::string p = f.build(err);
    ASSERT_TRUE(err.empty()) << err;

    // The path appears exactly once as an allow subpath (via the mount) — the workdir
    // auto-grant must not add a duplicate rule for the same subpath.
    const std::string needle = "(subpath \"/Users/tester/project\"))";
    EXPECT_EQ(count_occurrences(p, needle), 1u)
        << "workdir must not be emitted twice\n" << p;
}

// ===========================================================================
// build_seatbelt_profile() — network section
// ===========================================================================

// NetMode::Off with no loopback ports: the profile's last rule is (deny network*).
TEST(Seatbelt, NetOffEndsWithDenyNetwork) {
    Fixture f;
    f.cfg.net = NetMode::Off;  // no allow_loopback_ports

    std::string err;
    std::string p = f.build(err);
    ASSERT_TRUE(err.empty()) << err;

    EXPECT_TRUE(contains(p, "(deny network*)")) << p;

    std::string trimmed = p;
    while (!trimmed.empty() && (trimmed.back() == '\n' || trimmed.back() == '\r')) {
        trimmed.pop_back();
    }
    EXPECT_TRUE(ends_with(trimmed, "(deny network*)")) << p;
}

// A guarded proxy / egress bridge (allow_loopback_ports non-empty): deny ALL outbound at
// the kernel level and re-allow ONLY the loopback proxy port via the "localhost:" form.
// The raw "127.0.0.1:PORT" form must never appear (it fails to compile — measured).
TEST(Seatbelt, LoopbackPortsDenyAllAndAllowLocalhost) {
    Fixture f;
    f.cfg.net = NetMode::Full;  // even Full: the kernel firewall overrides
    f.in.allow_loopback_ports = {18080};

    std::string err;
    std::string p = f.build(err);
    ASSERT_TRUE(err.empty()) << err;

    EXPECT_TRUE(contains(p, "(deny network*)")) << p;
    EXPECT_TRUE(contains(
        p, "(allow network-outbound (remote ip \"localhost:18080\"))")) << p;
    EXPECT_FALSE(contains(p, "127.0.0.1:")) << p;
}

// NetMode::Full with no ports: (allow default) already permits network — emit nothing.
TEST(Seatbelt, NetFullNoPortsHasNoDenyNetwork) {
    Fixture f;
    f.cfg.net = NetMode::Full;

    std::string err;
    std::string p = f.build(err);
    ASSERT_TRUE(err.empty()) << err;
    EXPECT_FALSE(contains(p, "(deny network*)")) << p;
}

// ===========================================================================
// build_seatbelt_profile() — fail closed
// ===========================================================================

// An unrepresentable path (embedded newline) fails CLOSED: empty profile + err set,
// rather than emitting a profile a smuggled newline could subvert.
TEST(Seatbelt, FailsClosedOnNewlineInRealHome) {
    Fixture f;
    f.in.real_home = "/Users/te\nster";

    std::string err;
    std::string p = f.build(err);
    EXPECT_TRUE(p.empty());
    EXPECT_FALSE(err.empty());
}
