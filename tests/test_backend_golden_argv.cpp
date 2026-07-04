// Raincoat — backend golden-argv tests. LINUX-ONLY suite (bubblewrap backend).
//
// This suite links against bwrap::build_bwrap_argv and the Linux backend translation
// unit (backend_linux.cpp) — both compiled ONLY on Linux. CMake excludes this file on
// APPLE (it is listed in RC_LINUX_ONLY_TESTS), so it deliberately does NOT compile or run
// on macOS; it runs on Linux CI.
//
// It pins the backend seam's Linux contract:
//   * backend_capabilities() reports the bubblewrap (structural) guarantees, and
//   * backend_build_launch() reproduces build_bwrap_argv() byte-for-byte with the jail
//     off, and prepends the pasta netns-jail wrap (with the strict -o 127.0.0.1 outbound
//     bind) when the jail is active.
#include <gtest/gtest.h>

#include <algorithm>
#include <optional>
#include <string>
#include <vector>

#include "backend.hpp"
#include "bwrap.hpp"

using namespace raincoat;

namespace {

bool has_token(const std::vector<std::string>& v, const std::string& t) {
    return std::find(v.begin(), v.end(), t) != v.end();
}

// A representative fully-resolved launch: a RW workdir mount + a RO data mount, a small
// resolved env, a fake home, sandbox tmp/out, and an audit-mask dir. `cfg` is filled in
// by reference so callers can keep it alive for `in.cfg`.
LaunchInputs make_inputs(Config& cfg) {
    cfg.strict = false;
    cfg.net = NetMode::Off;
    cfg.workdir = "/work";
    cfg.command = {"/bin/echo", "hello"};

    LaunchInputs in;
    in.backend_path = "/usr/bin/bwrap";
    in.cfg = &cfg;
    in.mounts = {
        {"/work", "/work", MountMode::ReadWrite},
        {"/data", "/data", MountMode::ReadOnly},
    };
    in.env.resolved = {{"PATH", "/usr/bin:/bin"}, {"USER", "user"}};
    in.env.allowed = {"PATH"};
    in.env.set = {"USER"};
    in.fake_home = "/home/user";
    in.sandbox_tmp = "/tmp/rc.tmp";
    in.bind_resolv_conf = false;
    in.font_dir = "";
    in.audit_mask_dir = "/tmp/rc.audit";
    in.sandbox_out = "/tmp/rc.out";
    in.mask_empty_file = "";
    in.mask_files = {};
    in.curated_font_dirs = {};
    in.mask_usr_local_fonts = true;
    return in;
}

}  // namespace

// ===========================================================================
// backend_capabilities() — the Linux (bubblewrap) descriptor
// ===========================================================================

TEST(BackendGoldenArgv, LinuxCapabilities) {
    Capabilities c = backend_capabilities();
    EXPECT_EQ(c.fs_hiding, FsHiding::Structural);
    EXPECT_EQ(c.net_off, NetOff::UnshareNet);
    EXPECT_EQ(c.env_apply, EnvApply::ViaArgv);
    EXPECT_TRUE(c.supports_fontconfig_isolation);
    EXPECT_TRUE(c.supports_uts_hostname);
    EXPECT_TRUE(c.supports_minimal_etc);
    EXPECT_TRUE(c.supports_curated_fonts);
    EXPECT_TRUE(c.supports_netns_jail);
    EXPECT_NE(c.label.find("bubblewrap"), std::string::npos);
}

// ===========================================================================
// backend_build_launch() — jail OFF reproduces build_bwrap_argv() exactly
// ===========================================================================

TEST(BackendGoldenArgv, MatchesBuildBwrapArgvWhenNoJail) {
    Config cfg;
    LaunchInputs in = make_inputs(cfg);
    in.jail_active = false;

    std::vector<std::string> golden = build_bwrap_argv(
        in.backend_path, *in.cfg, in.mounts, in.env, in.fake_home, in.sandbox_tmp,
        in.bind_resolv_conf, in.font_dir, in.audit_mask_dir, in.sandbox_out,
        in.mask_empty_file, in.mask_files, in.curated_font_dirs, in.mask_usr_local_fonts);

    std::string err;
    auto plan = backend_build_launch(in, err);
    ASSERT_TRUE(plan.has_value()) << err;

    EXPECT_EQ(plan->argv, golden);
    EXPECT_EQ(plan->launch_path, in.backend_path);
    EXPECT_EQ(plan->env_apply, EnvApply::ViaArgv);
    // ViaArgv bakes env into argv (--clearenv/--setenv); child_env is unused here.
    EXPECT_TRUE(plan->child_env.empty());
}

// ===========================================================================
// backend_build_launch() — jail ON prepends the pasta netns-jail wrap
// ===========================================================================

TEST(BackendGoldenArgv, PastaJailWrapNonStrict) {
    Config cfg;
    LaunchInputs in = make_inputs(cfg);
    in.jail_active = true;
    in.strict_jail = false;
    in.pasta_path = std::string("/usr/bin/pasta");
    in.jail_forward_ports = {18080};

    std::string err;
    auto plan = backend_build_launch(in, err);
    ASSERT_TRUE(plan.has_value()) << err;

    EXPECT_EQ(plan->launch_path, "/usr/bin/pasta");
    ASSERT_FALSE(plan->argv.empty());
    EXPECT_EQ(plan->argv[0], "/usr/bin/pasta");

    EXPECT_TRUE(has_token(plan->argv, "--config-net"));
    EXPECT_TRUE(has_token(plan->argv, "-t"));
    EXPECT_TRUE(has_token(plan->argv, "none"));
    EXPECT_TRUE(has_token(plan->argv, "-T"));
    EXPECT_TRUE(has_token(plan->argv, "18080"));
    EXPECT_TRUE(has_token(plan->argv, "--"));  // separator before the bwrap argv

    // Non-strict must NOT bind pasta's outbound to loopback.
    EXPECT_FALSE(has_token(plan->argv, "-o"));
    EXPECT_FALSE(has_token(plan->argv, "127.0.0.1"));
}

TEST(BackendGoldenArgv, PastaJailWrapStrictAddsOutboundBind) {
    Config cfg;
    LaunchInputs in = make_inputs(cfg);
    in.jail_active = true;
    in.strict_jail = true;
    in.pasta_path = std::string("/usr/bin/pasta");
    in.jail_forward_ports = {18080};

    std::string err;
    auto plan = backend_build_launch(in, err);
    ASSERT_TRUE(plan.has_value()) << err;

    EXPECT_EQ(plan->launch_path, "/usr/bin/pasta");
    ASSERT_FALSE(plan->argv.empty());
    EXPECT_EQ(plan->argv[0], "/usr/bin/pasta");

    // Strict jail adds the -o 127.0.0.1 outbound bind (bridge-only egress firewall).
    EXPECT_TRUE(has_token(plan->argv, "-o"));
    EXPECT_TRUE(has_token(plan->argv, "127.0.0.1"));
    EXPECT_TRUE(has_token(plan->argv, "-T"));
    EXPECT_TRUE(has_token(plan->argv, "18080"));
    EXPECT_TRUE(has_token(plan->argv, "--"));
}
