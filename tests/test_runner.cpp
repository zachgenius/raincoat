// Unit tests for runner::resolve_config.
//
// resolve_config is a PURE resolution step: given a parsed CliInvocation, a
// (fake) parent environment, and a working directory, it produces the fully
// resolved Config that the runner would execute against. It execs nothing and
// touches the filesystem only to load a --profile file, so we can exercise all
// of its precedence/default rules in-process with injected inputs.
//
// Behaviours under test (docs/DESIGN.md, docs/SPEC.md, src/runner.cpp):
//   * strict  => network defaults to Off
//   * !strict => network defaults to Full
//   * explicit --net always wins over the strict-derived default
//   * TZ / LANG / LC_ALL env defaults are injected (without clobbering user ones)
//   * audit_log default = cwd + "/.raincoat/audit.log"
//   * workdir default   = cwd
//   * profile + CLI merge precedence: CLI flags override profile values
#include <gtest/gtest.h>

#include <atomic>
#include <filesystem>
#include <fstream>
#include <map>
#include <string>

#include "config.hpp"
#include "runner.hpp"

using raincoat::CliInvocation;
using raincoat::Config;
using raincoat::NetMode;
using raincoat::Options;
using raincoat::resolve_config;
using raincoat::Subcommand;

namespace {

// A representative fake parent environment. resolve_config does not currently
// read it (env resolution happens later, in run()), but the contract takes one,
// so we inject a realistic map to keep the call honest and future-proof.
std::map<std::string, std::string> fake_parent_env() {
    return {
        {"PATH", "/usr/bin:/bin"},
        {"HOME", "/home/tester"},
        {"TERM", "xterm"},
        {"OPENAI_API_KEY", "leakme"},
    };
}

// Build a minimal Run invocation carrying the given options.
CliInvocation run_inv(Options opt) {
    CliInvocation inv;
    inv.sub = Subcommand::Run;
    inv.options = std::move(opt);
    return inv;
}

// Write `content` to a fresh, uniquely-named temp file and return its path.
std::string write_temp_profile(const std::string& content) {
    namespace fs = std::filesystem;
    static std::atomic<unsigned> counter{0};
    fs::path dir = fs::temp_directory_path() / "rc-runner-tests";
    fs::create_directories(dir);
    fs::path p = dir / ("profile-" + std::to_string(counter.fetch_add(1)) + ".toml");
    std::ofstream ofs(p, std::ios::binary | std::ios::trunc);
    ofs << content;
    ofs.close();
    return p.string();
}

const char kCwd[] = "/work/project";

}  // namespace

// ---------------------------------------------------------------------------
// Network default derived from strict
// ---------------------------------------------------------------------------

TEST(ResolveConfig, StrictDefaultsNetworkOff) {
    Options opt;
    opt.strict = true;
    opt.strict_set = true;

    std::string err;
    Config cfg = resolve_config(run_inv(opt), fake_parent_env(), kCwd, err);

    EXPECT_TRUE(err.empty()) << err;
    EXPECT_TRUE(cfg.strict);
    EXPECT_EQ(cfg.net, NetMode::Off);
}

TEST(ResolveConfig, NonStrictDefaultsNetworkFull) {
    Options opt;  // strict stays false

    std::string err;
    Config cfg = resolve_config(run_inv(opt), fake_parent_env(), kCwd, err);

    EXPECT_TRUE(err.empty()) << err;
    EXPECT_FALSE(cfg.strict);
    EXPECT_EQ(cfg.net, NetMode::Full);
}

// ---------------------------------------------------------------------------
// Explicit --net wins over the strict-derived default, both directions
// ---------------------------------------------------------------------------

TEST(ResolveConfig, ExplicitNetFullBeatsStrictOffDefault) {
    Options opt;
    opt.strict = true;
    opt.strict_set = true;
    opt.net = NetMode::Full;  // user forced networking on despite strict

    std::string err;
    Config cfg = resolve_config(run_inv(opt), fake_parent_env(), kCwd, err);

    EXPECT_TRUE(err.empty()) << err;
    EXPECT_EQ(cfg.net, NetMode::Full);
}

TEST(ResolveConfig, ExplicitNetOffBeatsNonStrictFullDefault) {
    Options opt;  // non-strict
    opt.net = NetMode::Off;

    std::string err;
    Config cfg = resolve_config(run_inv(opt), fake_parent_env(), kCwd, err);

    EXPECT_TRUE(err.empty()) << err;
    EXPECT_EQ(cfg.net, NetMode::Off);
}

// ---------------------------------------------------------------------------
// Locale / timezone env defaults are injected
// ---------------------------------------------------------------------------

TEST(ResolveConfig, InjectsLocaleAndTimezoneDefaults) {
    Options opt;

    std::string err;
    Config cfg = resolve_config(run_inv(opt), fake_parent_env(), kCwd, err);

    ASSERT_TRUE(err.empty()) << err;
    ASSERT_EQ(cfg.env_defaults.count("TZ"), 1u);
    ASSERT_EQ(cfg.env_defaults.count("LANG"), 1u);
    ASSERT_EQ(cfg.env_defaults.count("LC_ALL"), 1u);
    EXPECT_EQ(cfg.env_defaults["TZ"], "UTC");
    EXPECT_EQ(cfg.env_defaults["LANG"], "en_US.UTF-8");
    EXPECT_EQ(cfg.env_defaults["LC_ALL"], "en_US.UTF-8");
}

TEST(ResolveConfig, DoesNotClobberUserSuppliedEnvDefaults) {
    Options opt;
    opt.env_defaults["TZ"] = "America/New_York";  // user override

    std::string err;
    Config cfg = resolve_config(run_inv(opt), fake_parent_env(), kCwd, err);

    ASSERT_TRUE(err.empty()) << err;
    EXPECT_EQ(cfg.env_defaults["TZ"], "America/New_York");
    // The unmentioned defaults are still backfilled.
    EXPECT_EQ(cfg.env_defaults["LANG"], "en_US.UTF-8");
    EXPECT_EQ(cfg.env_defaults["LC_ALL"], "en_US.UTF-8");
}

// ---------------------------------------------------------------------------
// audit_log + workdir defaults come from cwd
// ---------------------------------------------------------------------------

TEST(ResolveConfig, AuditLogDefaultsUnderCwd) {
    Options opt;

    std::string err;
    Config cfg = resolve_config(run_inv(opt), fake_parent_env(), kCwd, err);

    ASSERT_TRUE(err.empty()) << err;
    EXPECT_EQ(cfg.audit_log_path, std::string(kCwd) + "/.raincoat/audit.log");
}

TEST(ResolveConfig, WorkdirDefaultsToCwd) {
    Options opt;

    std::string err;
    Config cfg = resolve_config(run_inv(opt), fake_parent_env(), kCwd, err);

    ASSERT_TRUE(err.empty()) << err;
    EXPECT_EQ(cfg.workdir, kCwd);
}

TEST(ResolveConfig, ExplicitWorkdirAndAuditLogWin) {
    Options opt;
    opt.workdir = "/somewhere/else";
    opt.audit_log = "/var/log/raincoat.log";

    std::string err;
    Config cfg = resolve_config(run_inv(opt), fake_parent_env(), kCwd, err);

    ASSERT_TRUE(err.empty()) << err;
    EXPECT_EQ(cfg.workdir, "/somewhere/else");
    EXPECT_EQ(cfg.audit_log_path, "/var/log/raincoat.log");
}

// ---------------------------------------------------------------------------
// Profile + CLI merge precedence (real temp profile file)
// ---------------------------------------------------------------------------

TEST(ResolveConfig, CliNetOverridesProfileNet) {
    // Profile asks for strict + network off; CLI explicitly forces network full.
    const std::string profile = write_temp_profile(
        "strict = true\n"
        "network = \"off\"\n"
        "allow_read = [\"/etc/hostname\"]\n");

    Options cli;
    cli.profile_path = profile;
    cli.net = NetMode::Full;  // CLI override

    std::string err;
    Config cfg = resolve_config(run_inv(cli), fake_parent_env(), kCwd, err);

    ASSERT_TRUE(err.empty()) << err;
    // strict comes from the profile (CLI did not set it)...
    EXPECT_TRUE(cfg.strict);
    // ...but the explicit CLI --net wins over the profile's network = "off".
    EXPECT_EQ(cfg.net, NetMode::Full);
    // list values from the profile survive the merge.
    ASSERT_EQ(cfg.allow_read.size(), 1u);
    EXPECT_EQ(cfg.allow_read[0], "/etc/hostname");
}

TEST(ResolveConfig, CliStrictOverridesProfileStrict) {
    // Profile is non-strict; CLI forces strict. Since CLI does NOT pass --net,
    // the network default must be derived from the *merged* strict value (Off).
    const std::string profile = write_temp_profile(
        "strict = false\n"
        "network = \"full\"\n");

    Options cli;
    cli.profile_path = profile;
    cli.strict = true;
    cli.strict_set = true;  // CLI explicitly set --strict

    std::string err;
    Config cfg = resolve_config(run_inv(cli), fake_parent_env(), kCwd, err);

    ASSERT_TRUE(err.empty()) << err;
    EXPECT_TRUE(cfg.strict);
    // Profile said network = full, but merge() keeps the profile net only when
    // CLI has none; here the profile explicitly set full, so net stays Full even
    // though strict is now true. This documents the exact precedence: an
    // explicit profile network survives, it is not re-derived from strict.
    EXPECT_EQ(cfg.net, NetMode::Full);
}

TEST(ResolveConfig, MissingProfileFileYieldsError) {
    Options cli;
    cli.profile_path = "/no/such/profile/raincoat.toml";

    std::string err;
    Config cfg = resolve_config(run_inv(cli), fake_parent_env(), kCwd, err);

    EXPECT_FALSE(err.empty());
}
