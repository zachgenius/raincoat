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
#include <cstdlib>
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

// ---------------------------------------------------------------------------
// Egress bridge mode (phase 2) — network resolution + conflict handling
// ---------------------------------------------------------------------------

// A minimal profile enabling egress bridge mode with one bridge.
static const char kEgressProfile[] =
    "[egress]\n"
    "mode = \"bridge\"\n"
    "hide_upstreams_from_child = true\n"
    "\n"
    "[[egress.bridge]]\n"
    "name = \"primary-api\"\n"
    "env = \"SOME_BASE_URL\"\n"
    "child_endpoint = \"http://127.0.0.1:18080\"\n"
    "upstream_endpoint = \"https://real-upstream.example.com\"\n";

TEST(ResolveConfigEgress, BridgeModeSharesHostNet) {
    // Egress bridge mode needs loopback reachability, so the resolved network must be
    // SHARED host net (Full for flag emission => no --unshare-net), NOT fail-closed off.
    const std::string profile = write_temp_profile(kEgressProfile);
    Options cli;
    cli.profile_path = profile;

    std::string err;
    Config cfg = resolve_config(run_inv(cli), fake_parent_env(), kCwd, err);

    ASSERT_TRUE(err.empty()) << err;
    EXPECT_TRUE(cfg.ext.egress.enabled);
    EXPECT_EQ(cfg.net, NetMode::Full);
    // The profile path is carried through for the leak guard.
    ASSERT_TRUE(cfg.profile_path.has_value());
    EXPECT_EQ(*cfg.profile_path, profile);
    // The upstream endpoint survives in config (host-side only) but is never a net mode.
    ASSERT_EQ(cfg.ext.egress.bridges.size(), 1u);
    EXPECT_EQ(cfg.ext.egress.bridges[0].upstream_endpoint,
              "https://real-upstream.example.com");
}

TEST(ResolveConfigEgress, BridgeModeStrictStillSharesHostNet) {
    // Even under --strict (which would otherwise default net to Off), egress bridge mode
    // wins so the child can reach the bridge.
    const std::string profile = write_temp_profile(kEgressProfile);
    Options cli;
    cli.profile_path = profile;
    cli.strict = true;
    cli.strict_set = true;

    std::string err;
    Config cfg = resolve_config(run_inv(cli), fake_parent_env(), kCwd, err);

    ASSERT_TRUE(err.empty()) << err;
    EXPECT_TRUE(cfg.strict);
    EXPECT_EQ(cfg.net, NetMode::Full);
}

TEST(ResolveConfigEgress, ExplicitNetOffConflictsRefused) {
    // Egress needs reachability; an explicit --net off contradicts it => hard error.
    const std::string profile = write_temp_profile(kEgressProfile);
    Options cli;
    cli.profile_path = profile;
    cli.net = NetMode::Off;  // explicit CLI --net off

    std::string err;
    Config cfg = resolve_config(run_inv(cli), fake_parent_env(), kCwd, err);

    EXPECT_FALSE(err.empty());
    EXPECT_NE(err.find("egress"), std::string::npos);
}

TEST(ResolveConfigEgress, ProfileNetworkOffConflictsRefused) {
    // Same conflict when network="off" comes from the profile itself.
    const std::string profile = write_temp_profile(
        std::string("network = \"off\"\n") + kEgressProfile);
    Options cli;
    cli.profile_path = profile;

    std::string err;
    Config cfg = resolve_config(run_inv(cli), fake_parent_env(), kCwd, err);

    EXPECT_FALSE(err.empty());
    EXPECT_NE(err.find("egress"), std::string::npos);
}

TEST(ResolveConfigEgress, ExplicitNetFullHonoredWithEgress) {
    // An explicit --net full is compatible with egress (still shared host net).
    const std::string profile = write_temp_profile(kEgressProfile);
    Options cli;
    cli.profile_path = profile;
    cli.net = NetMode::Full;

    std::string err;
    Config cfg = resolve_config(run_inv(cli), fake_parent_env(), kCwd, err);

    ASSERT_TRUE(err.empty()) << err;
    EXPECT_EQ(cfg.net, NetMode::Full);
    EXPECT_TRUE(cfg.ext.egress.enabled);
}

// ===========================================================================
// audit_hides_upstream — per-bridge audit-redaction precedence (pure)
// ===========================================================================
//
// This is the exact decision the runner uses to redact each bridge's upstream in the audit
// (see runner.cpp). It must fail CLOSED: an upstream is disclosed ONLY when every hiding
// condition is off. Locks docs/EGRESS.md "Audit redaction (per-bridge)".

namespace {
// Build a global egress config with the given global redaction flag, and a bridge with the
// given per-bridge hide_upstream, then evaluate the redaction predicate.
bool hides(bool global_redact, bool bridge_hide, bool child_readable) {
    raincoat::EgressConfig eg;
    eg.redact_upstreams_in_audit = global_redact;
    raincoat::EgressBridge br;
    br.hide_upstream = bridge_hide;
    return raincoat::audit_hides_upstream(eg, br, child_readable);
}
}  // namespace

// Default posture (both flags default true, audit not child-readable): upstream hidden.
TEST(AuditHidesUpstream, DefaultsHide) {
    EXPECT_TRUE(hides(/*global*/ true, /*bridge*/ true, /*child_readable*/ false));
}

// The ONLY way to disclose an upstream: global redaction off AND this bridge's
// hide_upstream off AND the audit is not child-readable.
TEST(AuditHidesUpstream, AllOffDiscloses) {
    EXPECT_FALSE(hides(/*global*/ false, /*bridge*/ false, /*child_readable*/ false));
}

// Global redaction off but the per-bridge hide_upstream still true: hidden. This is the
// per-bridge knob being LIVE (a sibling with hide_upstream=false can be shown while this one
// stays hidden).
TEST(AuditHidesUpstream, PerBridgeHideOverridesGlobalOff) {
    EXPECT_TRUE(hides(/*global*/ false, /*bridge*/ true, /*child_readable*/ false));
}

// Global redaction on hides regardless of the per-bridge flag.
TEST(AuditHidesUpstream, GlobalRedactHidesEvenIfBridgeShown) {
    EXPECT_TRUE(hides(/*global*/ true, /*bridge*/ false, /*child_readable*/ false));
}

// Fail-closed: a child-READABLE audit forces hiding even when BOTH the global flag and the
// per-bridge flag are off — the upstream must NEVER be revealed to a child that can read the
// audit, regardless of the flags.
TEST(AuditHidesUpstream, ChildReadableForcesHideRegardlessOfFlags) {
    EXPECT_TRUE(hides(/*global*/ false, /*bridge*/ false, /*child_readable*/ true));
    EXPECT_TRUE(hides(/*global*/ false, /*bridge*/ true, /*child_readable*/ true));
    EXPECT_TRUE(hides(/*global*/ true, /*bridge*/ false, /*child_readable*/ true));
}

// ===========================================================================
// discover_default_config — config auto-discovery precedence
// ===========================================================================
namespace {
namespace fs = std::filesystem;

fs::path make_temp_dir() {
    static std::atomic<int> ctr{0};
    fs::path d = fs::temp_directory_path() / ("rc_disc_test_" + std::to_string(ctr++));
    fs::remove_all(d);
    fs::create_directories(d);
    return d;
}

void write_toml(const fs::path& p) {
    fs::create_directories(p.parent_path());
    std::ofstream(p) << "allow_read = []\n";
}

// RAII env override so tests don't leak HOME/XDG changes into each other.
struct ScopedEnv {
    std::string key, old;
    bool had;
    ScopedEnv(const char* k, const std::string& v) : key(k) {
        const char* o = std::getenv(k);
        had = (o != nullptr);
        if (had) old = o;
        ::setenv(k, v.c_str(), 1);
    }
    ~ScopedEnv() {
        if (had) ::setenv(key.c_str(), old.c_str(), 1);
        else ::unsetenv(key.c_str());
    }
};
}  // namespace

using raincoat::discover_default_config;

TEST(DiscoverConfig, ProjectLocalRaincoatTomlWins) {
    fs::path cwd = make_temp_dir();
    write_toml(cwd / ".raincoat.toml");
    auto got = discover_default_config(cwd.string());
    ASSERT_TRUE(got.has_value());
    EXPECT_EQ(*got, (cwd / ".raincoat.toml").string());
    fs::remove_all(cwd);
}

TEST(DiscoverConfig, XdgUserConfigWhenNoProjectLocal) {
    fs::path cwd = make_temp_dir();               // no project config
    fs::path xdg = make_temp_dir();
    write_toml(xdg / "raincoat" / "config.toml");
    ScopedEnv e("XDG_CONFIG_HOME", xdg.string());
    auto got = discover_default_config(cwd.string());
    ASSERT_TRUE(got.has_value());
    EXPECT_EQ(*got, (xdg / "raincoat" / "config.toml").string());
    fs::remove_all(cwd);
    fs::remove_all(xdg);
}

TEST(DiscoverConfig, ProjectLocalBeatsUserConfig) {
    fs::path cwd = make_temp_dir();
    write_toml(cwd / ".raincoat.toml");
    fs::path xdg = make_temp_dir();
    write_toml(xdg / "raincoat" / "config.toml");
    ScopedEnv e("XDG_CONFIG_HOME", xdg.string());
    auto got = discover_default_config(cwd.string());
    ASSERT_TRUE(got.has_value());
    EXPECT_EQ(*got, (cwd / ".raincoat.toml").string());
    fs::remove_all(cwd);
    fs::remove_all(xdg);
}

TEST(DiscoverConfig, NothingFoundIsNullopt) {
    fs::path cwd = make_temp_dir();               // empty
    fs::path home = make_temp_dir();               // empty home, no ~/.config or ~/.raincoat.toml
    ScopedEnv eh("HOME", home.string());
    ScopedEnv ex("XDG_CONFIG_HOME", (home / "nope").string());
    auto got = discover_default_config(cwd.string());
    EXPECT_FALSE(got.has_value());
    fs::remove_all(cwd);
    fs::remove_all(home);
}
