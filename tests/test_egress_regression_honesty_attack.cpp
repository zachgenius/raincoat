// Attack round 1: regression + honesty tests for wiring the egress bridge into
// the live sandbox (src/runner.cpp resolve_config + profile.cpp egress parsing).
//
// Three invariants under attack here:
//
//   1. NO REGRESSION when egress is NOT configured. A flat / no-profile run must
//      resolve networking exactly as before (non-strict => Full, strict => Off),
//      with ext.egress.enabled false and no reserved network mode.
//
//   2. FAIL CLOSED for a restrictive egress intent that never activated. A profile
//      that asks for [egress] mode="bridge" but supplies ZERO bridges expressed a
//      clear intent to CONSTRAIN the network; it must NOT silently fall through to
//      Full (shared host net). It must fail closed to NetMode::Off.
//
//   3. HONESTY. When egress bridge forwarding is genuinely active, the resolved
//      audit note must state that the sandbox SHARES the host network namespace and
//      the child is NOT network-jailed. It must NOT overclaim that the child can
//      "only reach the bridge" / cannot reach the general network.
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

std::map<std::string, std::string> fake_parent_env() {
    return {{"PATH", "/usr/bin:/bin"}, {"HOME", "/home/tester"}};
}

CliInvocation run_inv(Options opt) {
    CliInvocation inv;
    inv.sub = Subcommand::Run;
    inv.options = std::move(opt);
    return inv;
}

std::string write_temp_profile(const std::string& content) {
    namespace fs = std::filesystem;
    static std::atomic<unsigned> counter{0};
    fs::path dir = fs::temp_directory_path() / "rc-egress-regress-tests";
    fs::create_directories(dir);
    fs::path p = dir / ("profile-" + std::to_string(counter.fetch_add(1)) + ".toml");
    std::ofstream ofs(p, std::ios::binary | std::ios::trunc);
    ofs << content;
    ofs.close();
    return p.string();
}

const char kCwd[] = "/work/project";

// Find any reserved note mentioning the reconciled network outcome.
bool any_note_contains(const Config& cfg, const std::string& needle) {
    for (const auto& n : cfg.ext.reserved_notes)
        if (n.find(needle) != std::string::npos) return true;
    return false;
}

}  // namespace

// ===========================================================================
// (1) NO REGRESSION when egress is not configured
// ===========================================================================

TEST(EgressRegression, NoProfileNonStrictStillFull) {
    Options opt;  // non-strict, no profile, no egress
    std::string err;
    Config cfg = resolve_config(run_inv(opt), fake_parent_env(), kCwd, err);

    ASSERT_TRUE(err.empty()) << err;
    EXPECT_EQ(cfg.net, NetMode::Full);
    EXPECT_FALSE(cfg.ext.egress.enabled);
    EXPECT_FALSE(cfg.ext.reserved_net_mode.has_value());
}

TEST(EgressRegression, NoProfileStrictStillOff) {
    Options opt;
    opt.strict = true;
    opt.strict_set = true;
    std::string err;
    Config cfg = resolve_config(run_inv(opt), fake_parent_env(), kCwd, err);

    ASSERT_TRUE(err.empty()) << err;
    EXPECT_EQ(cfg.net, NetMode::Off);
    EXPECT_FALSE(cfg.ext.egress.enabled);
    EXPECT_FALSE(cfg.ext.reserved_net_mode.has_value());
}

TEST(EgressRegression, FlatNetOffProfileUnchanged) {
    // A plain network="off" profile (no egress) must still resolve Off with NO
    // reserved egress mode leaking in — behaves exactly as before phase 2.
    const std::string profile = write_temp_profile("network = \"off\"\n");
    Options cli;
    cli.profile_path = profile;
    std::string err;
    Config cfg = resolve_config(run_inv(cli), fake_parent_env(), kCwd, err);

    ASSERT_TRUE(err.empty()) << err;
    EXPECT_EQ(cfg.net, NetMode::Off);
    EXPECT_FALSE(cfg.ext.egress.enabled);
    EXPECT_FALSE(cfg.ext.reserved_net_mode.has_value());
}

// An [egress] section with mode="disabled" is NOT a restrictive intent; it must
// not force fail-closed, i.e. a non-strict run keeps the ordinary Full default.
TEST(EgressRegression, EgressModeDisabledDoesNotFailClosed) {
    const std::string profile = write_temp_profile(
        "[egress]\n"
        "mode = \"disabled\"\n");
    Options cli;
    cli.profile_path = profile;
    std::string err;
    Config cfg = resolve_config(run_inv(cli), fake_parent_env(), kCwd, err);

    ASSERT_TRUE(err.empty()) << err;
    EXPECT_FALSE(cfg.ext.egress.enabled);
    EXPECT_FALSE(cfg.ext.reserved_net_mode.has_value());
    EXPECT_EQ(cfg.net, NetMode::Full);
}

// ===========================================================================
// (2) FAIL CLOSED: mode="bridge" with ZERO bridges must NOT silently share net
// ===========================================================================

TEST(EgressFailClosed, BridgeModeZeroBridgesFailsClosedOffNonStrict) {
    // The attack: a profile asks for bridge egress but forgets the [[egress.bridge]]
    // entries. Before the fix this fell through to the non-strict Full default and
    // SILENTLY SHARED the host network. It must fail closed to Off instead.
    const std::string profile = write_temp_profile(
        "[egress]\n"
        "mode = \"bridge\"\n");
    Options cli;
    cli.profile_path = profile;  // non-strict
    std::string err;
    Config cfg = resolve_config(run_inv(cli), fake_parent_env(), kCwd, err);

    ASSERT_TRUE(err.empty()) << err;
    EXPECT_FALSE(cfg.ext.egress.enabled);
    EXPECT_EQ(cfg.net, NetMode::Off)
        << "zero-bridge bridge mode must fail closed to off, not share the host net";
}

TEST(EgressFailClosed, BridgeModeZeroBridgesFailsClosedOffStrict) {
    const std::string profile = write_temp_profile(
        "[egress]\n"
        "mode = \"bridge\"\n");
    Options cli;
    cli.profile_path = profile;
    cli.strict = true;
    cli.strict_set = true;
    std::string err;
    Config cfg = resolve_config(run_inv(cli), fake_parent_env(), kCwd, err);

    ASSERT_TRUE(err.empty()) << err;
    EXPECT_EQ(cfg.net, NetMode::Off);
    EXPECT_FALSE(cfg.ext.egress.enabled);
}

// The reconciled audit note must HONESTLY state the restriction was not enforced
// and networking fell closed to off — never claim the bridge is active.
TEST(EgressFailClosed, BridgeModeZeroBridgesNoteIsHonest) {
    const std::string profile = write_temp_profile(
        "[egress]\n"
        "mode = \"bridge\"\n");
    Options cli;
    cli.profile_path = profile;
    std::string err;
    Config cfg = resolve_config(run_inv(cli), fake_parent_env(), kCwd, err);

    ASSERT_TRUE(err.empty()) << err;
    ASSERT_TRUE(cfg.ext.reserved_net_mode.has_value());
    EXPECT_TRUE(any_note_contains(cfg, "fails closed"))
        << "reserved note should disclose the fail-closed-to-off outcome";
    // Must NOT dishonestly claim the bridge forwarding is active in this case.
    EXPECT_FALSE(any_note_contains(cfg, "egress bridge forwarding is ACTIVE"));
}

// A non-strict run must not accidentally regress via a proxy/guarded egress mode
// that is likewise not implemented: also fail closed.
TEST(EgressFailClosed, ProxyEgressModeFailsClosedOffNonStrict) {
    const std::string profile = write_temp_profile(
        "[egress]\n"
        "mode = \"proxy\"\n");
    Options cli;
    cli.profile_path = profile;
    std::string err;
    Config cfg = resolve_config(run_inv(cli), fake_parent_env(), kCwd, err);

    ASSERT_TRUE(err.empty()) << err;
    EXPECT_FALSE(cfg.ext.egress.enabled);
    EXPECT_EQ(cfg.net, NetMode::Off);
}

// ===========================================================================
// (3) HONESTY: active bridge shares host net and is NOT a network jail
// ===========================================================================

// Profile with a reserved top-level network="bridge" AND a genuinely active egress
// bridge. The reconciled reserved note must honestly disclose the shared-host-net,
// not-a-jail model and NOT overclaim that the child can only reach the bridge.
static const char kActiveEgressProfile[] =
    "network = \"bridge\"\n"
    "[egress]\n"
    "mode = \"bridge\"\n"
    "[[egress.bridge]]\n"
    "name = \"primary\"\n"
    "env = \"SOME_BASE_URL\"\n"
    "child_endpoint = \"http://127.0.0.1:18080\"\n"
    "upstream_endpoint = \"https://real-upstream.example.com\"\n";

TEST(EgressHonesty, ActiveBridgeSharesHostNetAndSaysSo) {
    const std::string profile = write_temp_profile(kActiveEgressProfile);
    Options cli;
    cli.profile_path = profile;
    std::string err;
    Config cfg = resolve_config(run_inv(cli), fake_parent_env(), kCwd, err);

    ASSERT_TRUE(err.empty()) << err;
    EXPECT_TRUE(cfg.ext.egress.enabled);
    EXPECT_EQ(cfg.net, NetMode::Full);  // shared host net (no --unshare-net)
    // Honest disclosure present.
    EXPECT_TRUE(any_note_contains(cfg, "SHARES the host network namespace"));
    EXPECT_TRUE(any_note_contains(cfg, "NOT"));
    EXPECT_TRUE(any_note_contains(cfg, "network-jailed") ||
                any_note_contains(cfg, "general host network"));
}

TEST(EgressHonesty, ActiveBridgeDoesNotOverclaimJail) {
    const std::string profile = write_temp_profile(kActiveEgressProfile);
    Options cli;
    cli.profile_path = profile;
    std::string err;
    Config cfg = resolve_config(run_inv(cli), fake_parent_env(), kCwd, err);

    ASSERT_TRUE(err.empty()) << err;
    // These phrases would each be a dishonest OVERCLAIM: the child is NOT jailed to
    // the bridge; the shared host namespace leaves general network reachable.
    EXPECT_FALSE(any_note_contains(cfg, "only reach the bridge"));
    EXPECT_FALSE(any_note_contains(cfg, "can only reach"));
    EXPECT_FALSE(any_note_contains(cfg, "cannot reach the network"));
    EXPECT_FALSE(any_note_contains(cfg, "network is jailed"));
    EXPECT_FALSE(any_note_contains(cfg, "blocks all other network"));
}
