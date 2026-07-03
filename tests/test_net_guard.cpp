// Raincoat — net_guard test suite (TDD red).
//
// Contract under test (docs/DESIGN.md "net_guard", docs/SPEC.md "Network modes"):
//   std::vector<std::string> net_flags(NetMode m);   // Off -> {"--unshare-net"}; Full -> {}
//   bool binds_resolv_conf(NetMode m);               // true ONLY for Full
//
// MVP semantics for the reserved enum values (Allowlist / Ask):
//   The MVP implements only Full and Off. Allowlist and Ask are reserved in the enum
//   so parsing / audit / argv assembly compile, but there is no allowlist/ask backend
//   yet. The documented, tested MVP behaviour is:
//     * net_flags(Allowlist) / net_flags(Ask): network is NOT unshared (these modes
//       conceptually permit some network), so they behave like Full and return {}.
//       They must never crash and must never emit "--unshare-net" (that would silently
//       turn an "allow some/ask" request into a hard network-off, the opposite intent).
//     * binds_resolv_conf(Allowlist) / binds_resolv_conf(Ask): false. DESIGN.md states
//       resolv.conf is bound "true only for Full"; the reserved modes do not yet get a
//       resolver view in the MVP.
//   These expectations are asserted explicitly below so the behaviour is pinned, not
//   accidental.

#include <algorithm>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include "config.hpp"
#include "net_guard.hpp"

using raincoat::NetMode;
using raincoat::net_flags;
using raincoat::binds_resolv_conf;

namespace {

const std::string kUnshareNet = "--unshare-net";

// Does `flags` contain the given token?
bool contains(const std::vector<std::string>& flags, const std::string& tok) {
    return std::find(flags.begin(), flags.end(), tok) != flags.end();
}

}  // namespace

// ---------------------------------------------------------------------------
// net_flags: the two implemented modes (core contract)
// ---------------------------------------------------------------------------

TEST(NetGuard, OffUnsharesNet) {
    EXPECT_EQ(net_flags(NetMode::Off), std::vector<std::string>{kUnshareNet});
}

TEST(NetGuard, OffFlagsHaveExactlyOneEntry) {
    const auto flags = net_flags(NetMode::Off);
    ASSERT_EQ(flags.size(), 1u);
    EXPECT_EQ(flags[0], kUnshareNet);
}

TEST(NetGuard, OffFlagSpelledExactly) {
    // Guard against typos like "--unshare-network" or "--unshare_net".
    const auto flags = net_flags(NetMode::Off);
    ASSERT_FALSE(flags.empty());
    EXPECT_EQ(flags.front(), "--unshare-net");
}

TEST(NetGuard, FullEmitsNoFlags) {
    EXPECT_TRUE(net_flags(NetMode::Full).empty());
}

TEST(NetGuard, FullDoesNotUnshareNet) {
    // The critical safety property for "full" networking: we must NOT unshare.
    EXPECT_FALSE(contains(net_flags(NetMode::Full), kUnshareNet));
}

// ---------------------------------------------------------------------------
// net_flags: reserved MVP modes (must not crash; documented behaviour)
// ---------------------------------------------------------------------------

TEST(NetGuard, AllowlistBehavesLikeFullForFlags) {
    // Reserved mode: network conceptually permitted -> no unshare -> empty flags.
    EXPECT_TRUE(net_flags(NetMode::Allowlist).empty());
    EXPECT_FALSE(contains(net_flags(NetMode::Allowlist), kUnshareNet));
}

TEST(NetGuard, AskBehavesLikeFullForFlags) {
    EXPECT_TRUE(net_flags(NetMode::Ask).empty());
    EXPECT_FALSE(contains(net_flags(NetMode::Ask), kUnshareNet));
}

TEST(NetGuard, ReservedModesNeverForceNetworkOff) {
    // Explicit anti-regression: neither reserved mode may silently hard-disable net.
    EXPECT_FALSE(contains(net_flags(NetMode::Allowlist), kUnshareNet));
    EXPECT_FALSE(contains(net_flags(NetMode::Ask), kUnshareNet));
}

TEST(NetGuard, OnlyOffProducesFlags) {
    // Of the four enum values, exactly one (Off) yields a non-empty flag list.
    EXPECT_TRUE(net_flags(NetMode::Full).empty());
    EXPECT_FALSE(net_flags(NetMode::Off).empty());
    EXPECT_TRUE(net_flags(NetMode::Allowlist).empty());
    EXPECT_TRUE(net_flags(NetMode::Ask).empty());
}

// ---------------------------------------------------------------------------
// net_flags: purity / stability
// ---------------------------------------------------------------------------

TEST(NetGuard, NetFlagsIsDeterministic) {
    // Same input -> same output across repeated calls (pure function).
    EXPECT_EQ(net_flags(NetMode::Off), net_flags(NetMode::Off));
    EXPECT_EQ(net_flags(NetMode::Full), net_flags(NetMode::Full));
    EXPECT_EQ(net_flags(NetMode::Allowlist), net_flags(NetMode::Allowlist));
    EXPECT_EQ(net_flags(NetMode::Ask), net_flags(NetMode::Ask));
}

TEST(NetGuard, OffAndFullDiffer) {
    EXPECT_NE(net_flags(NetMode::Off), net_flags(NetMode::Full));
}

// ---------------------------------------------------------------------------
// binds_resolv_conf: true ONLY for Full
// ---------------------------------------------------------------------------

TEST(NetGuard, BindsResolvConfTrueForFull) {
    EXPECT_TRUE(binds_resolv_conf(NetMode::Full));
}

TEST(NetGuard, BindsResolvConfFalseForOff) {
    EXPECT_FALSE(binds_resolv_conf(NetMode::Off));
}

TEST(NetGuard, BindsResolvConfFalseForAllowlist) {
    EXPECT_FALSE(binds_resolv_conf(NetMode::Allowlist));
}

TEST(NetGuard, BindsResolvConfFalseForAsk) {
    EXPECT_FALSE(binds_resolv_conf(NetMode::Ask));
}

TEST(NetGuard, BindsResolvConfIsDeterministic) {
    EXPECT_EQ(binds_resolv_conf(NetMode::Full), binds_resolv_conf(NetMode::Full));
    EXPECT_EQ(binds_resolv_conf(NetMode::Off), binds_resolv_conf(NetMode::Off));
}

// ---------------------------------------------------------------------------
// Cross-invariants tying the two functions together
// ---------------------------------------------------------------------------

TEST(NetGuard, ResolvConfImpliesNetworkNotUnshared) {
    // If we bind resolv.conf we must have network up (no --unshare-net), otherwise the
    // resolver view is dead weight inside an isolated netns.
    for (NetMode m : {NetMode::Full, NetMode::Off, NetMode::Allowlist, NetMode::Ask}) {
        if (binds_resolv_conf(m)) {
            EXPECT_FALSE(contains(net_flags(m), kUnshareNet))
                << "resolv.conf bound but network unshared for mode "
                << raincoat::to_string(m);
        }
    }
}

TEST(NetGuard, UnshareNetImpliesNoResolvConf) {
    // Contrapositive: whenever we unshare the network, we must not bind resolv.conf.
    for (NetMode m : {NetMode::Full, NetMode::Off, NetMode::Allowlist, NetMode::Ask}) {
        if (contains(net_flags(m), kUnshareNet)) {
            EXPECT_FALSE(binds_resolv_conf(m))
                << "network unshared but resolv.conf bound for mode "
                << raincoat::to_string(m);
        }
    }
}

TEST(NetGuard, FullIsTheOnlyResolvConfMode) {
    int resolv_modes = 0;
    for (NetMode m : {NetMode::Full, NetMode::Off, NetMode::Allowlist, NetMode::Ask}) {
        if (binds_resolv_conf(m)) ++resolv_modes;
    }
    EXPECT_EQ(resolv_modes, 1);
    EXPECT_TRUE(binds_resolv_conf(NetMode::Full));
}

// ---------------------------------------------------------------------------
// Robustness: exercising every enum value must never crash.
// ---------------------------------------------------------------------------

TEST(NetGuard, AllEnumValuesSafe) {
    for (NetMode m : {NetMode::Full, NetMode::Off, NetMode::Allowlist, NetMode::Ask}) {
        EXPECT_NO_THROW({
            volatile auto n = net_flags(m).size();
            (void)n;
            volatile bool b = binds_resolv_conf(m);
            (void)b;
        });
    }
}
