// Raincoat — attack-round-3 honesty test for the reserved network-mode audit note.
//
// This test encodes an HONESTY guarantee the code CLAIMS but does NOT deliver. It
// is expected to FAIL against the current tree; the failing assertion IS the bug
// report. No production code is changed in this round.
//
// Defect (honesty, profile/audit): the persistent audit "Reserved (configured, not
//   enforced)" note for a reserved network mode (proxy/bridge/guarded) is a STATIC
//   string baked at profile-load time (profile.cpp): it asserts, unconditionally,
//   that "network fails closed to \"off\" (egress is NOT restricted as configured)".
//   But resolve_config lets an explicit CLI `--net full` override the fail-closed
//   fallback (options.net wins over ext.reserved_net_mode), so the child actually
//   gets FULL, unrestricted network. The note is never reconciled with the resolved
//   net. Result: the tamper-proof audit log simultaneously headlines "Network: full"
//   AND records a reserved note swearing the network "fails closed to off" — a
//   directly FALSE security claim. A reviewer reading the reserved section would
//   conclude the sandbox had no egress when in fact it had full egress. (The stderr
//   warning IS reconciled — it says "fell back to full" — but the persisted audit
//   note that outlives the run is not.)
//
//   Reproduced end-to-end against the binary: a profile with `network = "bridge"`
//   run with `--net full` writes an audit log whose reserved note claims fail-closed
//   to off while "Network: full" and the (network-enabled) bwrap command — no
//   --unshare-net, resolv.conf bound — show full connectivity.

#include <gtest/gtest.h>

#include <atomic>
#include <filesystem>
#include <fstream>
#include <string>

#include "audit.hpp"
#include "config.hpp"
#include "runner.hpp"

namespace fs = std::filesystem;
using namespace raincoat;

namespace {

std::string write_profile(const std::string& body) {
  static std::atomic<unsigned> counter{0};
  fs::path dir = fs::temp_directory_path() / "rc-net-honesty";
  fs::create_directories(dir);
  fs::path p = dir / ("profile-" + std::to_string(counter.fetch_add(1)) + ".toml");
  std::ofstream(p, std::ios::binary | std::ios::trunc) << body;
  return p.string();
}

// Rebuild the audit record exactly as run() does for the fields under test.
AuditRecord audit_from(const Config& cfg) {
  AuditRecord rec;
  rec.net = cfg.net;
  rec.profile_name = cfg.ext.profile_name;
  rec.reserved_notes = cfg.ext.reserved_notes;
  return rec;
}

}  // namespace

// ---------------------------------------------------------------------------
// The reserved note must not assert "fails closed to off" when the resolved
// network is actually full (an explicit --net full overrode the fallback).
// ---------------------------------------------------------------------------
TEST(ReservedNetHonestyAttack, BridgeNoteMustNotClaimFailClosedWhenNetIsFull) {
  const std::string profile = write_profile("network = \"bridge\"\n");

  // CLI: explicit --net full (the documented override) atop the reserved-mode profile.
  Options cli;
  cli.net = NetMode::Full;
  cli.profile_path = profile;

  CliInvocation inv;
  inv.sub = Subcommand::Run;
  inv.options = cli;

  std::string err;
  Config cfg = resolve_config(inv, /*parent_env=*/{}, /*cwd=*/"/work", err);
  ASSERT_TRUE(err.empty()) << err;

  // Sanity: the override took effect — the child really gets full network.
  ASSERT_EQ(cfg.net, NetMode::Full);

  // Data-level: no reserved note may assert the fail-closed-to-off outcome while the
  // resolved network is full. That is the false claim persisted to the audit.
  for (const auto& note : cfg.ext.reserved_notes) {
    EXPECT_EQ(note.find("fails closed to \"off\""), std::string::npos)
        << "reserved note dishonestly claims the network fails closed to off while "
           "cfg.net == full (the child has unrestricted egress): " << note;
    EXPECT_EQ(note.find("egress is NOT restricted as configured"), std::string::npos)
        << "reserved note asserts egress is unrestricted-as-configured yet the child "
           "actually got FULL network, not the reserved (restricted) mode: " << note;
  }

  // Rendered audit: the headline and the reserved section must not contradict each
  // other. When "Network: full" is printed, the audit body must not also swear the
  // network fails closed to off.
  const std::string text = format_audit_start(audit_from(cfg));
  ASSERT_NE(text.find("Network:      full"), std::string::npos) << text;
  EXPECT_EQ(text.find("fails closed to \"off\""), std::string::npos)
      << "the tamper-proof audit log both headlines Network: full AND records a "
         "reserved note claiming the network fails closed to off — a directly false "
         "security statement in the persisted audit:\n"
      << text;
}
