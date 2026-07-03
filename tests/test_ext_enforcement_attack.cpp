// Raincoat — attack-round-1 enforcement tests for ExtendedConfig wiring.
//
// These tests encode SECURITY / CORRECTNESS guarantees that the code CLAIMS in its
// own comments but does NOT actually deliver. They are expected to FAIL against the
// current tree; each one pins a concrete, reproduced defect. No production code is
// changed in this round — the failing assertions ARE the bug report.
//
// Defect A (security, fs_guard): the filesystem deny list is bypassable. plan_mounts
//   (and the runner comment at fs_guard.cpp) promise a denied path "must NEVER be
//   mounted — even when the user explicitly --allow-read/--allow-write's it." But the
//   deny check (fs_deny_hit) only refuses a mount whose ROOT is at/under a deny entry.
//   Bind-mounting a PARENT of a denied path exposes the denied child in full, and that
//   parent mount is NOT refused. So `deny = ["~/.ssh"]` + `--allow-read $HOME` leaks
//   the whole ~/.ssh tree into the sandbox. Reproduced end-to-end against the binary.
//
// Defect B (correctness, env_guard): custom scrub_patterns silently promote the
//   BUILT-IN sensitive-name heuristic to veto an explicit --allow-env. The contract
//   (config.hpp EnvPolicy docs + env_guard.cpp resolve_env comment) says the built-in
//   is_sensitive_env heuristic is "deliberately NOT part of this gate: a deliberate
//   `--allow-env OPENAI_API_KEY` must still work (only the user's own deny/scrub policy
//   is strong enough to veto an explicit allow)." But setting ANY unrelated scrub
//   pattern makes is_scrubbed_name (which OR-includes is_sensitive_env) block every
//   built-in-sensitive name from --allow-env — over-scrubbing that contradicts the
//   documented behavior and the no-scrub-patterns baseline.

#include <gtest/gtest.h>
#include <unistd.h>

#include <filesystem>
#include <fstream>
#include <map>
#include <string>
#include <vector>

#include "config.hpp"
#include "env_guard.hpp"
#include "fs_guard.hpp"

namespace fs = std::filesystem;
using namespace raincoat;

namespace {

std::string make_tmp_root() {
  static int counter = 0;
  fs::path base = fs::temp_directory_path();
  fs::path root = base / ("rc_attack_" + std::to_string(::getpid()) + "_" +
                          std::to_string(counter++));
  fs::remove_all(root);
  fs::create_directories(root);
  return fs::canonical(root).string();
}

}  // namespace

// ---------------------------------------------------------------------------
// Defect A: mounting the PARENT of a denied path must be refused, because a bind
// mount of the parent exposes the denied child inside the sandbox.
// ---------------------------------------------------------------------------
TEST(ExtEnforcementAttack, DenyIsBypassedByAllowingAnAncestorDirectory) {
  const std::string root = make_tmp_root();
  // Simulated home tree with a sensitive subdir.
  const std::string home = root + "/home";
  const std::string ssh = home + "/.ssh";
  ASSERT_TRUE(fs::create_directories(ssh));
  { std::ofstream(ssh + "/id_rsa") << "SECRET"; }

  Config cfg;
  cfg.strict = true;  // no auto-cwd noise; only the explicit allow is planned.
  cfg.ext.fs_deny = {ssh};       // policy: ~/.ssh must never be exposed
  cfg.allow_read = {home};       // user opens the whole home read-only

  std::string err, warning;
  std::vector<Mount> mounts = plan_mounts(cfg, root, /*real_home=*/home, err, warning);

  // The denied ~/.ssh sits UNDER the mounted home, so it would be fully readable in
  // the sandbox. The documented guarantee ("denied path must NEVER be mounted") means
  // plan_mounts must refuse this mount. Currently it does not: it returns a mount of
  // `home` with no error, exposing the denied subtree.
  EXPECT_FALSE(err.empty())
      << "plan_mounts must refuse an allow_read that exposes a denied descendant path; "
         "the deny list is silently bypassed by allowing an ancestor directory.";
  EXPECT_TRUE(mounts.empty())
      << "no mount should be planned when it would expose a denied path.";
}

// Same defect, isolated at the enforcement primitive: fs_deny_hit should report that
// mounting `home` reaches the denied `home/.ssh`.
TEST(ExtEnforcementAttack, DenyHitMustCatchAncestorMountThatExposesDeniedChild) {
  const std::string root = make_tmp_root();
  const std::string home = root + "/home";
  const std::string ssh = home + "/.ssh";
  ASSERT_TRUE(fs::create_directories(ssh));

  auto hit = fs_deny_hit(home, /*fs_deny=*/{ssh}, /*real_home=*/"");
  EXPECT_TRUE(hit.has_value())
      << "mounting an ancestor of a denied path exposes it; fs_deny_hit must flag it.";
}

// ---------------------------------------------------------------------------
// Defect B: an unrelated scrub pattern must not cause the built-in heuristic to veto
// an explicit --allow-env of a built-in-sensitive name.
// ---------------------------------------------------------------------------
TEST(ExtEnforcementAttack, ScrubPatternsMustNotPromoteBuiltinHeuristicOverAllowEnv) {
  std::map<std::string, std::string> parent = {{"GITHUB_TOKEN", "deliberate"}};
  std::vector<std::string> allow_env = {"GITHUB_TOKEN"};

  // Baseline: with NO scrub patterns, a deliberate --allow-env of a built-in-sensitive
  // name is honored (this passes today and documents the intended behavior).
  {
    EnvPolicy policy;  // empty scrub_patterns
    EnvResolution r = resolve_env(parent, allow_env, {}, {}, /*strict=*/false, policy);
    ASSERT_NE(r.resolved.find("GITHUB_TOKEN"), r.resolved.end())
        << "baseline: --allow-env GITHUB_TOKEN must pass through with no scrub patterns.";
  }

  // Defect: adding an UNRELATED scrub pattern (does not match GITHUB_TOKEN) must not
  // change the outcome for GITHUB_TOKEN. The contract says only the user's OWN scrub
  // policy vetoes an explicit allow — the built-in heuristic must not gain that power.
  EnvPolicy policy;
  policy.scrub_patterns = {"ZZZ_*"};  // matches nothing here
  EnvResolution r = resolve_env(parent, allow_env, {}, {}, /*strict=*/false, policy);
  EXPECT_NE(r.resolved.find("GITHUB_TOKEN"), r.resolved.end())
      << "an unrelated scrub pattern must not make the built-in is_sensitive_env "
         "heuristic veto an explicit --allow-env; GITHUB_TOKEN is scrubbed only via "
         "the built-in rule, which the contract says is NOT allow-env-strong.";
}
