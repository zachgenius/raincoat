// Raincoat — attack-round-2 enforcement tests for ExtendedConfig wiring.
//
// Round 1 (test_ext_enforcement_attack.cpp) pinned two defects that have since been
// fixed (the ancestor-exposure fs_deny check and the scrub-pattern over-veto). This
// file pins a NEW, still-live defect found in round 2. It is expected to FAIL against
// the current tree; the failing assertion IS the bug report. No production code is
// changed in this round.
//
// Defect C (security, fs_guard): the filesystem deny list is bypassable for WRITABLE
//   mounts whenever the denied path does not YET exist on disk. plan_mounts /
//   fs_deny_hit promise a denied path "must NEVER be mounted — even when the user
//   explicitly --allow-read/--allow-write's it." The round-1 fix added an ancestor-
//   exposure check, but it is gated on `fs::exists(denied)` — its rationale ("a purely
//   hypothetical denied descendant has nothing to expose") only holds for READ mounts.
//   For a WRITABLE ancestor mount, a NON-existent denied descendant is not harmless:
//   the sandboxed child can CREATE it and write through the bind straight into the real
//   filesystem. So `deny = ["~/.aws"]` (not present yet) + `--allow-write $HOME` lets the
//   child do `mkdir ~/.aws && echo creds > ~/.aws/credentials`, planting a real file at
//   the exact path the deny rule swore would never be mounted.
//
//   Reproduced end-to-end against ./build/raincoat: with HOME pointed at a scratch dir,
//   `deny = ["~/.aws"]`, `--allow-write <home>`, and a child that writes the absolute
//   path <home>/.aws/credentials, the file appears in the real (host) home after the run.

#include <gtest/gtest.h>
#include <unistd.h>

#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#include "config.hpp"
#include "fs_guard.hpp"

namespace fs = std::filesystem;
using namespace raincoat;

namespace {

std::string make_tmp_root() {
  static int counter = 0;
  fs::path base = fs::temp_directory_path();
  fs::path root = base / ("rc_attack2_" + std::to_string(::getpid()) + "_" +
                          std::to_string(counter++));
  fs::remove_all(root);
  fs::create_directories(root);
  return fs::canonical(root).string();
}

}  // namespace

// ---------------------------------------------------------------------------
// Defect C: a WRITABLE mount of an ancestor of a denied path must be refused even
// when the denied path does not exist yet, because the child can create it through
// the writable bind and thereby write into the very location the deny rule forbids.
// ---------------------------------------------------------------------------
TEST(ExtEnforcementAttack2, WritableAncestorOfNonexistentDeniedPathMustBeRefused) {
  const std::string root = make_tmp_root();
  const std::string home = root + "/home";
  ASSERT_TRUE(fs::create_directories(home + "/project"));
  // NOTE: home/.aws deliberately does NOT exist yet — that is the whole point.
  const std::string aws = home + "/.aws";
  ASSERT_FALSE(fs::exists(aws));

  Config cfg;
  cfg.strict = true;                 // isolate the explicit allow; no auto-cwd noise.
  cfg.ext.fs_deny = {aws};           // policy: ~/.aws must NEVER be mounted/exposed.
  cfg.allow_write = {home};          // user opens the whole home READ-WRITE.

  std::string err, warning;
  std::vector<Mount> mounts =
      plan_mounts(cfg, /*cwd=*/home, /*real_home=*/home, err, warning);

  // A writable bind of `home` gives the child a live handle to create home/.aws and
  // write real files into it — the deny guarantee is violated. plan_mounts must refuse.
  EXPECT_FALSE(err.empty())
      << "plan_mounts must refuse a WRITABLE mount that would let the child create the "
         "denied path; a non-existent denied descendant is NOT harmless under a "
         "read-write bind.";
  EXPECT_TRUE(mounts.empty())
      << "no mount should be planned when a writable bind would expose the denied path "
         "to creation.";
}
