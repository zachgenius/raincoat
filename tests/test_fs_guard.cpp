// Raincoat — fs_guard tests (TDD).
//
// Behaviour under test (from docs/DESIGN.md + docs/SPEC.md):
//   make_mount:  absolutize(user_path, cwd) -> canonicalize -> exist-check.
//                On missing path: err = "Error: allowed path does not exist: <user_path>"
//                (quoting the ORIGINAL spelling) and return nullopt.
//                On success: Mount{host_path = canonical path, sandbox_path == host_path
//                (identity mapping), mode = requested mode}.
//   plan_mounts: one RO mount per allow_read, one RW mount per allow_write, in order
//                (reads first, then writes). Non-strict mode auto-appends the cwd as a
//                ReadWrite mount when it is not already covered by an allow path; strict
//                mode NEVER auto-adds the cwd. On any missing path: set err (exact
//                message) and return an empty vector.
//   any_writable: true iff at least one mount is ReadWrite.
//
// Tests use REAL temporary directories/files created via std::filesystem so the
// canonicalize + exist-check logic is exercised for real.

#include <gtest/gtest.h>
#include <unistd.h>

#include <filesystem>
#include <fstream>
#include <optional>
#include <string>
#include <vector>

#include "config.hpp"
#include "fs_guard.hpp"

namespace fs = std::filesystem;
using namespace raincoat;

namespace {

// Test fixture: a unique on-disk temp root that exists for the duration of a test.
class FsGuard : public ::testing::Test {
 protected:
  void SetUp() override {
    static int counter = 0;
    fs::path base = fs::temp_directory_path();
    root_ = base / ("rc_fsguard_" + std::to_string(::getpid()) + "_" +
                    std::to_string(counter++));
    fs::remove_all(root_);
    ASSERT_TRUE(fs::create_directories(root_));
    // The canonical spelling of the root (realpath) — temp_directory_path() itself may
    // live behind a symlink (e.g. /tmp -> /private/tmp), so always compare against this.
    root_canon_ = fs::canonical(root_);
  }

  void TearDown() override {
    std::error_code ec;
    fs::remove_all(root_, ec);
  }

  // Create a subdirectory under the root and return its canonical string path.
  std::string make_subdir(const std::string& name) {
    fs::path p = root_ / name;
    EXPECT_TRUE(fs::create_directories(p));
    return fs::canonical(p).string();
  }

  // Create an empty regular file under the root; return its canonical string path.
  std::string make_file(const std::string& name) {
    fs::path p = root_ / name;
    std::ofstream(p.string()).close();
    EXPECT_TRUE(fs::exists(p));
    return fs::canonical(p).string();
  }

  // A path under the root that is guaranteed NOT to exist.
  std::string missing_path(const std::string& name) {
    fs::path p = root_ / name;
    std::error_code ec;
    fs::remove_all(p, ec);
    EXPECT_FALSE(fs::exists(p));
    return p.string();
  }

  std::string cwd() const { return root_canon_.string(); }

  fs::path root_;
  fs::path root_canon_;
};

// ---------------------------------------------------------------------------
// make_mount — success cases
// ---------------------------------------------------------------------------

TEST_F(FsGuard, MakeMountAbsoluteReadOnly) {
  std::string dir = make_subdir("data");
  std::string err = "sentinel";
  auto m = make_mount(dir, cwd(), MountMode::ReadOnly, err);

  ASSERT_TRUE(m.has_value());
  EXPECT_EQ(m->host_path, dir);
  EXPECT_EQ(m->mode, MountMode::ReadOnly);
  // Identity mapping: the sandbox path equals the canonical host path.
  EXPECT_EQ(m->sandbox_path, m->host_path);
  EXPECT_EQ(m->sandbox_path, dir);
}

TEST_F(FsGuard, MakeMountAbsoluteReadWrite) {
  std::string dir = make_subdir("out");
  std::string err;
  auto m = make_mount(dir, cwd(), MountMode::ReadWrite, err);

  ASSERT_TRUE(m.has_value());
  EXPECT_EQ(m->host_path, dir);
  EXPECT_EQ(m->mode, MountMode::ReadWrite);
  EXPECT_EQ(m->sandbox_path, m->host_path);
}

TEST_F(FsGuard, MakeMountResolvesRelativeAgainstCwd) {
  std::string dir = make_subdir("proj");  // canonical <root>/proj
  std::string err;
  // Relative user path resolved against cwd == root.
  auto m = make_mount("proj", cwd(), MountMode::ReadOnly, err);

  ASSERT_TRUE(m.has_value());
  EXPECT_EQ(m->host_path, dir);
  EXPECT_EQ(m->sandbox_path, dir);
}

TEST_F(FsGuard, MakeMountResolvesDotSlashRelative) {
  std::string dir = make_subdir("src");
  std::string err;
  auto m = make_mount("./src", cwd(), MountMode::ReadOnly, err);

  ASSERT_TRUE(m.has_value());
  EXPECT_EQ(m->host_path, dir);
}

TEST_F(FsGuard, MakeMountCanonicalizesDotDotAndExtraSlashes) {
  make_subdir("a/b");
  std::string canonical_b = fs::canonical(root_ / "a" / "b").string();
  std::string err;
  // a/../a//b/  should canonicalize to <root>/a/b
  auto m = make_mount("a/../a//b", cwd(), MountMode::ReadWrite, err);

  ASSERT_TRUE(m.has_value());
  EXPECT_EQ(m->host_path, canonical_b);
  EXPECT_EQ(m->sandbox_path, canonical_b);
}

TEST_F(FsGuard, MakeMountAbsolutePathIgnoresCwd) {
  std::string dir = make_subdir("abs");
  std::string err;
  // Absolute user path must succeed regardless of the (irrelevant) cwd argument.
  auto m = make_mount(dir, "/nonexistent/cwd/should/be/ignored", MountMode::ReadOnly, err);

  ASSERT_TRUE(m.has_value());
  EXPECT_EQ(m->host_path, dir);
}

TEST_F(FsGuard, MakeMountWorksForRegularFile) {
  std::string file = make_file("config.txt");
  std::string err;
  auto m = make_mount(file, cwd(), MountMode::ReadOnly, err);

  ASSERT_TRUE(m.has_value());
  EXPECT_EQ(m->host_path, file);
  EXPECT_EQ(m->sandbox_path, file);
}

// ---------------------------------------------------------------------------
// make_mount — missing path
// ---------------------------------------------------------------------------

TEST_F(FsGuard, MakeMountMissingAbsolutePathErrors) {
  std::string gone = missing_path("nope");
  std::string err;
  auto m = make_mount(gone, cwd(), MountMode::ReadOnly, err);

  EXPECT_FALSE(m.has_value());
  EXPECT_EQ(err, "Error: allowed path does not exist: " + gone);
}

TEST_F(FsGuard, MakeMountMissingRelativePathQuotesOriginalSpelling) {
  // Ensure the relative name does not exist.
  missing_path("ghost");
  std::string err;
  auto m = make_mount("./ghost", cwd(), MountMode::ReadWrite, err);

  EXPECT_FALSE(m.has_value());
  // The error must echo the ORIGINAL user spelling, not the absolutized path.
  EXPECT_EQ(err, "Error: allowed path does not exist: ./ghost");
}

// ---------------------------------------------------------------------------
// any_writable
// ---------------------------------------------------------------------------

TEST_F(FsGuard, AnyWritableEmptyIsFalse) {
  EXPECT_FALSE(any_writable({}));
}

TEST_F(FsGuard, AnyWritableOnlyReadOnlyIsFalse) {
  std::vector<Mount> mounts = {
      {"/a", "/a", MountMode::ReadOnly},
      {"/b", "/b", MountMode::ReadOnly},
  };
  EXPECT_FALSE(any_writable(mounts));
}

TEST_F(FsGuard, AnyWritableWithOneReadWriteIsTrue) {
  std::vector<Mount> mounts = {
      {"/a", "/a", MountMode::ReadOnly},
      {"/b", "/b", MountMode::ReadWrite},
  };
  EXPECT_TRUE(any_writable(mounts));
}

// ---------------------------------------------------------------------------
// plan_mounts — helpers
// ---------------------------------------------------------------------------

// Build a minimal Config with the fields plan_mounts cares about.
static Config make_config(bool strict,
                          std::vector<std::string> reads,
                          std::vector<std::string> writes) {
  Config cfg;
  cfg.strict = strict;
  cfg.allow_read = std::move(reads);
  cfg.allow_write = std::move(writes);
  return cfg;
}

// Convenience wrapper for the mount-shape tests below: runs plan_mounts with the home
// guard DISABLED (real_home == "") so the pre-existing RO/RW/cwd behaviour is exercised
// in isolation. A separate block of tests drives the guard with a real home path.
static std::vector<Mount> plan_no_home(const Config& cfg, const std::string& cwd,
                                       std::string& err) {
  std::string warning = "sentinel-warning";
  auto mounts = plan_mounts(cfg, cwd, /*real_home=*/"", err, warning);
  // With the guard disabled the warning is always cleared.
  EXPECT_TRUE(warning.empty());
  return mounts;
}

// ---------------------------------------------------------------------------
// plan_mounts — non-strict cwd auto-add
// ---------------------------------------------------------------------------

TEST_F(FsGuard, PlanMountsNonStrictAutoAddsCwdAsReadWrite) {
  Config cfg = make_config(/*strict=*/false, {}, {});
  std::string err = "sentinel";
  auto mounts = plan_no_home(cfg, cwd(), err);

  EXPECT_TRUE(err.empty());
  ASSERT_EQ(mounts.size(), 1u);
  EXPECT_EQ(mounts[0].host_path, cwd());
  EXPECT_EQ(mounts[0].sandbox_path, cwd());
  EXPECT_EQ(mounts[0].mode, MountMode::ReadWrite);
  EXPECT_TRUE(any_writable(mounts));
}

TEST_F(FsGuard, PlanMountsNonStrictAppendsCwdAfterAllowPaths) {
  std::string r = make_subdir("ro");
  std::string w = make_subdir("rw");
  Config cfg = make_config(/*strict=*/false, {r}, {w});
  std::string err;
  auto mounts = plan_no_home(cfg, cwd(), err);

  EXPECT_TRUE(err.empty());
  ASSERT_EQ(mounts.size(), 3u);
  // Reads first, then writes, then the auto-added cwd (RW) last.
  EXPECT_EQ(mounts[0].host_path, r);
  EXPECT_EQ(mounts[0].mode, MountMode::ReadOnly);
  EXPECT_EQ(mounts[1].host_path, w);
  EXPECT_EQ(mounts[1].mode, MountMode::ReadWrite);
  EXPECT_EQ(mounts[2].host_path, cwd());
  EXPECT_EQ(mounts[2].mode, MountMode::ReadWrite);
}

TEST_F(FsGuard, PlanMountsNonStrictDoesNotDuplicateCwdWhenAlreadyAllowed) {
  // cwd is explicitly allowed for writing -> it is already covered, so no auto-add.
  Config cfg = make_config(/*strict=*/false, {}, {cwd()});
  std::string err;
  auto mounts = plan_no_home(cfg, cwd(), err);

  EXPECT_TRUE(err.empty());
  ASSERT_EQ(mounts.size(), 1u);
  EXPECT_EQ(mounts[0].host_path, cwd());
  EXPECT_EQ(mounts[0].mode, MountMode::ReadWrite);
  EXPECT_TRUE(any_writable(mounts));
}

TEST_F(FsGuard, PlanMountsNonStrictCwdGivenAsRelativeAllowPathNotDuplicated) {
  // "." resolves to cwd; covered, so the cwd is not appended a second time.
  Config cfg = make_config(/*strict=*/false, {}, {"."});
  std::string err;
  auto mounts = plan_no_home(cfg, cwd(), err);

  EXPECT_TRUE(err.empty());
  ASSERT_EQ(mounts.size(), 1u);
  EXPECT_EQ(mounts[0].host_path, cwd());
  EXPECT_EQ(mounts[0].mode, MountMode::ReadWrite);
}

// ---------------------------------------------------------------------------
// plan_mounts — strict mode never auto-adds cwd
// ---------------------------------------------------------------------------

TEST_F(FsGuard, PlanMountsStrictNoAllowPathsIsEmpty) {
  Config cfg = make_config(/*strict=*/true, {}, {});
  std::string err = "sentinel";
  auto mounts = plan_no_home(cfg, cwd(), err);

  EXPECT_TRUE(err.empty());
  EXPECT_TRUE(mounts.empty());
  EXPECT_FALSE(any_writable(mounts));
}

TEST_F(FsGuard, PlanMountsStrictDoesNotAutoAddCwd) {
  std::string r = make_subdir("readable");
  Config cfg = make_config(/*strict=*/true, {r}, {});
  std::string err;
  auto mounts = plan_no_home(cfg, cwd(), err);

  EXPECT_TRUE(err.empty());
  ASSERT_EQ(mounts.size(), 1u);  // only the allow_read; cwd NOT added
  EXPECT_EQ(mounts[0].host_path, r);
  EXPECT_EQ(mounts[0].mode, MountMode::ReadOnly);
  EXPECT_FALSE(any_writable(mounts));  // no writable mount in strict w/o allow_write
}

TEST_F(FsGuard, PlanMountsStrictWithAllowWriteIsWritable) {
  std::string w = make_subdir("writable");
  Config cfg = make_config(/*strict=*/true, {}, {w});
  std::string err;
  auto mounts = plan_no_home(cfg, cwd(), err);

  EXPECT_TRUE(err.empty());
  ASSERT_EQ(mounts.size(), 1u);
  EXPECT_EQ(mounts[0].host_path, w);
  EXPECT_EQ(mounts[0].mode, MountMode::ReadWrite);
  EXPECT_TRUE(any_writable(mounts));
}

// ---------------------------------------------------------------------------
// plan_mounts — mount modes & identity mapping across multiple paths
// ---------------------------------------------------------------------------

TEST_F(FsGuard, PlanMountsModesAndIdentityMapping) {
  std::string r1 = make_subdir("r1");
  std::string r2 = make_subdir("r2");
  std::string w1 = make_subdir("w1");
  Config cfg = make_config(/*strict=*/true, {r1, r2}, {w1});
  std::string err;
  auto mounts = plan_no_home(cfg, cwd(), err);

  EXPECT_TRUE(err.empty());
  ASSERT_EQ(mounts.size(), 3u);
  EXPECT_EQ(mounts[0].host_path, r1);
  EXPECT_EQ(mounts[0].mode, MountMode::ReadOnly);
  EXPECT_EQ(mounts[1].host_path, r2);
  EXPECT_EQ(mounts[1].mode, MountMode::ReadOnly);
  EXPECT_EQ(mounts[2].host_path, w1);
  EXPECT_EQ(mounts[2].mode, MountMode::ReadWrite);
  // Identity mapping holds for every mount.
  for (const auto& m : mounts) {
    EXPECT_EQ(m.sandbox_path, m.host_path);
  }
}

TEST_F(FsGuard, PlanMountsResolvesRelativeAllowPaths) {
  make_subdir("rel");
  std::string canonical_rel = fs::canonical(root_ / "rel").string();
  Config cfg = make_config(/*strict=*/true, {"rel"}, {});
  std::string err;
  auto mounts = plan_no_home(cfg, cwd(), err);

  EXPECT_TRUE(err.empty());
  ASSERT_EQ(mounts.size(), 1u);
  EXPECT_EQ(mounts[0].host_path, canonical_rel);
  EXPECT_EQ(mounts[0].sandbox_path, canonical_rel);
}

// ---------------------------------------------------------------------------
// plan_mounts — missing path propagation
// ---------------------------------------------------------------------------

TEST_F(FsGuard, PlanMountsMissingReadPathErrorsAndReturnsEmpty) {
  std::string good = make_subdir("good");
  Config cfg = make_config(/*strict=*/false, {good, "./does-not-exist"}, {});
  std::string err;
  auto mounts = plan_no_home(cfg, cwd(), err);

  EXPECT_TRUE(mounts.empty());
  EXPECT_EQ(err, "Error: allowed path does not exist: ./does-not-exist");
}

TEST_F(FsGuard, PlanMountsMissingWritePathErrorsAndReturnsEmpty) {
  Config cfg = make_config(/*strict=*/false, {}, {"/absolutely/not/here"});
  std::string err;
  auto mounts = plan_no_home(cfg, cwd(), err);

  EXPECT_TRUE(mounts.empty());
  EXPECT_EQ(err, "Error: allowed path does not exist: /absolutely/not/here");
}

TEST_F(FsGuard, PlanMountsStrictMissingPathStillErrors) {
  Config cfg = make_config(/*strict=*/true, {"missing-read"}, {});
  std::string err;
  auto mounts = plan_no_home(cfg, cwd(), err);

  EXPECT_TRUE(mounts.empty());
  EXPECT_EQ(err, "Error: allowed path does not exist: missing-read");
}

// ---------------------------------------------------------------------------
// cwd_is_home — the privacy predicate, on real temp dirs
// ---------------------------------------------------------------------------

TEST_F(FsGuard, CwdIsHomeEqualPathIsTrue) {
  std::string home = make_subdir("home/user");
  EXPECT_TRUE(cwd_is_home(home, home));
}

TEST_F(FsGuard, CwdIsHomeAncestorOfHomeIsTrue) {
  // cwd is an ancestor of home => mounting cwd would expose the whole home tree.
  std::string home = make_subdir("home/user");
  std::string ancestor = fs::canonical(root_ / "home").string();
  EXPECT_TRUE(cwd_is_home(ancestor, home));
}

TEST_F(FsGuard, CwdBelowHomeIsNotHome) {
  // A project subdir *under* home is safe to mount — it does not expose siblings
  // like ~/.ssh, so the guard must NOT fire.
  std::string home = make_subdir("home/user");
  std::string proj = make_subdir("home/user/project");
  EXPECT_FALSE(cwd_is_home(proj, home));
}

TEST_F(FsGuard, CwdIsSiblingPrefixOfHomeIsNotHome) {
  // "/…/home/user" must NOT be treated as an ancestor of "/…/home/user2":
  // component-wise comparison, not string-prefix.
  make_subdir("home/user");
  make_subdir("home/user2");
  std::string user = fs::canonical(root_ / "home" / "user").string();
  std::string user2 = fs::canonical(root_ / "home" / "user2").string();
  EXPECT_FALSE(cwd_is_home(user, user2));
}

TEST_F(FsGuard, CwdIsHomeDisabledWhenRealHomeEmpty) {
  std::string home = make_subdir("home/user");
  EXPECT_FALSE(cwd_is_home(home, ""));  // guard disabled
}

// ---------------------------------------------------------------------------
// plan_mounts — home privacy guard
// ---------------------------------------------------------------------------

TEST_F(FsGuard, PlanMountsRefusesToAutoMountHomeAndWarns) {
  // Non-strict, cwd == real_home, nothing explicitly allowed: the cwd must NOT be
  // auto-mounted, and a warning must be surfaced to the caller.
  std::string home = make_subdir("home/user");
  Config cfg = make_config(/*strict=*/false, {}, {});
  std::string err = "sentinel";
  std::string warning;
  auto mounts = plan_mounts(cfg, /*cwd=*/home, /*real_home=*/home, err, warning);

  EXPECT_TRUE(err.empty());
  EXPECT_TRUE(mounts.empty());          // home was NOT auto-mounted
  EXPECT_FALSE(any_writable(mounts));
  EXPECT_FALSE(warning.empty());        // refusal surfaced to the runner
}

TEST_F(FsGuard, PlanMountsRefusesWhenCwdIsAncestorOfHome) {
  std::string home = make_subdir("home/user");
  std::string ancestor = fs::canonical(root_ / "home").string();
  Config cfg = make_config(/*strict=*/false, {}, {});
  std::string err;
  std::string warning;
  auto mounts = plan_mounts(cfg, /*cwd=*/ancestor, /*real_home=*/home, err, warning);

  EXPECT_TRUE(err.empty());
  EXPECT_TRUE(mounts.empty());
  EXPECT_FALSE(warning.empty());
}

TEST_F(FsGuard, PlanMountsAutoMountsNormalProjectDirRW) {
  // cwd is a normal project dir (not home, not an ancestor of home) => auto-mounted RW,
  // and no warning.
  std::string home = make_subdir("home/user");
  std::string proj = make_subdir("work/project");
  Config cfg = make_config(/*strict=*/false, {}, {});
  std::string err = "sentinel";
  std::string warning = "sentinel";
  auto mounts = plan_mounts(cfg, /*cwd=*/proj, /*real_home=*/home, err, warning);

  EXPECT_TRUE(err.empty());
  EXPECT_TRUE(warning.empty());
  ASSERT_EQ(mounts.size(), 1u);
  EXPECT_EQ(mounts[0].host_path, proj);
  EXPECT_EQ(mounts[0].sandbox_path, proj);
  EXPECT_EQ(mounts[0].mode, MountMode::ReadWrite);
  EXPECT_TRUE(any_writable(mounts));
}

TEST_F(FsGuard, PlanMountsAutoMountsProjectSubdirOfHomeRW) {
  // A subdir *under* home is fine to auto-mount (it does not expose siblings).
  std::string home = make_subdir("home/user");
  std::string proj = make_subdir("home/user/project");
  Config cfg = make_config(/*strict=*/false, {}, {});
  std::string err;
  std::string warning = "sentinel";
  auto mounts = plan_mounts(cfg, /*cwd=*/proj, /*real_home=*/home, err, warning);

  EXPECT_TRUE(err.empty());
  EXPECT_TRUE(warning.empty());
  ASSERT_EQ(mounts.size(), 1u);
  EXPECT_EQ(mounts[0].host_path, proj);
  EXPECT_EQ(mounts[0].mode, MountMode::ReadWrite);
}

TEST_F(FsGuard, PlanMountsStrictNeverAutoMountsEvenWhenCwdNotHome) {
  // Strict mode never auto-adds the cwd, guard or not — and never warns about it.
  std::string home = make_subdir("home/user");
  std::string proj = make_subdir("work/project");
  Config cfg = make_config(/*strict=*/true, {}, {});
  std::string err = "sentinel";
  std::string warning = "sentinel";
  auto mounts = plan_mounts(cfg, /*cwd=*/proj, /*real_home=*/home, err, warning);

  EXPECT_TRUE(err.empty());
  EXPECT_TRUE(warning.empty());
  EXPECT_TRUE(mounts.empty());
}

TEST_F(FsGuard, PlanMountsExplicitAllowWriteOfHomeSubdirIsHonored) {
  // Explicit intent overrides the guard: even with cwd == home, an explicit
  // --allow-write of a subdir of home is mounted RW. The home itself is still not
  // auto-mounted (cwd is home), so a warning is still surfaced.
  std::string home = make_subdir("home/user");
  std::string sub = make_subdir("home/user/allowed");
  Config cfg = make_config(/*strict=*/false, {}, {sub});
  std::string err;
  std::string warning;
  auto mounts = plan_mounts(cfg, /*cwd=*/home, /*real_home=*/home, err, warning);

  EXPECT_TRUE(err.empty());
  ASSERT_EQ(mounts.size(), 1u);         // only the explicit subdir, not the home cwd
  EXPECT_EQ(mounts[0].host_path, sub);
  EXPECT_EQ(mounts[0].mode, MountMode::ReadWrite);
  EXPECT_TRUE(any_writable(mounts));
  EXPECT_FALSE(warning.empty());        // home cwd itself was still refused
}

TEST_F(FsGuard, PlanMountsExplicitAllowOfHomeItselfIsHonoredNoWarning) {
  // If the user explicitly allows the home path, it is covered => no auto-mount step is
  // reached and no warning is produced (explicit intent wins outright).
  std::string home = make_subdir("home/user");
  Config cfg = make_config(/*strict=*/false, {}, {home});
  std::string err;
  std::string warning = "sentinel";
  auto mounts = plan_mounts(cfg, /*cwd=*/home, /*real_home=*/home, err, warning);

  EXPECT_TRUE(err.empty());
  EXPECT_TRUE(warning.empty());
  ASSERT_EQ(mounts.size(), 1u);
  EXPECT_EQ(mounts[0].host_path, home);
  EXPECT_EQ(mounts[0].mode, MountMode::ReadWrite);
}

}  // namespace
