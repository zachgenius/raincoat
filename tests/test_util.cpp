// Raincoat — util module test suite (TDD).
//
// Covers the leaf path + string helpers declared in src/util.hpp:
//   canonicalize, absolutize, path_exists, is_dir, make_dirs,
//   environ_to_map, to_upper, starts_with, ends_with, split, trim.
//
// These tests define the behavioural contract. They are written against the
// stub implementation and are EXPECTED to FAIL until util.cpp is implemented.
//
// std::filesystem is used only as a *test harness* (to build fixtures and to
// compute ground-truth canonical paths) — it is not the code under test.

#include <gtest/gtest.h>

#include "util.hpp"

#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <string>
#include <system_error>
#include <vector>

#include <unistd.h>

namespace fs = std::filesystem;
using namespace raincoat;

// ---------------------------------------------------------------------------
// Filesystem fixture: a fresh, real temp directory per test, cleaned up after.
// ---------------------------------------------------------------------------
namespace {

class UtilFsTest : public ::testing::Test {
protected:
    fs::path root_;

    void SetUp() override {
        std::string tmpl = (fs::temp_directory_path() / "rc_util_XXXXXX").string();
        std::vector<char> buf(tmpl.begin(), tmpl.end());
        buf.push_back('\0');
        char* made = ::mkdtemp(buf.data());
        ASSERT_NE(made, nullptr) << "mkdtemp failed";
        // Canonicalize the root itself so comparisons are immune to symlinks in
        // the temp prefix (e.g. /tmp being a symlink on some hosts).
        std::error_code ec;
        root_ = fs::canonical(fs::path(made), ec);
        ASSERT_FALSE(ec) << "canonical(root) failed: " << ec.message();
    }

    void TearDown() override {
        std::error_code ec;
        fs::remove_all(root_, ec);
    }

    // Helper: create a regular file with some contents.
    void write_file(const fs::path& p, const std::string& contents = "x") {
        std::ofstream ofs(p);
        ofs << contents;
        ofs.close();
    }

    std::string s(const fs::path& p) const { return p.string(); }
};

}  // namespace

// ===========================================================================
// canonicalize  (realpath; nullopt if missing)
// ===========================================================================

TEST_F(UtilFsTest, CanonicalizeExistingDirectory) {
    fs::create_directory(root_ / "d");
    auto got = canonicalize(s(root_ / "d"));
    ASSERT_TRUE(got.has_value());
    EXPECT_EQ(*got, s(fs::canonical(root_ / "d")));
}

TEST_F(UtilFsTest, CanonicalizeExistingFile) {
    write_file(root_ / "f.txt");
    auto got = canonicalize(s(root_ / "f.txt"));
    ASSERT_TRUE(got.has_value());
    EXPECT_EQ(*got, s(root_ / "f.txt"));
}

TEST_F(UtilFsTest, CanonicalizeNonexistentReturnsNullopt) {
    auto got = canonicalize(s(root_ / "does_not_exist"));
    EXPECT_FALSE(got.has_value());
}

TEST_F(UtilFsTest, CanonicalizeNonexistentNestedReturnsNullopt) {
    auto got = canonicalize(s(root_ / "nope" / "deeper" / "leaf"));
    EXPECT_FALSE(got.has_value());
}

TEST_F(UtilFsTest, CanonicalizeEmptyStringReturnsNullopt) {
    // realpath("") fails (ENOENT) -> nullopt.
    EXPECT_FALSE(canonicalize("").has_value());
}

TEST_F(UtilFsTest, CanonicalizeStripsTrailingSlash) {
    fs::create_directory(root_ / "d");
    auto with_slash = canonicalize(s(root_ / "d") + "/");
    auto without = canonicalize(s(root_ / "d"));
    ASSERT_TRUE(with_slash.has_value());
    ASSERT_TRUE(without.has_value());
    EXPECT_EQ(*with_slash, *without);
    // Canonical form has no trailing slash.
    EXPECT_NE(with_slash->back(), '/');
}

TEST_F(UtilFsTest, CanonicalizeCollapsesDotAndDotDot) {
    fs::create_directories(root_ / "a" / "b");
    // <root>/a/b/../b/./  -> <root>/a/b
    std::string messy = s(root_ / "a" / "b") + "/../b/.";
    auto got = canonicalize(messy);
    ASSERT_TRUE(got.has_value());
    EXPECT_EQ(*got, s(root_ / "a" / "b"));
}

TEST_F(UtilFsTest, CanonicalizeResolvesSymlinkToDir) {
    fs::create_directory(root_ / "target");
    fs::create_directory_symlink(root_ / "target", root_ / "link");
    auto got = canonicalize(s(root_ / "link"));
    ASSERT_TRUE(got.has_value());
    EXPECT_EQ(*got, s(root_ / "target"));
}

TEST_F(UtilFsTest, CanonicalizeResolvesSymlinkToFile) {
    write_file(root_ / "real.txt");
    fs::create_symlink(root_ / "real.txt", root_ / "alias.txt");
    auto got = canonicalize(s(root_ / "alias.txt"));
    ASSERT_TRUE(got.has_value());
    EXPECT_EQ(*got, s(root_ / "real.txt"));
}

TEST_F(UtilFsTest, CanonicalizeDanglingSymlinkReturnsNullopt) {
    fs::create_symlink(root_ / "missing_target", root_ / "dangling");
    EXPECT_FALSE(canonicalize(s(root_ / "dangling")).has_value());
}

TEST_F(UtilFsTest, CanonicalizeReturnsAbsolutePath) {
    fs::create_directory(root_ / "d");
    // Resolve a relative spelling against the process cwd.
    char cwdbuf[4096];
    ASSERT_NE(::getcwd(cwdbuf, sizeof(cwdbuf)), nullptr);
    ASSERT_EQ(::chdir(root_.c_str()), 0);
    auto got = canonicalize("d");
    // restore cwd before assertions to avoid leaking state on failure
    ASSERT_EQ(::chdir(cwdbuf), 0);
    ASSERT_TRUE(got.has_value());
    EXPECT_EQ(got->front(), '/');
    EXPECT_EQ(*got, s(root_ / "d"));
}

// ===========================================================================
// absolutize  (lexical: make absolute + normalize; no filesystem access)
// ===========================================================================

TEST(UtilAbsolutize, AbsoluteInputPassesThrough) {
    EXPECT_EQ(absolutize("/a/b/c", "/base"), "/a/b/c");
}

TEST(UtilAbsolutize, RelativeJoinedToBase) {
    EXPECT_EQ(absolutize("foo", "/home/user"), "/home/user/foo");
}

TEST(UtilAbsolutize, RelativeMultiSegmentJoined) {
    EXPECT_EQ(absolutize("foo/bar", "/home/user"), "/home/user/foo/bar");
}

TEST(UtilAbsolutize, LeadingDotSlashNormalized) {
    EXPECT_EQ(absolutize("./foo", "/base"), "/base/foo");
}

TEST(UtilAbsolutize, SingleDotResolvesToBase) {
    EXPECT_EQ(absolutize(".", "/base"), "/base");
}

TEST(UtilAbsolutize, DotDotCollapsesInRelative) {
    EXPECT_EQ(absolutize("a/../b", "/base"), "/base/b");
}

TEST(UtilAbsolutize, DotDotAscendsFromBase) {
    EXPECT_EQ(absolutize("../x", "/base/sub"), "/base/x");
}

TEST(UtilAbsolutize, DotDotCollapsesInAbsoluteInput) {
    EXPECT_EQ(absolutize("/a/b/../c", "/base"), "/a/c");
}

TEST(UtilAbsolutize, TrailingSlashRemoved) {
    EXPECT_EQ(absolutize("foo/", "/base"), "/base/foo");
}

TEST(UtilAbsolutize, DuplicateSlashesCollapsed) {
    EXPECT_EQ(absolutize("a//b", "/base"), "/base/a/b");
}

TEST(UtilAbsolutize, EmptyPathYieldsBase) {
    EXPECT_EQ(absolutize("", "/base"), "/base");
}

TEST(UtilAbsolutize, DoesNotTouchFilesystem) {
    // Purely lexical: a nonexistent path still resolves.
    EXPECT_EQ(absolutize("no/such/dir", "/nonexistent/base"),
              "/nonexistent/base/no/such/dir");
}

// ===========================================================================
// path_exists
// ===========================================================================

TEST_F(UtilFsTest, PathExistsForDir) {
    fs::create_directory(root_ / "d");
    EXPECT_TRUE(path_exists(s(root_ / "d")));
}

TEST_F(UtilFsTest, PathExistsForFile) {
    write_file(root_ / "f");
    EXPECT_TRUE(path_exists(s(root_ / "f")));
}

TEST_F(UtilFsTest, PathExistsFalseForMissing) {
    EXPECT_FALSE(path_exists(s(root_ / "missing")));
}

TEST_F(UtilFsTest, PathExistsFalseForEmptyString) {
    EXPECT_FALSE(path_exists(""));
}

TEST_F(UtilFsTest, PathExistsTrueForSymlinkToExisting) {
    write_file(root_ / "real");
    fs::create_symlink(root_ / "real", root_ / "lnk");
    EXPECT_TRUE(path_exists(s(root_ / "lnk")));
}

TEST_F(UtilFsTest, PathExistsFalseForDanglingSymlink) {
    fs::create_symlink(root_ / "gone", root_ / "dangling");
    EXPECT_FALSE(path_exists(s(root_ / "dangling")));
}

// ===========================================================================
// is_dir
// ===========================================================================

TEST_F(UtilFsTest, IsDirTrueForDirectory) {
    fs::create_directory(root_ / "d");
    EXPECT_TRUE(is_dir(s(root_ / "d")));
}

TEST_F(UtilFsTest, IsDirFalseForFile) {
    write_file(root_ / "f");
    EXPECT_FALSE(is_dir(s(root_ / "f")));
}

TEST_F(UtilFsTest, IsDirFalseForMissing) {
    EXPECT_FALSE(is_dir(s(root_ / "missing")));
}

TEST_F(UtilFsTest, IsDirFalseForEmptyString) {
    EXPECT_FALSE(is_dir(""));
}

TEST_F(UtilFsTest, IsDirTrueForSymlinkToDir) {
    fs::create_directory(root_ / "target");
    fs::create_directory_symlink(root_ / "target", root_ / "link");
    // stat() follows symlinks -> the link points at a directory.
    EXPECT_TRUE(is_dir(s(root_ / "link")));
}

TEST_F(UtilFsTest, IsDirFalseForSymlinkToFile) {
    write_file(root_ / "real");
    fs::create_symlink(root_ / "real", root_ / "lnk");
    EXPECT_FALSE(is_dir(s(root_ / "lnk")));
}

TEST_F(UtilFsTest, IsDirHandlesTrailingSlash) {
    fs::create_directory(root_ / "d");
    EXPECT_TRUE(is_dir(s(root_ / "d") + "/"));
}

// ===========================================================================
// make_dirs  (mkdir -p)
// ===========================================================================

TEST_F(UtilFsTest, MakeDirsCreatesNested) {
    std::string err = "sentinel";
    fs::path target = root_ / "a" / "b" / "c";
    EXPECT_TRUE(make_dirs(s(target), err));
    EXPECT_TRUE(is_dir(s(target)));
    EXPECT_TRUE(fs::is_directory(target));
    EXPECT_TRUE(err.empty()) << "err should be cleared on success, was: " << err;
}

TEST_F(UtilFsTest, MakeDirsIdempotentOnExisting) {
    fs::create_directories(root_ / "x" / "y");
    std::string err = "sentinel";
    EXPECT_TRUE(make_dirs(s(root_ / "x" / "y"), err));
    EXPECT_TRUE(err.empty());
}

TEST_F(UtilFsTest, MakeDirsUnderExistingParent) {
    fs::create_directory(root_ / "parent");
    std::string err;
    EXPECT_TRUE(make_dirs(s(root_ / "parent" / "child"), err));
    EXPECT_TRUE(fs::is_directory(root_ / "parent" / "child"));
}

TEST_F(UtilFsTest, MakeDirsHandlesTrailingSlash) {
    std::string err;
    EXPECT_TRUE(make_dirs(s(root_ / "withslash") + "/", err));
    EXPECT_TRUE(fs::is_directory(root_ / "withslash"));
}

TEST_F(UtilFsTest, MakeDirsFailsWhenComponentIsFile) {
    // A regular file sits where a directory component is required.
    write_file(root_ / "blocker");
    std::string err;
    EXPECT_FALSE(make_dirs(s(root_ / "blocker" / "sub"), err));
    EXPECT_FALSE(err.empty()) << "err must describe the failure";
}

TEST_F(UtilFsTest, MakeDirsFailsWhenTargetIsExistingFile) {
    write_file(root_ / "afile");
    std::string err;
    EXPECT_FALSE(make_dirs(s(root_ / "afile"), err));
    EXPECT_FALSE(err.empty());
}

TEST_F(UtilFsTest, MakeDirsEmptyStringFails) {
    std::string err;
    EXPECT_FALSE(make_dirs("", err));
    EXPECT_FALSE(err.empty());
}

// ===========================================================================
// environ_to_map
// ===========================================================================

TEST(UtilEnviron, ParsesBasicEntries) {
    const char* env[] = {"A=1", "B=two", nullptr};
    auto m = environ_to_map(const_cast<char**>(env));
    ASSERT_EQ(m.size(), 2u);
    EXPECT_EQ(m["A"], "1");
    EXPECT_EQ(m["B"], "two");
}

TEST(UtilEnviron, SplitsOnFirstEqualsOnly) {
    const char* env[] = {"URL=http://x/?a=b&c=d", nullptr};
    auto m = environ_to_map(const_cast<char**>(env));
    ASSERT_EQ(m.count("URL"), 1u);
    EXPECT_EQ(m["URL"], "http://x/?a=b&c=d");
}

TEST(UtilEnviron, EmptyValueKept) {
    const char* env[] = {"EMPTY=", nullptr};
    auto m = environ_to_map(const_cast<char**>(env));
    ASSERT_EQ(m.count("EMPTY"), 1u);
    EXPECT_EQ(m["EMPTY"], "");
}

TEST(UtilEnviron, NullEnvpYieldsEmptyMap) {
    auto m = environ_to_map(nullptr);
    EXPECT_TRUE(m.empty());
}

TEST(UtilEnviron, EmptyArrayYieldsEmptyMap) {
    const char* env[] = {nullptr};
    auto m = environ_to_map(const_cast<char**>(env));
    EXPECT_TRUE(m.empty());
}

TEST(UtilEnviron, EntryWithoutEqualsIsIgnored) {
    const char* env[] = {"GOOD=1", "NOEQUALS", "ALSO=2", nullptr};
    auto m = environ_to_map(const_cast<char**>(env));
    EXPECT_EQ(m.count("NOEQUALS"), 0u);
    EXPECT_EQ(m["GOOD"], "1");
    EXPECT_EQ(m["ALSO"], "2");
}

TEST(UtilEnviron, LaterDuplicateWins) {
    const char* env[] = {"K=first", "K=second", nullptr};
    auto m = environ_to_map(const_cast<char**>(env));
    EXPECT_EQ(m["K"], "second");
}

// ===========================================================================
// to_upper
// ===========================================================================

TEST(UtilToUpper, LowercaseToUpper) { EXPECT_EQ(to_upper("abc"), "ABC"); }
TEST(UtilToUpper, MixedCaseAndDigits) { EXPECT_EQ(to_upper("aB3z"), "AB3Z"); }
TEST(UtilToUpper, AlreadyUpperUnchanged) { EXPECT_EQ(to_upper("XYZ"), "XYZ"); }
TEST(UtilToUpper, EmptyString) { EXPECT_EQ(to_upper(""), ""); }
TEST(UtilToUpper, NonAlphaUnchanged) { EXPECT_EQ(to_upper("a_b-c.1"), "A_B-C.1"); }

// ===========================================================================
// starts_with
// ===========================================================================

TEST(UtilStartsWith, TrueWhenPrefixMatches) { EXPECT_TRUE(starts_with("hello", "he")); }
TEST(UtilStartsWith, FalseWhenNotMatching) { EXPECT_FALSE(starts_with("hello", "lo")); }
TEST(UtilStartsWith, TrueForEmptyPrefix) { EXPECT_TRUE(starts_with("hello", "")); }
TEST(UtilStartsWith, TrueForEqualStrings) { EXPECT_TRUE(starts_with("hello", "hello")); }
TEST(UtilStartsWith, FalseWhenPrefixLongerThanString) {
    EXPECT_FALSE(starts_with("hi", "hihi"));
}
TEST(UtilStartsWith, EmptyStringEmptyPrefix) { EXPECT_TRUE(starts_with("", "")); }
TEST(UtilStartsWith, EmptyStringNonEmptyPrefix) { EXPECT_FALSE(starts_with("", "x")); }
TEST(UtilStartsWith, SuffixPatternMatch) {
    EXPECT_TRUE(starts_with("AWS_SECRET", "AWS_"));
}

// ===========================================================================
// ends_with
// ===========================================================================

TEST(UtilEndsWith, TrueWhenSuffixMatches) { EXPECT_TRUE(ends_with("hello", "lo")); }
TEST(UtilEndsWith, FalseWhenNotMatching) { EXPECT_FALSE(ends_with("hello", "he")); }
TEST(UtilEndsWith, TrueForEmptySuffix) { EXPECT_TRUE(ends_with("hello", "")); }
TEST(UtilEndsWith, TrueForEqualStrings) { EXPECT_TRUE(ends_with("hello", "hello")); }
TEST(UtilEndsWith, FalseWhenSuffixLongerThanString) {
    EXPECT_FALSE(ends_with("hi", "hihi"));
}
TEST(UtilEndsWith, EmptyStringEmptySuffix) { EXPECT_TRUE(ends_with("", "")); }
TEST(UtilEndsWith, EmptyStringNonEmptySuffix) { EXPECT_FALSE(ends_with("", "x")); }
TEST(UtilEndsWith, TokenSuffixMatch) {
    EXPECT_TRUE(ends_with("MY_TOKEN", "_TOKEN"));
}

// ===========================================================================
// split
// ===========================================================================
// Contract: token count == delimiter count + 1; empty tokens are preserved.

TEST(UtilSplit, BasicThreeTokens) {
    EXPECT_EQ(split("a,b,c", ','), (std::vector<std::string>{"a", "b", "c"}));
}
TEST(UtilSplit, SingleTokenNoDelimiter) {
    EXPECT_EQ(split("abc", ','), (std::vector<std::string>{"abc"}));
}
TEST(UtilSplit, EmptyInputYieldsSingleEmptyToken) {
    EXPECT_EQ(split("", ','), (std::vector<std::string>{""}));
}
TEST(UtilSplit, LeadingDelimiterKeepsEmptyFront) {
    EXPECT_EQ(split(",a", ','), (std::vector<std::string>{"", "a"}));
}
TEST(UtilSplit, TrailingDelimiterKeepsEmptyBack) {
    EXPECT_EQ(split("a,", ','), (std::vector<std::string>{"a", ""}));
}
TEST(UtilSplit, ConsecutiveDelimitersKeepEmptyMiddle) {
    EXPECT_EQ(split("a,,b", ','), (std::vector<std::string>{"a", "", "b"}));
}
TEST(UtilSplit, OnlyDelimiterYieldsTwoEmpties) {
    EXPECT_EQ(split(",", ','), (std::vector<std::string>{"", ""}));
}
TEST(UtilSplit, DifferentDelimiterColon) {
    EXPECT_EQ(split("/usr/bin:/bin:/sbin", ':'),
              (std::vector<std::string>{"/usr/bin", "/bin", "/sbin"}));
}
TEST(UtilSplit, DelimiterNotPresentReturnsWhole) {
    EXPECT_EQ(split("no-delims-here", ';'),
              (std::vector<std::string>{"no-delims-here"}));
}

// ===========================================================================
// trim
// ===========================================================================

TEST(UtilTrim, RemovesLeadingAndTrailingSpaces) {
    EXPECT_EQ(trim("  abc  "), "abc");
}
TEST(UtilTrim, RemovesMixedWhitespace) {
    EXPECT_EQ(trim("\t\n abc \r\n"), "abc");
}
TEST(UtilTrim, EmptyStringStaysEmpty) { EXPECT_EQ(trim(""), ""); }
TEST(UtilTrim, AllWhitespaceBecomesEmpty) {
    EXPECT_EQ(trim("   \t\n "), "");
}
TEST(UtilTrim, NoWhitespaceUnchanged) { EXPECT_EQ(trim("abc"), "abc"); }
TEST(UtilTrim, InternalWhitespacePreserved) {
    EXPECT_EQ(trim("  a b\tc  "), "a b\tc");
}
TEST(UtilTrim, LeadingOnly) { EXPECT_EQ(trim("   abc"), "abc"); }
TEST(UtilTrim, TrailingOnly) { EXPECT_EQ(trim("abc   "), "abc"); }
TEST(UtilTrim, SingleCharNonSpace) { EXPECT_EQ(trim("x"), "x"); }
