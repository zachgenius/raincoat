// Raincoat — font_guard tests (TDD).
//
// Exercises setup_fontconfig() against a REAL temporary sandbox directory.
//
// Contract under test (from DESIGN.md / SPEC.md / module brief):
//   FontSetup setup_fontconfig(sandbox_dir, enabled, fonts_conf_source, err);
//   * enabled == false  -> status Disabled, empty env, empty dir, err untouched.
//   * enabled == true   -> create <sandbox_dir>/fontconfig, write fonts.conf
//                          (copy fonts_conf_source if it exists & is readable,
//                           otherwise write a minimal embedded fallback), and set
//                          env FONTCONFIG_PATH=<dir>, FONTCONFIG_FILE=<dir>/fonts.conf.
//       - status Enabled     : full success, the source was copied.
//       - status BestEffort  : dir + fallback fonts.conf written, but the source
//                              copy failed (missing / unreadable / not provided).
//       - status Unavailable : the fontconfig dir could not be created at all.

#include <gtest/gtest.h>

#include <algorithm>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include <unistd.h>

#include "font_guard.hpp"

namespace fs = std::filesystem;
using namespace raincoat;

namespace {

// Create a real, unique temporary directory and return its path (empty on failure).
std::string make_temp_dir() {
    fs::path tmpl = fs::temp_directory_path() / "rc-fontguard-XXXXXX";
    std::string s = tmpl.string();
    std::vector<char> buf(s.begin(), s.end());
    buf.push_back('\0');
    char* p = ::mkdtemp(buf.data());
    if (!p) return {};
    return std::string(p);
}

std::string read_file(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    std::ostringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

void write_file(const std::string& path, const std::string& content) {
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    out << content;
}

// RAII real temp sandbox directory; recursively removed on teardown.
struct TmpSandbox {
    std::string dir;
    TmpSandbox() { dir = make_temp_dir(); }
    ~TmpSandbox() {
        if (!dir.empty()) {
            std::error_code ec;
            fs::remove_all(dir, ec);
        }
    }
};

}  // namespace

// ---------------------------------------------------------------------------
// enabled == false  => Disabled
// ---------------------------------------------------------------------------

TEST(FontGuard, DisabledReturnsDisabledStatus) {
    TmpSandbox sb;
    ASSERT_FALSE(sb.dir.empty());
    std::string err = "sentinel";  // must be left untouched (or cleared) on the no-op path

    FontSetup r = setup_fontconfig(sb.dir, /*enabled=*/false, /*source=*/"", err);

    EXPECT_EQ(r.status, FontStatus::Disabled);
}

// (a) The disabled no-op path must leave the caller's err buffer clean.
TEST(FontGuard, DisabledClearsErr) {
    TmpSandbox sb;
    ASSERT_FALSE(sb.dir.empty());
    std::string err = "sentinel";

    FontSetup r = setup_fontconfig(sb.dir, /*enabled=*/false, /*source=*/"", err);

    EXPECT_EQ(r.status, FontStatus::Disabled);
    EXPECT_TRUE(err.empty());
}

TEST(FontGuard, DisabledHasEmptyEnv) {
    TmpSandbox sb;
    ASSERT_FALSE(sb.dir.empty());
    std::string err;

    FontSetup r = setup_fontconfig(sb.dir, false, "", err);

    EXPECT_TRUE(r.env.empty());
    EXPECT_EQ(r.env.count("FONTCONFIG_PATH"), 0u);
    EXPECT_EQ(r.env.count("FONTCONFIG_FILE"), 0u);
}

TEST(FontGuard, DisabledHasEmptyDir) {
    TmpSandbox sb;
    ASSERT_FALSE(sb.dir.empty());
    std::string err;

    FontSetup r = setup_fontconfig(sb.dir, false, "", err);

    EXPECT_TRUE(r.dir.empty());
}

TEST(FontGuard, DisabledDoesNotCreateFontconfigDir) {
    TmpSandbox sb;
    ASSERT_FALSE(sb.dir.empty());
    std::string err;

    setup_fontconfig(sb.dir, false, "", err);

    EXPECT_FALSE(fs::exists(fs::path(sb.dir) / "fontconfig"));
}

// ---------------------------------------------------------------------------
// enabled == true  => directory + fonts.conf + env
// ---------------------------------------------------------------------------

TEST(FontGuard, EnabledCreatesFontconfigDir) {
    TmpSandbox sb;
    ASSERT_FALSE(sb.dir.empty());
    std::string err;

    FontSetup r = setup_fontconfig(sb.dir, /*enabled=*/true, /*source=*/"", err);

    EXPECT_NE(r.status, FontStatus::Disabled);
    EXPECT_NE(r.status, FontStatus::Unavailable);
    EXPECT_EQ(r.dir, (fs::path(sb.dir) / "fontconfig").string());
    EXPECT_TRUE(fs::is_directory(r.dir));
}

TEST(FontGuard, EnabledWritesNonEmptyFontsConf) {
    TmpSandbox sb;
    ASSERT_FALSE(sb.dir.empty());
    std::string err;

    FontSetup r = setup_fontconfig(sb.dir, true, "", err);

    std::string conf = (fs::path(r.dir) / "fonts.conf").string();
    EXPECT_TRUE(fs::exists(conf));
    EXPECT_FALSE(read_file(conf).empty());
}

TEST(FontGuard, EnabledSetsFontconfigEnvVars) {
    TmpSandbox sb;
    ASSERT_FALSE(sb.dir.empty());
    std::string err;

    FontSetup r = setup_fontconfig(sb.dir, true, "", err);

    ASSERT_EQ(r.env.count("FONTCONFIG_PATH"), 1u);
    ASSERT_EQ(r.env.count("FONTCONFIG_FILE"), 1u);
    EXPECT_EQ(r.env.at("FONTCONFIG_PATH"), r.dir);
    EXPECT_EQ(r.env.at("FONTCONFIG_FILE"), (fs::path(r.dir) / "fonts.conf").string());
}

// XDG_DATA_DIRS is pinned to a minimal, system-only value (SPEC) so the child
// never inherits the host's data-dir list; it points under the read-only /usr bind.
TEST(FontGuard, EnabledSetsMinimalXdgDataDirs) {
    TmpSandbox sb;
    ASSERT_FALSE(sb.dir.empty());
    std::string err;

    FontSetup r = setup_fontconfig(sb.dir, true, "", err);

    ASSERT_EQ(r.env.count("XDG_DATA_DIRS"), 1u);
    EXPECT_EQ(r.env.at("XDG_DATA_DIRS"), "/usr/local/share:/usr/share");
}

// The written file must actually exist where the env says it does.
TEST(FontGuard, EnabledEnvFilePointsAtRealFile) {
    TmpSandbox sb;
    ASSERT_FALSE(sb.dir.empty());
    std::string err;

    FontSetup r = setup_fontconfig(sb.dir, true, "", err);

    ASSERT_EQ(r.env.count("FONTCONFIG_FILE"), 1u);
    EXPECT_TRUE(fs::exists(r.env.at("FONTCONFIG_FILE")));
}

// FONTCONFIG_FILE must live under FONTCONFIG_PATH regardless of path spelling.
TEST(FontGuard, EnabledEnvIsInternallyConsistent) {
    TmpSandbox sb;
    ASSERT_FALSE(sb.dir.empty());
    std::string err;

    FontSetup r = setup_fontconfig(sb.dir, true, "", err);

    ASSERT_EQ(r.env.count("FONTCONFIG_PATH"), 1u);
    ASSERT_EQ(r.env.count("FONTCONFIG_FILE"), 1u);
    EXPECT_EQ(r.env.at("FONTCONFIG_FILE"),
              (fs::path(r.env.at("FONTCONFIG_PATH")) / "fonts.conf").string());
}

TEST(FontGuard, EnabledLeavesErrEmptyOnSuccess) {
    TmpSandbox sb;
    ASSERT_FALSE(sb.dir.empty());
    std::string err = "sentinel";

    FontSetup r = setup_fontconfig(sb.dir, true, "", err);

    ASSERT_NE(r.status, FontStatus::Unavailable);
    EXPECT_TRUE(err.empty());
}

TEST(FontGuard, EnabledPopulatesAuditNote) {
    TmpSandbox sb;
    ASSERT_FALSE(sb.dir.empty());
    std::string err;

    FontSetup r = setup_fontconfig(sb.dir, true, "", err);

    EXPECT_FALSE(r.note.empty());
}

// ---------------------------------------------------------------------------
// Fallback path (no usable source) => BestEffort
// ---------------------------------------------------------------------------

TEST(FontGuard, EmptySourceFallsBackToBestEffort) {
    TmpSandbox sb;
    ASSERT_FALSE(sb.dir.empty());
    std::string err;

    FontSetup r = setup_fontconfig(sb.dir, true, /*source=*/"", err);

    EXPECT_EQ(r.status, FontStatus::BestEffort);
    // dir + fallback file + env are still fully set up.
    EXPECT_TRUE(fs::is_directory(r.dir));
    EXPECT_TRUE(fs::exists((fs::path(r.dir) / "fonts.conf")));
    EXPECT_EQ(r.env.count("FONTCONFIG_FILE"), 1u);
}

// Write-failure branch (a): a source WAS requested (non-empty path) but could not be
// copied, so the minimal fallback is written => BestEffort with the copy-failure note.
TEST(FontGuard, RequestedButUnusableSourceNotesCopyFailure) {
    TmpSandbox sb;
    ASSERT_FALSE(sb.dir.empty());
    std::string err;
    std::string missing = (fs::path(sb.dir) / "does-not-exist.conf").string();
    ASSERT_FALSE(fs::exists(missing));

    FontSetup r = setup_fontconfig(sb.dir, true, missing, err);

    EXPECT_EQ(r.status, FontStatus::BestEffort);
    EXPECT_NE(r.note.find("source copy failed"), std::string::npos) << r.note;
    EXPECT_NE(r.note.find("minimal fallback"), std::string::npos) << r.note;
    EXPECT_TRUE(err.empty());
    EXPECT_TRUE(fs::exists((fs::path(r.dir) / "fonts.conf")));
}

// The no-source case is distinguished from a copy failure in the audit note.
TEST(FontGuard, EmptySourceNotesNoUsableSource) {
    TmpSandbox sb;
    ASSERT_FALSE(sb.dir.empty());
    std::string err;

    FontSetup r = setup_fontconfig(sb.dir, true, /*source=*/"", err);

    EXPECT_EQ(r.status, FontStatus::BestEffort);
    EXPECT_NE(r.note.find("no usable source"), std::string::npos) << r.note;
}

TEST(FontGuard, MissingSourceFallsBackToBestEffort) {
    TmpSandbox sb;
    ASSERT_FALSE(sb.dir.empty());
    std::string err;
    std::string missing = (fs::path(sb.dir) / "does-not-exist.conf").string();
    ASSERT_FALSE(fs::exists(missing));

    FontSetup r = setup_fontconfig(sb.dir, true, missing, err);

    EXPECT_EQ(r.status, FontStatus::BestEffort);
    EXPECT_TRUE(fs::exists((fs::path(r.dir) / "fonts.conf")));
}

// The embedded fallback must be a plausible fontconfig document.
TEST(FontGuard, FallbackFontsConfLooksLikeFontconfig) {
    TmpSandbox sb;
    ASSERT_FALSE(sb.dir.empty());
    std::string err;

    FontSetup r = setup_fontconfig(sb.dir, true, "", err);

    std::string conf = read_file((fs::path(r.dir) / "fonts.conf").string());
    EXPECT_NE(conf.find("fontconfig"), std::string::npos);
}

// A source path whose file is unreadable (permissions) must degrade to BestEffort
// with the fallback still written. Skipped under root, where mode bits are ignored.
TEST(FontGuard, UnreadableSourceFallsBackToBestEffort) {
    if (::geteuid() == 0) {
        GTEST_SKIP() << "running as root: file permission bits are not enforced";
    }
    TmpSandbox sb;
    ASSERT_FALSE(sb.dir.empty());
    std::string err;

    std::string src = (fs::path(sb.dir) / "unreadable.conf").string();
    write_file(src, "<?xml version=\"1.0\"?><fontconfig>SOURCE</fontconfig>");
    std::error_code ec;
    fs::permissions(src, fs::perms::none, ec);
    ASSERT_FALSE(ec);

    FontSetup r = setup_fontconfig(sb.dir, true, src, err);

    // restore perms so cleanup can remove it
    fs::permissions(src, fs::perms::owner_all, ec);

    EXPECT_EQ(r.status, FontStatus::BestEffort);
    EXPECT_TRUE(fs::exists((fs::path(r.dir) / "fonts.conf")));
}

// ---------------------------------------------------------------------------
// Readable source => Enabled, copied verbatim
// ---------------------------------------------------------------------------

TEST(FontGuard, ReadableSourceProducesEnabled) {
    TmpSandbox sb;
    ASSERT_FALSE(sb.dir.empty());
    std::string err;

    std::string src = (fs::path(sb.dir) / "source-fonts.conf").string();
    write_file(src, "<?xml version=\"1.0\"?>\n<fontconfig><dir>/x</dir></fontconfig>\n");

    FontSetup r = setup_fontconfig(sb.dir, true, src, err);

    EXPECT_EQ(r.status, FontStatus::Enabled);
    EXPECT_EQ(r.env.count("FONTCONFIG_FILE"), 1u);
}

TEST(FontGuard, ReadableSourceCopiedVerbatim) {
    TmpSandbox sb;
    ASSERT_FALSE(sb.dir.empty());
    std::string err;

    const std::string marker =
        "<?xml version=\"1.0\"?>\n<fontconfig>UNIQUE-MARKER-9137</fontconfig>\n";
    std::string src = (fs::path(sb.dir) / "source-fonts.conf").string();
    write_file(src, marker);

    FontSetup r = setup_fontconfig(sb.dir, true, src, err);

    ASSERT_EQ(r.status, FontStatus::Enabled);
    std::string written = read_file((fs::path(r.dir) / "fonts.conf").string());
    EXPECT_EQ(written, marker);
}

TEST(FontGuard, ReadableSourceLeavesErrEmpty) {
    TmpSandbox sb;
    ASSERT_FALSE(sb.dir.empty());
    std::string err = "sentinel";

    std::string src = (fs::path(sb.dir) / "source-fonts.conf").string();
    write_file(src, "<fontconfig/>");

    FontSetup r = setup_fontconfig(sb.dir, true, src, err);

    EXPECT_EQ(r.status, FontStatus::Enabled);
    EXPECT_TRUE(err.empty());
}

// ---------------------------------------------------------------------------
// Unavailable => the fontconfig directory cannot be created
// ---------------------------------------------------------------------------

TEST(FontGuard, UnavailableWhenDirCannotBeCreated) {
    TmpSandbox sb;
    ASSERT_FALSE(sb.dir.empty());
    std::string err;

    // Make sandbox_dir a *file*, so that <sandbox_dir>/fontconfig cannot be a directory.
    std::string as_file = (fs::path(sb.dir) / "iam-a-file").string();
    write_file(as_file, "not a directory");
    ASSERT_TRUE(fs::is_regular_file(as_file));

    FontSetup r = setup_fontconfig(as_file, /*enabled=*/true, /*source=*/"", err);

    EXPECT_EQ(r.status, FontStatus::Unavailable);
}

// Write-failure branch (b): the fontconfig directory cannot be created => Unavailable,
// with a note that names the directory-creation failure.
TEST(FontGuard, DirCreateFailNotesDirectoryFailure) {
    TmpSandbox sb;
    ASSERT_FALSE(sb.dir.empty());
    std::string err;

    std::string as_file = (fs::path(sb.dir) / "iam-a-file").string();
    write_file(as_file, "not a directory");
    ASSERT_TRUE(fs::is_regular_file(as_file));

    FontSetup r = setup_fontconfig(as_file, true, "", err);

    EXPECT_EQ(r.status, FontStatus::Unavailable);
    EXPECT_NE(r.note.find("could not create fontconfig directory"),
              std::string::npos) << r.note;
    EXPECT_FALSE(err.empty());
}

// (b) An empty sandbox_dir must be rejected outright, not turned into a relative path.
TEST(FontGuard, EmptySandboxDirIsUnavailable) {
    std::string err;

    FontSetup r = setup_fontconfig(/*sandbox_dir=*/"", true, "", err);

    EXPECT_EQ(r.status, FontStatus::Unavailable);
    EXPECT_FALSE(err.empty());
    EXPECT_EQ(r.env.count("FONTCONFIG_FILE"), 0u);
    EXPECT_TRUE(r.dir.empty());
}

// (b) A relative sandbox_dir must be rejected and must NOT create a stray
// "fontconfig/" directory in the current working directory.
TEST(FontGuard, RelativeSandboxDirIsUnavailable) {
    // Use a uniquely-named relative path so we can assert nothing was created for it.
    const std::string rel = "rc-relative-sandbox-9137";
    std::error_code ec;
    fs::remove_all(rel, ec);  // pre-clean in case a prior run left it behind
    std::string err;

    FontSetup r = setup_fontconfig(rel, true, "", err);

    EXPECT_EQ(r.status, FontStatus::Unavailable);
    EXPECT_FALSE(err.empty());
    EXPECT_FALSE(fs::exists(fs::path(rel) / "fontconfig"))
        << "must not create a relative fontconfig/ in the process CWD";

    fs::remove_all(rel, ec);  // cleanup if anything did appear
}

TEST(FontGuard, UnavailableSetsErr) {
    TmpSandbox sb;
    ASSERT_FALSE(sb.dir.empty());
    std::string err;

    std::string as_file = (fs::path(sb.dir) / "iam-a-file").string();
    write_file(as_file, "x");

    FontSetup r = setup_fontconfig(as_file, true, "", err);

    ASSERT_EQ(r.status, FontStatus::Unavailable);
    EXPECT_FALSE(err.empty());
}

TEST(FontGuard, UnavailableSetsNoFontconfigEnv) {
    TmpSandbox sb;
    ASSERT_FALSE(sb.dir.empty());
    std::string err;

    std::string as_file = (fs::path(sb.dir) / "iam-a-file").string();
    write_file(as_file, "x");

    FontSetup r = setup_fontconfig(as_file, true, "", err);

    ASSERT_EQ(r.status, FontStatus::Unavailable);
    EXPECT_EQ(r.env.count("FONTCONFIG_FILE"), 0u);
    EXPECT_EQ(r.env.count("FONTCONFIG_PATH"), 0u);
}

// ---------------------------------------------------------------------------
// Robustness / edge cases
// ---------------------------------------------------------------------------

// Calling twice against the same sandbox (dir already exists) must still succeed.
TEST(FontGuard, IdempotentOnPreexistingDir) {
    TmpSandbox sb;
    ASSERT_FALSE(sb.dir.empty());
    std::string err1, err2;

    FontSetup r1 = setup_fontconfig(sb.dir, true, "", err1);
    ASSERT_NE(r1.status, FontStatus::Unavailable);

    FontSetup r2 = setup_fontconfig(sb.dir, true, "", err2);
    EXPECT_NE(r2.status, FontStatus::Unavailable);
    EXPECT_TRUE(err2.empty());
    EXPECT_TRUE(fs::exists((fs::path(r2.dir) / "fonts.conf")));
}

// A trailing slash on sandbox_dir must still yield a valid, self-consistent setup.
TEST(FontGuard, TrailingSlashSandboxDir) {
    TmpSandbox sb;
    ASSERT_FALSE(sb.dir.empty());
    std::string err;

    FontSetup r = setup_fontconfig(sb.dir + "/", true, "", err);

    ASSERT_NE(r.status, FontStatus::Unavailable);
    ASSERT_EQ(r.env.count("FONTCONFIG_FILE"), 1u);
    EXPECT_TRUE(fs::exists(r.env.at("FONTCONFIG_FILE")));
    EXPECT_TRUE(fs::is_directory(r.dir));
}

// ---------------------------------------------------------------------------
// Curated generic font set (real fs-level isolation)
// ---------------------------------------------------------------------------

// curated_font_dirs() returns only existing dirs, all under the known curated set,
// each an absolute, existing directory. Robust to which curated dirs the host has.
TEST(FontGuard, CuratedDirsAreExistingAbsoluteSubsetOfKnownSet) {
    static const std::vector<std::string> kKnown = {
        "/usr/share/fonts/truetype/dejavu",
        "/usr/share/fonts/truetype/noto",
        "/usr/share/fonts/opentype/noto",
    };
    std::vector<std::string> dirs = curated_font_dirs();
    for (const auto& d : dirs) {
        EXPECT_TRUE(fs::is_directory(d)) << d << " should exist";
        EXPECT_EQ(d.rfind("/usr/share/fonts/", 0), 0u) << d;
        EXPECT_NE(std::find(kKnown.begin(), kKnown.end(), d), kKnown.end())
            << d << " is not in the curated set";
    }
    // No duplicates.
    std::vector<std::string> sorted = dirs;
    std::sort(sorted.begin(), sorted.end());
    EXPECT_EQ(std::adjacent_find(sorted.begin(), sorted.end()), sorted.end());
}

// When enabled, setup_fontconfig reports the curated dirs it detected (so the runner
// can mask /usr/share/fonts and re-bind only these). They match curated_font_dirs().
TEST(FontGuard, EnabledPopulatesFontDirs) {
    TmpSandbox sb;
    ASSERT_FALSE(sb.dir.empty());
    std::string err;

    FontSetup r = setup_fontconfig(sb.dir, true, "", err);
    EXPECT_EQ(r.font_dirs, curated_font_dirs());
}

// Disabled must not report curated dirs (no masking when fontconfig is off).
TEST(FontGuard, DisabledHasNoFontDirs) {
    TmpSandbox sb;
    ASSERT_FALSE(sb.dir.empty());
    std::string err;

    FontSetup r = setup_fontconfig(sb.dir, false, "", err);
    EXPECT_TRUE(r.font_dirs.empty());
}

// The generated (no-source) fonts.conf lists the curated dirs and the generic
// aliases (sans-serif/serif/monospace/emoji) so fontconfig enumerates only the
// generic set.
TEST(FontGuard, GeneratedFontsConfListsCuratedDirsAndAliases) {
    TmpSandbox sb;
    ASSERT_FALSE(sb.dir.empty());
    std::string err;

    FontSetup r = setup_fontconfig(sb.dir, true, "", err);
    const std::string conf = read_file((fs::path(r.dir) / "fonts.conf").string());

    EXPECT_NE(conf.find("sans-serif"), std::string::npos) << conf;
    EXPECT_NE(conf.find("monospace"), std::string::npos) << conf;
    EXPECT_NE(conf.find("emoji"), std::string::npos) << conf;
    EXPECT_NE(conf.find("Noto Sans"), std::string::npos) << conf;
    // Every detected curated dir must be listed as a <dir> entry.
    for (const auto& d : r.font_dirs) {
        EXPECT_NE(conf.find("<dir>" + d + "</dir>"), std::string::npos) << conf;
    }
}

// Disabled must win even when a perfectly good source is supplied.
TEST(FontGuard, DisabledIgnoresSource) {
    TmpSandbox sb;
    ASSERT_FALSE(sb.dir.empty());
    std::string err;

    std::string src = (fs::path(sb.dir) / "source.conf").string();
    write_file(src, "<fontconfig/>");

    FontSetup r = setup_fontconfig(sb.dir, false, src, err);

    EXPECT_EQ(r.status, FontStatus::Disabled);
    EXPECT_TRUE(r.env.empty());
    EXPECT_FALSE(fs::exists(fs::path(sb.dir) / "fontconfig"));
}
