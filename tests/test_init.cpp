// Raincoat — init module tests.
//
// Covers the two public entry points from DESIGN.md / SPEC.md:
//   std::string default_toml();
//   bool write_init(const std::string& path, bool force, std::string& err);
//
// default_toml() must be non-empty, deterministic, structurally-valid TOML, and must
// match the SPEC "Config file (TOML)" example fields. write_init() must refuse to
// overwrite an existing file unless `force` is set, and must create the file otherwise.
//
// These tests validate TOML structure locally with a lightweight line scanner.
//
// NOTE: this suite is intentionally compiled with ONLY src/init.cpp + src/util.cpp so
// it has no link dependency on src/toml.cpp (which is edited by a concurrent stream).
// The cross-module "default_toml() round-trips through the project's own parse_toml"
// check is deliberately NOT here; a later integration phase re-adds a proper
// cross-module round-trip test that links the real toml parser.

#include <gtest/gtest.h>

#include <cstdlib>
#include <fstream>
#include <sstream>
#include <string>
#include <unistd.h>
#include <sys/stat.h>

#include <map>
#include <vector>

#include "init.hpp"

using raincoat::default_toml;
using raincoat::write_init;

namespace {

// ---- small filesystem helpers (self-contained; no util.hpp dependency) ------

// Create a fresh empty temporary directory and return its absolute path.
std::string make_temp_dir() {
    char tmpl[] = "/tmp/rc-init-test-XXXXXX";
    char* d = ::mkdtemp(tmpl);
    EXPECT_NE(d, nullptr) << "mkdtemp failed";
    return d ? std::string(d) : std::string();
}

bool file_exists(const std::string& p) {
    struct stat st{};
    return ::stat(p.c_str(), &st) == 0;
}

std::string read_file(const std::string& p) {
    std::ifstream in(p, std::ios::binary);
    std::ostringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

void write_file(const std::string& p, const std::string& content) {
    std::ofstream out(p, std::ios::binary | std::ios::trunc);
    out << content;
}

std::string to_lower(std::string s) {
    for (char& c : s) c = static_cast<char>(::tolower(static_cast<unsigned char>(c)));
    return s;
}

bool contains(const std::string& hay, const std::string& needle) {
    return hay.find(needle) != std::string::npos;
}

std::string strip(const std::string& s) {
    size_t a = s.find_first_not_of(" \t\r\n");
    if (a == std::string::npos) return "";
    size_t b = s.find_last_not_of(" \t\r\n");
    return s.substr(a, b - a + 1);
}

// A deliberately lightweight structural check for the tiny TOML subset the config
// uses: comments, blank lines, `[table]` headers, and `key = value` lines.
// Returns true if every meaningful line is well-formed.
bool looks_like_valid_toml(const std::string& text, std::string& why) {
    std::istringstream in(text);
    std::string line;
    while (std::getline(in, line)) {
        std::string t = strip(line);
        if (t.empty()) continue;
        if (t[0] == '#') continue;  // comment
        if (t[0] == '[') {          // table header
            if (t.back() != ']') { why = "unterminated table header: " + t; return false; }
            continue;
        }
        // otherwise must be key = value
        size_t eq = t.find('=');
        if (eq == std::string::npos) { why = "line has no '=': " + t; return false; }
        std::string key = strip(t.substr(0, eq));
        std::string val = strip(t.substr(eq + 1));
        if (key.empty()) { why = "empty key: " + t; return false; }
        if (val.empty()) { why = "empty value: " + t; return false; }
        // balanced double quotes on the value portion
        size_t quotes = 0;
        for (char c : val) if (c == '"') ++quotes;
        if (quotes % 2 != 0) { why = "unbalanced quotes: " + t; return false; }
        // balanced brackets for inline arrays
        long depth = 0;
        for (char c : val) { if (c == '[') ++depth; else if (c == ']') --depth; }
        if (depth != 0) { why = "unbalanced array brackets: " + t; return false; }
    }
    return true;
}

}  // namespace

// ===========================================================================
// default_toml() — content + structure
// ===========================================================================

TEST(Init, DefaultTomlIsNotEmpty) {
    EXPECT_FALSE(default_toml().empty());
}

TEST(Init, DefaultTomlIsDeterministic) {
    EXPECT_EQ(default_toml(), default_toml());
}

TEST(Init, DefaultTomlIsStructurallyValid) {
    std::string why;
    EXPECT_TRUE(looks_like_valid_toml(default_toml(), why)) << why;
}

TEST(Init, DefaultTomlHasStrictFalse) {
    // SPEC example: strict = false
    const std::string t = default_toml();
    EXPECT_TRUE(contains(t, "strict")) << "missing strict key";
    EXPECT_TRUE(contains(t, "strict = false") || contains(t, "strict=false"))
        << "strict should default to false";
}

TEST(Init, DefaultTomlHasNetworkFull) {
    // SPEC example: network = "full"
    const std::string t = default_toml();
    EXPECT_TRUE(contains(t, "network"));
    EXPECT_TRUE(contains(t, "\"full\"")) << "network should default to \"full\"";
}

TEST(Init, DefaultTomlHasAllowReadArray) {
    const std::string t = default_toml();
    EXPECT_TRUE(contains(t, "allow_read"));
    EXPECT_TRUE(contains(t, "[\"./src\"]")) << "allow_read example value from SPEC";
}

TEST(Init, DefaultTomlHasAllowWriteArray) {
    const std::string t = default_toml();
    EXPECT_TRUE(contains(t, "allow_write"));
    EXPECT_TRUE(contains(t, "[\"./out\"]")) << "allow_write example value from SPEC";
}

TEST(Init, DefaultTomlHasAllowEnvArray) {
    const std::string t = default_toml();
    EXPECT_TRUE(contains(t, "allow_env"));
    EXPECT_TRUE(contains(t, "OPENAI_API_KEY")) << "allow_env example value from SPEC";
}

TEST(Init, DefaultTomlHasEnvTableWithLocaleAndTz) {
    const std::string t = default_toml();
    EXPECT_TRUE(contains(t, "[env]")) << "missing [env] table header";
    EXPECT_TRUE(contains(t, "TZ = \"UTC\"") || contains(t, "TZ=\"UTC\""));
    EXPECT_TRUE(contains(t, "LANG = \"en_US.UTF-8\"") || contains(t, "LANG=\"en_US.UTF-8\""));
    EXPECT_TRUE(contains(t, "LC_ALL = \"en_US.UTF-8\"") || contains(t, "LC_ALL=\"en_US.UTF-8\""));
}

TEST(Init, DefaultTomlHasFontconfigEnabledTrue) {
    const std::string t = default_toml();
    EXPECT_TRUE(contains(t, "[fontconfig]")) << "missing [fontconfig] table header";
    EXPECT_TRUE(contains(t, "enabled = true") || contains(t, "enabled=true"));
}

TEST(Init, DefaultTomlHasAuditLogFile) {
    const std::string t = default_toml();
    EXPECT_TRUE(contains(t, "[audit]")) << "missing [audit] table header";
    EXPECT_TRUE(contains(t, ".raincoat/audit.log")) << "audit log_file example value from SPEC";
}

TEST(Init, DefaultTomlEndsWithNewline) {
    // A generated config file should be newline-terminated.
    const std::string t = default_toml();
    ASSERT_FALSE(t.empty());
    EXPECT_EQ(t.back(), '\n');
}

// ===========================================================================
// write_init() — fresh creation
// ===========================================================================

TEST(Init, WriteInitCreatesFileFresh) {
    const std::string dir = make_temp_dir();
    ASSERT_FALSE(dir.empty());
    const std::string path = dir + "/.raincoat.toml";

    std::string err = "sentinel";
    ASSERT_FALSE(file_exists(path));
    EXPECT_TRUE(write_init(path, /*force=*/false, err)) << "fresh write should succeed";
    EXPECT_TRUE(err.empty()) << "err should be cleared on success, got: " << err;
    EXPECT_TRUE(file_exists(path));
}

TEST(Init, WriteInitWritesDefaultTomlContent) {
    const std::string dir = make_temp_dir();
    ASSERT_FALSE(dir.empty());
    const std::string path = dir + "/.raincoat.toml";

    std::string err;
    ASSERT_TRUE(write_init(path, /*force=*/false, err));
    EXPECT_EQ(read_file(path), default_toml())
        << "written file should contain exactly default_toml()";
}

// ===========================================================================
// write_init() — refuse overwrite unless force
// ===========================================================================

TEST(Init, WriteInitRefusesOverwriteWithoutForce) {
    const std::string dir = make_temp_dir();
    ASSERT_FALSE(dir.empty());
    const std::string path = dir + "/.raincoat.toml";

    std::string err;
    ASSERT_TRUE(write_init(path, /*force=*/false, err));  // first write

    err.clear();
    EXPECT_FALSE(write_init(path, /*force=*/false, err))
        << "second write without force must fail";
    EXPECT_FALSE(err.empty()) << "a helpful error message must be set on refusal";
}

TEST(Init, WriteInitRefusalMessageIsHelpful) {
    const std::string dir = make_temp_dir();
    ASSERT_FALSE(dir.empty());
    const std::string path = dir + "/.raincoat.toml";

    std::string err;
    ASSERT_TRUE(write_init(path, /*force=*/false, err));

    err.clear();
    ASSERT_FALSE(write_init(path, /*force=*/false, err));
    const std::string low = to_lower(err);
    // Helpful == names the situation (already exists) or the escape hatch (force).
    EXPECT_TRUE(contains(low, "exist") || contains(low, "force"))
        << "refusal error should mention that the file exists or suggest --force; got: " << err;
    EXPECT_TRUE(contains(err, path))
        << "refusal error should quote the offending path; got: " << err;
}

TEST(Init, WriteInitRefusalMessageReferencesForce) {
    // The refusal advertises the actual escape hatch: `raincoat init --force`.
    const std::string dir = make_temp_dir();
    ASSERT_FALSE(dir.empty());
    const std::string path = dir + "/.raincoat.toml";

    std::string err;
    ASSERT_TRUE(write_init(path, /*force=*/false, err));

    err.clear();
    ASSERT_FALSE(write_init(path, /*force=*/false, err));
    EXPECT_TRUE(contains(err, "--force"))
        << "refusal error should point the user at --force; got: " << err;
}

TEST(Init, WriteInitRefusalLeavesExistingFileUntouched) {
    const std::string dir = make_temp_dir();
    ASSERT_FALSE(dir.empty());
    const std::string path = dir + "/.raincoat.toml";

    const std::string sentinel = "# user-edited config, do not clobber\n";
    write_file(path, sentinel);

    std::string err;
    EXPECT_FALSE(write_init(path, /*force=*/false, err));
    EXPECT_EQ(read_file(path), sentinel)
        << "a refused write must not modify the pre-existing file";
}

// ===========================================================================
// write_init() — force overwrites
// ===========================================================================

TEST(Init, WriteInitForceOverwritesExisting) {
    const std::string dir = make_temp_dir();
    ASSERT_FALSE(dir.empty());
    const std::string path = dir + "/.raincoat.toml";

    write_file(path, "# stale contents\n");

    std::string err = "sentinel";
    EXPECT_TRUE(write_init(path, /*force=*/true, err)) << "force write should succeed";
    EXPECT_TRUE(err.empty()) << "err should be cleared on success, got: " << err;
    EXPECT_EQ(read_file(path), default_toml())
        << "force write should replace contents with default_toml()";
}

TEST(Init, WriteInitForceCreatesWhenAbsent) {
    // force on a non-existent file should simply create it (no file to protect).
    const std::string dir = make_temp_dir();
    ASSERT_FALSE(dir.empty());
    const std::string path = dir + "/.raincoat.toml";

    std::string err = "sentinel";
    ASSERT_FALSE(file_exists(path));
    EXPECT_TRUE(write_init(path, /*force=*/true, err));
    EXPECT_TRUE(err.empty());
    EXPECT_EQ(read_file(path), default_toml());
}

// ===========================================================================
// write_init() — error surface
// ===========================================================================

TEST(Init, WriteInitFailsOnUnwritableLocation) {
    // Parent directory does not exist -> the write cannot succeed and must report,
    // not crash or silently claim success.
    const std::string dir = make_temp_dir();
    ASSERT_FALSE(dir.empty());
    const std::string path = dir + "/no-such-subdir/.raincoat.toml";

    std::string err;
    EXPECT_FALSE(write_init(path, /*force=*/false, err))
        << "writing into a missing parent directory should fail";
    EXPECT_FALSE(err.empty()) << "an error message should be set on write failure";
    EXPECT_FALSE(file_exists(path));
}
