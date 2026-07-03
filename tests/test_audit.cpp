// Raincoat — comprehensive GoogleTest suite for the `audit` module.
//
// Covers AuditRecord + format_audit_start / format_audit_end / write_audit as
// specified in docs/DESIGN.md and docs/SPEC.md ("Audit log" section).
//
// These tests are written BEFORE the implementation (TDD red): they compile
// against the stub header but are expected to FAIL until audit.cpp is written.
//
// Standalone build:
//   g++ -std=c++17 -Isrc src/audit.cpp src/util.cpp tests/test_audit.cpp
//       -lgtest -lgtest_main -lpthread -o /tmp/rc-t-audit && /tmp/rc-t-audit

#include <gtest/gtest.h>

#include <atomic>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>

#include <unistd.h>

#include "audit.hpp"

using namespace raincoat;
namespace fs = std::filesystem;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

static bool contains(const std::string& hay, const std::string& needle) {
    return hay.find(needle) != std::string::npos;
}

static std::string read_file(const fs::path& p) {
    std::ifstream in(p, std::ios::binary);
    std::ostringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

// Return the single line of `text` that begins with `label` (label included),
// or "" if none. Used to make assertions precise: we inspect ONLY the intended
// line rather than substring-matching against the whole document (where an
// incidental digit in e.g. the Fake HOME path could satisfy a bare count check).
static std::string line_with_label(const std::string& text, const std::string& label) {
    std::istringstream in(text);
    std::string line;
    while (std::getline(in, line)) {
        if (line.rfind(label, 0) == 0) return line;
    }
    return "";
}

// Count comma-separated NAME entries on a "Label: a, b, c" line, or 0 for "(none)".
static int count_names_on_line(const std::string& line, const std::string& label) {
    const std::string rest = line.substr(label.size());
    // Trim leading spaces.
    std::size_t start = rest.find_first_not_of(' ');
    if (start == std::string::npos) return 0;
    const std::string names = rest.substr(start);
    if (names == "(none)") return 0;
    int count = 1;
    for (char c : names)
        if (c == ',') ++count;
    return count;
}

static Mount mk_mount(const std::string& host, MountMode m) {
    Mount mt;
    mt.host_path = host;
    mt.sandbox_path = host;  // identity mapping in the MVP
    mt.mode = m;
    return mt;
}

// A fully-populated, realistic record used across the formatting tests. The
// secret VALUES here (sk-SECRETVALUE123, supersecretset) live only in the
// resolved-env map and must NEVER appear in the formatted audit output.
static AuditRecord sample_record() {
    AuditRecord r;
    r.command_line = "python train.py --epochs 3";
    r.strict = false;
    r.net = NetMode::Full;
    r.fake_home = "/tmp/rc-sandbox-XYZ/home/user";
    r.workdir = "/home/zach/project";
    r.mounts = {
        mk_mount("/home/zach/project/src", MountMode::ReadOnly),
        mk_mount("/home/zach/project/out", MountMode::ReadWrite),
    };
    r.env.resolved = {
        {"PATH", "/usr/bin:/bin"},
        {"OPENAI_API_KEY", "sk-SECRETVALUE123"},
        {"MY_SET_VAR", "supersecretset"},
    };
    r.env.allowed = {"PATH", "OPENAI_API_KEY"};
    r.env.set = {"LANG", "LC_ALL", "MY_SET_VAR", "TZ", "USER"};
    r.env.scrubbed = {"AWS_SECRET_ACCESS_KEY", "GITHUB_TOKEN", "SSH_AUTH_SOCK"};
    r.font = FontStatus::Enabled;
    r.timezone = "UTC";
    r.locale = "en_US.UTF-8";
    r.bwrap_command =
        "/usr/bin/bwrap --die-with-parent --unshare-pid --unshare-uts "
        "--unshare-ipc --chdir /home/zach/project python train.py --epochs 3";
    return r;
}

// ---------------------------------------------------------------------------
// format_audit_start — structure / header
// ---------------------------------------------------------------------------

TEST(Audit, StartIsNonEmpty) {
    EXPECT_FALSE(format_audit_start(sample_record()).empty());
}

TEST(Audit, StartHasStartedHeader) {
    EXPECT_TRUE(contains(format_audit_start(sample_record()), "Raincoat started"));
}

TEST(Audit, StartIsMultiLine) {
    const std::string out = format_audit_start(sample_record());
    EXPECT_NE(out.find('\n'), std::string::npos);
}

// ---------------------------------------------------------------------------
// format_audit_start — content fields
// ---------------------------------------------------------------------------

TEST(Audit, StartShowsCommand) {
    EXPECT_TRUE(contains(format_audit_start(sample_record()),
                         "python train.py --epochs 3"));
}

TEST(Audit, StartShowsNormalModeWhenNotStrict) {
    AuditRecord r = sample_record();
    r.strict = false;
    EXPECT_TRUE(contains(format_audit_start(r), "normal"));
}

TEST(Audit, StartShowsStrictModeWhenStrict) {
    AuditRecord r = sample_record();
    r.strict = true;
    EXPECT_TRUE(contains(format_audit_start(r), "strict"));
}

TEST(Audit, StartShowsNetworkFull) {
    AuditRecord r = sample_record();
    r.net = NetMode::Full;
    EXPECT_TRUE(contains(format_audit_start(r), "full"));
}

TEST(Audit, StartShowsNetworkOff) {
    AuditRecord r = sample_record();
    r.net = NetMode::Off;
    EXPECT_TRUE(contains(format_audit_start(r), "off"));
}

TEST(Audit, StartShowsFakeHome) {
    EXPECT_TRUE(contains(format_audit_start(sample_record()),
                         "/tmp/rc-sandbox-XYZ/home/user"));
}

TEST(Audit, StartShowsWorkdir) {
    EXPECT_TRUE(contains(format_audit_start(sample_record()),
                         "/home/zach/project"));
}

TEST(Audit, StartShowsAllowedReadPath) {
    EXPECT_TRUE(contains(format_audit_start(sample_record()),
                         "/home/zach/project/src"));
}

TEST(Audit, StartShowsAllowedWritePath) {
    EXPECT_TRUE(contains(format_audit_start(sample_record()),
                         "/home/zach/project/out"));
}

TEST(Audit, StartShowsTimezone) {
    EXPECT_TRUE(contains(format_audit_start(sample_record()), "UTC"));
}

TEST(Audit, StartShowsLocale) {
    EXPECT_TRUE(contains(format_audit_start(sample_record()), "en_US.UTF-8"));
}

TEST(Audit, StartShowsFontconfigStatus) {
    AuditRecord r = sample_record();

    r.font = FontStatus::Enabled;
    EXPECT_TRUE(contains(format_audit_start(r), "enabled"));

    r.font = FontStatus::BestEffort;
    EXPECT_TRUE(contains(format_audit_start(r), "best-effort"));

    r.font = FontStatus::Unavailable;
    EXPECT_TRUE(contains(format_audit_start(r), "unavailable"));

    r.font = FontStatus::Disabled;
    EXPECT_TRUE(contains(format_audit_start(r), "disabled"));
}

TEST(Audit, StartShowsBwrapCommandLine) {
    EXPECT_TRUE(contains(format_audit_start(sample_record()),
                         "--die-with-parent"));
    EXPECT_TRUE(contains(format_audit_start(sample_record()),
                         "/usr/bin/bwrap"));
}

// ---------------------------------------------------------------------------
// format_audit_start — env variable NAMES (allowed / set / scrubbed)
// ---------------------------------------------------------------------------

TEST(Audit, StartShowsAllowedEnvNames) {
    const std::string out = format_audit_start(sample_record());
    EXPECT_TRUE(contains(out, "PATH"));
    EXPECT_TRUE(contains(out, "OPENAI_API_KEY"));
}

TEST(Audit, StartShowsSetEnvNames) {
    const std::string out = format_audit_start(sample_record());
    EXPECT_TRUE(contains(out, "MY_SET_VAR"));
    EXPECT_TRUE(contains(out, "TZ"));
    EXPECT_TRUE(contains(out, "LANG"));
    EXPECT_TRUE(contains(out, "USER"));
}

TEST(Audit, StartShowsScrubbedEnvNames) {
    const std::string out = format_audit_start(sample_record());
    EXPECT_TRUE(contains(out, "AWS_SECRET_ACCESS_KEY"));
    EXPECT_TRUE(contains(out, "GITHUB_TOKEN"));
    EXPECT_TRUE(contains(out, "SSH_AUTH_SOCK"));
}

// Precise count assertion: the scrubbed line must list EXACTLY the 3 scrubbed
// names — checked by parsing that line, not by substring-matching a bare "3"
// against the whole document (which could coincidentally hit a digit elsewhere,
// e.g. in the Fake HOME path). This nails both the count and the isolation.
TEST(Audit, StartScrubbedCountIsExact) {
    const std::string out = format_audit_start(sample_record());  // 3 scrubbed
    const std::string label = "Env scrubbed:";
    const std::string line = line_with_label(out, label);
    ASSERT_FALSE(line.empty()) << "no 'Env scrubbed:' line in audit output";
    EXPECT_EQ(count_names_on_line(line, label), 3) << "scrubbed line: " << line;
    // The scrubbed NAMES appear on that very line (not merely somewhere else).
    EXPECT_TRUE(contains(line, "AWS_SECRET_ACCESS_KEY"));
    EXPECT_TRUE(contains(line, "GITHUB_TOKEN"));
    EXPECT_TRUE(contains(line, "SSH_AUTH_SOCK"));
}

TEST(Audit, StartScrubbedCountIsZeroWhenNoneScrubbed) {
    AuditRecord r = sample_record();
    r.env.scrubbed.clear();
    const std::string label = "Env scrubbed:";
    const std::string line = line_with_label(format_audit_start(r), label);
    ASSERT_FALSE(line.empty());
    EXPECT_EQ(count_names_on_line(line, label), 0) << "scrubbed line: " << line;
}

// ---------------------------------------------------------------------------
// format_audit_start — SECURITY: never print secret VALUES
// ---------------------------------------------------------------------------

TEST(Audit, StartNeverLeaksAllowedSecretValue) {
    // OPENAI_API_KEY is allowed and its value is present in env.resolved.
    // The name may (and should) appear; the value must never appear.
    const std::string out = format_audit_start(sample_record());
    EXPECT_TRUE(contains(out, "OPENAI_API_KEY"));
    EXPECT_FALSE(contains(out, "sk-SECRETVALUE123"))
        << "audit output leaked a secret env value";
}

TEST(Audit, StartNeverLeaksSetSecretValue) {
    const std::string out = format_audit_start(sample_record());
    EXPECT_TRUE(contains(out, "MY_SET_VAR"));
    EXPECT_FALSE(contains(out, "supersecretset"))
        << "audit output leaked a --set-env value";
}

TEST(Audit, StartNeverLeaksScrubbedSecretValue) {
    // A scrubbed sensitive var whose value happens to be present in resolved.
    AuditRecord r = sample_record();
    r.env.resolved["GITHUB_TOKEN"] = "ghp_TOPSECRETtoken999";
    r.env.scrubbed.push_back("GITHUB_TOKEN");
    const std::string out = format_audit_start(r);
    EXPECT_TRUE(contains(out, "GITHUB_TOKEN"));
    EXPECT_FALSE(contains(out, "ghp_TOPSECRETtoken999"))
        << "audit output leaked a scrubbed secret value";
}

TEST(Audit, StartNeverLeaksAnyResolvedValue) {
    // Blanket check: no resolved value substring should ever surface.
    AuditRecord r = sample_record();
    r.env.resolved["EXTRA"] = "zzz-unique-value-marker-42";
    const std::string out = format_audit_start(r);
    EXPECT_FALSE(contains(out, "zzz-unique-value-marker-42"));
    EXPECT_FALSE(contains(out, "/usr/bin:/bin"));  // PATH's value, not name
}

// format_audit_start prints AuditRecord.bwrap_command VERBATIM. Redaction of
// secret env VALUES happens UPSTREAM at the argv vector layer
// (bwrap::redact_argv_for_audit); the audit module deliberately does NOT re-parse
// or re-redact the flattened string (that heuristic was lossy and was removed).
// This test pins the verbatim contract: the exact bwrap_command string, character
// for character, must appear in the output.
TEST(Audit, StartPrintsBwrapCommandVerbatim) {
    AuditRecord r = sample_record();
    r.bwrap_command =
        "/usr/bin/bwrap --clearenv "
        "--setenv OPENAI_API_KEY <redacted> "
        "--chdir /home/zach/project python train.py --epochs 3";
    const std::string out = format_audit_start(r);
    EXPECT_TRUE(contains(out, r.bwrap_command))
        << "format_audit_start must print bwrap_command verbatim";
}

// A literal token in the (already-redacted) command that superficially looks like
// a "--setenv" must survive verbatim — the audit module must not touch it.
TEST(Audit, StartDoesNotReRedactBwrapCommand) {
    AuditRecord r = sample_record();
    // The command region legitimately contains a "--setenv FOO barvalue"; upstream
    // left it verbatim, and audit must not strip barvalue.
    r.bwrap_command =
        "/usr/bin/bwrap --chdir /work mytool --setenv FOO barvalue";
    const std::string out = format_audit_start(r);
    EXPECT_TRUE(contains(out, "--setenv FOO barvalue"))
        << "audit must not re-redact the flattened bwrap command";
    EXPECT_FALSE(contains(out, "<redacted>"))
        << "audit must not inject redaction markers of its own";
}

// SECURITY: given a bwrap_command PRODUCED BY redact_argv_for_audit (i.e. already
// has its --setenv VALUES replaced by <redacted>), format_audit_start must not
// leak any secret value. The env NAME lists are printed, but no secret VALUE from
// the resolved env may appear anywhere in the output.
TEST(Audit, StartLeaksNoSecretFromRedactedBwrapCommand) {
    AuditRecord r = sample_record();
    // Exactly the shape redact_argv_for_audit emits: NAMES shown, VALUES redacted.
    r.bwrap_command =
        "/usr/bin/bwrap --clearenv "
        "--setenv OPENAI_API_KEY <redacted> "
        "--setenv MY_SET_VAR <redacted> "
        "--setenv APP_PASSPHRASE <redacted> "
        "--chdir /home/zach/project python train.py --epochs 3";
    const std::string out = format_audit_start(r);
    // No secret VALUE (from sample_record's resolved env) survives.
    EXPECT_FALSE(contains(out, "sk-SECRETVALUE123")) << "leaked OPENAI_API_KEY value";
    EXPECT_FALSE(contains(out, "supersecretset")) << "leaked MY_SET_VAR value";
    // NAMES are still shown (from both the redacted command and the env lists).
    EXPECT_TRUE(contains(out, "OPENAI_API_KEY"));
    EXPECT_TRUE(contains(out, "MY_SET_VAR"));
    EXPECT_TRUE(contains(out, "<redacted>"));
}

// ---------------------------------------------------------------------------
// format_audit_start — edge cases
// ---------------------------------------------------------------------------

TEST(Audit, StartHandlesEmptyMountsAndEnv) {
    AuditRecord r;  // all defaults: empty command, empty lists, Full net, Disabled font
    const std::string out = format_audit_start(r);
    EXPECT_FALSE(out.empty());
    EXPECT_TRUE(contains(out, "Raincoat started"));
}

TEST(Audit, StartHandlesNoScrubbedVars) {
    AuditRecord r = sample_record();
    r.env.scrubbed.clear();
    const std::string out = format_audit_start(r);
    EXPECT_FALSE(out.empty());
    EXPECT_TRUE(contains(out, "Raincoat started"));
}

TEST(Audit, StartStrictWithNetOff) {
    AuditRecord r = sample_record();
    r.strict = true;
    r.net = NetMode::Off;
    const std::string out = format_audit_start(r);
    EXPECT_TRUE(contains(out, "strict"));
    EXPECT_TRUE(contains(out, "off"));
}

// ---------------------------------------------------------------------------
// format_audit_end
// ---------------------------------------------------------------------------

TEST(Audit, EndIsNonEmpty) {
    EXPECT_FALSE(format_audit_end(0).empty());
}

TEST(Audit, EndShowsZeroExitCode) {
    EXPECT_TRUE(contains(format_audit_end(0), "0"));
}

TEST(Audit, EndShowsNonZeroExitCode) {
    EXPECT_TRUE(contains(format_audit_end(42), "42"));
}

TEST(Audit, EndShowsSignalDeathExitCode) {
    // 128 + signal convention (e.g. SIGKILL -> 137).
    EXPECT_TRUE(contains(format_audit_end(137), "137"));
}

TEST(Audit, EndMentionsExit) {
    const std::string out = format_audit_end(7);
    // Human-friendly line should reference the exit / finish, per spec.
    EXPECT_TRUE(contains(out, "exit") || contains(out, "Exit"));
}

// ---------------------------------------------------------------------------
// write_audit — filesystem side effects
// ---------------------------------------------------------------------------

class AuditWrite : public ::testing::Test {
   protected:
    fs::path base_;

    void SetUp() override {
        static std::atomic<int> counter{0};
        base_ = fs::temp_directory_path() /
                ("rc-audit-test-" + std::to_string(::getpid()) + "-" +
                 std::to_string(counter.fetch_add(1)));
        fs::remove_all(base_);
    }

    void TearDown() override {
        std::error_code ec;
        fs::remove_all(base_, ec);
    }
};

TEST_F(AuditWrite, CreatesFileAndReturnsTrue) {
    const fs::path path = base_ / "audit.log";
    std::string err = "sentinel";
    const bool ok = write_audit(path.string(), "hello audit\n", err);
    EXPECT_TRUE(ok);
    EXPECT_TRUE(err.empty()) << "err should be cleared on success: " << err;
    ASSERT_TRUE(fs::exists(path));
    EXPECT_EQ(read_file(path), "hello audit\n");
}

TEST_F(AuditWrite, MakesParentDirectoriesRecursively) {
    // Parent chain does not exist yet -> write_audit must mkdir -p.
    const fs::path path = base_ / "deep" / "nested" / "path" / "audit.log";
    ASSERT_FALSE(fs::exists(base_ / "deep"));
    std::string err;
    const bool ok = write_audit(path.string(), "content\n", err);
    EXPECT_TRUE(ok) << "err=" << err;
    EXPECT_TRUE(fs::exists(path));
    EXPECT_EQ(read_file(path), "content\n");
}

TEST_F(AuditWrite, AppendsRatherThanTruncates) {
    const fs::path path = base_ / "audit.log";
    std::string err;
    ASSERT_TRUE(write_audit(path.string(), "first line\n", err));
    ASSERT_TRUE(write_audit(path.string(), "second line\n", err));
    EXPECT_EQ(read_file(path), "first line\nsecond line\n");
}

TEST_F(AuditWrite, AppendPreservesStartThenEndBlocks) {
    const fs::path path = base_ / "audit.log";
    std::string err;
    const std::string start = format_audit_start(sample_record());
    const std::string end = format_audit_end(0);
    ASSERT_TRUE(write_audit(path.string(), start, err));
    ASSERT_TRUE(write_audit(path.string(), end, err));
    const std::string body = read_file(path);
    EXPECT_TRUE(contains(body, "Raincoat started"));
    // start block must come before the end block.
    EXPECT_LT(body.find("Raincoat started"), body.size());
}

TEST_F(AuditWrite, WritesEmptyContentAndStillCreatesFile) {
    const fs::path path = base_ / "empty.log";
    std::string err;
    const bool ok = write_audit(path.string(), "", err);
    EXPECT_TRUE(ok) << "err=" << err;
    EXPECT_TRUE(fs::exists(path));
    EXPECT_EQ(read_file(path), "");
}

TEST_F(AuditWrite, FailsGracefullyWhenParentIsAFile) {
    // A regular file sits where a directory would need to be created.
    fs::create_directories(base_);
    const fs::path blocker = base_ / "blocker";
    { std::ofstream(blocker) << "i am a file"; }
    const fs::path path = blocker / "sub" / "audit.log";
    std::string err;
    const bool ok = write_audit(path.string(), "x", err);
    EXPECT_FALSE(ok);
    EXPECT_FALSE(err.empty()) << "failure should report a non-empty err";
}

// ---------------------------------------------------------------------------
// format_audit_start — rich sectioned-config transparency (profile name,
// active policy notes, reserved-but-not-enforced notes).
// ---------------------------------------------------------------------------

TEST(Audit, StartShowsProfileNameWhenSet) {
    AuditRecord r = sample_record();
    r.profile_name = "default-agent-sandbox";
    const std::string out = format_audit_start(r);
    EXPECT_TRUE(contains(out, "Profile:"));
    EXPECT_TRUE(contains(out, "default-agent-sandbox"));
}

TEST(Audit, StartOmitsProfileLineWhenUnset) {
    AuditRecord r = sample_record();  // profile_name defaults to nullopt
    const std::string line = line_with_label(format_audit_start(r), "Profile:");
    EXPECT_TRUE(line.empty()) << "should not print a Profile line without a profile name";
}

TEST(Audit, StartListsReservedNotes) {
    AuditRecord r = sample_record();
    r.reserved_notes = {
        "network mode \"bridge\" is not yet enforced (phase 2)",
        "browser isolation configured — not yet enforced (phase 2)",
    };
    const std::string out = format_audit_start(r);
    EXPECT_TRUE(contains(out, "Reserved (configured, not enforced):"));
    EXPECT_TRUE(contains(out, "network mode \"bridge\""));
    EXPECT_TRUE(contains(out, "browser isolation configured"));
}

TEST(Audit, StartOmitsReservedSectionWhenEmpty) {
    AuditRecord r = sample_record();  // reserved_notes empty
    EXPECT_FALSE(contains(format_audit_start(r), "Reserved (configured, not enforced):"));
}

TEST(Audit, StartListsActivePolicyNotes) {
    AuditRecord r = sample_record();
    r.active_policy_notes = {
        "env deny list active (5 name(s) never passed through)",
        "filesystem deny list active (20 path(s) never mounted)",
    };
    const std::string out = format_audit_start(r);
    EXPECT_TRUE(contains(out, "Active policy:"));
    EXPECT_TRUE(contains(out, "env deny list active"));
    EXPECT_TRUE(contains(out, "filesystem deny list active"));
}

TEST(Audit, StartOmitsActivePolicySectionWhenEmpty) {
    AuditRecord r = sample_record();  // active_policy_notes empty
    EXPECT_FALSE(contains(format_audit_start(r), "Active policy:"));
}

// The new sections must not leak any secret VALUE either (they carry names/counts).
TEST(Audit, StartRichSectionsLeakNoSecretValues) {
    AuditRecord r = sample_record();
    r.profile_name = "p";
    r.active_policy_notes = {"env deny list active (1 name(s) never passed through)"};
    r.reserved_notes = {"dns override configured — not yet enforced (phase 2)"};
    const std::string out = format_audit_start(r);
    EXPECT_FALSE(contains(out, "sk-SECRETVALUE123"));
    EXPECT_FALSE(contains(out, "supersecretset"));
}
