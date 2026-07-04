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

// ---------------------------------------------------------------------------
// Egress bridge audit lines (phase 2)
// ---------------------------------------------------------------------------

// Build an audit record carrying two active egress bridges with the upstream hidden.
static AuditRecord egress_record() {
    AuditRecord r = sample_record();
    EgressBridgeAudit a;
    a.name = "openai";
    a.child_endpoint = "http://127.0.0.1:18080";
    a.injected_env = "OPENAI_BASE_URL";
    a.upstream_hidden = true;
    a.upstream = "";  // hidden => never populated
    r.egress_bridges.push_back(a);

    EgressBridgeAudit b;
    b.name = "anthropic";
    b.child_endpoint = "http://127.0.0.1:18081";
    b.injected_env = "ANTHROPIC_BASE_URL";
    b.upstream_hidden = true;
    r.egress_bridges.push_back(b);
    return r;
}

TEST(AuditEgress, EmitsPerBridgeLines) {
    const std::string out = format_audit_start(egress_record());
    EXPECT_TRUE(contains(out, "Egress bridge enabled: openai"));
    EXPECT_TRUE(contains(out, "Child-visible endpoint: http://127.0.0.1:18080"));
    EXPECT_TRUE(contains(out, "Injected env var: OPENAI_BASE_URL"));
    EXPECT_TRUE(contains(out, "Egress bridge enabled: anthropic"));
    EXPECT_TRUE(contains(out, "Child-visible endpoint: http://127.0.0.1:18081"));
    EXPECT_TRUE(contains(out, "Injected env var: ANTHROPIC_BASE_URL"));
}

TEST(AuditEgress, HidesUpstreamByDefault) {
    const std::string out = format_audit_start(egress_record());
    EXPECT_TRUE(contains(out, "Upstream endpoint: hidden"));
    // The real upstream URL must never be persisted when redacted.
    EXPECT_FALSE(contains(out, "real-upstream.example.com"));
    EXPECT_FALSE(contains(out, "https://api.openai.com"));
}

TEST(AuditEgress, ShowsUpstreamOnlyWhenRedactionDisabled) {
    AuditRecord r = sample_record();
    EgressBridgeAudit a;
    a.name = "openai";
    a.child_endpoint = "http://127.0.0.1:18080";
    a.injected_env = "OPENAI_BASE_URL";
    a.upstream_hidden = false;                       // redaction explicitly disabled
    a.upstream = "https://api.openai.com";           // now recorded
    r.egress_bridges.push_back(a);

    const std::string out = format_audit_start(r);
    EXPECT_TRUE(contains(out, "Upstream endpoint: https://api.openai.com"));
    EXPECT_FALSE(contains(out, "Upstream endpoint: hidden"));
}

TEST(AuditEgress, NoEgressSectionWhenEmpty) {
    const std::string out = format_audit_start(sample_record());
    EXPECT_FALSE(contains(out, "Egress bridge enabled:"));
}

// ---------------------------------------------------------------------------
// format_audit_json — structured JSON audit (same info, never secret VALUES)
// ---------------------------------------------------------------------------

namespace {

// A minimal, dependency-free JSON well-formedness check: balanced braces/brackets
// outside of strings, and balanced double quotes (respecting backslash escapes).
// Sufficient to catch the shapes format_audit_json could plausibly get wrong; the
// integration test additionally validates with a real JSON parser (python).
bool json_wellformed(const std::string& s) {
    int braces = 0, brackets = 0;
    bool in_str = false, esc = false;
    for (char c : s) {
        if (in_str) {
            if (esc) { esc = false; continue; }
            if (c == '\\') { esc = true; continue; }
            if (c == '"') in_str = false;
            continue;
        }
        switch (c) {
            case '"': in_str = true; break;
            case '{': ++braces; break;
            case '}': if (--braces < 0) return false; break;
            case '[': ++brackets; break;
            case ']': if (--brackets < 0) return false; break;
            default: break;
        }
    }
    return braces == 0 && brackets == 0 && !in_str;
}

}  // namespace

TEST(AuditJson, IsWellFormedAndSingleObject) {
    const std::string out = format_audit_json(sample_record(), 0);
    ASSERT_FALSE(out.empty());
    EXPECT_TRUE(json_wellformed(out)) << out;
    // A single object: starts with '{' and (ignoring a trailing newline) ends '}'.
    std::string trimmed = out;
    while (!trimmed.empty() && (trimmed.back() == '\n' || trimmed.back() == '\r'))
        trimmed.pop_back();
    ASSERT_FALSE(trimmed.empty());
    EXPECT_EQ(trimmed.front(), '{');
    EXPECT_EQ(trimmed.back(), '}');
}

TEST(AuditJson, ContainsExpectedKeys) {
    const std::string out = format_audit_json(sample_record(), 7);
    for (const char* key : {"\"command\"", "\"mode\"", "\"network\"", "\"fake_home\"",
                            "\"workdir\"", "\"allowed_read_paths\"",
                            "\"allowed_write_paths\"", "\"env_allowed\"", "\"env_set\"",
                            "\"env_scrubbed\"", "\"timezone\"", "\"locale\"",
                            "\"fontconfig\"", "\"bwrap_command\"", "\"exit_code\""}) {
        EXPECT_TRUE(contains(out, key)) << "missing key " << key << " in:\n" << out;
    }
}

TEST(AuditJson, ExitCodeIsRawNumber) {
    EXPECT_TRUE(contains(format_audit_json(sample_record(), 42), "\"exit_code\":42"));
    EXPECT_TRUE(contains(format_audit_json(sample_record(), 0), "\"exit_code\":0"));
}

TEST(AuditJson, RecordsModeNetworkAndEnvNames) {
    const std::string out = format_audit_json(sample_record(), 0);
    EXPECT_TRUE(contains(out, "\"mode\":\"normal\""));
    EXPECT_TRUE(contains(out, "\"network\":\"full\""));
    // Env NAMES appear (they are safe); values must not (checked below).
    EXPECT_TRUE(contains(out, "OPENAI_API_KEY"));
    EXPECT_TRUE(contains(out, "MY_SET_VAR"));
    EXPECT_TRUE(contains(out, "AWS_SECRET_ACCESS_KEY"));
}

// SECURITY: no secret VALUE from the resolved env may appear in the JSON.
TEST(AuditJson, NeverLeaksSecretValues) {
    AuditRecord r = sample_record();
    r.env.resolved["EXTRA_SECRET"] = "zzz-json-secret-marker-77";
    r.bwrap_command =
        "/usr/bin/bwrap --clearenv --setenv OPENAI_API_KEY <redacted> "
        "--setenv MY_SET_VAR <redacted> --chdir /w python train.py";
    const std::string out = format_audit_json(r, 0);
    EXPECT_FALSE(contains(out, "sk-SECRETVALUE123")) << out;
    EXPECT_FALSE(contains(out, "supersecretset")) << out;
    EXPECT_FALSE(contains(out, "zzz-json-secret-marker-77")) << out;
    EXPECT_FALSE(contains(out, "/usr/bin:/bin")) << "leaked PATH value";
    // Still well-formed with the redacted bwrap command embedded.
    EXPECT_TRUE(json_wellformed(out)) << out;
}

// Strings with JSON metacharacters (quotes/backslashes/newlines) are escaped so the
// object stays well-formed.
TEST(AuditJson, EscapesSpecialCharacters) {
    AuditRecord r = sample_record();
    r.command_line = "echo \"hi\"\tand\\back\nnewline";
    r.warnings = "a \"quoted\" warning\nline2";
    const std::string out = format_audit_json(r, 0);
    EXPECT_TRUE(json_wellformed(out)) << out;
    // The raw (unescaped) quote-run must not appear verbatim; escaped form does.
    EXPECT_TRUE(contains(out, "\\\"hi\\\"")) << out;
    EXPECT_TRUE(contains(out, "\\n")) << out;
    EXPECT_TRUE(contains(out, "\\t")) << out;
}

// Egress upstreams stay hidden by default in the JSON too.
TEST(AuditJson, HidesEgressUpstreamByDefault) {
    const std::string out = format_audit_json(egress_record(), 0);
    EXPECT_TRUE(json_wellformed(out)) << out;
    EXPECT_TRUE(contains(out, "\"upstream_hidden\":true"));
    EXPECT_FALSE(contains(out, "real-upstream.example.com"));
    EXPECT_FALSE(contains(out, "api.openai.com"));
}

// -------------------------------------------------------------------------
// RFC 8259 requires JSON text to be valid UTF-8. A command argument or env var
// NAME on Linux is an arbitrary byte string (filenames are not required to be
// UTF-8), so a run over e.g. a Latin-1 filename feeds non-UTF-8 bytes into the
// record. json_escape passes every byte >= 0x20 through verbatim, so those bytes
// land raw in the "command"/"env_*" fields and the audit is no longer valid JSON:
// a strict parser (`python -m json.tool`, the acceptance criterion) rejects it.
// -------------------------------------------------------------------------

// Strict UTF-8 validator (RFC 3629 well-formed byte sequences). No decoding of
// meaning — only structural validity, which is all JSON requires of its text.
static bool is_valid_utf8(const std::string& s) {
    std::size_t i = 0, n = s.size();
    while (i < n) {
        unsigned char c = static_cast<unsigned char>(s[i]);
        std::size_t extra;
        unsigned char lo = 0x80, hi = 0xBF;
        if (c < 0x80) { ++i; continue; }
        else if (c >= 0xC2 && c <= 0xDF) { extra = 1; }
        else if (c == 0xE0) { extra = 2; lo = 0xA0; }
        else if (c >= 0xE1 && c <= 0xEC) { extra = 2; }
        else if (c == 0xED) { extra = 2; hi = 0x9F; }
        else if (c >= 0xEE && c <= 0xEF) { extra = 2; }
        else if (c == 0xF0) { extra = 3; lo = 0x90; }
        else if (c >= 0xF1 && c <= 0xF3) { extra = 3; }
        else if (c == 0xF4) { extra = 3; hi = 0x8F; }
        else return false;  // 0x80-0xC1, 0xF5-0xFF are never valid lead bytes
        if (i + extra >= n) return false;
        for (std::size_t k = 1; k <= extra; ++k) {
            unsigned char cc = static_cast<unsigned char>(s[i + k]);
            unsigned char lob = (k == 1) ? lo : 0x80;
            unsigned char hib = (k == 1) ? hi : 0xBF;
            if (cc < lob || cc > hib) return false;
        }
        i += extra + 1;
    }
    return true;
}

// DEFECT (currently RED): a non-UTF-8 byte in a command arg yields invalid JSON.
TEST(AuditJson, IsValidUtf8EvenWithNonUtf8CommandBytes) {
    AuditRecord r = sample_record();
    // A filename with a lone 0xFF byte (e.g. Latin-1 "ÿ") — legal on Linux.
    r.command_line = std::string("/bin/cat file-\xFF-name");
    const std::string out = format_audit_json(r, 0);
    EXPECT_TRUE(is_valid_utf8(out))
        << "format_audit_json emitted non-UTF-8 (invalid JSON per RFC 8259); a "
           "strict parser like `python -m json.tool` rejects it. Offending byte "
           "reached the output verbatim through json_escape.";
}

// DEFECT (currently RED): the same hole via a non-UTF-8 env var NAME.
TEST(AuditJson, IsValidUtf8EvenWithNonUtf8EnvName) {
    AuditRecord r = sample_record();
    r.env.scrubbed.push_back(std::string("BAD_\xFF_NAME"));
    const std::string out = format_audit_json(r, 0);
    EXPECT_TRUE(is_valid_utf8(out))
        << "a non-UTF-8 env NAME leaks a raw byte into env_scrubbed, making the "
           "JSON audit invalid UTF-8.";
}
