// Comprehensive GoogleTest suite for raincoat::parse_cli (args EXCLUDE argv[0]).
// TDD (red) phase: these are written against the DESIGN.md/SPEC.md contract and are
// EXPECTED TO FAIL against the current stub implementation.
#include <gtest/gtest.h>

#include <string>
#include <vector>

#include "cli.hpp"

using namespace raincoat;

namespace {

CliInvocation parse(const std::vector<std::string>& args) {
    return parse_cli(args);
}

// Exact user-facing error strings from the contract.
const char* kNoCommandErr =
    "Error: no command provided.\n\nUsage:\n  raincoat -- <command> [args...]";
const char* kSetEnvErr = "Error: expected --set-env KEY=VALUE";

// Find a set_env entry by key.
bool hasSetEnv(const Options& o, const std::string& key, const std::string& val) {
    for (const auto& kv : o.set_env)
        if (kv.first == key) return kv.second == val;
    return false;
}
bool hasSetEnvKey(const Options& o, const std::string& key) {
    for (const auto& kv : o.set_env)
        if (kv.first == key) return true;
    return false;
}

}  // namespace

// ---------------------------------------------------------------------------
// Bare alias form: `raincoat -- <cmd>` == `raincoat run -- <cmd>`
// ---------------------------------------------------------------------------

TEST(Cli, BareDashDashSelectsRunAndCapturesCommand) {
    auto inv = parse({"--", "npm", "test"});
    EXPECT_FALSE(inv.has_error()) << inv.error;
    EXPECT_EQ(inv.sub, Subcommand::Run);
    ASSERT_EQ(inv.options.command.size(), 2u);
    EXPECT_EQ(inv.options.command[0], "npm");
    EXPECT_EQ(inv.options.command[1], "test");
}

TEST(Cli, SingleTokenCommandAfterDashDash) {
    auto inv = parse({"--", "ls"});
    EXPECT_FALSE(inv.has_error()) << inv.error;
    EXPECT_EQ(inv.sub, Subcommand::Run);
    ASSERT_EQ(inv.options.command.size(), 1u);
    EXPECT_EQ(inv.options.command[0], "ls");
}

// ---------------------------------------------------------------------------
// Subcommand selection
// ---------------------------------------------------------------------------

TEST(Cli, RunTokenSelectsRun) {
    auto inv = parse({"run", "--", "echo", "hi"});
    EXPECT_FALSE(inv.has_error()) << inv.error;
    EXPECT_EQ(inv.sub, Subcommand::Run);
    ASSERT_EQ(inv.options.command.size(), 2u);
    EXPECT_EQ(inv.options.command[0], "echo");
    EXPECT_EQ(inv.options.command[1], "hi");
}

TEST(Cli, DoctorSubcommand) {
    auto inv = parse({"doctor"});
    EXPECT_EQ(inv.sub, Subcommand::Doctor);
    EXPECT_FALSE(inv.has_error()) << inv.error;
}

TEST(Cli, InitSubcommand) {
    auto inv = parse({"init"});
    EXPECT_EQ(inv.sub, Subcommand::Init);
    EXPECT_FALSE(inv.has_error()) << inv.error;
}

TEST(Cli, InitDefaultsForceFalse) {
    auto inv = parse({"init"});
    EXPECT_EQ(inv.sub, Subcommand::Init);
    EXPECT_FALSE(inv.has_error()) << inv.error;
    EXPECT_FALSE(inv.options.init_force);
}

TEST(Cli, InitForceLongFlagSetsInitForce) {
    auto inv = parse({"init", "--force"});
    EXPECT_EQ(inv.sub, Subcommand::Init);
    EXPECT_FALSE(inv.has_error()) << inv.error;
    EXPECT_TRUE(inv.options.init_force);
}

TEST(Cli, InitForceShortFlagSetsInitForce) {
    auto inv = parse({"init", "-f"});
    EXPECT_EQ(inv.sub, Subcommand::Init);
    EXPECT_FALSE(inv.has_error()) << inv.error;
    EXPECT_TRUE(inv.options.init_force);
}

TEST(Cli, ReportSubcommand) {
    auto inv = parse({"report"});
    EXPECT_EQ(inv.sub, Subcommand::Report);
    EXPECT_FALSE(inv.has_error()) << inv.error;
}

TEST(Cli, DoctorDoesNotRequireCommand) {
    // Management subcommands must NOT emit the "no command provided" error.
    auto inv = parse({"doctor"});
    EXPECT_NE(inv.error, kNoCommandErr);
    EXPECT_FALSE(inv.has_error());
}

TEST(Cli, UnknownFirstTokenDefaultsToRun) {
    // A leading option (not a subcommand keyword) => default Run.
    auto inv = parse({"--strict", "--", "x"});
    EXPECT_EQ(inv.sub, Subcommand::Run);
    EXPECT_FALSE(inv.has_error()) << inv.error;
    EXPECT_TRUE(inv.options.strict);
    ASSERT_EQ(inv.options.command.size(), 1u);
    EXPECT_EQ(inv.options.command[0], "x");
}

// ---------------------------------------------------------------------------
// Global options BEFORE the subcommand keyword (grammar extension)
// ---------------------------------------------------------------------------

// `raincoat --profile X init` selects Init and applies the preceding --profile.
TEST(Cli, GlobalProfileBeforeInitSelectsInitWithProfile) {
    auto inv = parse({"--profile", "/p/.raincoat.toml", "init"});
    EXPECT_FALSE(inv.has_error()) << inv.error;
    EXPECT_EQ(inv.sub, Subcommand::Init);
    ASSERT_TRUE(inv.options.profile_path.has_value());
    EXPECT_EQ(*inv.options.profile_path, "/p/.raincoat.toml");
}

// The value of a value-flag must NOT be mistaken for a subcommand keyword.
TEST(Cli, ProfileValueEqualToKeywordIsNotASubcommand) {
    // `--profile init` consumes "init" as the profile PATH; no subcommand keyword
    // remains, so this defaults to Run (and errors: no command).
    auto inv = parse({"--profile", "init", "--", "x"});
    EXPECT_FALSE(inv.has_error()) << inv.error;
    EXPECT_EQ(inv.sub, Subcommand::Run);
    ASSERT_TRUE(inv.options.profile_path.has_value());
    EXPECT_EQ(*inv.options.profile_path, "init");
}

// `raincoat --strict doctor` selects Doctor even though --strict precedes it.
TEST(Cli, GlobalStrictBeforeDoctorSelectsDoctor) {
    auto inv = parse({"--strict", "doctor"});
    EXPECT_FALSE(inv.has_error()) << inv.error;
    EXPECT_EQ(inv.sub, Subcommand::Doctor);
    EXPECT_TRUE(inv.options.strict);
}

// AMBIGUITY RESOLUTION: `-- init` RUNS `init` as a command (everything after the
// first -- is the verbatim command); it does NOT select the init subcommand.
TEST(Cli, DashDashInitRunsInitAsCommandNotSubcommand) {
    auto inv = parse({"--", "init"});
    EXPECT_FALSE(inv.has_error()) << inv.error;
    EXPECT_EQ(inv.sub, Subcommand::Run);
    ASSERT_EQ(inv.options.command.size(), 1u);
    EXPECT_EQ(inv.options.command[0], "init");
}

// A global option before `report`, plus its positional audit path, all apply.
TEST(Cli, GlobalOptionsBeforeReportWithPositionalPath) {
    auto inv = parse({"--profile", "p.toml", "report", "/var/log/a.log"});
    EXPECT_FALSE(inv.has_error()) << inv.error;
    EXPECT_EQ(inv.sub, Subcommand::Report);
    ASSERT_TRUE(inv.options.profile_path.has_value());
    EXPECT_EQ(*inv.options.profile_path, "p.toml");
    ASSERT_EQ(inv.options.command.size(), 1u);
    EXPECT_EQ(inv.options.command[0], "/var/log/a.log");
}

// `raincoat init --force` (subcommand first, option after) is unchanged.
TEST(Cli, InitFirstThenForceStillWorks) {
    auto inv = parse({"init", "--force"});
    EXPECT_EQ(inv.sub, Subcommand::Init);
    EXPECT_FALSE(inv.has_error()) << inv.error;
    EXPECT_TRUE(inv.options.init_force);
}

// ---------------------------------------------------------------------------
// --audit-format
// ---------------------------------------------------------------------------

TEST(Cli, AuditFormatJson) {
    auto inv = parse({"run", "--audit-format", "json", "--", "x"});
    EXPECT_FALSE(inv.has_error()) << inv.error;
    ASSERT_TRUE(inv.options.audit_format.has_value());
    EXPECT_EQ(*inv.options.audit_format, AuditFormat::Json);
}

TEST(Cli, AuditFormatTextExplicit) {
    auto inv = parse({"run", "--audit-format", "text", "--", "x"});
    EXPECT_FALSE(inv.has_error()) << inv.error;
    ASSERT_TRUE(inv.options.audit_format.has_value());
    EXPECT_EQ(*inv.options.audit_format, AuditFormat::Text);
}

TEST(Cli, AuditFormatDefaultsUnset) {
    auto inv = parse({"run", "--", "x"});
    EXPECT_FALSE(inv.options.audit_format.has_value());
}

TEST(Cli, AuditFormatBeforeSubcommandApplies) {
    auto inv = parse({"--audit-format", "json", "doctor"});
    EXPECT_EQ(inv.sub, Subcommand::Doctor);
    ASSERT_TRUE(inv.options.audit_format.has_value());
    EXPECT_EQ(*inv.options.audit_format, AuditFormat::Json);
}

TEST(Cli, AuditFormatInvalidValueErrors) {
    auto inv = parse({"run", "--audit-format", "yaml", "--", "x"});
    ASSERT_TRUE(inv.has_error());
    EXPECT_NE(inv.error.find("text"), std::string::npos) << inv.error;
    EXPECT_NE(inv.error.find("json"), std::string::npos) << inv.error;
}

// ---------------------------------------------------------------------------
// Help / Version (only before `--`)
// ---------------------------------------------------------------------------

TEST(Cli, LongHelp) {
    EXPECT_EQ(parse({"--help"}).sub, Subcommand::Help);
}
TEST(Cli, ShortHelp) {
    EXPECT_EQ(parse({"-h"}).sub, Subcommand::Help);
}
TEST(Cli, LongVersion) {
    EXPECT_EQ(parse({"--version"}).sub, Subcommand::Version);
}
TEST(Cli, ShortVersion) {
    EXPECT_EQ(parse({"-V"}).sub, Subcommand::Version);
}

TEST(Cli, HelpUnderRunSubcommand) {
    auto inv = parse({"run", "--help"});
    EXPECT_EQ(inv.sub, Subcommand::Help);
}

TEST(Cli, HelpAfterDashDashIsVerbatimNotHelp) {
    auto inv = parse({"--", "--help"});
    EXPECT_EQ(inv.sub, Subcommand::Run);
    EXPECT_FALSE(inv.has_error()) << inv.error;
    ASSERT_EQ(inv.options.command.size(), 1u);
    EXPECT_EQ(inv.options.command[0], "--help");
}

TEST(Cli, VersionAfterDashDashIsVerbatimNotVersion) {
    auto inv = parse({"--", "tool", "--version"});
    EXPECT_EQ(inv.sub, Subcommand::Run);
    ASSERT_EQ(inv.options.command.size(), 2u);
    EXPECT_EQ(inv.options.command[0], "tool");
    EXPECT_EQ(inv.options.command[1], "--version");
}

// ---------------------------------------------------------------------------
// strict + net
// ---------------------------------------------------------------------------

TEST(Cli, StrictAndNetOff) {
    auto inv = parse({"run", "--strict", "--net", "off", "--", "x"});
    EXPECT_FALSE(inv.has_error()) << inv.error;
    EXPECT_TRUE(inv.options.strict);
    EXPECT_TRUE(inv.options.strict_set);
    ASSERT_TRUE(inv.options.net.has_value());
    EXPECT_EQ(*inv.options.net, NetMode::Off);
    ASSERT_EQ(inv.options.command.size(), 1u);
    EXPECT_EQ(inv.options.command[0], "x");
}

TEST(Cli, NetFull) {
    auto inv = parse({"run", "--net", "full", "--", "x"});
    EXPECT_FALSE(inv.has_error()) << inv.error;
    ASSERT_TRUE(inv.options.net.has_value());
    EXPECT_EQ(*inv.options.net, NetMode::Full);
}

TEST(Cli, StrictSetFlagRecorded) {
    auto inv = parse({"run", "--strict", "--", "x"});
    EXPECT_TRUE(inv.options.strict);
    EXPECT_TRUE(inv.options.strict_set);
}

TEST(Cli, NetNotSetWhenAbsent) {
    auto inv = parse({"run", "--", "x"});
    EXPECT_FALSE(inv.has_error()) << inv.error;
    EXPECT_FALSE(inv.options.net.has_value());
}

TEST(Cli, BadNetValueErrorNamesFullAndOff) {
    auto inv = parse({"run", "--net", "bogus", "--", "x"});
    ASSERT_TRUE(inv.has_error());
    EXPECT_NE(inv.error.find("full"), std::string::npos) << inv.error;
    EXPECT_NE(inv.error.find("off"), std::string::npos) << inv.error;
}

TEST(Cli, NetAllowlistNotAcceptedInMvp) {
    // MVP only accepts full|off from the CLI; allowlist/ask must be rejected.
    auto inv = parse({"run", "--net", "allowlist", "--", "x"});
    ASSERT_TRUE(inv.has_error());
    EXPECT_NE(inv.error.find("full"), std::string::npos) << inv.error;
    EXPECT_NE(inv.error.find("off"), std::string::npos) << inv.error;
}

// ---------------------------------------------------------------------------
// Repeatable flags accumulate
// ---------------------------------------------------------------------------

TEST(Cli, AllowReadAccumulates) {
    auto inv = parse({"run", "--allow-read", "a", "--allow-read", "b", "--", "x"});
    EXPECT_FALSE(inv.has_error()) << inv.error;
    ASSERT_EQ(inv.options.allow_read.size(), 2u);
    EXPECT_EQ(inv.options.allow_read[0], "a");
    EXPECT_EQ(inv.options.allow_read[1], "b");
}

TEST(Cli, AllowWriteAccumulates) {
    auto inv = parse({"run", "--allow-write", "o1", "--allow-write", "o2", "--", "x"});
    EXPECT_FALSE(inv.has_error()) << inv.error;
    ASSERT_EQ(inv.options.allow_write.size(), 2u);
    EXPECT_EQ(inv.options.allow_write[0], "o1");
    EXPECT_EQ(inv.options.allow_write[1], "o2");
}

TEST(Cli, AllowEnvAccumulates) {
    auto inv = parse({"run", "--allow-env", "FOO", "--allow-env", "BAR", "--", "x"});
    EXPECT_FALSE(inv.has_error()) << inv.error;
    ASSERT_EQ(inv.options.allow_env.size(), 2u);
    EXPECT_EQ(inv.options.allow_env[0], "FOO");
    EXPECT_EQ(inv.options.allow_env[1], "BAR");
}

TEST(Cli, MixedRepeatableFlagsKeepOrder) {
    auto inv = parse({"run",
                      "--allow-read", "r1",
                      "--allow-write", "w1",
                      "--allow-read", "r2",
                      "--allow-env", "E1",
                      "--", "x"});
    EXPECT_FALSE(inv.has_error()) << inv.error;
    ASSERT_EQ(inv.options.allow_read.size(), 2u);
    EXPECT_EQ(inv.options.allow_read[0], "r1");
    EXPECT_EQ(inv.options.allow_read[1], "r2");
    ASSERT_EQ(inv.options.allow_write.size(), 1u);
    EXPECT_EQ(inv.options.allow_write[0], "w1");
    ASSERT_EQ(inv.options.allow_env.size(), 1u);
    EXPECT_EQ(inv.options.allow_env[0], "E1");
}

// ---------------------------------------------------------------------------
// --set-env parsing
// ---------------------------------------------------------------------------

TEST(Cli, SetEnvBasic) {
    auto inv = parse({"run", "--set-env", "KEY=VALUE", "--", "x"});
    EXPECT_FALSE(inv.has_error()) << inv.error;
    ASSERT_EQ(inv.options.set_env.size(), 1u);
    EXPECT_TRUE(hasSetEnv(inv.options, "KEY", "VALUE"));
}

TEST(Cli, SetEnvAccumulates) {
    auto inv = parse({"run", "--set-env", "A=1", "--set-env", "B=2", "--", "x"});
    EXPECT_FALSE(inv.has_error()) << inv.error;
    ASSERT_EQ(inv.options.set_env.size(), 2u);
    EXPECT_TRUE(hasSetEnv(inv.options, "A", "1"));
    EXPECT_TRUE(hasSetEnv(inv.options, "B", "2"));
}

TEST(Cli, SetEnvEmptyValueIsValid) {
    // KEY= (trailing '=' present) => valid with an empty value.
    auto inv = parse({"run", "--set-env", "KEY=", "--", "x"});
    EXPECT_FALSE(inv.has_error()) << inv.error;
    ASSERT_TRUE(hasSetEnvKey(inv.options, "KEY"));
    EXPECT_TRUE(hasSetEnv(inv.options, "KEY", ""));
}

TEST(Cli, SetEnvValueMayContainEquals) {
    // Split on the FIRST '='; the value keeps the remaining '='.
    auto inv = parse({"run", "--set-env", "KEY=a=b=c", "--", "x"});
    EXPECT_FALSE(inv.has_error()) << inv.error;
    ASSERT_TRUE(hasSetEnvKey(inv.options, "KEY"));
    EXPECT_TRUE(hasSetEnv(inv.options, "KEY", "a=b=c"));
}

TEST(Cli, SetEnvEmptyKeyIsMalformed) {
    // "=VALUE" splits into an EMPTY key. An environment variable with an empty
    // name is invalid: downstream env_guard would store resolved[""]="VALUE" and
    // bwrap would emit `--setenv "" VALUE`, which setenv() rejects (EINVAL). The
    // parser accepts it silently today, so this exposes a missing-validation bug.
    auto inv = parse({"run", "--set-env", "=VALUE", "--", "x"});
    ASSERT_TRUE(inv.has_error())
        << "empty env-var name '=VALUE' was accepted; produced key='"
        << (inv.options.set_env.empty() ? std::string("<none>")
                                        : inv.options.set_env[0].first)
        << "'";
    EXPECT_EQ(inv.error, kSetEnvErr);
}

TEST(Cli, SetEnvNoEqualsIsMalformed) {
    auto inv = parse({"run", "--set-env", "KEY", "--", "x"});
    ASSERT_TRUE(inv.has_error());
    EXPECT_EQ(inv.error, kSetEnvErr);
}

TEST(Cli, SetEnvBareWordMalformedExactMessage) {
    auto inv = parse({"run", "--set-env", "JUSTAKEY", "--", "x"});
    EXPECT_EQ(inv.error, kSetEnvErr);
}

// ---------------------------------------------------------------------------
// --profile / --workdir / --audit-log / --keep-temp
// ---------------------------------------------------------------------------

TEST(Cli, ProfilePathRecorded) {
    auto inv = parse({"run", "--profile", "/path/to/.raincoat.toml", "--", "x"});
    EXPECT_FALSE(inv.has_error()) << inv.error;
    ASSERT_TRUE(inv.options.profile_path.has_value());
    EXPECT_EQ(*inv.options.profile_path, "/path/to/.raincoat.toml");
}

TEST(Cli, WorkdirRecorded) {
    auto inv = parse({"run", "--workdir", "/w", "--", "x"});
    EXPECT_FALSE(inv.has_error()) << inv.error;
    ASSERT_TRUE(inv.options.workdir.has_value());
    EXPECT_EQ(*inv.options.workdir, "/w");
}

TEST(Cli, AuditLogRecorded) {
    auto inv = parse({"run", "--audit-log", "/tmp/a.log", "--", "x"});
    EXPECT_FALSE(inv.has_error()) << inv.error;
    ASSERT_TRUE(inv.options.audit_log.has_value());
    EXPECT_EQ(*inv.options.audit_log, "/tmp/a.log");
}

TEST(Cli, KeepTempFlag) {
    auto inv = parse({"run", "--keep-temp", "--", "x"});
    EXPECT_FALSE(inv.has_error()) << inv.error;
    EXPECT_TRUE(inv.options.keep_temp);
    EXPECT_TRUE(inv.options.keep_temp_set);
}

TEST(Cli, KeepTempDefaultsFalseWhenAbsent) {
    auto inv = parse({"run", "--", "x"});
    EXPECT_FALSE(inv.options.keep_temp);
    EXPECT_FALSE(inv.options.keep_temp_set);
}

// ---------------------------------------------------------------------------
// Verbatim capture after `--`
// ---------------------------------------------------------------------------

TEST(Cli, EverythingAfterDashDashIsVerbatim) {
    auto inv = parse({"run", "--strict", "--", "npm", "--net", "off", "--allow-read", "x"});
    EXPECT_FALSE(inv.has_error()) << inv.error;
    EXPECT_TRUE(inv.options.strict);
    // The --net/--allow-read AFTER -- must NOT be interpreted as raincoat options.
    EXPECT_FALSE(inv.options.net.has_value());
    EXPECT_TRUE(inv.options.allow_read.empty());
    ASSERT_EQ(inv.options.command.size(), 5u);
    EXPECT_EQ(inv.options.command[0], "npm");
    EXPECT_EQ(inv.options.command[1], "--net");
    EXPECT_EQ(inv.options.command[2], "off");
    EXPECT_EQ(inv.options.command[3], "--allow-read");
    EXPECT_EQ(inv.options.command[4], "x");
}

TEST(Cli, ValueFlagDoesNotSwallowDashDashTerminator) {
    // A value-taking flag with no value before `--` must NOT consume the `--`
    // separator: the contract says "everything after the first -- is the target
    // command (verbatim)". Here the user clearly provided a command after `--`.
    auto inv = parse({"run", "--allow-read", "--", "npm", "test"});
    // The command after `--` must be captured verbatim, and this must NOT collapse
    // into the "no command provided" error.
    EXPECT_NE(inv.error, kNoCommandErr) << "the -- terminator was swallowed as a flag value";
    EXPECT_FALSE(inv.has_error()) << inv.error;
    ASSERT_EQ(inv.options.command.size(), 2u);
    EXPECT_EQ(inv.options.command[0], "npm");
    EXPECT_EQ(inv.options.command[1], "test");
    // And the `--` must not have leaked in as an allowed read path.
    EXPECT_TRUE(inv.options.allow_read.empty());
}

TEST(Cli, SecondDashDashIsPartOfCommand) {
    auto inv = parse({"--", "a", "--", "b"});
    EXPECT_FALSE(inv.has_error()) << inv.error;
    ASSERT_EQ(inv.options.command.size(), 3u);
    EXPECT_EQ(inv.options.command[0], "a");
    EXPECT_EQ(inv.options.command[1], "--");
    EXPECT_EQ(inv.options.command[2], "b");
}

TEST(Cli, RunKeywordAfterDashDashIsVerbatim) {
    auto inv = parse({"--", "run"});
    EXPECT_EQ(inv.sub, Subcommand::Run);
    ASSERT_EQ(inv.options.command.size(), 1u);
    EXPECT_EQ(inv.options.command[0], "run");
}

// ---------------------------------------------------------------------------
// Empty command error
// ---------------------------------------------------------------------------

TEST(Cli, NoArgsIsNoCommandError) {
    auto inv = parse({});
    ASSERT_TRUE(inv.has_error());
    EXPECT_EQ(inv.error, kNoCommandErr);
}

TEST(Cli, RunWithNoCommandError) {
    auto inv = parse({"run"});
    ASSERT_TRUE(inv.has_error());
    EXPECT_EQ(inv.error, kNoCommandErr);
}

TEST(Cli, RunWithOptionsButNoCommandError) {
    auto inv = parse({"run", "--strict"});
    ASSERT_TRUE(inv.has_error());
    EXPECT_EQ(inv.error, kNoCommandErr);
}

TEST(Cli, DashDashWithNothingAfterIsNoCommandError) {
    auto inv = parse({"run", "--strict", "--"});
    ASSERT_TRUE(inv.has_error());
    EXPECT_EQ(inv.error, kNoCommandErr);
}

TEST(Cli, BareDashDashOnlyIsNoCommandError) {
    auto inv = parse({"--"});
    ASSERT_TRUE(inv.has_error());
    EXPECT_EQ(inv.error, kNoCommandErr);
}

// ---------------------------------------------------------------------------
// Combined / integration-style parse
// ---------------------------------------------------------------------------

TEST(Cli, FullKitchenSink) {
    auto inv = parse({"run",
                      "--strict",
                      "--net", "off",
                      "--profile", "p.toml",
                      "--allow-read", "./src",
                      "--allow-write", "./out",
                      "--allow-env", "OPENAI_API_KEY",
                      "--set-env", "TZ=UTC",
                      "--set-env", "FOO=bar=baz",
                      "--workdir", "/work",
                      "--audit-log", "audit.log",
                      "--keep-temp",
                      "--", "python", "agent.py", "--flag"});
    EXPECT_FALSE(inv.has_error()) << inv.error;
    EXPECT_EQ(inv.sub, Subcommand::Run);
    EXPECT_TRUE(inv.options.strict);
    ASSERT_TRUE(inv.options.net.has_value());
    EXPECT_EQ(*inv.options.net, NetMode::Off);
    ASSERT_TRUE(inv.options.profile_path.has_value());
    EXPECT_EQ(*inv.options.profile_path, "p.toml");
    ASSERT_EQ(inv.options.allow_read.size(), 1u);
    EXPECT_EQ(inv.options.allow_read[0], "./src");
    ASSERT_EQ(inv.options.allow_write.size(), 1u);
    EXPECT_EQ(inv.options.allow_write[0], "./out");
    ASSERT_EQ(inv.options.allow_env.size(), 1u);
    EXPECT_EQ(inv.options.allow_env[0], "OPENAI_API_KEY");
    EXPECT_TRUE(hasSetEnv(inv.options, "TZ", "UTC"));
    EXPECT_TRUE(hasSetEnv(inv.options, "FOO", "bar=baz"));
    ASSERT_TRUE(inv.options.workdir.has_value());
    EXPECT_EQ(*inv.options.workdir, "/work");
    ASSERT_TRUE(inv.options.audit_log.has_value());
    EXPECT_EQ(*inv.options.audit_log, "audit.log");
    EXPECT_TRUE(inv.options.keep_temp);
    ASSERT_EQ(inv.options.command.size(), 3u);
    EXPECT_EQ(inv.options.command[0], "python");
    EXPECT_EQ(inv.options.command[1], "agent.py");
    EXPECT_EQ(inv.options.command[2], "--flag");
}

// ---------------------------------------------------------------------------
// `--flag=value` equals form + rejection of unknown options (round-1 fix)
// ---------------------------------------------------------------------------

// The equals form must be honored, not silently dropped: `--audit-format=json`
// previously fell through to the default and produced a TEXT log, defeating the
// user's explicit request for JSON.
TEST(Cli, AuditFormatEqualsFormJson) {
    auto inv = parse({"run", "--audit-format=json", "--", "x"});
    EXPECT_FALSE(inv.has_error()) << inv.error;
    ASSERT_TRUE(inv.options.audit_format.has_value());
    EXPECT_EQ(*inv.options.audit_format, AuditFormat::Json);
}

TEST(Cli, AuditFormatEqualsFormTextExplicit) {
    auto inv = parse({"run", "--audit-format=text", "--", "x"});
    EXPECT_FALSE(inv.has_error()) << inv.error;
    ASSERT_TRUE(inv.options.audit_format.has_value());
    EXPECT_EQ(*inv.options.audit_format, AuditFormat::Text);
}

TEST(Cli, AuditFormatEqualsFormInvalidErrors) {
    auto inv = parse({"run", "--audit-format=yaml", "--", "x"});
    ASSERT_TRUE(inv.has_error());
    EXPECT_NE(inv.error.find("text"), std::string::npos) << inv.error;
    EXPECT_NE(inv.error.find("json"), std::string::npos) << inv.error;
}

TEST(Cli, NetEqualsFormOff) {
    auto inv = parse({"run", "--net=off", "--", "x"});
    EXPECT_FALSE(inv.has_error()) << inv.error;
    ASSERT_TRUE(inv.options.net.has_value());
    EXPECT_EQ(*inv.options.net, NetMode::Off);
}

TEST(Cli, NetEqualsFormBadValueErrors) {
    auto inv = parse({"run", "--net=bogus", "--", "x"});
    ASSERT_TRUE(inv.has_error());
    EXPECT_NE(inv.error.find("full"), std::string::npos) << inv.error;
    EXPECT_NE(inv.error.find("off"), std::string::npos) << inv.error;
}

TEST(Cli, ProfileEqualsForm) {
    auto inv = parse({"run", "--profile=/p/.raincoat.toml", "--", "x"});
    EXPECT_FALSE(inv.has_error()) << inv.error;
    ASSERT_TRUE(inv.options.profile_path.has_value());
    EXPECT_EQ(*inv.options.profile_path, "/p/.raincoat.toml");
}

TEST(Cli, SetEnvEqualsFormPreservesInnerEquals) {
    // `--set-env=FOO=a=b` -> split off the flag on the first '=', then the env
    // assignment splits on ITS first '=' => key=FOO, value="a=b".
    auto inv = parse({"run", "--set-env=FOO=a=b", "--", "x"});
    EXPECT_FALSE(inv.has_error()) << inv.error;
    EXPECT_TRUE(hasSetEnv(inv.options, "FOO", "a=b"));
}

TEST(Cli, AllowReadEqualsForm) {
    auto inv = parse({"run", "--allow-read=./src", "--", "x"});
    EXPECT_FALSE(inv.has_error()) << inv.error;
    ASSERT_EQ(inv.options.allow_read.size(), 1u);
    EXPECT_EQ(inv.options.allow_read[0], "./src");
}

// Unknown `--` options before `--` are a HARD ERROR, never silently ignored — a
// mistyped security-relevant flag must fail loudly rather than fall back to a default.
TEST(Cli, UnknownLongOptionIsRejected) {
    auto inv = parse({"run", "--totally-bogus-flag", "--", "x"});
    ASSERT_TRUE(inv.has_error());
    EXPECT_NE(inv.error.find("--totally-bogus-flag"), std::string::npos) << inv.error;
}

TEST(Cli, NoFontconfigFlagIsRejectedNotSilentlyAccepted) {
    // fontconfig toggling is profile-only; a bogus `--no-fontconfig` CLI flag must
    // be rejected rather than silently accepted (exit 0) as before.
    auto inv = parse({"run", "--no-fontconfig", "--", "x"});
    ASSERT_TRUE(inv.has_error());
    EXPECT_NE(inv.error.find("--no-fontconfig"), std::string::npos) << inv.error;
}

TEST(Cli, MisspelledStrictIsRejected) {
    auto inv = parse({"run", "--stric", "--", "x"});
    ASSERT_TRUE(inv.has_error());
    EXPECT_NE(inv.error.find("--stric"), std::string::npos) << inv.error;
}

TEST(Cli, BooleanFlagWithInlineValueIsRejected) {
    auto inv = parse({"run", "--strict=yes", "--", "x"});
    ASSERT_TRUE(inv.has_error());
    EXPECT_NE(inv.error.find("--strict"), std::string::npos) << inv.error;
}

// The unknown-option rejection must NOT fire after `--`: a bogus-looking flag there
// is the verbatim target command, not a raincoat option.
TEST(Cli, UnknownOptionAfterDashDashIsVerbatimCommand) {
    auto inv = parse({"run", "--", "tool", "--totally-bogus-flag"});
    EXPECT_FALSE(inv.has_error()) << inv.error;
    ASSERT_EQ(inv.options.command.size(), 2u);
    EXPECT_EQ(inv.options.command[0], "tool");
    EXPECT_EQ(inv.options.command[1], "--totally-bogus-flag");
}
