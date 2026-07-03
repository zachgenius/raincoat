// Raincoat — report module tests.
//
// Focus: summarize_audit(const std::string&) is a PURE function that turns an
// audit-log block into a short, playful-but-professional human summary that
// surfaces:
//   * that the real HOME was hidden,
//   * the COUNT of scrubbed (dropped) environment variables,
//   * the network mode (full/off),
//   * whether the run was strict or normal.
// An optional closing "verdict" line is allowed (e.g. the classic
// "Verdict: this tool did not get to see you naked.").
//
// These tests are written RED-first against the stub (which returns ""), so they
// are expected to FAIL until the module is implemented.
//
// Assumed audit-text format (mirrors docs/SPEC.md "Audit log" — human-friendly
// lines) that summarize_audit is expected to parse. The audit module emits these
// labels; report reads them back:
//
//   Raincoat started
//   Command: <cmd>
//   Mode: <strict|normal>
//   Network: <full|off>
//   Fake HOME: <path>
//   Workdir: <path>
//   Allowed read paths: <a, b | (none)>
//   Allowed write paths: <a, b | (none)>
//   Env allowed: <NAME, NAME | (none)>
//   Env set: <NAME, NAME | (none)>
//   Env scrubbed: <NAME, NAME | (none)>
//   Timezone: <tz>
//   Locale: <locale>
//   Fontconfig: <enabled|best-effort|unavailable|disabled>
//   Bubblewrap command: <...>
//   Process exit code: <n>
//
// The scrubbed count is derived from the comma-separated names on the
// "Env scrubbed:" line; the sentinel "(none)" means zero.
#include <algorithm>
#include <cctype>
#include <string>

#include <gtest/gtest.h>

#include "report.hpp"

namespace {

using raincoat::summarize_audit;

std::string lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

// Case-insensitive substring test.
bool icontains(const std::string& hay, const std::string& needle) {
    return lower(hay).find(lower(needle)) != std::string::npos;
}

// Case-sensitive substring test.
bool contains(const std::string& hay, const std::string& needle) {
    return hay.find(needle) != std::string::npos;
}

// A strict run: network off, 6 scrubbed env vars.
const std::string kStrictAudit = R"(Raincoat started
Command: python agent.py --do-stuff
Mode: strict
Network: off
Fake HOME: /tmp/raincoat.ab12cd/home/user
Workdir: /home/zach/project
Allowed read paths: /home/zach/project/src
Allowed write paths: /home/zach/project/out
Env allowed: PATH, TERM
Env set: HOME, LANG, LC_ALL, TMPDIR, TZ, USER
Env scrubbed: ANTHROPIC_API_KEY, AWS_SECRET_ACCESS_KEY, GITHUB_TOKEN, KUBECONFIG, OPENAI_API_KEY, SSH_AUTH_SOCK
Timezone: UTC
Locale: en_US.UTF-8
Fontconfig: enabled
Bubblewrap command: bwrap --die-with-parent --unshare-net --ro-bind /usr /usr ...
Process exit code: 0
)";
const int kStrictScrubbedCount = 6;

// A normal run: network full, 2 scrubbed env vars.
const std::string kNormalAudit = R"(Raincoat started
Command: node index.js
Mode: normal
Network: full
Fake HOME: /tmp/raincoat.zz99/home/user
Workdir: /home/zach/proj
Allowed read paths: (none)
Allowed write paths: /home/zach/proj
Env allowed: PATH, TERM
Env set: HOME, LANG, LC_ALL, TMPDIR, TZ, USER
Env scrubbed: DOCKER_HOST, GITHUB_TOKEN
Timezone: UTC
Locale: en_US.UTF-8
Fontconfig: best-effort
Bubblewrap command: bwrap --die-with-parent --ro-bind /usr /usr ...
Process exit code: 0
)";
const int kNormalScrubbedCount = 2;

}  // namespace

// --- scrubbed-count accuracy -------------------------------------------------

TEST(Report, CountsScrubbedVarsFromSampleBlock) {
    const std::string out = summarize_audit(kStrictAudit);
    EXPECT_TRUE(icontains(out, "scrub")) << "summary should mention scrubbing; got:\n" << out;
    EXPECT_TRUE(contains(out, std::to_string(kStrictScrubbedCount)))
        << "expected scrubbed count " << kStrictScrubbedCount << " in summary:\n" << out;
}

TEST(Report, CountsScrubbedVarsDifferentBlock) {
    const std::string out = summarize_audit(kNormalAudit);
    EXPECT_TRUE(contains(out, std::to_string(kNormalScrubbedCount)))
        << "expected scrubbed count " << kNormalScrubbedCount << " in summary:\n" << out;
}

TEST(Report, CountsSingleScrubbedVar) {
    // A lone scrubbed var (no comma) must count as 1, not 0 and not 2.
    const std::string audit = R"(Raincoat started
Mode: normal
Network: full
Fake HOME: /tmp/raincoat.x/home/user
Env scrubbed: GITHUB_TOKEN
Process exit code: 0
)";
    const std::string out = summarize_audit(audit);
    EXPECT_TRUE(contains(out, "1")) << "single scrubbed var should count as 1:\n" << out;
}

TEST(Report, CountsZeroScrubbedVarsWithNoneSentinel) {
    const std::string audit = R"(Raincoat started
Mode: normal
Network: full
Fake HOME: /tmp/raincoat.x/home/user
Env scrubbed: (none)
Process exit code: 0
)";
    const std::string out = summarize_audit(audit);
    EXPECT_TRUE(contains(out, "0")) << "the (none) sentinel should be reported as 0:\n" << out;
}

TEST(Report, ScrubbedCountToleratesIrregularWhitespace) {
    // Extra/uneven spacing around the comma-separated names must not skew the count.
    const std::string audit = R"(Raincoat started
Mode: strict
Network: off
Fake HOME: /tmp/raincoat.x/home/user
Env scrubbed:   AWS_SECRET_ACCESS_KEY ,  GITHUB_TOKEN ,NPM_TOKEN
Process exit code: 0
)";
    const std::string out = summarize_audit(audit);
    EXPECT_TRUE(contains(out, "3")) << "expected 3 scrubbed vars despite spacing:\n" << out;
}

TEST(Report, ScrubbedCountIgnoresAllowedAndSetLines) {
    // allowed=7, set=2, scrubbed=3 — the count must come from the scrubbed line only.
    const std::string audit = R"(Raincoat started
Mode: strict
Network: off
Fake HOME: /tmp/raincoat.x/home/user
Env allowed: PATH, TERM, A, B, C, D, E
Env set: TZ, LANG
Env scrubbed: GITHUB_TOKEN, AWS_SECRET_ACCESS_KEY, NPM_TOKEN
Process exit code: 0
)";
    const std::string out = summarize_audit(audit);
    EXPECT_TRUE(contains(out, "3")) << "scrubbed count should be 3 (not allowed/set counts):\n" << out;
}

// --- network mode ------------------------------------------------------------

TEST(Report, IncludesNetworkModeOff) {
    const std::string out = summarize_audit(kStrictAudit);
    EXPECT_TRUE(icontains(out, "network")) << "summary should mention networking:\n" << out;
    EXPECT_TRUE(icontains(out, "off")) << "summary should surface network mode 'off':\n" << out;
}

TEST(Report, IncludesNetworkModeFull) {
    const std::string out = summarize_audit(kNormalAudit);
    EXPECT_TRUE(icontains(out, "network")) << "summary should mention networking:\n" << out;
    EXPECT_TRUE(icontains(out, "full")) << "summary should surface network mode 'full':\n" << out;
}

// --- hidden HOME -------------------------------------------------------------

TEST(Report, MentionsHomeWasHidden) {
    const std::string out = summarize_audit(kStrictAudit);
    EXPECT_TRUE(icontains(out, "home")) << "summary should mention HOME:\n" << out;
    EXPECT_TRUE(icontains(out, "hid") || icontains(out, "hidden") || icontains(out, "fake"))
        << "summary should convey the real HOME was hidden/faked:\n" << out;
}

// --- strict / normal ---------------------------------------------------------

TEST(Report, SurfacesStrictMode) {
    const std::string out = summarize_audit(kStrictAudit);
    EXPECT_TRUE(icontains(out, "strict")) << "summary should mention strict mode:\n" << out;
}

TEST(Report, SurfacesNormalMode) {
    const std::string out = summarize_audit(kNormalAudit);
    EXPECT_TRUE(icontains(out, "normal")) << "summary should mention normal mode:\n" << out;
}

// --- shape / robustness ------------------------------------------------------

TEST(Report, ProducesNonEmptySummaryForValidAudit) {
    EXPECT_FALSE(summarize_audit(kStrictAudit).empty());
    EXPECT_FALSE(summarize_audit(kNormalAudit).empty());
}

TEST(Report, DoesNotEchoRawAuditBlock) {
    // The summary should be a distilled human sentence, not a copy of the raw log.
    const std::string out = summarize_audit(kStrictAudit);
    EXPECT_FALSE(contains(out, "Bubblewrap command:"))
        << "summary should not paste the raw bwrap command line:\n" << out;
}

TEST(Report, DoesNotThrowOnEmptyInput) {
    EXPECT_NO_THROW({ (void)summarize_audit(""); });
}

TEST(Report, DoesNotThrowOnMissingScrubbedLine) {
    // An audit block lacking an "Env scrubbed:" line must be handled gracefully.
    const std::string audit = R"(Raincoat started
Mode: normal
Network: full
Fake HOME: /tmp/raincoat.x/home/user
Process exit code: 0
)";
    EXPECT_NO_THROW({ (void)summarize_audit(audit); });
}
