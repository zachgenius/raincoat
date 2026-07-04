// Raincoat — env_guard tests.
//
// Covers is_sensitive_env pattern matching and resolve_env resolution semantics
// as specified in docs/DESIGN.md (env_guard interface) and docs/SPEC.md
// ("Environment variable scrubbing"). Suite prefix: EnvGuard.
//
// NOTE (TDD red): these are written against the intended behaviour; the current
// env_guard.cpp is a stub, so they are expected to FAIL until the module is built.
#include <gtest/gtest.h>

#include <algorithm>
#include <map>
#include <string>
#include <utility>
#include <vector>

#include "env_guard.hpp"

using raincoat::EnvPolicy;
using raincoat::EnvResolution;
using raincoat::env_name_matches_glob;
using raincoat::is_scrubbed_name;
using raincoat::is_sensitive_env;
using raincoat::resolve_env;

namespace {

// --- small helpers ---------------------------------------------------------

bool has(const std::vector<std::string>& v, const std::string& name) {
    return std::find(v.begin(), v.end(), name) != v.end();
}

bool inResolved(const EnvResolution& r, const std::string& name) {
    return r.resolved.find(name) != r.resolved.end();
}

std::string resolvedValue(const EnvResolution& r, const std::string& name) {
    auto it = r.resolved.find(name);
    return it == r.resolved.end() ? std::string("<absent>") : it->second;
}

// Empty argument bundles for the common "defaults only" call shape.
const std::vector<std::string> kNoAllow{};
const std::vector<std::pair<std::string, std::string>> kNoSet{};
const std::map<std::string, std::string> kNoDefaults{};

// The scenario parent env from the module brief.
std::map<std::string, std::string> richParent() {
    return {
        {"OPENAI_API_KEY", "sk-openai-xxx"},
        {"AWS_SECRET_ACCESS_KEY", "aws-secret-xxx"},
        {"GITHUB_TOKEN", "ghp_xxx"},
        {"HOME", "/home/realuser"},
        {"PATH", "/usr/bin:/bin"},
        {"TERM", "xterm-256color"},
        {"USER", "realuser"},
        {"SSH_AUTH_SOCK", "/run/user/1000/ssh-agent.sock"},
    };
}

}  // namespace

// ===========================================================================
// is_sensitive_env — suffix rules (_TOKEN / _SECRET / _KEY)
// ===========================================================================

TEST(EnvGuard, SensitiveSuffixToken) {
    EXPECT_TRUE(is_sensitive_env("GITHUB_TOKEN"));
    EXPECT_TRUE(is_sensitive_env("MY_TOKEN"));
    EXPECT_TRUE(is_sensitive_env("SOME_CUSTOM_TOKEN"));
}

TEST(EnvGuard, SensitiveSuffixSecret) {
    EXPECT_TRUE(is_sensitive_env("MY_SECRET"));
    EXPECT_TRUE(is_sensitive_env("DB_PASSWORD_SECRET"));
}

TEST(EnvGuard, SensitiveSuffixKey) {
    EXPECT_TRUE(is_sensitive_env("API_KEY"));
    EXPECT_TRUE(is_sensitive_env("AWS_SECRET_ACCESS_KEY"));
    EXPECT_TRUE(is_sensitive_env("SOME_PRIVATE_KEY"));
}

// A bare word equal to the suffix (no leading segment) still ends with it.
TEST(EnvGuard, SensitiveSuffixExactWords) {
    EXPECT_TRUE(is_sensitive_env("_TOKEN"));
    EXPECT_TRUE(is_sensitive_env("_SECRET"));
    EXPECT_TRUE(is_sensitive_env("_KEY"));
}

// The suffix must be preceded by the underscore form; plain words are NOT flagged.
TEST(EnvGuard, NonSensitiveBareWords) {
    EXPECT_FALSE(is_sensitive_env("TOKEN"));
    EXPECT_FALSE(is_sensitive_env("SECRET"));
    EXPECT_FALSE(is_sensitive_env("KEY"));
    EXPECT_FALSE(is_sensitive_env("MYKEY"));      // no underscore before KEY
    EXPECT_FALSE(is_sensitive_env("KEYBOARD"));   // KEY is a prefix, not the suffix
    EXPECT_FALSE(is_sensitive_env("TOKENIZER"));
}

// ===========================================================================
// is_sensitive_env — prefix rules
// ===========================================================================

TEST(EnvGuard, SensitivePrefixAws) {
    EXPECT_TRUE(is_sensitive_env("AWS_"));
    EXPECT_TRUE(is_sensitive_env("AWS_REGION"));
    EXPECT_TRUE(is_sensitive_env("AWS_ACCESS_KEY_ID"));
}

TEST(EnvGuard, SensitivePrefixGithub) {
    EXPECT_TRUE(is_sensitive_env("GITHUB_ACTOR"));
    EXPECT_TRUE(is_sensitive_env("GITHUB_REPOSITORY"));
}

TEST(EnvGuard, SensitivePrefixGoogle) {
    EXPECT_TRUE(is_sensitive_env("GOOGLE_APPLICATION_CREDENTIALS"));
    EXPECT_TRUE(is_sensitive_env("GOOGLE_CLOUD_PROJECT"));
}

TEST(EnvGuard, SensitivePrefixOpenai) {
    EXPECT_TRUE(is_sensitive_env("OPENAI_API_KEY"));
    EXPECT_TRUE(is_sensitive_env("OPENAI_ORG"));
}

TEST(EnvGuard, SensitivePrefixAnthropic) {
    EXPECT_TRUE(is_sensitive_env("ANTHROPIC_API_KEY"));
    EXPECT_TRUE(is_sensitive_env("ANTHROPIC_BASE_URL"));
}

// DYLD_ is the macOS dynamic-linker injection family; scrubbed unconditionally (the
// prefix never occurs on Linux, so this stays green there too).
TEST(EnvGuard, SensitivePrefixDyld) {
    EXPECT_TRUE(is_sensitive_env("DYLD_"));
    EXPECT_TRUE(is_sensitive_env("DYLD_INSERT_LIBRARIES"));
    EXPECT_TRUE(is_sensitive_env("DYLD_LIBRARY_PATH"));
    EXPECT_TRUE(is_sensitive_env("DYLD_FRAMEWORK_PATH"));
    // Must be at the very start — an embedded DYLD_ is not a match on its own.
    EXPECT_FALSE(is_sensitive_env("MY_DYLD_PATH"));
}

// A prefix must appear at the START of the name.
TEST(EnvGuard, PrefixMustBeAtStart) {
    EXPECT_FALSE(is_sensitive_env("MY_AWS_REGION"));    // AWS_ not at start; no matching suffix
    EXPECT_FALSE(is_sensitive_env("XGITHUB_ACTOR"));
    EXPECT_FALSE(is_sensitive_env("NOT_GOOGLE_CLOUD"));
}

// SSH_ / DOCKER_ are NOT blanket prefixes — only the exact names are sensitive.
TEST(EnvGuard, PrefixesNotOverbroad) {
    EXPECT_FALSE(is_sensitive_env("SSH_AGENT_PID"));    // SSH_ is not a prefix rule
    EXPECT_FALSE(is_sensitive_env("SSH_CONNECTION"));
    EXPECT_FALSE(is_sensitive_env("DOCKER_HOSTNAME"));  // DOCKER_ is not a prefix rule
    EXPECT_FALSE(is_sensitive_env("KUBECONFIG_DIR"));   // only exact KUBECONFIG
}

// ===========================================================================
// is_sensitive_env — exact-name rules
// ===========================================================================

TEST(EnvGuard, SensitiveExactNames) {
    EXPECT_TRUE(is_sensitive_env("KUBECONFIG"));
    EXPECT_TRUE(is_sensitive_env("SSH_AUTH_SOCK"));
    EXPECT_TRUE(is_sensitive_env("DOCKER_HOST"));
    EXPECT_TRUE(is_sensitive_env("NPM_TOKEN"));   // also matches _TOKEN suffix
    EXPECT_TRUE(is_sensitive_env("PYPI_TOKEN"));  // also matches _TOKEN suffix
}

// ===========================================================================
// is_sensitive_env — case sensitivity and safe names
// ===========================================================================

TEST(EnvGuard, CaseSensitiveDoesNotMatchLowercase) {
    EXPECT_FALSE(is_sensitive_env("aws_region"));
    EXPECT_FALSE(is_sensitive_env("my_token"));
    EXPECT_FALSE(is_sensitive_env("api_key"));
    EXPECT_FALSE(is_sensitive_env("kubeconfig"));
    EXPECT_FALSE(is_sensitive_env("ssh_auth_sock"));
}

TEST(EnvGuard, SafeNamesNotSensitive) {
    EXPECT_FALSE(is_sensitive_env("PATH"));
    EXPECT_FALSE(is_sensitive_env("TERM"));
    EXPECT_FALSE(is_sensitive_env("USER"));
    EXPECT_FALSE(is_sensitive_env("HOME"));
    EXPECT_FALSE(is_sensitive_env("LANG"));
    EXPECT_FALSE(is_sensitive_env("LC_ALL"));
    EXPECT_FALSE(is_sensitive_env("TZ"));
    EXPECT_FALSE(is_sensitive_env("SHELL"));
    EXPECT_FALSE(is_sensitive_env(""));
}

// ===========================================================================
// resolve_env — base safe allowlist (PATH, TERM)
// ===========================================================================

TEST(EnvGuard, BaseAllowlistPathTermCopiedFromParent) {
    std::map<std::string, std::string> parent{
        {"PATH", "/usr/bin:/bin"},
        {"TERM", "xterm-256color"},
    };
    auto r = resolve_env(parent, kNoAllow, kNoSet, kNoDefaults, false);

    EXPECT_EQ(resolvedValue(r, "PATH"), "/usr/bin:/bin");
    EXPECT_EQ(resolvedValue(r, "TERM"), "xterm-256color");
    EXPECT_TRUE(has(r.allowed, "PATH"));
    EXPECT_TRUE(has(r.allowed, "TERM"));
    // Copied verbatim from parent => classified as allowed, not set.
    EXPECT_FALSE(has(r.set, "PATH"));
    EXPECT_FALSE(has(r.set, "TERM"));
}

TEST(EnvGuard, BaseAllowlistAbsentWhenNotInParent) {
    std::map<std::string, std::string> parent{};  // no PATH / TERM
    auto r = resolve_env(parent, kNoAllow, kNoSet, kNoDefaults, false);

    EXPECT_FALSE(inResolved(r, "PATH"));
    EXPECT_FALSE(inResolved(r, "TERM"));
    EXPECT_FALSE(has(r.allowed, "PATH"));
    EXPECT_FALSE(has(r.allowed, "TERM"));
    // Nothing to scrub: only names PRESENT in parent are scrubbed.
    EXPECT_FALSE(has(r.scrubbed, "PATH"));
    EXPECT_FALSE(has(r.scrubbed, "TERM"));
}

// ===========================================================================
// resolve_env — USER forced to generic value
// ===========================================================================

TEST(EnvGuard, UserForcedToGenericAndNotLeaked) {
    std::map<std::string, std::string> parent{{"USER", "realuser"}};
    auto r = resolve_env(parent, kNoAllow, kNoSet, kNoDefaults, false);

    EXPECT_EQ(resolvedValue(r, "USER"), "user");
    EXPECT_NE(resolvedValue(r, "USER"), "realuser");
    EXPECT_TRUE(has(r.set, "USER"));      // synthetic value => set
    EXPECT_FALSE(has(r.allowed, "USER")); // not copied from parent
    // The real username must never appear as a value anywhere in resolved.
    for (const auto& kv : r.resolved) {
        EXPECT_NE(kv.second, "realuser");
    }
    // USER was replaced, not dropped: it is not "scrubbed".
    EXPECT_FALSE(has(r.scrubbed, "USER"));
}

TEST(EnvGuard, UserGenericEvenWhenAbsentFromParent) {
    std::map<std::string, std::string> parent{};
    auto r = resolve_env(parent, kNoAllow, kNoSet, kNoDefaults, false);
    EXPECT_EQ(resolvedValue(r, "USER"), "user");
    EXPECT_TRUE(has(r.set, "USER"));
}

// ===========================================================================
// resolve_env — identity-protected vars are never copied from parent via allow_env
// ===========================================================================

// --allow-env USER must NOT resurrect the real login name: USER stays generic.
TEST(EnvGuard, AllowEnvCannotResurrectRealUser) {
    std::map<std::string, std::string> parent{{"USER", "realuser"}};
    std::vector<std::string> allow{"USER"};
    auto r = resolve_env(parent, allow, kNoSet, kNoDefaults, false);

    EXPECT_EQ(resolvedValue(r, "USER"), "user");
    EXPECT_NE(resolvedValue(r, "USER"), "realuser");
    EXPECT_TRUE(has(r.set, "USER"));       // synthetic value => set
    EXPECT_FALSE(has(r.allowed, "USER"));  // never copied from parent
    for (const auto& kv : r.resolved) EXPECT_NE(kv.second, "realuser");
}

// --allow-env LOGNAME must NOT copy the parent's login name. env_guard does not
// itself inject a generic LOGNAME (the runner does), so the protected name is
// simply refused entry and lands in scrubbed instead of allowed/resolved.
TEST(EnvGuard, AllowEnvCannotResurrectRealLogname) {
    std::map<std::string, std::string> parent{{"LOGNAME", "realuser"}};
    std::vector<std::string> allow{"LOGNAME"};
    auto r = resolve_env(parent, allow, kNoSet, kNoDefaults, false);

    EXPECT_FALSE(has(r.allowed, "LOGNAME"));           // never copied from parent
    EXPECT_NE(resolvedValue(r, "LOGNAME"), "realuser");
    EXPECT_TRUE(has(r.scrubbed, "LOGNAME"));           // dropped, runner re-injects
    for (const auto& kv : r.resolved) EXPECT_NE(kv.second, "realuser");
}

// --allow-env HOSTNAME must NOT copy the parent's host name.
TEST(EnvGuard, AllowEnvCannotResurrectRealHostname) {
    std::map<std::string, std::string> parent{{"HOSTNAME", "pop-os"}};
    std::vector<std::string> allow{"HOSTNAME"};
    auto r = resolve_env(parent, allow, kNoSet, kNoDefaults, false);

    EXPECT_FALSE(has(r.allowed, "HOSTNAME"));          // never copied from parent
    EXPECT_NE(resolvedValue(r, "HOSTNAME"), "pop-os");
    EXPECT_TRUE(has(r.scrubbed, "HOSTNAME"));          // dropped, runner re-injects
    for (const auto& kv : r.resolved) EXPECT_NE(kv.second, "pop-os");
}

// --set-env still wins over the identity guard: an explicit value the user chose
// is honored (it is not the host's real value).
TEST(EnvGuard, SetEnvStillOverridesIdentityGuard) {
    std::map<std::string, std::string> parent{{"LOGNAME", "realuser"},
                                              {"HOSTNAME", "pop-os"}};
    std::vector<std::string> allow{"LOGNAME", "HOSTNAME"};
    std::vector<std::pair<std::string, std::string>> set{{"LOGNAME", "ci"},
                                                         {"HOSTNAME", "ci-box"}};
    auto r = resolve_env(parent, allow, set, kNoDefaults, false);

    EXPECT_EQ(resolvedValue(r, "LOGNAME"), "ci");
    EXPECT_EQ(resolvedValue(r, "HOSTNAME"), "ci-box");
    EXPECT_TRUE(has(r.set, "LOGNAME"));
    EXPECT_TRUE(has(r.set, "HOSTNAME"));
}

// ===========================================================================
// resolve_env — defaults applied as `set`
// ===========================================================================

TEST(EnvGuard, DefaultsAppliedAsSet) {
    std::map<std::string, std::string> defaults{
        {"TZ", "UTC"},
        {"LANG", "en_US.UTF-8"},
        {"LC_ALL", "en_US.UTF-8"},
    };
    auto r = resolve_env(kNoDefaults, kNoAllow, kNoSet, defaults, false);

    EXPECT_EQ(resolvedValue(r, "TZ"), "UTC");
    EXPECT_EQ(resolvedValue(r, "LANG"), "en_US.UTF-8");
    EXPECT_EQ(resolvedValue(r, "LC_ALL"), "en_US.UTF-8");
    EXPECT_TRUE(has(r.set, "TZ"));
    EXPECT_TRUE(has(r.set, "LANG"));
    EXPECT_TRUE(has(r.set, "LC_ALL"));
    EXPECT_FALSE(has(r.allowed, "TZ"));
}

// A default whose name also exists in the parent still uses the default (synthetic)
// value, and the name is classified as set — not scrubbed (it IS in resolved).
TEST(EnvGuard, DefaultShadowsParentValue) {
    std::map<std::string, std::string> parent{{"TZ", "America/New_York"}};
    std::map<std::string, std::string> defaults{{"TZ", "UTC"}};
    auto r = resolve_env(parent, kNoAllow, kNoSet, defaults, false);

    EXPECT_EQ(resolvedValue(r, "TZ"), "UTC");
    EXPECT_TRUE(has(r.set, "TZ"));
    EXPECT_FALSE(has(r.scrubbed, "TZ"));
}

// ===========================================================================
// resolve_env — --allow-env
// ===========================================================================

TEST(EnvGuard, AllowEnvCopiesFromParentWhenPresent) {
    std::map<std::string, std::string> parent{{"OPENAI_API_KEY", "sk-xxx"}};
    std::vector<std::string> allow{"OPENAI_API_KEY"};
    auto r = resolve_env(parent, allow, kNoSet, kNoDefaults, false);

    EXPECT_EQ(resolvedValue(r, "OPENAI_API_KEY"), "sk-xxx");
    EXPECT_TRUE(has(r.allowed, "OPENAI_API_KEY"));
    EXPECT_FALSE(has(r.set, "OPENAI_API_KEY"));
    // Explicitly allowed => not scrubbed even though it matches a sensitive pattern.
    EXPECT_FALSE(has(r.scrubbed, "OPENAI_API_KEY"));
}

TEST(EnvGuard, AllowEnvIgnoredWhenAbsentFromParent) {
    std::map<std::string, std::string> parent{};  // MISSING
    std::vector<std::string> allow{"MY_VAR"};
    auto r = resolve_env(parent, allow, kNoSet, kNoDefaults, false);

    EXPECT_FALSE(inResolved(r, "MY_VAR"));
    EXPECT_FALSE(has(r.allowed, "MY_VAR"));
    EXPECT_FALSE(has(r.scrubbed, "MY_VAR"));  // not in parent => nothing to scrub
}

// ===========================================================================
// resolve_env — --set-env
// ===========================================================================

TEST(EnvGuard, SetEnvAssignsValue) {
    std::vector<std::pair<std::string, std::string>> set{{"FOO", "bar"}};
    auto r = resolve_env(kNoDefaults, kNoAllow, set, kNoDefaults, false);

    EXPECT_EQ(resolvedValue(r, "FOO"), "bar");
    EXPECT_TRUE(has(r.set, "FOO"));
    EXPECT_FALSE(has(r.allowed, "FOO"));
}

TEST(EnvGuard, SetEnvForNameNotInParentIsNotScrubbed) {
    std::map<std::string, std::string> parent{{"PATH", "/bin"}};
    std::vector<std::pair<std::string, std::string>> set{{"NEWVAR", "v"}};
    auto r = resolve_env(parent, kNoAllow, set, kNoDefaults, false);

    EXPECT_EQ(resolvedValue(r, "NEWVAR"), "v");
    EXPECT_FALSE(has(r.scrubbed, "NEWVAR"));
}

// set_env overrides --allow-env: same NAME allowed AND set => the set value wins.
TEST(EnvGuard, SetEnvOverridesAllowEnv) {
    std::map<std::string, std::string> parent{{"API_HOST", "parent-value"}};
    std::vector<std::string> allow{"API_HOST"};
    std::vector<std::pair<std::string, std::string>> set{{"API_HOST", "override-value"}};
    auto r = resolve_env(parent, allow, set, kNoDefaults, false);

    EXPECT_EQ(resolvedValue(r, "API_HOST"), "override-value");
    // The overridden name is classified as set (synthetic), not allowed (verbatim).
    EXPECT_TRUE(has(r.set, "API_HOST"));
    EXPECT_FALSE(has(r.allowed, "API_HOST"));
    EXPECT_FALSE(has(r.scrubbed, "API_HOST"));
    // The parent value must not leak.
    EXPECT_NE(resolvedValue(r, "API_HOST"), "parent-value");
}

// set_env overrides defaults too.
TEST(EnvGuard, SetEnvOverridesDefaults) {
    std::map<std::string, std::string> defaults{{"TZ", "UTC"}};
    std::vector<std::pair<std::string, std::string>> set{{"TZ", "Europe/London"}};
    auto r = resolve_env(kNoDefaults, kNoAllow, set, defaults, false);

    EXPECT_EQ(resolvedValue(r, "TZ"), "Europe/London");
    EXPECT_TRUE(has(r.set, "TZ"));
}

// set_env can override the generic USER as well.
TEST(EnvGuard, SetEnvOverridesGenericUser) {
    std::map<std::string, std::string> parent{{"USER", "realuser"}};
    std::vector<std::pair<std::string, std::string>> set{{"USER", "ci"}};
    auto r = resolve_env(parent, kNoAllow, set, kNoDefaults, false);

    EXPECT_EQ(resolvedValue(r, "USER"), "ci");
    EXPECT_TRUE(has(r.set, "USER"));
}

// Later --set-env entries win over earlier ones for the same key.
TEST(EnvGuard, SetEnvLastWinsForDuplicateKey) {
    std::vector<std::pair<std::string, std::string>> set{{"K", "first"}, {"K", "second"}};
    auto r = resolve_env(kNoDefaults, kNoAllow, set, kNoDefaults, false);
    EXPECT_EQ(resolvedValue(r, "K"), "second");
}

// ===========================================================================
// resolve_env — scrubbed list
// ===========================================================================

TEST(EnvGuard, ScrubbedContainsSensitiveParentVarsNotAllowed) {
    auto parent = richParent();
    auto r = resolve_env(parent, kNoAllow, kNoSet, kNoDefaults, false);

    // Sensitive, un-allowed parent vars must be scrubbed.
    EXPECT_TRUE(has(r.scrubbed, "OPENAI_API_KEY"));
    EXPECT_TRUE(has(r.scrubbed, "AWS_SECRET_ACCESS_KEY"));
    EXPECT_TRUE(has(r.scrubbed, "GITHUB_TOKEN"));
    EXPECT_TRUE(has(r.scrubbed, "SSH_AUTH_SOCK"));
    // HOME is present in parent and injected later by the runner, not here => scrubbed.
    EXPECT_TRUE(has(r.scrubbed, "HOME"));

    // Base-allowlisted / replaced names are NOT scrubbed.
    EXPECT_FALSE(has(r.scrubbed, "PATH"));
    EXPECT_FALSE(has(r.scrubbed, "TERM"));
    EXPECT_FALSE(has(r.scrubbed, "USER"));

    // And none of them leak into resolved.
    EXPECT_FALSE(inResolved(r, "OPENAI_API_KEY"));
    EXPECT_FALSE(inResolved(r, "AWS_SECRET_ACCESS_KEY"));
    EXPECT_FALSE(inResolved(r, "GITHUB_TOKEN"));
    EXPECT_FALSE(inResolved(r, "SSH_AUTH_SOCK"));
    EXPECT_FALSE(inResolved(r, "HOME"));
}

TEST(EnvGuard, ScrubbedIsSorted) {
    std::map<std::string, std::string> parent{
        {"ZED_TOKEN", "z"},
        {"ALPHA_SECRET", "a"},
        {"MIDDLE_KEY", "m"},
        {"HOME", "/home/x"},
    };
    auto r = resolve_env(parent, kNoAllow, kNoSet, kNoDefaults, false);
    EXPECT_TRUE(std::is_sorted(r.scrubbed.begin(), r.scrubbed.end()));
}

// Every parent name that is NOT in resolved must appear in scrubbed, and vice-versa.
TEST(EnvGuard, ScrubbedIsExactlyParentMinusResolved) {
    auto parent = richParent();
    auto r = resolve_env(parent, kNoAllow, kNoSet, kNoDefaults, false);

    for (const auto& kv : parent) {
        const std::string& name = kv.first;
        if (inResolved(r, name)) {
            EXPECT_FALSE(has(r.scrubbed, name)) << name << " is resolved yet scrubbed";
        } else {
            EXPECT_TRUE(has(r.scrubbed, name)) << name << " dropped but not scrubbed";
        }
    }
    // Scrubbed must never contain a name absent from the parent.
    for (const auto& name : r.scrubbed) {
        EXPECT_NE(parent.find(name), parent.end()) << name << " scrubbed but not in parent";
    }
}

// A non-sensitive, un-allowed parent var is still dropped (only PATH/TERM/USER survive
// by default) and therefore appears in scrubbed.
TEST(EnvGuard, NonSensitiveUnallowedParentVarScrubbed) {
    std::map<std::string, std::string> parent{
        {"PATH", "/bin"},
        {"EDITOR", "vim"},
        {"SHELL", "/bin/zsh"},
    };
    auto r = resolve_env(parent, kNoAllow, kNoSet, kNoDefaults, false);
    EXPECT_TRUE(has(r.scrubbed, "EDITOR"));
    EXPECT_TRUE(has(r.scrubbed, "SHELL"));
    EXPECT_FALSE(inResolved(r, "EDITOR"));
    EXPECT_FALSE(inResolved(r, "SHELL"));
}

// ===========================================================================
// resolve_env — secrets must never appear in allowed/set name lists inadvertently
// ===========================================================================

TEST(EnvGuard, SecretsNeverInAllowedOrSetByDefault) {
    auto parent = richParent();
    auto r = resolve_env(parent, kNoAllow, kNoSet, kNoDefaults, false);

    for (const auto& name : r.allowed) {
        EXPECT_FALSE(is_sensitive_env(name)) << name << " leaked into allowed list";
    }
    for (const auto& name : r.set) {
        EXPECT_FALSE(is_sensitive_env(name)) << name << " leaked into set list";
    }
}

// Even the value strings of the secrets must not survive anywhere in resolved.
TEST(EnvGuard, SecretValuesNeverInResolvedByDefault) {
    auto parent = richParent();
    auto r = resolve_env(parent, kNoAllow, kNoSet, kNoDefaults, false);
    for (const auto& kv : r.resolved) {
        EXPECT_NE(kv.second, "sk-openai-xxx");
        EXPECT_NE(kv.second, "aws-secret-xxx");
        EXPECT_NE(kv.second, "ghp_xxx");
        EXPECT_NE(kv.second, "/run/user/1000/ssh-agent.sock");
        EXPECT_NE(kv.second, "/home/realuser");
    }
}

// A sensitive var appears in the allowed list ONLY when it was explicitly --allow-env'd.
TEST(EnvGuard, SensitiveInAllowedOnlyWhenExplicitlyAllowed) {
    auto parent = richParent();
    std::vector<std::string> allow{"GITHUB_TOKEN"};
    auto r = resolve_env(parent, allow, kNoSet, kNoDefaults, false);

    EXPECT_TRUE(has(r.allowed, "GITHUB_TOKEN"));
    EXPECT_EQ(resolvedValue(r, "GITHUB_TOKEN"), "ghp_xxx");
    EXPECT_FALSE(has(r.scrubbed, "GITHUB_TOKEN"));
    // The other secrets are still scrubbed.
    EXPECT_TRUE(has(r.scrubbed, "OPENAI_API_KEY"));
    EXPECT_TRUE(has(r.scrubbed, "AWS_SECRET_ACCESS_KEY"));
}

// ===========================================================================
// resolve_env — full brief scenario + strict parity
// ===========================================================================

TEST(EnvGuard, FullScenarioDefaultResolution) {
    auto parent = richParent();
    auto r = resolve_env(parent, kNoAllow, kNoSet, kNoDefaults, false);

    // Exactly the base allowlist + generic USER survive with no defaults given.
    EXPECT_EQ(resolvedValue(r, "PATH"), "/usr/bin:/bin");
    EXPECT_EQ(resolvedValue(r, "TERM"), "xterm-256color");
    EXPECT_EQ(resolvedValue(r, "USER"), "user");
    EXPECT_EQ(r.resolved.size(), 3u);
}

TEST(EnvGuard, StrictModeStillScrubsAndKeepsBaseAllowlist) {
    auto parent = richParent();
    auto r = resolve_env(parent, kNoAllow, kNoSet, kNoDefaults, /*strict=*/true);

    EXPECT_EQ(resolvedValue(r, "PATH"), "/usr/bin:/bin");
    EXPECT_EQ(resolvedValue(r, "TERM"), "xterm-256color");
    EXPECT_EQ(resolvedValue(r, "USER"), "user");
    EXPECT_TRUE(has(r.scrubbed, "OPENAI_API_KEY"));
    EXPECT_TRUE(has(r.scrubbed, "AWS_SECRET_ACCESS_KEY"));
    EXPECT_TRUE(has(r.scrubbed, "GITHUB_TOKEN"));
    EXPECT_TRUE(has(r.scrubbed, "SSH_AUTH_SOCK"));
    EXPECT_TRUE(has(r.scrubbed, "HOME"));
}

// Empty parent + empty options: only the synthetic generic USER is produced.
TEST(EnvGuard, EmptyParentProducesOnlyGenericUser) {
    auto r = resolve_env(kNoDefaults, kNoAllow, kNoSet, kNoDefaults, false);
    EXPECT_EQ(resolvedValue(r, "USER"), "user");
    EXPECT_EQ(r.resolved.size(), 1u);
    EXPECT_TRUE(r.scrubbed.empty());
    EXPECT_TRUE(r.allowed.empty());
}

// Full combined interaction: defaults + allow-env + set-env override, all at once.
TEST(EnvGuard, CombinedResolutionPrecedence) {
    std::map<std::string, std::string> parent{
        {"PATH", "/usr/bin"},
        {"TERM", "screen"},
        {"USER", "realuser"},
        {"OPENAI_API_KEY", "sk-secret"},
        {"BUILD_ID", "42"},
        {"HOME", "/home/realuser"},
    };
    std::map<std::string, std::string> defaults{{"TZ", "UTC"}, {"LANG", "en_US.UTF-8"}};
    std::vector<std::string> allow{"BUILD_ID", "OPENAI_API_KEY"};
    std::vector<std::pair<std::string, std::string>> set{{"OPENAI_API_KEY", "sk-override"},
                                                         {"TZ", "Asia/Tokyo"}};
    auto r = resolve_env(parent, allow, set, defaults, false);

    EXPECT_EQ(resolvedValue(r, "PATH"), "/usr/bin");
    EXPECT_EQ(resolvedValue(r, "TERM"), "screen");
    EXPECT_EQ(resolvedValue(r, "USER"), "user");
    EXPECT_EQ(resolvedValue(r, "LANG"), "en_US.UTF-8");
    EXPECT_EQ(resolvedValue(r, "TZ"), "Asia/Tokyo");            // set beats default
    EXPECT_EQ(resolvedValue(r, "BUILD_ID"), "42");             // allow-env copy
    EXPECT_EQ(resolvedValue(r, "OPENAI_API_KEY"), "sk-override");  // set beats allow-env

    EXPECT_TRUE(has(r.allowed, "BUILD_ID"));
    EXPECT_TRUE(has(r.set, "OPENAI_API_KEY"));   // overridden => set, not allowed
    EXPECT_FALSE(has(r.allowed, "OPENAI_API_KEY"));
    EXPECT_TRUE(has(r.scrubbed, "HOME"));
    EXPECT_FALSE(has(r.scrubbed, "OPENAI_API_KEY"));
    EXPECT_FALSE(has(r.scrubbed, "BUILD_ID"));
    // The original parent secret value must not survive.
    for (const auto& kv : r.resolved) EXPECT_NE(kv.second, "sk-secret");
}

// ===========================================================================
// env_name_matches_glob — the scrub-pattern glob matcher
// ===========================================================================

TEST(EnvGuard, GlobStarSuffix) {
    EXPECT_TRUE(env_name_matches_glob("AWS_REGION", "AWS_*"));
    EXPECT_TRUE(env_name_matches_glob("AWS_", "AWS_*"));       // * matches empty
    EXPECT_FALSE(env_name_matches_glob("XAWS_REGION", "AWS_*"));
}

TEST(EnvGuard, GlobStarPrefix) {
    EXPECT_TRUE(env_name_matches_glob("GITHUB_TOKEN", "*_TOKEN"));
    EXPECT_TRUE(env_name_matches_glob("_TOKEN", "*_TOKEN"));
    EXPECT_FALSE(env_name_matches_glob("TOKEN", "*_TOKEN"));  // needs the underscore
}

TEST(EnvGuard, GlobStarBothEnds) {
    EXPECT_TRUE(env_name_matches_glob("MY_SECRET_VALUE", "*SECRET*"));
    EXPECT_FALSE(env_name_matches_glob("MY_PUBLIC_VALUE", "*SECRET*"));
}

TEST(EnvGuard, GlobQuestionMark) {
    EXPECT_TRUE(env_name_matches_glob("AB", "A?"));
    EXPECT_FALSE(env_name_matches_glob("A", "A?"));   // ? requires exactly one char
    EXPECT_FALSE(env_name_matches_glob("ABC", "A?"));
}

TEST(EnvGuard, GlobLiteralNoWildcards) {
    EXPECT_TRUE(env_name_matches_glob("EXACT", "EXACT"));
    EXPECT_FALSE(env_name_matches_glob("EXACTX", "EXACT"));
    EXPECT_TRUE(env_name_matches_glob("", "*"));      // lone star matches empty
    EXPECT_TRUE(env_name_matches_glob("anything", "*"));
}

// ===========================================================================
// is_scrubbed_name — patterns EXTEND the built-in is_sensitive_env defaults
// ===========================================================================

TEST(EnvGuard, IsScrubbedNameBuiltinsStillApplyWithNoPatterns) {
    EXPECT_TRUE(is_scrubbed_name("AWS_REGION", {}));      // built-in prefix
    EXPECT_TRUE(is_scrubbed_name("MY_TOKEN", {}));        // built-in suffix
    EXPECT_FALSE(is_scrubbed_name("EDITOR", {}));         // neither
}

TEST(EnvGuard, IsScrubbedNamePatternsExtendBuiltins) {
    // A name that is NOT a built-in sensitive var becomes sensitive via a custom glob.
    EXPECT_FALSE(is_scrubbed_name("MYCORP_DATA", {}));
    EXPECT_TRUE(is_scrubbed_name("MYCORP_DATA", {"MYCORP_*"}));
    // Built-ins are still honored even when unrelated patterns are supplied.
    EXPECT_TRUE(is_scrubbed_name("AWS_REGION", {"MYCORP_*"}));
}

// ===========================================================================
// resolve_env — EnvPolicy: username, env_deny, scrub_patterns
// ===========================================================================

// ext.username drives the generic USER value.
TEST(EnvGuard, PolicyUsernameOverridesGenericUser) {
    EnvPolicy policy;
    policy.username = "agent";
    std::map<std::string, std::string> parent{{"USER", "realuser"}};
    auto r = resolve_env(parent, kNoAllow, kNoSet, kNoDefaults, false, policy);
    EXPECT_EQ(resolvedValue(r, "USER"), "agent");
    EXPECT_TRUE(has(r.set, "USER"));
    for (const auto& kv : r.resolved) EXPECT_NE(kv.second, "realuser");
}

// env_deny: a denied name is NEVER copied from the parent, even via --allow-env, and
// therefore lands in scrubbed.
TEST(EnvGuard, PolicyEnvDenyBlocksAllowEnv) {
    EnvPolicy policy;
    policy.deny = {"DOCKER_HOST"};
    std::map<std::string, std::string> parent{{"DOCKER_HOST", "tcp://leak"}};
    std::vector<std::string> allow{"DOCKER_HOST"};  // user tries to allow it back
    auto r = resolve_env(parent, allow, kNoSet, kNoDefaults, false, policy);

    EXPECT_FALSE(inResolved(r, "DOCKER_HOST"));
    EXPECT_FALSE(has(r.allowed, "DOCKER_HOST"));
    EXPECT_TRUE(has(r.scrubbed, "DOCKER_HOST"));
    for (const auto& kv : r.resolved) EXPECT_NE(kv.second, "tcp://leak");
}

// env_deny does NOT block an explicit --set-env (a user-chosen synthetic value).
TEST(EnvGuard, PolicyEnvDenyDoesNotBlockSetEnv) {
    EnvPolicy policy;
    policy.deny = {"DOCKER_HOST"};
    std::vector<std::pair<std::string, std::string>> set{{"DOCKER_HOST", "tcp://chosen"}};
    auto r = resolve_env(kNoDefaults, kNoAllow, set, kNoDefaults, false, policy);
    EXPECT_EQ(resolvedValue(r, "DOCKER_HOST"), "tcp://chosen");
    EXPECT_TRUE(has(r.set, "DOCKER_HOST"));
}

// scrub_patterns: a matching name is force-scrubbed even when explicitly --allow-env'd.
TEST(EnvGuard, PolicyScrubPatternBlocksAllowEnv) {
    EnvPolicy policy;
    policy.scrub_patterns = {"MYCORP_*"};
    std::map<std::string, std::string> parent{{"MYCORP_DATA", "corp-value"}};
    std::vector<std::string> allow{"MYCORP_DATA"};
    auto r = resolve_env(parent, allow, kNoSet, kNoDefaults, false, policy);

    EXPECT_FALSE(inResolved(r, "MYCORP_DATA"));
    EXPECT_TRUE(has(r.scrubbed, "MYCORP_DATA"));
    for (const auto& kv : r.resolved) EXPECT_NE(kv.second, "corp-value");
}

// Control: without the pattern, the same --allow-env DOES copy the (non-sensitive) var.
TEST(EnvGuard, WithoutScrubPatternAllowEnvCopiesNonSensitiveVar) {
    std::map<std::string, std::string> parent{{"MYCORP_DATA", "corp-value"}};
    std::vector<std::string> allow{"MYCORP_DATA"};
    auto r = resolve_env(parent, allow, kNoSet, kNoDefaults, false);  // default policy
    EXPECT_EQ(resolvedValue(r, "MYCORP_DATA"), "corp-value");
    EXPECT_TRUE(has(r.allowed, "MYCORP_DATA"));
}

// A default (5-arg) call and a default-constructed EnvPolicy behave identically, so
// the trailing-parameter change is backward compatible.
TEST(EnvGuard, DefaultPolicyMatchesLegacyCall) {
    auto parent = richParent();
    auto a = resolve_env(parent, kNoAllow, kNoSet, kNoDefaults, false);
    auto b = resolve_env(parent, kNoAllow, kNoSet, kNoDefaults, false, EnvPolicy{});
    EXPECT_EQ(a.resolved, b.resolved);
    EXPECT_EQ(a.scrubbed, b.scrubbed);
}
