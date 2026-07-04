// Raincoat — env_guard: environment scrubbing / resolution.
#include "env_guard.hpp"

#include <algorithm>

namespace raincoat {

namespace {

bool has_prefix(const std::string& s, const std::string& prefix) {
    return s.size() >= prefix.size() &&
           s.compare(0, prefix.size(), prefix) == 0;
}

bool has_suffix(const std::string& s, const std::string& suffix) {
    return s.size() >= suffix.size() &&
           s.compare(s.size() - suffix.size(), suffix.size(), suffix) == 0;
}

// Identity fingerprints whose REAL value must never reach the child, regardless
// of what the user requests. resolve_env forces USER to a generic value; LOGNAME
// and HOSTNAME are injected with generic values later by the runner (it owns the
// synthetic host/login identity). For all three we additionally refuse to copy the
// parent's value through --allow-env, so an explicit `--allow-env USER` (etc.)
// can never resurrect the real login/host name. `--set-env NAME=...` is still
// honored — that is a value the user deliberately chose, not the host's.
bool is_identity_protected(const std::string& name) {
    return name == "USER" || name == "LOGNAME" || name == "HOSTNAME";
}

}  // namespace

bool env_name_matches_glob(const std::string& name, const std::string& pattern) {
    // Classic two-pointer glob matcher with backtracking for `*`. `?` matches any
    // single character; every other pattern character is literal. Iterative form so
    // there is no recursion depth concern for pathological patterns.
    std::size_t n = 0, p = 0;             // cursors into name / pattern
    std::size_t star = std::string::npos; // last '*' position in pattern
    std::size_t match = 0;                // name position when the last '*' matched
    while (n < name.size()) {
        if (p < pattern.size() && (pattern[p] == '?' || pattern[p] == name[n])) {
            ++n;
            ++p;
        } else if (p < pattern.size() && pattern[p] == '*') {
            star = p++;
            match = n;
        } else if (star != std::string::npos) {
            p = star + 1;
            n = ++match;
        } else {
            return false;
        }
    }
    while (p < pattern.size() && pattern[p] == '*') ++p;
    return p == pattern.size();
}

bool is_scrubbed_name(const std::string& name, const std::vector<std::string>& patterns) {
    if (is_sensitive_env(name)) return true;
    for (const auto& pat : patterns) {
        if (env_name_matches_glob(name, pat)) return true;
    }
    return false;
}

bool is_sensitive_env(const std::string& name) {
    // Suffix rules: *_TOKEN / *_SECRET / *_KEY.
    if (has_suffix(name, "_TOKEN") || has_suffix(name, "_SECRET") ||
        has_suffix(name, "_KEY")) {
        return true;
    }
    // Prefix rules (must be at the very start). DYLD_ is macOS-specific dynamic-linker
    // injection (DYLD_INSERT_LIBRARIES / DYLD_LIBRARY_PATH / ...): under the macOS
    // allow-default Seatbelt profile the child runs on the real FS, so a leaked DYLD_*
    // var could preload host libraries into it. Harmless to scrub on Linux (no DYLD_*
    // vars exist there), so it is applied unconditionally.
    if (has_prefix(name, "AWS_") || has_prefix(name, "GITHUB_") ||
        has_prefix(name, "GOOGLE_") || has_prefix(name, "OPENAI_") ||
        has_prefix(name, "ANTHROPIC_") || has_prefix(name, "DYLD_")) {
        return true;
    }
    // Exact-name rules.
    if (name == "KUBECONFIG" || name == "SSH_AUTH_SOCK" ||
        name == "DOCKER_HOST" || name == "NPM_TOKEN" || name == "PYPI_TOKEN") {
        return true;
    }
    return false;
}

EnvResolution resolve_env(const std::map<std::string, std::string>& parent,
                          const std::vector<std::string>& allow_env,
                          const std::vector<std::pair<std::string, std::string>>& set_env,
                          const std::map<std::string, std::string>& defaults,
                          bool /*strict*/,
                          const EnvPolicy& policy) {
    EnvResolution out;

    // A name whose REAL parent VALUE must never be copied into the child, so it is
    // refused entry from BOTH the base allowlist (PATH/TERM) and --allow-env and
    // therefore lands in `scrubbed`. Three sources, all strong enough to override an
    // explicit --allow-env:
    //   1. identity-protected names (USER/LOGNAME/HOSTNAME) — never the host's,
    //   2. ext.env_deny — user policy: never allowed even if allow-env'd,
    //   3. ext.scrub_patterns — when non-empty, a matching name is force-scrubbed.
    // The built-in is_sensitive_env heuristic is deliberately NOT part of this gate:
    // a deliberate `--allow-env OPENAI_API_KEY` must still work (only the user's own
    // deny/scrub policy is strong enough to veto an explicit allow). `--set-env` is a
    // user-chosen synthetic value and is never gated here.
    auto blocked_from_parent = [&](const std::string& name) {
        if (is_identity_protected(name)) return true;
        for (const auto& d : policy.deny) {
            if (d == name) return true;
        }
        // Only the user's OWN scrub_patterns are strong enough to veto an explicit
        // --allow-env. We deliberately match the patterns DIRECTLY here rather than
        // via is_scrubbed_name(), because is_scrubbed_name() OR-includes the built-in
        // is_sensitive_env heuristic — and per the contract (see comment above and
        // config.hpp EnvPolicy docs) that heuristic must NOT gain veto power over an
        // explicit allow just because the user happens to have set an unrelated scrub
        // pattern. So a deliberate `--allow-env OPENAI_API_KEY` still works unless the
        // user's own pattern matches it.
        for (const auto& pat : policy.scrub_patterns) {
            if (env_name_matches_glob(name, pat)) return true;
        }
        return false;
    };

    // Category of each resolved name: true => allowed (verbatim from parent),
    // false => set (synthetic value).
    std::map<std::string, bool> category;

    auto put_allowed = [&](const std::string& name, const std::string& value) {
        out.resolved[name] = value;
        category[name] = true;
    };
    auto put_set = [&](const std::string& name, const std::string& value) {
        out.resolved[name] = value;
        category[name] = false;
    };

    // 2. Base safe allowlist copied from parent if present -> allowed. A name the
    //    user's deny/scrub policy vetoes is refused even here (it then falls through
    //    to `scrubbed`). PATH/TERM never match the built-in globs, so default policy
    //    leaves this untouched.
    for (const char* name : {"PATH", "TERM"}) {
        if (blocked_from_parent(name)) continue;
        auto it = parent.find(name);
        if (it != parent.end()) {
            put_allowed(it->first, it->second);
        }
    }

    // 3. USER forced to a generic value (never leak the real username) -> set. The
    //    generic value comes from the profile (ext.username), defaulting to "user".
    put_set("USER", policy.username);

    // 4. Apply defaults (TZ, LANG, LC_ALL, ...) as set values.
    for (const auto& kv : defaults) {
        put_set(kv.first, kv.second);
    }

    // 5. --allow-env: copy from parent only if present -> allowed. Identity-
    //    protected names (USER/LOGNAME/HOSTNAME) are NEVER copied from the parent,
    //    even when explicitly allow-env'd — the real login/host name must not leak.
    //    USER keeps its generic value from step 3; LOGNAME/HOSTNAME are injected by
    //    the runner. A later --set-env for one of these still wins (step 6).
    for (const auto& name : allow_env) {
        if (blocked_from_parent(name)) continue;
        auto it = parent.find(name);
        if (it != parent.end()) {
            put_allowed(name, it->second);
        }
    }

    // 6. --set-env KEY=VALUE: assign -> set. Overrides allow-env and defaults.
    //    Later entries win over earlier ones for the same key.
    for (const auto& kv : set_env) {
        put_set(kv.first, kv.second);
    }

    // Build the allowed / set NAME lists from the final categories.
    for (const auto& kv : category) {
        if (kv.second) {
            out.allowed.push_back(kv.first);
        } else {
            out.set.push_back(kv.first);
        }
    }

    // 7. scrubbed = every parent name NOT in resolved, sorted.
    for (const auto& kv : parent) {
        if (out.resolved.find(kv.first) == out.resolved.end()) {
            out.scrubbed.push_back(kv.first);
        }
    }
    std::sort(out.scrubbed.begin(), out.scrubbed.end());

    return out;
}

}  // namespace raincoat
