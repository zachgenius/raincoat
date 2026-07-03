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

bool is_sensitive_env(const std::string& name) {
    // Suffix rules: *_TOKEN / *_SECRET / *_KEY.
    if (has_suffix(name, "_TOKEN") || has_suffix(name, "_SECRET") ||
        has_suffix(name, "_KEY")) {
        return true;
    }
    // Prefix rules (must be at the very start).
    if (has_prefix(name, "AWS_") || has_prefix(name, "GITHUB_") ||
        has_prefix(name, "GOOGLE_") || has_prefix(name, "OPENAI_") ||
        has_prefix(name, "ANTHROPIC_")) {
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
                          bool /*strict*/) {
    EnvResolution out;

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

    // 2. Base safe allowlist copied from parent if present -> allowed.
    for (const char* name : {"PATH", "TERM"}) {
        auto it = parent.find(name);
        if (it != parent.end()) {
            put_allowed(it->first, it->second);
        }
    }

    // 3. USER forced to a generic value (never leak the real username) -> set.
    put_set("USER", "user");

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
        if (is_identity_protected(name)) continue;
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
