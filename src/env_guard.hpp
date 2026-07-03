// Raincoat — env_guard: environment scrubbing / resolution.
#pragma once

#include <map>
#include <string>
#include <utility>
#include <vector>

#include "config.hpp"

namespace raincoat {

bool is_sensitive_env(const std::string& name);

// Glob-ish match for an environment variable NAME against a single pattern. Supports
// `*` (any run, including empty) and `?` (exactly one character); every other
// character is literal. Case-sensitive, matching is_sensitive_env's conventions.
// Used to apply ext.scrub_patterns like "AWS_*" / "*_TOKEN".
bool env_name_matches_glob(const std::string& name, const std::string& pattern);

// True when `name` should be treated as sensitive: it matches the built-in
// is_sensitive_env defaults OR (when `patterns` is non-empty) any of the supplied
// glob patterns. This is how ext.scrub_patterns EXTEND the built-in defaults.
bool is_scrubbed_name(const std::string& name, const std::vector<std::string>& patterns);

// resolve_env now takes an optional EnvPolicy (from ExtendedConfig) as a trailing
// parameter. A default-constructed EnvPolicy reproduces the original MVP behavior,
// so existing 5-argument call sites/tests are unchanged.
EnvResolution resolve_env(const std::map<std::string, std::string>& parent,
                          const std::vector<std::string>& allow_env,
                          const std::vector<std::pair<std::string, std::string>>& set_env,
                          const std::map<std::string, std::string>& defaults,
                          bool strict,
                          const EnvPolicy& policy = {});

}  // namespace raincoat
