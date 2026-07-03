// Raincoat — toml: minimal parser sized to the config schema. TomlTable lives here.
#pragma once

#include <map>
#include <optional>
#include <string>
#include <vector>

namespace raincoat {

class TomlTable {
public:
    std::optional<bool> get_bool(const std::string& dotted_key) const;
    std::optional<std::string> get_string(const std::string& dotted_key) const;
    std::optional<std::vector<std::string>> get_string_array(const std::string& dotted_key) const;
    std::map<std::string, std::string> get_table_of_strings(const std::string& table) const;

    // True if `dotted_key` was present in the source with ANY scalar/bool/array
    // value type. Lets callers distinguish "absent" from "present but wrong
    // type": e.g. `strict = "true"` yields get_bool("strict") == nullopt yet
    // contains("strict") == true, so the profile layer can reject it instead of
    // silently treating strict as unset (a privacy downgrade).
    bool contains(const std::string& dotted_key) const;

    // Backing storage for parsed values (implementation detail; kept public-ish so the
    // parser in toml.cpp can populate it). Real logic arrives in a later phase.
    std::map<std::string, std::string> scalars_;                       // dotted_key -> raw string
    std::map<std::string, bool> bools_;                                // dotted_key -> bool
    std::map<std::string, std::vector<std::string>> arrays_;           // dotted_key -> array
    std::map<std::string, std::map<std::string, std::string>> tables_; // table -> (key -> value)
};

std::optional<TomlTable> parse_toml(const std::string& text, std::string& err);

}  // namespace raincoat
