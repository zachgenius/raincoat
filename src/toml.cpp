// Raincoat — toml: minimal TOML parser sized to the config schema.
//
// Supports exactly what docs/SPEC.md's config file needs:
//   * `# comments` (full-line and inline)
//   * `key = value`
//   * booleans (true/false)
//   * "double" and 'single' quoted strings
//   * inline arrays ["a", "b"] and multiline arrays
//   * [table] and dotted [a.b] headers
// It is NOT a full TOML implementation. Malformed input is rejected with a
// helpful `err` message and a nullopt return — never a crash.
#include "toml.hpp"

namespace raincoat {

namespace {

bool is_ws(char c) { return c == ' ' || c == '\t' || c == '\r' || c == '\n'; }

std::string ltrim(const std::string& s) {
    size_t i = 0;
    while (i < s.size() && is_ws(s[i])) ++i;
    return s.substr(i);
}

std::string rtrim(const std::string& s) {
    size_t n = s.size();
    while (n > 0 && is_ws(s[n - 1])) --n;
    return s.substr(0, n);
}

std::string trim(const std::string& s) { return rtrim(ltrim(s)); }

std::vector<std::string> split_lines(const std::string& text) {
    std::vector<std::string> out;
    std::string cur;
    for (char c : text) {
        if (c == '\n') {
            out.push_back(cur);
            cur.clear();
        } else {
            cur.push_back(c);
        }
    }
    out.push_back(cur);
    return out;
}

// Outcome of trying to parse an array from an accumulated buffer.
enum class ArrScan { Ok, Incomplete, Error };

// Parse a (possibly multi-line) buffer that begins with '['. Elements must be
// quoted strings; whitespace, newlines, commas and #-comments between them are
// skipped. Returns Ok once a matching ']' is found, Incomplete if the buffer
// ends before the array closes (caller should append more lines), or Error for
// malformed content (a non-string element or a string broken by a newline).
ArrScan parse_array(const std::string& s, std::vector<std::string>& out,
                    std::string& err, size_t& close_pos) {
    out.clear();
    close_pos = std::string::npos;
    if (s.empty() || s[0] != '[') {
        err = "internal: array does not start with '['";
        return ArrScan::Error;
    }
    size_t i = 1;
    while (i < s.size()) {
        char c = s[i];
        if (is_ws(c) || c == ',') {
            ++i;
            continue;
        }
        if (c == '#') {  // comment to end of line
            while (i < s.size() && s[i] != '\n') ++i;
            continue;
        }
        if (c == ']') {
            close_pos = i;
            return ArrScan::Ok;
        }
        if (c == '"' || c == '\'') {
            char quote = c;
            size_t j = i + 1;
            std::string elem;
            bool closed = false;
            for (; j < s.size(); ++j) {
                if (s[j] == '\n') {  // basic strings cannot span lines
                    err = "unterminated string in array";
                    return ArrScan::Error;
                }
                if (s[j] == quote) {
                    closed = true;
                    break;
                }
                elem.push_back(s[j]);
            }
            if (!closed) {
                // Ran off the end of the buffer without a newline: need more.
                return ArrScan::Incomplete;
            }
            out.push_back(elem);
            i = j + 1;
            continue;
        }
        // Anything else is an unsupported array element type.
        err = "array elements must be quoted strings";
        return ArrScan::Error;
    }
    return ArrScan::Incomplete;  // no closing ']' yet
}

}  // namespace

// ---------------------------------------------------------------------------
// Typed getters
// ---------------------------------------------------------------------------

std::optional<bool> TomlTable::get_bool(const std::string& dotted_key) const {
    auto it = bools_.find(dotted_key);
    if (it == bools_.end()) return std::nullopt;
    return it->second;
}

std::optional<std::string> TomlTable::get_string(const std::string& dotted_key) const {
    auto it = scalars_.find(dotted_key);
    if (it == scalars_.end()) return std::nullopt;
    return it->second;
}

std::optional<std::vector<std::string>> TomlTable::get_string_array(
    const std::string& dotted_key) const {
    auto it = arrays_.find(dotted_key);
    if (it == arrays_.end()) return std::nullopt;
    return it->second;
}

std::map<std::string, std::string> TomlTable::get_table_of_strings(
    const std::string& table) const {
    auto it = tables_.find(table);
    if (it == tables_.end()) return {};
    return it->second;
}

bool TomlTable::contains(const std::string& dotted_key) const {
    if (scalars_.count(dotted_key) || bools_.count(dotted_key) ||
        arrays_.count(dotted_key)) {
        return true;
    }
    // Also report presence when the key was supplied as a [table] header (or a
    // dotted sub-table thereof). A guarded scalar/bool key (e.g. `network`,
    // `fontconfig.enabled`) written in table form — `[network]` — lands only in
    // tables_ and would otherwise read as ABSENT, letting a wrong-type value slip
    // past the profile's present-but-wrong-type guards and silently downgrade
    // privacy. Treat it as present-but-wrong-type so those guards fire.
    if (tables_.count(dotted_key)) return true;
    const std::string prefix = dotted_key + ".";
    for (const auto& kv : tables_) {
        if (kv.first.rfind(prefix, 0) == 0) return true;
    }
    for (const auto& kv : scalars_) {
        if (kv.first.rfind(prefix, 0) == 0) return true;
    }
    return false;
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

std::optional<TomlTable> parse_toml(const std::string& text, std::string& err) {
    err.clear();
    TomlTable table;
    std::vector<std::string> lines = split_lines(text);

    std::string prefix;  // current table prefix (empty at top level)

    auto fail = [&](const std::string& msg, size_t lineno) -> std::optional<TomlTable> {
        err = "TOML parse error (line " + std::to_string(lineno + 1) + "): " + msg;
        return std::nullopt;
    };

    size_t i = 0;
    while (i < lines.size()) {
        const std::string raw = lines[i];
        const std::string line = ltrim(raw);

        // Blank or comment-only line.
        if (line.empty() || line[0] == '#') {
            ++i;
            continue;
        }

        // Table header: [name] or [a.b].
        if (line[0] == '[') {
            size_t close = line.find(']');
            if (close == std::string::npos) {
                return fail("unterminated table header (missing ']')", i);
            }
            std::string name = trim(line.substr(1, close - 1));
            if (name.empty()) {
                return fail("empty table header", i);
            }
            // Anything after ']' must be blank or a comment.
            std::string rest = trim(line.substr(close + 1));
            if (!rest.empty() && rest[0] != '#') {
                return fail("unexpected text after table header", i);
            }
            prefix = name;
            table.tables_[prefix];  // ensure the (possibly empty) table exists
            ++i;
            continue;
        }

        // key = value.
        size_t eq = line.find('=');
        if (eq == std::string::npos) {
            return fail("expected 'key = value' (no '=' found)", i);
        }
        std::string key = trim(line.substr(0, eq));
        if (key.empty()) {
            return fail("missing key before '='", i);
        }
        std::string value = ltrim(line.substr(eq + 1));
        if (value.empty()) {
            return fail("missing value after '='", i);
        }

        std::string dotted = prefix.empty() ? key : (prefix + "." + key);
        char c0 = value[0];

        if (c0 == '"' || c0 == '\'') {
            // Quoted string on a single line.
            char quote = c0;
            size_t j = 1;
            std::string str;
            bool closed = false;
            for (; j < value.size(); ++j) {
                if (value[j] == quote) {
                    closed = true;
                    break;
                }
                str.push_back(value[j]);
            }
            if (!closed) {
                return fail("unterminated string value", i);
            }
            std::string after = trim(value.substr(j + 1));
            if (!after.empty() && after[0] != '#') {
                return fail("unexpected text after string value", i);
            }
            table.scalars_[dotted] = str;
            // Populate tables_ for any dotted key so that get_table_of_strings()
            // sees both `[env]`-header members and idiomatic root dotted keys
            // (`env.TZ = "UTC"`). Split on the LAST dot: everything before is the
            // (possibly dotted) table name, the final segment is the leaf key.
            if (size_t dot = dotted.rfind('.'); dot != std::string::npos) {
                table.tables_[dotted.substr(0, dot)][dotted.substr(dot + 1)] = str;
            }
            ++i;
            continue;
        }

        if (c0 == '[') {
            // Array — may span multiple lines.
            std::string buf = value;
            std::vector<std::string> elems;
            std::string aerr;
            size_t consumed = i;
            size_t close_pos = std::string::npos;
            ArrScan status = parse_array(buf, elems, aerr, close_pos);
            while (status == ArrScan::Incomplete) {
                ++consumed;
                if (consumed >= lines.size()) {
                    return fail("unterminated array (missing ']')", i);
                }
                buf += "\n";
                buf += lines[consumed];
                status = parse_array(buf, elems, aerr, close_pos);
            }
            if (status == ArrScan::Error) {
                return fail(aerr, i);
            }
            // Anything after the closing ']' on its line must be blank or a
            // comment — mirror the trailing-text check on string values.
            size_t rest_start = close_pos + 1;
            size_t nl = buf.find('\n', rest_start);
            std::string after =
                trim(buf.substr(rest_start, nl == std::string::npos
                                                ? std::string::npos
                                                : nl - rest_start));
            if (!after.empty() && after[0] != '#') {
                return fail("unexpected text after array", i);
            }
            table.arrays_[dotted] = elems;
            i = consumed + 1;
            continue;
        }

        // Bare token: only booleans are supported.
        std::string token = value;
        size_t hash = token.find('#');
        if (hash != std::string::npos) token = token.substr(0, hash);
        token = trim(token);
        if (token == "true") {
            table.bools_[dotted] = true;
        } else if (token == "false") {
            table.bools_[dotted] = false;
        } else {
            return fail("unsupported or unquoted value: '" + token + "'", i);
        }
        ++i;
    }

    return table;
}

}  // namespace raincoat
