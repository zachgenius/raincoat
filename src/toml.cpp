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

// A bare (unquoted) value is tolerated when it looks like a TOML numeric literal
// (integer/float/hex-ish: digits, sign, dot, underscore, exponent). This lets a
// rich config carry keys like `timeout_seconds = 120` WITHOUT the parser erroring,
// while still rejecting genuine bare words such as `network = full`. The value is
// stored verbatim as a scalar string; higher layers interpret it as needed.
bool looks_like_number(const std::string& s) {
    if (s.empty()) return false;
    bool has_digit = false;
    for (char c : s) {
        if (c >= '0' && c <= '9') {
            has_digit = true;
        } else if (c == '+' || c == '-' || c == '.' || c == '_' ||
                   c == 'e' || c == 'E' || c == 'x' || c == 'o' || c == 'b' ||
                   (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
            // Permitted in numeric/hex literals; a leading-digit requirement below
            // still keeps bare words like `full` from slipping through.
        } else {
            return false;
        }
    }
    // Require a leading sign or digit so alphabetic-first words are rejected.
    char c0 = s[0];
    if (!(c0 == '+' || c0 == '-' || (c0 >= '0' && c0 <= '9'))) return false;
    return has_digit;
}

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

// Normalize a raw TOML key (the text left of '='): split on unquoted dots, strip
// the surrounding quotes from each `"quoted"`/`'quoted'` segment, and reject a
// malformed bare segment (empty, or containing interior whitespace — TOML bare
// keys may not contain spaces, which would otherwise mask a dropped '=' or a
// stray two-word key). On success `out` holds the logical dotted key with quotes
// removed (so a documented `"X-Raincoat-Bridge"` header key is reachable under
// its unquoted name). Returns false and sets `err` on a malformed key.
bool normalize_key(const std::string& raw, std::string& out, std::string& err) {
    out.clear();
    std::vector<std::string> segs;
    std::string cur;
    bool in_quote = false;
    char q = 0;
    for (char c : raw) {
        if (in_quote) {
            cur.push_back(c);
            if (c == q) in_quote = false;
        } else if (c == '"' || c == '\'') {
            in_quote = true;
            q = c;
            cur.push_back(c);
        } else if (c == '.') {
            segs.push_back(cur);
            cur.clear();
        } else {
            cur.push_back(c);
        }
    }
    if (in_quote) {
        err = "unterminated quoted key";
        return false;
    }
    segs.push_back(cur);

    std::string result;
    for (const std::string& s : segs) {
        std::string seg = trim(s);
        if (seg.size() >= 2 &&
            ((seg.front() == '"' && seg.back() == '"') ||
             (seg.front() == '\'' && seg.back() == '\''))) {
            seg = seg.substr(1, seg.size() - 2);  // strip surrounding quotes
        } else {
            if (seg.empty()) {
                err = "missing key before '='";
                return false;
            }
            for (char c : seg) {
                if (is_ws(c)) {
                    err = "invalid key (contains whitespace)";
                    return false;
                }
            }
        }
        if (!result.empty()) result.push_back('.');
        result += seg;
    }
    out = result;
    return true;
}

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

std::vector<TomlTable> TomlTable::get_table_array(const std::string& dotted_name) const {
    auto it = array_tables_.find(dotted_name);
    if (it == array_tables_.end()) return {};
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
    if (tables_.count(dotted_key) || array_tables_.count(dotted_key)) return true;
    const std::string prefix = dotted_key + ".";
    for (const auto& kv : tables_) {
        if (kv.first.rfind(prefix, 0) == 0) return true;
    }
    for (const auto& kv : scalars_) {
        if (kv.first.rfind(prefix, 0) == 0) return true;
    }
    // bools_ and arrays_ must be scanned too: a section whose ONLY members are
    // booleans or arrays (e.g. `browser.isolate = true`, `network_policy.deny = [..]`)
    // stores its leaves ONLY here, never in tables_/scalars_. Omitting these loops made
    // contains("browser") read as ABSENT for the dotted-key form even though it is
    // identical TOML to the [browser] header form — so a reserved section configured
    // that way was silently swallowed with no honest audit disclosure.
    for (const auto& kv : bools_) {
        if (kv.first.rfind(prefix, 0) == 0) return true;
    }
    for (const auto& kv : arrays_) {
        if (kv.first.rfind(prefix, 0) == 0) return true;
    }
    for (const auto& kv : array_tables_) {
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

    // Where subsequent `key = value` lines and `[sub]` headers land. Normally the
    // root table; while inside a `[[array.of.tables]]` entry it points at that
    // entry so its keys and nested sub-tables stay self-contained.
    TomlTable* active = &table;
    std::string prefix;          // dotted prefix within `active` (empty = its root)

    // A STACK of currently-open array-of-tables scopes, outermost first. Each
    // scope names the array's full dotted name, the table that OWNS the array
    // (root for a top-level [[a]], or a parent entry for a nested [[a.b]]), and
    // the relative key of the array within that owner. Tracking the full nesting
    // — not just one open name — lets a header that re-opens a SHALLOWER level
    // (e.g. returning to [[a.b]] after descending into [[a.b.c]]) resolve to the
    // correct parent container instead of silently stranding the entry at root.
    //
    // Pointer stability: a scope's `container` can only be invalidated by an
    // append to its OWNER's array vector, which happens exactly when a sibling is
    // added at that owner's level — and that sibling header first pops every
    // deeper scope. So while a scope remains on the stack, its container pointer
    // stays valid.
    struct ArrayScope {
        std::string name;       // full dotted name of the [[array-of-tables]]
        TomlTable* container;   // table whose array_tables_[rel] holds the entries
        std::string rel;        // key of the array within `container`
    };
    std::vector<ArrayScope> array_stack;

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

        // Array-of-tables header: [[name]]. Each occurrence starts a fresh entry.
        if (line.size() >= 2 && line[0] == '[' && line[1] == '[') {
            size_t close = line.find("]]");
            if (close == std::string::npos) {
                return fail("unterminated array-of-tables header (missing ']]')", i);
            }
            std::string name = trim(line.substr(2, close - 2));
            if (name.empty()) {
                return fail("empty array-of-tables header", i);
            }
            std::string rest = trim(line.substr(close + 2));
            if (!rest.empty() && rest[0] != '#') {
                return fail("unexpected text after array-of-tables header", i);
            }
            // Pop every open scope that is neither this array itself nor an
            // ancestor of it. Returning to a shallower level (e.g. [[a.b]] after
            // [[a.b.c]]) thus lands on the right parent instead of the deepest
            // open scope.
            while (!array_stack.empty()) {
                const std::string& top = array_stack.back().name;
                if (name == top || name.rfind(top + ".", 0) == 0) break;
                array_stack.pop_back();
            }
            // Decide the container that owns this entry's array and its relative
            // key, extending the stack for a newly-entered nesting level.
            TomlTable* container;
            std::string rel;
            if (!array_stack.empty() && array_stack.back().name == name) {
                // Repeat of an already-open array: a sibling entry in the same
                // container.
                container = array_stack.back().container;
                rel = array_stack.back().rel;
            } else if (!array_stack.empty()) {
                // Nested array-of-tables inside the current entry, e.g.
                // [[fruit.variety]] under an open [[fruit]]. It belongs to that
                // entry's own array_tables_ under the relative sub-name.
                ArrayScope& top = array_stack.back();
                container = &top.container->array_tables_[top.rel].back();
                rel = name.substr(top.name.size() + 1);
                array_stack.push_back({name, container, rel});
            } else {
                // A new top-level array-of-tables at the document root.
                container = &table;
                rel = name;
                array_stack.push_back({name, container, rel});
            }
            // A name cannot be both an array-of-tables and a plain table.
            if (container->tables_.count(rel)) {
                return fail("'" + name + "' already defined as a table", i);
            }
            container->array_tables_[rel].emplace_back();
            active = &container->array_tables_[rel].back();
            prefix.clear();
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
            // A `[array.name.sub]` header appearing while `[[array.name]]` is open
            // is a sub-table of the current entry (e.g. [egress.bridge.inject_headers]
            // under [[egress.bridge]]). Keep `active` on the entry and store the
            // remainder as a prefix relative to it. Otherwise it's a top-level table:
            // reset to the root and close any open array-of-tables scope.
            if (!array_stack.empty() &&
                name.rfind(array_stack.back().name + ".", 0) == 0) {
                ArrayScope& top = array_stack.back();
                active = &top.container->array_tables_[top.rel].back();
                prefix = name.substr(top.name.size() + 1);
            } else {
                active = &table;
                prefix = name;
                array_stack.clear();
            }
            // A name cannot be both a plain table and an array-of-tables.
            if (active->array_tables_.count(prefix)) {
                return fail("'" + name + "' already defined as an array-of-tables", i);
            }
            // Reject a table re-opened after it was already populated (a
            // duplicate definition — same downgrade risk as a duplicate key).
            if (auto tit = active->tables_.find(prefix);
                tit != active->tables_.end() && !tit->second.empty()) {
                return fail("duplicate table '" + prefix + "'", i);
            }
            active->tables_[prefix];  // ensure the (possibly empty) table exists
            ++i;
            continue;
        }

        // key = value.
        size_t eq = line.find('=');
        if (eq == std::string::npos) {
            return fail("expected 'key = value' (no '=' found)", i);
        }
        std::string key;
        if (std::string kerr; !normalize_key(line.substr(0, eq), key, kerr)) {
            return fail(kerr, i);
        }
        if (key.empty()) {
            return fail("missing key before '='", i);
        }
        std::string value = ltrim(line.substr(eq + 1));
        if (value.empty()) {
            return fail("missing value after '='", i);
        }

        std::string dotted = prefix.empty() ? key : (prefix + "." + key);

        // Reject a duplicate key. TOML forbids defining a key twice, and for a
        // privacy tool last-value-wins is a silent downgrade vector (a later
        // `strict = false` overriding an earlier `strict = true` with no error,
        // slipping past the profile layer's wrong-type guards because the value
        // is a valid bool — just the wrong one). Also reject a key that collides
        // with an already-defined [table] of the same dotted name.
        if (active->scalars_.count(dotted) || active->bools_.count(dotted) ||
            active->arrays_.count(dotted) || active->tables_.count(dotted)) {
            return fail("duplicate key '" + dotted + "'", i);
        }

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
            active->scalars_[dotted] = str;
            // Populate tables_ for any dotted key so that get_table_of_strings()
            // sees both `[env]`-header members and idiomatic root dotted keys
            // (`env.TZ = "UTC"`). Split on the LAST dot: everything before is the
            // (possibly dotted) table name, the final segment is the leaf key.
            if (size_t dot = dotted.rfind('.'); dot != std::string::npos) {
                active->tables_[dotted.substr(0, dot)][dotted.substr(dot + 1)] = str;
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
            active->arrays_[dotted] = elems;
            i = consumed + 1;
            continue;
        }

        // Bare token: booleans, plus tolerated numeric literals (stored as scalars
        // so a rich config's `timeout_seconds = 120` never errors). Genuine bare
        // words (`network = full`) remain rejected as malformed.
        std::string token = value;
        size_t hash = token.find('#');
        if (hash != std::string::npos) token = token.substr(0, hash);
        token = trim(token);
        if (token == "true") {
            active->bools_[dotted] = true;
        } else if (token == "false") {
            active->bools_[dotted] = false;
        } else if (looks_like_number(token)) {
            active->scalars_[dotted] = token;
            if (size_t dot = dotted.rfind('.'); dot != std::string::npos) {
                active->tables_[dotted.substr(0, dot)][dotted.substr(dot + 1)] = token;
            }
        } else {
            return fail("unsupported or unquoted value: '" + token + "'", i);
        }
        ++i;
    }

    return table;
}

}  // namespace raincoat
