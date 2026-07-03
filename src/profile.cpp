// Raincoat — profile: load + merge profile options.
//
// load_profile parses the profile file via the shared toml module (toml::parse_toml
// + the typed getters) and maps the parsed values onto an Options struct following
// docs/DESIGN.md semantics. Routing through the toml module means multiline arrays
// and idiomatic dotted keys (e.g. `env.TZ = "UTC"`) load correctly, and the profile
// no longer carries a second, divergent TOML parser.
// merge combines a profile Options with a CLI Options where CLI wins.
#include "profile.hpp"

#include <fstream>
#include <set>
#include <sstream>

#include "toml.hpp"

namespace raincoat {

std::optional<Options> load_profile(const std::string& path, std::string& err) {
    err.clear();
    std::ifstream ifs(path, std::ios::binary);
    if (!ifs) {
        err = "Error: could not open profile: " + path;
        return std::nullopt;
    }
    std::ostringstream buf;
    buf << ifs.rdbuf();
    std::string text = buf.str();

    // Parse with the shared TOML module. On malformed input it sets `err` and
    // returns nullopt; propagate that verbatim.
    auto parsed = parse_toml(text, err);
    if (!parsed.has_value()) {
        return std::nullopt;
    }
    const TomlTable& t = *parsed;

    Options o;

    // strict (bool)
    // A `strict` key of a non-bool type (quoted-boolean string like
    // `strict = "true"`, integer, or array) must be rejected with an error, NOT
    // silently ignored. If it fell through, o.strict would stay false /
    // strict_set false and the runner would treat the profile as NON-strict —
    // CWD mounted read-write, network full by default, less env scrubbing. So a
    // user who writes `strict = "true"` (a plausible mistake: quoting the
    // boolean) intending to ENABLE strict isolation would silently get the LESS
    // protective mode. contains() lets us tell "present-but-wrong-type" apart
    // from "absent" (get_bool returns nullopt for both).
    if (auto b = t.get_bool("strict"); b.has_value()) {
        o.strict = *b;
        o.strict_set = true;
    } else if (t.contains("strict")) {
        err = "Error: invalid strict value in profile (expected true|false)";
        return std::nullopt;
    }

    // network (string -> NetMode)
    // A `network` key of a non-string type (bool token like `network = false`,
    // integer, or array) must be rejected with the same error as a bad string,
    // NOT silently ignored. If it fell through, o.net would stay unset and the
    // non-strict runner defaults to FULL open networking — so `network = false`
    // (a plausible attempt to disable networking) would silently yield OPEN
    // networking.
    if (auto s = t.get_string("network"); s.has_value()) {
        auto m = net_mode_from_string(*s);
        // The MVP implements only full|off. net_mode_from_string also accepts the
        // reserved "allowlist"/"ask" modes, but net_guard emits no --unshare-net
        // for those, so accepting them would silently yield FULL open networking.
        // Reject them here exactly as the CLI parser does.
        if (!m.has_value() || (*m != NetMode::Full && *m != NetMode::Off)) {
            err = "Error: invalid network value in profile: \"" + *s +
                  "\" (expected full|off)";
            return std::nullopt;
        }
        o.net = *m;
    } else if (t.contains("network")) {
        err = "Error: invalid network value in profile (expected full|off)";
        return std::nullopt;
    }

    // allow_read / allow_write / allow_env (string arrays)
    if (auto a = t.get_string_array("allow_read"); a.has_value()) o.allow_read = *a;
    if (auto a = t.get_string_array("allow_write"); a.has_value()) o.allow_write = *a;
    if (auto a = t.get_string_array("allow_env"); a.has_value()) o.allow_env = *a;

    // [env] table -> env_defaults
    // Members of the [env] table are string values only. A non-string member
    // (e.g. `DEBUG = true` or an array under [env]) parses into the toml table's
    // bools_/arrays_ under the dotted name "env.<key>" and never reaches
    // get_table_of_strings("env"), so it would silently vanish from env_defaults.
    // Reject such keys with a clear error rather than dropping them. (Legitimate
    // top-level keys such as `allow_env` do not share the "env." dotted prefix.)
    for (const auto& kv : t.bools_) {
        if (kv.first.rfind("env.", 0) == 0) {
            err = "Error: invalid value for [env]." + kv.first.substr(4) +
                  " in profile (expected a string)";
            return std::nullopt;
        }
    }
    for (const auto& kv : t.arrays_) {
        if (kv.first.rfind("env.", 0) == 0) {
            err = "Error: invalid value for [env]." + kv.first.substr(4) +
                  " in profile (expected a string)";
            return std::nullopt;
        }
    }
    o.env_defaults = t.get_table_of_strings("env");

    // [fontconfig].enabled -> optional<bool>
    // As with `strict`, a wrong-typed fontconfig.enabled (string like
    // `enabled = "false"`, or an array) misses the bool lookup and would be
    // silently ignored. Reject it explicitly instead of dropping it.
    if (auto b = t.get_bool("fontconfig.enabled"); b.has_value()) {
        o.fontconfig_enabled = *b;
    } else if (t.contains("fontconfig.enabled")) {
        err = "Error: invalid fontconfig.enabled value in profile (expected true|false)";
        return std::nullopt;
    }

    // [audit].log_file -> audit_log
    // As with the other typed keys, a wrong-typed audit.log_file (array like
    // `log_file = ["/var/log/rc.log"]`, or a bool) misses the string lookup and
    // would be silently ignored, leaving audit_log unset. SPEC's default audit
    // location is .raincoat/audit.log inside the project dir, which non-strict
    // mode mounts read-write and exposes to the untrusted child, so a user who
    // points the audit log at a tamper-proof path but mistypes the value type
    // silently gets the child-writable default. Reject it explicitly.
    if (auto s = t.get_string("audit.log_file"); s.has_value()) {
        o.audit_log = *s;
    } else if (t.contains("audit.log_file")) {
        err = "Error: invalid audit.log_file value in profile (expected a string)";
        return std::nullopt;
    }

    // set_env is CLI-only: never read from a profile (intentionally ignored).

    return o;
}

namespace {

void union_strings(std::vector<std::string>& out,
                   const std::vector<std::string>& a,
                   const std::vector<std::string>& b) {
    std::set<std::string> seen;
    for (const auto& x : a) if (seen.insert(x).second) out.push_back(x);
    for (const auto& x : b) if (seen.insert(x).second) out.push_back(x);
}

}  // namespace

Options merge(const Options& profile, const Options& cli) {
    Options m;

    // Lists: unioned profile-first, de-duplicated.
    union_strings(m.allow_read, profile.allow_read, cli.allow_read);
    union_strings(m.allow_write, profile.allow_write, cli.allow_write);
    union_strings(m.allow_env, profile.allow_env, cli.allow_env);

    // set_env: unioned profile-first, de-duplicated by (key,value).
    {
        std::set<std::pair<std::string, std::string>> seen;
        for (const auto& kv : profile.set_env)
            if (seen.insert(kv).second) m.set_env.push_back(kv);
        for (const auto& kv : cli.set_env)
            if (seen.insert(kv).second) m.set_env.push_back(kv);
    }

    // strict: CLI wins when it explicitly set the flag, else profile.
    if (cli.strict_set) {
        m.strict = cli.strict;
    } else {
        m.strict = profile.strict;
    }
    m.strict_set = cli.strict_set || profile.strict_set;

    // net: CLI value wins when present, else profile.
    m.net = cli.net.has_value() ? cli.net : profile.net;

    // workdir / audit_log: CLI when present, else profile.
    m.workdir = cli.workdir.has_value() ? cli.workdir : profile.workdir;
    m.audit_log = cli.audit_log.has_value() ? cli.audit_log : profile.audit_log;
    m.profile_path = cli.profile_path.has_value() ? cli.profile_path : profile.profile_path;

    // keep_temp: CLI wins when explicitly set, else profile.
    if (cli.keep_temp_set) {
        m.keep_temp = cli.keep_temp;
    } else {
        m.keep_temp = profile.keep_temp;
    }
    m.keep_temp_set = cli.keep_temp_set || profile.keep_temp_set;

    // fontconfig_enabled: CLI when present, else profile.
    m.fontconfig_enabled =
        cli.fontconfig_enabled.has_value() ? cli.fontconfig_enabled : profile.fontconfig_enabled;

    // env_defaults: profile table overlaid by cli (cli keys win).
    m.env_defaults = profile.env_defaults;
    for (const auto& kv : cli.env_defaults) m.env_defaults[kv.first] = kv.second;

    // command is a CLI concept; take CLI when present, else profile.
    m.command = !cli.command.empty() ? cli.command : profile.command;

    return m;
}

}  // namespace raincoat
