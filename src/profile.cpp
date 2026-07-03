// Raincoat — profile: load + merge profile options.
//
// load_profile parses the profile file via the shared toml module (toml::parse_toml
// + the typed getters) and maps the parsed values onto an Options struct following
// docs/DESIGN.md semantics. Routing through the toml module means multiline arrays
// and idiomatic dotted keys (e.g. `env.TZ = "UTC"`) load correctly, and the profile
// no longer carries a second, divergent TOML parser.
// merge combines a profile Options with a CLI Options where CLI wins.
#include "profile.hpp"

#include <exception>
#include <fstream>
#include <set>
#include <sstream>
#include <utility>

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
        const std::string& nv = *s;
        if (nv == "off") {
            o.net = NetMode::Off;
        } else if (nv == "full") {
            o.net = NetMode::Full;
        } else if (nv == "proxy" || nv == "bridge" || nv == "guarded") {
            // Reserved network modes from the rich sectioned schema. The MVP has no
            // NetMode for these and net_guard emits no enforcement for them, so we do
            // NOT set o.net (leaving it unset). Instead record the requested mode in
            // ext.reserved_net_mode so resolve_config fails CLOSED — falling back to
            // NetMode::Off regardless of strict, never to Full — because the user asked
            // to CONSTRAIN egress and unrestricted networking is the opposite of that
            // intent. Also record an honest audit note so the behavior is not silently
            // misrepresented.
            o.ext.reserved_net_mode = nv;
            // Record a load-time placeholder note only. The ACTUAL network outcome
            // depends on resolution: an explicit `--net full` can override the
            // fail-closed fallback (options.net wins over reserved_net_mode in
            // resolve_config), in which case the child gets FULL egress. Baking a
            // static "fails closed to off" claim here would make the persisted audit
            // lie whenever that override fires. resolve_config reconciles this note
            // with the resolved cfg.net, so keep it outcome-free here.
            o.ext.reserved_notes.push_back(
                "network mode \"" + nv + "\" is not yet enforced (phase 2)");
        } else {
            // allowlist/ask/banana/... : genuinely invalid. Reject exactly as before so
            // an unimplemented/typo mode never silently yields FULL open networking.
            err = "Error: invalid network value in profile: \"" + nv +
                  "\" (expected full|off)";
            return std::nullopt;
        }
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

    // -----------------------------------------------------------------------
    // Rich sectioned schema (phase 1.5). Everything below is TOLERANT: absent
    // sections leave the MVP defaults; unknown keys/sections are ignored (never
    // fatal). Nested sections take precedence over the equivalent flat top-level
    // keys. A top-level `set_env` array is still ignored (CLI-only), but the
    // structured `[environment.set]` table DOES populate set_env per DESIGN.md.
    // -----------------------------------------------------------------------

    // Small helper: set a backend bool from `key` when present.
    auto set_backend_bool = [&](const std::string& key, bool& dst) {
        if (auto b = t.get_bool(key); b.has_value()) dst = *b;
    };

    // top-level: profile_name / keep_temp / workdir.
    if (auto s = t.get_string("profile_name"); s.has_value()) o.ext.profile_name = *s;
    if (auto b = t.get_bool("keep_temp"); b.has_value()) {
        o.keep_temp = *b;
        o.keep_temp_set = true;
    }
    if (auto s = t.get_string("workdir"); s.has_value()) o.workdir = *s;

    // [identity] -> ext identity + env defaults (TZ/LANG/LC_ALL/LANGUAGE).
    if (auto s = t.get_string("identity.username"); s.has_value()) o.ext.username = *s;
    if (auto s = t.get_string("identity.hostname"); s.has_value()) o.ext.hostname = *s;
    if (auto s = t.get_string("identity.home"); s.has_value()) o.ext.home = *s;
    if (auto s = t.get_string("identity.timezone"); s.has_value())
        o.env_defaults["TZ"] = *s;
    if (auto s = t.get_string("identity.locale"); s.has_value()) {
        o.env_defaults["LANG"] = *s;
        o.env_defaults["LC_ALL"] = *s;
    }
    if (auto s = t.get_string("identity.language"); s.has_value())
        o.env_defaults["LANGUAGE"] = *s;

    // [environment]: allow -> allow_env (overrides flat), deny -> ext.env_deny,
    // scrub_patterns -> ext.scrub_patterns, [environment.set] -> set_env.
    if (auto a = t.get_string_array("environment.allow"); a.has_value())
        o.allow_env = *a;
    if (auto a = t.get_string_array("environment.deny"); a.has_value())
        o.ext.env_deny = *a;
    if (auto a = t.get_string_array("environment.scrub_patterns"); a.has_value())
        o.ext.scrub_patterns = *a;
    for (const auto& kv : t.get_table_of_strings("environment.set"))
        o.set_env.emplace_back(kv.first, kv.second);

    // [filesystem]: nested allow_read/allow_write override the flat top-level lists;
    // deny -> ext.fs_deny; mode == "deny-by-default" -> ext.fs_deny_by_default;
    // [filesystem.tripwire] -> ext.tripwire_*.
    if (auto a = t.get_string_array("filesystem.allow_read"); a.has_value())
        o.allow_read = *a;
    if (auto a = t.get_string_array("filesystem.allow_write"); a.has_value())
        o.allow_write = *a;
    if (auto a = t.get_string_array("filesystem.deny"); a.has_value())
        o.ext.fs_deny = *a;
    if (auto s = t.get_string("filesystem.mode"); s.has_value())
        o.ext.fs_deny_by_default = (*s == "deny-by-default");
    if (auto b = t.get_bool("filesystem.tripwire.enabled"); b.has_value())
        o.ext.tripwire_enabled = *b;
    if (auto a = t.get_string_array("filesystem.tripwire.fake_sensitive_files");
        a.has_value())
        o.ext.tripwire_files = *a;

    // [backend] -> ext.backend (start from the MVP defaults, override what is set).
    if (auto s = t.get_string("backend.bwrap_path"); s.has_value())
        o.ext.backend.bwrap_path = *s;
    set_backend_bool("backend.unshare_user", o.ext.backend.unshare_user);
    set_backend_bool("backend.unshare_pid", o.ext.backend.unshare_pid);
    set_backend_bool("backend.unshare_ipc", o.ext.backend.unshare_ipc);
    set_backend_bool("backend.unshare_uts", o.ext.backend.unshare_uts);
    set_backend_bool("backend.unshare_cgroup", o.ext.backend.unshare_cgroup);
    set_backend_bool("backend.unshare_net_when_off",
                     o.ext.backend.unshare_net_when_off);
    set_backend_bool("backend.mount_proc", o.ext.backend.mount_proc);
    set_backend_bool("backend.mount_dev", o.ext.backend.mount_dev);
    set_backend_bool("backend.mount_tmpfs_tmp", o.ext.backend.mount_tmpfs_tmp);
    set_backend_bool("backend.die_with_parent", o.ext.backend.die_with_parent);
    set_backend_bool("backend.seccomp", o.ext.backend.seccomp);  // reserved

    // [init].create_dirs -> ext.init_create_dirs.
    if (auto a = t.get_string_array("init.create_dirs"); a.has_value())
        o.ext.init_create_dirs = *a;

    // [report]: latest_log -> ext.report_log, playful_summary -> ext.playful_report.
    if (auto s = t.get_string("report.latest_log"); s.has_value())
        o.ext.report_log = *s;
    if (auto b = t.get_bool("report.playful_summary"); b.has_value())
        o.ext.playful_report = *b;

    // [proxy]: when enabled, inject non-empty proxy vars into set_env. This is a
    // MECHANISM distinct from the reserved network=proxy MODE above.
    if (t.get_bool("proxy.enabled").value_or(false)) {
        for (const char* key : {"http_proxy", "https_proxy", "all_proxy", "no_proxy"}) {
            if (auto v = t.get_string(std::string("proxy.") + key);
                v.has_value() && !v->empty()) {
                o.set_env.emplace_back(key, *v);
            }
        }
    }

    // RESERVED sections: parsed + tolerated, NOT enforced. Record honest audit notes.
    // [backend].seccomp is accepted and carried in ext.backend.seccomp, but bwrap emits
    // no seccomp filter for it (see DESIGN.md RESERVED set). Disclose it so the audit
    // never silently implies syscall hardening that is not actually applied.
    if (t.get_bool("backend.seccomp").value_or(false)) {
        o.ext.reserved_notes.push_back(
            "seccomp filter requested but not yet enforced (reserved)");
    }
    // [egress] + [[egress.bridge]] -> ext.egress (EgressConfig). Unlike the
    // browser/dns/network_policy sections below, egress forwarding LANDS this phase,
    // so this is REAL parsed config now — NOT a reserved note. The bridge module
    // (host-side listeners + HTTP forwarding) consumes ext.egress; the profile layer
    // only has to map the schema faithfully and stay tolerant of unknown keys.
    if (t.contains("egress")) {
        EgressConfig& eg = o.ext.egress;

        // [egress].* scalars/bools. Absent keys keep the struct's defaults.
        if (auto s = t.get_string("egress.mode"); s.has_value()) eg.mode = *s;
        if (auto b = t.get_bool("egress.hide_upstreams_from_child"); b.has_value())
            eg.hide_upstreams_from_child = *b;
        if (auto b = t.get_bool("egress.redact_upstreams_in_audit"); b.has_value())
            eg.redact_upstreams_in_audit = *b;
        if (auto b = t.get_bool("egress.log_request_bodies"); b.has_value())
            eg.log_request_bodies = *b;
        if (auto b = t.get_bool("egress.log_response_bodies"); b.has_value())
            eg.log_response_bodies = *b;
        if (auto b = t.get_bool("egress.streaming"); b.has_value()) eg.streaming = *b;
        // timeout_seconds is an integer; the toml module stores numeric scalars as
        // their raw source text, so parse it defensively and ignore a non-numeric
        // value (keeps the default rather than aborting the whole profile load).
        if (auto s = t.get_string("egress.timeout_seconds"); s.has_value()) {
            try {
                eg.timeout_seconds = std::stoi(*s);
            } catch (const std::exception&) {
                // leave the default; tolerating unknown/odd values, never fatal.
            }
        }
        // CLAMP to a sane floor. A value <= 0 would disable SO_RCVTIMEO and the
        // slowloris wall-clock deadline in the bridge (read_request_head /
        // handle_connection). Because an active egress bridge SHARES the host
        // network namespace, ANY local process can connect to the loopback bridge
        // and dribble a request; a disabled timeout pins a worker thread forever and
        // EgressServer::stop() then blocks run teardown (and SIGINT cleanup) waiting
        // on active_conns_. Never allow a non-positive timeout to reach the bridge.
        if (eg.timeout_seconds < 1) eg.timeout_seconds = 1;

        // [[egress.bridge]] array-of-tables -> one EgressBridge per entry, in order.
        for (const TomlTable& bt : t.get_table_array("egress.bridge")) {
            EgressBridge br;
            if (auto s = bt.get_string("name"); s.has_value()) br.name = *s;
            if (auto s = bt.get_string("env"); s.has_value()) br.env = *s;
            if (auto s = bt.get_string("child_endpoint"); s.has_value())
                br.child_endpoint = *s;
            if (auto s = bt.get_string("upstream_endpoint"); s.has_value())
                br.upstream_endpoint = *s;
            if (auto b = bt.get_bool("hide_upstream"); b.has_value())
                br.hide_upstream = *b;
            if (auto b = bt.get_bool("preserve_host"); b.has_value())
                br.preserve_host = *b;
            if (auto b = bt.get_bool("preserve_path"); b.has_value())
                br.preserve_path = *b;
            if (auto b = bt.get_bool("preserve_query"); b.has_value())
                br.preserve_query = *b;
            if (auto b = bt.get_bool("preserve_method"); b.has_value())
                br.preserve_method = *b;
            if (auto a = bt.get_string_array("strip_headers"); a.has_value())
                br.strip_headers = *a;
            // [egress.bridge.inject_headers] is a sub-table on the entry: name->value
            // header pairs added to the upstream request.
            for (const auto& kv : bt.get_table_of_strings("inject_headers"))
                br.inject_headers.emplace_back(kv.first, kv.second);
            eg.bridges.push_back(std::move(br));
        }

        // enabled only when the bridge mode is active AND at least one bridge exists.
        // Any other mode (disabled/proxy/guarded) or an empty bridge list leaves the
        // forwarding path OFF, matching EGRESS.md's MVP scope (bridge mode only).
        eg.enabled = (eg.mode == "bridge") && !eg.bridges.empty();

        // FAIL CLOSED for a RESTRICTIVE egress intent that did NOT actually activate.
        // A profile that asks for a constraining egress mode ("bridge"/"proxy"/"guarded")
        // but does not activate the forwarding path (e.g. mode="bridge" with ZERO bridges,
        // or an unimplemented proxy/guarded mode) has expressed a clear intent to CONSTRAIN
        // the network. Left alone, resolve_config's default would hand a non-strict run FULL
        // open networking (shared host net) — the exact OPPOSITE of that intent, and a silent
        // fail-OPEN downgrade. Instead record it as a reserved (unenforced) network mode so
        // resolve_config falls back to NetMode::Off (never Full) and the runner warns on
        // stderr. Only when egress did NOT actually activate; an active bridge intentionally
        // shares the host net (handled separately). Do not clobber a mode already recorded by
        // the top-level `network` key.
        if (!eg.enabled && !o.ext.reserved_net_mode.has_value() &&
            (eg.mode == "bridge" || eg.mode == "proxy" || eg.mode == "guarded")) {
            o.ext.reserved_net_mode = eg.mode;
            o.ext.reserved_notes.push_back(
                "network mode \"" + eg.mode + "\" is not yet enforced (phase 2)");
        }
    }
    if (t.contains("browser")) {
        o.ext.reserved_notes.push_back(
            "browser isolation configured — not yet enforced (phase 2)");
    }
    if (t.contains("dns")) {
        o.ext.reserved_notes.push_back(
            "dns override configured — not yet enforced (phase 2)");
    }
    if (t.contains("network_policy")) {
        o.ext.reserved_notes.push_back(
            "network_policy configured — not yet enforced (phase 2)");
    }

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

    // ext (rich sectioned config): the CLI has no way to populate ExtendedConfig
    // today, so the profile's ext flows through unchanged. Scalar CLI overrides
    // above (strict/net/workdir/audit/keep_temp/fontconfig) still win; the ext
    // carries only profile-derived, forward-compatible options. If a CLI ext ever
    // appears, this is the seam to merge it field-by-field.
    m.ext = profile.ext;

    return m;
}

}  // namespace raincoat
