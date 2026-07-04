// Raincoat — audit: audit record + formatting. AuditRecord lives here.
#pragma once

#include <optional>
#include <string>
#include <vector>

#include "config.hpp"

namespace raincoat {

// One active egress bridge's audit summary. Carries only child-safe values by
// default: the real upstream is stored in `upstream` ONLY when redaction is off
// (redact_upstreams_in_audit == false). By default `upstream_hidden` is true and
// `upstream` is empty so the real upstream URL is never persisted.
struct EgressBridgeAudit {
    std::string name;            // bridge name
    std::string child_endpoint;  // child-visible endpoint (safe to log)
    std::string injected_env;    // env var name injected into the child
    bool upstream_hidden = true; // true => "Upstream endpoint: hidden"
    std::string upstream;        // real upstream, populated ONLY when not redacted
};

struct AuditRecord {
    std::string command_line;
    bool strict = false;
    NetMode net = NetMode::Full;
    std::string fake_home;
    std::string workdir;
    std::vector<Mount> mounts;
    EnvResolution env;
    FontStatus font = FontStatus::Disabled;
    std::string timezone;
    std::string locale;
    std::string bwrap_command;

    // Rich sectioned-config transparency (all optional; empty => not printed):
    //   profile_name        -> the [profile_name] the run was configured from.
    //   active_policy_notes -> short, secret-free notes about which extended policies
    //                          are ACTIVE this run (env_deny/fs_deny/scrub_patterns/
    //                          backend overrides/tripwire). NAMES/counts only.
    //   reserved_notes      -> sections that are configured but NOT yet enforced
    //                          (ext.reserved_notes) — surfaced honestly so behavior is
    //                          never silently misrepresented.
    std::optional<std::string> profile_name;
    std::vector<std::string> active_policy_notes;
    std::vector<std::string> reserved_notes;

    // Free-form warnings surfaced for this run (also printed to stderr). Included in
    // the JSON audit object; the text format appends them separately.
    std::string warnings;

    // Egress bridges that are ACTIVE this run (phase 2). One entry per bridge; the
    // formatter emits the child-visible endpoint and the injected env var NAME, and
    // hides the real upstream unless redaction was explicitly disabled. Empty => no
    // egress bridges (nothing printed).
    std::vector<EgressBridgeAudit> egress_bridges;
};

std::string format_audit_start(const AuditRecord& r);
std::string format_audit_end(int exit_code);

// PURE. Render the whole run as a SINGLE valid JSON object (one line + trailing
// newline) carrying the same information as the text audit start+end blocks and the
// given process exit code. Like the text formatter it emits env NAMES only (never a
// secret VALUE), keeps every egress upstream "hidden" unless redaction was disabled,
// and prints the already-redacted bwrap command verbatim. All strings are properly
// JSON-escaped.
std::string format_audit_json(const AuditRecord& r, int exit_code);

bool write_audit(const std::string& path, const std::string& content, std::string& err);

}  // namespace raincoat
