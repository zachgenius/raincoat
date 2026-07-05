// Raincoat — run_status: publish a small JSON status file per live sandbox run, so the macOS
// menu-bar app (and any future tray) can show what is currently sandboxed WITHOUT a daemon.
//
// The file is the entire contract with the GUI (see docs/GUI-MACOS.md). It is best-effort and
// purely informational: any write/remove failure is ignored and never affects the run. The
// runner writes one file once the child is forked and removes it in cleanup_root().
#pragma once

#include <map>
#include <string>
#include <vector>

namespace raincoat {

struct RunStatus {
    long supervisor_pid = 0;   // the raincoat process (owns the file, forwards signals)
    long child_pid = 0;        // the sandboxed process
    std::string command;       // display-safe command line
    std::string audit_log;     // path to this run's audit log
    std::string backend;       // Capabilities::label
    std::string net_mode;      // off | open | proxied | egress-bridge
    long started_at = 0;       // unix seconds
    std::map<std::string, std::string> capabilities;  // filesystem / network / identity
    std::vector<std::string> notes;                   // selected active-policy notes
};

// The per-user runtime dir that holds run/<pid>.json:
//   macOS: ~/Library/Application Support/Raincoat
//   Linux: $XDG_RUNTIME_DIR/raincoat, else ${TMPDIR:-/tmp}/raincoat-<uid>
// Returns "" only if $HOME is unset on macOS (then status publishing is skipped).
std::string run_status_dir();

// PURE, unit-testable: serialize a RunStatus to the schema-1 JSON string.
std::string run_status_to_json(const RunStatus& s);

// Best-effort: write <run_status_dir>/run/<supervisor_pid>.json (atomic via temp+rename).
// Returns false on any error; the caller ignores it.
bool run_status_write(const RunStatus& s);

// Best-effort: remove the status file for supervisor_pid (no-op if absent).
void run_status_remove(long supervisor_pid);

}  // namespace raincoat
