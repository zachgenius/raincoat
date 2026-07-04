// Raincoat — seatbelt: pure SBPL (Seatbelt profile language) assembly, no side effects.
//
// The macOS peer of bwrap.cpp. `build_seatbelt_profile` is PURE — it turns FULLY
// realpath-resolved LaunchInputs into the text of a `.sb` profile, doing only
// deterministic string assembly + SBPL escaping, so it is unit-testable with hand-built
// inputs exactly like bwrap::build_bwrap_argv. The CALLER (backend_macos.cpp) is
// responsible for realpath'ing every path first (SBPL (subpath ...) matches the kernel's
// canonical path; a raw /tmp/... rule silently fails open — measured, see docs/MACOS.md).
#pragma once

#include <string>

#include "backend.hpp"

namespace raincoat {

// Assemble the SBPL profile for `in`. Filter model: it starts from (allow default) and
// SUBTRACTS the real home, /Users enumeration, the fs-deny set, the audit dir, and the
// profile itself, then RE-ALLOWS the sandbox-private dirs, the working dir, and the user
// mounts. Ordering is last-match-wins: a deny that must beat a broad re-allow is emitted
// after it. Network: off / kernel-firewall (deny all + allow only the loopback proxy
// port) / full. Returns "" and sets err when a path is unrepresentable (contains a newline
// or NUL) — fail closed rather than emit a profile a smuggled byte could subvert.
std::string build_seatbelt_profile(const LaunchInputs& in, std::string& err);

// PURE helper, exposed for testing: wrap a path as an SBPL string literal, escaping the
// two bytes that break the TinyScheme reader (backslash, double-quote). Sets ok=false if
// the string contains a newline or NUL (which cannot be represented safely).
std::string sbpl_str(const std::string& s, bool& ok);

}  // namespace raincoat
