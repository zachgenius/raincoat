// Raincoat — seatbelt: pure SBPL assembly (see seatbelt.hpp). No filesystem access.
#include "seatbelt.hpp"

#include <sstream>
#include <string>
#include <vector>

#include "config.hpp"

namespace raincoat {

std::string sbpl_str(const std::string& s, bool& ok) {
    ok = true;
    std::string out;
    out.reserve(s.size() + 2);
    out.push_back('"');
    for (char c : s) {
        if (c == '\n' || c == '\r' || c == '\0') {
            ok = false;  // unrepresentable — a smuggled newline/NUL could inject a rule
            return std::string();
        }
        if (c == '\\' || c == '"') out.push_back('\\');
        out.push_back(c);
    }
    out.push_back('"');
    return out;
}

namespace {

// Emit `(<op> <filters...> (subpath "<path>"))`, or fail-close via ok. A path that is
// empty is skipped (returns true, emits nothing) so absent optional dirs are no-ops.
bool emit_subpath(std::ostringstream& os, const char* rule, const std::string& path,
                  bool& ok) {
    if (path.empty()) return true;
    std::string q = sbpl_str(path, ok);
    if (!ok) return false;
    os << rule << " (subpath " << q << "))\n";
    return true;
}

}  // namespace

std::string build_seatbelt_profile(const LaunchInputs& in, std::string& err) {
    if (in.cfg == nullptr) {
        err = "seatbelt: null config";
        return std::string();
    }
    const Config& cfg = *in.cfg;
    std::ostringstream os;
    bool ok = true;

    os << "(version 1)\n";
    // FILTER model: start permissive, then subtract. This is NOT the structural,
    // fail-closed hiding bwrap gives — a rule that fails to match silently grants access,
    // which is why the runner runs a fail-closed pre-flight probe. See docs/MACOS.md.
    os << "(allow default)\n";
    if (cfg.strict) {
        os << "; strict: allow-default + no cwd auto-grant (the working dir is NOT auto-\n"
              "; exposed). The deny set is otherwise the same as non-strict. This is NOT\n"
              "; kernel default-deny (a bare (deny default) cannot even load libSystem on\n"
              "; macOS); the honest posture is disclosed in the audit. See docs/MACOS.md.\n";
    }

    // --- (1) Hide the real home + block username enumeration ---
    // file-read* also blocks stat(), so the child cannot even confirm a file exists under
    // the real home (measured). One realpath'd spelling covers the Data-volume firmlink
    // twin (measured — no doubling needed).
    if (!emit_subpath(os, "(deny file-read* file-write*", in.real_home, ok)) {
        err = "seatbelt: unrepresentable real_home path";
        return std::string();
    }
    // Deny READ of /Users so `ls /Users` cannot enumerate the real username; specific
    // subpaths (workdir, mounts) are RE-ALLOWED below and win by last-match-wins.
    os << "(deny file-read* (subpath \"/Users\"))\n";

    // --- (1b) Broad early denies (host /tmp, Darwin per-user TEMP) emitted BEFORE the
    // sandbox re-allows, so the sandbox scratch dirs nested under the Darwin TEMP dir survive
    // (step 2 re-allows win by last-match-wins) while the rest of that tree stays hidden. ---
    for (const std::string& d : in.fs_deny_early) {
        if (!emit_subpath(os, "(deny file-read* file-write*", d, ok)) {
            err = "seatbelt: unrepresentable fs_deny_early path";
            return std::string();
        }
    }

    // --- (2) Re-allow the sandbox-private writable areas ---
    if (!emit_subpath(os, "(allow file-read* file-write*", in.fake_home, ok) ||
        !emit_subpath(os, "(allow file-read* file-write*", in.sandbox_tmp, ok) ||
        !emit_subpath(os, "(allow file-read* file-write*", in.sandbox_out, ok)) {
        err = "seatbelt: unrepresentable sandbox dir path";
        return std::string();
    }

    // --- (3) Re-allow the effective working directory (un-hides a project under $HOME),
    // unless it is already covered by the fake home (strict mode) or a user mount (the
    // non-strict cwd auto-mount), to avoid a redundant duplicate rule. ---
    bool workdir_covered = (cfg.workdir == in.fake_home);
    for (const Mount& m : in.mounts) {
        if (m.host_path == cfg.workdir) workdir_covered = true;
    }
    if (!workdir_covered &&
        !emit_subpath(os, "(allow file-read* file-write*", cfg.workdir, ok)) {
        err = "seatbelt: unrepresentable workdir path";
        return std::string();
    }

    // --- (4) Re-allow each user mount, in two passes so ordering is correct under the filter
    // model. Pass 1: RW mounts (read+write). Pass 2: RO mounts — read allowed AND writes
    // explicitly DENIED. Under (allow default) a bare read-allow would leave the path WRITABLE
    // (unlike Linux --ro-bind = EROFS); and Linux gives each mount its own mount point, so an
    // --allow-read subdir of an auto-mounted RW cwd stays read-only. To mirror that, the RO
    // write-denies are emitted AFTER every RW allow, so an explicit --allow-read wins even when
    // a broader RW mount (the cwd auto-mount) contains it. The fs-deny set below still wins over
    // both. (subpath ...) is correct for files and dirs. ---
    for (const Mount& m : in.mounts) {
        if (m.mode == MountMode::ReadWrite &&
            !emit_subpath(os, "(allow file-read* file-write*", m.host_path, ok)) {
            err = "seatbelt: unrepresentable mount path";
            return std::string();
        }
    }
    for (const Mount& m : in.mounts) {
        if (m.mode != MountMode::ReadWrite &&
            (!emit_subpath(os, "(allow file-read*", m.host_path, ok) ||
             !emit_subpath(os, "(deny file-write*", m.host_path, ok))) {
            err = "seatbelt: unrepresentable mount path";
            return std::string();
        }
    }

    // --- (5) Re-deny the fs-deny set LAST among file rules so a deny beats any broad
    // re-allow above (e.g. workdir==$HOME re-allowed, but ~/.ssh denied). Includes the
    // DARWIN per-user cache/temp dirs the caller folds in. ---
    for (const std::string& d : in.fs_deny_resolved) {
        if (!emit_subpath(os, "(deny file-read* file-write*", d, ok)) {
            err = "seatbelt: unrepresentable fs_deny path";
            return std::string();
        }
    }

    // --- (6) Deny the audit-log dir so the child cannot read/forge/erase the log ---
    if (!emit_subpath(os, "(deny file-read* file-write*", in.audit_mask_dir, ok)) {
        err = "seatbelt: unrepresentable audit_mask_dir path";
        return std::string();
    }

    // --- (7) Self-deny the generated profile (it names the real home / username) ---
    if (!in.profile_path.empty()) {
        std::string q = sbpl_str(in.profile_path, ok);
        if (!ok) {
            err = "seatbelt: unrepresentable profile_path";
            return std::string();
        }
        os << "(deny file-read* (literal " << q << "))\n";
    }

    // --- (7b) Re-allow reading the injected identity interposer dylib, even if it lives under
    // a denied path (e.g. a dev build under $HOME). Last-match-wins puts this after the denies
    // so dyld can load it; it is read-only. ---
    if (!in.interpose_dylib.empty()) {
        if (!emit_subpath(os, "(allow file-read*", in.interpose_dylib, ok)) {
            err = "seatbelt: unrepresentable interpose_dylib path";
            return std::string();
        }
    }

    // --- (7c) Re-allow reading the command's OWN binary, even under a denied path (e.g. a tool
    // installed in ~/.local/bin). Read-only, after the denies so it wins by last-match-wins:
    // the wrapped command must be runnable by definition. The sandbox hides your data, not the
    // tool you asked it to run. ---
    if (!in.command_exec_path.empty()) {
        if (!emit_subpath(os, "(allow file-read*", in.command_exec_path, ok)) {
            err = "seatbelt: unrepresentable command_exec_path";
            return std::string();
        }
    }

    // --- (8) Network ---
    // A non-empty allow_loopback_ports means a guarded proxy / egress bridge is active:
    // deny ALL outbound at the kernel level (for EVERY client, not just proxy-aware ones —
    // a macOS strength over the Linux pasta jail) and re-allow ONLY the loopback proxy
    // port(s). "localhost" is required — a raw "127.0.0.1:PORT" fails to compile, and
    // "localhost" covers both 127.0.0.1 and ::1 (measured). DNS is intentionally NOT
    // allowed: the proxy resolves host-side, so a non-proxy client is fully contained.
    if (!in.allow_loopback_ports.empty()) {
        os << "(deny network*)\n";
        for (int p : in.allow_loopback_ports) {
            os << "(allow network-outbound (remote ip \"localhost:" << p << "\"))\n";
        }
    } else if (cfg.net == NetMode::Off) {
        os << "(deny network*)\n";
    }
    // NetMode::Full with no proxy: (allow default) already permits network; emit nothing.

    (void)err;
    return os.str();
}

}  // namespace raincoat
