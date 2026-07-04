// Raincoat — backend_macos: the Seatbelt (sandbox-exec) backend behind the platform seam.
//
// Compiled ONLY on macOS (see CMakeLists; Linux links backend_linux.cpp instead). It
// realpath-resolves every path (SBPL matches the kernel-canonical path — a raw /tmp/...
// rule silently fails open, measured), drives the pure build_seatbelt_profile, and returns
// a LaunchPlan whose env is applied at exec (SBPL has no env directives). Best-effort:
// see docs/MACOS.md for the honest guarantee downgrade vs the Linux backend.
#include "backend.hpp"

#include <cstddef>
#include <string>
#include <vector>

#include <unistd.h>  // access, confstr, X_OK

#include "seatbelt.hpp"
#include "util.hpp"  // canonicalize

namespace raincoat {

namespace {
const char* kSandboxExec = "/usr/bin/sandbox-exec";

std::string canon_or(const std::string& p) {
    if (p.empty()) return p;
    auto c = canonicalize(p);
    return c ? *c : p;  // fall back to the given path if it does not exist yet
}

// The profile file does not exist yet, so realpath the parent dir and rejoin the basename.
std::string canon_parent_join(const std::string& p) {
    auto slash = p.find_last_of('/');
    if (slash == std::string::npos) return p;
    std::string parent = p.substr(0, slash);
    std::string base = p.substr(slash);  // keeps the leading '/'
    auto c = canonicalize(parent);
    return (c ? *c : parent) + base;
}

// The per-user Darwin cache dir (/private/var/folders/.../C/) holds app caches/credentials
// and is NOT under $HOME, so the home deny misses it. (We deliberately do NOT deny the
// Darwin TEMP dir — the sandbox itself lives under it.)
std::string darwin_cache_dir() {
    char buf[1024];
    size_t n = ::confstr(_CS_DARWIN_USER_CACHE_DIR, buf, sizeof(buf));
    if (n == 0 || n > sizeof(buf)) return std::string();
    return canon_or(std::string(buf));
}

// Display-safe join of the launch argv for the audit log. Unlike the bwrap path there are
// no --setenv pairs to redact (env is applied at exec, not in argv); the command tail is
// the user's own argv, logged verbatim exactly as on Linux.
std::string join_for_audit(const std::vector<std::string>& argv) {
    std::string out;
    for (size_t i = 0; i < argv.size(); ++i) {
        if (i) out += ' ';
        const std::string& t = argv[i];
        if (t.empty() || t.find(' ') != std::string::npos) {
            out += '\'';
            out += t;
            out += '\'';
        } else {
            out += t;
        }
    }
    return out;
}
}  // namespace

Capabilities backend_capabilities() {
    Capabilities c;
    c.fs_hiding = FsHiding::Filter;          // deny over the real FS, not structural absence
    c.net_off = NetOff::PolicyDeny;          // (deny network*), no netns to unshare
    c.env_apply = EnvApply::ViaExec;         // SBPL has no env directives
    c.net_firewall_kernel = true;            // kernel-enforced egress for ALL clients, no pasta
    c.supports_fontconfig_isolation = false;  // macOS uses Core Text, not fontconfig
    c.supports_uts_hostname = false;          // no UTS namespace; cannot fake gethostname()
    c.supports_minimal_etc = false;           // cannot bind a fake /etc
    c.supports_curated_fonts = false;         // cannot overlay /usr/share/fonts
    c.supports_netns_jail = false;            // no netns; kernel firewall replaces it
    c.supports_proc_overlays = false;         // no /proc to overlay; Tier-1 masks are Linux-only
    c.supports_seccomp_identity = false;      // no seccomp; identity faking would need DYLD interpose
    c.label = "Seatbelt (sandbox-exec, best-effort)";
    return c;
}

std::optional<std::string> backend_locate(const Config& cfg, std::string& err) {
    (void)cfg;
    if (::access(kSandboxExec, X_OK) == 0) return std::string(kSandboxExec);
    err =
        "Error: /usr/bin/sandbox-exec was not found or is not executable.\n"
        "\n"
        "Raincoat's macOS backend needs Apple's Seatbelt sandbox (sandbox-exec).\n"
        "Then run:\n"
        "  raincoat doctor\n";
    return std::nullopt;
}

std::optional<LaunchPlan> backend_build_launch(const LaunchInputs& in, std::string& err) {
    // Canonicalize every path the generator will see.
    LaunchInputs c = in;
    c.real_home = canon_or(in.real_home);
    c.fake_home = canon_or(in.fake_home);
    c.sandbox_tmp = canon_or(in.sandbox_tmp);
    c.sandbox_out = canon_or(in.sandbox_out);
    c.audit_mask_dir = canon_or(in.audit_mask_dir);
    c.profile_path = canon_parent_join(in.profile_path);
    for (auto& m : c.mounts) m.host_path = canon_or(m.host_path);

    c.fs_deny_resolved.clear();
    for (const std::string& d : in.fs_deny_resolved) c.fs_deny_resolved.push_back(canon_or(d));
    std::string cache = darwin_cache_dir();
    if (!cache.empty()) c.fs_deny_resolved.push_back(cache);

    // A local Config with a canonical workdir (the generator reads cfg->workdir/strict/net).
    Config cfgc = *in.cfg;
    cfgc.workdir = canon_or(in.cfg->workdir);
    c.cfg = &cfgc;

    std::string profile = build_seatbelt_profile(c, err);
    if (!err.empty()) return std::nullopt;

    LaunchPlan plan;
    plan.launch_path = kSandboxExec;
    plan.argv = {"sandbox-exec", "-f", c.profile_path, "--"};
    for (const std::string& t : in.cfg->command) plan.argv.push_back(t);
    plan.child_env = in.env.resolved;      // applied at execve by the runner
    plan.env_apply = EnvApply::ViaExec;
    plan.profile_text = profile;
    plan.profile_path = c.profile_path;
    plan.audit_command = join_for_audit(plan.argv);
    return plan;
}

}  // namespace raincoat
