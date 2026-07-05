// Raincoat — backend_macos: the Seatbelt (sandbox-exec) backend behind the platform seam.
//
// Compiled ONLY on macOS (see CMakeLists; Linux links backend_linux.cpp instead). It
// realpath-resolves every path (SBPL matches the kernel-canonical path — a raw /tmp/...
// rule silently fails open, measured), drives the pure build_seatbelt_profile, and returns
// a LaunchPlan whose env is applied at exec (SBPL has no env directives). Best-effort:
// see docs/MACOS.md for the honest guarantee downgrade vs the Linux backend.
#include "backend.hpp"

#include <climits>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include <mach-o/dyld.h>  // _NSGetExecutablePath (locate the interposer dylib)
#include <unistd.h>       // access, confstr, X_OK

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
// and is NOT under $HOME, so the home deny misses it.
std::string darwin_cache_dir() {
    char buf[1024];
    size_t n = ::confstr(_CS_DARWIN_USER_CACHE_DIR, buf, sizeof(buf));
    if (n == 0 || n > sizeof(buf)) return std::string();
    return canon_or(std::string(buf));
}

// The per-user Darwin TEMP dir (/private/var/folders/.../T/) — other apps' scratch + the
// host's sibling temp files. The sandbox's OWN scratch lives under it, so this must be an
// EARLY deny (the sandbox re-allows nested under it win by last-match-wins), never a late one.
std::string darwin_temp_dir() {
    char buf[1024];
    size_t n = ::confstr(_CS_DARWIN_USER_TEMP_DIR, buf, sizeof(buf));
    if (n == 0 || n > sizeof(buf)) return std::string();
    return canon_or(std::string(buf));
}

// Locate rc_interpose.dylib next to the running raincoat executable (CMake builds it there),
// falling back to ../lib/raincoat/ relative to the executable (the installed layout:
// <prefix>/bin/raincoat + <prefix>/lib/raincoat/rc_interpose.dylib). Returns "" if it cannot
// be found — the interposer is then simply not injected (best-effort; env-level identity
// still applies).
std::string interpose_dylib_path() {
    char buf[PATH_MAX];
    uint32_t sz = sizeof(buf);
    if (_NSGetExecutablePath(buf, &sz) != 0) return std::string();
    std::string exe = canon_or(std::string(buf));
    auto slash = exe.find_last_of('/');
    std::string dir = (slash == std::string::npos) ? std::string(".") : exe.substr(0, slash);
    for (const std::string& dylib : {dir + "/rc_interpose.dylib",
                                     dir + "/../lib/raincoat/rc_interpose.dylib"}) {
        if (::access(dylib.c_str(), R_OK) == 0) return canon_or(dylib);
    }
    return std::string();
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
    c.supports_path_remap = false;            // no bind mount; the child keeps its real cwd
    c.supports_dyld_interpose = true;         // in-process sandbox_init + execve preserves DYLD injection
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

    // mount_tmpfs_tmp (default true): Linux gives the child a private tmpfs /tmp. macOS has no
    // bind, so instead deny the host's shared temp dirs — the classic /private/tmp AND the
    // per-user Darwin TEMP dir — as EARLY denies (before the sandbox re-allows), so the child's
    // OWN scratch (sandbox_tmp/out under the Darwin TEMP dir) survives while sibling temp files
    // stay hidden. The child's TMPDIR already points at its private scratch.
    c.fs_deny_early.clear();
    if (in.cfg->ext.backend.mount_tmpfs_tmp) {
        c.fs_deny_early.push_back("/private/tmp");
        std::string tmp = darwin_temp_dir();
        if (!tmp.empty()) c.fs_deny_early.push_back(tmp);
    }

    // A local Config with a canonical workdir (the generator reads cfg->workdir/strict/net).
    Config cfgc = *in.cfg;
    cfgc.workdir = canon_or(in.cfg->workdir);
    c.cfg = &cfgc;

    // Locate + canonicalize the interposer dylib BEFORE generating the profile, so the profile
    // re-allows reading it (it may live under a denied path, e.g. a dev build under $HOME).
    const std::string dylib = canon_or(interpose_dylib_path());
    c.interpose_dylib = dylib;

    std::string profile = build_seatbelt_profile(c, err);
    if (!err.empty()) return std::nullopt;

    LaunchPlan plan;
    // In-process apply model: the child sandbox_init(apply_sbpl)s then exec's the target
    // ITSELF (argv = the raw command), so an injected DYLD_INSERT_LIBRARIES survives SIP —
    // going through the SIP-protected /usr/bin/sandbox-exec would strip it (measured). The
    // profile is ALSO written to a file (profile_path, kept) for the fail-closed pre-flight
    // probe, which still runs via sandbox-exec -f (same SBPL, same enforcement).
    plan.apply_sbpl = profile;
    plan.argv = in.cfg->command;
    plan.launch_path = plan.argv.empty() ? std::string() : plan.argv.front();
    plan.child_env = in.env.resolved;      // applied at exec by the runner
    plan.env_apply = EnvApply::ViaExec;
    plan.profile_text = profile;
    plan.profile_path = c.profile_path;
    plan.audit_command = join_for_audit(plan.argv);

    // Best-effort identity/fingerprint interposer: inject the dylib (when present next to the
    // executable) + the value-driven RC_FAKE_* env it reads, faking gethostname/uname/
    // getpwuid/getlogin/sysctl that Seatbelt cannot. DYLD_* was scrubbed from env.resolved, so
    // setting our OWN controlled value here is deliberate and wins over the scrub.
    if (!dylib.empty()) {
        const BackendConfig& bk = in.cfg->ext.backend;
        // Source the identity fakes from the child's ACTUAL resolved env (HOME/USER/HOSTNAME),
        // so the interposer's getpwuid/getlogin/gethostname can never disagree with $HOME/$USER/
        // $HOSTNAME — a mismatch is itself a fingerprint. Fall back to the config/defaults.
        auto env_or = [&](const char* k, const std::string& fb) -> std::string {
            auto it = plan.child_env.find(k);
            return (it != plan.child_env.end() && !it->second.empty()) ? it->second : fb;
        };
        plan.child_env["DYLD_INSERT_LIBRARIES"] = dylib;
        plan.child_env["RC_FAKE_HOSTNAME"] = env_or("HOSTNAME", in.cfg->ext.hostname.value_or("sandbox"));
        plan.child_env["RC_FAKE_USER"] = env_or("USER", in.cfg->ext.username.value_or("user"));
        plan.child_env["RC_FAKE_HOME"] = env_or("HOME", c.fake_home);
        if (bk.kernel_osrelease) plan.child_env["RC_FAKE_OSRELEASE"] = *bk.kernel_osrelease;
        if (bk.kernel_version) plan.child_env["RC_FAKE_OSVERSION"] = *bk.kernel_version;
        if (bk.cpu_model_name) plan.child_env["RC_FAKE_CPU_BRAND"] = *bk.cpu_model_name;
        if (bk.cpu_vendor_id) plan.child_env["RC_FAKE_CPU_VENDOR"] = *bk.cpu_vendor_id;
        if (bk.mem_total_kb)
            plan.child_env["RC_FAKE_MEMSIZE"] = std::to_string(*bk.mem_total_kb * 1024ull);
        if (bk.cpu_count) plan.child_env["RC_FAKE_NCPU"] = std::to_string(*bk.cpu_count);
        if (bk.machine_id) plan.child_env["RC_FAKE_HOSTUUID"] = *bk.machine_id;
        if (bk.boot_id) plan.child_env["RC_FAKE_BOOTUUID"] = *bk.boot_id;
        if (bk.uptime_seconds) plan.child_env["RC_FAKE_UPTIME"] = std::to_string(*bk.uptime_seconds);
    }
    return plan;
}

}  // namespace raincoat
