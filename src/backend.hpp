// Raincoat — backend: the platform seam.
//
// The runner does not talk to bubblewrap or sandbox-exec directly. It talks to the
// three free functions below plus the three POD structs. EXACTLY ONE backend
// translation unit is linked per build — `backend_linux.cpp` on Linux (delegates to
// the pure `bwrap::build_bwrap_argv`), `backend_macos.cpp` on macOS (delegates to the
// pure `build_seatbelt_profile`). Selection is at COMPILE time (see CMakeLists), so
// there is no runtime dispatch and no `virtual` — matching the codebase's
// free-functions-in-`namespace raincoat`, error-code style (bool / std::optional<T> +
// std::string& err). See docs/DESIGN.md.
//
// The Capabilities descriptor is what keeps Raincoat's honesty model intact across
// platforms: the runner GATES every platform-specific step (fontconfig masking, minimal
// /etc, UTS hostname, the pasta netns jail, the env-injection strategy) on these flags,
// so a backend that cannot deliver a guarantee simply SKIPS the step instead of emitting
// a dishonest audit note. Linux defaults reproduce today's behavior exactly.
#pragma once

#include <map>
#include <optional>
#include <string>
#include <vector>

#include "config.hpp"

namespace raincoat {

// How the backend hides host paths from the child.
//   Structural -> the sandbox is CONSTRUCTED from binds/masks; an unlisted path does not
//                 exist inside it (bubblewrap mount namespace). A missing bind aborts the
//                 run — fail-closed.
//   Filter     -> the child runs on the REAL filesystem and a kernel policy DENIES unlisted
//                 paths (Seatbelt). A rule that fails to match silently grants access —
//                 fail-open — which is why the macOS backend pairs this with a per-run
//                 pre-flight probe (see docs/MACOS.md).
//   None       -> no filesystem hiding.
enum class FsHiding { Structural, Filter, None };

// How the backend realises NetMode::Off.
//   UnshareNet -> a fresh, empty network namespace (bwrap --unshare-net).
//   PolicyDeny -> a kernel policy rule denies outbound sockets (Seatbelt (deny network*)).
//   None       -> the backend cannot isolate the network.
enum class NetOff { UnshareNet, PolicyDeny, None };

// How the resolved child environment reaches the child process.
//   ViaArgv       -> baked INTO argv (bwrap --clearenv/--setenv). LaunchPlan.child_env is
//                    unused; the runner exec's carrying the PARENT environ, which bwrap
//                    itself discards. This is the historic Linux path — do NOT change it.
//   ViaExec       -> SBPL has no env directives, so the runner must install child_env at
//                    exec time (execve/posix_spawn with the resolved env). Applying the
//                    resolved env on the Linux path instead would feed pasta/bwrap the
//                    wrong environment — a real regression — hence this is per-backend.
enum class EnvApply { ViaArgv, ViaExec };

// Static description of what the linked backend can enforce. Pure data. Default values are
// the Linux (bubblewrap) contract; the macOS backend overrides the ones it cannot deliver.
struct Capabilities {
    FsHiding     fs_hiding     = FsHiding::Structural;
    NetOff       net_off       = NetOff::UnshareNet;
    EnvApply     env_apply     = EnvApply::ViaArgv;

    // The guarded-proxy egress firewall is kernel-enforced for ALL clients on macOS
    // (Seatbelt (deny network*) + allow only the loopback proxy port) with no helper; on
    // Linux the equivalent needs the pasta strict netns jail. True => the backend can make
    // the proxy the child's only exit at the kernel level without a netns jail.
    bool net_firewall_kernel = false;

    bool supports_fontconfig_isolation = true;  // curated fonts.conf + XDG_DATA_DIRS (fontconfig)
    bool supports_uts_hostname         = true;  // fresh UTS ns + generic hostname
    bool supports_minimal_etc          = true;  // generic /etc/hostname,/etc/hosts,/etc/localtime binds
    bool supports_curated_fonts        = true;  // tmpfs /usr/share/fonts + re-bind curated set
    bool supports_netns_jail           = true;  // pasta/slirp4netns isolated-netns egress jail

    // Machine-fingerprint faking (see docs/FINGERPRINT-SYSCALLS.md).
    bool supports_proc_overlays        = true;  // Tier 1: --ro-bind generic /proc/{cpuinfo,version,...}
    bool supports_seccomp_identity     = true;  // Tier 2: fake uname(2)/sysinfo(2) via seccomp user-notify

    // [filesystem].remap_cwd — mount the working dir at a neutral path (e.g. /work) to hide the
    // host path. Needs a real bind mount that remaps the path (bwrap); a Filter backend
    // (Seatbelt) has no bind mount and the child keeps its real cwd, so it cannot remap.
    bool supports_path_remap           = true;

    // Best-effort identity/fingerprint faking via DYLD function interposition (macOS): fake
    // gethostname/uname/getpwuid/sysctl that Seatbelt cannot. Only for backends that apply the
    // sandbox in-process and exec the target themselves (so DYLD_INSERT_LIBRARIES survives).
    bool supports_dyld_interpose       = false;

    std::string label = "bubblewrap (Linux user namespaces)";  // for audit + doctor
};

// Everything a backend needs to build the final launch. This is the argument set of
// bwrap::build_bwrap_argv PLUS the pasta-jail context (so the Linux backend can reproduce
// the wrap internally) PLUS macOS-only fields the Seatbelt generator needs. The runner
// pre-resolves every value (including realpath'ing the macOS paths); the backend does not
// re-derive them. `cfg` points at the EFFECTIVE config (cfg_copy: effective workdir +
// honesty overrides already applied) and must outlive the call.
struct LaunchInputs {
    std::string              backend_path;      // located executable (argv[0]); from backend_locate
    const Config*            cfg = nullptr;      // = cfg_copy
    std::vector<Mount>       mounts;
    EnvResolution            env;                // env.resolved == the exact child env
    std::string              fake_home;
    std::string              sandbox_tmp;
    bool                     bind_resolv_conf = false;  // = binds_resolv_conf(cfg.net)
    std::string              font_dir;
    std::string              audit_mask_dir;
    std::string              sandbox_out;
    std::string              mask_empty_file;
    std::vector<std::string> mask_files;
    std::vector<std::string> curated_font_dirs;
    bool                     mask_usr_local_fonts = true;
    // Tier-1 fingerprint overlays: {host_file, /proc target} pairs bound over the fresh
    // procfs (Linux). Empty on backends without supports_proc_overlays.
    std::vector<std::pair<std::string, std::string>> proc_overlays;

    // Isolated-netns (pasta) jail context. supports_netns_jail=false backends leave these
    // default (jail_active=false) and emit no wrap.
    bool                       jail_active = false;
    bool                       strict_jail = false;
    std::optional<std::string> pasta_path;
    std::vector<int>           jail_forward_ports;

    // macOS / Seatbelt-only inputs (unused by the Linux backend). All realpath-resolved.
    std::string              real_home;          // host $HOME to hide (deny subtree)
    std::vector<std::string> fs_deny_resolved;   // [filesystem].deny, realpath'd
    std::string              profile_path;        // where the runner will write the .sb
    std::vector<int>         allow_loopback_ports;// proxy + egress-bridge child ports for the firewall
    std::string              interpose_dylib;     // macOS: re-allow reading the injected interposer
};

// The result the runner needs to fork/exec and to audit. Built by the backend so the
// runner never re-parses backend-shaped argv.
struct LaunchPlan {
    std::string                        launch_path;         // program to exec (bwrap/pasta, or sandbox-exec)
    std::vector<std::string>           argv;                // full argv (post jail-wrap)
    std::map<std::string, std::string> child_env;           // applied at exec IFF env_apply == ViaExec
    EnvApply                           env_apply = EnvApply::ViaArgv;
    std::string                        audit_command;       // display-safe, already redacted

    // macOS: the SBPL text + where the runner must write it before exec (side effect owned
    // by the runner). Empty on Linux.
    std::string                        profile_text;
    std::string                        profile_path;

    // macOS: when non-empty, the child applies this SBPL in-process via sandbox_init() and
    // then exec's the target ITSELF (rather than exec'ing /usr/bin/sandbox-exec), so an
    // injected DYLD_INSERT_LIBRARIES survives SIP. Empty on Linux / non-interposer paths.
    std::string                        apply_sbpl;
};

// Static capability descriptor of the linked backend. Pure.
Capabilities backend_capabilities();

// Locate the backend executable. Linux: honor an executable cfg.ext.backend.bwrap_path
// (must contain '/' and be X_OK), else find_bwrap(); on total failure return nullopt and
// set err to the multi-line "missing bwrap" message (the runner prints it and returns 127).
// macOS: return the fixed /usr/bin/sandbox-exec, or nullopt + err if it is absent.
std::optional<std::string> backend_locate(const Config& cfg, std::string& err);

// Build the final launch from fully-resolved inputs. Returns nullopt + err when the backend
// cannot satisfy the inputs (Linux currently never fails here; the Seatbelt backend fails
// closed on an unrepresentable profile). Never touches the filesystem — the runner writes
// any profile_text itself.
std::optional<LaunchPlan> backend_build_launch(const LaunchInputs& in, std::string& err);

}  // namespace raincoat
