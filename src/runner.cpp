// Raincoat — runner: resolve config + orchestrate the sandboxed run.
#include "runner.hpp"

#include <algorithm>
#include <atomic>
#include <cctype>
#include <cerrno>
#include <csignal>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include <pthread.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>

#include "audit.hpp"
#include "browser.hpp"
#include "bwrap.hpp"
#include "doctor.hpp"
#include "egress.hpp"
#include "env_guard.hpp"
#include "font_guard.hpp"
#include "fs_guard.hpp"
#include "net_guard.hpp"
#include "profile.hpp"
#include "proxy.hpp"
#include "seccomp_notify.hpp"
#include "util.hpp"

namespace raincoat {

namespace {

// Verbatim SPEC message for a missing bubblewrap backend (docs/SPEC.md).
const char* kBwrapMissing =
    "Error: bubblewrap / bwrap was not found.\n"
    "\n"
    "Install it with your package manager, for example:\n"
    "  Ubuntu/Debian: sudo apt install bubblewrap\n"
    "  Fedora: sudo dnf install bubblewrap\n"
    "  Arch: sudo pacman -S bubblewrap\n"
    "\n"
    "Then run:\n"
    "  raincoat doctor\n";

// Join a command argv into a single display string (audit "Command:" line).
std::string join_command(const std::vector<std::string>& cmd) {
    std::ostringstream ss;
    for (std::size_t i = 0; i < cmd.size(); ++i) {
        if (i) ss << ' ';
        ss << cmd[i];
    }
    return ss.str();
}

// True when `path` is exactly `mount` or lives beneath it (identity mapping).
bool path_within(const std::string& path, const std::string& mount) {
    if (path == mount) return true;
    return starts_with(path, mount + "/");
}

// Look up a key in env_defaults, returning "" when absent.
std::string default_or_empty(const std::map<std::string, std::string>& m,
                             const std::string& key) {
    auto it = m.find(key);
    return it == m.end() ? std::string() : it->second;
}

// True on x86 hosts (the only arch for which we synthesize a plausible /proc/cpuinfo).
// On other arches (arm64, riscv, ...) the cpuinfo format differs enough that a wrong
// generic block would confuse tools more than the leak it prevents, so we leave the
// real file in place there. `uname -m` is the host machine string.
bool host_is_x86() {
    struct utsname u{};
    if (::uname(&u) != 0) return false;
    const std::string m = u.machine;
    return m == "x86_64" || m == "amd64" || m == "i386" || m == "i486" ||
           m == "i586" || m == "i686";
}

// Build a generic x86_64 /proc/cpuinfo with `nproc` identical logical processors. It
// masks the host's real CPU model/family/stepping/microcode/MHz/cache/bogomips (a
// strong machine fingerprint) while keeping the logical-processor COUNT and a common
// baseline flag set, so tools that size thread pools from cpuinfo or probe for SSE2
// still behave. Two different machines with the same core count emit byte-identical
// output — that is the anti-fingerprint goal. `vendor_id` and `model_name` are profile-
// configurable (backend.cpu_vendor_id / backend.cpu_model_name) so a profile can present
// a chosen CPU. Not meant to be a faithful CPU report.
std::string generic_cpuinfo(unsigned nproc, const std::string& vendor_id,
                            const std::string& model_name) {
    if (nproc == 0) nproc = 1;
    const char* kFlags =
        "fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 "
        "clflush mmx fxsr sse sse2 ht syscall nx lm constant_tsc";
    std::ostringstream ss;
    for (unsigned i = 0; i < nproc; ++i) {
        ss << "processor\t: " << i << "\n"
           << "vendor_id\t: " << vendor_id << "\n"
           << "cpu family\t: 6\n"
           << "model\t\t: 60\n"
           << "model name\t: " << model_name << "\n"
           << "stepping\t: 3\n"
           << "microcode\t: 0x1\n"
           << "cpu MHz\t\t: 2000.000\n"
           << "cache size\t: 8192 KB\n"
           << "physical id\t: 0\n"
           << "siblings\t: " << nproc << "\n"
           << "core id\t\t: " << i << "\n"
           << "cpu cores\t: " << nproc << "\n"
           << "apicid\t\t: " << i << "\n"
           << "initial apicid\t: " << i << "\n"
           << "fpu\t\t: yes\n"
           << "fpu_exception\t: yes\n"
           << "cpuid level\t: 13\n"
           << "wp\t\t: yes\n"
           << "flags\t\t: " << kFlags << "\n"
           << "bugs\t\t:\n"
           << "bogomips\t: 4000.00\n"
           << "clflush size\t: 64\n"
           << "cache_alignment\t: 64\n"
           << "address sizes\t: 39 bits physical, 48 bits virtual\n"
           << "power management:\n"
           << "\n";
    }
    return ss.str();
}

// Generic /proc/version line. Real format is
// "Linux version <release> (<builduser@host>) (<compiler>) <version>". We synthesize a
// neutral one so the child cannot read the host's exact kernel release or — as here on
// Pop!_OS — the distro build host (jenkins@warp.pop-os.org), a strong fingerprint.
std::string generic_proc_version(const std::string& osrelease, const std::string& version) {
    return "Linux version " + osrelease +
           " (builder@sandbox) (gcc version 13.0.0 (Generic)) " + version + "\n";
}

// Generic /proc/meminfo. Masks the host's exact RAM size (a weak fingerprint) while keeping a
// plausible, self-consistent layout. `total_kb` is shared with the sysinfo(2) fake.
std::string generic_meminfo(std::uint64_t total_kb) {
    const std::uint64_t avail = total_kb / 2;
    std::ostringstream ss;
    ss << "MemTotal:       " << total_kb << " kB\n"
       << "MemFree:        " << avail << " kB\n"
       << "MemAvailable:   " << avail << " kB\n"
       << "Buffers:               0 kB\n"
       << "Cached:                0 kB\n"
       << "SwapTotal:             0 kB\n"
       << "SwapFree:              0 kB\n";
    return ss.str();
}

// Terminating-signal handling for sandbox cleanup. When raincoat is interrupted
// while the bwrap child is running (Ctrl-C, `kill`, terminal hangup), the default
// disposition would kill raincoat before cleanup_root() runs, leaking the whole
// sandbox tree under /tmp. Instead we catch SIGINT/SIGTERM/SIGHUP and forward the
// signal to the bwrap child: that makes waitpid() return, so the normal cleanup
// path (remove the sandbox root) still executes. remove_all() is NOT async-signal-
// safe, so it is deliberately kept out of the handler.
volatile std::sig_atomic_t g_child_pid = 0;
volatile std::sig_atomic_t g_pending_signal = 0;

void forward_terminating_signal(int sig) {
    g_pending_signal = sig;
    if (g_child_pid > 0) ::kill(static_cast<pid_t>(g_child_pid), sig);
}

}  // namespace

Config resolve_config(const CliInvocation& inv,
                      const std::map<std::string, std::string>& /*parent_env*/,
                      const std::string& cwd, std::string& err) {
    err.clear();

    Options options = inv.options;

    // A profile, if any, is the base; explicit CLI flags win via merge().
    if (options.profile_path.has_value()) {
        std::string perr;
        std::optional<Options> prof = load_profile(*options.profile_path, perr);
        if (!prof.has_value()) {
            err = perr;
            return Config{};
        }
        options = merge(*prof, inv.options);
    }

    Config cfg;
    cfg.strict = options.strict;

    // Egress bridge mode (phase 2) is ACTIVE when [egress] mode=="bridge" with at least
    // one bridge (load_profile sets ext.egress.enabled). It changes the network model:
    // the child must reach the host-loopback bridge, so the sandbox SHARES the host
    // network namespace (no --unshare-net). See run() and docs/EGRESS.md.
    const bool egress_active = options.ext.egress.enabled;

    // Network-policy guarded proxy (phase 4) is ACTIVE when [network_policy].enabled. Like
    // the egress bridge it needs the child to reach a host-loopback listener (Raincoat's
    // filtering forward proxy), so the sandbox must SHARE the host network namespace (no
    // --unshare-net) — or, when composed with the pasta netns jail, JOIN that jail with the
    // proxy port forwarded. Both cases require cfg.net to be a shared/Full mode below.
    const bool netpolicy_active = options.ext.network_policy.enabled;
    // Either feature needs the child to reach a host-loopback listener.
    const bool shared_net_needed = egress_active || netpolicy_active;

    // A hard conflict: egress-bridge / guarded-proxy mode needs loopback reachability, but
    // the user also demanded `--net off` (or profile network="off"). Honoring both is
    // impossible, so REFUSE with an explicit error rather than silently picking a winner.
    if (shared_net_needed && options.net.has_value() && *options.net == NetMode::Off) {
        err =
            egress_active
                ? "Error: egress bridge mode ([egress] mode=\"bridge\") requires network "
                  "reachability to the host loopback bridge, but network was set to \"off\" "
                  "(--net off or network = \"off\"). These conflict. Remove the off setting "
                  "to run egress (the sandbox shares the host network namespace), or disable "
                  "egress."
                : "Error: network policy ([network_policy].enabled) requires network "
                  "reachability to the host loopback guarded proxy, but network was set to "
                  "\"off\" (--net off or network = \"off\"). These conflict. Remove the off "
                  "setting to run the guarded proxy (the sandbox shares the host network "
                  "namespace, or joins the pasta netns jail with only the proxy port "
                  "forwarded), or disable network_policy.";
        return Config{};
    }

    // Network resolution + reserved fallback.
    //   * An explicit net (CLI --net or profile network=full|off) always wins.
    //   * Egress bridge mode overrides the reserved fail-closed: it forces SHARED host
    //     net (Full for flag emission — no --unshare-net) so 127.0.0.1 reaches the bridge.
    //   * A reserved restrictive mode (proxy/bridge/guarded) leaves options.net unset but
    //     sets ext.reserved_net_mode (see load_profile). It is NOT yet enforced, so fail
    //     CLOSED: fall back to NetMode::Off regardless of strict — never Full. The user
    //     asked to CONSTRAIN egress; defaulting to unrestricted networking would be the
    //     exact opposite of that intent (a fail-OPEN downgrade). run() also warns on
    //     stderr so a user who never reads the audit still learns the mode was unapplied.
    //   * Otherwise (flat/absent profile) keep the MVP default: Off in strict, Full else.
    if (options.net.has_value()) {
        cfg.net = *options.net;
    } else if (shared_net_needed) {
        cfg.net = NetMode::Full;
    } else if (options.ext.reserved_net_mode.has_value()) {
        cfg.net = NetMode::Off;
    } else {
        cfg.net = cfg.strict ? NetMode::Off : NetMode::Full;
    }

    // Carry the merged rich sectioned config through to Config. run() wires ext into
    // the live sandbox (identity, env policy, backend toggles, fs deny, tripwire, audit).
    cfg.ext = options.ext;

    // Audit-log format: a CLI/profile override (options.audit_format) wins; otherwise
    // keep the default (text). Stored on ext so run() can select the writer.
    cfg.ext.audit_format = options.audit_format.value_or(AuditFormat::Text);

    // Reconcile the reserved network-mode note with the RESOLVED network. The note was
    // recorded at profile-load time, BEFORE resolution knew whether an explicit --net
    // would override the fail-closed fallback (options.net wins above). Rewriting it from
    // the actual cfg.net keeps the tamper-proof audit honest: it must never simultaneously
    // headline "Network: full" AND swear the network fails closed to off. Only assert
    // fail-closed-to-off when cfg.net is genuinely Off; otherwise state the real outcome.
    if (cfg.ext.reserved_net_mode.has_value()) {
        const std::string& mode = *cfg.ext.reserved_net_mode;
        std::string reconciled;
        if (egress_active) {
            // Egress bridge forwarding is actually running this phase. The reserved
            // NetMode itself is still not enforced, but the honest outcome is not
            // "unrestricted with no egress handling" — it is "egress bridge active,
            // sharing the host net namespace (child NOT network-jailed)".
            reconciled = "network mode \"" + mode +
                         "\": egress bridge forwarding is ACTIVE; the child reaches "
                         "configured upstreams via the injected loopback bridge, but the "
                         "sandbox SHARES the host network namespace so the child is NOT "
                         "network-jailed (it retains general host network access)";
        } else if (cfg.net == NetMode::Off) {
            reconciled = "network mode \"" + mode +
                         "\" is not yet enforced (phase 2); egress fails closed to "
                         "\"off\" (all networking blocked)";
        } else {
            reconciled = "network mode \"" + mode +
                         "\" is not yet enforced (phase 2); network resolved to \"" +
                         std::string(to_string(cfg.net)) +
                         "\" (e.g. via an explicit --net), so the configured egress "
                         "restriction is NOT applied and egress is unrestricted";
        }
        const std::string prefix = "network mode \"" + mode + "\"";
        bool replaced = false;
        for (auto& note : cfg.ext.reserved_notes) {
            if (note.rfind(prefix, 0) == 0) {
                note = reconciled;
                replaced = true;
                break;
            }
        }
        if (!replaced) cfg.ext.reserved_notes.push_back(reconciled);
    }

    cfg.allow_read = options.allow_read;
    cfg.allow_write = options.allow_write;
    cfg.allow_env = options.allow_env;
    cfg.set_env = options.set_env;

    cfg.env_defaults = options.env_defaults;
    // Ensure the generic locale/timezone defaults are present without clobbering
    // any values the user (or profile) supplied explicitly.
    if (cfg.env_defaults.find("TZ") == cfg.env_defaults.end())
        cfg.env_defaults["TZ"] = "UTC";
    if (cfg.env_defaults.find("LANG") == cfg.env_defaults.end())
        cfg.env_defaults["LANG"] = "en_US.UTF-8";
    if (cfg.env_defaults.find("LC_ALL") == cfg.env_defaults.end())
        cfg.env_defaults["LC_ALL"] = "en_US.UTF-8";

    cfg.fontconfig_enabled = options.fontconfig_enabled.value_or(true);

    cfg.workdir = options.workdir.value_or(cwd);
    cfg.audit_log_path = options.audit_log.value_or(cwd + "/.raincoat/audit.log");
    cfg.keep_temp = options.keep_temp;
    cfg.command = options.command;

    // Carry the --profile path (if any) so run() can detect and mask a profile that
    // lands inside a mounted path — it holds egress upstream_endpoint values that must
    // never reach the child. Sourced from the CLI invocation (where --profile came from).
    cfg.profile_path = inv.options.profile_path;

    return cfg;
}

int run(const Config& cfg, const std::map<std::string, std::string>& parent_env,
        const std::string& cwd, const std::string& assets_dir, std::string& err) {
    err.clear();

    // ---- 0. Install terminating-signal handlers FIRST -------------------
    // These MUST be armed before mkdtemp() creates the sandbox root: a SIGINT/
    // SIGTERM/SIGHUP arriving in the window between root creation and the fork below
    // would otherwise hit the default (process-killing) disposition and leak the whole
    // /tmp/raincoat-* tree because cleanup_root() never runs. With the handlers armed
    // here, such a signal is merely recorded (g_pending_signal) — every code path from
    // mkdtemp onward funnels through cleanup_root(), and once the child exists the
    // signal is forwarded to it (see the fork section) so waitpid() returns and the
    // normal teardown still runs. No process-terminating disposition can fire between
    // root creation and teardown.
    g_child_pid = 0;
    g_pending_signal = 0;
    struct sigaction sa;
    std::memset(&sa, 0, sizeof(sa));
    sa.sa_handler = forward_terminating_signal;
    ::sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;  // no SA_RESTART: let waitpid() return EINTR so we re-check.
    struct sigaction old_int, old_term, old_hup;
    ::sigaction(SIGINT, &sa, &old_int);
    ::sigaction(SIGTERM, &sa, &old_term);
    ::sigaction(SIGHUP, &sa, &old_hup);
    auto restore_signals = [&]() {
        ::sigaction(SIGINT, &old_int, nullptr);
        ::sigaction(SIGTERM, &old_term, nullptr);
        ::sigaction(SIGHUP, &old_hup, nullptr);
        g_child_pid = 0;
    };

    // ---- Egress bridge server (phase 2) ---------------------------------
    // Declared here at function scope so its destructor tears down every loopback
    // listener + worker thread on ANY return path (errors, signals, normal exit) — no
    // orphaned listeners. It is only started() when egress-bridge mode is active; an
    // unstarted server destructs harmlessly (stop() is idempotent). When active, the
    // sandbox SHARES the host network namespace (see resolve_config: cfg.net forced to a
    // shared/Full mode, so build_bwrap_argv emits no --unshare-net) so the child can
    // reach 127.0.0.1:<bridge>. This does NOT jail the network: the bridge only hides the
    // real upstream URL from the child's env/config; the child keeps general host network
    // access. Documented, honest limitation (docs/EGRESS.md).
    const bool egress_active = cfg.ext.egress.enabled;
    EgressServer egress_srv;

    // ---- Guarded proxy server (phase 4) ---------------------------------
    // Declared at function scope so its destructor tears down the loopback listener +
    // every worker thread on ANY return path (errors, signals, normal exit) — no orphaned
    // proxy. Started() only when [network_policy].enabled; an unstarted server destructs
    // harmlessly (stop() is idempotent). When active the sandbox SHARES the host network
    // namespace (resolve_config forced cfg.net Full) so the child can reach the proxy at
    // 127.0.0.1:<proxy_port>; composed with the pasta netns jail below, bwrap joins that
    // jail and the proxy port is forwarded (-T). The actual bound port is published here so
    // the env injection, the jail forward list, and the audit all agree on it.
    const bool netpolicy_active = cfg.ext.network_policy.enabled;
    ProxyServer proxy_srv;
    int proxy_port = -1;

    // ---- Egress isolation mode decision (isolated netns vs shared loopback) ----
    // When egress is active AND the profile did not opt out ([egress].isolate_netns
    // != off) AND pasta is available on the host, run the child inside pasta's
    // ISOLATED network namespace: `pasta --config-net -t none -T <bridge-ports> --
    // bwrap ...`. bwrap then JOINS pasta's netns (it must NOT --unshare-net, which the
    // egress path already guarantees since cfg.net is Full). MEASURED on this host:
    //   * the child reaches each bridge at 127.0.0.1:<child_port> (child_endpoint is
    //     unchanged — pasta -T forwards ns loopback:port to the host bridge);
    //   * the host-side bridge's upstream socket stays in the HOST netns, so the
    //     child's /proc/net/tcp NEVER reveals the real upstream IP:port (the shared-
    //     loopback /proc-net leak is FIXED);
    //   * `-t none` means ONLY the forwarded bridge ports are reachable on the ns
    //     loopback — other host-loopback services are NOT (tighter than shared mode);
    //   * pasta still NATs general outbound traffic, so the child retains general
    //     outbound internet by IP — this is a NAT, NOT a per-destination firewall.
    // When pasta is absent (or isolate_netns=off) fall back to the shared-loopback
    // model with the existing honest warning.
    //
    // STRICT level (isolate_netns=strict): the jail additionally BLOCKS general internet.
    // The runner appends `-o 127.0.0.1` (pasta --outbound bound to loopback) to the pasta
    // args below, so pasta cannot NAT the child's traffic out any real interface — only the
    // `-T <bridge-ports>` forwards keep working. MEASURED on this host: with `-o 127.0.0.1`
    // the child's connections to real IPs (e.g. 1.1.1.1) time out while the bridge still
    // reaches the upstream. The result is a true per-destination (bridge-only) egress
    // firewall. Strict REQUIRES pasta: there is no safe shared-loopback equivalent (shared
    // loopback would hand the child general host network), so strict-without-pasta fails
    // CLOSED (refused below) rather than silently downgrading to general internet.
    // The netns jail composes with BOTH egress and the guarded proxy. For network policy
    // the jail is what turns the allow/block list into a REAL egress firewall: in STRICT
    // mode pasta forwards ONLY the proxy port and blocks general outbound, so the proxy is
    // the child's sole way out. Without the jail (or in on/auto, which NAT general
    // outbound) the policy only constrains proxy-aware clients — disclosed honestly below.
    const NetnsIsolation isolate_mode = cfg.ext.egress.isolate_netns;
    const bool jail_requested =
        (egress_active || netpolicy_active) && isolate_mode != NetnsIsolation::Off;
    std::optional<std::string> pasta_path;
    if (jail_requested) pasta_path = find_pasta();
    const bool jail_active = jail_requested && pasta_path.has_value();
    // Strict jail: block general internet by binding pasta's outbound to loopback. Only
    // meaningful once the jail is actually active (pasta present).
    const bool strict_jail = jail_active && isolate_mode == NetnsIsolation::Strict;

    // Fail CLOSED for STRICT without pasta. Strict promises "only the bridge, no general
    // internet". The shared-loopback fallback used by auto/on would instead give the child
    // GENERAL host network access — the exact opposite of strict. Rather than silently
    // downgrade (fail OPEN), refuse the run with an actionable error. This returns before
    // mkdtemp(), so only the signal handlers (armed in step 0) need restoring; no sandbox
    // root exists to clean up yet.
    if ((egress_active || netpolicy_active) && isolate_mode == NetnsIsolation::Strict &&
        !pasta_path.has_value()) {
        err =
            "Error: [egress].isolate_netns = \"strict\" blocks the child's general internet "
            "and exposes ONLY the forwarded loopback port(s) (the egress bridge and/or the "
            "guarded proxy), which requires `pasta` (passt) to run the child in an isolated "
            "network namespace — but pasta was not found on this host. There is no safe "
            "shared-loopback equivalent of \"strict\" (sharing the host loopback would grant "
            "the child general host network access), so the run is refused (fail-closed) "
            "rather than silently downgraded. Install pasta, or set isolate_netns to "
            "\"on\"/\"auto\" (jail with general internet via NAT) or \"off\" (shared "
            "loopback).";
        restore_signals();
        return 1;
    }

    // ---- 1. Create the sandbox root + fixed sub-tree ---------------------
    const char* tmpdir_env = std::getenv("TMPDIR");
    std::string base = (tmpdir_env && *tmpdir_env) ? tmpdir_env : "/tmp";
    std::string tmpl = base + "/raincoat-XXXXXX";
    std::vector<char> tbuf(tmpl.begin(), tmpl.end());
    tbuf.push_back('\0');
    if (::mkdtemp(tbuf.data()) == nullptr) {
        err = "Error: could not create sandbox directory: " +
              std::string(std::strerror(errno));
        restore_signals();
        return 1;
    }
    const std::string root(tbuf.data());

    const std::string fake_home = root + "/home/user";
    const std::string sandbox_tmp = root + "/tmp";
    // Dedicated writable scratch dir (SPEC `<temp>/out`), bound into the sandbox so
    // the child has a private output area that is destroyed with the sandbox root.
    const std::string sandbox_out = root + "/out";

    // Remove the sandbox root unless the user asked to keep it.
    auto cleanup_root = [&]() {
        if (cfg.keep_temp) {
            std::cerr << "kept sandbox: " << root << "\n";
        } else {
            std::error_code ec;
            std::filesystem::remove_all(root, ec);
        }
    };

    {
        std::string derr;
        if (!make_dirs(fake_home, derr) || !make_dirs(sandbox_tmp, derr) ||
            !make_dirs(sandbox_out, derr)) {
            err = "Error: could not set up sandbox: " + derr;
            cleanup_root();
            restore_signals();
            return 1;
        }
    }

    // ---- 2. Real HOME (fs guard only; never mounted) ---------------------
    std::string real_home;
    if (auto it = parent_env.find("HOME"); it != parent_env.end()) real_home = it->second;

    // ---- 3. Environment resolution + fake HOME/TMPDIR --------------------
    // Generic identity values come from the profile ([identity]); defaults preserve
    // the MVP behavior (USER/LOGNAME "user", hostname "sandbox").
    const std::string identity_user = cfg.ext.username.value_or("user");
    const std::string identity_host = cfg.ext.hostname.value_or("sandbox");
    EnvPolicy env_policy;
    env_policy.deny = cfg.ext.env_deny;
    env_policy.scrub_patterns = cfg.ext.scrub_patterns;
    env_policy.username = identity_user;
    EnvResolution env = resolve_env(parent_env, cfg.allow_env, cfg.set_env,
                                    cfg.env_defaults, cfg.strict, env_policy);
    env.resolved["HOME"] = fake_home;
    env.resolved["TMPDIR"] = sandbox_tmp;

    // Promote a variable into the "set" category. Because these names were
    // remapped to synthetic sandbox values (not dropped), they must also leave
    // BOTH the "scrubbed" and "allowed" lists that resolve_env populated before
    // we injected them into env.resolved — otherwise the audit log
    // double-classifies the same variable (SPEC: the three categories are
    // disjoint). In particular, `--allow-env HOME`/`TMPDIR` files the name under
    // `allowed` ("copied verbatim from parent"), but we then override the value
    // with a synthetic sandbox path, so `set` is the only truthful category.
    auto record_set = [&](const std::string& name) {
        if (std::find(env.set.begin(), env.set.end(), name) == env.set.end())
            env.set.push_back(name);
        env.scrubbed.erase(
            std::remove(env.scrubbed.begin(), env.scrubbed.end(), name),
            env.scrubbed.end());
        env.allowed.erase(
            std::remove(env.allowed.begin(), env.allowed.end(), name),
            env.allowed.end());
    };
    record_set("HOME");
    record_set("TMPDIR");

    // USER, like HOME, must only ever carry a SYNTHETIC value — the real login
    // name must never reach the child. resolve_env forces USER="user", but a
    // later `--allow-env USER` (step 5) copies the real username verbatim,
    // silently re-exposing it. Re-assert the generic value here (mirroring the
    // HOME/TMPDIR hard override) unless the user explicitly supplied one via
    // `--set-env USER=...`, which is a value the user chose and is honored.
    bool user_set_explicitly =
        std::any_of(cfg.set_env.begin(), cfg.set_env.end(),
                    [](const std::pair<std::string, std::string>& kv) {
                        return kv.first == "USER";
                    });
    if (!user_set_explicitly) {
        env.resolved["USER"] = identity_user;
        record_set("USER");
    }

    // LOGNAME is the other common source of the login name (many programs derive
    // the username from it), so it needs the same guard as USER: force the generic
    // value unless the user explicitly chose one via `--set-env LOGNAME=...`.
    // Without this, `--allow-env LOGNAME` would copy the real login name verbatim
    // and defeat the never-leak-the-real-username invariant.
    bool logname_set_explicitly =
        std::any_of(cfg.set_env.begin(), cfg.set_env.end(),
                    [](const std::pair<std::string, std::string>& kv) {
                        return kv.first == "LOGNAME";
                    });
    if (!logname_set_explicitly) {
        env.resolved["LOGNAME"] = identity_user;
        record_set("LOGNAME");
    }

    // HOSTNAME is a machine fingerprint the child can trivially read to learn the
    // real host name. The UTS namespace already carries the generic `--hostname
    // <ext.hostname>` (default "sandbox"), so mirror that same value in the
    // environment unless the user explicitly chose one via `--set-env HOSTNAME`.
    // Combined with env_guard never copying HOSTNAME through --allow-env, the real
    // host name can never reach the child.
    bool hostname_set_explicitly =
        std::any_of(cfg.set_env.begin(), cfg.set_env.end(),
                    [](const std::pair<std::string, std::string>& kv) {
                        return kv.first == "HOSTNAME";
                    });
    if (!hostname_set_explicitly) {
        env.resolved["HOSTNAME"] = identity_host;
        record_set("HOSTNAME");
    }

    // ---- 3e. Egress bridge: start listeners + inject child endpoints -----
    // BEFORE launching bwrap, bind each bridge's loopback listener and inject the
    // child-visible endpoint into the child env. The upstream_endpoint is NEVER injected
    // — only the generic child_endpoint. `child_visible[name]` records the endpoint we
    // actually injected (with the real bound port substituted for a ":0" placeholder) so
    // the audit reflects what the child received. If start() fails (e.g. the port is
    // already in use), abort the run rather than silently proceed WITHOUT the bridge —
    // the child would otherwise get no endpoint and the run would misbehave.
    std::map<std::string, std::string> child_visible;
    // In jail mode these are the actual bound bridge ports that pasta must forward from
    // the child's netns loopback to the host bridge (`-T <ports>`). Collected here where
    // the real (possibly ":0"-resolved) port is known.
    std::vector<int> jail_forward_ports;
    if (egress_active) {
        std::string serr;
        if (!egress_srv.start(cfg.ext.egress, serr)) {
            err = "Error: could not start egress bridge: " + serr;
            cleanup_root();
            restore_signals();
            return 1;
        }
        for (const auto& br : cfg.ext.egress.bridges) {
            // Reconstruct the child-visible endpoint with the ACTUAL bound port (handles
            // a ":0" ephemeral request). Fall back to the configured string on any parse
            // hiccup — start() already validated it, so this is belt-and-suspenders.
            std::string endpoint = br.child_endpoint;
            Url u;
            std::string uerr;
            int port = egress_srv.port_for(br.name);
            if (port > 0 && parse_url(br.child_endpoint, u, uerr)) {
                endpoint = u.scheme + "://" + u.host + ":" + std::to_string(port) + u.path;
            }
            if (port > 0) jail_forward_ports.push_back(port);
            if (!br.env.empty()) {
                env.resolved[br.env] = endpoint;
                record_set(br.env);
            }
            child_visible[br.name] = endpoint;
        }
    }

    // ---- 3f. Guarded proxy (phase 4): start + inject http(s)_proxy -------
    // BEFORE launching the sandbox, bind the filtering forward proxy on a host loopback
    // ephemeral port and inject http_proxy/https_proxy/all_proxy pointing at it. The proxy
    // checks each request's target host against cfg.ext.network_policy and forwards or 403s.
    // Failure to bind aborts the run (fail-closed) rather than launching the child WITHOUT
    // the policy in force. The reused egress timeout bounds per-connection idle waits.
    if (netpolicy_active) {
        std::string perr;
        if (!proxy_srv.start("127.0.0.1", 0, cfg.ext.network_policy,
                             cfg.ext.egress.timeout_seconds, perr)) {
            err = "Error: could not start guarded proxy: " + perr;
            cleanup_root();
            restore_signals();
            return 1;
        }
        proxy_port = proxy_srv.port();
        const std::string proxy_url = "http://127.0.0.1:" + std::to_string(proxy_port);
        // Inject the proxy endpoint. This OVERRIDES any external [proxy].enabled values that
        // resolve_env already folded into env.resolved: Raincoat's guarded proxy takes
        // precedence, and the external proxy URL (which can carry credentials) is neither
        // used nor logged. Assigning env.resolved[...] replaces the value; record_set files
        // the name under "set" (and removes it from allowed/scrubbed) so the audit is honest.
        //
        // CASE MATTERS: real HTTP clients honour BOTH the lowercase and UPPERCASE spellings of
        // these variables (curl/wget/Go read HTTPS_PROXY/ALL_PROXY/NO_PROXY; Python urllib folds
        // case for NO_PROXY). If we only touched the lowercase names, a leftover UPPERCASE
        // HTTPS_PROXY (pointing a client at an ATTACKER proxy) or NO_PROXY=* (telling a proxy-
        // aware client to skip the guarded proxy) would defeat the policy — even for the
        // proxy-aware clients we claim to constrain. Match case-INSENSITIVELY (rather than a
        // fixed set of literal spellings) so ANY casing the attacker slips in is handled.
        auto lower = [](std::string s) {
            for (char& c : s)
                c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
            return s;
        };
        auto drop_name = [](std::vector<std::string>& v, const std::string& n) {
            v.erase(std::remove(v.begin(), v.end(), n), v.end());
        };
        auto drop_from_audit = [&](const std::string& n) {
            drop_name(env.set, n);
            drop_name(env.allowed, n);
            drop_name(env.scrubbed, n);
        };
        // First pass: erase EVERY case spelling of a proxy-related var already present in the
        // resolved env (http/https/all_proxy AND no_proxy), plus its audit-name entries. This
        // removes an attacker-supplied UPPERCASE HTTPS_PROXY, a mixed-case No_Proxy, an ambient
        // --allow-env'd bypass list, etc. — nothing survives to override or skip the proxy.
        for (auto it = env.resolved.begin(); it != env.resolved.end();) {
            const std::string lk = lower(it->first);
            if (lk == "http_proxy" || lk == "https_proxy" || lk == "all_proxy" ||
                lk == "no_proxy") {
                drop_from_audit(it->first);
                it = env.resolved.erase(it);
            } else {
                ++it;
            }
        }
        // Second pass: inject the guarded-proxy endpoint under both the lowercase and UPPERCASE
        // canonical spellings so every proxy-aware client reads it. no_proxy is left ABSENT (an
        // empty bypass list), so no host can be dialed around the proxy.
        for (const char* k : {"http_proxy", "https_proxy", "all_proxy",
                              "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"}) {
            env.resolved[k] = proxy_url;
            record_set(k);
        }
        // In jail mode the child reaches the proxy at 127.0.0.1:<proxy_port> on the netns
        // loopback ONLY because pasta forwards it (-T). Add it to the forward set so the
        // isolated-netns wrapping below exposes the proxy port to the child.
        if (proxy_port > 0) jail_forward_ports.push_back(proxy_port);
    }

    // ---- 4. Fontconfig isolation (best-effort) ---------------------------
    std::string ferr;
    FontSetup font = setup_fontconfig(root, cfg.fontconfig_enabled,
                                      assets_dir + "/fontconfig/fonts.conf", ferr);
    for (const auto& kv : font.env) {
        env.resolved[kv.first] = kv.second;
        record_set(kv.first);
    }

    // ---- 4a2. Browser isolation (best-effort) ----------------------------
    // Creates a throwaway browser profile dir and (when use_launch_shims) generic PATH
    // launch shims that start Chromium/Chrome/Firefox with low-information flags. We
    // merge its env (TZ) into the child, PREPEND the shim dir to the child PATH so the
    // shims win, and (below, after mount planning) bind the profile + shim dirs into the
    // sandbox so they are reachable. Honest limitation surfaced in the audit note.
    std::string browser_shim_dir, browser_profile_dir, browser_note;
    if (cfg.ext.browser.enabled) {
        std::string berr;
        BrowserSetup browser = setup_browser(cfg.ext.browser, root, berr);
        for (const auto& kv : browser.env) {
            env.resolved[kv.first] = kv.second;
            record_set(kv.first);
        }
        browser_shim_dir = browser.shim_dir;
        browser_profile_dir = browser.profile_dir;
        browser_note = browser.note;
        if (!browser_shim_dir.empty()) {
            // Prepend the shim dir so the shims are found before the real browser.
            auto it = env.resolved.find("PATH");
            if (it != env.resolved.end() && !it->second.empty())
                it->second = browser_shim_dir + ":" + it->second;
            else
                // No PATH in the resolved env (rare: the base allowlist normally copies
                // it). Prepend the shim dir onto a sane default so the child keeps
                // resolvable base bin dirs rather than ONLY the shim dir.
                env.resolved["PATH"] = browser_shim_dir + ":/usr/bin:/bin";
            // Raincoat REWROTE PATH (prepended the shim dir), so it is no longer the
            // parent's verbatim value. Reclassify it as "set" (mirroring HOME/TMPDIR and
            // the font env vars) so the tamper-evident audit does not label the modified
            // PATH as "allowed" ("copied verbatim from parent").
            record_set("PATH");
        }
        if (!berr.empty()) std::cerr << "raincoat: note: " << berr << "\n";
    }

    // ---- 4b. Tripwire bait files (inside the FAKE home only) -------------
    // When [filesystem.tripwire] is enabled, plant harmless decoy "credential" files
    // inside the fake home so a probing tool that goes looking for ~/.ssh/id_rsa,
    // ~/.aws/credentials, etc. finds inert bait instead of nothing. A leading "~/" (or
    // "/") maps to the fake home root; every write is normalized to stay UNDER the fake
    // home — the real home is never touched. Best-effort: a failure to plant one bait
    // file is noted but never fatal.
    std::size_t tripwire_planted = 0;
    if (cfg.ext.tripwire_enabled) {
        namespace fs = std::filesystem;
        const fs::path home_root = fs::path(fake_home).lexically_normal();
        for (const auto& spec : cfg.ext.tripwire_files) {
            std::string rel = spec;
            if (rel.rfind("~/", 0) == 0) rel = rel.substr(2);
            else if (!rel.empty() && rel[0] == '~') rel = rel.substr(1);
            while (!rel.empty() && rel[0] == '/') rel = rel.substr(1);
            if (rel.empty()) continue;
            fs::path target = (home_root / rel).lexically_normal();
            // Containment guard: never escape the fake home (e.g. a "../" spec).
            const std::string ts = target.string();
            const std::string hs = home_root.string();
            if (ts.size() < hs.size() || ts.compare(0, hs.size(), hs) != 0) continue;
            std::string derr;
            if (!make_dirs(target.parent_path().string(), derr)) continue;
            std::ofstream bait(target, std::ios::binary | std::ios::trunc);
            if (!bait) continue;
            // Inert content — decidedly NOT a real credential.
            bait << "# raincoat tripwire decoy — not a real credential\n";
            if (bait) ++tripwire_planted;
        }
    }

    // ---- 5. Filesystem mount planning ------------------------------------
    std::string warning;
    std::vector<Mount> mounts = plan_mounts(cfg, cwd, real_home, err, warning);
    if (!err.empty()) {
        // The SPEC "allowed path does not exist" case: report and bail.
        std::cerr << err << "\n";
        err.clear();  // already surfaced; don't let the caller double-print.
        cleanup_root();
        restore_signals();
        return 1;
    }
    if (cfg.strict && !any_writable(mounts)) {
        if (!warning.empty()) warning += "\n";
        warning +=
            "Warning: strict mode with no writable paths allowed; the command may "
            "fail. Grant one with --allow-write <path>.";
    }

    // ---- 5a2. Browser isolation binds ------------------------------------
    // The browser profile + shim dirs live under the sandbox root (or a user path), so
    // like the fontconfig dir they need explicit binds to be reachable inside the
    // sandbox. Profile is read-write (the browser writes it); the shims are read-only.
    if (cfg.ext.browser.enabled) {
        if (!browser_profile_dir.empty())
            mounts.push_back(
                Mount{browser_profile_dir, browser_profile_dir, MountMode::ReadWrite});
        if (!browser_shim_dir.empty())
            mounts.push_back(
                Mount{browser_shim_dir, browser_shim_dir, MountMode::ReadOnly});
    }

    // ---- 5b. Minimal /etc view -------------------------------------------
    // Provide GENERIC /etc files so the child sees a neutral machine identity and a
    // usable timezone, WITHOUT ever exposing the host's real /etc/hostname or
    // /etc/hosts (which are trivial fingerprints). The files are written into the
    // sandbox temp tree and bound read-only at their canonical /etc paths; they are
    // destroyed with the sandbox root. /etc/localtime is bound from the host zoneinfo
    // for the resolved TZ (falling back to UTC) only when that file exists.
    bool etc_hostname = false, etc_hosts = false, etc_localtime = false, etc_machine_id = false;
    {
        const std::string etc_dir = root + "/etc";
        std::string derr;
        if (make_dirs(etc_dir, derr)) {
            // Constant generic /etc/machine-id (a stable per-install identifier the host
            // would otherwise expose, or leave absent). A shared constant is non-
            // identifying; configurable via backend.machine_id.
            if (cfg.ext.backend.machine_id) {
                const std::string mid_path = etc_dir + "/machine-id";
                std::ofstream mf(mid_path, std::ios::binary | std::ios::trunc);
                mf << *cfg.ext.backend.machine_id << "\n";
                if (mf) {
                    mounts.push_back(
                        Mount{mid_path, "/etc/machine-id", MountMode::ReadOnly});
                    etc_machine_id = true;
                }
            }
            const std::string hostname_path = etc_dir + "/hostname";
            const std::string hosts_path = etc_dir + "/hosts";
            {
                std::ofstream hf(hostname_path, std::ios::binary | std::ios::trunc);
                hf << identity_host << "\n";
                if (hf) {
                    mounts.push_back(
                        Mount{hostname_path, "/etc/hostname", MountMode::ReadOnly});
                    etc_hostname = true;
                }
            }
            {
                std::ofstream hf(hosts_path, std::ios::binary | std::ios::trunc);
                hf << "127.0.0.1 localhost\n::1 localhost\n127.0.1.1 " << identity_host
                   << "\n";
                if (hf) {
                    mounts.push_back(
                        Mount{hosts_path, "/etc/hosts", MountMode::ReadOnly});
                    etc_hosts = true;
                }
            }
            std::string tz = default_or_empty(env.resolved, "TZ");
            if (tz.empty()) tz = "UTC";
            const std::string zoneinfo = "/usr/share/zoneinfo/" + tz;
            std::error_code zec;
            if (std::filesystem::is_regular_file(zoneinfo, zec) && !zec) {
                mounts.push_back(
                    Mount{zoneinfo, "/etc/localtime", MountMode::ReadOnly});
                etc_localtime = true;
            }
        }
    }

    // ---- 5c. Disabled-fontconfig main config -----------------------------
    // When fontconfig isolation is DISABLED, font_guard writes no fonts.conf and
    // sets no FONTCONFIG_FILE, and the base sandbox never binds the host /etc. With
    // no main config, every fontconfig client prints "Cannot load default config
    // file" on stderr and falls back to compiled-in defaults. Disabled is meant to
    // mean "host fonts, NORMAL fontconfig" — so bind the host's real /etc/fonts
    // read-only, giving fontconfig its usual config over the (unmasked) host font
    // tree. Read-only and best-effort: absence just restores the prior behavior. In
    // the ENABLED path this is intentionally skipped (FONTCONFIG_FILE is pinned and
    // the curated conf must win, not the host /etc/fonts).
    bool etc_fonts_bound = false;
    if (!cfg.fontconfig_enabled) {
        std::error_code fec;
        if (std::filesystem::is_directory("/etc/fonts", fec) && !fec) {
            mounts.push_back(Mount{"/etc/fonts", "/etc/fonts", MountMode::ReadOnly});
            etc_fonts_bound = true;
        }
    }
    (void)etc_fonts_bound;

    // ---- 6. Effective working directory ----------------------------------
    // Prefer cfg.workdir when it lands inside a mounted path; otherwise fall
    // back to the fake HOME (the cwd was withheld: strict, or the home guard).
    std::string workdir_canon = canonicalize(cfg.workdir).value_or(cfg.workdir);
    bool workdir_mounted = false;
    for (const auto& m : mounts) {
        if (path_within(workdir_canon, m.sandbox_path)) {
            workdir_mounted = true;
            break;
        }
    }
    // When mounted, use the absolute canonical path the mount is keyed on — the
    // raw cfg.workdir may be a relative string (e.g. "sub"), and bwrap --chdir
    // starts at "/" inside the sandbox, so a relative target would not exist.
    std::string effective_workdir = workdir_canon;
    if (!workdir_mounted) {
        effective_workdir = fake_home;
        if (!warning.empty()) warning += "\n";
        warning += "Note: working directory is not mounted; using the fake home (" +
                   fake_home + ") instead.";
    }

    Config cfg_copy = cfg;
    cfg_copy.workdir = effective_workdir;

    // Fail-safe + honesty: network=off MUST actually isolate the network. A profile
    // that pairs `network = "off"` with `[backend].unshare_net_when_off = false` would
    // otherwise suppress the ONLY isolation mechanism (--unshare-net), leaving the child
    // in the HOST network namespace with full connectivity while the audit still
    // headlines "Network: off". Rather than emit that dishonest audit (or silently grant
    // unintended network), force the isolation back on and tell the user their backend
    // toggle was overridden. The audit backend-overrides note below reads cfg_copy, so
    // it reflects the forced (honest) value.
    if (cfg.net == NetMode::Off && !cfg.ext.backend.unshare_net_when_off) {
        cfg_copy.ext.backend.unshare_net_when_off = true;
        if (!warning.empty()) warning += "\n";
        warning +=
            "Warning: network=off requires network isolation; overriding "
            "[backend].unshare_net_when_off=false so the sandbox is genuinely offline "
            "(the child would otherwise share the host network namespace).";
    }

    // Fail-safe + honesty: raincoat ALWAYS masks the host name from the child. Step 3
    // unconditionally injects a generic HOSTNAME (cfg.ext.hostname.value_or("sandbox"))
    // into the env and the audit asserts the real host name can never reach the child.
    // But the ONLY mechanism that hides the kernel/UTS host name — what gethostname(),
    // `hostname`, and `uname -n` return — is bwrap's --hostname, which build_bwrap_argv
    // gates on --unshare-uts. A profile with [backend].unshare_uts=false would therefore
    // inherit the HOST UTS namespace and leak the real host name while $HOSTNAME says
    // "sandbox": a dishonest false assurance. This applies to BOTH a configured
    // [identity].hostname AND the plain default-hostname case (no [identity].hostname),
    // so the override must NOT be gated on cfg.ext.hostname.has_value(). Mirror the
    // net=off override: force the UTS namespace back on so the generic hostname genuinely
    // takes effect, and disclose the forced toggle. build_bwrap_argv and the backend-
    // overrides audit note both read cfg_copy, so both reflect the forced (honest) value.
    if (!cfg.ext.backend.unshare_uts) {
        cfg_copy.ext.backend.unshare_uts = true;
        if (!warning.empty()) warning += "\n";
        warning +=
            "Warning: the sandbox masks the host name (HOSTNAME=" + identity_host +
            ") but [backend].unshare_uts=false would leave the child in the host UTS "
            "namespace, leaking the real host name via gethostname()/hostname/uname; "
            "overriding it to true so the generic hostname is genuinely applied.";
    }

    // Fail-safe + honesty: a reserved restrictive network mode (proxy/bridge/guarded) is
    // not yet enforced. resolve_config already failed CLOSED (net forced to Off unless a
    // CLI --net overrode it), but that only shows in the audit log. Surface it on stderr
    // too so a user who never opens the audit still learns their egress restriction was
    // not applied and what networking they actually got.
    if (cfg.ext.reserved_net_mode.has_value() && !egress_active) {
        if (!warning.empty()) warning += "\n";
        warning +=
            "Warning: network mode \"" + *cfg.ext.reserved_net_mode +
            "\" is not yet enforced; the configured egress restriction was NOT applied. "
            "Networking fell back to \"" + std::string(to_string(cfg.net)) +
            "\" (fail-closed to off unless overridden with --net).";
    }

    // Honest disclosure when egress-bridge mode is active. The message MUST reflect the
    // MEASURED reality of the mode actually selected: an isolated pasta netns jail, or the
    // shared-loopback fallback. Surface it on stderr so a user who never opens the audit
    // still learns the model.
    if (egress_active && strict_jail) {
        if (!warning.empty()) warning += "\n";
        warning +=
            "Note: egress bridge mode is active in STRICT ISOLATED-NETNS mode (pasta " +
            *pasta_path +
            "). The child runs in a private network namespace with pasta's outbound bound "
            "to loopback (-o 127.0.0.1), so its general outbound internet is BLOCKED "
            "(connections to real IPs fail/time out). The child can reach ONLY the "
            "configured bridge endpoint(s) at 127.0.0.1:<port> (relayed to the upstream) "
            "and has NO other network access — no general internet, and no other "
            "host-loopback services. For this STRICT level, egress is a per-destination "
            "(bridge-only) firewall. The host-side bridge's upstream socket stays in the "
            "host network namespace, so the child's /proc/net/tcp does NOT reveal the real "
            "upstream IP:port.";
    } else if (egress_active && jail_active) {
        if (!warning.empty()) warning += "\n";
        warning +=
            "Note: egress bridge mode is active in ISOLATED-NETNS mode (pasta " +
            *pasta_path +
            "). The child runs in a private network namespace and reaches the "
            "configured upstream(s) via the injected loopback bridge. The host-side "
            "bridge's upstream socket stays in the host network namespace, so the "
            "child's /proc/net/tcp does NOT reveal the real upstream IP:port. The "
            "child is NOT fully network-jailed: pasta NATs general outbound traffic, "
            "so it retains general outbound internet by IP (a NAT, not a per-"
            "destination firewall). Other host-loopback services are NOT reachable.";
    } else if (egress_active) {
        if (jail_requested && !pasta_path.has_value()) {
            // The profile asked for (or defaulted to) the isolated jail but pasta is not
            // installed. Fall back to shared-loopback and say so honestly.
            if (!warning.empty()) warning += "\n";
            warning +=
                "Warning: egress isolate_netns was requested but `pasta` was not found "
                "on this host; falling back to the shared-loopback model. Install pasta "
                "(passt) to run the child in an isolated network namespace and hide the "
                "upstream socket from the child's /proc/net/tcp.";
        }
        if (!warning.empty()) warning += "\n";
        warning +=
            "Note: egress bridge mode is active; the sandbox SHARES the host network "
            "namespace so the child can reach the loopback bridge. The bridge hides the "
            "upstream URL from the child's environment, but the child is NOT network-jailed "
            "(it retains general host network access, and the resolved upstream IP:port is "
            "observable via /proc/net/tcp).";
    }

    // Honest disclosure for the guarded proxy. Surface on stderr so a user who never opens
    // the audit still learns whether the allow/block list is a REAL firewall (strict jail:
    // proxy is the only egress) or merely constrains proxy-aware clients (shared net or a
    // NAT jail, where a raw-IP / proxy-ignoring client bypasses the policy).
    if (netpolicy_active) {
        const std::string purl = "http://127.0.0.1:" + std::to_string(proxy_port);
        if (!warning.empty()) warning += "\n";
        if (strict_jail) {
            warning +=
                "Note: network policy is enforced by the guarded proxy (" + purl +
                ") AND the STRICT netns jail (pasta -o 127.0.0.1) forwards ONLY the proxy "
                "port, so the proxy is the child's ONLY egress path: the allow/block host "
                "list is a REAL domain-level egress firewall (direct, non-proxy connections "
                "are blocked).";
        } else if (jail_active) {
            warning +=
                "Note: guarded proxy active (" + purl +
                "); the netns jail NATs general outbound traffic, so a client that ignores "
                "http_proxy or connects to a raw IP can still reach the internet — the "
                "allow/block list only constrains proxy-aware clients. Use "
                "[egress].isolate_netns = \"strict\" to make it a real egress firewall.";
        } else {
            warning +=
                "Note: guarded proxy active (" + purl +
                ") on the SHARED host network; only proxy-aware clients are constrained (a "
                "client that ignores http_proxy/https_proxy or connects to a raw IP bypasses "
                "the policy, and the child retains general host network access). Compose "
                "[egress].isolate_netns = \"strict\" with pasta to forward only the proxy "
                "port and make the allow/block list a real egress firewall.";
        }
    }

    // ---- 7. Locate the bubblewrap backend --------------------------------
    // An explicit [backend].bwrap_path (ext.backend.bwrap_path) overrides auto-find,
    // but only when it names an actual executable — otherwise fall back to the PATH
    // search so a stale profile path does not hard-fail a runnable host.
    std::optional<std::string> bwrap_path;
    if (!cfg.ext.backend.bwrap_path.empty()) {
        const std::string& bp = cfg.ext.backend.bwrap_path;
        if (bp.find('/') != std::string::npos && ::access(bp.c_str(), X_OK) == 0) {
            bwrap_path = bp;  // absolute/relative path to a real executable
        }
    }
    if (!bwrap_path.has_value()) bwrap_path = find_bwrap();
    if (!bwrap_path.has_value()) {
        std::cerr << kBwrapMissing;
        cleanup_root();
        restore_signals();
        return 127;
    }

    // ---- 8. Assemble the bwrap argv --------------------------------------
    // Mask the audit-log directory inside the sandbox when it lands in a writable
    // mount (normally the auto-mounted cwd), so the untrusted child cannot forge or
    // erase the log raincoat writes. Empty when the audit dir is unreachable by the
    // child (no masking needed).
    std::string mask_dir = audit_mask_dir(cfg.audit_log_path, mounts);
    // Footgun guard: the child CAN write the audit dir (a writable mount reaches it)
    // but we are NOT masking it — either a custom --audit-log points into a user
    // --allow-write'd data dir, or the user redundantly --allow-write'd .raincoat. The
    // log is not tamper-proof for this run, so surface that instead of failing silently.
    // The same condition means the child can READ the on-disk audit, which matters for
    // egress: the "start" block is written before the fork, so if it carried the real
    // upstream (redact_upstreams_in_audit=false) the child could read the upstream out
    // of the audit file. We force upstream redaction in that case (below) and disclose
    // it here rather than leak silently under this double opt-out.
    const bool audit_child_reachable =
        mask_dir.empty() && audit_dir_child_writable(cfg.audit_log_path, mounts);
    // The egress upstream leak is about the child READING the on-disk audit "start"
    // block (written before the fork), which a READ-ONLY mount permits just as well as a
    // read-write one. audit_dir_child_writable only classifies read-write mounts (correct
    // for the tamper warning below), so it would MISS a `--audit-log` inside an
    // `--allow-read`'d directory — a child-readable audit that is not child-writable. Use
    // the broader readability test for the egress redaction decision so the real upstream
    // can never be read out of the audit regardless of the mount's read/write mode.
    const bool audit_child_readable =
        mask_dir.empty() && audit_dir_child_readable(cfg.audit_log_path, mounts);
    if (audit_child_reachable) {
        if (!warning.empty()) warning += "\n";
        warning +=
            "Warning: the audit log (" + cfg.audit_log_path +
            ") is inside a writable path the sandboxed command can reach; it is NOT "
            "tamper-protected and the command could forge or erase it. Use the default "
            "--audit-log location (.raincoat/) to keep the log tamper-proof.";
    }
    if (egress_active && audit_child_readable && !cfg.ext.egress.redact_upstreams_in_audit) {
        if (!warning.empty()) warning += "\n";
        warning +=
            "Warning: because egress is active and this audit log is child-readable, the "
            "real upstream endpoint(s) would be readable by the child from the on-disk "
            "audit; upstream redaction is being FORCED for this run despite "
            "redact_upstreams_in_audit=false. Move --audit-log to the default (.raincoat/) "
            "location to record the real upstream safely.";
    }
    // Egress profile-leak guard: the --profile file contains upstream_endpoint values.
    // If that file lives inside a path mounted into the sandbox (e.g. it sits in the
    // auto-mounted cwd), the child could read the real upstream straight out of the file
    // — defeating the whole point of hiding it. Detect that and shadow the file with an
    // empty read-only bind so the child sees nothing. Skipped when the user explicitly
    // opted out of hiding upstreams ([egress].hide_upstreams_from_child = false). Only
    // relevant when egress is active AND a profile was loaded.
    std::string mask_empty_file;
    std::vector<std::string> mask_files;
    if (egress_active && cfg.ext.egress.hide_upstreams_from_child &&
        cfg.profile_path.has_value() && !cfg.profile_path->empty()) {
        std::string prof_canon =
            canonicalize(*cfg.profile_path).value_or(absolutize(*cfg.profile_path, cwd));
        bool prof_reachable = false;
        for (const auto& m : mounts) {
            if (path_within(prof_canon, m.sandbox_path)) {
                prof_reachable = true;
                break;
            }
        }
        if (prof_reachable) {
            // Hardlink-alias leak guard: the mask below shadows the profile by PATH (a bind
            // mount over its canonical name). A SECOND hardlink to the same inode under a
            // different name inside a mounted path is a distinct directory entry the path-
            // based mask does NOT cover, so the child could read the real upstream straight
            // out of the alias while the canonical name reads empty. We cannot cheaply
            // enumerate every alias across all mounts, so fail CLOSED when the profile has
            // more than one link rather than leak: refuse the run and tell the user how to
            // proceed (move the profile outside the mounted paths, drop the extra hardlinks,
            // or opt out via [egress].hide_upstreams_from_child = false).
            struct ::stat pst;
            if (::stat(prof_canon.c_str(), &pst) == 0 && pst.st_nlink > 1) {
                err = "Error: the --profile at " + prof_canon +
                      " is reachable by the sandboxed child and has additional hardlinks "
                      "(link count " + std::to_string(static_cast<unsigned long>(pst.st_nlink)) +
                      "); raincoat masks the profile by path and cannot shadow every hardlink "
                      "alias, so an alias would leak the real egress upstream endpoint. Move "
                      "the profile outside the mounted paths, remove the extra hardlinks, or "
                      "set [egress].hide_upstreams_from_child = false to allow it.";
                cleanup_root();
                restore_signals();
                return 1;
            }
            // Create a raincoat-owned empty file on the host to bind over the profile.
            mask_empty_file = root + "/.rc-egress-mask-empty";
            std::ofstream ef(mask_empty_file, std::ios::binary | std::ios::trunc);
            if (ef) {
                ef.close();
                mask_files.push_back(prof_canon);
                if (!warning.empty()) warning += "\n";
                warning +=
                    "Note: the --profile file (" + prof_canon +
                    ") is inside a path mounted into the sandbox and contains egress "
                    "upstream endpoints; it is masked (shadowed with an empty file) so the "
                    "child cannot read the real upstream from it.";
            } else {
                // Could not create the mask file: refuse rather than leak the upstream.
                mask_empty_file.clear();
                err = "Error: could not create egress profile mask file (" +
                      mask_empty_file + "); refusing to run because the --profile at " +
                      prof_canon +
                      " is reachable by the child and would leak the real upstream "
                      "endpoint. Move the profile outside the mounted paths, or set "
                      "[egress].hide_upstreams_from_child = false to allow it.";
                cleanup_root();
                restore_signals();
                return 1;
            }
        }
    }

    // Curated font isolation: when fontconfig is enabled and at least one curated
    // font dir exists on the host, pass them so build_bwrap_argv masks
    // /usr/share/fonts and re-binds ONLY the curated set (see font_guard). Empty when
    // fontconfig is disabled (font.font_dirs is only populated on the enabled path),
    // leaving the host font tree untouched — the documented disabled behavior.
    // Only ask build_bwrap_argv to mask /usr/local/share/fonts when that dir actually
    // exists on the host. It sits under /usr/local (an FHS "local admin install" tree
    // no distro package populates), so it is frequently absent even when curated fonts
    // exist under /usr/share/fonts. bwrap cannot mkdir a tmpfs mountpoint under the
    // read-only /usr bind, so an unconditional `--tmpfs /usr/local/share/fonts` aborts
    // the WHOLE run on such hosts. When the dir is absent there is nothing to leak, so
    // skipping the mask is safe. /usr/share/fonts needs no such guard: a non-empty
    // curated list guarantees it exists (every curated dir lives beneath it).
    bool mask_usr_local_fonts = false;
    {
        std::error_code lec;
        mask_usr_local_fonts =
            std::filesystem::is_directory("/usr/local/share/fonts", lec) && !lec;
    }

    // Generic /proc fingerprint masks. When proc is mounted, synthesize generic host
    // files and hand build_bwrap_argv a list of {host_file, /proc target} overlays that
    // it binds over the fresh procfs, so the child cannot read the host's exact CPU
    // (/proc/cpuinfo) or kernel (/proc/version + /proc/sys/kernel/{osrelease,version})
    // as fingerprints. cpuinfo is x86-only (see host_is_x86); elsewhere it is left
    // untouched. Non-fatal: any write failure just leaves that real file exposed
    // (best-effort, like the other masks).
    std::vector<std::pair<std::string, std::string>> proc_overlays;
    bool cpuinfo_masked = false;
    bool cpuinfo_skipped_arch = false;
    bool kernel_masked = false;
    bool meminfo_masked = false;
    bool uptime_masked = false;
    bool boot_id_masked = false;
    if (cfg.ext.backend.mount_proc) {
        auto write_overlay = [&](const std::string& name, const std::string& target,
                                 const std::string& content) -> bool {
            const std::string path = root + "/" + name;
            std::ofstream f(path, std::ios::binary | std::ios::trunc);
            f << content;
            if (!f) return false;
            proc_overlays.emplace_back(path, target);
            return true;
        };
        const BackendConfig& bk = cfg.ext.backend;
        // cpuinfo: faked when either cpu identity value is set; unset one -> generic default.
        if (bk.cpu_vendor_id || bk.cpu_model_name) {
            if (host_is_x86()) {
                cpuinfo_masked = write_overlay(
                    ".rc-cpuinfo", "/proc/cpuinfo",
                    generic_cpuinfo(std::thread::hardware_concurrency(),
                                    bk.cpu_vendor_id.value_or("GenuineIntel"),
                                    bk.cpu_model_name.value_or("Generic x86_64 Processor")));
            } else {
                cpuinfo_skipped_arch = true;
            }
        }
        // kernel: faked when either kernel value is set. For /proc/version (a composite of
        // release + build string) the UNSET part uses the host's REAL value, honoring
        // "unset => system". The individual mirror files are written only for the value set.
        if (bk.kernel_osrelease || bk.kernel_version) {
            struct utsname real;
            const bool have_real = (::uname(&real) == 0);
            const std::string rel =
                bk.kernel_osrelease.value_or(have_real ? real.release : "6.1.0-generic");
            const std::string ver = bk.kernel_version.value_or(
                have_real ? real.version : "#1 SMP PREEMPT_DYNAMIC Generic");
            bool v = write_overlay(".rc-version", "/proc/version",
                                   generic_proc_version(rel, ver));
            bool r = true, k = true;
            if (bk.kernel_osrelease)
                r = write_overlay(".rc-osrelease", "/proc/sys/kernel/osrelease",
                                  *bk.kernel_osrelease + "\n");
            if (bk.kernel_version)
                k = write_overlay(".rc-kversion", "/proc/sys/kernel/version",
                                  *bk.kernel_version + "\n");
            kernel_masked = v && r && k;
        }
        if (bk.mem_total_kb) {
            meminfo_masked = write_overlay(".rc-meminfo", "/proc/meminfo",
                                           generic_meminfo(*bk.mem_total_kb));
        }
        if (bk.uptime_seconds) {
            const std::string u = std::to_string(*bk.uptime_seconds) + ".00";
            bool up = write_overlay(".rc-uptime", "/proc/uptime", u + " " + u + "\n");
            bool la = write_overlay(".rc-loadavg", "/proc/loadavg", "0.00 0.00 0.00 1/128 1\n");
            uptime_masked = up && la;
        }
        if (bk.boot_id) {
            boot_id_masked = write_overlay(".rc-bootid", "/proc/sys/kernel/random/boot_id",
                                           *bk.boot_id + "\n");
        }
    }

    std::vector<std::string> argv =
        build_bwrap_argv(*bwrap_path, cfg_copy, mounts, env, fake_home, sandbox_tmp,
                         binds_resolv_conf(cfg.net), font.dir, mask_dir, sandbox_out,
                         mask_empty_file, mask_files, font.font_dirs, mask_usr_local_fonts,
                         proc_overlays);

    // ---- 8b. Isolated-netns wrapping (pasta) -----------------------------
    // In jail mode the child runs inside pasta's private network namespace: prepend
    //   pasta --config-net -t none -T <bridge-ports> --
    // to the bwrap argv. bwrap does NOT --unshare-net here (cfg.net is Full on the
    // egress path), so it JOINS pasta's netns. `-t none` disables inbound forwarding
    // (host->ns); `-T <ports>` forwards ONLY the bridge port(s) from the ns loopback to
    // the host bridge, so the child reaches 127.0.0.1:<child_port> (child_endpoint is
    // unchanged) while no other host-loopback service is exposed. The program that is
    // exec'd becomes pasta; pasta runs bwrap as its child and propagates its exit code.
    // MEASURED: the host-side bridge's upstream socket lives in the host netns, so the
    // child's /proc/net/tcp does NOT reveal it — the shared-loopback leak is fixed.
    std::string launch_path = *bwrap_path;
    if (jail_active) {
        std::vector<std::string> wrapped;
        wrapped.reserve(argv.size() + 8);
        wrapped.push_back(*pasta_path);
        wrapped.push_back("--config-net");
        wrapped.push_back("-t");
        wrapped.push_back("none");
        if (!jail_forward_ports.empty()) {
            std::string spec;
            for (std::size_t i = 0; i < jail_forward_ports.size(); ++i) {
                if (i) spec += ",";
                spec += std::to_string(jail_forward_ports[i]);
            }
            wrapped.push_back("-T");
            wrapped.push_back(spec);
        }
        // STRICT: bind pasta's outbound to loopback so general internet is BLOCKED while
        // the `-T` bridge forward(s) still work. MEASURED on this host: with `-o 127.0.0.1`
        // the child cannot reach real IPs (they time out) but the forwarded bridge port
        // still reaches the upstream — a true "only the bridge, nothing else" jail. Without
        // it (auto/on) pasta NATs general outbound, so the child keeps general internet.
        if (strict_jail) {
            wrapped.push_back("-o");
            wrapped.push_back("127.0.0.1");
        }
        wrapped.push_back("--");
        for (auto& tok : argv) wrapped.push_back(std::move(tok));
        argv = std::move(wrapped);
        launch_path = *pasta_path;
    }

    // ---- 9. Audit record -------------------------------------------------
    AuditRecord rec;
    rec.command_line = join_command(cfg.command);
    rec.strict = cfg.strict;
    rec.net = cfg.net;
    rec.fake_home = fake_home;
    rec.workdir = effective_workdir;
    rec.mounts = mounts;
    rec.env = env;
    rec.font = font.status;
    // Source from the resolved env, not cfg.env_defaults: --set-env overrides
    // (which live in cfg.set_env, never cfg.env_defaults) are already folded into
    // env.resolved, so this reflects what the child actually received.
    rec.timezone = default_or_empty(env.resolved, "TZ");
    rec.locale = default_or_empty(env.resolved, "LANG");
    rec.bwrap_command = redact_argv_for_audit(argv, cfg.command.size());

    // Rich sectioned-config transparency. NAMES/counts only — never a secret VALUE.
    rec.profile_name = cfg.ext.profile_name;
    rec.reserved_notes = cfg.ext.reserved_notes;
    if (!cfg.ext.env_deny.empty()) {
        rec.active_policy_notes.push_back(
            "env deny list active (" + std::to_string(cfg.ext.env_deny.size()) +
            " name(s) never passed through)");
    }
    if (!cfg.ext.scrub_patterns.empty()) {
        rec.active_policy_notes.push_back(
            "custom env scrub patterns active (" +
            std::to_string(cfg.ext.scrub_patterns.size()) +
            " glob(s) extending the built-in sensitive-name rules)");
    }
    if (!cfg.ext.fs_deny.empty()) {
        rec.active_policy_notes.push_back(
            "filesystem deny list active (" + std::to_string(cfg.ext.fs_deny.size()) +
            " path(s) never mounted)");
    }
    if (cfg.ext.fs_deny_by_default.value_or(false)) {
        rec.active_policy_notes.push_back(
            "filesystem deny-by-default: the working directory is not auto-mounted");
    }
    {
        // Backend overrides relative to the safe defaults (BackendConfig defaults).
        const BackendConfig def;  // MVP defaults
        // Read the EFFECTIVE backend (cfg_copy), which reflects the net=off isolation
        // override above, so the note never lists a toggle we silently forced back on.
        const BackendConfig& b = cfg_copy.ext.backend;
        std::vector<std::string> flags;
        if (b.unshare_user != def.unshare_user)
            flags.push_back(std::string("unshare_user=") + (b.unshare_user ? "on" : "off"));
        if (b.unshare_cgroup != def.unshare_cgroup)
            flags.push_back(std::string("unshare_cgroup=") + (b.unshare_cgroup ? "on" : "off"));
        if (b.unshare_pid != def.unshare_pid)
            flags.push_back(std::string("unshare_pid=") + (b.unshare_pid ? "on" : "off"));
        if (b.unshare_ipc != def.unshare_ipc)
            flags.push_back(std::string("unshare_ipc=") + (b.unshare_ipc ? "on" : "off"));
        if (b.unshare_uts != def.unshare_uts)
            flags.push_back(std::string("unshare_uts=") + (b.unshare_uts ? "on" : "off"));
        if (b.unshare_net_when_off != def.unshare_net_when_off)
            flags.push_back(std::string("unshare_net_when_off=") +
                            (b.unshare_net_when_off ? "on" : "off"));
        if (b.mount_proc != def.mount_proc)
            flags.push_back(std::string("mount_proc=") + (b.mount_proc ? "on" : "off"));
        if (b.mount_dev != def.mount_dev)
            flags.push_back(std::string("mount_dev=") + (b.mount_dev ? "on" : "off"));
        if (b.mount_tmpfs_tmp != def.mount_tmpfs_tmp)
            flags.push_back(std::string("mount_tmpfs_tmp=") + (b.mount_tmpfs_tmp ? "on" : "off"));
        if (b.die_with_parent != def.die_with_parent)
            flags.push_back(std::string("die_with_parent=") + (b.die_with_parent ? "on" : "off"));
        if (!b.bwrap_path.empty())
            flags.push_back("bwrap_path set");
        if (!flags.empty()) {
            std::string note = "backend overrides: ";
            for (std::size_t i = 0; i < flags.size(); ++i) {
                if (i) note += ", ";
                note += flags[i];
            }
            rec.active_policy_notes.push_back(note);
        }
    }
    if (cfg.ext.tripwire_enabled) {
        rec.active_policy_notes.push_back(
            "tripwire bait planted in the fake home (" +
            std::to_string(tripwire_planted) + " file(s))");
    }
    if (cfg.ext.browser.enabled) {
        const bool shims_on = !browser_shim_dir.empty();
        std::string note = "Browser isolation: enabled (";
        note += browser_note.empty()
                    ? ("profile " + browser_profile_dir + ", shims " +
                       (shims_on ? "on" : "off"))
                    : browser_note;
        note += ")";
        if (shims_on)
            note +=
                " — shims only affect a browser launched by name via PATH (an absolute-"
                "path launch or overridden flags are not constrained)";
        rec.active_policy_notes.push_back(note);
    }
    if (etc_hostname || etc_hosts || etc_localtime) {
        std::string files;
        auto add = [&](const char* f) {
            if (!files.empty()) files += ", ";
            files += f;
        };
        if (etc_hostname) add("hostname");
        if (etc_hosts) add("hosts");
        if (etc_localtime) add("localtime");
        rec.active_policy_notes.push_back(
            "Minimal /etc provided (generic, host /etc never exposed): " + files);
    }
    if (cpuinfo_masked) {
        rec.active_policy_notes.push_back(
            "/proc/cpuinfo masked with a generic block (host CPU model/stepping/"
            "microcode/MHz/flags hidden; logical-processor count preserved). Best-"
            "effort fingerprint reduction — the uname() kernel/arch string is NOT "
            "faked and other /proc and /sys entries remain the host's.");
    } else if (cpuinfo_skipped_arch) {
        rec.active_policy_notes.push_back(
            "/proc/cpuinfo left unmasked: fake_cpuinfo only synthesizes an x86 block, "
            "and this is a non-x86 host where a wrong-arch fake would mislead tools.");
    }
    if (kernel_masked) {
        rec.active_policy_notes.push_back(
            "Kernel identity masked: /proc/version and /proc/sys/kernel/{osrelease,version} "
            "show a generic kernel (host release + distro build host hidden). Best-effort — "
            "the uname() SYSCALL is NOT faked, so a tool calling it directly still sees the "
            "real kernel; only the /proc file reads are covered.");
    }
    if (etc_machine_id) {
        rec.active_policy_notes.push_back(
            "/etc/machine-id presented as a constant generic value (host per-install "
            "identifier not exposed).");
    }
    if (meminfo_masked) {
        rec.active_policy_notes.push_back(
            "/proc/meminfo masked (host RAM size hidden; generic self-consistent totals).");
    }
    if (uptime_masked) {
        rec.active_policy_notes.push_back(
            "/proc/uptime and /proc/loadavg masked with generic constants (uptime/load "
            "correlation signal hidden).");
    }
    if (boot_id_masked) {
        rec.active_policy_notes.push_back(
            "/proc/sys/kernel/random/boot_id presented as a constant (per-boot correlation "
            "UUID hidden).");
    }
    const bool note_uname =
        cfg.ext.backend.kernel_osrelease.has_value() || cfg.ext.backend.kernel_version.has_value();
    const bool note_sysinfo =
        cfg.ext.backend.mem_total_kb.has_value() || cfg.ext.backend.uptime_seconds.has_value();
    if (note_uname || note_sysinfo) {
        std::string which;
        if (note_uname) which += "uname(2)";
        if (note_sysinfo)
            which += (which.empty() ? "" : " + ") + std::string("sysinfo(2)");
        if (seccomp_identity_supported()) {
            rec.active_policy_notes.push_back(
                which + " syscall(s) faked via a seccomp user-notify supervisor: even a "
                "static/Go binary calling them directly sees the same generic identity as "
                "the /proc masks. Best-effort — installs a seccomp filter + supervisor "
                "thread; on setup failure the trapped call returns ENOSYS.");
        } else {
            rec.active_policy_notes.push_back(
                which + " syscall mask requested but unsupported on this arch (x86_64 "
                "only) — left real.");
        }
    }

    // Egress bridge transparency. Honest network-model disclosure + one summary per
    // bridge (name, child-visible endpoint, injected env var name). The real upstream is
    // recorded ONLY when redaction was explicitly disabled; by default it is hidden. The
    // upstream_endpoint is NEVER placed in the child env (only child_endpoint is).
    if (egress_active && strict_jail) {
        rec.active_policy_notes.push_back(
            "egress bridge active in STRICT ISOLATED-NETNS mode (pasta " + *pasta_path +
            "): the child runs in a PRIVATE network namespace (pasta --config-net -t "
            "none -o 127.0.0.1 -T <bridge-ports>) and bwrap joins it (no --unshare-net). "
            "pasta's outbound is bound to loopback (-o 127.0.0.1), so the child's general "
            "outbound internet is BLOCKED — connections to real IPs fail/time out. The "
            "child can reach ONLY the forwarded bridge port(s) at their child_endpoint "
            "(127.0.0.1:<port>, relayed to the configured upstream(s)); it has NO general "
            "internet access and NO access to other host-loopback services. MEASURED on "
            "this host: the host-side bridge's upstream socket lives in the HOST network "
            "namespace, so the child's /proc/net/tcp does NOT reveal the real upstream "
            "IP:port — the shared-loopback /proc-net leak is FIXED. For this STRICT level "
            "ONLY, egress is restricted to the configured bridge endpoint(s): this IS a "
            "per-destination (bridge-only) egress firewall. (The \"on\"/\"auto\" levels "
            "still NAT general outbound internet; only \"strict\" blocks it.)");
    } else if (egress_active && jail_active) {
        rec.active_policy_notes.push_back(
            "egress bridge active in ISOLATED-NETNS mode (pasta " + *pasta_path +
            "): the child runs in a PRIVATE network namespace (pasta --config-net -t "
            "none -T <bridge-ports>) and bwrap joins it (no --unshare-net). The child "
            "reaches each configured upstream via the injected loopback bridge at its "
            "child_endpoint (127.0.0.1:<port>, forwarded to the host-side bridge). "
            "MEASURED on this host: the host-side bridge's upstream socket lives in the "
            "HOST network namespace, so the child's /proc/net/tcp does NOT reveal the "
            "real upstream IP:port — the shared-loopback /proc-net leak is FIXED. Only "
            "the forwarded bridge port(s) are reachable on the ns loopback; other host-"
            "loopback services are NOT. The child is NOT fully network-jailed: pasta "
            "NATs general outbound traffic, so it retains general outbound internet by "
            "IP (a NAT, not a per-destination firewall).");
    } else if (egress_active) {
        rec.active_policy_notes.push_back(
            "egress bridge active (shared-loopback mode): the sandbox SHARES the host "
            "network namespace so the child can reach the loopback bridge; the child is "
            "NOT network-jailed (general host network remains reachable). The bridge only "
            "hides upstream URLs from the child's environment/config; because the net "
            "namespace is shared, the resolved upstream IP:port is still observable to the "
            "child via /proc/net/tcp. Install pasta and keep [egress].isolate_netns != off "
            "to run in an isolated netns that fixes this /proc-net leak.");
    }
    if (egress_active) {
        if (!mask_files.empty()) {
            rec.active_policy_notes.push_back(
                "egress profile-leak guard: the --profile file is reachable by the child "
                "and was masked (shadowed with an empty file) so the real upstream cannot "
                "be read from it.");
        }
        // Per-bridge redaction decision. An upstream is hidden in the audit when ANY of:
        //   * the global [egress].redact_upstreams_in_audit is on (default true), OR
        //   * this bridge's per-bridge hide_upstream is on (default true), OR
        //   * the audit log is child-READABLE — forced closed regardless of the settings:
        //     the "start" block is written to disk before the fork, so an un-redacted
        //     upstream there is readable by the child through ANY mount (read-only OR
        //     read-write); the user was warned above.
        // Honoring br.hide_upstream here makes the per-bridge knob live: to expose exactly
        // one upstream in the audit a user must BOTH disable the global redaction AND set
        // that single bridge's hide_upstream=false (every other bridge stays hidden by its
        // own default-true hide_upstream). The default (both true) hides everything.
        for (const auto& br : cfg.ext.egress.bridges) {
            const bool redact =
                audit_hides_upstream(cfg.ext.egress, br, audit_child_readable);
            EgressBridgeAudit ba;
            ba.name = br.name;
            auto it = child_visible.find(br.name);
            ba.child_endpoint =
                (it != child_visible.end()) ? it->second : br.child_endpoint;
            ba.injected_env = br.env;
            ba.upstream_hidden = redact;
            if (!redact) ba.upstream = br.upstream_endpoint;
            rec.egress_bridges.push_back(std::move(ba));
        }
    }

    // Network policy / guarded proxy transparency (phase 4). COUNTS + the loopback proxy
    // endpoint only — never the host names, never a secret. The honest firewall-vs-proxy-
    // aware reality is recorded as an active policy note so behaviour is never overclaimed.
    if (netpolicy_active) {
        const NetworkPolicy& np = cfg.ext.network_policy;
        rec.network_policy_enabled = true;
        rec.network_policy_default_action = np.default_action;
        rec.guarded_proxy_endpoint = "http://127.0.0.1:" + std::to_string(proxy_port);
        rec.network_policy_allow_count = np.allow_hosts.size();
        rec.network_policy_block_count = np.block_hosts.size();
        rec.network_policy_metadata_blocked = np.block_private_metadata_endpoints;
        // Document the precedence honestly: if an external proxy was ALSO configured
        // ([proxy].enabled or --set-env http_proxy/…), the guarded proxy OVERRODE it. The
        // external proxy is not used and its value (which can carry credentials) is never
        // logged — only its presence is noted here.
        bool external_proxy_configured = false;
        for (const auto& kv : cfg.set_env) {
            if (kv.first == "http_proxy" || kv.first == "https_proxy" ||
                kv.first == "all_proxy" || kv.first == "no_proxy") {
                external_proxy_configured = true;
                break;
            }
        }
        if (external_proxy_configured) {
            rec.active_policy_notes.push_back(
                "an external proxy was configured ([proxy] or --set-env) but the guarded "
                "proxy takes PRECEDENCE: http_proxy/https_proxy/all_proxy were overridden to "
                "the loopback guarded proxy, any no_proxy bypass list was dropped, and the "
                "external proxy value (possibly carrying credentials) is neither used nor "
                "logged.");
        }
        if (strict_jail) {
            rec.active_policy_notes.push_back(
                "network policy enforced by the guarded proxy; the STRICT netns jail (pasta "
                "-o 127.0.0.1) forwards ONLY the proxy port, so the proxy is the child's "
                "ONLY egress path and the allow/block host list is a REAL domain-level "
                "egress firewall — a direct, non-proxy connection from the child is blocked.");
        } else if (jail_active) {
            rec.active_policy_notes.push_back(
                "network policy active behind the guarded proxy; the netns jail NATs general "
                "outbound traffic, so a client that ignores http_proxy or dials a raw IP "
                "still reaches the internet — the allow/block list only constrains proxy-"
                "aware clients. Use [egress].isolate_netns = \"strict\" for a real firewall.");
        } else {
            rec.active_policy_notes.push_back(
                "network policy active behind the guarded proxy on the SHARED host network; "
                "only proxy-aware clients are constrained (a client that ignores http_proxy "
                "or dials a raw IP bypasses the policy, and the child retains general host "
                "network access). Compose [egress].isolate_netns = \"strict\" with pasta to "
                "forward only the proxy port and make the allow/block list a real egress "
                "firewall.");
        }
    }

    // ---- 10. Write the audit "start" block (+ any warnings) --------------
    // JSON format emits a SINGLE object per run (it carries the exit code, so it can
    // only be written AFTER the child is reaped — see step 12). Text format writes the
    // truthful "start" block BEFORE the fork (tamper-evidence: the child cannot forge
    // facts recorded before it ran). Warnings always go to stderr regardless of format.
    rec.warnings = warning;
    const bool audit_json = cfg.ext.audit_format == AuditFormat::Json;
    if (!warning.empty()) std::cerr << warning << "\n";
    if (!audit_json) {
        std::string start_content = format_audit_start(rec);
        if (!warning.empty()) start_content += "Warnings:\n  " + warning + "\n";
        std::string aerr;
        if (!write_audit(cfg.audit_log_path, start_content, aerr)) {
            std::cerr << "raincoat: note: " << aerr << "\n";
        }
    }

    // ---- 11. Fork + exec the sandboxed command ---------------------------
    // If a terminating signal already arrived during startup (handlers were armed in
    // step 0, before mkdtemp), abort before launching the child: tear down the sandbox
    // and exit with the conventional 128+signo code. Without this the child would spawn
    // only to be immediately killed by the forwarded signal below; bailing here is
    // cleaner and skips the pointless bwrap launch.
    if (g_pending_signal != 0) {
        int sig = static_cast<int>(g_pending_signal);
        cleanup_root();
        restore_signals();
        return 128 + sig;
    }

    std::vector<char*> cargv;
    cargv.reserve(argv.size() + 1);
    for (auto& s : argv) cargv.push_back(const_cast<char*>(s.c_str()));
    cargv.push_back(nullptr);

    // Identity-syscall mask (Tier 2: uname(2), sysinfo(2)). When enabled and supported, install
    // a seccomp user-notify filter in the child (it survives execve, so bwrap and the target
    // inherit it) and service the trapped calls from a supervisor thread in this (unfiltered)
    // parent, returning the same generic identity the /proc masks show. The BPF program is built
    // HERE (parent) so the child path stays allocation-free; the listener fd is handed back over
    // a socketpair. Best-effort: any setup failure disables the hook and leaves the syscalls
    // real (the kernel returns ENOSYS to any orphaned trap). See docs/FINGERPRINT-SYSCALLS.md.
    // The syscall hooks turn on with the same values that drive the /proc file masks: a set
    // kernel value hooks uname(2); a set memory/uptime value hooks sysinfo(2).
    const bool want_uname =
        cfg.ext.backend.kernel_osrelease.has_value() || cfg.ext.backend.kernel_version.has_value();
    const bool want_sysinfo =
        cfg.ext.backend.mem_total_kb.has_value() || cfg.ext.backend.uptime_seconds.has_value();
    bool id_hook = (want_uname || want_sysinfo) && seccomp_identity_supported();
    std::vector<sock_filter> id_prog;
    int sc_sock[2] = {-1, -1};
    if (id_hook) {
        id_prog = build_identity_filter_program(want_uname, want_sysinfo);
        if (::socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sc_sock) != 0) {
            id_hook = false;
            sc_sock[0] = sc_sock[1] = -1;
        }
    }

    pid_t pid = ::fork();
    if (pid < 0) {
        err = "Error: fork failed: " + std::string(std::strerror(errno));
        if (id_hook) { ::close(sc_sock[0]); ::close(sc_sock[1]); }
        restore_signals();
        cleanup_root();
        return 1;
    }
    if (pid == 0) {
        if (id_hook) {
            ::close(sc_sock[0]);  // parent end
            seccomp_child_install_and_send(sc_sock[1], id_prog.data(),
                                           static_cast<unsigned int>(id_prog.size()));
            ::close(sc_sock[1]);
        }
        ::execvp(launch_path.c_str(), cargv.data());
        // Only reached if exec failed.
        std::perror(jail_active ? "raincoat: failed to exec pasta"
                                : "raincoat: failed to exec bwrap");
        _exit(127);
    }

    // Publish the child pid to the handler; if a signal already fired in the tiny
    // window before this assignment, forward it now so we don't swallow it.
    g_child_pid = pid;
    if (g_pending_signal != 0) ::kill(pid, static_cast<int>(g_pending_signal));

    // Bring up the identity supervisor thread. It runs with SIGINT/SIGTERM/SIGHUP blocked so
    // those keep hitting the main thread's handlers; the main thread waits on the child while
    // the supervisor answers notifications concurrently (no waitpid/notify deadlock).
    std::atomic<bool> id_stop{false};
    std::thread id_thread;
    int id_listener = -1;
    if (id_hook) {
        ::close(sc_sock[1]);  // child end
        id_listener = seccomp_recv_listener_fd(sc_sock[0]);
        ::close(sc_sock[0]);
        if (id_listener >= 0) {
            IdentitySpoof spoof;
            spoof.trap_uname = want_uname;
            spoof.trap_sysinfo = want_sysinfo;
            spoof.uts_nodename = identity_host;
            spoof.uts_release = cfg.ext.backend.kernel_osrelease;
            spoof.uts_version = cfg.ext.backend.kernel_version;
            if (cfg.ext.backend.mem_total_kb)
                spoof.sys_total_ram_bytes = *cfg.ext.backend.mem_total_kb * 1024;
            spoof.sys_uptime_seconds = cfg.ext.backend.uptime_seconds;
            sigset_t block, old;
            sigemptyset(&block);
            sigaddset(&block, SIGINT);
            sigaddset(&block, SIGTERM);
            sigaddset(&block, SIGHUP);
            pthread_sigmask(SIG_BLOCK, &block, &old);
            id_thread = std::thread(seccomp_supervise_identity, id_listener,
                                    spoof, std::ref(id_stop));
            pthread_sigmask(SIG_SETMASK, &old, nullptr);
        } else {
            id_hook = false;  // no listener; kernel makes trapped syscalls return ENOSYS
        }
    }
    // Tear down the supervisor thread (idempotent): stop it and join before returning on any
    // path, so its std::thread is never destroyed while joinable.
    auto stop_id_supervisor = [&]() {
        if (id_thread.joinable()) {
            id_stop.store(true);
            id_thread.join();
        }
        if (id_listener >= 0) {
            ::close(id_listener);
            id_listener = -1;
        }
    };

    int status = 0;
    while (::waitpid(pid, &status, 0) < 0) {
        if (errno != EINTR) {
            err = "Error: waitpid failed: " + std::string(std::strerror(errno));
            stop_id_supervisor();
            restore_signals();
            cleanup_root();
            return 1;
        }
    }
    // The child has been reaped: clear the published pid as the VERY FIRST action so
    // a terminating signal arriving before restore_signals() re-installs the default
    // dispositions cannot make the handler kill() a now-reaped (possibly kernel-
    // recycled) pid. forward_terminating_signal only signals when g_child_pid > 0.
    g_child_pid = 0;
    // Child gone: no more uname() callers, so stop and join the supervisor before we
    // proceed to teardown/audit.
    stop_id_supervisor();
    restore_signals();

    // Child reaped: tear down the egress bridge listeners + worker threads now (free the
    // loopback ports promptly). stop() is idempotent and the destructor would also cover
    // this, but doing it explicitly here matches the lifecycle and releases ports before
    // the audit/cleanup work below. On the error/signal return paths above, the
    // function-scope EgressServer destructor performs the same teardown — no orphans.
    egress_srv.stop();
    // Same lifecycle for the guarded proxy: close the listener + drain workers now (free the
    // loopback port promptly). stop() is idempotent and the function-scope ProxyServer
    // destructor covers every error/signal return path above — no orphaned proxy.
    proxy_srv.stop();

    int exit_code;
    if (WIFEXITED(status)) {
        exit_code = WEXITSTATUS(status);
    } else if (WIFSIGNALED(status)) {
        exit_code = 128 + WTERMSIG(status);
    } else {
        exit_code = 1;
    }

    // ---- 12. Write the audit "end"/JSON block ----------------------------
    // Text: append the one-line "finished" block after the pre-fork start block.
    // JSON: write the complete single-object record now (it needs the exit code).
    {
        std::string content = audit_json ? format_audit_json(rec, exit_code)
                                         : format_audit_end(exit_code);
        std::string aerr;
        if (!write_audit(cfg.audit_log_path, content, aerr)) {
            std::cerr << "raincoat: note: " << aerr << "\n";
        }
    }

    // ---- 13. Tear down the sandbox ---------------------------------------
    cleanup_root();

    // ---- 14. Propagate the child's exit code -----------------------------
    return exit_code;
}

}  // namespace raincoat
