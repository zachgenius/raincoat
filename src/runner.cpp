// Raincoat — runner: resolve config + orchestrate the sandboxed run.
#include "runner.hpp"

#include <algorithm>
#include <cerrno>
#include <csignal>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include <sys/wait.h>
#include <unistd.h>

#include "audit.hpp"
#include "bwrap.hpp"
#include "doctor.hpp"
#include "env_guard.hpp"
#include "font_guard.hpp"
#include "fs_guard.hpp"
#include "net_guard.hpp"
#include "profile.hpp"
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
    // Network resolution + reserved fallback.
    //   * An explicit net (CLI --net or profile network=full|off) always wins.
    //   * A reserved restrictive mode (proxy/bridge/guarded) leaves options.net unset but
    //     sets ext.reserved_net_mode (see load_profile). It is NOT yet enforced, so fail
    //     CLOSED: fall back to NetMode::Off regardless of strict — never Full. The user
    //     asked to CONSTRAIN egress; defaulting to unrestricted networking would be the
    //     exact opposite of that intent (a fail-OPEN downgrade). run() also warns on
    //     stderr so a user who never reads the audit still learns the mode was unapplied.
    //   * Otherwise (flat/absent profile) keep the MVP default: Off in strict, Full else.
    if (options.net.has_value()) {
        cfg.net = *options.net;
    } else if (options.ext.reserved_net_mode.has_value()) {
        cfg.net = NetMode::Off;
    } else {
        cfg.net = cfg.strict ? NetMode::Off : NetMode::Full;
    }

    // Carry the merged rich sectioned config through to Config. run() wires ext into
    // the live sandbox (identity, env policy, backend toggles, fs deny, tripwire, audit).
    cfg.ext = options.ext;

    // Reconcile the reserved network-mode note with the RESOLVED network. The note was
    // recorded at profile-load time, BEFORE resolution knew whether an explicit --net
    // would override the fail-closed fallback (options.net wins above). Rewriting it from
    // the actual cfg.net keeps the tamper-proof audit honest: it must never simultaneously
    // headline "Network: full" AND swear the network fails closed to off. Only assert
    // fail-closed-to-off when cfg.net is genuinely Off; otherwise state the real outcome.
    if (cfg.ext.reserved_net_mode.has_value()) {
        const std::string& mode = *cfg.ext.reserved_net_mode;
        std::string reconciled;
        if (cfg.net == NetMode::Off) {
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

    // ---- 4. Fontconfig isolation (best-effort) ---------------------------
    std::string ferr;
    FontSetup font = setup_fontconfig(root, cfg.fontconfig_enabled,
                                      assets_dir + "/fontconfig/fonts.conf", ferr);
    for (const auto& kv : font.env) {
        env.resolved[kv.first] = kv.second;
        record_set(kv.first);
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
    if (cfg.ext.reserved_net_mode.has_value()) {
        if (!warning.empty()) warning += "\n";
        warning +=
            "Warning: network mode \"" + *cfg.ext.reserved_net_mode +
            "\" is not yet enforced; the configured egress restriction was NOT applied. "
            "Networking fell back to \"" + std::string(to_string(cfg.net)) +
            "\" (fail-closed to off unless overridden with --net).";
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
    if (mask_dir.empty() && audit_dir_child_writable(cfg.audit_log_path, mounts)) {
        if (!warning.empty()) warning += "\n";
        warning +=
            "Warning: the audit log (" + cfg.audit_log_path +
            ") is inside a writable path the sandboxed command can reach; it is NOT "
            "tamper-protected and the command could forge or erase it. Use the default "
            "--audit-log location (.raincoat/) to keep the log tamper-proof.";
    }
    std::vector<std::string> argv =
        build_bwrap_argv(*bwrap_path, cfg_copy, mounts, env, fake_home, sandbox_tmp,
                         binds_resolv_conf(cfg.net), font.dir, mask_dir, sandbox_out);

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

    // ---- 10. Write the audit "start" block (+ any warnings) --------------
    if (!warning.empty()) std::cerr << warning << "\n";
    std::string start_content = format_audit_start(rec);
    if (!warning.empty()) start_content += "Warnings:\n  " + warning + "\n";
    {
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

    pid_t pid = ::fork();
    if (pid < 0) {
        err = "Error: fork failed: " + std::string(std::strerror(errno));
        restore_signals();
        cleanup_root();
        return 1;
    }
    if (pid == 0) {
        ::execvp(bwrap_path->c_str(), cargv.data());
        // Only reached if exec failed.
        std::perror("raincoat: failed to exec bwrap");
        _exit(127);
    }

    // Publish the child pid to the handler; if a signal already fired in the tiny
    // window before this assignment, forward it now so we don't swallow it.
    g_child_pid = pid;
    if (g_pending_signal != 0) ::kill(pid, static_cast<int>(g_pending_signal));

    int status = 0;
    while (::waitpid(pid, &status, 0) < 0) {
        if (errno != EINTR) {
            err = "Error: waitpid failed: " + std::string(std::strerror(errno));
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
    restore_signals();

    int exit_code;
    if (WIFEXITED(status)) {
        exit_code = WEXITSTATUS(status);
    } else if (WIFSIGNALED(status)) {
        exit_code = 128 + WTERMSIG(status);
    } else {
        exit_code = 1;
    }

    // ---- 12. Write the audit "end" block ---------------------------------
    {
        std::string aerr;
        if (!write_audit(cfg.audit_log_path, format_audit_end(exit_code), aerr)) {
            std::cerr << "raincoat: note: " << aerr << "\n";
        }
    }

    // ---- 13. Tear down the sandbox ---------------------------------------
    cleanup_root();

    // ---- 14. Propagate the child's exit code -----------------------------
    return exit_code;
}

}  // namespace raincoat
