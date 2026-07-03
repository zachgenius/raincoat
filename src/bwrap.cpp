// Raincoat — bwrap: pure argv assembly, no side effects.
#include "bwrap.hpp"

#include <cstddef>
#include <sstream>

namespace raincoat {

namespace {

// Wrap a token in single quotes iff it is empty or contains a space, so the
// flattened audit rendering stays legible (an empty value or a value with spaces
// would otherwise be indistinguishable from a token boundary). This is a display
// decoration only — it never alters the token's meaning.
std::string quote_for_display(const std::string& tok) {
    if (tok.empty() || tok.find(' ') != std::string::npos) {
        return "'" + tok + "'";
    }
    return tok;
}

}  // namespace

std::vector<std::string> build_bwrap_argv(const std::string& bwrap_path, const Config& cfg,
                                          const std::vector<Mount>& mounts,
                                          const EnvResolution& env,
                                          const std::string& fake_home,
                                          const std::string& sandbox_tmp,
                                          bool bind_resolv_conf,
                                          const std::string& font_dir,
                                          const std::string& audit_mask_dir,
                                          const std::string& sandbox_out) {
    std::vector<std::string> a;
    auto p1 = [&](const std::string& x) { a.push_back(x); };
    auto p2 = [&](const std::string& x, const std::string& y) {
        a.push_back(x);
        a.push_back(y);
    };
    auto p3 = [&](const std::string& x, const std::string& y, const std::string& z) {
        a.push_back(x);
        a.push_back(y);
        a.push_back(z);
    };

    // Backend knobs from the profile's [backend] section. Every field defaults to
    // the hard-coded MVP behavior (see BackendConfig in config.hpp), so an absent
    // profile emits exactly the same argv as before.
    const BackendConfig& backend = cfg.ext.backend;

    // argv[0]
    p1(bwrap_path);

    // Lifecycle + namespace isolation (each gated on its backend toggle; defaults
    // reproduce the original unconditional flags).
    if (backend.die_with_parent) p1("--die-with-parent");
    // --unshare-user / --unshare-cgroup are OFF by default (they can break tools /
    // are unnecessary for the privacy model) and only emitted when the profile asks.
    if (backend.unshare_user) p1("--unshare-user");
    if (backend.unshare_pid) p1("--unshare-pid");
    if (backend.unshare_uts) {
        p1("--unshare-uts");
        // Give the sandbox a generic hostname so the real host name (a trivially-read
        // machine fingerprint) never leaks in through the fresh UTS namespace. This
        // requires --unshare-uts to take effect, so it is gated on it. The value comes
        // from the profile (ext.hostname), defaulting to "sandbox".
        p2("--hostname", cfg.ext.hostname.value_or("sandbox"));
    }
    if (backend.unshare_ipc) p1("--unshare-ipc");
    if (backend.unshare_cgroup) p1("--unshare-cgroup");
    // Honor NetMode::Off with a fresh (empty) network namespace, unless the profile
    // disabled that coupling via unshare_net_when_off.
    if (cfg.net == NetMode::Off && backend.unshare_net_when_off) p1("--unshare-net");

    // Base system view.
    p3("--ro-bind", "/usr", "/usr");
    p3("--symlink", "usr/bin", "/bin");
    p3("--symlink", "usr/lib", "/lib");
    p3("--symlink", "usr/lib64", "/lib64");
    p3("--symlink", "usr/sbin", "/sbin");
    if (backend.mount_proc) p2("--proc", "/proc");
    if (backend.mount_dev) p2("--dev", "/dev");

    // TLS trust store; DNS resolver (only when requested).
    p3("--ro-bind-try", "/etc/ssl", "/etc/ssl");
    if (bind_resolv_conf) p3("--ro-bind-try", "/etc/resolv.conf", "/etc/resolv.conf");

    // Sandbox-writable dirs. The fake home is always bound; the writable temp scratch
    // (the sandbox's /tmp) is gated on backend.mount_tmpfs_tmp (default true).
    p3("--bind", fake_home, fake_home);
    if (backend.mount_tmpfs_tmp) p3("--bind", sandbox_tmp, sandbox_tmp);
    // Dedicated writable scratch area (SPEC `<temp>/out`). Bound identity so the
    // child has a private, disposable place to write output that lives on the host
    // temp tree and is torn down with the sandbox.
    if (!sandbox_out.empty()) p3("--bind", sandbox_out, sandbox_out);

    // Curated fontconfig dir (read-only). It lives outside fake_home/sandbox_tmp,
    // so without an explicit bind the FONTCONFIG_FILE/PATH we hand the child would
    // point at a path that does not exist inside the namespace.
    if (!font_dir.empty()) p3("--ro-bind", font_dir, font_dir);

    // User-requested mounts, in order.
    for (const auto& m : mounts) {
        const char* flag = (m.mode == MountMode::ReadWrite) ? "--bind" : "--ro-bind";
        p3(flag, m.host_path, m.sandbox_path);
    }

    // Shadow the audit-log directory with a fresh tmpfs so the untrusted child
    // cannot read, forge, or erase the host audit log that raincoat writes. This
    // MUST come after the user mounts (its parent mount must already exist) — the
    // tmpfs then hides the real audit dir that would otherwise sit in the writable
    // cwd mount. The genuine log lives on the host and is written by the raincoat
    // parent process, which is outside this namespace.
    if (!audit_mask_dir.empty()) p2("--tmpfs", audit_mask_dir);

    // Environment: clear then set each resolved entry (std::map => sorted order).
    p1("--clearenv");
    for (const auto& kv : env.resolved) p3("--setenv", kv.first, kv.second);

    // Working directory, then the target command tokens last.
    p2("--chdir", cfg.workdir);
    for (const auto& tok : cfg.command) p1(tok);

    return a;
}

std::string redact_argv_for_audit(const std::vector<std::string>& argv,
                                  std::size_t num_command_tokens) {
    std::ostringstream out;
    bool first = true;
    auto emit = [&](const std::string& s) {
        if (!first) out << ' ';
        out << s;
        first = false;
    };

    const std::size_t n = argv.size();
    // The command tokens are the last num_command_tokens elements; everything
    // before them is the bwrap-options region we scan for --setenv. Clamp so a
    // caller passing a larger count than argv can never underflow.
    const std::size_t options_end = (num_command_tokens <= n) ? n - num_command_tokens : 0;

    std::size_t i = 0;
    while (i < options_end) {
        if (argv[i] == "--setenv") {
            emit(quote_for_display(argv[i]));  // flag
            // NAME is safe to display; VALUE is redacted. Consume exactly the
            // next two tokens regardless of their content.
            if (i + 1 < options_end) emit(quote_for_display(argv[i + 1]));
            emit("<redacted>");
            i += 3;  // flag + NAME + VALUE
            continue;
        }
        emit(quote_for_display(argv[i]));
        ++i;
    }

    // Target command tokens: appended VERBATIM (only display-quoted, never
    // redacted) — a literal "--setenv" here is the user's command, not a secret.
    for (; i < n; ++i) emit(quote_for_display(argv[i]));

    return out.str();
}

}  // namespace raincoat
