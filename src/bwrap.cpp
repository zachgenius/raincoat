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
                                          bool bind_resolv_conf) {
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

    // argv[0]
    p1(bwrap_path);

    // Lifecycle + namespace isolation.
    p1("--die-with-parent");
    p1("--unshare-pid");
    p1("--unshare-uts");
    p1("--unshare-ipc");
    if (cfg.net == NetMode::Off) p1("--unshare-net");

    // Base system view.
    p3("--ro-bind", "/usr", "/usr");
    p3("--symlink", "usr/bin", "/bin");
    p3("--symlink", "usr/lib", "/lib");
    p3("--symlink", "usr/lib64", "/lib64");
    p3("--symlink", "usr/sbin", "/sbin");
    p2("--proc", "/proc");
    p2("--dev", "/dev");

    // TLS trust store; DNS resolver (only when requested).
    p3("--ro-bind-try", "/etc/ssl", "/etc/ssl");
    if (bind_resolv_conf) p3("--ro-bind-try", "/etc/resolv.conf", "/etc/resolv.conf");

    // Sandbox-writable dirs.
    p3("--bind", fake_home, fake_home);
    p3("--bind", sandbox_tmp, sandbox_tmp);

    // User-requested mounts, in order.
    for (const auto& m : mounts) {
        const char* flag = (m.mode == MountMode::ReadWrite) ? "--bind" : "--ro-bind";
        p3(flag, m.host_path, m.sandbox_path);
    }

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
