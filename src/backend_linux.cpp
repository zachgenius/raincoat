// Raincoat — backend_linux: the bubblewrap backend behind the platform seam.
//
// Compiled ONLY on Linux (see CMakeLists; macOS links backend_macos.cpp instead). This is
// a VERBATIM extraction of the runner's old bwrap-locate (runner.cpp §7), argv-assembly
// (§8) and pasta netns-jail wrap (§8b): it delegates to the unchanged pure
// bwrap::build_bwrap_argv and reproduces the wrap token-for-token, so the Linux launch is
// byte-for-byte identical to the pre-seam behavior. Do NOT "improve" anything here.
#include "backend.hpp"

#include <cstddef>
#include <string>
#include <utility>
#include <vector>

#include <unistd.h>

#include "bwrap.hpp"
#include "doctor.hpp"  // find_bwrap

namespace raincoat {

namespace {
// Verbatim SPEC message for a missing bubblewrap backend (docs/SPEC.md). Moved here from
// the runner so the backend owns "how do I find my executable / what if it is absent".
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
}  // namespace

Capabilities backend_capabilities() {
    return Capabilities{};  // all defaults == today's Linux (bubblewrap) behavior
}

std::optional<std::string> backend_locate(const Config& cfg, std::string& err) {
    // An explicit [backend].bwrap_path overrides auto-find, but only when it names an
    // actual executable — otherwise fall back to the PATH search so a stale profile path
    // does not hard-fail a runnable host.
    if (!cfg.ext.backend.bwrap_path.empty()) {
        const std::string& bp = cfg.ext.backend.bwrap_path;
        if (bp.find('/') != std::string::npos && ::access(bp.c_str(), X_OK) == 0) {
            return bp;
        }
    }
    if (auto p = find_bwrap()) return p;
    err = kBwrapMissing;
    return std::nullopt;
}

std::optional<LaunchPlan> backend_build_launch(const LaunchInputs& in, std::string& err) {
    (void)err;  // the Linux assembler never fails; the contract allows it to for other backends
    LaunchPlan plan;

    std::vector<std::string> argv = build_bwrap_argv(
        in.backend_path, *in.cfg, in.mounts, in.env, in.fake_home, in.sandbox_tmp,
        in.bind_resolv_conf, in.font_dir, in.audit_mask_dir, in.sandbox_out,
        in.mask_empty_file, in.mask_files, in.curated_font_dirs, in.mask_usr_local_fonts,
        in.proc_overlays, in.command_exec_path);
    plan.launch_path = in.backend_path;

    // Isolated-netns wrapping (pasta): prepend `pasta --config-net -t none -T <ports>
    // [-o 127.0.0.1] --` so the child JOINS pasta's namespace (bwrap does not --unshare-net
    // on this path). Verbatim from the old runner.cpp:1110-1140.
    if (in.jail_active) {
        std::vector<std::string> wrapped;
        wrapped.reserve(argv.size() + 8);
        wrapped.push_back(*in.pasta_path);
        wrapped.push_back("--config-net");
        wrapped.push_back("-t");
        wrapped.push_back("none");
        if (!in.jail_forward_ports.empty()) {
            std::string spec;
            for (std::size_t i = 0; i < in.jail_forward_ports.size(); ++i) {
                if (i) spec += ",";
                spec += std::to_string(in.jail_forward_ports[i]);
            }
            wrapped.push_back("-T");
            wrapped.push_back(spec);
        }
        if (in.strict_jail) {
            wrapped.push_back("-o");
            wrapped.push_back("127.0.0.1");
        }
        wrapped.push_back("--");
        for (auto& tok : argv) wrapped.push_back(std::move(tok));
        argv = std::move(wrapped);
        plan.launch_path = *in.pasta_path;
    }

    // Env is baked into argv by build_bwrap_argv (--clearenv/--setenv); the runner exec's
    // carrying the parent environ, which bwrap discards. Redaction is computed from the
    // FINAL (post-wrap) argv with the user command-token count, exactly as before.
    plan.env_apply = EnvApply::ViaArgv;
    plan.audit_command = redact_argv_for_audit(argv, in.cfg->command.size());
    plan.argv = std::move(argv);
    return plan;
}

}  // namespace raincoat
