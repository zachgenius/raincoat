// Raincoat — main: parse argv and dispatch to the selected subcommand.
#include <climits>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include <unistd.h>

#include "cli.hpp"
#include "config.hpp"
#include "doctor.hpp"
#include "init.hpp"
#include "profile.hpp"
#include "report.hpp"
#include "runner.hpp"
#include "util.hpp"

using namespace raincoat;

namespace {

const char* kUsage =
    "raincoat — a lightweight privacy sandbox for nosy CLI tools and AI agents.\n"
    "\n"
    "Usage:\n"
    "  raincoat -- <command> [args...]\n"
    "  raincoat run [options] -- <command> [args...]\n"
    "  raincoat doctor\n"
    "  raincoat init\n"
    "  raincoat report\n"
    "  raincoat --help | --version\n";

const char* kVersion = "raincoat 0.1.0\n";

// Absolute working directory of the raincoat process.
std::string current_working_dir() {
    char buf[PATH_MAX];
    if (::getcwd(buf, sizeof(buf)) != nullptr) return std::string(buf);
    return ".";
}

// Resolve the assets directory (fontconfig template, etc.) to an absolute path.
// Try the install-relative location first (dir(argv0)/../assets), then the
// well-known dev tree, then a bare "assets" — font_guard falls back to a minimal
// embedded fonts.conf if none of these exist.
std::string resolve_assets_dir(const char* argv0, const std::string& cwd) {
    std::string a0 = argv0 ? argv0 : "";
    if (a0.find('/') != std::string::npos) {
        std::string abs = absolutize(a0, cwd);
        auto slash = abs.find_last_of('/');
        std::string dir = (slash == std::string::npos) ? abs : abs.substr(0, slash);
        std::string cand = absolutize(dir + "/../assets", cwd);
        if (is_dir(cand)) return cand;
    }
    if (is_dir("/home/zach/Develop/Raincoat/assets"))
        return "/home/zach/Develop/Raincoat/assets";
    return "assets";
}

}  // namespace

int main(int argc, char** argv, char** envp) {
    std::vector<std::string> args;
    for (int i = 1; i < argc; ++i) args.emplace_back(argv[i]);

    CliInvocation inv = parse_cli(args);
    if (inv.has_error()) {
        std::cerr << inv.error << "\n";
        return 2;
    }

    switch (inv.sub) {
        case Subcommand::Help:
            std::cout << kUsage;
            return 0;
        case Subcommand::Version:
            std::cout << kVersion;
            return 0;
        case Subcommand::Doctor: {
            DoctorReport rep = run_doctor();
            std::cout << format_doctor(rep);
            return rep.usable() ? 0 : 1;
        }
        case Subcommand::Init: {
            std::string err;
            if (!write_init(".raincoat.toml", inv.options.init_force, err)) {
                std::cerr << err << "\n";
                return 1;
            }
            // Honor a profile's [init].create_dirs: `raincoat init --profile <path>`
            // also creates those directories (relative to the cwd) alongside the
            // generated .raincoat.toml.
            if (inv.options.profile_path.has_value()) {
                std::string perr;
                std::optional<Options> prof = load_profile(*inv.options.profile_path, perr);
                if (!prof.has_value()) {
                    std::cerr << perr << "\n";
                    return 1;
                }
                std::string derr;
                if (!create_init_dirs(prof->ext.init_create_dirs, current_working_dir(),
                                      derr)) {
                    std::cerr << derr << "\n";
                    return 1;
                }
            }
            return 0;
        }
        case Subcommand::Report: {
            std::string cwd = current_working_dir();

            // A profile (if given) can supply the default audit path via
            // [report].latest_log and the output style via [report].playful_summary.
            bool playful = true;
            std::optional<std::string> profile_log;
            if (inv.options.profile_path.has_value()) {
                std::string perr;
                std::optional<Options> prof = load_profile(*inv.options.profile_path, perr);
                if (!prof.has_value()) {
                    std::cerr << perr << "\n";
                    return 1;
                }
                playful = prof->ext.playful_report.value_or(true);
                profile_log = prof->ext.report_log;
            }

            // Resolution order for the audit path: an explicit positional path wins,
            // else the profile's [report].latest_log, else the default under the cwd.
            std::string path;
            if (!inv.options.command.empty() && !inv.options.command.front().empty()) {
                path = inv.options.command.front();
            } else if (profile_log.has_value() && !profile_log->empty()) {
                path = absolutize(*profile_log, cwd);
            } else {
                path = cwd + "/.raincoat/audit.log";
            }
            std::ifstream ifs(path, std::ios::binary);
            if (!ifs) {
                std::cerr << "no audit log found at " << path << "\n";
                return 1;
            }
            std::ostringstream buf;
            buf << ifs.rdbuf();
            std::cout << summarize_audit(buf.str(), playful);
            return 0;
        }
        case Subcommand::Run: {
            std::map<std::string, std::string> parent = environ_to_map(envp);
            std::string cwd = current_working_dir();
            std::string assets_dir = resolve_assets_dir(argv[0], cwd);
            std::string err;
            Config cfg = resolve_config(inv, parent, cwd, err);
            if (!err.empty()) {
                std::cerr << err << "\n";
                return 1;
            }
            int rc = run(cfg, parent, cwd, assets_dir, err);
            if (!err.empty()) {
                std::cerr << err << "\n";
                return 1;
            }
            return rc;
        }
    }
    return 0;
}
