// Raincoat — main: parse argv and dispatch to the selected subcommand.
//
// This is a minimal real dispatch that calls into the (currently stubbed) modules.
#include <iostream>
#include <string>
#include <vector>

#include "cli.hpp"
#include "config.hpp"
#include "doctor.hpp"
#include "init.hpp"
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
            return 0;
        }
        case Subcommand::Report: {
            std::cout << summarize_audit("");
            return 0;
        }
        case Subcommand::Run: {
            std::map<std::string, std::string> parent = environ_to_map(envp);
            std::string cwd;  // resolved inside runner in the real implementation
            std::string err;
            Config cfg = resolve_config(inv, parent, cwd, err);
            if (!err.empty()) {
                std::cerr << err << "\n";
                return 1;
            }
            int rc = run(cfg, parent, cwd, "assets", err);
            if (!err.empty()) {
                std::cerr << err << "\n";
                return 1;
            }
            return rc;
        }
    }
    return 0;
}
