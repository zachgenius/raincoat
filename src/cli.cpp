// Raincoat — cli: command-line parsing.
#include "cli.hpp"

namespace raincoat {

namespace {

const char* kNoCommandErr =
    "Error: no command provided.\n\nUsage:\n  raincoat -- <command> [args...]";
const char* kSetEnvErr = "Error: expected --set-env KEY=VALUE";

}  // namespace

CliInvocation parse_cli(const std::vector<std::string>& args) {
    CliInvocation inv;
    inv.sub = Subcommand::Run;

    size_t i = 0;

    // Leading subcommand keyword selection.
    if (!args.empty()) {
        const std::string& first = args[0];
        if (first == "doctor") {
            inv.sub = Subcommand::Doctor;
            return inv;
        }
        if (first == "init") {
            inv.sub = Subcommand::Init;
            // `raincoat init [--force|-f] [--profile <path>]`: --force overwrites an
            // existing .raincoat.toml; --profile names a profile whose [init].create_dirs
            // are also created. Anything else is ignored (init takes no other options).
            for (size_t j = 1; j < args.size(); ++j) {
                if (args[j] == "--force" || args[j] == "-f") {
                    inv.options.init_force = true;
                } else if (args[j] == "--profile" && j + 1 < args.size()) {
                    inv.options.profile_path = args[++j];
                }
            }
            return inv;
        }
        if (first == "report") {
            inv.sub = Subcommand::Report;
            // `raincoat report [path] [--profile <path>]`: an optional positional audit
            // path and an optional profile (its [report].latest_log / playful_summary
            // shape the default path and output style).
            for (size_t j = 1; j < args.size(); ++j) {
                if (args[j] == "--profile" && j + 1 < args.size()) {
                    inv.options.profile_path = args[++j];
                } else if (!args[j].empty() && args[j][0] != '-') {
                    inv.options.command.push_back(args[j]);  // positional audit path
                }
            }
            return inv;
        }
        if (first == "run") {
            inv.sub = Subcommand::Run;
            i = 1;  // consume the keyword
        }
    }

    Options& opt = inv.options;
    bool saw_dashdash = false;

    for (; i < args.size(); ++i) {
        const std::string& a = args[i];

        if (a == "--") {
            saw_dashdash = true;
            ++i;
            for (; i < args.size(); ++i) opt.command.push_back(args[i]);
            break;
        }

        // Help / version only before `--`.
        if (a == "--help" || a == "-h") {
            inv.sub = Subcommand::Help;
            return inv;
        }
        if (a == "--version" || a == "-V") {
            inv.sub = Subcommand::Version;
            return inv;
        }

        if (a == "--strict") {
            opt.strict = true;
            opt.strict_set = true;
            continue;
        }
        if (a == "--keep-temp") {
            opt.keep_temp = true;
            opt.keep_temp_set = true;
            continue;
        }
        if (a == "--net") {
            if (i + 1 >= args.size() || args[i + 1] == "--") {
                inv.error = "Error: --net requires a value (full|off)";
                return inv;
            }
            const std::string& v = args[++i];
            if (v == "full") {
                opt.net = NetMode::Full;
            } else if (v == "off") {
                opt.net = NetMode::Off;
            } else {
                inv.error =
                    "Error: invalid --net value '" + v + "' (expected full|off)";
                return inv;
            }
            continue;
        }
        if (a == "--allow-read") {
            if (i + 1 < args.size() && args[i + 1] != "--")
                opt.allow_read.push_back(args[++i]);
            continue;
        }
        if (a == "--allow-write") {
            if (i + 1 < args.size() && args[i + 1] != "--")
                opt.allow_write.push_back(args[++i]);
            continue;
        }
        if (a == "--allow-env") {
            if (i + 1 < args.size() && args[i + 1] != "--")
                opt.allow_env.push_back(args[++i]);
            continue;
        }
        if (a == "--set-env") {
            if (i + 1 >= args.size() || args[i + 1] == "--") {
                inv.error = kSetEnvErr;
                return inv;
            }
            const std::string& kv = args[++i];
            auto eq = kv.find('=');
            if (eq == std::string::npos || eq == 0) {
                inv.error = kSetEnvErr;
                return inv;
            }
            opt.set_env.emplace_back(kv.substr(0, eq), kv.substr(eq + 1));
            continue;
        }
        if (a == "--profile") {
            if (i + 1 < args.size() && args[i + 1] != "--") opt.profile_path = args[++i];
            continue;
        }
        if (a == "--workdir") {
            if (i + 1 < args.size() && args[i + 1] != "--") opt.workdir = args[++i];
            continue;
        }
        if (a == "--audit-log") {
            if (i + 1 < args.size() && args[i + 1] != "--") opt.audit_log = args[++i];
            continue;
        }

        // Unknown token before `--`: ignore (kept lenient for the MVP parser).
    }

    (void)saw_dashdash;

    if (inv.sub == Subcommand::Run && opt.command.empty()) {
        inv.error = kNoCommandErr;
        return inv;
    }

    return inv;
}

}  // namespace raincoat
