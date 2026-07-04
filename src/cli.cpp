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

    Options& opt = inv.options;

    // Grammar: global options may precede a bare subcommand keyword
    // (run|doctor|init|report). The FIRST such keyword appearing BEFORE the `--`
    // separator selects the subcommand; the options around it still apply. Once `--`
    // is seen, everything after it is the verbatim target command (so `-- init` RUNS
    // `init` as a command, it does NOT select the init subcommand). Only the first
    // keyword counts; later keyword-looking tokens are treated as positionals/unknown.
    bool sub_explicit = false;
    std::vector<std::string> positionals;  // non-option tokens before `--` (report path)

    auto subcommand_of = [](const std::string& a) -> std::optional<Subcommand> {
        if (a == "run") return Subcommand::Run;
        if (a == "doctor") return Subcommand::Doctor;
        if (a == "init") return Subcommand::Init;
        if (a == "report") return Subcommand::Report;
        return std::nullopt;
    };

    for (size_t i = 0; i < args.size(); ++i) {
        const std::string& a = args[i];

        if (a == "--") {
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

        // A bare subcommand keyword in option position selects the subcommand.
        if (!sub_explicit) {
            if (auto s = subcommand_of(a); s.has_value()) {
                inv.sub = *s;
                sub_explicit = true;
                continue;
            }
        }

        // Support the `--flag=value` equals form for long options. Split the token
        // into its NAME (`--flag`) and an inline VALUE once, on the FIRST '=', so a
        // value that itself contains '=' (e.g. --set-env=FOO=a=b) is preserved. Short
        // flags (`-f`) and the already-handled `--` terminator never carry an inline
        // value. Previously the equals form was silently dropped by the catch-all and
        // the flag fell back to its default — e.g. `--audit-format=json` produced a
        // text log — so this closes a silent fail-open on value-taking security flags.
        std::string name = a;
        std::optional<std::string> inline_val;
        if (a.rfind("--", 0) == 0 && a.size() > 2) {
            const auto eq = a.find('=');
            if (eq != std::string::npos) {
                name = a.substr(0, eq);
                inline_val = a.substr(eq + 1);
            }
        }
        // True when a value is available for a value-taking flag: an inline `=value`,
        // or a following token that is not the `--` command terminator.
        auto has_value = [&]() -> bool {
            return inline_val.has_value() ||
                   (i + 1 < args.size() && args[i + 1] != "--");
        };
        // Consume and return the flag's value (inline if present, else the next token).
        // Only call after has_value() returned true.
        auto take_value = [&]() -> std::string {
            return inline_val ? *inline_val : args[++i];
        };
        // A boolean flag must not be given an inline value (`--strict=x` is a typo).
        auto reject_inline = [&](const char* flag) -> bool {
            if (inline_val) {
                inv.error =
                    std::string("Error: option '") + flag + "' does not take a value";
                return true;
            }
            return false;
        };

        if (name == "--strict") {
            if (reject_inline("--strict")) return inv;
            opt.strict = true;
            opt.strict_set = true;
            continue;
        }
        if (name == "--keep-temp") {
            if (reject_inline("--keep-temp")) return inv;
            opt.keep_temp = true;
            opt.keep_temp_set = true;
            continue;
        }
        // `--force` / `-f` is only meaningful for `init`, but accepting it anywhere
        // before `--` keeps the parser uniform; other subcommands ignore init_force.
        if (name == "--force" || a == "-f") {
            if (name == "--force" && reject_inline("--force")) return inv;
            opt.init_force = true;
            continue;
        }
        if (name == "--audit-format") {
            if (!has_value()) {
                inv.error = "Error: --audit-format requires a value (text|json)";
                return inv;
            }
            const std::string v = take_value();
            if (auto f = audit_format_from_string(v); f.has_value()) {
                opt.audit_format = *f;
            } else {
                inv.error = "Error: invalid --audit-format value '" + v +
                            "' (expected text|json)";
                return inv;
            }
            continue;
        }
        if (name == "--net") {
            if (!has_value()) {
                inv.error = "Error: --net requires a value (full|off)";
                return inv;
            }
            const std::string v = take_value();
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
        if (name == "--allow-read") {
            if (has_value()) opt.allow_read.push_back(take_value());
            continue;
        }
        if (name == "--allow-write") {
            if (has_value()) opt.allow_write.push_back(take_value());
            continue;
        }
        if (name == "--allow-env") {
            if (has_value()) opt.allow_env.push_back(take_value());
            continue;
        }
        if (name == "--set-env") {
            if (!has_value()) {
                inv.error = kSetEnvErr;
                return inv;
            }
            const std::string kv = take_value();
            auto eq = kv.find('=');
            if (eq == std::string::npos || eq == 0) {
                inv.error = kSetEnvErr;
                return inv;
            }
            opt.set_env.emplace_back(kv.substr(0, eq), kv.substr(eq + 1));
            continue;
        }
        if (name == "--profile") {
            if (has_value()) opt.profile_path = take_value();
            continue;
        }
        if (name == "--workdir") {
            if (has_value()) opt.workdir = take_value();
            continue;
        }
        if (name == "--audit-log") {
            if (has_value()) opt.audit_log = take_value();
            continue;
        }

        // A non-option token (not starting with '-') before `--` is a positional.
        if (!a.empty() && a[0] != '-') {
            positionals.push_back(a);
            continue;
        }

        // Any other `-`-prefixed token before `--` is an unrecognized option. Reject
        // it with a hard error instead of silently ignoring it: a mistyped
        // security-relevant flag (e.g. `--stric`, `--no-fontconfig`, `--audit-fromat`)
        // must fail loudly, never be dropped and fall back to a weaker default.
        inv.error = "Error: unknown option '" + a + "'";
        return inv;
    }

    // `report` consumes a positional token as its audit-log path (command[0]); every
    // other subcommand ignores positionals (only the post-`--` command matters).
    if (inv.sub == Subcommand::Report) {
        for (const auto& p : positionals) opt.command.push_back(p);
    }

    if (inv.sub == Subcommand::Run && opt.command.empty()) {
        inv.error = kNoCommandErr;
        return inv;
    }

    return inv;
}

}  // namespace raincoat
