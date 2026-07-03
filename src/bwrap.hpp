// Raincoat — bwrap: pure argv assembly, no side effects.
#pragma once

#include <string>
#include <vector>

#include "config.hpp"

namespace raincoat {

std::vector<std::string> build_bwrap_argv(const std::string& bwrap_path, const Config& cfg,
                                          const std::vector<Mount>& mounts,
                                          const EnvResolution& env, const std::string& fake_home,
                                          const std::string& sandbox_tmp, bool bind_resolv_conf,
                                          const std::string& font_dir = "",
                                          const std::string& audit_mask_dir = "",
                                          const std::string& sandbox_out = "",
                                          const std::string& mask_empty_file = "",
                                          const std::vector<std::string>& mask_files = {});

// PURE. Render the bwrap argv as a display-safe string for the audit log. Every
// `--setenv <NAME> <VALUE>` value is redacted to `<redacted>` (the NAME is shown)
// so secret env VALUES are never written to disk. Redaction is STRUCTURAL: only the
// options region `argv[0 .. size-num_command_tokens)` is scanned, and on `--setenv`
// exactly the next two tokens (NAME, VALUE) are consumed. The trailing
// `num_command_tokens` command tokens are appended VERBATIM (they are the user's
// chosen command, not secrets). Tokens that are empty or contain spaces are
// single-quoted for readability. Over-redaction is safe; under-redaction is not.
std::string redact_argv_for_audit(const std::vector<std::string>& argv,
                                  std::size_t num_command_tokens);

}  // namespace raincoat
