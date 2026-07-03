// Raincoat — report: audit log summarization (pure).
#pragma once

#include <string>

namespace raincoat {

// Summarize an audit-log block into a short human summary. When `playful` is true
// (the default) it produces the playful-but-professional narrative; when false it
// produces a plain, factual bullet summary (honoring [report].playful_summary =
// false from the profile). Both surface the same facts (HOME hidden, scrubbed count,
// network mode, strict/normal, and any deliberately-mounted sensitive path).
std::string summarize_audit(const std::string& audit_text, bool playful = true);

}  // namespace raincoat
