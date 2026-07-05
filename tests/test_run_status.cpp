// Raincoat tests — run_status: the pure JSON serializer that is the C<->Swift contract for the
// macOS menu-bar app (see docs/GUI-MACOS.md). Serialization is pure + portable, so it is
// unit-tested on both platforms.
#include <gtest/gtest.h>

#include <string>

#include "run_status.hpp"

using namespace raincoat;

static RunStatus sample() {
    RunStatus s;
    s.supervisor_pid = 12345;
    s.child_pid = 12346;
    s.command = "node build.js";
    s.audit_log = "/Users/me/proj/.raincoat/audit.log";
    s.backend = "Seatbelt (sandbox-exec, best-effort)";
    s.net_mode = "proxied";
    s.started_at = 1720190940;
    s.capabilities = {{"filesystem", "confined"}, {"network", "proxied"}, {"identity", "faked"}};
    s.notes = {"note one", "note two"};
    return s;
}

TEST(RunStatus, JsonHasSchemaAndCoreFields) {
    std::string j = run_status_to_json(sample());
    EXPECT_NE(j.find("\"schema\":1"), std::string::npos) << j;
    EXPECT_NE(j.find("\"supervisor_pid\":12345"), std::string::npos) << j;
    EXPECT_NE(j.find("\"child_pid\":12346"), std::string::npos) << j;
    EXPECT_NE(j.find("\"command\":\"node build.js\""), std::string::npos) << j;
    EXPECT_NE(j.find("\"net_mode\":\"proxied\""), std::string::npos) << j;
    EXPECT_NE(j.find("\"started_at\":1720190940"), std::string::npos) << j;
    EXPECT_NE(j.find("\"identity\":\"faked\""), std::string::npos) << j;
    EXPECT_NE(j.find("\"note two\""), std::string::npos) << j;
    // Well-formed object bounds.
    EXPECT_EQ(j.front(), '{');
    EXPECT_EQ(j.back(), '}');
}

TEST(RunStatus, JsonEscapesQuotesAndBackslashesAndControls) {
    RunStatus s = sample();
    s.command = "a\"b\\c\td";  // quote, backslash, tab
    s.audit_log = "/p/li\nne";  // newline
    std::string j = run_status_to_json(s);
    EXPECT_NE(j.find("a\\\"b\\\\c\\td"), std::string::npos) << j;
    EXPECT_NE(j.find("li\\nne"), std::string::npos) << j;
    // No raw control byte survives into the JSON.
    EXPECT_EQ(j.find('\n'), std::string::npos);
    EXPECT_EQ(j.find('\t'), std::string::npos);
}

TEST(RunStatus, EmptyCapabilitiesAndNotesStillValid) {
    RunStatus s = sample();
    s.capabilities.clear();
    s.notes.clear();
    std::string j = run_status_to_json(s);
    EXPECT_NE(j.find("\"capabilities\":{}"), std::string::npos) << j;
    EXPECT_NE(j.find("\"notes\":[]"), std::string::npos) << j;
}

TEST(RunStatus, DirIsNonEmptyAndAbsolute) {
    // On macOS this needs $HOME (always set in the test env); on Linux it falls back to TMPDIR.
    std::string d = run_status_dir();
    ASSERT_FALSE(d.empty());
    EXPECT_EQ(d.front(), '/');
    // "Raincoat" (macOS) or "raincoat" (Linux) — match the case-insensitive common substring.
    EXPECT_NE(d.find("aincoat"), std::string::npos) << d;
}
