// Raincoat — attack-round-2 honesty tests for reserved-section disclosure.
//
// These tests encode an HONESTY guarantee that the code CLAIMS but does NOT
// deliver. They are expected to FAIL against the current tree; the failing
// assertions ARE the bug report. No production code is changed in this round.
//
// Defect C (honesty, toml/profile): a RESERVED section (browser/dns/
//   network_policy/egress) is disclosed in the audit as "configured, not
//   enforced" ONLY when it is written as a `[section]` HEADER or with a STRING
//   member. TOML treats `browser.isolate = true` and `[browser]\nisolate = true`
//   as IDENTICAL, yet load_profile detects the reserved section only in the
//   header form. Root cause: TomlTable::contains() prefix-scans scalars_,
//   tables_ and array_tables_ but NOT bools_ or arrays_, so a reserved section
//   whose only members are booleans or arrays (a very natural shape:
//   `browser.isolate = true`, `network_policy.rules = [...]`) is reported as
//   ABSENT. load_profile's `if (t.contains("browser"))` guard therefore never
//   fires and the section is silently swallowed — no reserved note, no error.
//   The user is led to believe a privacy feature was accepted when in fact it
//   was dropped without a trace. Reproduced end-to-end against the binary's audit.

#include <gtest/gtest.h>
#include <unistd.h>

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <string>

#include "config.hpp"
#include "profile.hpp"
#include "toml.hpp"

namespace fs = std::filesystem;
using namespace raincoat;

namespace {

std::string write_profile(const std::string& body) {
  static int counter = 0;
  fs::path p = fs::temp_directory_path() /
               ("rc_honesty_" + std::to_string(::getpid()) + "_" +
                std::to_string(counter++) + ".toml");
  std::ofstream(p) << body;
  return p.string();
}

// True when any reserved note mentions `needle` (case-sensitive substring).
bool mentions(const std::vector<std::string>& notes, const std::string& needle) {
  return std::any_of(notes.begin(), notes.end(), [&](const std::string& n) {
    return n.find(needle) != std::string::npos;
  });
}

}  // namespace

// ---------------------------------------------------------------------------
// Baseline (documents the intended behavior; passes today): the SAME reserved
// section written as a [browser] header IS disclosed.
// ---------------------------------------------------------------------------
TEST(ReservedHonestyAttack, HeaderFormBrowserIsDisclosed) {
  std::string path = write_profile("[browser]\nisolate = true\n");
  std::string err;
  auto opt = load_profile(path, err);
  ASSERT_TRUE(opt.has_value()) << err;
  EXPECT_TRUE(mentions(opt->ext.reserved_notes, "browser"))
      << "header-form [browser] must be disclosed as a reserved section.";
}

// ---------------------------------------------------------------------------
// Defect C: dotted-key form of the SAME section is silently swallowed.
// `browser.isolate = true` is identical TOML to `[browser]\nisolate = true`,
// so it MUST produce the same reserved disclosure. It currently produces none.
// ---------------------------------------------------------------------------
TEST(ReservedHonestyAttack, DottedBoolFormBrowserMustAlsoBeDisclosed) {
  std::string path = write_profile("browser.isolate = true\n");
  std::string err;
  auto opt = load_profile(path, err);
  ASSERT_TRUE(opt.has_value()) << err;
  EXPECT_TRUE(mentions(opt->ext.reserved_notes, "browser"))
      << "a reserved section configured via a dotted boolean key "
         "(`browser.isolate = true`) is silently swallowed with no reserved "
         "note — the audit dishonestly implies nothing was configured.";
}

// Same defect via an array-valued member of a reserved section.
TEST(ReservedHonestyAttack, DottedArrayFormNetworkPolicyMustAlsoBeDisclosed) {
  std::string path = write_profile("network_policy.deny = [\"evil.example\"]\n");
  std::string err;
  auto opt = load_profile(path, err);
  ASSERT_TRUE(opt.has_value()) << err;
  EXPECT_TRUE(mentions(opt->ext.reserved_notes, "network_policy"))
      << "a reserved section configured via a dotted array key is silently "
         "swallowed with no reserved note.";
}

// ---------------------------------------------------------------------------
// Root cause pinned at the primitive: TomlTable::contains() must recognise a
// section whose only members are booleans/arrays. It scans scalars_/tables_/
// array_tables_ by prefix but omits bools_ and arrays_.
// ---------------------------------------------------------------------------
TEST(ReservedHonestyAttack, ContainsMustSeeSectionWithOnlyBooleanChild) {
  std::string err;
  auto t = parse_toml("browser.isolate = true\n", err);
  ASSERT_TRUE(t.has_value()) << err;
  EXPECT_TRUE(t->contains("browser"))
      << "contains(\"browser\") must be true when the only child is a boolean "
         "(`browser.isolate = true`); the prefix scan omits bools_.";
}

TEST(ReservedHonestyAttack, ContainsMustSeeSectionWithOnlyArrayChild) {
  std::string err;
  auto t = parse_toml("network_policy.deny = [\"x\"]\n", err);
  ASSERT_TRUE(t.has_value()) << err;
  EXPECT_TRUE(t->contains("network_policy"))
      << "contains(\"network_policy\") must be true when the only child is an "
         "array; the prefix scan omits arrays_.";
}
