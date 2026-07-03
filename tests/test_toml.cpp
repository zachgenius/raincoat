// Raincoat — toml: comprehensive GoogleTest suite (TDD red).
//
// Exercises the minimal TOML parser against the config schema described in
// docs/SPEC.md / docs/DESIGN.md: comments, key=value, booleans, single/double
// quoted strings, inline + multiline arrays, [table] and dotted [a.b] headers,
// the typed dotted-key getters, and malformed-input rejection (helpful err, no
// crash). Written before the implementation exists; expected to fail (red).
#include <gtest/gtest.h>

#include <fstream>
#include <map>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

#include "toml.hpp"

using raincoat::TomlTable;
using raincoat::parse_toml;

namespace {

// Parse text that is expected to be VALID. On failure returns a default-
// constructed table (value_or) so a broken parser produces red assertions
// rather than crashing the test binary.
TomlTable MustParse(const std::string& text) {
    std::string err = "sentinel-unchanged";
    auto parsed = parse_toml(text, err);
    EXPECT_TRUE(parsed.has_value()) << "expected valid parse, got err=\"" << err << "\"";
    EXPECT_TRUE(err.empty()) << "err should be empty on success, got \"" << err << "\"";
    return parsed.value_or(TomlTable{});
}

// Parse text that is expected to be MALFORMED: parse_toml must return nullopt
// AND populate a non-empty, helpful err — without crashing.
void ExpectMalformed(const std::string& text) {
    std::string err;
    auto parsed = parse_toml(text, err);
    EXPECT_FALSE(parsed.has_value()) << "expected malformed input to be rejected";
    EXPECT_FALSE(err.empty()) << "malformed input must produce a helpful err message";
}

const char* kSpecExample =
    "strict = false\n"
    "network = \"full\"\n"
    "allow_read = [\"./src\"]\n"
    "allow_write = [\"./out\"]\n"
    "allow_env = [\"OPENAI_API_KEY\"]\n"
    "[env]\n"
    "TZ = \"UTC\"\n"
    "LANG = \"en_US.UTF-8\"\n"
    "LC_ALL = \"en_US.UTF-8\"\n"
    "[fontconfig]\n"
    "enabled = true\n"
    "[audit]\n"
    "log_file = \".raincoat/audit.log\"\n";

// ---------------------------------------------------------------------------
// Empty / whitespace / comment-only inputs are valid (empty tables).
// ---------------------------------------------------------------------------

TEST(Toml, EmptyInputIsValidEmptyTable) {
    std::string err = "sentinel";
    auto parsed = parse_toml("", err);
    ASSERT_TRUE(parsed.has_value());
    EXPECT_TRUE(err.empty());
    EXPECT_FALSE(parsed->get_bool("anything").has_value());
    EXPECT_FALSE(parsed->get_string("anything").has_value());
    EXPECT_FALSE(parsed->get_string_array("anything").has_value());
    EXPECT_TRUE(parsed->get_table_of_strings("anything").empty());
}

TEST(Toml, WhitespaceOnlyIsValid) {
    auto t = MustParse("   \n\t\n   \n");
    EXPECT_FALSE(t.get_string("x").has_value());
}

TEST(Toml, CommentOnlyIsValid) {
    auto t = MustParse("# just a comment\n#another\n");
    EXPECT_FALSE(t.get_bool("x").has_value());
}

TEST(Toml, LeadingWhitespaceBeforeComment) {
    auto t = MustParse("    # indented comment\n");
    EXPECT_FALSE(t.get_string("x").has_value());
}

// ---------------------------------------------------------------------------
// Booleans.
// ---------------------------------------------------------------------------

TEST(Toml, BoolTrue) {
    auto t = MustParse("enabled = true\n");
    auto v = t.get_bool("enabled");
    ASSERT_TRUE(v.has_value());
    EXPECT_TRUE(*v);
}

TEST(Toml, BoolFalse) {
    auto t = MustParse("strict = false\n");
    auto v = t.get_bool("strict");
    ASSERT_TRUE(v.has_value());
    EXPECT_FALSE(*v);
}

TEST(Toml, MissingBoolKeyIsNullopt) {
    auto t = MustParse("strict = false\n");
    EXPECT_FALSE(t.get_bool("nope").has_value());
}

TEST(Toml, GetBoolOnStringValueIsNullopt) {
    auto t = MustParse("network = \"full\"\n");
    EXPECT_FALSE(t.get_bool("network").has_value());
}

// ---------------------------------------------------------------------------
// Strings: double + single quoted.
// ---------------------------------------------------------------------------

TEST(Toml, DoubleQuotedString) {
    auto t = MustParse("network = \"full\"\n");
    auto v = t.get_string("network");
    ASSERT_TRUE(v.has_value());
    EXPECT_EQ(*v, "full");
}

TEST(Toml, SingleQuotedString) {
    auto t = MustParse("network = 'off'\n");
    auto v = t.get_string("network");
    ASSERT_TRUE(v.has_value());
    EXPECT_EQ(*v, "off");
}

TEST(Toml, EmptyStringValue) {
    auto t = MustParse("name = \"\"\n");
    auto v = t.get_string("name");
    ASSERT_TRUE(v.has_value());
    EXPECT_EQ(*v, "");
}

TEST(Toml, StringWithSpaces) {
    auto t = MustParse("greeting = \"hello world\"\n");
    auto v = t.get_string("greeting");
    ASSERT_TRUE(v.has_value());
    EXPECT_EQ(*v, "hello world");
}

TEST(Toml, StringWithPathAndDots) {
    auto t = MustParse("log_file = \".raincoat/audit.log\"\n");
    auto v = t.get_string("log_file");
    ASSERT_TRUE(v.has_value());
    EXPECT_EQ(*v, ".raincoat/audit.log");
}

TEST(Toml, HashInsideStringIsNotAComment) {
    auto t = MustParse("token = \"abc#123\"\n");
    auto v = t.get_string("token");
    ASSERT_TRUE(v.has_value());
    EXPECT_EQ(*v, "abc#123");
}

TEST(Toml, EqualsInsideStringIsLiteral) {
    auto t = MustParse("kv = \"a=b\"\n");
    auto v = t.get_string("kv");
    ASSERT_TRUE(v.has_value());
    EXPECT_EQ(*v, "a=b");
}

TEST(Toml, BracketsInsideStringAreLiteral) {
    auto t = MustParse("weird = \"[not an array]\"\n");
    auto v = t.get_string("weird");
    ASSERT_TRUE(v.has_value());
    EXPECT_EQ(*v, "[not an array]");
}

TEST(Toml, GetStringOnBoolValueIsNullopt) {
    auto t = MustParse("strict = true\n");
    EXPECT_FALSE(t.get_string("strict").has_value());
}

// ---------------------------------------------------------------------------
// Whitespace / comment placement around key=value.
// ---------------------------------------------------------------------------

TEST(Toml, WhitespaceAroundEquals) {
    auto t = MustParse("network    =    \"full\"\n");
    auto v = t.get_string("network");
    ASSERT_TRUE(v.has_value());
    EXPECT_EQ(*v, "full");
}

TEST(Toml, NoTrailingNewline) {
    auto t = MustParse("network = \"full\"");
    auto v = t.get_string("network");
    ASSERT_TRUE(v.has_value());
    EXPECT_EQ(*v, "full");
}

TEST(Toml, InlineCommentAfterStringValue) {
    auto t = MustParse("network = \"full\"   # trailing comment\n");
    auto v = t.get_string("network");
    ASSERT_TRUE(v.has_value());
    EXPECT_EQ(*v, "full");
}

TEST(Toml, InlineCommentAfterBoolValue) {
    auto t = MustParse("strict = false # explanation\n");
    auto v = t.get_bool("strict");
    ASSERT_TRUE(v.has_value());
    EXPECT_FALSE(*v);
}

TEST(Toml, FullLineCommentBetweenKeys) {
    auto t = MustParse("a = \"1\"\n# comment line\nb = \"2\"\n");
    EXPECT_EQ(t.get_string("a").value_or(""), "1");
    EXPECT_EQ(t.get_string("b").value_or(""), "2");
}

// ---------------------------------------------------------------------------
// Inline arrays.
// ---------------------------------------------------------------------------

TEST(Toml, InlineArraySingleElement) {
    auto t = MustParse("allow_read = [\"./src\"]\n");
    auto v = t.get_string_array("allow_read");
    ASSERT_TRUE(v.has_value());
    ASSERT_EQ(v->size(), 1u);
    EXPECT_EQ((*v)[0], "./src");
}

TEST(Toml, InlineArrayMultipleElements) {
    auto t = MustParse("allow_read = [\"./src\", \"./lib\", \"./include\"]\n");
    auto v = t.get_string_array("allow_read");
    ASSERT_TRUE(v.has_value());
    ASSERT_EQ(v->size(), 3u);
    EXPECT_EQ((*v)[0], "./src");
    EXPECT_EQ((*v)[1], "./lib");
    EXPECT_EQ((*v)[2], "./include");
}

TEST(Toml, InlineArrayNoSpaces) {
    auto t = MustParse("a = [\"x\",\"y\",\"z\"]\n");
    auto v = t.get_string_array("a");
    ASSERT_TRUE(v.has_value());
    ASSERT_EQ(v->size(), 3u);
    EXPECT_EQ((*v)[2], "z");
}

TEST(Toml, InlineArrayMixedQuoteStyles) {
    auto t = MustParse("a = [\"x\", 'y']\n");
    auto v = t.get_string_array("a");
    ASSERT_TRUE(v.has_value());
    ASSERT_EQ(v->size(), 2u);
    EXPECT_EQ((*v)[0], "x");
    EXPECT_EQ((*v)[1], "y");
}

TEST(Toml, EmptyArray) {
    auto t = MustParse("allow_read = []\n");
    auto v = t.get_string_array("allow_read");
    ASSERT_TRUE(v.has_value());
    EXPECT_TRUE(v->empty());
}

TEST(Toml, InlineArrayTrailingComma) {
    auto t = MustParse("a = [\"x\", \"y\",]\n");
    auto v = t.get_string_array("a");
    ASSERT_TRUE(v.has_value());
    ASSERT_EQ(v->size(), 2u);
    EXPECT_EQ((*v)[1], "y");
}

TEST(Toml, ArrayElementWithCommaInString) {
    auto t = MustParse("a = [\"x,y\", \"z\"]\n");
    auto v = t.get_string_array("a");
    ASSERT_TRUE(v.has_value());
    ASSERT_EQ(v->size(), 2u);
    EXPECT_EQ((*v)[0], "x,y");
    EXPECT_EQ((*v)[1], "z");
}

TEST(Toml, GetStringArrayOnScalarIsNullopt) {
    auto t = MustParse("network = \"full\"\n");
    EXPECT_FALSE(t.get_string_array("network").has_value());
}

TEST(Toml, MissingArrayKeyIsNullopt) {
    auto t = MustParse("a = [\"x\"]\n");
    EXPECT_FALSE(t.get_string_array("nope").has_value());
}

// ---------------------------------------------------------------------------
// Multiline arrays.
// ---------------------------------------------------------------------------

TEST(Toml, MultilineArray) {
    auto t = MustParse(
        "allow_read = [\n"
        "  \"./src\",\n"
        "  \"./lib\",\n"
        "  \"./include\"\n"
        "]\n");
    auto v = t.get_string_array("allow_read");
    ASSERT_TRUE(v.has_value());
    ASSERT_EQ(v->size(), 3u);
    EXPECT_EQ((*v)[0], "./src");
    EXPECT_EQ((*v)[1], "./lib");
    EXPECT_EQ((*v)[2], "./include");
}

TEST(Toml, MultilineArrayTrailingComma) {
    auto t = MustParse(
        "allow_read = [\n"
        "  \"a\",\n"
        "  \"b\",\n"
        "]\n");
    auto v = t.get_string_array("allow_read");
    ASSERT_TRUE(v.has_value());
    ASSERT_EQ(v->size(), 2u);
    EXPECT_EQ((*v)[1], "b");
}

TEST(Toml, MultilineArrayWithComments) {
    auto t = MustParse(
        "allow_read = [\n"
        "  \"a\", # first\n"
        "  \"b\"  # second\n"
        "]\n");
    auto v = t.get_string_array("allow_read");
    ASSERT_TRUE(v.has_value());
    ASSERT_EQ(v->size(), 2u);
    EXPECT_EQ((*v)[0], "a");
    EXPECT_EQ((*v)[1], "b");
}

TEST(Toml, KeyAfterMultilineArrayStillParses) {
    auto t = MustParse(
        "allow_read = [\n"
        "  \"a\"\n"
        "]\n"
        "network = \"off\"\n");
    ASSERT_TRUE(t.get_string_array("allow_read").has_value());
    EXPECT_EQ(t.get_string("network").value_or(""), "off");
}

// ---------------------------------------------------------------------------
// Tables: [table] and dotted [a.b] headers -> dotted-key lookups.
// ---------------------------------------------------------------------------

TEST(Toml, SimpleTableDottedKeyLookup) {
    auto t = MustParse(
        "[env]\n"
        "TZ = \"UTC\"\n"
        "LANG = \"en_US.UTF-8\"\n");
    EXPECT_EQ(t.get_string("env.TZ").value_or(""), "UTC");
    EXPECT_EQ(t.get_string("env.LANG").value_or(""), "en_US.UTF-8");
}

TEST(Toml, TableBoolDottedKey) {
    auto t = MustParse(
        "[fontconfig]\n"
        "enabled = true\n");
    auto v = t.get_bool("fontconfig.enabled");
    ASSERT_TRUE(v.has_value());
    EXPECT_TRUE(*v);
}

TEST(Toml, DottedTableHeader) {
    auto t = MustParse(
        "[a.b]\n"
        "key = \"value\"\n");
    EXPECT_EQ(t.get_string("a.b.key").value_or(""), "value");
}

TEST(Toml, MultipleTables) {
    auto t = MustParse(
        "[env]\n"
        "TZ = \"UTC\"\n"
        "[audit]\n"
        "log_file = \".raincoat/audit.log\"\n");
    EXPECT_EQ(t.get_string("env.TZ").value_or(""), "UTC");
    EXPECT_EQ(t.get_string("audit.log_file").value_or(""), ".raincoat/audit.log");
}

TEST(Toml, TopLevelKeysBeforeTableAreNotNamespaced) {
    auto t = MustParse(
        "strict = false\n"
        "[env]\n"
        "TZ = \"UTC\"\n");
    // top-level key stays un-prefixed
    ASSERT_TRUE(t.get_bool("strict").has_value());
    EXPECT_FALSE(*t.get_bool("strict"));
    // and is NOT reachable under the table prefix
    EXPECT_FALSE(t.get_bool("env.strict").has_value());
}

TEST(Toml, TableHeaderWithSurroundingWhitespace) {
    auto t = MustParse(
        "[ env ]\n"
        "TZ = \"UTC\"\n");
    EXPECT_EQ(t.get_string("env.TZ").value_or(""), "UTC");
}

// ---------------------------------------------------------------------------
// get_table_of_strings.
// ---------------------------------------------------------------------------

TEST(Toml, GetTableOfStrings) {
    auto t = MustParse(
        "[env]\n"
        "TZ = \"UTC\"\n"
        "LANG = \"en_US.UTF-8\"\n"
        "LC_ALL = \"en_US.UTF-8\"\n");
    auto m = t.get_table_of_strings("env");
    EXPECT_EQ(m.size(), 3u);
    EXPECT_EQ(m["TZ"], "UTC");
    EXPECT_EQ(m["LANG"], "en_US.UTF-8");
    EXPECT_EQ(m["LC_ALL"], "en_US.UTF-8");
}

TEST(Toml, GetTableOfStringsMissingTableIsEmpty) {
    auto t = MustParse(
        "[env]\n"
        "TZ = \"UTC\"\n");
    EXPECT_TRUE(t.get_table_of_strings("nope").empty());
}

TEST(Toml, GetTableOfStringsOfEmptyTable) {
    auto t = MustParse("[env]\n");
    EXPECT_TRUE(t.get_table_of_strings("env").empty());
}

// ---------------------------------------------------------------------------
// The exact example config from SPEC.md.
// ---------------------------------------------------------------------------

TEST(Toml, SpecExampleParses) {
    std::string err = "sentinel";
    auto parsed = parse_toml(kSpecExample, err);
    ASSERT_TRUE(parsed.has_value()) << "err=" << err;
    EXPECT_TRUE(err.empty());
}

TEST(Toml, SpecExampleTopLevelScalars) {
    auto t = MustParse(kSpecExample);
    auto strict = t.get_bool("strict");
    ASSERT_TRUE(strict.has_value());
    EXPECT_FALSE(*strict);
    EXPECT_EQ(t.get_string("network").value_or(""), "full");
}

TEST(Toml, SpecExampleArrays) {
    auto t = MustParse(kSpecExample);
    auto rd = t.get_string_array("allow_read");
    ASSERT_TRUE(rd.has_value());
    ASSERT_EQ(rd->size(), 1u);
    EXPECT_EQ((*rd)[0], "./src");

    auto wr = t.get_string_array("allow_write");
    ASSERT_TRUE(wr.has_value());
    ASSERT_EQ(wr->size(), 1u);
    EXPECT_EQ((*wr)[0], "./out");

    auto ev = t.get_string_array("allow_env");
    ASSERT_TRUE(ev.has_value());
    ASSERT_EQ(ev->size(), 1u);
    EXPECT_EQ((*ev)[0], "OPENAI_API_KEY");
}

TEST(Toml, SpecExampleEnvTable) {
    auto t = MustParse(kSpecExample);
    auto m = t.get_table_of_strings("env");
    EXPECT_EQ(m.size(), 3u);
    EXPECT_EQ(m["TZ"], "UTC");
    EXPECT_EQ(m["LANG"], "en_US.UTF-8");
    EXPECT_EQ(m["LC_ALL"], "en_US.UTF-8");
    // also reachable via dotted keys
    EXPECT_EQ(t.get_string("env.TZ").value_or(""), "UTC");
}

TEST(Toml, SpecExampleFontconfigAndAudit) {
    auto t = MustParse(kSpecExample);
    auto fc = t.get_bool("fontconfig.enabled");
    ASSERT_TRUE(fc.has_value());
    EXPECT_TRUE(*fc);
    EXPECT_EQ(t.get_string("audit.log_file").value_or(""), ".raincoat/audit.log");
}

// ---------------------------------------------------------------------------
// Malformed inputs: rejected with a helpful err, never a crash.
// ---------------------------------------------------------------------------

TEST(Toml, MalformedKeyWithoutEquals) {
    ExpectMalformed("strict\n");
}

TEST(Toml, MalformedBareWordLine) {
    ExpectMalformed("this is not toml\n");
}

TEST(Toml, MalformedMissingValue) {
    ExpectMalformed("network =\n");
}

TEST(Toml, MalformedMissingKey) {
    ExpectMalformed("= \"full\"\n");
}

TEST(Toml, MalformedUnterminatedDoubleQuote) {
    ExpectMalformed("network = \"full\n");
}

TEST(Toml, MalformedUnterminatedSingleQuote) {
    ExpectMalformed("network = 'full\n");
}

TEST(Toml, MalformedUnterminatedInlineArray) {
    ExpectMalformed("allow_read = [\"a\", \"b\"\n");
}

TEST(Toml, MalformedUnterminatedMultilineArray) {
    ExpectMalformed(
        "allow_read = [\n"
        "  \"a\",\n"
        "  \"b\",\n");
}

TEST(Toml, MalformedUnclosedTableHeader) {
    ExpectMalformed("[env\nTZ = \"UTC\"\n");
}

TEST(Toml, MalformedEmptyTableHeader) {
    ExpectMalformed("[]\n");
}

TEST(Toml, MalformedUnquotedStringValue) {
    // Bare, non-boolean value is not a supported type in this minimal parser.
    ExpectMalformed("network = full\n");
}

// BUG EXPOSURE (adversarial round 1): the array branch does NOT validate
// content after the closing ']', even though the string and bool branches DO
// reject trailing junk (see InlineCommentAfterStringValue / the string branch's
// "unexpected text after string value"). This makes rejection inconsistent and
// lets malformed input through silently. These tests currently FAIL (the parser
// returns a value instead of an error).
TEST(Toml, MalformedTrailingJunkAfterInlineArray) {
    // `a = "x" junk` is rejected, so `a = ["x"] junk` must be too.
    ExpectMalformed("allow_read = [\"x\"] junk\n");
}

TEST(Toml, MalformedTrailingJunkAfterMultilineArray) {
    ExpectMalformed(
        "allow_read = [\n"
        "  \"x\"\n"
        "] junk\n");
}

TEST(Toml, MalformedDoubleClosedArray) {
    // Extra ']' is silently dropped instead of being reported.
    ExpectMalformed("allow_read = [\"x\"]]\n");
}

TEST(Toml, MalformedDoesNotCrashOnJunkBrackets) {
    // Must not crash; must report an error.
    std::string err;
    auto parsed = parse_toml("]][[==\"\"\n", err);
    EXPECT_FALSE(parsed.has_value());
    EXPECT_FALSE(err.empty());
}

// ---------------------------------------------------------------------------
// Nested tables: [a.b.c] headers and keys under them.
// ---------------------------------------------------------------------------

TEST(Toml, DeeplyNestedTableHeader) {
    auto t = MustParse(
        "[a.b.c]\n"
        "key = \"value\"\n"
        "flag = true\n");
    EXPECT_EQ(t.get_string("a.b.c.key").value_or(""), "value");
    ASSERT_TRUE(t.get_bool("a.b.c.flag").has_value());
    EXPECT_TRUE(*t.get_bool("a.b.c.flag"));
}

TEST(Toml, NestedTableGetTableOfStrings) {
    auto t = MustParse(
        "[a.b]\n"
        "x = \"1\"\n"
        "y = \"2\"\n");
    auto m = t.get_table_of_strings("a.b");
    EXPECT_EQ(m.size(), 2u);
    EXPECT_EQ(m["x"], "1");
    EXPECT_EQ(m["y"], "2");
}

TEST(Toml, NestedTablesAreDistinct) {
    auto t = MustParse(
        "[a.b]\n"
        "x = \"1\"\n"
        "[a.c]\n"
        "x = \"2\"\n");
    EXPECT_EQ(t.get_string("a.b.x").value_or(""), "1");
    EXPECT_EQ(t.get_string("a.c.x").value_or(""), "2");
}

// ---------------------------------------------------------------------------
// Numeric literals are TOLERATED (stored as raw scalars), never fatal — while
// genuine bare words stay rejected.
// ---------------------------------------------------------------------------

TEST(Toml, BareIntegerIsToleratedAsScalar) {
    auto t = MustParse("timeout_seconds = 120\n");
    EXPECT_EQ(t.get_string("timeout_seconds").value_or(""), "120");
    // It is not a bool.
    EXPECT_FALSE(t.get_bool("timeout_seconds").has_value());
    // But it is present (present-but-not-a-bool, not absent).
    EXPECT_TRUE(t.contains("timeout_seconds"));
}

TEST(Toml, BareIntegerInTableIsTolerated) {
    auto t = MustParse(
        "[egress]\n"
        "timeout_seconds = 120\n");
    EXPECT_EQ(t.get_string("egress.timeout_seconds").value_or(""), "120");
    auto m = t.get_table_of_strings("egress");
    EXPECT_EQ(m["timeout_seconds"], "120");
}

TEST(Toml, BareNegativeAndFloatTolerated) {
    auto t = MustParse(
        "a = -7\n"
        "b = 3.14\n");
    EXPECT_EQ(t.get_string("a").value_or(""), "-7");
    EXPECT_EQ(t.get_string("b").value_or(""), "3.14");
}

TEST(Toml, BareWordStillRejected) {
    // Guard: numeric tolerance must not accept alphabetic bare words.
    ExpectMalformed("network = full\n");
}

TEST(Toml, UnknownKeysAndSectionsAreTolerated) {
    // A rich, mixed config with keys/sections this parser doesn't "know" about
    // must parse without error.
    auto t = MustParse(
        "profile_name = \"x\"\n"
        "[some_future_section]\n"
        "count = 42\n"
        "flag = false\n"
        "label = \"hi\"\n"
        "list = [\"a\", \"b\"]\n");
    EXPECT_EQ(t.get_string("profile_name").value_or(""), "x");
    EXPECT_EQ(t.get_string("some_future_section.count").value_or(""), "42");
    EXPECT_EQ(t.get_string("some_future_section.label").value_or(""), "hi");
}

// ---------------------------------------------------------------------------
// Array-of-tables: [[name]].
// ---------------------------------------------------------------------------

TEST(Toml, ArrayOfTablesAbsentIsEmpty) {
    auto t = MustParse("network = \"full\"\n");
    EXPECT_TRUE(t.get_table_array("egress.bridge").empty());
}

TEST(Toml, ArrayOfTablesTwoEntries) {
    auto t = MustParse(
        "[[server]]\n"
        "name = \"a\"\n"
        "port = 1\n"
        "[[server]]\n"
        "name = \"b\"\n"
        "port = 2\n");
    auto v = t.get_table_array("server");
    ASSERT_EQ(v.size(), 2u);
    EXPECT_EQ(v[0].get_string("name").value_or(""), "a");
    EXPECT_EQ(v[0].get_string("port").value_or(""), "1");
    EXPECT_EQ(v[1].get_string("name").value_or(""), "b");
    EXPECT_EQ(v[1].get_string("port").value_or(""), "2");
    // Entry keys are relative to the entry, not the array name.
    EXPECT_FALSE(v[0].get_string("server.name").has_value());
}

TEST(Toml, ArrayOfTablesSingleEntry) {
    auto t = MustParse(
        "[[dns.map]]\n"
        "host = \"example.com\"\n"
        "ip = \"203.0.113.10\"\n");
    auto v = t.get_table_array("dns.map");
    ASSERT_EQ(v.size(), 1u);
    EXPECT_EQ(v[0].get_string("host").value_or(""), "example.com");
    EXPECT_EQ(v[0].get_string("ip").value_or(""), "203.0.113.10");
}

TEST(Toml, ArrayOfTablesWithArraysAndBools) {
    auto t = MustParse(
        "[[egress.bridge]]\n"
        "name = \"primary\"\n"
        "preserve_host = false\n"
        "strip_headers = [\"A\", \"B\", \"C\"]\n");
    auto v = t.get_table_array("egress.bridge");
    ASSERT_EQ(v.size(), 1u);
    ASSERT_TRUE(v[0].get_bool("preserve_host").has_value());
    EXPECT_FALSE(*v[0].get_bool("preserve_host"));
    auto sh = v[0].get_string_array("strip_headers");
    ASSERT_TRUE(sh.has_value());
    ASSERT_EQ(sh->size(), 3u);
    EXPECT_EQ((*sh)[2], "C");
}

TEST(Toml, ArrayOfTablesEntrySubTable) {
    // [egress.bridge.inject_headers] under [[egress.bridge]] must be reachable
    // from the entry as the sub-table "inject_headers".
    auto t = MustParse(
        "[[egress.bridge]]\n"
        "name = \"primary\"\n"
        "[egress.bridge.inject_headers]\n"
        "X-Trace = \"on\"\n"
        "[[egress.bridge]]\n"
        "name = \"secondary\"\n");
    auto v = t.get_table_array("egress.bridge");
    ASSERT_EQ(v.size(), 2u);
    EXPECT_EQ(v[0].get_string("name").value_or(""), "primary");
    auto ih = v[0].get_table_of_strings("inject_headers");
    ASSERT_EQ(ih.size(), 1u);
    EXPECT_EQ(ih["X-Trace"], "on");
    EXPECT_EQ(v[0].get_string("inject_headers.X-Trace").value_or(""), "on");
    // The sub-table belongs to the FIRST entry only.
    EXPECT_TRUE(v[1].get_table_of_strings("inject_headers").empty());
    EXPECT_EQ(v[1].get_string("name").value_or(""), "secondary");
}

TEST(Toml, ArrayOfTablesEmptySubTableStillReachable) {
    // An empty sub-table header (only a comment inside) is still present.
    auto t = MustParse(
        "[[egress.bridge]]\n"
        "name = \"primary\"\n"
        "[egress.bridge.inject_headers]\n"
        "# nothing here\n");
    auto v = t.get_table_array("egress.bridge");
    ASSERT_EQ(v.size(), 1u);
    EXPECT_TRUE(v[0].get_table_of_strings("inject_headers").empty());
    // contains() distinguishes present-but-empty from absent.
    EXPECT_TRUE(v[0].contains("inject_headers"));
    EXPECT_FALSE(v[0].contains("nonexistent"));
}

TEST(Toml, TopLevelTableAfterArrayOfTablesResetsContext) {
    // A plain [header] that is NOT a sub-table of the open array closes the
    // array scope and lands back at the root.
    auto t = MustParse(
        "[[server]]\n"
        "name = \"a\"\n"
        "[other]\n"
        "k = \"v\"\n");
    EXPECT_EQ(t.get_string("other.k").value_or(""), "v");
    auto v = t.get_table_array("server");
    ASSERT_EQ(v.size(), 1u);
    // "other" must NOT have leaked into the server entry.
    EXPECT_TRUE(v[0].get_table_of_strings("other").empty());
}

TEST(Toml, MalformedUnterminatedArrayOfTablesHeader) {
    ExpectMalformed("[[server]\nname = \"a\"\n");
}

TEST(Toml, MalformedEmptyArrayOfTablesHeader) {
    ExpectMalformed("[[]]\n");
}

// ---------------------------------------------------------------------------
// End-to-end: the full directional config reference must parse WITHOUT error,
// with spot-checks across sections, arrays-of-tables and nested sub-tables.
// ---------------------------------------------------------------------------

namespace {
// Read docs/full-config-reference.toml, tolerating whichever cwd the test binary
// runs from (repo root for the standalone build, build/ dir under ctest).
std::string ReadReferenceConfig() {
    const char* candidates[] = {
        "docs/full-config-reference.toml",
        "../docs/full-config-reference.toml",
        "../../docs/full-config-reference.toml",
        "/home/zach/Develop/Raincoat/docs/full-config-reference.toml",
    };
    for (const char* path : candidates) {
        std::ifstream f(path);
        if (f.good()) {
            std::ostringstream ss;
            ss << f.rdbuf();
            return ss.str();
        }
    }
    return "";
}
}  // namespace

TEST(Toml, FullConfigReferenceParsesWithoutError) {
    std::string text = ReadReferenceConfig();
    ASSERT_FALSE(text.empty()) << "could not locate docs/full-config-reference.toml";
    std::string err = "sentinel";
    auto parsed = parse_toml(text, err);
    ASSERT_TRUE(parsed.has_value()) << "reference config failed to parse: " << err;
    EXPECT_TRUE(err.empty());
}

TEST(Toml, FullConfigReferenceSpotChecks) {
    std::string text = ReadReferenceConfig();
    ASSERT_FALSE(text.empty());
    auto t = MustParse(text);

    // Top-level scalars.
    ASSERT_TRUE(t.get_bool("strict").has_value());
    EXPECT_TRUE(*t.get_bool("strict"));
    EXPECT_EQ(t.get_string("network").value_or(""), "bridge");
    EXPECT_EQ(t.get_string("profile_name").value_or(""), "default-agent-sandbox");

    // [identity].username
    EXPECT_EQ(t.get_string("identity.username").value_or(""), "user");
    EXPECT_EQ(t.get_string("identity.timezone").value_or(""), "UTC");

    // [environment.set] table
    auto envset = t.get_table_of_strings("environment.set");
    EXPECT_EQ(envset["HOME"], "/home/user");
    EXPECT_EQ(envset["USER"], "user");
    EXPECT_EQ(envset["LANG"], "en_US.UTF-8");
    EXPECT_EQ(t.get_string("environment.set.TZ").value_or(""), "UTC");

    // A tolerated bare integer somewhere in the config.
    EXPECT_EQ(t.get_string("egress.timeout_seconds").value_or(""), "120");

    // [[egress.bridge]] has 2 entries.
    auto bridges = t.get_table_array("egress.bridge");
    ASSERT_EQ(bridges.size(), 2u);

    // First entry fields.
    EXPECT_EQ(bridges[0].get_string("name").value_or(""), "primary-api");
    EXPECT_EQ(bridges[0].get_string("env").value_or(""), "SOME_BASE_URL");
    EXPECT_EQ(bridges[0].get_string("child_endpoint").value_or(""),
              "http://127.0.0.1:18080");
    EXPECT_EQ(bridges[0].get_string("upstream_endpoint").value_or(""),
              "https://real-upstream.example.com");
    auto sh0 = bridges[0].get_string_array("strip_headers");
    ASSERT_TRUE(sh0.has_value());
    ASSERT_EQ(sh0->size(), 4u);
    EXPECT_EQ((*sh0)[0], "Proxy-Authorization");
    EXPECT_EQ((*sh0)[3], "X-Real-IP");

    // First entry's [egress.bridge.inject_headers] sub-table (empty but present).
    EXPECT_TRUE(bridges[0].get_table_of_strings("inject_headers").empty());
    EXPECT_TRUE(bridges[0].contains("inject_headers"));

    // Second entry fields.
    EXPECT_EQ(bridges[1].get_string("name").value_or(""), "secondary-api");
    EXPECT_EQ(bridges[1].get_string("env").value_or(""), "SECONDARY_BASE_URL");
    EXPECT_EQ(bridges[1].get_string("upstream_endpoint").value_or(""),
              "https://secondary-upstream.example.com");
    auto sh1 = bridges[1].get_string_array("strip_headers");
    ASSERT_TRUE(sh1.has_value());
    EXPECT_EQ(sh1->size(), 4u);

    // [[dns.map]] entry.
    auto dns = t.get_table_array("dns.map");
    ASSERT_EQ(dns.size(), 1u);
    EXPECT_EQ(dns[0].get_string("host").value_or(""), "example.com");
    EXPECT_EQ(dns[0].get_string("ip").value_or(""), "203.0.113.10");

    // A nested [network_policy] array is reachable.
    auto blocked = t.get_string_array("network_policy.block_hosts");
    ASSERT_TRUE(blocked.has_value());
    EXPECT_FALSE(blocked->empty());
}

// ---------------------------------------------------------------------------
// ADVERSARIAL ROUND 1 (attack the new TOML features): RED tests that pin down
// concrete defects. No code fix is applied — these document real, reproducible
// bugs found by feeding tricky-but-valid and malformed inputs.
// ---------------------------------------------------------------------------

// DEFECT (security-relevant): a key defined twice is silently accepted with
// last-value-wins instead of being rejected. TOML forbids duplicate keys, and
// for a privacy tool this is a silent downgrade vector: `strict = true` followed
// later (e.g. by an appended/stray line) by `strict = false` yields strict=false
// with NO error. The profile layer's present-but-wrong-type guards never fire
// because the value IS a valid bool — it is just the wrong one.
TEST(Toml, MalformedDuplicateKeyRejected) {
    ExpectMalformed("strict = true\nstrict = false\n");
}

// DEFECT: quoted keys keep their literal quote characters instead of being
// unquoted. The authoritative DEMO config documents inject_headers with a quoted
// header name (docs/full-config-reference.toml ~line 329:
// `"X-Raincoat-Bridge" = "primary-api"`) because HTTP header names are not
// bare-key safe. Parsing stores the key AS `"X-Raincoat-Bridge"` (quotes
// included), so the logical name is unreachable and the header map is silently
// wrong the moment a user follows the documented example.
TEST(Toml, QuotedKeyIsUnquoted) {
    auto t = MustParse("\"X-Raincoat-Bridge\" = \"primary-api\"\n");
    EXPECT_EQ(t.get_string("X-Raincoat-Bridge").value_or("<missing>"),
              "primary-api");
}

TEST(Toml, QuotedKeyInInjectHeadersSubTable) {
    auto t = MustParse(
        "[[egress.bridge]]\n"
        "name = \"primary-api\"\n"
        "[egress.bridge.inject_headers]\n"
        "\"X-Raincoat-Bridge\" = \"primary-api\"\n");
    auto b = t.get_table_array("egress.bridge");
    ASSERT_EQ(b.size(), 1u);
    auto ih = b[0].get_table_of_strings("inject_headers");
    ASSERT_EQ(ih.size(), 1u);
    EXPECT_EQ(ih.count("X-Raincoat-Bridge"), 1u)
        << "quoted header key retained its literal quote characters; stored as "
        << ih.begin()->first;
}

// DEFECT: a nested array-of-tables `[[a.b]]` declared while `[[a]]` is the open
// entry is stored at the ROOT under the dotted name `a.b` instead of nested
// inside the current `a` entry, and NO error is raised. The nesting is silently
// lost, so a config relying on nested arrays-of-tables misparses without any
// diagnostic.
TEST(Toml, NestedArrayOfTablesBelongsToParentEntry) {
    auto t = MustParse(
        "[[fruit]]\n"
        "name = \"apple\"\n"
        "[[fruit.variety]]\n"
        "name = \"red delicious\"\n"
        "[[fruit.variety]]\n"
        "name = \"granny smith\"\n");
    auto fruit = t.get_table_array("fruit");
    ASSERT_EQ(fruit.size(), 1u);
    auto var = fruit[0].get_table_array("variety");
    EXPECT_EQ(var.size(), 2u)
        << "nested [[fruit.variety]] should belong to the fruit entry, not root";
}

// DEFECT: a bare key containing whitespace (`a b = ...`) is accepted as a single
// key literally named "a b". TOML bare keys may not contain spaces; this masks
// typos like a dropped `=` or an accidental two-word key.
TEST(Toml, MalformedBareKeyWithSpaceRejected) {
    ExpectMalformed("a b = \"c\"\n");
}

// ---------------------------------------------------------------------------
// ADVERSARIAL ROUND 2 (attack the new TOML features again): RED tests pinning
// concrete defects found by feeding deeper nesting and type-collision inputs.
// No code fix is applied — these document real, reproducible bugs.
// ---------------------------------------------------------------------------

// DEFECT (data loss, no diagnostic): the nested array-of-tables handling only
// tracks ONE currently-open array name (`current_array`). Descending two levels
// — [[a]] -> [[a.b]] -> [[a.b.c]] — and then re-opening the intermediate level
// [[a.b]] as a sibling is NOT recognised as belonging to the a[0] entry, because
// the open array is now "a.b.c" and "a.b" neither equals it nor is prefixed by
// it. The entry is silently created at the document ROOT under the dotted name
// "a.b" instead of appended to a[0]'s "b" array, and NO error is raised. The
// second variety is simply lost from the structure a caller reads via
// get_table_array on the parent entry.
TEST(Toml, NestedArrayOfTablesReturnToIntermediateLevel) {
    auto t = MustParse(
        "[[a]]\n"
        "n = \"1\"\n"
        "[[a.b]]\n"
        "n = \"2\"\n"
        "[[a.b.c]]\n"
        "n = \"3\"\n"
        "[[a.b]]\n"          // sibling of the first [[a.b]] under a[0]
        "n = \"4\"\n");
    auto a = t.get_table_array("a");
    ASSERT_EQ(a.size(), 1u);
    // Both [[a.b]] entries belong to a[0]'s "b" array.
    EXPECT_EQ(a[0].get_table_array("b").size(), 2u)
        << "re-opened intermediate [[a.b]] should be a sibling under a[0], not "
           "stranded at the root";
    // And nothing should have leaked to a root-level "a.b" array-of-tables.
    EXPECT_TRUE(t.get_table_array("a.b").empty())
        << "nested array-of-tables entry was silently misplaced at the document root";
}

// DEFECT (type collision silently accepted): a name used as an array-of-tables
// [[egress.bridge]] and then re-declared as a plain [egress.bridge] table (or
// vice versa) is contradictory in TOML — a single name cannot be both. The
// parser accepts both with no error, populating array_tables_ AND tables_ under
// the same dotted name. contains("egress.bridge") is then true while the plain
// table's keys and the array entries coexist, an incoherent structure that hides
// a genuine config mistake instead of reporting it.
TEST(Toml, MalformedTableRedeclaredAsArrayOfTables) {
    ExpectMalformed(
        "[[egress.bridge]]\n"
        "n = \"1\"\n"
        "[egress.bridge]\n"
        "x = \"2\"\n");
}

TEST(Toml, MalformedArrayOfTablesRedeclaredAsTable) {
    ExpectMalformed(
        "[egress.bridge]\n"
        "x = \"2\"\n"
        "[[egress.bridge]]\n"
        "n = \"1\"\n");
}

}  // namespace
