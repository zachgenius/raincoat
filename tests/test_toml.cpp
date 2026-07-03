// Raincoat — toml: comprehensive GoogleTest suite (TDD red).
//
// Exercises the minimal TOML parser against the config schema described in
// docs/SPEC.md / docs/DESIGN.md: comments, key=value, booleans, single/double
// quoted strings, inline + multiline arrays, [table] and dotted [a.b] headers,
// the typed dotted-key getters, and malformed-input rejection (helpful err, no
// crash). Written before the implementation exists; expected to fail (red).
#include <gtest/gtest.h>

#include <map>
#include <optional>
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

}  // namespace
