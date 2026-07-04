// Raincoat — attack round 1: /usr/local/share/fonts fingerprint leak.
//
// DEFECT (privacy leak, fails RED until fixed):
//   The curated-font isolation masks ONLY /usr/share/fonts (build_bwrap_argv emits
//   `--tmpfs /usr/share/fonts` + re-binds the curated Noto/DejaVu dirs). But two
//   things still steer fontconfig (and GTK/pango) at /usr/local/share/fonts:
//     1. the SHIPPED assets/fontconfig/fonts.conf — copied verbatim into the child
//        and pinned via FONTCONFIG_FILE — contains `<dir>/usr/local/share/fonts</dir>`;
//     2. font_guard pins XDG_DATA_DIRS="/usr/local/share:/usr/share", and toolkits
//        scan "$XDG_DATA_DIRS/fonts".
//   /usr/local/share/fonts lives UNDER the base `--ro-bind /usr /usr`, so it is exposed
//   to the child unmasked. Any font a host has installed there (the standard location
//   for admin / manually-installed fonts) is therefore fully enumerable inside the
//   sandbox, defeating the anti-fingerprinting guarantee even with fontconfig ENABLED.
//
//   Proven live: reproducing raincoat's exact font-isolation mounts under bwrap while a
//   host-only family ("Lato") sits in /usr/local/share/fonts, `fc-list` inside the
//   sandbox lists "Lato".
//
//   Correct behavior: whenever the curated mask is active, /usr/local/share/fonts must
//   also be neutralized (mask it with a tmpfs, mirroring /usr/share/fonts). These tests
//   assert that and currently FAIL because no such mask is emitted.
#include <gtest/gtest.h>

#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include "bwrap.hpp"
#include "config.hpp"

using namespace raincoat;
using Argv = std::vector<std::string>;

namespace {

bool hasPair(const Argv& a, const std::string& x, const std::string& y) {
    for (int i = 0; i + 1 < static_cast<int>(a.size()); ++i)
        if (a[i] == x && a[i + 1] == y) return true;
    return false;
}
int indexOfTriple(const Argv& a, const std::string& x, const std::string& y,
                  const std::string& z) {
    for (int i = 0; i + 2 < static_cast<int>(a.size()); ++i)
        if (a[i] == x && a[i + 1] == y && a[i + 2] == z) return i;
    return -1;
}
int indexOfTmpfs(const Argv& a, const std::string& target) {
    for (int i = 0; i + 1 < static_cast<int>(a.size()); ++i)
        if (a[i] == "--tmpfs" && a[i + 1] == target) return i;
    return -1;
}

const std::vector<std::string> kCurated = {
    "/usr/share/fonts/truetype/dejavu",
    "/usr/share/fonts/opentype/noto",
};

Config baseCfg() {
    Config c;
    c.net = NetMode::Full;
    c.workdir = "/work";
    c.command = {"cmd"};
    return c;
}
EnvResolution env1() {
    EnvResolution e;
    e.resolved = {{"PATH", "/usr/bin"}};
    return e;
}

Argv buildFontOnly() {
    return build_bwrap_argv("/usr/bin/bwrap", baseCfg(), {}, env1(), "/fh", "/tmp",
                            /*bind_resolv_conf=*/true, /*font_dir=*/"", /*audit_mask_dir=*/"",
                            /*sandbox_out=*/"", /*mask_empty_file=*/"", /*mask_files=*/{},
                            kCurated);
}

}  // namespace

// The shipped fonts.conf really does point fontconfig at /usr/local/share/fonts, so the
// leak surface is live for every enabled run. (Context assertion — passes today.)
TEST(FontLocalShareLeak, ShippedConfScansUsrLocalShareFonts) {
    const std::string path =
        std::string(RC_SOURCE_DIR) + "/assets/fontconfig/fonts.conf";
    std::ifstream in(path, std::ios::binary);
    ASSERT_TRUE(in.is_open()) << "cannot open shipped fonts.conf: " << path;
    std::ostringstream ss;
    ss << in.rdbuf();
    const std::string conf = ss.str();
    EXPECT_NE(conf.find("<dir>/usr/local/share/fonts</dir>"), std::string::npos)
        << "shipped fonts.conf no longer references /usr/local/share/fonts; if it was "
           "removed as the fix, delete this context assertion.";
}

// CORE DEFECT: with the curated mask active, /usr/local/share/fonts must be masked too.
// It sits under `--ro-bind /usr /usr` and is scanned by the shipped fonts.conf +
// XDG_DATA_DIRS, so leaving it unmasked leaks the host's locally-installed font list.
// FAILS today: build_bwrap_argv masks only /usr/share/fonts.
TEST(FontLocalShareLeak, UsrLocalShareFontsIsMaskedWhenCuratedActive) {
    Argv a = buildFontOnly();
    // Sanity: the existing /usr/share/fonts mask IS present (isolation is active).
    ASSERT_TRUE(hasPair(a, "--tmpfs", "/usr/share/fonts"));
    // The leak: /usr/local/share/fonts must also be neutralized.
    EXPECT_GE(indexOfTmpfs(a, "/usr/local/share/fonts"), 0)
        << "/usr/local/share/fonts is exposed via --ro-bind /usr and scanned by the "
           "shipped fonts.conf; host fonts installed there leak the family list into "
           "the sandbox despite fontconfig isolation being enabled.";
}

// The mask (once added) must overlay the /usr bind, mirroring the /usr/share/fonts mask.
// FAILS today for the same reason (no such tmpfs exists).
TEST(FontLocalShareLeak, UsrLocalMaskFollowsUsrRoBind) {
    Argv a = buildFontOnly();
    int usr = indexOfTriple(a, "--ro-bind", "/usr", "/usr");
    int local = indexOfTmpfs(a, "/usr/local/share/fonts");
    ASSERT_GE(usr, 0);
    ASSERT_GE(local, 0) << "no mask on /usr/local/share/fonts (leak present)";
    EXPECT_LT(usr, local) << "the mask must overlay the /usr bind, not precede it";
}
