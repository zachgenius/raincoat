// Raincoat — doctor tests (TDD red).
//
// Module contract (docs/DESIGN.md, docs/SPEC.md):
//   struct DoctorReport { bool bwrap_found; std::string bwrap_path, bwrap_version;
//                         bool userns_ok, smoke_ok; std::vector<std::string> notes;
//                         bool usable() const { return bwrap_found && smoke_ok; } };
//   std::optional<std::string> find_bwrap();   // search PATH for an executable bwrap
//   DoctorReport run_doctor();                 // presence + version + real smoke test
//   std::string  format_doctor(const DoctorReport&); // pass/fail lines + install hints if missing
//
// This host HAS bwrap installed (/usr/bin/bwrap, functional --unshare-net), so
// find_bwrap() must locate it and run_doctor() must report the host usable. We also
// exercise format_doctor() on a SYNTHETIC report with bwrap_found=false to assert the
// apt/dnf/pacman install hints are surfaced. Tests never depend on a specific bwrap
// version string.

#include <gtest/gtest.h>

#include <algorithm>
#include <cctype>
#include <optional>
#include <string>
#include <vector>

#include <unistd.h>    // ::access, X_OK, F_OK
#include <sys/stat.h>  // ::stat

#include "doctor.hpp"

// NOTE: this suite deliberately does NOT lean on src/util.cpp helpers
// (path_exists / ends_with / ...). util is a sibling module owned by another
// agent and may be a stub during TDD; host-fact detection here uses raw POSIX
// calls so the red/green signal reflects ONLY the doctor module.

using namespace raincoat;

// --------------------------------------------------------------------------
// helpers
// --------------------------------------------------------------------------

namespace {

std::string lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    return s;
}

bool contains(const std::string& hay, const std::string& needle) {
    return hay.find(needle) != std::string::npos;
}

// case-insensitive contains
bool icontains(const std::string& hay, const std::string& needle) {
    return contains(lower(hay), lower(needle));
}

bool ends_with(const std::string& s, const std::string& suf) {
    return s.size() >= suf.size() &&
           s.compare(s.size() - suf.size(), suf.size(), suf) == 0;
}

// Raw filesystem probes (independent of the util module).
bool file_present(const std::string& p) {
    struct stat st{};
    return ::stat(p.c_str(), &st) == 0;
}

bool file_executable(const std::string& p) {
    return ::access(p.c_str(), X_OK) == 0;
}

// Is bwrap actually available + executable on this host? (guards host-fact tests)
bool host_has_bwrap() {
    return file_executable("/usr/bin/bwrap") || file_executable("/bin/bwrap");
}

DoctorReport make_missing_report() {
    DoctorReport r;
    r.bwrap_found = false;
    r.bwrap_path.clear();
    r.bwrap_version.clear();
    r.userns_ok = false;
    r.smoke_ok = false;
    return r;
}

DoctorReport make_healthy_report() {
    DoctorReport r;
    r.bwrap_found = true;
    r.bwrap_path = "/usr/bin/bwrap";
    r.bwrap_version = "bubblewrap 0.0.0";
    r.userns_ok = true;
    r.smoke_ok = true;
    return r;
}

}  // namespace

// --------------------------------------------------------------------------
// DoctorReport::usable() — pure contract on the header struct
// --------------------------------------------------------------------------

TEST(Doctor, UsableRequiresFoundAndSmoke) {
    DoctorReport r = make_healthy_report();
    EXPECT_TRUE(r.usable());
}

TEST(Doctor, UsableFalseWhenBwrapMissing) {
    DoctorReport r = make_healthy_report();
    r.bwrap_found = false;
    EXPECT_FALSE(r.usable());
}

TEST(Doctor, UsableFalseWhenSmokeFails) {
    DoctorReport r = make_healthy_report();
    r.smoke_ok = false;
    EXPECT_FALSE(r.usable());
}

TEST(Doctor, UsableIndependentOfUserns) {
    // usable() is documented as (bwrap_found && smoke_ok); userns_ok must not gate it.
    DoctorReport r = make_healthy_report();
    r.userns_ok = false;
    EXPECT_TRUE(r.usable());
}

TEST(Doctor, DefaultReportIsUnusable) {
    DoctorReport r;
    EXPECT_FALSE(r.bwrap_found);
    EXPECT_FALSE(r.smoke_ok);
    EXPECT_FALSE(r.usable());
}

// --------------------------------------------------------------------------
// find_bwrap() — search PATH for an executable bwrap
// --------------------------------------------------------------------------

TEST(Doctor, FindBwrapLocatesInstalledBinary) {
    if (!host_has_bwrap()) GTEST_SKIP() << "bwrap not installed on this host";
    auto p = find_bwrap();
    ASSERT_TRUE(p.has_value()) << "find_bwrap() should locate bwrap on this host";
    EXPECT_FALSE(p->empty());
}

TEST(Doctor, FindBwrapReturnsExecutablePath) {
    if (!host_has_bwrap()) GTEST_SKIP() << "bwrap not installed on this host";
    auto p = find_bwrap();
    ASSERT_TRUE(p.has_value());
    // The returned path must exist, be absolute, end in "bwrap", and be executable.
    EXPECT_TRUE(file_present(*p)) << "returned path should exist: " << *p;
    EXPECT_TRUE(ends_with(*p, "bwrap")) << "returned path should end in bwrap: " << *p;
    ASSERT_FALSE(p->empty());
    EXPECT_EQ((*p)[0], '/') << "returned path should be absolute: " << *p;
    EXPECT_TRUE(file_executable(*p)) << "returned path should be executable: " << *p;
}

// --------------------------------------------------------------------------
// run_doctor() — real probing of the host
// --------------------------------------------------------------------------

TEST(Doctor, RunDoctorReportsBwrapFound) {
    if (!host_has_bwrap()) GTEST_SKIP() << "bwrap not installed on this host";
    DoctorReport r = run_doctor();
    EXPECT_TRUE(r.bwrap_found);
    EXPECT_FALSE(r.bwrap_path.empty());
    EXPECT_TRUE(file_present(r.bwrap_path)) << "bwrap_path should point at a real file";
}

TEST(Doctor, RunDoctorCapturesVersion) {
    if (!host_has_bwrap()) GTEST_SKIP() << "bwrap not installed on this host";
    DoctorReport r = run_doctor();
    // Do NOT assert a specific version string — only that some version text was captured.
    EXPECT_FALSE(r.bwrap_version.empty())
        << "run_doctor() should capture `bwrap --version` output";
    // Real `bwrap --version` prints a line mentioning bubblewrap.
    EXPECT_TRUE(icontains(r.bwrap_version, "bubblewrap") ||
                icontains(r.bwrap_version, "bwrap"))
        << "captured version should look like bwrap output: " << r.bwrap_version;
}

TEST(Doctor, RunDoctorSmokeTestPasses) {
    if (!host_has_bwrap()) GTEST_SKIP() << "bwrap not installed on this host";
    DoctorReport r = run_doctor();
    // A real `bwrap ... true` smoke test should succeed on this functional host.
    EXPECT_TRUE(r.smoke_ok) << "bwrap smoke test (`bwrap ... true`) should pass here";
}

TEST(Doctor, RunDoctorReportsUsableOnThisHost) {
    if (!host_has_bwrap()) GTEST_SKIP() << "bwrap not installed on this host";
    DoctorReport r = run_doctor();
    EXPECT_TRUE(r.usable())
        << "host has a functional bwrap, so run_doctor() must report usable";
}

TEST(Doctor, RunDoctorPathMatchesFindBwrap) {
    if (!host_has_bwrap()) GTEST_SKIP() << "bwrap not installed on this host";
    auto found = find_bwrap();
    DoctorReport r = run_doctor();
    ASSERT_TRUE(found.has_value());
    ASSERT_TRUE(r.bwrap_found);
    EXPECT_EQ(*found, r.bwrap_path)
        << "run_doctor() should locate bwrap the same way find_bwrap() does";
}

// --------------------------------------------------------------------------
// format_doctor() — install hints when missing
// --------------------------------------------------------------------------

TEST(Doctor, FormatMissingShowsInstallHints) {
    DoctorReport r = make_missing_report();
    std::string out = format_doctor(r);
    ASSERT_FALSE(out.empty());
    // Must mention the package and all three package managers.
    EXPECT_TRUE(icontains(out, "bubblewrap")) << out;
    EXPECT_TRUE(icontains(out, "apt")) << "expected Ubuntu/Debian hint (apt)\n" << out;
    EXPECT_TRUE(icontains(out, "dnf")) << "expected Fedora hint (dnf)\n" << out;
    EXPECT_TRUE(icontains(out, "pacman")) << "expected Arch hint (pacman)\n" << out;
}

TEST(Doctor, FormatMissingNamesTheMissingBackend) {
    DoctorReport r = make_missing_report();
    std::string out = format_doctor(r);
    // Should surface that bwrap was not found (some fail/not-found marker).
    EXPECT_TRUE(icontains(out, "not found") || icontains(out, "missing") ||
                icontains(out, "fail") || contains(out, "bwrap"))
        << out;
}

TEST(Doctor, FormatMissingIsNotUsable) {
    DoctorReport r = make_missing_report();
    std::string out = format_doctor(r);
    // Should communicate the host is not usable (some negative/unusable marker).
    EXPECT_TRUE(icontains(out, "not usable") || icontains(out, "unusable") ||
                icontains(out, "cannot") || icontains(out, "fail"))
        << out;
}

// bwrap present but the smoke test fails: format_doctor() must hint at unprivileged
// user namespaces (the usual culprit) rather than telling the user to install bwrap.
TEST(Doctor, FormatSmokeFailHintsUserNamespaces) {
    DoctorReport r;
    r.bwrap_found = true;
    r.bwrap_path = "/usr/bin/bwrap";
    r.bwrap_version = "bubblewrap 0.0.0";
    r.userns_ok = false;
    r.smoke_ok = false;
    ASSERT_FALSE(r.usable());

    std::string out = format_doctor(r);
    ASSERT_FALSE(out.empty());
    EXPECT_TRUE(icontains(out, "unprivileged user namespaces"))
        << "smoke-fail case should hint at unprivileged user namespaces\n" << out;
    // It must NOT tell the user to install bubblewrap; bwrap is present.
    EXPECT_FALSE(icontains(out, "apt install")) << out;
    EXPECT_FALSE(icontains(out, "pacman -S")) << out;
}

// Missing bwrap: format_doctor() must surface apt / dnf / pacman install hints.
TEST(Doctor, FormatMissingSurfacesAllPackageManagers) {
    DoctorReport r = make_missing_report();
    std::string out = format_doctor(r);
    ASSERT_FALSE(out.empty());
    EXPECT_TRUE(icontains(out, "apt")) << "expected apt hint\n" << out;
    EXPECT_TRUE(icontains(out, "dnf")) << "expected dnf hint\n" << out;
    EXPECT_TRUE(icontains(out, "pacman")) << "expected pacman hint\n" << out;
}

TEST(Doctor, FormatHealthyReportsPass) {
    DoctorReport r = make_healthy_report();
    std::string out = format_doctor(r);
    ASSERT_FALSE(out.empty());
    // A pass/ok/usable indication should be present for a healthy host.
    EXPECT_TRUE(icontains(out, "ok") || icontains(out, "pass") ||
                icontains(out, "usable") || contains(out, "✓"))
        << out;
}

TEST(Doctor, FormatHealthyShowsBwrapPath) {
    DoctorReport r = make_healthy_report();
    std::string out = format_doctor(r);
    EXPECT_TRUE(contains(out, r.bwrap_path))
        << "format_doctor() should surface the bwrap path\n" << out;
}

TEST(Doctor, FormatHealthyOmitsInstallHints) {
    // Install hints are for the missing case; a usable host should not be told to
    // install bubblewrap.
    DoctorReport r = make_healthy_report();
    std::string out = format_doctor(r);
    EXPECT_FALSE(icontains(out, "apt install"))
        << "healthy host should not print apt install hint\n" << out;
    EXPECT_FALSE(icontains(out, "pacman -S"))
        << "healthy host should not print pacman install hint\n" << out;
}

TEST(Doctor, FormatRealRunDoctorIsNonEmpty) {
    DoctorReport r = run_doctor();
    std::string out = format_doctor(r);
    EXPECT_FALSE(out.empty()) << "format_doctor() should always produce output";
}
