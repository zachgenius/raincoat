// Raincoat — browser isolation, ATTACK ROUND 2 (regression).
//
// Focus: the [browser] feature must be a strict NO-OP when disabled (the default) and
// must never DEGRADE the surrounding features (MVP env/PATH handling, the guarded proxy
// / network policy) when composed with them. Its shim dir, when prepended to the child
// PATH, must ONLY intercept the handful of known browser names and never shadow an
// unrelated binary — including names that merely SHARE a substring with a browser name.
//
// Test kinds:
//   * Pure/mechanism tests (no bwrap, no real browser) drive setup_browser() directly
//     and probe the shim dir against fake stubs.
//   * End-to-end tests drive the compiled `raincoat` binary through bubblewrap; they
//     GTEST_SKIP() when bwrap or the binary is unavailable so the suite is a no-op (not
//     a failure) on hosts that cannot sandbox.
//
// One e2e test — EnabledShimsMustNotMislabelPathAsVerbatim — is EXPECTED TO FAIL against
// the current implementation. It demonstrates a genuine audit-honesty regression: when
// launch shims are on the runner PREPENDS the shim dir to $PATH (modifying the value the
// child receives) but leaves PATH classified under "Env allowed" ("copied verbatim from
// parent"). The audit therefore swears PATH was passed through untouched while Raincoat
// in fact rewrote it. The fix is to reclassify PATH as "set" (as the font env vars are)
// once the shim dir is prepended.

#include <gtest/gtest.h>
#include "rc_test_timeout.h"

#include <atomic>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <vector>

#include <sys/wait.h>
#include <unistd.h>

#include "browser.hpp"
#include "config.hpp"

namespace fs = std::filesystem;
using namespace raincoat;

namespace {

std::string make_root(const char* tag) {
    static std::atomic<unsigned> counter{0};
    fs::path p = fs::temp_directory_path() /
                 (std::string("rc_battack2_") + tag + "_" + std::to_string(::getpid()) +
                  "_" + std::to_string(counter.fetch_add(1)));
    fs::create_directories(p);
    return p.string();
}

// popen capture (stdout+stderr), wrapped in a hard timeout so a regressed (recursing)
// shim cannot hang the suite.
std::string run_capture(const std::string& cmd) {
    std::string full = rc_timeout(10) + cmd + " 2>&1";
    std::string out;
    FILE* p = ::popen(full.c_str(), "r");
    if (!p) return out;
    char buf[4096];
    size_t n;
    while ((n = ::fread(buf, 1, sizeof(buf), p)) > 0) out.append(buf, n);
    ::pclose(p);
    return out;
}

void write_stub(const std::string& path, const std::string& tag) {
    std::ofstream f(path);
    f << "#!/bin/sh\necho " << tag << "\n";
    f.close();
    fs::permissions(path, fs::perms::owner_all | fs::perms::group_read |
                              fs::perms::group_exec | fs::perms::others_read |
                              fs::perms::others_exec);
}

BrowserConfig enabled_shims_cfg() {
    BrowserConfig c;
    c.enabled = true;
    c.use_launch_shims = true;
    c.locale = "en-US";
    c.viewport = "1280x720";
    c.timezone = "UTC";
    return c;
}

}  // namespace

// ===========================================================================
// PURE MECHANISM TESTS (no bwrap)
// ===========================================================================

// The disabled no-op must be gated on `enabled` ALONE — not on the other knobs. A future
// refactor that keyed the early-return on, say, use_launch_shims would materialize a
// throwaway profile / shim dir for a user who explicitly disabled the whole feature.
// enabled=false with EVERY other field set to its "do work" value must still touch
// nothing on disk and return an empty setup.
TEST(BrowserAttack2Regression, DisabledIsNoOpEvenWithEveryOtherKnobRequested) {
    BrowserConfig c;
    c.enabled = false;            // the ONLY thing that should matter
    c.use_launch_shims = true;    // would otherwise write shims
    c.isolate_profile = true;     // would otherwise create a profile dir
    c.profile_dir = "/should/not/be/created";
    c.locale = "en-US";
    c.viewport = "1280x720";
    c.timezone = "UTC";

    std::string root = make_root("disabled");
    std::string err;
    BrowserSetup s = setup_browser(c, root, err);

    EXPECT_TRUE(err.empty()) << err;
    EXPECT_TRUE(s.shim_dir.empty());
    EXPECT_TRUE(s.profile_dir.empty());
    EXPECT_TRUE(s.env.empty());
    // Nothing under the root, and the configured profile_dir was NOT created either.
    EXPECT_FALSE(fs::exists(fs::path(root) / "browser"))
        << "disabled browser isolation created a <root>/browser subtree";
    EXPECT_FALSE(fs::exists("/should/not/be/created"))
        << "disabled browser isolation created the configured profile_dir";
}

// Name interception must be EXACT. Prepending the shim dir must not shadow a binary whose
// name merely CONTAINS, is contained BY, or is a near-miss of a browser name (e.g.
// "chrom", "google-chrome-helper", "firefoxx"). Only an exact browser name resolves to
// the shim; everything else falls through PATH to its real location.
TEST(BrowserAttack2Regression, ShimDirDoesNotShadowSubstringOrSupersetNames) {
    BrowserConfig c = enabled_shims_cfg();
    std::string root = make_root("substr");
    std::string err;
    BrowserSetup s = setup_browser(c, root, err);
    ASSERT_TRUE(err.empty()) << err;
    ASSERT_FALSE(s.shim_dir.empty());

    const std::string realbin = root + "/realbin";
    fs::create_directories(realbin);
    // Near-miss names that must NOT be intercepted, plus a real browser name (chromium)
    // as a positive control that MUST be intercepted.
    const char* passthrough[] = {"chrom", "chromiu", "google-chrome-helper",
                                  "firefoxx", "xfirefox", "chromedriver", "chrome-sandbox"};
    for (const char* n : passthrough) write_stub(realbin + "/" + n, std::string("REAL-") + n);
    write_stub(realbin + "/chromium", "REAL-CHROMIUM");

    const std::string path = s.shim_dir + ":" + realbin + ":/usr/bin:/bin";

    for (const char* n : passthrough) {
        // No shim file of this name exists...
        EXPECT_FALSE(fs::exists(fs::path(s.shim_dir) / n))
            << "shim dir unexpectedly holds a near-miss name: " << n;
        // ...and PATH resolution finds the REAL binary, never the shim dir.
        const std::string resolved =
            run_capture("env PATH='" + path + "' sh -c 'command -v " + n + "'");
        EXPECT_NE(resolved.find(realbin + "/" + n), std::string::npos)
            << "near-miss name '" << n << "' was not resolved to its real binary: "
            << resolved;
        EXPECT_EQ(resolved.find(s.shim_dir + "/" + n), std::string::npos)
            << "near-miss name '" << n << "' was shadowed by the shim dir: " << resolved;
    }

    // Positive control: the EXACT browser name resolves to the shim.
    const std::string chromium =
        run_capture("env PATH='" + path + "' sh -c 'command -v chromium'");
    EXPECT_NE(chromium.find(s.shim_dir + "/chromium"), std::string::npos)
        << "exact browser name must resolve to the shim: " << chromium;
}

// ===========================================================================
// END-TO-END TESTS (drive the compiled binary through bwrap)
// ===========================================================================

namespace {

std::string raincoat_bin() {
    const char* e = std::getenv("RAINCOAT_BIN");
    if (e && *e) return std::string(e);
    return "/home/zach/Develop/Raincoat/build/raincoat";
}

constexpr const char* kBwrapPath = "/usr/bin/bwrap";

bool have_prereqs(std::string& bin, std::string& why) {
    bin = raincoat_bin();
    if (::access(bin.c_str(), X_OK) != 0) {
        why = "raincoat binary not found/executable at " + bin;
        return false;
    }
    if (::access(kBwrapPath, X_OK) != 0) {
        why = std::string("bwrap not found/executable at ") + kBwrapPath;
        return false;
    }
    return true;
}

struct RunResult {
    int exit_code = -1;
    bool spawn_ok = false;
    std::string output;
};

RunResult run_proc(const std::string& bin, const std::vector<std::string>& args,
                   const std::map<std::string, std::string>& env,
                   const std::string& cwd) {
    RunResult r;
    int fds[2];
    if (::pipe(fds) != 0) return r;
    pid_t pid = ::fork();
    if (pid < 0) {
        ::close(fds[0]);
        ::close(fds[1]);
        return r;
    }
    if (pid == 0) {
        if (::chdir(cwd.c_str()) != 0) _exit(126);
        ::dup2(fds[1], STDOUT_FILENO);
        ::dup2(fds[1], STDERR_FILENO);
        ::close(fds[0]);
        ::close(fds[1]);
        std::vector<std::string> argv_str;
        argv_str.push_back(bin);
        for (const auto& a : args) argv_str.push_back(a);
        std::vector<char*> argv;
        for (auto& s : argv_str) argv.push_back(const_cast<char*>(s.c_str()));
        argv.push_back(nullptr);
        std::vector<std::string> env_str;
        for (const auto& kv : env) env_str.push_back(kv.first + "=" + kv.second);
        std::vector<char*> envp;
        for (auto& s : env_str) envp.push_back(const_cast<char*>(s.c_str()));
        envp.push_back(nullptr);
        ::execve(bin.c_str(), argv.data(), envp.data());
        _exit(127);
    }
    r.spawn_ok = true;
    ::close(fds[1]);
    char buf[4096];
    ssize_t n;
    while ((n = ::read(fds[0], buf, sizeof(buf))) > 0)
        r.output.append(buf, static_cast<size_t>(n));
    ::close(fds[0]);
    int status = 0;
    while (::waitpid(pid, &status, 0) < 0) {
        if (errno != EINTR) break;
    }
    if (WIFEXITED(status)) r.exit_code = WEXITSTATUS(status);
    return r;
}

std::string make_temp_dir(const std::string& tag) {
    static std::atomic<unsigned> counter{0};
    fs::path base = fs::temp_directory_path() / "rc-browser-e2e2";
    fs::create_directories(base);
    fs::path dir = base / (tag + "-" + std::to_string(::getpid()) + "-" +
                           std::to_string(counter.fetch_add(1)));
    fs::create_directories(dir);
    return dir.string();
}

std::map<std::string, std::string> base_env(const std::string& real_home) {
    return {
        {"PATH", "/usr/bin:/bin"},
        {"TERM", "xterm"},
        {"HOME", real_home},
    };
}

std::string read_file(const std::string& path) {
    std::ifstream ifs(path, std::ios::binary);
    if (!ifs) return {};
    std::ostringstream ss;
    ss << ifs.rdbuf();
    return ss.str();
}

std::string write_profile(const std::string& cwd, const std::string& content) {
    std::string p = cwd + "/round2.toml";
    std::ofstream ofs(p, std::ios::binary | std::ios::trunc);
    ofs << content;
    ofs.close();
    return p;
}

// Return the trailing value of a "Label: v1, v2, ..." line in the audit (or "" if absent).
std::string audit_line_value(const std::string& audit, const std::string& label) {
    std::size_t pos = audit.find(label);
    if (pos == std::string::npos) return {};
    std::size_t start = pos + label.size();
    std::size_t eol = audit.find('\n', start);
    std::string v = audit.substr(start, eol == std::string::npos ? std::string::npos
                                                                  : eol - start);
    // Trim leading spaces.
    std::size_t nb = v.find_first_not_of(' ');
    return nb == std::string::npos ? std::string() : v.substr(nb);
}

bool list_contains_token(const std::string& csv, const std::string& tok) {
    std::stringstream ss(csv);
    std::string item;
    while (std::getline(ss, item, ',')) {
        std::size_t a = item.find_first_not_of(' ');
        std::size_t b = item.find_last_not_of(' ');
        if (a == std::string::npos) continue;
        if (item.substr(a, b - a + 1) == tok) return true;
    }
    return false;
}

#define SKIP_UNLESS_SANDBOXABLE(binvar)                       \
    std::string binvar;                                       \
    do {                                                      \
        std::string why;                                      \
        if (!have_prereqs(binvar, why)) GTEST_SKIP() << why;  \
    } while (0)

}  // namespace

// ---------------------------------------------------------------------------
// Disabled browser MUST NOT degrade the guarded proxy / network policy. The
// proxy env is still injected, the child PATH is the untouched base PATH (no
// shim dir), and the audit carries the network-policy line but NO "Browser
// isolation:" note.
// ---------------------------------------------------------------------------
TEST(BrowserAttack2Regression, DisabledBrowserDoesNotRegressNetworkPolicy) {
    SKIP_UNLESS_SANDBOXABLE(bin);

    std::string real_home = make_temp_dir("home");
    std::string cwd = make_temp_dir("cwd");
    auto env = base_env(real_home);

    // Browser explicitly disabled but with shims requested (the knob must be ignored),
    // composed with an active guarded proxy (network policy). isolate_netns="off" pins
    // the shared-loopback model so the test is deterministic on hosts with pasta.
    std::string profile = write_profile(cwd,
        "[browser]\n"
        "enabled = false\n"
        "use_launch_shims = true\n"
        "\n"
        "[network_policy]\n"
        "enabled = true\n"
        "default_action = \"deny\"\n"
        "allow_hosts = [\"localhost\"]\n"
        "\n"
        "[egress]\n"
        "isolate_netns = \"off\"\n");

    RunResult r = run_proc(bin, {"--profile", profile, "--", "/usr/bin/env"}, env, cwd);
    ASSERT_TRUE(r.spawn_ok);
    EXPECT_EQ(r.exit_code, 0) << r.output;

    // Network policy still in force: the proxy env is injected (both cases).
    EXPECT_NE(r.output.find("http_proxy=http://127.0.0.1:"), std::string::npos)
        << "guarded proxy env was not injected with browser disabled:\n" << r.output;
    EXPECT_NE(r.output.find("HTTP_PROXY=http://127.0.0.1:"), std::string::npos) << r.output;

    // Child PATH is the untouched base PATH: no browser shim dir leaked onto it.
    EXPECT_EQ(r.output.find("/browser/shims"), std::string::npos)
        << "a browser shim dir leaked onto the child PATH while browser is disabled:\n"
        << r.output;

    std::string audit = read_file((fs::path(cwd) / ".raincoat" / "audit.log").string());
    ASSERT_FALSE(audit.empty());
    EXPECT_NE(audit.find("Network policy:"), std::string::npos) << audit;
    EXPECT_EQ(audit.find("Browser isolation:"), std::string::npos)
        << "disabled browser isolation emitted an enabled audit note:\n" << audit;
}

// ---------------------------------------------------------------------------
// EXPECTED FAIL (regression demonstrator): with launch shims ON the runner
// PREPENDS the shim dir to $PATH, so PATH is NO LONGER the parent's value —
// yet the audit still files PATH under "Env allowed" ("copied verbatim from
// parent"). A modified variable must be reported as "set", not "allowed",
// otherwise the tamper-proof audit lies about what reached the child.
// ---------------------------------------------------------------------------
TEST(BrowserAttack2Regression, EnabledShimsMustNotMislabelPathAsVerbatim) {
    SKIP_UNLESS_SANDBOXABLE(bin);

    std::string real_home = make_temp_dir("home");
    std::string cwd = make_temp_dir("cwd");
    auto env = base_env(real_home);

    std::string profile = write_profile(cwd,
        "[browser]\n"
        "enabled = true\n"
        "use_launch_shims = true\n"
        "locale = \"en-US\"\n"
        "viewport = \"1280x720\"\n");

    RunResult r = run_proc(bin, {"--profile", profile, "--", "/usr/bin/true"}, env, cwd);
    ASSERT_TRUE(r.spawn_ok);
    EXPECT_EQ(r.exit_code, 0) << r.output;

    std::string audit = read_file((fs::path(cwd) / ".raincoat" / "audit.log").string());
    ASSERT_FALSE(audit.empty()) << audit;

    // Sanity: shims really are on for this run (so PATH really was rewritten).
    ASSERT_NE(audit.find("Browser isolation: enabled"), std::string::npos) << audit;

    const std::string allowed = audit_line_value(audit, "Env allowed:");
    const std::string setv = audit_line_value(audit, "Env set:");

    // The defect: PATH is listed as "allowed (verbatim from parent)" although Raincoat
    // prepended the shim dir to it. Honest classification puts a modified var under "set".
    EXPECT_FALSE(list_contains_token(allowed, "PATH"))
        << "PATH is labelled 'Env allowed' (copied verbatim from parent) but Raincoat "
           "prepended the browser shim dir to it — the audit misrepresents the modified "
           "PATH.\nEnv allowed: " << allowed << "\nEnv set: " << setv;
    EXPECT_TRUE(list_contains_token(setv, "PATH"))
        << "a shim-modified PATH should be reported under 'Env set'.\nEnv allowed: "
        << allowed << "\nEnv set: " << setv;
}
