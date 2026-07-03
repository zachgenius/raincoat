// End-to-end integration tests for the compiled `raincoat` binary.
//
// These are REAL runs: each test fork/execs the actual raincoat executable with
// a fully controlled environment and working directory, lets it drive bubblewrap,
// and inspects the child's combined stdout+stderr, exit code, and audit log.
//
// The binary is located via $RAINCOAT_BIN, falling back to the in-tree build
// output. Every test is guarded by GTEST_SKIP() when either /usr/bin/bwrap or the
// raincoat binary is unavailable, so the suite is a no-op (not a failure) on hosts
// that cannot sandbox.
//
// Design notes for non-flakiness:
//   * No dependence on real internet. The --net off test asserts on the audited
//     network mode + that the process still runs, never on reaching a live host.
//   * Each run gets its own fresh temp cwd, so audit logs never collide.
//   * Commands use absolute interpreters (/usr/bin/env, sh, cat) resolvable from
//     the sandbox PATH we inject.
#include <gtest/gtest.h>

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <map>
#include <sstream>
#include <string>
#include <vector>

#include <sys/wait.h>
#include <unistd.h>

namespace {

namespace fs = std::filesystem;

// ---------------------------------------------------------------------------
// Prerequisite detection + binary location
// ---------------------------------------------------------------------------

std::string raincoat_bin() {
    const char* e = std::getenv("RAINCOAT_BIN");
    if (e && *e) return std::string(e);
    return "/home/zach/Develop/Raincoat/build/raincoat";
}

constexpr const char* kBwrapPath = "/usr/bin/bwrap";

// Returns true and fills `bin` when both the raincoat binary and bwrap are
// executable; otherwise returns false so the caller can GTEST_SKIP.
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

// ---------------------------------------------------------------------------
// Process runner: fork/exec with a fully controlled env + cwd, capture output
// ---------------------------------------------------------------------------

struct RunResult {
    int exit_code = -1;     // WEXITSTATUS, or 128+sig when signalled
    bool signaled = false;
    bool spawn_ok = false;  // false if the harness itself failed (pipe/fork)
    std::string output;     // combined stdout + stderr
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
        // ---- child ----
        if (::chdir(cwd.c_str()) != 0) _exit(126);
        ::dup2(fds[1], STDOUT_FILENO);
        ::dup2(fds[1], STDERR_FILENO);
        ::close(fds[0]);
        ::close(fds[1]);

        // argv
        std::vector<std::string> argv_str;
        argv_str.reserve(args.size() + 1);
        argv_str.push_back(bin);
        for (const auto& a : args) argv_str.push_back(a);
        std::vector<char*> argv;
        argv.reserve(argv_str.size() + 1);
        for (auto& s : argv_str) argv.push_back(const_cast<char*>(s.c_str()));
        argv.push_back(nullptr);

        // envp (fully replaces the parent environment -> controlled)
        std::vector<std::string> env_str;
        env_str.reserve(env.size());
        for (const auto& kv : env) env_str.push_back(kv.first + "=" + kv.second);
        std::vector<char*> envp;
        envp.reserve(env_str.size() + 1);
        for (auto& s : env_str) envp.push_back(const_cast<char*>(s.c_str()));
        envp.push_back(nullptr);

        ::execve(bin.c_str(), argv.data(), envp.data());
        _exit(127);  // exec failed
    }

    // ---- parent ----
    r.spawn_ok = true;
    ::close(fds[1]);
    char buf[4096];
    ssize_t n;
    while ((n = ::read(fds[0], buf, sizeof(buf))) > 0) {
        r.output.append(buf, static_cast<size_t>(n));
    }
    ::close(fds[0]);

    int status = 0;
    while (::waitpid(pid, &status, 0) < 0) {
        if (errno != EINTR) break;
    }
    if (WIFEXITED(status)) {
        r.exit_code = WEXITSTATUS(status);
    } else if (WIFSIGNALED(status)) {
        r.signaled = true;
        r.exit_code = 128 + WTERMSIG(status);
    }
    return r;
}

// ---------------------------------------------------------------------------
// Temp-dir helpers
// ---------------------------------------------------------------------------

// Create a fresh unique directory under the system temp root and return it.
std::string make_temp_dir(const std::string& tag) {
    static std::atomic<unsigned> counter{0};
    fs::path base = fs::temp_directory_path() / "rc-integration";
    fs::create_directories(base);
    fs::path dir = base / (tag + "-" + std::to_string(::getpid()) + "-" +
                           std::to_string(counter.fetch_add(1)));
    fs::create_directories(dir);
    return dir.string();
}

// A minimal controlled base environment for a sandboxed run. PATH lets the
// sandbox resolve bare command names (sh, cat); HOME is the *real* home the
// guard must hide. Callers extend/override as needed.
std::map<std::string, std::string> base_env(const std::string& real_home) {
    return {
        {"PATH", "/usr/bin:/bin"},
        {"TERM", "xterm"},
        {"HOME", real_home},
    };
}

// Read a whole file into a string (empty string if unreadable).
std::string read_file(const std::string& path) {
    std::ifstream ifs(path, std::ios::binary);
    if (!ifs) return {};
    std::ostringstream ss;
    ss << ifs.rdbuf();
    return ss.str();
}

// Extract the comma-separated NAME list following a "Label:" line in the audit
// text, e.g. line "Env set:      A, B, C" -> {"A","B","C"}. Returns empty if the
// label is not found.
std::vector<std::string> audit_name_list(const std::string& audit,
                                         const std::string& label) {
    std::vector<std::string> out;
    std::size_t pos = audit.find(label);
    if (pos == std::string::npos) return out;
    std::size_t eol = audit.find('\n', pos);
    std::string line = audit.substr(pos + label.size(),
                                    (eol == std::string::npos) ? std::string::npos
                                                               : eol - (pos + label.size()));
    std::istringstream ss(line);
    std::string tok;
    while (std::getline(ss, tok, ',')) {
        // trim spaces
        std::size_t b = tok.find_first_not_of(" \t");
        std::size_t e = tok.find_last_not_of(" \t");
        if (b == std::string::npos) continue;
        out.push_back(tok.substr(b, e - b + 1));
    }
    return out;
}

// GTEST_SKIP boilerplate condensed into a macro used at the top of each test.
#define SKIP_UNLESS_SANDBOXABLE(binvar)                       \
    std::string binvar;                                       \
    do {                                                      \
        std::string why;                                      \
        if (!have_prereqs(binvar, why)) GTEST_SKIP() << why;  \
    } while (0)

}  // namespace

// ---------------------------------------------------------------------------
// 1. Secrets hidden; locale defaults + fake HOME present
// ---------------------------------------------------------------------------

TEST(Integration, SecretsAreScrubbedButLocaleAndFakeHomeSurvive) {
    SKIP_UNLESS_SANDBOXABLE(bin);

    std::string real_home = make_temp_dir("realhome");
    std::string cwd = make_temp_dir("cwd");

    auto env = base_env(real_home);
    env["OPENAI_API_KEY"] = "leakme";
    env["AWS_SECRET_ACCESS_KEY"] = "xyz";

    RunResult r = run_proc(bin, {"--", "/usr/bin/env"}, env, cwd);
    ASSERT_TRUE(r.spawn_ok);
    EXPECT_EQ(r.exit_code, 0) << r.output;

    // Secret VALUES must not leak into the child environment.
    EXPECT_EQ(r.output.find("leakme"), std::string::npos) << r.output;
    EXPECT_EQ(r.output.find("xyz"), std::string::npos) << r.output;

    // Synthetic locale/timezone defaults DO reach the child.
    EXPECT_NE(r.output.find("TZ=UTC"), std::string::npos) << r.output;
    EXPECT_NE(r.output.find("LANG=en_US.UTF-8"), std::string::npos) << r.output;

    // HOME is remapped to a sandbox path, never the real home.
    EXPECT_NE(r.output.find("HOME="), std::string::npos) << r.output;
    EXPECT_NE(r.output.find("/home/user"), std::string::npos) << r.output;
    EXPECT_EQ(r.output.find("HOME=" + real_home), std::string::npos) << r.output;
}

// ---------------------------------------------------------------------------
// 2. Real HOME hidden: fake home is near-empty; ~/.ssh is not reachable
// ---------------------------------------------------------------------------

TEST(Integration, FakeHomeIsEmptyAndRealHomeIsHidden) {
    SKIP_UNLESS_SANDBOXABLE(bin);

    std::string real_home = make_temp_dir("realhome");
    // Plant a sensitive dir in the real home that must NOT be visible inside.
    fs::create_directories(fs::path(real_home) / ".ssh");
    std::ofstream(fs::path(real_home) / ".ssh" / "id_rsa") << "PRIVATE-KEY-BODY\n";

    std::string cwd = make_temp_dir("cwd");
    auto env = base_env(real_home);

    // (a) fake HOME is nearly empty: `ls -a $HOME | wc -l` ~ 2 (just . and ..).
    {
        RunResult r =
            run_proc(bin, {"--", "sh", "-c", "ls -a \"$HOME\" | wc -l"}, env, cwd);
        ASSERT_TRUE(r.spawn_ok);
        EXPECT_EQ(r.exit_code, 0) << r.output;
        int count = std::atoi(r.output.c_str());
        EXPECT_GE(count, 1) << r.output;
        EXPECT_LE(count, 3) << r.output;  // near-empty, not the real home
    }

    // (b) the real home's .ssh is not accessible from inside the sandbox.
    {
        std::string probe =
            "if [ -e \"" + real_home + "/.ssh\" ]; then echo SSH_VISIBLE; "
            "else echo SSH_HIDDEN; fi";
        RunResult r = run_proc(bin, {"--", "sh", "-c", probe}, env, cwd);
        ASSERT_TRUE(r.spawn_ok);
        EXPECT_EQ(r.exit_code, 0) << r.output;
        EXPECT_NE(r.output.find("SSH_HIDDEN"), std::string::npos) << r.output;
        EXPECT_EQ(r.output.find("SSH_VISIBLE"), std::string::npos) << r.output;
        EXPECT_EQ(r.output.find("PRIVATE-KEY-BODY"), std::string::npos) << r.output;
    }
}

// ---------------------------------------------------------------------------
// 3. Normal mode mounts the cwd; strict mode denies it
// ---------------------------------------------------------------------------

TEST(Integration, NormalReadsCwdFileButStrictDeniesIt) {
    SKIP_UNLESS_SANDBOXABLE(bin);

    std::string real_home = make_temp_dir("realhome");
    std::string cwd = make_temp_dir("cwd");
    std::ofstream(fs::path(cwd) / "file.txt") << "greetings\n";
    auto env = base_env(real_home);

    // Normal mode: cwd is auto-mounted read-write, so cat succeeds.
    {
        RunResult r = run_proc(bin, {"--", "cat", "file.txt"}, env, cwd);
        ASSERT_TRUE(r.spawn_ok);
        EXPECT_EQ(r.exit_code, 0) << r.output;
        EXPECT_NE(r.output.find("greetings"), std::string::npos) << r.output;
    }

    // Strict mode: cwd is NOT mounted, workdir falls back to the fake home, so
    // the relative file cannot be read and cat fails.
    {
        RunResult r = run_proc(bin, {"--strict", "--", "cat", "file.txt"}, env, cwd);
        ASSERT_TRUE(r.spawn_ok);
        EXPECT_NE(r.exit_code, 0) << r.output;
        EXPECT_EQ(r.output.find("greetings"), std::string::npos) << r.output;
    }
}

// ---------------------------------------------------------------------------
// 4. Audit log is created, records mode/network, and contains no secret value
// ---------------------------------------------------------------------------

TEST(Integration, AuditLogWrittenWithoutSecretValues) {
    SKIP_UNLESS_SANDBOXABLE(bin);

    std::string real_home = make_temp_dir("realhome");
    std::string cwd = make_temp_dir("cwd");
    auto env = base_env(real_home);
    env["OPENAI_API_KEY"] = "leakme";

    RunResult r = run_proc(bin, {"--", "/usr/bin/env"}, env, cwd);
    ASSERT_TRUE(r.spawn_ok);
    EXPECT_EQ(r.exit_code, 0) << r.output;

    std::string audit_path = (fs::path(cwd) / ".raincoat" / "audit.log").string();
    ASSERT_TRUE(fs::exists(audit_path)) << "expected audit log at " << audit_path;

    std::string audit = read_file(audit_path);
    EXPECT_NE(audit.find("Mode:"), std::string::npos) << audit;
    EXPECT_NE(audit.find("Network:"), std::string::npos) << audit;
    // The secret VALUE must never be persisted to the audit log.
    EXPECT_EQ(audit.find("leakme"), std::string::npos) << audit;
}

// ---------------------------------------------------------------------------
// 5. Missing command prints the exact error and exits nonzero
// ---------------------------------------------------------------------------

TEST(Integration, MissingCommandErrorsOut) {
    SKIP_UNLESS_SANDBOXABLE(bin);

    std::string real_home = make_temp_dir("realhome");
    std::string cwd = make_temp_dir("cwd");
    auto env = base_env(real_home);

    // The exact SPEC message emitted by cli::parse_cli for an empty command.
    const std::string kExpected =
        "Error: no command provided.\n\nUsage:\n  raincoat -- <command> [args...]";

    RunResult r = run_proc(bin, {"--"}, env, cwd);
    ASSERT_TRUE(r.spawn_ok);
    EXPECT_NE(r.exit_code, 0) << r.output;
    EXPECT_NE(r.output.find(kExpected), std::string::npos) << r.output;
}

// ---------------------------------------------------------------------------
// 6. doctor exits 0 when bwrap is present (which the guard guarantees)
// ---------------------------------------------------------------------------

TEST(Integration, DoctorSucceedsWhenBwrapPresent) {
    SKIP_UNLESS_SANDBOXABLE(bin);

    std::string real_home = make_temp_dir("realhome");
    std::string cwd = make_temp_dir("cwd");
    auto env = base_env(real_home);

    RunResult r = run_proc(bin, {"doctor"}, env, cwd);
    ASSERT_TRUE(r.spawn_ok);
    EXPECT_EQ(r.exit_code, 0) << r.output;
}

// ---------------------------------------------------------------------------
// 7. --net off: process still runs and the audit records network = off
// ---------------------------------------------------------------------------

TEST(Integration, NetOffRunsAndIsAudited) {
    SKIP_UNLESS_SANDBOXABLE(bin);

    std::string real_home = make_temp_dir("realhome");
    std::string cwd = make_temp_dir("cwd");
    auto env = base_env(real_home);

    // Robust + non-flaky: we do not depend on real internet. We prove the process
    // still runs under network isolation and that the audit records mode "off".
    RunResult r =
        run_proc(bin, {"--net", "off", "--", "sh", "-c", "echo ran"}, env, cwd);
    ASSERT_TRUE(r.spawn_ok);
    EXPECT_EQ(r.exit_code, 0) << r.output;
    EXPECT_NE(r.output.find("ran"), std::string::npos) << r.output;

    std::string audit_path = (fs::path(cwd) / ".raincoat" / "audit.log").string();
    ASSERT_TRUE(fs::exists(audit_path)) << audit_path;
    std::string audit = read_file(audit_path);
    EXPECT_NE(audit.find("Network:      off"), std::string::npos) << audit;
}

// ---------------------------------------------------------------------------
// 8. BUG: the audit log must classify each env var in exactly ONE category.
//
// resolve_env partitions the environment into allowed / set / scrubbed. The
// runner then remaps HOME (and TMPDIR, and any pre-existing fontconfig vars) to
// synthetic sandbox values and records them as "set" — but it never removes them
// from the "scrubbed" list that resolve_env already populated (because they were
// present in the parent but absent from resolved at that point). Result: HOME and
// TMPDIR appear in BOTH "Env set:" and "Env scrubbed:" in every audit log.
//
// This is a real correctness defect in the tool's core security-transparency
// artifact: per SPEC "scrubbed = present in parent but deliberately dropped", yet
// HOME was NOT dropped — it was remapped to the fake home. A reviewer reading the
// audit sees mutually contradictory facts about HOME on every single run.
TEST(Integration, AuditEnvCategoriesAreDisjoint) {
    SKIP_UNLESS_SANDBOXABLE(bin);

    std::string real_home = make_temp_dir("realhome");
    std::string cwd = make_temp_dir("cwd");
    auto env = base_env(real_home);  // HOME is present in the parent env

    RunResult r = run_proc(bin, {"--", "sh", "-c", "true"}, env, cwd);
    ASSERT_TRUE(r.spawn_ok);
    EXPECT_EQ(r.exit_code, 0) << r.output;

    std::string audit_path = (fs::path(cwd) / ".raincoat" / "audit.log").string();
    ASSERT_TRUE(fs::exists(audit_path)) << audit_path;
    std::string audit = read_file(audit_path);

    std::vector<std::string> set_names = audit_name_list(audit, "Env set:");
    std::vector<std::string> scrubbed_names = audit_name_list(audit, "Env scrubbed:");

    auto in = [](const std::vector<std::string>& v, const std::string& n) {
        return std::find(v.begin(), v.end(), n) != v.end();
    };

    // HOME is always remapped to the fake home, so it belongs to "set" and must
    // NOT simultaneously be reported as "scrubbed".
    EXPECT_TRUE(in(set_names, "HOME")) << audit;
    EXPECT_FALSE(in(scrubbed_names, "HOME"))
        << "HOME is listed as BOTH set and scrubbed in the audit log:\n"
        << audit;

    // More generally, no name may appear in both categories.
    for (const auto& n : set_names) {
        EXPECT_FALSE(in(scrubbed_names, n))
            << "env var '" << n << "' appears in both Env set and Env scrubbed:\n"
            << audit;
    }
}

// ---------------------------------------------------------------------------
// 9. BUG (user-facing consequence): `raincoat report` over-counts scrubbed vars.
//
// Same root cause as test #8, but observed through the SPEC-headline feature:
// report prints "scrubbed N sensitive environment variables" using the audit's
// "Env scrubbed" list. Because the remapped HOME and (parent-provided) TMPDIR are
// wrongly included in that list, report inflates the count. Here exactly ONE
// variable (SECRET_TOKEN) is genuinely dropped, yet HOME + TMPDIR are counted too,
// so report claims "3" instead of "1".
TEST(Integration, ReportDoesNotOverCountRemappedVarsAsScrubbed) {
    SKIP_UNLESS_SANDBOXABLE(bin);

    std::string real_home = make_temp_dir("realhome");
    std::string parent_tmp = make_temp_dir("parenttmp");
    std::string cwd = make_temp_dir("cwd");

    auto env = base_env(real_home);  // PATH, TERM (allowed) + HOME (remapped)
    env["TMPDIR"] = parent_tmp;      // parent-provided TMPDIR: remapped, not dropped
    env["SECRET_TOKEN"] = "sekret";  // the ONLY variable actually scrubbed

    RunResult r = run_proc(bin, {"--", "sh", "-c", "true"}, env, cwd);
    ASSERT_TRUE(r.spawn_ok);
    EXPECT_EQ(r.exit_code, 0) << r.output;

    std::string audit_path = (fs::path(cwd) / ".raincoat" / "audit.log").string();
    ASSERT_TRUE(fs::exists(audit_path)) << audit_path;

    std::string audit = read_file(audit_path);
    std::vector<std::string> scrubbed = audit_name_list(audit, "Env scrubbed:");
    // Only SECRET_TOKEN was genuinely dropped; HOME/TMPDIR were remapped.
    EXPECT_EQ(scrubbed.size(), 1u)
        << "expected only SECRET_TOKEN scrubbed, got: " << audit;

    RunResult rep = run_proc(bin, {"report", audit_path}, env, cwd);
    ASSERT_TRUE(rep.spawn_ok);
    EXPECT_EQ(rep.exit_code, 0) << rep.output;
    // The playful headline must reflect the true count (1), singular phrasing.
    EXPECT_NE(rep.output.find("1 sensitive environment variable was"),
              std::string::npos)
        << "report over-counts remapped HOME/TMPDIR as scrubbed secrets:\n"
        << rep.output;
}

// ---------------------------------------------------------------------------
// 10. BUG: the audit's Timezone/Locale lines must reflect the value the child
//     ACTUALLY received, honoring `--set-env` (SPEC: "--set-env wins").
//
// SPEC mandates the audit log record "Timezone" and "Locale", and separately
// mandates that `--set-env KEY=VALUE` overrides everything for KEY. When a user
// runs `--set-env TZ=Asia/Tokyo --set-env LANG=fr_FR.UTF-8`, resolve_env correctly
// hands the child TZ=Asia/Tokyo / LANG=fr_FR.UTF-8 (proven below by reading the
// child's own environment). But the runner builds the AuditRecord's timezone/locale
// from cfg.env_defaults (runner.cpp: rec.timezone = default_or_empty(cfg.env_defaults,
// "TZ")) — which still holds the injected generic defaults UTC / en_US.UTF-8 because
// --set-env values live in a separate set_env vector, never in env_defaults. So the
// audit — the tool's security-transparency artifact — misreports the timezone and
// locale the sandboxed command was actually given on every run that overrides them.
TEST(Integration, AuditTimezoneAndLocaleReflectSetEnvOverride) {
    SKIP_UNLESS_SANDBOXABLE(bin);

    std::string real_home = make_temp_dir("realhome");
    std::string cwd = make_temp_dir("cwd");
    auto env = base_env(real_home);

    // Read the single value following a "<label>" prefix in the audit text.
    auto audit_line_value = [](const std::string& audit,
                               const std::string& label) -> std::string {
        std::size_t pos = audit.find(label);
        if (pos == std::string::npos) return {};
        std::size_t start = pos + label.size();
        std::size_t eol = audit.find('\n', start);
        std::string v = audit.substr(
            start, eol == std::string::npos ? std::string::npos : eol - start);
        std::size_t b = v.find_first_not_of(" \t");
        std::size_t e = v.find_last_not_of(" \t");
        if (b == std::string::npos) return {};
        return v.substr(b, e - b + 1);
    };

    RunResult r = run_proc(
        bin,
        {"--set-env", "TZ=Asia/Tokyo", "--set-env", "LANG=fr_FR.UTF-8", "--",
         "/usr/bin/env"},
        env, cwd);
    ASSERT_TRUE(r.spawn_ok);
    EXPECT_EQ(r.exit_code, 0) << r.output;

    // Ground truth: the child really did receive the overridden values.
    EXPECT_NE(r.output.find("TZ=Asia/Tokyo"), std::string::npos) << r.output;
    EXPECT_NE(r.output.find("LANG=fr_FR.UTF-8"), std::string::npos) << r.output;

    std::string audit_path = (fs::path(cwd) / ".raincoat" / "audit.log").string();
    ASSERT_TRUE(fs::exists(audit_path)) << audit_path;
    std::string audit = read_file(audit_path);

    // The audit must report the SAME timezone/locale the child got, not the
    // generic UTC / en_US.UTF-8 defaults that --set-env overrode.
    EXPECT_EQ(audit_line_value(audit, "Timezone:"), "Asia/Tokyo")
        << "audit misreports the timezone the child actually received:\n"
        << audit;
    EXPECT_EQ(audit_line_value(audit, "Locale:"), "fr_FR.UTF-8")
        << "audit misreports the locale the child actually received:\n"
        << audit;
}

// ---------------------------------------------------------------------------
// BUG: `--allow-env HOME` makes the audit classify HOME as BOTH allowed AND set,
// and (falsely) claims the real HOME was passed to the tool verbatim.
//
// resolve_env sees `--allow-env HOME` while HOME is present in the parent, so it
// copies HOME into env.resolved and files the NAME under "allowed" (SPEC: allowed
// == "copied verbatim from parent"). The runner then unconditionally overrides
// env.resolved["HOME"] with the *fake* sandbox home and calls record_set("HOME"),
// which promotes HOME into "set" and drops it from "scrubbed" — but it never
// removes HOME from the "allowed" list. Result on every `--allow-env HOME` run:
//   * HOME appears in BOTH "Env allowed:" and "Env set:" (SPEC requires the three
//     categories be disjoint), and
//   * the audit asserts HOME was "allowed", i.e. the tool received the real home
//     path verbatim — which is FALSE (it received the fake sandbox home).
//
// The child env is still safe (HOME resolves to the fake home; no value leaks),
// so this is an audit-integrity / privacy-transparency defect: the security
// artifact makes a contradictory and misleading claim about the one variable a
// privacy reviewer cares most about. TMPDIR and any pre-existing fontconfig vars
// share the identical failure mode (record_set scrubs only the "scrubbed" list).
TEST(Integration, AuditAllowedAndSetAreDisjointWhenHomeIsAllowEnv) {
    SKIP_UNLESS_SANDBOXABLE(bin);

    std::string real_home = make_temp_dir("realhome");
    std::string cwd = make_temp_dir("cwd");
    auto env = base_env(real_home);  // HOME present in the parent env

    // User explicitly tries to allow HOME through; the runner must still remap it
    // to the fake home and must NOT report it as verbatim-passed ("allowed").
    RunResult r =
        run_proc(bin, {"--allow-env", "HOME", "--", "/usr/bin/env"}, env, cwd);
    ASSERT_TRUE(r.spawn_ok);
    EXPECT_EQ(r.exit_code, 0) << r.output;

    // Privacy sanity: the child must NOT receive the real home path as HOME.
    EXPECT_EQ(r.output.find("HOME=" + real_home), std::string::npos) << r.output;

    std::string audit_path = (fs::path(cwd) / ".raincoat" / "audit.log").string();
    ASSERT_TRUE(fs::exists(audit_path)) << audit_path;
    std::string audit = read_file(audit_path);

    std::vector<std::string> allowed_names = audit_name_list(audit, "Env allowed:");
    std::vector<std::string> set_names = audit_name_list(audit, "Env set:");

    auto in = [](const std::vector<std::string>& v, const std::string& n) {
        return std::find(v.begin(), v.end(), n) != v.end();
    };

    // HOME was remapped to the fake home, so it belongs to "set" and must NOT be
    // reported as "allowed" (verbatim from parent) at the same time.
    EXPECT_TRUE(in(set_names, "HOME")) << audit;
    EXPECT_FALSE(in(allowed_names, "HOME"))
        << "HOME is listed as BOTH allowed and set; the audit falsely claims the "
           "real HOME was passed to the tool verbatim:\n"
        << audit;

    // No name may appear in both the allowed and set categories.
    for (const auto& n : set_names) {
        EXPECT_FALSE(in(allowed_names, n))
            << "env var '" << n << "' appears in both Env allowed and Env set:\n"
            << audit;
    }
}

// ---------------------------------------------------------------------------
// 11. BUG: a RELATIVE --workdir that exists inside a mounted path is accepted by
//     the mounted-check but then handed to bwrap verbatim, so the run fails.
//
// runner.cpp resolves cfg.workdir to an absolute canonical path (workdir_canon)
// ONLY to decide whether it lands inside a mount. It correctly finds that a
// relative `--workdir sub` (which canonicalizes to <cwd>/sub, inside the
// auto-mounted cwd) IS mounted — so it takes the "mounted" branch and does NOT
// fall back to the fake home. But it then sets `effective_workdir = cfg.workdir`,
// i.e. the RAW, still-relative string "sub", and passes it to `bwrap --chdir`.
// Inside the sandbox bwrap starts at "/", so a relative chdir target does not
// exist and bwrap aborts with "Can't chdir to sub", exit 1 — even though the
// directory is mounted and fully reachable at its absolute path. effective_workdir
// should be workdir_canon (the absolute path the mount is keyed on), not the raw
// user spelling. SPEC lists `--workdir <path>` with no absolute-path requirement,
// so a relative workdir is a legitimate input that silently breaks every run.
TEST(Integration, RelativeWorkdirInsideMountIsHonored) {
    SKIP_UNLESS_SANDBOXABLE(bin);

    std::string real_home = make_temp_dir("realhome");
    std::string cwd = make_temp_dir("cwd");
    fs::create_directories(fs::path(cwd) / "sub");
    // A marker file so we can prove pwd really landed in <cwd>/sub.
    std::ofstream(fs::path(cwd) / "sub" / "here.txt") << "x\n";
    auto env = base_env(real_home);

    // Relative --workdir naming a real subdir of the (auto-mounted) cwd.
    RunResult r = run_proc(bin, {"--workdir", "sub", "--", "/bin/pwd"}, env, cwd);
    ASSERT_TRUE(r.spawn_ok);

    // The directory is mounted (identity) and reachable at its absolute path, so
    // the run must succeed and pwd must report the sub directory.
    EXPECT_EQ(r.exit_code, 0)
        << "relative --workdir inside a mounted path should chdir successfully, "
           "but the raw relative string was passed to bwrap --chdir:\n"
        << r.output;
    EXPECT_EQ(r.output.find("Can't chdir"), std::string::npos) << r.output;
    EXPECT_NE(r.output.find("/sub"), std::string::npos) << r.output;
}

// ---------------------------------------------------------------------------
// 12. BUG: `--allow-env USER` re-exposes the REAL parent username inside the
//     sandbox, defeating the tool's own "never leak the real username" guard.
//
// env_guard forces USER to the generic value "user" in step 3 ("USER forced to a
// generic value (never leak the real username)"), and the unit tests assert that
// "the real username must never appear as a value anywhere in resolved"
// (test_env_guard.cpp:225-228). But step 5 (`--allow-env`) runs AFTER the force
// and copies USER VERBATIM from the parent, silently overriding the anonymized
// value with the real login name. Compare with HOME, which the runner hard-
// overrides to the fake home AFTER resolve_env (env.resolved["HOME"] = fake_home)
// precisely so that `--allow-env HOME` cannot leak the real path — USER gets no
// such protection.
//
// This is a real privacy hole, not merely a user opt-in: `--allow-env` is
// documented as "copies NAME from parent env if present", and a shared profile
// may list USER in allow_env for unrelated reasons (some tools want $USER set).
// The safe design intent is that USER only ever carries a SYNTHETIC value —
// `--set-env USER=ci` (a value the user supplies) is fine, but the parent's REAL
// username must never reach the child. This test plants a distinctive real
// username and asserts it does not appear inside the sandbox; it currently FAILS
// because the child sees USER=<real login name>.
TEST(Integration, AllowEnvUserDoesNotLeakRealUsername) {
    SKIP_UNLESS_SANDBOXABLE(bin);

    std::string real_home = make_temp_dir("realhome");
    std::string cwd = make_temp_dir("cwd");
    auto env = base_env(real_home);
    const std::string secret_user = "topsecretlogin42";
    env["USER"] = secret_user;
    env["LOGNAME"] = secret_user;

    // User (or a profile) allows USER through. The generic-USER guard must still
    // win: the child must never receive the real login name.
    RunResult r =
        run_proc(bin, {"--allow-env", "USER", "--", "/usr/bin/env"}, env, cwd);
    ASSERT_TRUE(r.spawn_ok);
    EXPECT_EQ(r.exit_code, 0) << r.output;

    // The real username must not appear anywhere in the child environment.
    EXPECT_EQ(r.output.find(secret_user), std::string::npos)
        << "--allow-env USER leaked the real login name into the sandbox, "
           "defeating the generic-USER privacy guard:\n"
        << r.output;
    // And USER should still be the anonymized value.
    EXPECT_NE(r.output.find("USER=user"), std::string::npos) << r.output;
}
