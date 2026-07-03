// Attack round 2 (isolation+leak): the real egress upstream must not leak to the
// child through an audit log that lands in a READ-ONLY mounted path.
//
// Round 1 added a forced-redaction guard: when the audit log is child-reachable and
// [egress].redact_upstreams_in_audit=false, raincoat FORCES upstream redaction so the
// child cannot read the real upstream out of the on-disk audit "start" block (written
// before the fork). But that guard keyed on the audit dir being child-WRITABLE
// (audit_dir_child_writable), which only classifies READ-WRITE mounts.
//
// The leak: point --audit-log into a directory exposed to the child with a READ-ONLY
// mount (--allow-read <dir>). The child cannot WRITE it (so the tamper guard stays
// silent, correctly) but it CAN READ it — and with redact_upstreams_in_audit=false the
// un-redacted upstream sits right there in the file. Redaction must be forced for a
// child-READABLE audit, not merely a child-writable one.
//
// No forwarding is exercised: the upstream token is a non-routable sentinel; the leak
// under test is READING the on-disk audit, not a request.
#include <gtest/gtest.h>

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

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include "config.hpp"
#include "fs_guard.hpp"

namespace {

namespace fs = std::filesystem;

std::string raincoat_bin() {
    const char* e = std::getenv("RAINCOAT_BIN");
    if (e && *e) return std::string(e);
    return "/home/zach/Develop/Raincoat/build/raincoat";
}

constexpr const char* kBwrapPath = "/usr/bin/bwrap";
constexpr const char* kPython = "/usr/bin/python3";

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
    if (::access(kPython, X_OK) != 0) {
        why = std::string("python3 not found/executable at ") + kPython;
        return false;
    }
    return true;
}

#define SKIP_UNLESS_SANDBOXABLE(binvar)                       \
    std::string binvar;                                       \
    do {                                                      \
        std::string why;                                      \
        if (!have_prereqs(binvar, why)) GTEST_SKIP() << why;  \
    } while (0)

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
    while (::waitpid(pid, &status, 0) < 0)
        if (errno != EINTR) break;
    if (WIFEXITED(status)) r.exit_code = WEXITSTATUS(status);
    else if (WIFSIGNALED(status)) r.exit_code = 128 + WTERMSIG(status);
    return r;
}

std::string make_temp_dir(const std::string& tag) {
    static std::atomic<unsigned> counter{0};
    fs::path base = fs::temp_directory_path() / "rc-egress-ro-audit";
    fs::create_directories(base);
    fs::path dir = base / (tag + "-" + std::to_string(::getpid()) + "-" +
                           std::to_string(counter.fetch_add(1)));
    fs::create_directories(dir);
    return dir.string();
}

std::string read_file(const std::string& path) {
    std::ifstream ifs(path, std::ios::binary);
    if (!ifs) return {};
    std::ostringstream ss;
    ss << ifs.rdbuf();
    return ss.str();
}

int pick_free_port() {
    int s = ::socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) return -1;
    int one = 1;
    ::setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = 0;
    if (::bind(s, reinterpret_cast<sockaddr*>(&a), sizeof(a)) != 0) {
        ::close(s);
        return -1;
    }
    socklen_t len = sizeof(a);
    if (::getsockname(s, reinterpret_cast<sockaddr*>(&a), &len) != 0) {
        ::close(s);
        return -1;
    }
    int port = ntohs(a.sin_port);
    ::close(s);
    return port;
}

}  // namespace

// Unit-level pin of the defect (no bwrap needed): a READ-ONLY mount that covers the
// audit dir must count as child-READABLE (so egress redaction is forced) even though it
// is NOT child-writable (so the tamper warning correctly stays silent). Before the fix
// only `audit_dir_child_writable` existed and it ignored read-only mounts, so the runner
// had no signal that a read-only-mounted audit is still readable by the child.
TEST(EgressAuditReadOnlyLeak, ReadOnlyMountMakesAuditChildReadableNotWritable) {
    using raincoat::Mount;
    using raincoat::MountMode;

    const std::string data = "/some/exposed/data";
    const std::string audit_log = data + "/audit.log";

    std::vector<Mount> ro;
    ro.push_back(Mount{data, data, MountMode::ReadOnly});

    // Read-only mount: child can READ the audit dir but cannot WRITE it.
    EXPECT_TRUE(raincoat::audit_dir_child_readable(audit_log, ro))
        << "a read-only mount covering the audit dir must be child-readable";
    EXPECT_FALSE(raincoat::audit_dir_child_writable(audit_log, ro))
        << "a read-only mount is not child-writable";

    // Read-write mount: both hold.
    std::vector<Mount> rw;
    rw.push_back(Mount{data, data, MountMode::ReadWrite});
    EXPECT_TRUE(raincoat::audit_dir_child_readable(audit_log, rw));
    EXPECT_TRUE(raincoat::audit_dir_child_writable(audit_log, rw));

    // No covering mount: neither holds.
    std::vector<Mount> none;
    none.push_back(Mount{"/unrelated", "/unrelated", MountMode::ReadOnly});
    EXPECT_FALSE(raincoat::audit_dir_child_readable(audit_log, none));
    EXPECT_FALSE(raincoat::audit_dir_child_writable(audit_log, none));
}

// A --audit-log inside a READ-ONLY mounted directory is child-READABLE. With
// [egress].redact_upstreams_in_audit=false the un-redacted upstream would otherwise sit
// in the on-disk audit "start" block (written before the fork) and be readable by the
// child. Raincoat must FORCE upstream redaction for a child-READABLE audit — not only a
// child-writable one — and the real upstream token must be absent from the on-disk file.
TEST(EgressAuditReadOnlyLeak, ReadOnlyMountedAuditForcesUpstreamRedaction) {
    SKIP_UNLESS_SANDBOXABLE(bin);

    const std::string kUpstreamToken = "SECRET-UPSTREAM-RO-AUDIT-Q9X7.invalid";
    const std::string upstream_url = "http://" + kUpstreamToken + ":9443";

    const int cport = pick_free_port();
    ASSERT_GT(cport, 0);
    const std::string child_url = "http://127.0.0.1:" + std::to_string(cport);

    // Profile OUTSIDE any mounted path (so the profile-leak guard does not itself mask it
    // or refuse the run) with audit redaction EXPLICITLY disabled.
    std::string profile_dir = make_temp_dir("profile");
    std::string profile_path = (fs::path(profile_dir) / "egress.toml").string();
    {
        std::ofstream p(profile_path);
        p << "[egress]\n"
          << "mode = \"bridge\"\n"
          << "hide_upstreams_from_child = true\n"
          << "redact_upstreams_in_audit = false\n"
          << "\n"
          << "[[egress.bridge]]\n"
          << "name = \"local-api\"\n"
          << "env = \"MY_BASE_URL\"\n"
          << "child_endpoint = \"" << child_url << "\"\n"
          << "upstream_endpoint = \"" << upstream_url << "\"\n";
    }
    ASSERT_TRUE(fs::exists(profile_path));

    // A data dir exposed to the child READ-ONLY, with --audit-log pointed inside it.
    std::string data_dir = make_temp_dir("rodata");
    std::string audit_path = (fs::path(data_dir) / "audit.log").string();

    std::string real_home = make_temp_dir("home");
    std::string cwd = make_temp_dir("cwd");
    std::map<std::string, std::string> env = {
        {"PATH", "/usr/bin:/bin"}, {"TERM", "xterm"}, {"HOME", real_home}};

    // Child reads the audit file (visible via the read-only mount) and self-reports
    // whether the upstream token is present. The needle is assembled from fragments so
    // the child's OWN argv (which raincoat records verbatim in the audit "Command:" line)
    // never contains the contiguous token — otherwise the child would find its own source
    // echoed into the audit and false-positive.
    const std::string py =
        "needle = 'SECRET' + '-UPSTREAM-RO-AUDIT-' + 'Q9X7'\n"
        "d = open('" + audit_path + "').read()\n"
        "print('CHILD_AUDIT_LEN=%d' % len(d))\n"
        "print('CHILD_SAW_UPSTREAM=' + ('yes' if needle in d else 'no'))\n";

    RunResult r = run_proc(
        bin,
        {"--profile", profile_path, "--allow-read", data_dir, "--audit-log", audit_path,
         "--", kPython, "-c", py},
        env, cwd);
    ASSERT_TRUE(r.spawn_ok);

    ASSERT_TRUE(fs::exists(audit_path))
        << "expected audit log at " << audit_path << "\nOutput:\n" << r.output;
    std::string audit = read_file(audit_path);

    // Core invariant: the on-disk, child-readable audit must NOT carry the real upstream.
    EXPECT_EQ(audit.find(kUpstreamToken), std::string::npos)
        << "read-only-mounted (child-readable) audit leaked the real upstream despite the "
           "forced-redaction guard. Audit:\n"
        << audit;
    EXPECT_NE(audit.find("Upstream endpoint: hidden"), std::string::npos)
        << "expected forced 'Upstream endpoint: hidden' in a child-readable audit. Audit:\n"
        << audit;

    // The child's own view confirms it: it read the audit but did not see the upstream.
    EXPECT_NE(r.output.find("CHILD_SAW_UPSTREAM=no"), std::string::npos)
        << "child read the real upstream out of a read-only-mounted audit log. Output:\n"
        << r.output;
}
