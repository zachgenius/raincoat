// Attack round 3 — egress wiring: REGRESSION + HONESTY, remaining gaps.
//
// Rounds 1 & 2 pinned: (a) resolve_config's net decisions for the no-egress,
// zero-bridge, and active-bridge cases, and (b) end-to-end behavior of a flat
// --net off run, a zero-bridge fail-closed run, secret scrubbing, and the
// active-bridge "not a network jail" disclosure. This round attacks the CRACKS
// those left, at both the resolution/render layer (deterministic — always runs)
// and end-to-end against the real binary:
//
//   (A) HONESTY, self-consistency of the ACTIVE-bridge reconciled reserved note.
//       When a reserved top-level network mode ("bridge") coexists with a
//       genuinely active egress bridge, resolve_config REWRITES the reserved note
//       to the shared-host-net disclosure. That rewritten note (which is persisted
//       to the tamper-proof audit) must NOT still carry the stale fail-closed
//       language ("fails closed to off" / "egress is unrestricted") that the
//       inactive path uses — otherwise the audit contradicts its own "Network:
//       full" headline. (Guards runner.cpp's egress_active reconcile branch, which
//       no prior test checks for self-contradiction.)
//
//   (B) HONESTY, the EGRESS-ORIGINATED reserved mode under an explicit --net full.
//       A profile with [egress] mode="bridge" but ZERO bridges records the reserved
//       mode via the *egress* block (a different source than a top-level
//       network="bridge"). If the user then forces --net full, the child gets FULL
//       unrestricted network; the reconciled note must say so and must NOT swear
//       the network "fails closed to off". (test_reserved_net_honesty_attack covers
//       only the top-level-network source; this pins the egress-block source.)
//
//   (C) REGRESSION, the common no-egress path renders a CLEAN audit. A flat,
//       non-strict run must produce an audit that headlines "Network: full" and
//       contains NONE of the egress/shared-net/reserved noise — proving the egress
//       wiring never bleeds into ordinary runs.
//
//   (D) REGRESSION, audit stays TAMPER-PROOF under an ACTIVE egress bridge. The
//       default audit dir (cwd/.raincoat) is shadowed with a tmpfs inside the
//       sandbox, so a child that overwrites its audit.log cannot touch the real
//       host file. The post-run host audit must still carry the honest egress
//       disclosure AND the "finished" end block, and must never leak the upstream.
//       (Round 2 proved tamper-proofing for net-off; none proved it under egress.)
//
// (A)–(C) are deterministic and always run. (D) is guarded by GTEST_SKIP when
// bwrap / raincoat / python3 are missing.
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

#include <unistd.h>
#include <sys/wait.h>

#include "audit.hpp"
#include "config.hpp"
#include "runner.hpp"

using raincoat::AuditRecord;
using raincoat::CliInvocation;
using raincoat::Config;
using raincoat::EgressBridgeAudit;
using raincoat::format_audit_start;
using raincoat::NetMode;
using raincoat::Options;
using raincoat::resolve_config;
using raincoat::Subcommand;

namespace {

namespace fs = std::filesystem;

std::map<std::string, std::string> fake_parent_env() {
    return {{"PATH", "/usr/bin:/bin"}, {"HOME", "/home/tester"}};
}

CliInvocation run_inv(Options opt) {
    CliInvocation inv;
    inv.sub = Subcommand::Run;
    inv.options = std::move(opt);
    return inv;
}

std::string write_temp_profile(const std::string& content) {
    static std::atomic<unsigned> counter{0};
    fs::path dir = fs::temp_directory_path() / "rc-egress-attack3";
    fs::create_directories(dir);
    fs::path p = dir / ("profile-" + std::to_string(counter.fetch_add(1)) + ".toml");
    std::ofstream ofs(p, std::ios::binary | std::ios::trunc);
    ofs << content;
    ofs.close();
    return p.string();
}

const char kCwd[] = "/work/project";

bool any_note_contains(const std::vector<std::string>& notes, const std::string& needle) {
    for (const auto& n : notes)
        if (n.find(needle) != std::string::npos) return true;
    return false;
}

// Rebuild the AuditRecord for the fields run() actually persists for an egress run,
// so the render tests observe exactly what lands in the tamper-proof audit log.
AuditRecord audit_from(const Config& cfg,
                       const std::vector<EgressBridgeAudit>& bridges = {},
                       const std::vector<std::string>& policy_notes = {}) {
    AuditRecord rec;
    rec.net = cfg.net;
    rec.profile_name = cfg.ext.profile_name;
    rec.reserved_notes = cfg.ext.reserved_notes;
    rec.active_policy_notes = policy_notes;
    rec.egress_bridges = bridges;
    return rec;
}

// The exact shared-host-net active_policy_note run() appends for an active bridge.
const char kActiveEgressPolicyNote[] =
    "egress bridge active: the sandbox SHARES the host network namespace so the "
    "child can reach the loopback bridge; the child is NOT network-jailed (general "
    "host network remains reachable). The bridge only hides upstream URLs from the "
    "child's environment/config.";

}  // namespace

// ===========================================================================
// (A) The ACTIVE-bridge reconciled reserved note must not contradict itself.
// ===========================================================================
static const char kActiveBridgeReservedProfile[] =
    "network = \"bridge\"\n"          // reserved top-level mode...
    "[egress]\n"
    "mode = \"bridge\"\n"
    "[[egress.bridge]]\n"             // ...that IS backed by a live bridge
    "name = \"primary\"\n"
    "env = \"SOME_BASE_URL\"\n"
    "child_endpoint = \"http://127.0.0.1:18080\"\n"
    "upstream_endpoint = \"https://real-upstream.example.invalid\"\n";

TEST(EgressAttack3Honesty, ActiveBridgeReservedNoteIsSelfConsistent) {
    const std::string profile = write_temp_profile(kActiveBridgeReservedProfile);
    Options cli;
    cli.profile_path = profile;
    std::string err;
    Config cfg = resolve_config(run_inv(cli), fake_parent_env(), kCwd, err);

    ASSERT_TRUE(err.empty()) << err;
    ASSERT_TRUE(cfg.ext.egress.enabled);
    ASSERT_EQ(cfg.net, NetMode::Full);  // shared host net

    // The reconciled reserved note must disclose the ACTIVE, shared-net model...
    EXPECT_TRUE(any_note_contains(cfg.ext.reserved_notes, "ACTIVE"));
    EXPECT_TRUE(any_note_contains(cfg.ext.reserved_notes, "SHARES the host network namespace"));
    // ...and must NOT still carry the stale inactive-path fail-closed / unrestricted
    // language, which would flatly contradict the "Network: full, bridge active" state.
    for (const std::string& lie : {std::string("fails closed"),
                                   std::string("all networking blocked"),
                                   std::string("egress is unrestricted"),
                                   std::string("NOT applied")}) {
        EXPECT_FALSE(any_note_contains(cfg.ext.reserved_notes, lie))
            << "active-bridge reserved note carries stale inactive-path language: '"
            << lie << "'";
    }

    // Rendered, tamper-proof audit: "Network: full" must not coexist with any
    // fail-closed claim, and the real upstream host must never appear.
    EgressBridgeAudit ba;
    ba.name = "primary";
    ba.child_endpoint = "http://127.0.0.1:18080";
    ba.injected_env = "SOME_BASE_URL";
    ba.upstream_hidden = true;  // default redaction
    const std::string text =
        format_audit_start(audit_from(cfg, {ba}, {kActiveEgressPolicyNote}));

    ASSERT_NE(text.find("Network:      full"), std::string::npos) << text;
    EXPECT_EQ(text.find("fails closed"), std::string::npos)
        << "audit headlines Network: full for an ACTIVE bridge yet also claims the "
           "network fails closed — a self-contradictory security statement:\n"
        << text;
    EXPECT_NE(text.find("Upstream endpoint: hidden"), std::string::npos) << text;
    EXPECT_EQ(text.find("real-upstream.example.invalid"), std::string::npos)
        << "audit leaked the real upstream host:\n" << text;
}

// ===========================================================================
// (B) EGRESS-block reserved mode + explicit --net full must be honest.
// ===========================================================================
TEST(EgressAttack3Honesty, ZeroBridgeEgressReservedNoteHonestUnderNetFull) {
    // [egress] mode="bridge" with ZERO bridges records the reserved mode via the
    // EGRESS block (profile.cpp), a different source than a top-level network key.
    const std::string profile = write_temp_profile(
        "[egress]\n"
        "mode = \"bridge\"\n");
    Options cli;
    cli.profile_path = profile;
    cli.net = NetMode::Full;  // user overrides the fail-closed fallback
    std::string err;
    Config cfg = resolve_config(run_inv(cli), fake_parent_env(), kCwd, err);

    ASSERT_TRUE(err.empty()) << err;
    ASSERT_FALSE(cfg.ext.egress.enabled);         // never activated (no bridges)
    ASSERT_TRUE(cfg.ext.reserved_net_mode.has_value());
    ASSERT_EQ(cfg.net, NetMode::Full);            // override took effect

    // The note must NOT claim fail-closed-to-off (the child actually has FULL net),
    // and SHOULD disclose that the restriction was not applied / egress is unrestricted.
    EXPECT_FALSE(any_note_contains(cfg.ext.reserved_notes, "fails closed"))
        << "egress-originated reserved note claims fail-closed-to-off while cfg.net is "
           "full (unrestricted egress) — a false claim persisted to the audit";
    EXPECT_TRUE(any_note_contains(cfg.ext.reserved_notes, "unrestricted") ||
                any_note_contains(cfg.ext.reserved_notes, "NOT applied"))
        << "reserved note should disclose the egress restriction was not applied";

    const std::string text = format_audit_start(audit_from(cfg));
    ASSERT_NE(text.find("Network:      full"), std::string::npos) << text;
    EXPECT_EQ(text.find("fails closed"), std::string::npos)
        << "audit both headlines Network: full and swears fail-closed-to-off:\n" << text;
    // A non-activated bridge mode must never render an active-bridge section.
    EXPECT_EQ(text.find("Egress bridge enabled"), std::string::npos) << text;
}

// ===========================================================================
// (C) The flat, no-egress path renders a CLEAN audit (no egress noise).
// ===========================================================================
TEST(EgressAttack3Regression, FlatNonStrictAuditHasNoEgressNoise) {
    Options opt;  // flat, non-strict, no profile, no egress
    std::string err;
    Config cfg = resolve_config(run_inv(opt), fake_parent_env(), kCwd, err);

    ASSERT_TRUE(err.empty()) << err;
    EXPECT_EQ(cfg.net, NetMode::Full);
    EXPECT_FALSE(cfg.ext.egress.enabled);
    EXPECT_FALSE(cfg.ext.reserved_net_mode.has_value());
    EXPECT_TRUE(cfg.ext.reserved_notes.empty());

    // Rendered exactly as run() would for a flat run: no egress bridges, no policy
    // notes, no reserved notes.
    const std::string text = format_audit_start(audit_from(cfg));
    EXPECT_NE(text.find("Network:      full"), std::string::npos) << text;
    for (const std::string& noise : {std::string("Egress bridge enabled"),
                                     std::string("SHARES the host network namespace"),
                                     std::string("Reserved (configured"),
                                     std::string("fails closed"),
                                     std::string("network-jailed")}) {
        EXPECT_EQ(text.find(noise), std::string::npos)
            << "flat non-egress run leaked egress/shared-net noise into the audit: '"
            << noise << "'\n" << text;
    }
}

// ===========================================================================
// (D) End-to-end: audit stays tamper-proof under an ACTIVE egress bridge.
// ===========================================================================
namespace {

std::string raincoat_bin() {
    const char* e = std::getenv("RAINCOAT_BIN");
    if (e && *e) return std::string(e);
    return "/home/zach/Develop/Raincoat/build/raincoat";
}
constexpr const char* kBwrapPath = "/usr/bin/bwrap";
constexpr const char* kPython = "/usr/bin/python3";

bool have_prereqs(std::string& bin, std::string& why) {
    bin = raincoat_bin();
    if (::access(bin.c_str(), X_OK) != 0) { why = "raincoat not at " + bin; return false; }
    if (::access(kBwrapPath, X_OK) != 0) { why = "bwrap missing"; return false; }
    if (::access(kPython, X_OK) != 0) { why = "python3 missing"; return false; }
    return true;
}

struct RunResult {
    int exit_code = -1;
    bool spawn_ok = false;
    std::string output;
};

RunResult run_proc(const std::string& bin, const std::vector<std::string>& args,
                   const std::map<std::string, std::string>& env, const std::string& cwd) {
    RunResult r;
    int fds[2];
    if (::pipe(fds) != 0) return r;
    pid_t pid = ::fork();
    if (pid < 0) { ::close(fds[0]); ::close(fds[1]); return r; }
    if (pid == 0) {
        if (::chdir(cwd.c_str()) != 0) _exit(126);
        ::dup2(fds[1], STDOUT_FILENO);
        ::dup2(fds[1], STDERR_FILENO);
        ::close(fds[0]); ::close(fds[1]);
        std::vector<std::string> a{bin};
        for (const auto& s : args) a.push_back(s);
        std::vector<char*> argv;
        for (auto& s : a) argv.push_back(const_cast<char*>(s.c_str()));
        argv.push_back(nullptr);
        std::vector<std::string> es;
        for (const auto& kv : env) es.push_back(kv.first + "=" + kv.second);
        std::vector<char*> envp;
        for (auto& s : es) envp.push_back(const_cast<char*>(s.c_str()));
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
    while (::waitpid(pid, &status, 0) < 0) { if (errno != EINTR) break; }
    if (WIFEXITED(status)) r.exit_code = WEXITSTATUS(status);
    else if (WIFSIGNALED(status)) r.exit_code = 128 + WTERMSIG(status);
    return r;
}

std::string make_temp_dir(const std::string& tag) {
    static std::atomic<unsigned> counter{0};
    fs::path base = fs::temp_directory_path() / "rc-egress-attack3-e2e";
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

}  // namespace

TEST(EgressAttack3Regression, ActiveBridgeAuditIsTamperProof) {
    std::string bin, why;
    if (!have_prereqs(bin, why)) GTEST_SKIP() << why;

    // Distinctive upstream host token; no upstream needs to actually answer — the
    // child never forwards, it only tries to CLOBBER the audit log.
    const std::string kUpstreamToken = "TAMPER-UPSTREAM-HOST-8H2Q.invalid";
    const std::string upstream_url = "https://" + kUpstreamToken;
    const std::string child_url = "http://127.0.0.1:0";  // ephemeral bridge port

    std::string profile_dir = make_temp_dir("profile");
    std::string profile_path = (fs::path(profile_dir) / "egress.toml").string();
    {
        std::ofstream p(profile_path);
        p << "[egress]\nmode = \"bridge\"\n\n"
          << "[[egress.bridge]]\n"
          << "name = \"api\"\n"
          << "env = \"MY_BASE_URL\"\n"
          << "child_endpoint = \"" << child_url << "\"\n"
          << "upstream_endpoint = \"" << upstream_url << "\"\n";
    }
    std::string real_home = make_temp_dir("home");
    std::string cwd = make_temp_dir("cwd");
    std::map<std::string, std::string> env = {
        {"PATH", "/usr/bin:/bin"}, {"TERM", "xterm"}, {"HOME", real_home}};

    // The child attempts to forge the audit log from inside the sandbox: overwrite it
    // with garbage and also drop a sibling file. Because .raincoat is shadowed with a
    // tmpfs, these writes must NOT reach the real host audit.log.
    //
    // The forgery marker is ASSEMBLED at runtime from char codes so the literal token
    // never appears in the child's argv — which raincoat legitimately records in the
    // audit "Command:" line. (Searching the host audit for the literal string would
    // otherwise false-positive on that echoed command.) Codes spell "FORGEDBYCHILD".
    const std::string kForge = "FORGEDBYCHILD";
    const char* py =
        "import os\n"
        "os.makedirs('.raincoat', exist_ok=True)\n"
        "marker=''.join(map(chr,[70,79,82,71,69,68,66,89,67,72,73,76,68]))\n"
        "open('.raincoat/audit.log','w').write(marker+' do not trust\\n')\n"
        "open('.raincoat/child-was-here','w').write('x')\n"
        "print('CHILD_TAMPER_ATTEMPTED')\n";

    RunResult r = run_proc(
        bin, {"--profile", profile_path, "--", kPython, "-c", py}, env, cwd);
    ASSERT_TRUE(r.spawn_ok);
    ASSERT_EQ(r.exit_code, 0) << r.output;
    EXPECT_NE(r.output.find("CHILD_TAMPER_ATTEMPTED"), std::string::npos) << r.output;

    // The real host audit survived the child's forgery attempt intact.
    const std::string audit_path = (fs::path(cwd) / ".raincoat" / "audit.log").string();
    const std::string audit = read_file(audit_path);
    ASSERT_FALSE(audit.empty());
    EXPECT_EQ(audit.find(kForge), std::string::npos)
        << "child overwrote the real audit log — tamper-proofing regressed under "
           "egress:\n"
        << audit;
    // The genuine raincoat start block is still present (a full forgery would drop it).
    EXPECT_NE(audit.find("=== Raincoat started ==="), std::string::npos) << audit;
    // The child's sibling forgery never landed on the host either.
    EXPECT_FALSE(fs::exists(fs::path(cwd) / ".raincoat" / "child-was-here"))
        << "child wrote through the audit-dir tmpfs mask to the host";

    // The surviving audit is the HONEST one: shared-net disclosure + a proper end
    // block, and no leaked upstream host.
    EXPECT_NE(audit.find("SHARES the host network namespace"), std::string::npos) << audit;
    EXPECT_NE(audit.find("Raincoat finished"), std::string::npos)
        << "audit end block missing — the real raincoat audit was not the one on disk:\n"
        << audit;
    EXPECT_EQ(audit.find(kUpstreamToken), std::string::npos)
        << "audit leaked the real upstream host:\n" << audit;
}
