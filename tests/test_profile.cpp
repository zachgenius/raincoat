// Comprehensive GoogleTest suite for the `profile` module (load_profile + merge).
//
// Derived from docs/DESIGN.md (interface contract) and docs/SPEC.md (behaviour).
// These tests define the CONTRACT; they are written BEFORE the implementation
// (TDD red) and are expected to FAIL against the current stub.
//
// Behaviours under test:
//   load_profile(path, err) -> optional<Options>
//     * strict(bool), network(string->NetMode)
//     * allow_read / allow_write / allow_env (string arrays)
//     * [env] table -> env_defaults
//     * [fontconfig].enabled(bool) -> fontconfig_enabled (optional)
//     * [audit].log_file(string) -> audit_log (optional)
//     * set_env is CLI-only: NEVER read from a profile
//     * missing file / malformed TOML / invalid enum -> nullopt + err set
//   merge(profile, cli) -> Options   (CLI overrides profile)
//     * lists (allow_read/write/env, set_env): unioned profile-then-cli, de-duplicated
//     * scalars/optionals (strict, net, workdir, audit_log, keep_temp, fontconfig):
//       take CLI when explicitly set, else profile
//     * env_defaults: profile table overlaid by cli (cli keys win)

#include <gtest/gtest.h>

#include <atomic>
#include <filesystem>
#include <fstream>
#include <map>
#include <string>
#include <utility>
#include <vector>

#include "profile.hpp"

using raincoat::Options;
using raincoat::NetMode;
using raincoat::NetworkPolicy;
using raincoat::load_profile;
using raincoat::merge;

namespace {

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

// Write `content` to a fresh, uniquely-named temp file and return its path.
std::string write_temp_file(const std::string& content) {
    namespace fs = std::filesystem;
    static std::atomic<unsigned> counter{0};
    fs::path dir = fs::temp_directory_path() / "rc-profile-tests";
    fs::create_directories(dir);
    fs::path p = dir / ("profile-" + std::to_string(counter.fetch_add(1)) + ".toml");
    std::ofstream ofs(p, std::ios::binary | std::ios::trunc);
    ofs << content;
    ofs.close();
    return p.string();
}

// The canonical example profile straight out of docs/SPEC.md.
const char* kSpecExampleToml = R"TOML(strict = false
network = "full"
allow_read = ["./src"]
allow_write = ["./out"]
allow_env = ["OPENAI_API_KEY"]
[env]
TZ = "UTC"
LANG = "en_US.UTF-8"
LC_ALL = "en_US.UTF-8"
[fontconfig]
enabled = true
[audit]
log_file = ".raincoat/audit.log"
)TOML";

bool contains(const std::vector<std::string>& v, const std::string& s) {
    for (const auto& x : v) if (x == s) return true;
    return false;
}

// True if ANY element of `v` contains `needle` as a substring.
bool any_contains(const std::vector<std::string>& v, const std::string& needle) {
    for (const auto& x : v)
        if (x.find(needle) != std::string::npos) return true;
    return false;
}

// A verbatim copy of docs/full-config-reference.toml — the directional DEMO config the
// profile layer must ACCEPT without error (phase 1.5). Embedded (rather than read from
// the repo) so the test is self-contained and cwd-independent under both the standalone
// g++ build and ctest.
const char* kFullConfigToml = R"TOML(profile_name = "default-agent-sandbox"
strict = true

network = "bridge"
keep_temp = false
workdir = "/workspace"

[identity]
username = "user"
hostname = "workstation"
home = "/home/user"
timezone = "UTC"
locale = "en_US.UTF-8"
language = "en-US"
platform_label = "generic-linux"
persona = "generic-ci"

[filesystem]
fake_home = true
create_standard_dirs = true
mode = "deny-by-default"
allow_read = [
  "./README.md",
  "./package.json",
  "./Cargo.toml",
  "./src"
]
allow_write = [
  "./out",
  "./target",
  "./.raincoat-work"
]
deny = [
  "~/.ssh",
  "~/.aws",
  "~/.azure",
  "~/.config/gcloud",
  "~/.kube",
  "~/.gnupg",
  "~/.docker",
  "~/.npmrc",
  "~/.pypirc",
  "~/.git-credentials",
  "~/.gitconfig",
  "~/.config/gh"
]

[filesystem.tripwire]
enabled = false
fake_sensitive_files = [
  "~/.ssh/id_rsa",
  "~/.aws/credentials"
]

[environment]
clear = true
allow = [
  "PATH",
  "TERM"
]
deny = [
  "SSH_AUTH_SOCK",
  "KUBECONFIG",
  "DOCKER_HOST",
  "NPM_TOKEN",
  "PYPI_TOKEN"
]
scrub_patterns = [
  "*_TOKEN",
  "*_SECRET",
  "*_KEY",
  "AWS_*",
  "GITHUB_*",
  "OPENAI_*",
  "ANTHROPIC_*",
  "AZURE_*"
]

[environment.set]
HOME = "/home/user"
TMPDIR = "/tmp"
USER = "user"
LOGNAME = "user"
HOSTNAME = "workstation"
TZ = "UTC"
LANG = "en_US.UTF-8"
LC_ALL = "en_US.UTF-8"
LANGUAGE = "en-US"
XDG_CONFIG_HOME = "/home/user/.config"
XDG_CACHE_HOME = "/home/user/.cache"
XDG_DATA_HOME = "/home/user/.local/share"

[fontconfig]
enabled = true
hide_host_fonts = true
mode = "minimal"

[browser]
enabled = false
isolate_profile = true

[egress]
mode = "bridge"
hide_upstreams_from_child = true
timeout_seconds = 120

[[egress.bridge]]
name = "primary-api"
env = "SOME_BASE_URL"
child_endpoint = "http://127.0.0.1:18080"
upstream_endpoint = "https://real-upstream.example.com"
preserve_host = false

[[egress.bridge]]
name = "secondary-api"
env = "SECONDARY_BASE_URL"
child_endpoint = "http://127.0.0.1:18081"
upstream_endpoint = "https://secondary-upstream.example.com"
preserve_host = false

[proxy]
enabled = false
http_proxy = "http://127.0.0.1:18080"
https_proxy = "http://127.0.0.1:18080"
all_proxy = "socks5://127.0.0.1:18080"
no_proxy = ""

[dns]
enabled = false

[[dns.map]]
host = "example.com"
ip = "203.0.113.10"

[network_policy]
enabled = true
default_action = "allow"
allow_hosts = [
  "github.com",
  "api.github.com"
]
block_hosts = [
  "ipinfo.io"
]

[audit]
enabled = true
log_file = ".raincoat/audit.log"
format = "text"
redact_secrets = true

[backend]
type = "bubblewrap"
bwrap_path = "bwrap"
unshare_user = true
unshare_pid = true
unshare_ipc = true
unshare_uts = true
unshare_cgroup = true
unshare_net_when_off = true
mount_proc = true
mount_dev = true
mount_tmpfs_tmp = true
die_with_parent = true
seccomp = false

[init]
create_dirs = [
  ".raincoat",
  ".raincoat-work",
  "out"
]

[report]
latest_log = ".raincoat/audit.log"
playful_summary = true
)TOML";

// Look up a KEY in a vector<pair> set_env list; returns nullptr when absent.
const std::string* find_set_env(
    const std::vector<std::pair<std::string, std::string>>& v, const std::string& key) {
    for (const auto& kv : v)
        if (kv.first == key) return &kv.second;
    return nullptr;
}

}  // namespace

// ===========================================================================
// load_profile — happy path: the exact SPEC example TOML.
// ===========================================================================

TEST(Profile, LoadSpecExampleParsesEveryField) {
    std::string path = write_temp_file(kSpecExampleToml);
    std::string err;
    auto opt = load_profile(path, err);

    ASSERT_TRUE(opt.has_value()) << "err=" << err;
    EXPECT_TRUE(err.empty());

    const Options& o = *opt;
    EXPECT_FALSE(o.strict);

    ASSERT_TRUE(o.net.has_value());
    EXPECT_EQ(*o.net, NetMode::Full);

    ASSERT_EQ(o.allow_read.size(), 1u);
    EXPECT_EQ(o.allow_read[0], "./src");

    ASSERT_EQ(o.allow_write.size(), 1u);
    EXPECT_EQ(o.allow_write[0], "./out");

    ASSERT_EQ(o.allow_env.size(), 1u);
    EXPECT_EQ(o.allow_env[0], "OPENAI_API_KEY");

    // [env] table -> env_defaults
    EXPECT_EQ(o.env_defaults.at("TZ"), "UTC");
    EXPECT_EQ(o.env_defaults.at("LANG"), "en_US.UTF-8");
    EXPECT_EQ(o.env_defaults.at("LC_ALL"), "en_US.UTF-8");
    EXPECT_EQ(o.env_defaults.size(), 3u);

    // [fontconfig].enabled -> optional<bool>
    ASSERT_TRUE(o.fontconfig_enabled.has_value());
    EXPECT_TRUE(*o.fontconfig_enabled);

    // [audit].log_file -> audit_log
    ASSERT_TRUE(o.audit_log.has_value());
    EXPECT_EQ(*o.audit_log, ".raincoat/audit.log");

    // set_env is CLI-only; a profile never populates it.
    EXPECT_TRUE(o.set_env.empty());
}

// ===========================================================================
// load_profile — individual field mappings / edge cases.
// ===========================================================================

TEST(Profile, LoadStrictTrue) {
    std::string path = write_temp_file("strict = true\n");
    std::string err;
    auto opt = load_profile(path, err);
    ASSERT_TRUE(opt.has_value()) << "err=" << err;
    EXPECT_TRUE(opt->strict);
}

TEST(Profile, LoadStrictFalse) {
    std::string path = write_temp_file("strict = false\n");
    std::string err;
    auto opt = load_profile(path, err);
    ASSERT_TRUE(opt.has_value()) << "err=" << err;
    EXPECT_FALSE(opt->strict);
}

TEST(Profile, LoadNetworkOff) {
    std::string path = write_temp_file("network = \"off\"\n");
    std::string err;
    auto opt = load_profile(path, err);
    ASSERT_TRUE(opt.has_value()) << "err=" << err;
    ASSERT_TRUE(opt->net.has_value());
    EXPECT_EQ(*opt->net, NetMode::Off);
}

TEST(Profile, LoadNetworkFull) {
    std::string path = write_temp_file("network = \"full\"\n");
    std::string err;
    auto opt = load_profile(path, err);
    ASSERT_TRUE(opt.has_value()) << "err=" << err;
    ASSERT_TRUE(opt->net.has_value());
    EXPECT_EQ(*opt->net, NetMode::Full);
}

TEST(Profile, LoadFontconfigDisabled) {
    std::string path = write_temp_file("[fontconfig]\nenabled = false\n");
    std::string err;
    auto opt = load_profile(path, err);
    ASSERT_TRUE(opt.has_value()) << "err=" << err;
    ASSERT_TRUE(opt->fontconfig_enabled.has_value());
    EXPECT_FALSE(*opt->fontconfig_enabled);
}

TEST(Profile, LoadMultiElementArrays) {
    std::string path = write_temp_file(
        "allow_read = [\"./a\", \"./b\", \"/abs/c\"]\n"
        "allow_write = [\"./out1\", \"./out2\"]\n"
        "allow_env = [\"FOO\", \"BAR\", \"BAZ\"]\n");
    std::string err;
    auto opt = load_profile(path, err);
    ASSERT_TRUE(opt.has_value()) << "err=" << err;
    EXPECT_EQ(opt->allow_read, (std::vector<std::string>{"./a", "./b", "/abs/c"}));
    EXPECT_EQ(opt->allow_write, (std::vector<std::string>{"./out1", "./out2"}));
    EXPECT_EQ(opt->allow_env, (std::vector<std::string>{"FOO", "BAR", "BAZ"}));
}

// Keys that are absent should leave optionals empty and containers empty —
// so that merge() can tell "not specified" apart from an explicit value.
TEST(Profile, LoadMinimalLeavesUnspecifiedFieldsEmpty) {
    std::string path = write_temp_file("strict = true\n");
    std::string err;
    auto opt = load_profile(path, err);
    ASSERT_TRUE(opt.has_value()) << "err=" << err;
    const Options& o = *opt;
    EXPECT_FALSE(o.net.has_value());
    EXPECT_FALSE(o.fontconfig_enabled.has_value());
    EXPECT_FALSE(o.audit_log.has_value());
    EXPECT_TRUE(o.allow_read.empty());
    EXPECT_TRUE(o.allow_write.empty());
    EXPECT_TRUE(o.allow_env.empty());
    EXPECT_TRUE(o.env_defaults.empty());
    EXPECT_TRUE(o.set_env.empty());
    EXPECT_TRUE(o.command.empty());
}

TEST(Profile, LoadEmptyProfileSucceedsWithDefaults) {
    std::string path = write_temp_file("");
    std::string err;
    auto opt = load_profile(path, err);
    ASSERT_TRUE(opt.has_value()) << "err=" << err;
    EXPECT_FALSE(opt->strict);
    EXPECT_FALSE(opt->net.has_value());
    EXPECT_TRUE(opt->allow_read.empty());
}

// ===========================================================================
// Value-driven fingerprint masks: [backend].* optionals (presence == the switch).
// ===========================================================================

TEST(Profile, LoadBackendFingerprintValuesSet) {
    std::string path = write_temp_file(
        "[backend]\n"
        "cpu_vendor_id = \"AuthenticAMD\"\n"
        "cpu_model_name = \"Acme CPU\"\n"
        "cpu_count = 8\n"
        "kernel_osrelease = \"6.1.0-generic\"\n"
        "kernel_version = \"#1 SMP GENERIC\"\n"
        "kernel_cmdline = \"BOOT_IMAGE=/vmlinuz root=/dev/sda1\"\n"
        "machine_id = \"cafebabecafebabecafebabecafebabe\"\n"
        "boot_id = \"00000000-0000-4000-8000-000000000000\"\n"
        "mem_total_kb = 2097152\n"
        "uptime_seconds = 3600\n");
    std::string err;
    auto opt = load_profile(path, err);
    ASSERT_TRUE(opt.has_value()) << "err=" << err;
    const auto& b = opt->ext.backend;
    EXPECT_EQ(b.cpu_vendor_id.value_or(""), "AuthenticAMD");
    EXPECT_EQ(b.cpu_model_name.value_or(""), "Acme CPU");
    ASSERT_TRUE(b.cpu_count.has_value());
    EXPECT_EQ(*b.cpu_count, 8u);
    EXPECT_EQ(b.kernel_osrelease.value_or(""), "6.1.0-generic");
    EXPECT_EQ(b.kernel_version.value_or(""), "#1 SMP GENERIC");
    EXPECT_EQ(b.kernel_cmdline.value_or(""), "BOOT_IMAGE=/vmlinuz root=/dev/sda1");
    EXPECT_EQ(b.machine_id.value_or(""), "cafebabecafebabecafebabecafebabe");
    EXPECT_EQ(b.boot_id.value_or(""), "00000000-0000-4000-8000-000000000000");
    ASSERT_TRUE(b.mem_total_kb.has_value());
    EXPECT_EQ(*b.mem_total_kb, 2097152u);
    ASSERT_TRUE(b.uptime_seconds.has_value());
    EXPECT_EQ(*b.uptime_seconds, 3600u);
}

TEST(Profile, LoadBackendFingerprintValuesDefaultToUnset) {
    // No [backend] section => every fingerprint knob stays nullopt (real system value shown).
    std::string path = write_temp_file("strict = true\n");
    std::string err;
    auto opt = load_profile(path, err);
    ASSERT_TRUE(opt.has_value()) << "err=" << err;
    const auto& b = opt->ext.backend;
    EXPECT_FALSE(b.cpu_vendor_id.has_value());
    EXPECT_FALSE(b.cpu_model_name.has_value());
    EXPECT_FALSE(b.cpu_count.has_value());
    EXPECT_FALSE(b.kernel_osrelease.has_value());
    EXPECT_FALSE(b.kernel_version.has_value());
    EXPECT_FALSE(b.kernel_cmdline.has_value());
    EXPECT_FALSE(b.machine_id.has_value());
    EXPECT_FALSE(b.boot_id.has_value());
    EXPECT_FALSE(b.mem_total_kb.has_value());
    EXPECT_FALSE(b.uptime_seconds.has_value());
}

TEST(Profile, LoadBackendIntegerKnobsRejectNonNumeric) {
    // A non-numeric mem_total_kb is ignored (stays unset) rather than mis-parsed.
    std::string path = write_temp_file("[backend]\nmem_total_kb = \"lots\"\n");
    std::string err;
    auto opt = load_profile(path, err);
    ASSERT_TRUE(opt.has_value()) << "err=" << err;
    EXPECT_FALSE(opt->ext.backend.mem_total_kb.has_value());
}

// ===========================================================================
// Mount remap: [filesystem].remap_cwd + [[filesystem.mount]].
// ===========================================================================

TEST(Profile, LoadRemapCwd) {
    std::string path = write_temp_file("[filesystem]\nremap_cwd = \"/work\"\n");
    std::string err;
    auto opt = load_profile(path, err);
    ASSERT_TRUE(opt.has_value()) << "err=" << err;
    ASSERT_TRUE(opt->ext.remap_cwd.has_value());
    EXPECT_EQ(*opt->ext.remap_cwd, "/work");
}

TEST(Profile, LoadExplicitRemapMounts) {
    std::string path = write_temp_file(
        "[[filesystem.mount]]\n"
        "host = \"/home/u/data\"\n"
        "sandbox = \"/data\"\n"
        "mode = \"ro\"\n"
        "[[filesystem.mount]]\n"
        "host = \"/home/u/out\"\n"
        "sandbox = \"/out\"\n"
        "mode = \"rw\"\n");
    std::string err;
    auto opt = load_profile(path, err);
    ASSERT_TRUE(opt.has_value()) << "err=" << err;
    const auto& rm = opt->ext.remap_mounts;
    ASSERT_EQ(rm.size(), 2u);
    EXPECT_EQ(rm[0].host, "/home/u/data");
    EXPECT_EQ(rm[0].sandbox, "/data");
    EXPECT_EQ(rm[0].mode, raincoat::MountMode::ReadOnly);
    EXPECT_EQ(rm[1].host, "/home/u/out");
    EXPECT_EQ(rm[1].sandbox, "/out");
    EXPECT_EQ(rm[1].mode, raincoat::MountMode::ReadWrite);
}

TEST(Profile, LoadRemapMountDefaultsToReadOnly) {
    // Omitted mode defaults to read-only (the safe choice).
    std::string path = write_temp_file(
        "[[filesystem.mount]]\nhost = \"/home/u/data\"\nsandbox = \"/data\"\n");
    std::string err;
    auto opt = load_profile(path, err);
    ASSERT_TRUE(opt.has_value()) << "err=" << err;
    ASSERT_EQ(opt->ext.remap_mounts.size(), 1u);
    EXPECT_EQ(opt->ext.remap_mounts[0].mode, raincoat::MountMode::ReadOnly);
}

TEST(Profile, LoadRemapMountSkipsIncompleteEntry) {
    // An entry missing host or sandbox is dropped (not half-applied).
    std::string path = write_temp_file(
        "[[filesystem.mount]]\nsandbox = \"/data\"\n");
    std::string err;
    auto opt = load_profile(path, err);
    ASSERT_TRUE(opt.has_value()) << "err=" << err;
    EXPECT_TRUE(opt->ext.remap_mounts.empty());
}

TEST(Profile, LoadCommentsAndBlankLinesIgnored) {
    std::string path = write_temp_file(
        "# leading comment\n"
        "\n"
        "strict = true   # trailing comment\n"
        "\n"
        "network = \"off\"\n");
    std::string err;
    auto opt = load_profile(path, err);
    ASSERT_TRUE(opt.has_value()) << "err=" << err;
    EXPECT_TRUE(opt->strict);
    ASSERT_TRUE(opt->net.has_value());
    EXPECT_EQ(*opt->net, NetMode::Off);
}

TEST(Profile, LoadAuditLogFromAuditTable) {
    std::string path = write_temp_file("[audit]\nlog_file = \"/var/log/rc.log\"\n");
    std::string err;
    auto opt = load_profile(path, err);
    ASSERT_TRUE(opt.has_value()) << "err=" << err;
    ASSERT_TRUE(opt->audit_log.has_value());
    EXPECT_EQ(*opt->audit_log, "/var/log/rc.log");
}

TEST(Profile, LoadEnvTablePreservesAllPairs) {
    std::string path = write_temp_file(
        "[env]\n"
        "TZ = \"America/New_York\"\n"
        "LANG = \"C\"\n"
        "CUSTOM = \"hello world\"\n");
    std::string err;
    auto opt = load_profile(path, err);
    ASSERT_TRUE(opt.has_value()) << "err=" << err;
    EXPECT_EQ(opt->env_defaults.size(), 3u);
    EXPECT_EQ(opt->env_defaults.at("TZ"), "America/New_York");
    EXPECT_EQ(opt->env_defaults.at("LANG"), "C");
    EXPECT_EQ(opt->env_defaults.at("CUSTOM"), "hello world");
}

// set_env must be ignored even if a (misguided) profile tries to declare it.
TEST(Profile, LoadIgnoresSetEnvKeyInProfile) {
    std::string path = write_temp_file(
        "strict = true\n"
        "set_env = [\"SECRET=hunter2\", \"FOO=bar\"]\n");
    std::string err;
    auto opt = load_profile(path, err);
    ASSERT_TRUE(opt.has_value()) << "err=" << err;
    EXPECT_TRUE(opt->set_env.empty());
}

// ===========================================================================
// load_profile — error handling: nullopt + err populated, never crash.
// ===========================================================================

TEST(Profile, LoadMissingFileReturnsNulloptWithError) {
    std::string err;
    auto opt = load_profile("/nonexistent/path/does/not/exist-xyz.toml", err);
    EXPECT_FALSE(opt.has_value());
    EXPECT_FALSE(err.empty());
}

TEST(Profile, LoadMalformedTomlReturnsNulloptWithError) {
    // Unterminated table header / junk — parse_toml must reject with an err.
    std::string path = write_temp_file("this is = = not valid toml [[[\n");
    std::string err;
    auto opt = load_profile(path, err);
    EXPECT_FALSE(opt.has_value());
    EXPECT_FALSE(err.empty());
}

TEST(Profile, LoadInvalidNetworkValueReturnsError) {
    // "banana" is valid TOML but not a valid NetMode -> profile layer rejects.
    std::string path = write_temp_file("network = \"banana\"\n");
    std::string err;
    auto opt = load_profile(path, err);
    EXPECT_FALSE(opt.has_value());
    EXPECT_FALSE(err.empty());
}

// BUG (adversarial round 1): load_profile accepts network values that the MVP
// does not implement. SPEC ("Network modes": "MVP implements full and off
// only") and the loader's OWN error message ("expected full|off") say only
// full|off are valid from a profile. But net_mode_from_string() also accepts
// "allowlist"/"ask", and load_profile does not re-validate, so these load
// successfully. Because net_guard::net_flags() emits NO "--unshare-net" for
// Allowlist/Ask, a user who writes network = "allowlist" (intending RESTRICTED
// networking) silently gets FULL open networking — a privacy leak. A profile
// must reject these values, exactly as it rejects "banana".
TEST(Profile, LoadRejectsUnimplementedNetworkAllowlist) {
    std::string path = write_temp_file("network = \"allowlist\"\n");
    std::string err;
    auto opt = load_profile(path, err);
    EXPECT_FALSE(opt.has_value())
        << "network=\"allowlist\" loaded as net="
        << (opt && opt->net ? raincoat::to_string(*opt->net) : "?")
        << " — an unimplemented mode that yields full networking";
    EXPECT_FALSE(err.empty());
}

TEST(Profile, LoadRejectsUnimplementedNetworkAsk) {
    std::string path = write_temp_file("network = \"ask\"\n");
    std::string err;
    auto opt = load_profile(path, err);
    EXPECT_FALSE(opt.has_value());
    EXPECT_FALSE(err.empty());
}

// BUG (adversarial round 2): a `network` value that is a *boolean* token bypasses
// validation entirely. The loader only inspects p.scalars["network"] (string
// values); `network = false` / `network = true` are parsed as bools and land in
// p.bools, so the scalar lookup misses and `net` is left UNSET with no error.
// Contrast: `network = "banana"` and `network = 8080` are both rejected. The leak:
// a user who writes `network = false` (a very plausible way to try to *disable*
// networking) gets no error, `net` stays nullopt, and the runner's non-strict
// default is FULL — i.e. the profile silently yields OPEN networking, exactly the
// privacy failure the round-1 allowlist/ask rejection was meant to close. A
// non-string `network` value must be rejected just like "banana".
TEST(Profile, LoadRejectsBooleanNetworkFalse) {
    std::string path = write_temp_file("network = false\n");
    std::string err;
    auto opt = load_profile(path, err);
    EXPECT_FALSE(opt.has_value())
        << "network=false was accepted with net="
        << (opt && opt->net ? raincoat::to_string(*opt->net) : "<unset>")
        << " — the runner then defaults to FULL (open networking), silently "
           "ignoring an attempt to turn networking off";
    EXPECT_FALSE(err.empty());
}

TEST(Profile, LoadRejectsBooleanNetworkTrue) {
    std::string path = write_temp_file("network = true\n");
    std::string err;
    auto opt = load_profile(path, err);
    EXPECT_FALSE(opt.has_value());
    EXPECT_FALSE(err.empty());
}

// BUG (adversarial round 5): the round-2..4 wrong-type guards all lean on
// TomlTable::contains(), which reports presence for scalar/bool/array values but
// NOT for a TABLE. So a guarded key written as a `[table]` header slips past the
// "present-but-wrong-type" check and is silently treated as ABSENT. `network` is
// a top-level string key, but the config is heavy with tables (`[env]`,
// `[fontconfig]`, `[audit]`), so writing `[network]` (intending to group the
// networking setting, e.g. to turn it OFF) is a very plausible mistake. Trace:
// `[network]` lands only in tables_, get_string("network") misses (it lives in
// scalars_), and contains("network") is false because it never inspects tables_.
// load_profile therefore returns SUCCESS with net UNSET and NO error — and the
// runner's non-strict default is FULL. So a user who writes a `[network]` block
// to DISABLE networking silently gets OPEN networking, exactly the leak the
// round-2 `network = false` rejection was meant to close, merely re-expressed
// with a type (table) that contains() cannot see. A table-typed `network` must be
// rejected just like `network = false` is.
TEST(Profile, LoadRejectsTableTypedNetwork) {
    std::string path = write_temp_file("[network]\nmode = \"off\"\n");
    std::string err;
    auto opt = load_profile(path, err);
    EXPECT_FALSE(opt.has_value())
        << "[network] table was accepted with net="
        << (opt && opt->net ? raincoat::to_string(*opt->net) : "<unset>")
        << " — the runner then defaults to FULL (open networking), silently "
           "ignoring a table-form attempt to configure networking off";
    EXPECT_FALSE(err.empty());
}

// BUG (adversarial round 3): a wrong-typed `strict` value silently downgrades
// privacy, exactly the class of bug the round-2 `network = false` fix closed —
// but left unfixed for `strict`. The loader only inspects p.bools["strict"];
// `strict = "true"` (a very plausible mistake: quoting the boolean) is parsed
// as a STRING, lands in p.scalars, the bool lookup misses, and load_profile
// returns strict=false / strict_set=false with NO error. Contrast: `strict = 1`
// (integer) IS rejected ("Unrecognized value"). The leak: a user who writes
// strict = "true" intending to ENABLE strict isolation silently gets NON-strict
// mode — CWD mounted read-write, network full by default, less env scrubbing —
// i.e. the profile silently yields the LESS protective mode. A non-bool `strict`
// value must be rejected just like a non-string `network` value is.
TEST(Profile, LoadRejectsStringTypedStrictTrue) {
    std::string path = write_temp_file("strict = \"true\"\n");
    std::string err;
    auto opt = load_profile(path, err);
    EXPECT_FALSE(opt.has_value())
        << "strict=\"true\" was accepted with strict="
        << (opt ? (opt->strict ? "true" : "false") : "<none>")
        << " / strict_set="
        << (opt ? (opt->strict_set ? "true" : "false") : "<none>")
        << " — the runner then treats the profile as NON-strict, silently "
           "ignoring an attempt to turn strict isolation ON";
    EXPECT_FALSE(err.empty());
}

// BUG (adversarial round 4): `audit.log_file` is the one profile key that never
// got the "present-but-wrong-type" guard that strict / network / [env] /
// fontconfig.enabled all received. load_profile only reads
// p.scalars["audit.log_file"] (string values); a NON-string value —
// `audit.log_file = ["/var/log/rc.log"]` (a plausible mistake by analogy to the
// allow_read = [...] arrays) or `audit.log_file = true` — lands in p.arrays /
// p.bools, the scalar lookup misses, and load_profile returns SUCCESS with
// audit_log left UNSET and NO error. Contrast: every other typed key rejects a
// wrong-typed value. The downgrade: SPEC puts the DEFAULT audit log at
// `.raincoat/audit.log` inside the project dir, which non-strict mode mounts
// read-write and exposes to the untrusted child (SPEC "Default (non-strict)
// behavior": "Mount the current working directory read-write"). A security-
// conscious user who sets audit.log_file to a path OUTSIDE that writable area —
// to keep the audit trail tamper-proof — but mistypes the value type silently
// gets the child-tamperable in-project default instead of an error. A non-string
// `audit.log_file` must be rejected, exactly as a non-bool `strict` is.
TEST(Profile, LoadRejectsArrayTypedAuditLogFile) {
    std::string path = write_temp_file("audit.log_file = [\"/var/log/rc.log\"]\n");
    std::string err;
    auto opt = load_profile(path, err);
    EXPECT_FALSE(opt.has_value())
        << "audit.log_file=[...] was accepted with audit_log="
        << (opt && opt->audit_log ? *opt->audit_log : std::string("<unset>"))
        << " — auditing silently falls back to the child-writable in-project "
           "default, defeating the user's chosen tamper-proof location";
    EXPECT_FALSE(err.empty());
}

TEST(Profile, LoadRejectsBoolTypedAuditLogFile) {
    std::string path = write_temp_file("audit.log_file = true\n");
    std::string err;
    auto opt = load_profile(path, err);
    EXPECT_FALSE(opt.has_value());
    EXPECT_FALSE(err.empty());
}

// BUG (adversarial round 1): the profile's hand-rolled parser cannot read
// multi-line arrays. DESIGN declares `profile (deps: toml)` and the toml module
// "Must handle: ... multiline arrays", so a profile using the idiomatic
// multi-line array form must load. Instead load_profile fails with
// "Malformed array" because parse_toml_min only inspects a single line.
TEST(Profile, LoadMultilineArray) {
    std::string path = write_temp_file(
        "allow_read = [\n"
        "  \"./src\",\n"
        "  \"./tests\",\n"
        "]\n");
    std::string err;
    auto opt = load_profile(path, err);
    ASSERT_TRUE(opt.has_value()) << "err=" << err;
    EXPECT_EQ(opt->allow_read, (std::vector<std::string>{"./src", "./tests"}));
}

// A full SPEC-shaped profile written in the idiomatic multiline-array +
// root dotted-key (`env.TZ = "UTC"`) style must load identically to the
// single-line/[table] form. This only works because the profile now parses
// through the toml module (multiline arrays + dotted keys), which the old
// hand-rolled single-line parser could not do.
TEST(Profile, LoadMultilineAndDottedKeyVariant) {
    std::string path = write_temp_file(
        "strict = false\n"
        "network = \"full\"\n"
        "allow_read = [\n"
        "  \"./src\",\n"
        "  \"./tests\",\n"
        "]\n"
        "allow_write = [\"./out\"]\n"
        "allow_env = [\"OPENAI_API_KEY\"]\n"
        "env.TZ = \"UTC\"\n"
        "env.LANG = \"en_US.UTF-8\"\n"
        "fontconfig.enabled = true\n"
        "audit.log_file = \".raincoat/audit.log\"\n");
    std::string err;
    auto opt = load_profile(path, err);
    ASSERT_TRUE(opt.has_value()) << "err=" << err;
    const Options& o = *opt;
    EXPECT_FALSE(o.strict);
    ASSERT_TRUE(o.net.has_value());
    EXPECT_EQ(*o.net, NetMode::Full);
    EXPECT_EQ(o.allow_read, (std::vector<std::string>{"./src", "./tests"}));
    EXPECT_EQ(o.allow_write, (std::vector<std::string>{"./out"}));
    EXPECT_EQ(o.allow_env, (std::vector<std::string>{"OPENAI_API_KEY"}));
    // Root dotted `env.*` keys populate env_defaults just like an [env] table.
    EXPECT_EQ(o.env_defaults.size(), 2u);
    EXPECT_EQ(o.env_defaults.at("TZ"), "UTC");
    EXPECT_EQ(o.env_defaults.at("LANG"), "en_US.UTF-8");
    ASSERT_TRUE(o.fontconfig_enabled.has_value());
    EXPECT_TRUE(*o.fontconfig_enabled);
    ASSERT_TRUE(o.audit_log.has_value());
    EXPECT_EQ(*o.audit_log, ".raincoat/audit.log");
}

// ===========================================================================
// merge — list unioning (profile entries first, then cli, de-duplicated).
// ===========================================================================

TEST(Profile, MergeUnionsAllowReadProfileFirstDeduped) {
    Options profile;
    profile.allow_read = {"./a", "./b"};
    Options cli;
    cli.allow_read = {"./b", "./c", "./a"};

    Options m = merge(profile, cli);
    // profile order preserved, cli-only appended, duplicates dropped.
    EXPECT_EQ(m.allow_read, (std::vector<std::string>{"./a", "./b", "./c"}));
}

TEST(Profile, MergeUnionsAllowWriteAndAllowEnv) {
    Options profile;
    profile.allow_write = {"./out"};
    profile.allow_env = {"PATH", "TERM"};
    Options cli;
    cli.allow_write = {"./out", "./extra"};
    cli.allow_env = {"TERM", "FOO"};

    Options m = merge(profile, cli);
    EXPECT_EQ(m.allow_write, (std::vector<std::string>{"./out", "./extra"}));
    EXPECT_EQ(m.allow_env, (std::vector<std::string>{"PATH", "TERM", "FOO"}));
}

TEST(Profile, MergeEmptyProfileListsYieldsCliLists) {
    Options profile;  // empty
    Options cli;
    cli.allow_read = {"./x"};
    Options m = merge(profile, cli);
    EXPECT_EQ(m.allow_read, (std::vector<std::string>{"./x"}));
}

TEST(Profile, MergeEmptyCliListsYieldsProfileLists) {
    Options profile;
    profile.allow_read = {"./p"};
    Options cli;  // empty
    Options m = merge(profile, cli);
    EXPECT_EQ(m.allow_read, (std::vector<std::string>{"./p"}));
}

// ===========================================================================
// merge — set_env (CLI-only in practice, but merge is a general function).
// ===========================================================================

TEST(Profile, MergeSetEnvComesFromCli) {
    Options profile;  // profiles never carry set_env
    Options cli;
    cli.set_env = {{"FOO", "1"}, {"BAR", "2"}};

    Options m = merge(profile, cli);
    ASSERT_EQ(m.set_env.size(), 2u);
    EXPECT_EQ(m.set_env[0], (std::pair<std::string, std::string>{"FOO", "1"}));
    EXPECT_EQ(m.set_env[1], (std::pair<std::string, std::string>{"BAR", "2"}));
}

TEST(Profile, MergeSetEnvUnionedProfileFirst) {
    // Even though load never fills profile.set_env, merge must union deterministically.
    Options profile;
    profile.set_env = {{"A", "1"}};
    Options cli;
    cli.set_env = {{"B", "2"}};

    Options m = merge(profile, cli);
    ASSERT_EQ(m.set_env.size(), 2u);
    EXPECT_EQ(m.set_env[0].first, "A");
    EXPECT_EQ(m.set_env[1].first, "B");
}

// ===========================================================================
// merge — scalar/optional precedence: CLI wins when explicitly set.
// ===========================================================================

TEST(Profile, MergeCliStrictWinsOverProfileStrictFalse) {
    Options profile;
    profile.strict = false;
    profile.strict_set = true;
    Options cli;
    cli.strict = true;
    cli.strict_set = true;  // --strict was passed on the CLI

    Options m = merge(profile, cli);
    EXPECT_TRUE(m.strict);
}

TEST(Profile, MergeProfileStrictUsedWhenCliDidNotSet) {
    Options profile;
    profile.strict = true;
    profile.strict_set = true;
    Options cli;
    cli.strict = false;
    cli.strict_set = false;  // CLI did not pass --strict

    Options m = merge(profile, cli);
    EXPECT_TRUE(m.strict);
}

TEST(Profile, MergeCliNetWinsOverProfileNet) {
    Options profile;
    profile.net = NetMode::Full;
    Options cli;
    cli.net = NetMode::Off;

    Options m = merge(profile, cli);
    ASSERT_TRUE(m.net.has_value());
    EXPECT_EQ(*m.net, NetMode::Off);
}

TEST(Profile, MergeProfileNetUsedWhenCliNetUnset) {
    Options profile;
    profile.net = NetMode::Off;
    Options cli;  // cli.net == nullopt

    Options m = merge(profile, cli);
    ASSERT_TRUE(m.net.has_value());
    EXPECT_EQ(*m.net, NetMode::Off);
}

TEST(Profile, MergeCliWorkdirWinsElseProfile) {
    {
        Options profile; profile.workdir = "/p/dir";
        Options cli;     cli.workdir = "/c/dir";
        Options m = merge(profile, cli);
        ASSERT_TRUE(m.workdir.has_value());
        EXPECT_EQ(*m.workdir, "/c/dir");
    }
    {
        Options profile; profile.workdir = "/p/dir";
        Options cli;  // unset
        Options m = merge(profile, cli);
        ASSERT_TRUE(m.workdir.has_value());
        EXPECT_EQ(*m.workdir, "/p/dir");
    }
}

TEST(Profile, MergeCliAuditLogWinsElseProfile) {
    {
        Options profile; profile.audit_log = "/p/a.log";
        Options cli;     cli.audit_log = "/c/a.log";
        Options m = merge(profile, cli);
        ASSERT_TRUE(m.audit_log.has_value());
        EXPECT_EQ(*m.audit_log, "/c/a.log");
    }
    {
        Options profile; profile.audit_log = "/p/a.log";
        Options cli;
        Options m = merge(profile, cli);
        ASSERT_TRUE(m.audit_log.has_value());
        EXPECT_EQ(*m.audit_log, "/p/a.log");
    }
}

TEST(Profile, MergeFontconfigCliWinsElseProfile) {
    {
        Options profile; profile.fontconfig_enabled = true;
        Options cli;     cli.fontconfig_enabled = false;
        Options m = merge(profile, cli);
        ASSERT_TRUE(m.fontconfig_enabled.has_value());
        EXPECT_FALSE(*m.fontconfig_enabled);
    }
    {
        Options profile; profile.fontconfig_enabled = true;
        Options cli;  // unset
        Options m = merge(profile, cli);
        ASSERT_TRUE(m.fontconfig_enabled.has_value());
        EXPECT_TRUE(*m.fontconfig_enabled);
    }
}

TEST(Profile, MergeKeepTempCliWinsElseProfile) {
    {
        Options profile; profile.keep_temp = true; profile.keep_temp_set = true;
        Options cli;     cli.keep_temp = false;    cli.keep_temp_set = true;
        Options m = merge(profile, cli);
        EXPECT_FALSE(m.keep_temp);
    }
    {
        Options profile; profile.keep_temp = true; profile.keep_temp_set = true;
        Options cli;  // keep_temp_set == false
        Options m = merge(profile, cli);
        EXPECT_TRUE(m.keep_temp);
    }
}

// ===========================================================================
// merge — env_defaults: profile table overlaid by cli (cli keys win).
// ===========================================================================

TEST(Profile, MergeEnvDefaultsCliOverlaysProfile) {
    Options profile;
    profile.env_defaults = {{"TZ", "UTC"}, {"LANG", "en_US.UTF-8"}};
    Options cli;
    cli.env_defaults = {{"LANG", "C"}, {"EXTRA", "1"}};

    Options m = merge(profile, cli);
    EXPECT_EQ(m.env_defaults.at("TZ"), "UTC");     // profile-only survives
    EXPECT_EQ(m.env_defaults.at("LANG"), "C");     // cli overrides
    EXPECT_EQ(m.env_defaults.at("EXTRA"), "1");    // cli-only added
    EXPECT_EQ(m.env_defaults.size(), 3u);
}

// ===========================================================================
// Integration: load the SPEC profile then merge with a realistic CLI.
// ===========================================================================

TEST(Profile, LoadThenMergeAppliesCliOverrides) {
    std::string path = write_temp_file(kSpecExampleToml);
    std::string err;
    auto profile = load_profile(path, err);
    ASSERT_TRUE(profile.has_value()) << "err=" << err;

    // Simulate: raincoat run --strict --net off --allow-read ./tests
    //           --set-env TOKEN=abc --net off -- cmd
    Options cli;
    cli.strict = true;
    cli.strict_set = true;
    cli.net = NetMode::Off;
    cli.allow_read = {"./tests"};
    cli.set_env = {{"TOKEN", "abc"}};
    cli.env_defaults = {{"LANG", "C"}};

    Options m = merge(*profile, cli);

    // CLI --strict wins over profile strict=false.
    EXPECT_TRUE(m.strict);
    // CLI --net off wins over profile network="full".
    ASSERT_TRUE(m.net.has_value());
    EXPECT_EQ(*m.net, NetMode::Off);
    // Lists unioned: profile ./src then cli ./tests.
    EXPECT_EQ(m.allow_read, (std::vector<std::string>{"./src", "./tests"}));
    EXPECT_EQ(m.allow_write, (std::vector<std::string>{"./out"}));
    EXPECT_TRUE(contains(m.allow_env, "OPENAI_API_KEY"));
    // set_env is CLI-only.
    ASSERT_EQ(m.set_env.size(), 1u);
    EXPECT_EQ(m.set_env[0], (std::pair<std::string, std::string>{"TOKEN", "abc"}));
    // env_defaults: cli LANG overrides profile LANG; TZ/LC_ALL survive.
    EXPECT_EQ(m.env_defaults.at("LANG"), "C");
    EXPECT_EQ(m.env_defaults.at("TZ"), "UTC");
    EXPECT_EQ(m.env_defaults.at("LC_ALL"), "en_US.UTF-8");
    // fontconfig + audit_log come from the profile (CLI left them unset).
    ASSERT_TRUE(m.fontconfig_enabled.has_value());
    EXPECT_TRUE(*m.fontconfig_enabled);
    ASSERT_TRUE(m.audit_log.has_value());
    EXPECT_EQ(*m.audit_log, ".raincoat/audit.log");
}

// ===========================================================================
// Phase 1.5: the full rich sectioned config (docs/full-config-reference.toml)
// must LOAD without error and map every implemented section correctly, while
// gracefully RESERVING the not-yet-enforced sections.
// ===========================================================================

TEST(Profile, LoadFullReferenceConfigMapsEverySection) {
    std::string path = write_temp_file(kFullConfigToml);
    std::string err;
    auto opt = load_profile(path, err);
    ASSERT_TRUE(opt.has_value()) << "err=" << err;
    EXPECT_TRUE(err.empty());
    const Options& o = *opt;

    // ---- top-level ----
    EXPECT_TRUE(o.strict);
    ASSERT_TRUE(o.ext.profile_name.has_value());
    EXPECT_EQ(*o.ext.profile_name, "default-agent-sandbox");
    ASSERT_TRUE(o.workdir.has_value());
    EXPECT_EQ(*o.workdir, "/workspace");

    // network = "bridge" is a RESERVED mode: net left UNSET (safe fallback) and a
    // reserved note recorded that mentions "network".
    EXPECT_FALSE(o.net.has_value());
    EXPECT_TRUE(any_contains(o.ext.reserved_notes, "network"))
        << "expected a reserved note for the unenforced network mode";

    // ---- identity -> env defaults + ext ----
    EXPECT_EQ(o.env_defaults.at("TZ"), "UTC");
    EXPECT_EQ(o.env_defaults.at("LANG"), "en_US.UTF-8");
    EXPECT_EQ(o.env_defaults.at("LC_ALL"), "en_US.UTF-8");
    EXPECT_EQ(o.env_defaults.at("LANGUAGE"), "en-US");
    ASSERT_TRUE(o.ext.hostname.has_value());
    EXPECT_EQ(*o.ext.hostname, "workstation");
    ASSERT_TRUE(o.ext.username.has_value());
    EXPECT_EQ(*o.ext.username, "user");
    ASSERT_TRUE(o.ext.home.has_value());
    EXPECT_EQ(*o.ext.home, "/home/user");

    // ---- environment ----
    // allow -> allow_env (nested overrides flat).
    EXPECT_EQ(o.allow_env, (std::vector<std::string>{"PATH", "TERM"}));
    // deny -> ext.env_deny.
    EXPECT_TRUE(contains(o.ext.env_deny, "SSH_AUTH_SOCK"));
    EXPECT_TRUE(contains(o.ext.env_deny, "KUBECONFIG"));
    // scrub_patterns -> ext.scrub_patterns.
    EXPECT_TRUE(contains(o.ext.scrub_patterns, "AWS_*"));
    EXPECT_TRUE(contains(o.ext.scrub_patterns, "*_TOKEN"));
    // [environment.set] -> set_env.
    ASSERT_NE(find_set_env(o.set_env, "HOME"), nullptr);
    EXPECT_EQ(*find_set_env(o.set_env, "HOME"), "/home/user");
    ASSERT_NE(find_set_env(o.set_env, "USER"), nullptr);
    EXPECT_EQ(*find_set_env(o.set_env, "USER"), "user");
    EXPECT_NE(find_set_env(o.set_env, "XDG_CONFIG_HOME"), nullptr);
    EXPECT_NE(find_set_env(o.set_env, "XDG_CACHE_HOME"), nullptr);
    EXPECT_NE(find_set_env(o.set_env, "XDG_DATA_HOME"), nullptr);

    // ---- filesystem ----
    EXPECT_TRUE(contains(o.allow_read, "./src"));
    EXPECT_TRUE(contains(o.allow_read, "./README.md"));
    EXPECT_TRUE(contains(o.allow_write, "./out"));
    EXPECT_TRUE(contains(o.allow_write, "./target"));
    EXPECT_TRUE(contains(o.ext.fs_deny, "~/.ssh"));
    EXPECT_TRUE(contains(o.ext.fs_deny, "~/.aws"));
    ASSERT_TRUE(o.ext.fs_deny_by_default.has_value());
    EXPECT_TRUE(*o.ext.fs_deny_by_default);
    EXPECT_FALSE(o.ext.tripwire_enabled);
    EXPECT_TRUE(contains(o.ext.tripwire_files, "~/.ssh/id_rsa"));

    // ---- fontconfig / audit ----
    ASSERT_TRUE(o.fontconfig_enabled.has_value());
    EXPECT_TRUE(*o.fontconfig_enabled);
    ASSERT_TRUE(o.audit_log.has_value());
    EXPECT_EQ(*o.audit_log, ".raincoat/audit.log");

    // ---- backend toggles ----
    EXPECT_EQ(o.ext.backend.bwrap_path, "bwrap");
    EXPECT_TRUE(o.ext.backend.unshare_user);
    EXPECT_TRUE(o.ext.backend.unshare_cgroup);
    EXPECT_TRUE(o.ext.backend.unshare_net_when_off);
    EXPECT_TRUE(o.ext.backend.die_with_parent);
    EXPECT_FALSE(o.ext.backend.seccomp);

    // ---- init / report ----
    EXPECT_EQ(o.ext.init_create_dirs,
              (std::vector<std::string>{".raincoat", ".raincoat-work", "out"}));
    ASSERT_TRUE(o.ext.report_log.has_value());
    EXPECT_EQ(*o.ext.report_log, ".raincoat/audit.log");
    ASSERT_TRUE(o.ext.playful_report.has_value());
    EXPECT_TRUE(*o.ext.playful_report);

    // ---- proxy disabled here -> no proxy env injected ----
    EXPECT_EQ(find_set_env(o.set_env, "http_proxy"), nullptr);
    EXPECT_EQ(find_set_env(o.set_env, "https_proxy"), nullptr);
    EXPECT_EQ(find_set_env(o.set_env, "all_proxy"), nullptr);

    // ---- egress: PARSED into ext.egress this phase (no longer a reserved note) ----
    EXPECT_TRUE(o.ext.egress.enabled);
    EXPECT_EQ(o.ext.egress.mode, "bridge");
    EXPECT_TRUE(o.ext.egress.hide_upstreams_from_child);
    EXPECT_EQ(o.ext.egress.timeout_seconds, 120);
    ASSERT_EQ(o.ext.egress.bridges.size(), 2u);
    EXPECT_EQ(o.ext.egress.bridges[0].name, "primary-api");
    EXPECT_EQ(o.ext.egress.bridges[0].env, "SOME_BASE_URL");
    EXPECT_EQ(o.ext.egress.bridges[0].child_endpoint, "http://127.0.0.1:18080");
    EXPECT_FALSE(o.ext.egress.bridges[0].preserve_host);
    EXPECT_EQ(o.ext.egress.bridges[1].name, "secondary-api");
    EXPECT_EQ(o.ext.egress.bridges[1].env, "SECONDARY_BASE_URL");
    EXPECT_EQ(o.ext.egress.bridges[1].child_endpoint, "http://127.0.0.1:18081");
    // Egress is enforced this phase, so it must NOT appear as a reserved note.
    EXPECT_FALSE(any_contains(o.ext.reserved_notes, "egress"));

    // ---- browser: PARSED into ext.browser this phase ----
    // The fixture sets [browser] enabled=false, isolate_profile=true. The fields must
    // be parsed onto ext.browser; because it is configured but NOT enabled there is
    // nothing to apply, so it is still honestly disclosed as an inert reserved note.
    EXPECT_FALSE(o.ext.browser.enabled);
    EXPECT_TRUE(o.ext.browser.isolate_profile);
    EXPECT_TRUE(any_contains(o.ext.reserved_notes, "browser"));

    // ---- dns still reserved ----
    EXPECT_TRUE(any_contains(o.ext.reserved_notes, "dns"));

    // ---- network_policy: PARSED into ext.network_policy this phase (no reserved note) ----
    EXPECT_TRUE(o.ext.network_policy.enabled);
    EXPECT_EQ(o.ext.network_policy.default_action, "allow");
    EXPECT_EQ(o.ext.network_policy.allow_hosts,
              (std::vector<std::string>{"github.com", "api.github.com"}));
    EXPECT_EQ(o.ext.network_policy.block_hosts, (std::vector<std::string>{"ipinfo.io"}));
    // block_private_metadata_endpoints keeps its secure-by-default true when unspecified.
    EXPECT_TRUE(o.ext.network_policy.block_private_metadata_endpoints);
    EXPECT_FALSE(any_contains(o.ext.reserved_notes, "network_policy"));
}

// Regression (fix round 1): egress.timeout_seconds must be CLAMPED to a positive
// floor at load time. A value <= 0 would disable SO_RCVTIMEO and the slowloris
// wall-clock deadline in the bridge; since an active bridge shares the host net,
// any local process could then pin a worker thread and block EgressServer::stop()
// (and SIGINT teardown) indefinitely. The profile layer must never hand a non-
// positive timeout to the bridge.
TEST(Profile, EgressTimeoutZeroClampedToPositiveFloor) {
    std::string path = write_temp_file(
        "[egress]\n"
        "mode = \"bridge\"\n"
        "timeout_seconds = 0\n"
        "[[egress.bridge]]\n"
        "name = \"api\"\n"
        "env = \"BASE\"\n"
        "child_endpoint = \"http://127.0.0.1:18080\"\n"
        "upstream_endpoint = \"http://127.0.0.1:9\"\n");
    std::string err;
    auto opt = load_profile(path, err);
    ASSERT_TRUE(opt.has_value()) << "err=" << err;
    EXPECT_GE(opt->ext.egress.timeout_seconds, 1)
        << "timeout_seconds=0 must be clamped to a positive floor, not left disabled";
}

TEST(Profile, EgressTimeoutNegativeClampedToPositiveFloor) {
    std::string path = write_temp_file(
        "[egress]\n"
        "mode = \"bridge\"\n"
        "timeout_seconds = -30\n"
        "[[egress.bridge]]\n"
        "name = \"api\"\n"
        "env = \"BASE\"\n"
        "child_endpoint = \"http://127.0.0.1:18080\"\n"
        "upstream_endpoint = \"http://127.0.0.1:9\"\n");
    std::string err;
    auto opt = load_profile(path, err);
    ASSERT_TRUE(opt.has_value()) << "err=" << err;
    EXPECT_GE(opt->ext.egress.timeout_seconds, 1)
        << "negative timeout_seconds must be clamped to a positive floor";
}

// A normal positive value is preserved unchanged (the clamp only raises a bad floor).
TEST(Profile, EgressTimeoutPositiveValuePreserved) {
    std::string path = write_temp_file(
        "[egress]\n"
        "mode = \"bridge\"\n"
        "timeout_seconds = 45\n"
        "[[egress.bridge]]\n"
        "name = \"api\"\n"
        "env = \"BASE\"\n"
        "child_endpoint = \"http://127.0.0.1:18080\"\n"
        "upstream_endpoint = \"http://127.0.0.1:9\"\n");
    std::string err;
    auto opt = load_profile(path, err);
    ASSERT_TRUE(opt.has_value()) << "err=" << err;
    EXPECT_EQ(opt->ext.egress.timeout_seconds, 45);
}

// [egress].isolate_netns = "strict" (and its synonyms) parses to NetnsIsolation::Strict.
// Strict is the ONLY level that blocks general internet, so it must be an explicit,
// distinct value — never confused with auto/on/off.
TEST(Profile, EgressIsolateNetnsStrictParses) {
    for (const char* val : {"strict", "only-bridge", "egress-only", "bridge-only"}) {
        std::string path = write_temp_file(
            std::string("[egress]\n"
                        "mode = \"bridge\"\n"
                        "isolate_netns = \"") + val + "\"\n"
            "[[egress.bridge]]\n"
            "name = \"api\"\n"
            "env = \"BASE\"\n"
            "child_endpoint = \"http://127.0.0.1:18080\"\n"
            "upstream_endpoint = \"http://127.0.0.1:9\"\n");
        std::string err;
        auto opt = load_profile(path, err);
        ASSERT_TRUE(opt.has_value()) << "val=" << val << " err=" << err;
        EXPECT_EQ(opt->ext.egress.isolate_netns, raincoat::NetnsIsolation::Strict)
            << "isolate_netns = \"" << val << "\" must parse to Strict";
    }
}

// The canonical auto/on/off values still parse to their own levels (strict must not have
// swallowed them), and auto is NEVER strict — strict must be opted into explicitly.
TEST(Profile, EgressIsolateNetnsCanonicalLevelsUnchanged) {
    struct Case { const char* val; raincoat::NetnsIsolation want; };
    for (const Case& c : {Case{"auto", raincoat::NetnsIsolation::Auto},
                          Case{"on", raincoat::NetnsIsolation::On},
                          Case{"off", raincoat::NetnsIsolation::Off}}) {
        std::string path = write_temp_file(
            std::string("[egress]\n"
                        "mode = \"bridge\"\n"
                        "isolate_netns = \"") + c.val + "\"\n"
            "[[egress.bridge]]\n"
            "name = \"api\"\n"
            "env = \"BASE\"\n"
            "child_endpoint = \"http://127.0.0.1:18080\"\n"
            "upstream_endpoint = \"http://127.0.0.1:9\"\n");
        std::string err;
        auto opt = load_profile(path, err);
        ASSERT_TRUE(opt.has_value()) << "val=" << c.val << " err=" << err;
        EXPECT_EQ(opt->ext.egress.isolate_netns, c.want) << "val=" << c.val;
        EXPECT_NE(opt->ext.egress.isolate_netns, raincoat::NetnsIsolation::Strict)
            << "val=" << c.val << " must NOT be Strict (strict is explicit-only)";
    }
}

// Load the ACTUAL docs/full-config-reference.toml from the source tree (not the
// inline verbatim copy) and assert the egress bridge section parses end-to-end.
// This guards against the shipped reference config and the parser drifting apart.
TEST(Profile, DocsReferenceEgressBridgeParses) {
    std::filesystem::path doc =
        std::filesystem::path(RC_SOURCE_DIR) / "docs" / "full-config-reference.toml";
    ASSERT_TRUE(std::filesystem::exists(doc)) << "missing " << doc;

    std::string err;
    auto opt = load_profile(doc.string(), err);
    ASSERT_TRUE(opt.has_value()) << "err=" << err;
    const auto& eg = opt->ext.egress;

    EXPECT_TRUE(eg.enabled);
    EXPECT_EQ(eg.mode, "bridge");
    ASSERT_EQ(eg.bridges.size(), 2u);

    EXPECT_EQ(eg.bridges[0].name, "primary-api");
    EXPECT_EQ(eg.bridges[0].env, "SOME_BASE_URL");
    EXPECT_EQ(eg.bridges[0].child_endpoint, "http://127.0.0.1:18080");
    EXPECT_EQ(eg.bridges[0].upstream_endpoint, "https://real-upstream.example.com");
    EXPECT_FALSE(eg.bridges[0].preserve_host);
    EXPECT_FALSE(eg.bridges[0].strip_headers.empty());

    EXPECT_EQ(eg.bridges[1].name, "secondary-api");
    EXPECT_EQ(eg.bridges[1].env, "SECONDARY_BASE_URL");
    EXPECT_EQ(eg.bridges[1].child_endpoint, "http://127.0.0.1:18081");
    EXPECT_EQ(eg.bridges[1].upstream_endpoint,
              "https://secondary-upstream.example.com");
}

// The reserved network mode leaves net unset; resolve_config's value_or then picks
// the safe default. Verified here at the profile layer: strict=true + reserved mode
// => net unset (so downstream falls back to Off).
TEST(Profile, FullReferenceReservedNetworkLeavesNetUnset) {
    std::string path = write_temp_file(kFullConfigToml);
    std::string err;
    auto opt = load_profile(path, err);
    ASSERT_TRUE(opt.has_value()) << "err=" << err;
    EXPECT_TRUE(opt->strict);
    EXPECT_FALSE(opt->net.has_value());
}

// BUG (attack round 1, honesty): `[backend].seccomp` is a RESERVED knob — bwrap
// emits no seccomp filter for it and DESIGN.md ("RESERVED ... [backend].seccomp")
// requires it to be recorded in ext.reserved_notes so the audit says
// "configured, not yet enforced". Instead load_profile stores the bool into
// ext.backend.seccomp and records NOTHING: a profile that asks for `seccomp = true`
// gets no syscall filtering AND no honest disclosure, so the audit silently implies
// a hardening feature that does not exist. This test asserts the honest note is
// emitted; it FAILS today (reserved_notes is empty for a seccomp-only profile).
TEST(Profile, SeccompEnabledIsDisclosedAsReservedNotEnforced) {
    std::string path = write_temp_file("[backend]\nseccomp = true\n");
    std::string err;
    auto opt = load_profile(path, err);
    ASSERT_TRUE(opt.has_value()) << "err=" << err;
    // The value is carried (fine), but because it is NOT enforced it MUST be
    // disclosed as reserved so the audit is honest.
    EXPECT_TRUE(any_contains(opt->ext.reserved_notes, "seccomp"))
        << "seccomp = true is accepted but never enforced and never disclosed as "
           "reserved; the audit would silently imply syscall filtering that is not "
           "applied. reserved_notes = "
        << opt->ext.reserved_notes.size() << " entries";
}

// Proxy MECHANISM: when [proxy].enabled = true, the non-empty proxy vars are injected
// into set_env; empty ones (no_proxy = "") are skipped.
TEST(Profile, ProxyEnabledInjectsNonEmptyProxyEnv) {
    std::string path = write_temp_file(
        "[proxy]\n"
        "enabled = true\n"
        "http_proxy = \"http://127.0.0.1:18080\"\n"
        "https_proxy = \"http://127.0.0.1:18080\"\n"
        "all_proxy = \"socks5://127.0.0.1:18080\"\n"
        "no_proxy = \"\"\n");
    std::string err;
    auto opt = load_profile(path, err);
    ASSERT_TRUE(opt.has_value()) << "err=" << err;
    ASSERT_NE(find_set_env(opt->set_env, "http_proxy"), nullptr);
    EXPECT_EQ(*find_set_env(opt->set_env, "http_proxy"), "http://127.0.0.1:18080");
    EXPECT_NE(find_set_env(opt->set_env, "https_proxy"), nullptr);
    EXPECT_NE(find_set_env(opt->set_env, "all_proxy"), nullptr);
    // no_proxy is empty -> not injected.
    EXPECT_EQ(find_set_env(opt->set_env, "no_proxy"), nullptr);
}

// Reserved network modes must NOT be fatal (unlike allowlist/ask/banana): they load,
// leave net unset, and record a note.
TEST(Profile, ReservedNetworkModesLoadWithNote) {
    for (const char* mode : {"proxy", "bridge", "guarded"}) {
        std::string path =
            write_temp_file(std::string("network = \"") + mode + "\"\n");
        std::string err;
        auto opt = load_profile(path, err);
        ASSERT_TRUE(opt.has_value()) << "mode=" << mode << " err=" << err;
        EXPECT_FALSE(opt->net.has_value()) << "mode=" << mode;
        EXPECT_TRUE(any_contains(opt->ext.reserved_notes, "network")) << "mode=" << mode;
    }
}

// ===========================================================================
// Backward compatibility: a FLAT MVP profile still loads exactly as before,
// and populates NO ext (rich) fields.
// ===========================================================================

TEST(Profile, FlatMvpProfileStillLoadsUnchanged) {
    std::string path = write_temp_file(kSpecExampleToml);
    std::string err;
    auto opt = load_profile(path, err);
    ASSERT_TRUE(opt.has_value()) << "err=" << err;
    const Options& o = *opt;

    EXPECT_FALSE(o.strict);
    ASSERT_TRUE(o.net.has_value());
    EXPECT_EQ(*o.net, NetMode::Full);
    EXPECT_EQ(o.allow_read, (std::vector<std::string>{"./src"}));
    EXPECT_EQ(o.allow_write, (std::vector<std::string>{"./out"}));
    EXPECT_EQ(o.allow_env, (std::vector<std::string>{"OPENAI_API_KEY"}));
    EXPECT_EQ(o.env_defaults.at("TZ"), "UTC");
    ASSERT_TRUE(o.fontconfig_enabled.has_value());
    EXPECT_TRUE(*o.fontconfig_enabled);
    ASSERT_TRUE(o.audit_log.has_value());
    EXPECT_EQ(*o.audit_log, ".raincoat/audit.log");

    // No rich sections present -> ext stays at defaults, set_env empty.
    EXPECT_TRUE(o.set_env.empty());
    EXPECT_FALSE(o.ext.profile_name.has_value());
    EXPECT_FALSE(o.ext.hostname.has_value());
    EXPECT_FALSE(o.ext.username.has_value());
    EXPECT_TRUE(o.ext.env_deny.empty());
    EXPECT_TRUE(o.ext.scrub_patterns.empty());
    EXPECT_TRUE(o.ext.fs_deny.empty());
    EXPECT_FALSE(o.ext.fs_deny_by_default.has_value());
    EXPECT_TRUE(o.ext.init_create_dirs.empty());
    EXPECT_FALSE(o.ext.report_log.has_value());
    EXPECT_TRUE(o.ext.reserved_notes.empty());
}

// The nested [filesystem].allow_read/[environment].allow take precedence over the
// flat top-level allow_read/allow_env when BOTH are present.
TEST(Profile, NestedSectionTakesPrecedenceOverFlatKey) {
    std::string path = write_temp_file(
        "allow_read = [\"./flat-read\"]\n"
        "allow_env = [\"FLAT_ENV\"]\n"
        "[filesystem]\n"
        "allow_read = [\"./nested-read\"]\n"
        "[environment]\n"
        "allow = [\"NESTED_ENV\"]\n");
    std::string err;
    auto opt = load_profile(path, err);
    ASSERT_TRUE(opt.has_value()) << "err=" << err;
    EXPECT_EQ(opt->allow_read, (std::vector<std::string>{"./nested-read"}));
    EXPECT_EQ(opt->allow_env, (std::vector<std::string>{"NESTED_ENV"}));
}

// ===========================================================================
// Unknown keys/sections must be TOLERATED (never fatal).
// ===========================================================================

TEST(Profile, UnknownSectionsAndKeysAreTolerated) {
    std::string path = write_temp_file(
        "strict = true\n"
        "some_future_top_level_key = \"whatever\"\n"
        "another_number = 42\n"
        "[totally_unknown_section]\n"
        "flag = true\n"
        "value = \"x\"\n"
        "list = [\"a\", \"b\"]\n"
        "[identity]\n"
        "username = \"user\"\n"
        "unknown_identity_field = \"ignored\"\n"
        "[[unknown.array.of.tables]]\n"
        "k = \"v\"\n");
    std::string err;
    auto opt = load_profile(path, err);
    ASSERT_TRUE(opt.has_value()) << "err=" << err;
    EXPECT_TRUE(err.empty());
    EXPECT_TRUE(opt->strict);
    ASSERT_TRUE(opt->ext.username.has_value());
    EXPECT_EQ(*opt->ext.username, "user");
}

// merge() must carry the profile's ext through unchanged (the CLI has no ext today).
TEST(Profile, MergeCarriesProfileExt) {
    std::string path = write_temp_file(kFullConfigToml);
    std::string err;
    auto profile = load_profile(path, err);
    ASSERT_TRUE(profile.has_value()) << "err=" << err;

    Options cli;  // no ext
    Options m = merge(*profile, cli);

    ASSERT_TRUE(m.ext.profile_name.has_value());
    EXPECT_EQ(*m.ext.profile_name, "default-agent-sandbox");
    EXPECT_TRUE(contains(m.ext.env_deny, "SSH_AUTH_SOCK"));
    EXPECT_TRUE(contains(m.ext.fs_deny, "~/.ssh"));
    ASSERT_TRUE(m.ext.fs_deny_by_default.has_value());
    EXPECT_TRUE(*m.ext.fs_deny_by_default);
    EXPECT_FALSE(m.ext.reserved_notes.empty());
    EXPECT_EQ(m.ext.backend.bwrap_path, "bwrap");
    // Profile-derived set_env ([environment.set]) survives the merge.
    EXPECT_NE(find_set_env(m.set_env, "HOME"), nullptr);
}

// ===========================================================================
// [network_policy] parsing (phase 4). Enforced by the filtering forward proxy,
// so it is REAL parsed config (not a reserved note). An invalid default_action
// must be REJECTED, never silently defaulted to the fail-open "allow".
// ===========================================================================

TEST(Profile, NetworkPolicyDenyModeParsesEveryField) {
    std::string path = write_temp_file(
        "[network_policy]\n"
        "enabled = true\n"
        "default_action = \"deny\"\n"
        "allow_hosts = [\"github.com\", \"api.github.com\"]\n"
        "block_hosts = [\"evil.com\"]\n"
        "block_private_metadata_endpoints = false\n"
        "metadata_endpoints = [\"metadata.example.internal\"]\n");
    std::string err;
    auto opt = load_profile(path, err);
    ASSERT_TRUE(opt.has_value()) << "err=" << err;
    EXPECT_TRUE(err.empty());
    const NetworkPolicy& np = opt->ext.network_policy;
    EXPECT_TRUE(np.enabled);
    EXPECT_EQ(np.default_action, "deny");
    EXPECT_EQ(np.allow_hosts, (std::vector<std::string>{"github.com", "api.github.com"}));
    EXPECT_EQ(np.block_hosts, (std::vector<std::string>{"evil.com"}));
    EXPECT_FALSE(np.block_private_metadata_endpoints);
    EXPECT_EQ(np.metadata_endpoints,
              (std::vector<std::string>{"metadata.example.internal"}));
    // Enforced this phase: never surfaced as a reserved (unenforced) note.
    EXPECT_FALSE(any_contains(opt->ext.reserved_notes, "network_policy"));
}

TEST(Profile, NetworkPolicyDefaultsWhenSectionAbsent) {
    std::string path = write_temp_file("strict = true\n");
    std::string err;
    auto opt = load_profile(path, err);
    ASSERT_TRUE(opt.has_value()) << "err=" << err;
    const NetworkPolicy& np = opt->ext.network_policy;
    EXPECT_FALSE(np.enabled);
    EXPECT_EQ(np.default_action, "allow");
    EXPECT_TRUE(np.allow_hosts.empty());
    EXPECT_TRUE(np.block_hosts.empty());
    EXPECT_TRUE(np.block_private_metadata_endpoints);  // secure-by-default
}

TEST(Profile, NetworkPolicyRejectsInvalidDefaultAction) {
    std::string path = write_temp_file(
        "[network_policy]\n"
        "enabled = true\n"
        "default_action = \"den\"\n");
    std::string err;
    auto opt = load_profile(path, err);
    EXPECT_FALSE(opt.has_value());
    EXPECT_NE(err.find("default_action"), std::string::npos) << "err=" << err;
}

TEST(Profile, NetworkPolicyMergeCarriesThrough) {
    std::string path = write_temp_file(
        "[network_policy]\n"
        "enabled = true\n"
        "default_action = \"deny\"\n"
        "allow_hosts = [\"localhost\"]\n");
    std::string err;
    auto profile = load_profile(path, err);
    ASSERT_TRUE(profile.has_value()) << "err=" << err;
    Options cli;
    Options m = merge(*profile, cli);
    EXPECT_TRUE(m.ext.network_policy.enabled);
    EXPECT_EQ(m.ext.network_policy.default_action, "deny");
    EXPECT_EQ(m.ext.network_policy.allow_hosts, (std::vector<std::string>{"localhost"}));
}

// ---------------------------------------------------------------------------
// [browser] — parsed into ext.browser (phase 4). Enabled => enforced (no reserved
// note); every field maps; unknown keys are tolerated.
// ---------------------------------------------------------------------------
TEST(Profile, BrowserEnabledParsesEveryFieldNoReservedNote) {
    std::string path = write_temp_file(
        "[browser]\n"
        "enabled = true\n"
        "isolate_profile = true\n"
        "profile_dir = \"/tmp/rc-browser\"\n"
        "timezone = \"UTC\"\n"
        "locale = \"en-US\"\n"
        "viewport = \"1280x720\"\n"
        "disable_gpu = true\n"
        "disable_extensions = false\n"
        "disable_sync = true\n"
        "use_launch_shims = true\n");
    std::string err;
    auto opt = load_profile(path, err);
    ASSERT_TRUE(opt.has_value()) << "err=" << err;
    const auto& b = opt->ext.browser;
    EXPECT_TRUE(b.enabled);
    EXPECT_TRUE(b.isolate_profile);
    EXPECT_EQ(b.profile_dir, "/tmp/rc-browser");
    EXPECT_EQ(b.timezone, "UTC");
    EXPECT_EQ(b.locale, "en-US");
    EXPECT_EQ(b.viewport, "1280x720");
    EXPECT_TRUE(b.disable_gpu);
    EXPECT_FALSE(b.disable_extensions);
    EXPECT_TRUE(b.disable_sync);
    EXPECT_TRUE(b.use_launch_shims);
    // Enabled => enforced this phase, so NOT disclosed as a reserved/unenforced note.
    EXPECT_FALSE(any_contains(opt->ext.reserved_notes, "browser"));
}

TEST(Profile, BrowserConfiguredButDisabledIsDisclosedAsInert) {
    std::string path = write_temp_file("[browser]\nenabled = false\n");
    std::string err;
    auto opt = load_profile(path, err);
    ASSERT_TRUE(opt.has_value()) << "err=" << err;
    EXPECT_FALSE(opt->ext.browser.enabled);
    // Configured but not enabled: honestly disclosed (nothing applied).
    EXPECT_TRUE(any_contains(opt->ext.reserved_notes, "browser"));
}

TEST(Profile, BrowserMergeCarriesThrough) {
    std::string path = write_temp_file(
        "[browser]\nenabled = true\nuse_launch_shims = true\nlocale = \"fr-FR\"\n");
    std::string err;
    auto profile = load_profile(path, err);
    ASSERT_TRUE(profile.has_value()) << "err=" << err;
    Options cli;
    Options m = merge(*profile, cli);
    EXPECT_TRUE(m.ext.browser.enabled);
    EXPECT_TRUE(m.ext.browser.use_launch_shims);
    EXPECT_EQ(m.ext.browser.locale, "fr-FR");
}
