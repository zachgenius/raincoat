// Raincoat — tests for the seccomp identity notifier: the PURE parts (BPF program shape,
// new_utsname wire packing) plus a live integration test that installs the filter and checks
// the supervisor actually fakes uname(2)/sysinfo(2)/sched_getaffinity(2) at runtime.
#include <gtest/gtest.h>

#include <atomic>
#include <cstring>
#include <string>
#include <thread>

#include <sched.h>
#include <sys/socket.h>
#include <sys/sysinfo.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>

#include <linux/filter.h>
#include <linux/seccomp.h>

#include "seccomp_notify.hpp"

using namespace raincoat;

// ---------------------------------------------------------------------------
// BPF program shape (x86_64): traps uname as USER_NOTIF, everything else ALLOW.
// ---------------------------------------------------------------------------

// Count RET instructions with a given k value.
static int countRet(const std::vector<sock_filter>& p, __u32 k) {
    int c = 0;
    for (const auto& i : p)
        if (i.code == (BPF_RET | BPF_K) && i.k == k) ++c;
    return c;
}

#if defined(__x86_64__)
TEST(SeccompNotify, ProgramTrapsRequestedSyscalls) {
    // uname only: one USER_NOTIF match arm.
    auto u = build_identity_filter_program(true, false, false);
    EXPECT_EQ(u[0].code, (BPF_LD | BPF_W | BPF_ABS));  // load arch first
    EXPECT_EQ(countRet(u, static_cast<__u32>(SECCOMP_RET_USER_NOTIF)), 1);
    EXPECT_EQ(countRet(u, static_cast<__u32>(SECCOMP_RET_ALLOW)), 1);

    // all three: still a single shared USER_NOTIF return, reached by three JEQ arms.
    auto all = build_identity_filter_program(true, true, true);
    EXPECT_EQ(countRet(all, static_cast<__u32>(SECCOMP_RET_USER_NOTIF)), 1);
    // More JEQ-on-nr arms => `all` is longer than the uname-only program.
    EXPECT_GT(all.size(), u.size());
}

TEST(SeccompNotify, NeitherTrapIsPureAllow) {
    auto p = build_identity_filter_program(false, false, false);
    EXPECT_EQ(countRet(p, static_cast<__u32>(SECCOMP_RET_USER_NOTIF)), 0);
    EXPECT_GE(countRet(p, static_cast<__u32>(SECCOMP_RET_ALLOW)), 1);
}

TEST(SeccompNotify, AffinityOnlyStillTraps) {
    auto p = build_identity_filter_program(false, false, true);
    EXPECT_EQ(countRet(p, static_cast<__u32>(SECCOMP_RET_USER_NOTIF)), 1);
}

TEST(SeccompNotify, SupportedOnX86) { EXPECT_TRUE(seccomp_identity_supported()); }
#endif

TEST(SeccompNotify, ProgramEndsInARet) {
    // On any arch the program must terminate in a RET (never fall off the end).
    auto p = build_identity_filter_program(true, true, true);
    ASSERT_FALSE(p.empty());
    EXPECT_EQ(p.back().code, (BPF_RET | BPF_K));
}

// ---------------------------------------------------------------------------
// new_utsname wire packing: six 65-byte NUL-terminated fields, 390 bytes total.
// ---------------------------------------------------------------------------

// Read field `i` (0..5) out of the packed buffer as a C string.
static std::string field(const std::array<char, kUtsBufLen>& b, std::size_t i) {
    const char* p = b.data() + i * kUtsField;
    // Guaranteed NUL-terminated within the field by the packer.
    return std::string(p);
}

TEST(SeccompNotify, PacksAllSixFieldsInOrder) {
    UtsnameSpoof s;
    s.sysname = "Linux";
    s.nodename = "sandbox";
    s.release = "6.1.0-generic";
    s.version = "#1 SMP GENERIC";
    s.machine = "x86_64";
    s.domainname = "(none)";
    auto b = pack_new_utsname(s);
    EXPECT_EQ(b.size(), 390u);
    EXPECT_EQ(field(b, 0), "Linux");
    EXPECT_EQ(field(b, 1), "sandbox");
    EXPECT_EQ(field(b, 2), "6.1.0-generic");
    EXPECT_EQ(field(b, 3), "#1 SMP GENERIC");
    EXPECT_EQ(field(b, 4), "x86_64");
    EXPECT_EQ(field(b, 5), "(none)");
}

TEST(SeccompNotify, PadsUnusedBytesWithNul) {
    UtsnameSpoof s;  // defaults
    auto b = pack_new_utsname(s);
    // The byte right after "Linux" (5 chars) in field 0 must be NUL, and so must the
    // last byte of every field (the reserved terminator slot).
    EXPECT_EQ(b[5], '\0');
    for (std::size_t i = 0; i < kUtsFields; ++i)
        EXPECT_EQ(b[i * kUtsField + (kUtsField - 1)], '\0');
}

TEST(SeccompNotify, TruncatesOverlongFieldAndKeepsNul) {
    UtsnameSpoof s;
    s.release = std::string(200, 'A');  // longer than the 65-byte field
    s.version = "SENTINEL";             // the following field must stay intact
    auto b = pack_new_utsname(s);
    // Exactly 64 'A's then a NUL terminator (last byte of the 65-byte field).
    const char* rel = b.data() + 2 * kUtsField;
    EXPECT_EQ(std::strlen(rel), kUtsField - 1);  // 64
    EXPECT_EQ(rel[kUtsField - 1], '\0');         // terminator preserved
    // The overflow must not have bled into the next field.
    EXPECT_EQ(field(b, 3), "SENTINEL");
}

// ---------------------------------------------------------------------------
// Live integration: install the filter in a child and verify the supervisor fakes
// uname(2)/sysinfo(2)/sched_getaffinity(2) at the SYSCALL level. Self-contained (no bwrap).
// Skips gracefully when unprivileged seccomp user-notify is unavailable on the host.
// ---------------------------------------------------------------------------
#if defined(__x86_64__)

// Child exit codes report which stage failed (parent turns these into assertions).
enum : int { CX_OK = 0, CX_INSTALL = 10, CX_UNAME = 11, CX_SYSINFO = 12, CX_AFFINITY = 13 };

static constexpr unsigned long kFakeUptime = 4321;
static constexpr unsigned long long kFakeRamBytes = 2ULL * 1024 * 1024 * 1024;  // 2 GiB
static constexpr int kFakeCpus = 3;

TEST(SeccompNotifyLive, FakesUnameSysinfoAffinity) {
    int sock[2];
    ASSERT_EQ(::socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sock), 0);

    pid_t pid = ::fork();
    ASSERT_GE(pid, 0);
    if (pid == 0) {
        // ---- child ----
        ::close(sock[0]);
        auto prog = build_identity_filter_program(true, true, true);
        if (seccomp_child_install_and_send(sock[1], prog.data(),
                                           static_cast<unsigned int>(prog.size())) != 0)
            _exit(CX_INSTALL);
        // Filter is now active; these calls trap to the parent supervisor.
        struct utsname u;
        if (::uname(&u) != 0 || std::strcmp(u.nodename, "testhost") != 0 ||
            std::strcmp(u.release, "TESTREL") != 0 || std::strcmp(u.version, "TESTVER") != 0)
            _exit(CX_UNAME);
        struct sysinfo si;
        if (::sysinfo(&si) != 0 || static_cast<unsigned long>(si.uptime) != kFakeUptime ||
            static_cast<unsigned long long>(si.totalram) != kFakeRamBytes)
            _exit(CX_SYSINFO);
        cpu_set_t cs;
        CPU_ZERO(&cs);
        if (::sched_getaffinity(0, sizeof(cs), &cs) != 0 || CPU_COUNT(&cs) != kFakeCpus)
            _exit(CX_AFFINITY);
        _exit(CX_OK);
    }

    // ---- parent (supervisor) ----
    ::close(sock[1]);
    int lfd = seccomp_recv_listener_fd(sock[0]);
    ::close(sock[0]);
    if (lfd < 0) {
        // Child could not install the filter (kernel/policy lacks unprivileged user-notify).
        int st = 0;
        ::waitpid(pid, &st, 0);
        GTEST_SKIP() << "seccomp user-notify unavailable on this host";
    }

    IdentitySpoof spoof;
    spoof.trap_uname = spoof.trap_sysinfo = spoof.trap_affinity = true;
    spoof.uts_nodename = "testhost";
    spoof.uts_release = "TESTREL";
    spoof.uts_version = "TESTVER";
    spoof.sys_uptime_seconds = kFakeUptime;
    spoof.sys_total_ram_bytes = kFakeRamBytes;
    spoof.cpu_count = kFakeCpus;

    std::atomic<bool> stop{false};
    std::thread sup(seccomp_supervise_identity, lfd, spoof, std::ref(stop));

    int status = 0;
    ASSERT_EQ(::waitpid(pid, &status, 0), pid);
    stop.store(true);
    sup.join();
    ::close(lfd);

    ASSERT_TRUE(WIFEXITED(status));
    const int code = WEXITSTATUS(status);
    EXPECT_EQ(code, CX_OK) << "child failed at stage "
                           << (code == CX_INSTALL  ? "install"
                               : code == CX_UNAME    ? "uname"
                               : code == CX_SYSINFO  ? "sysinfo"
                               : code == CX_AFFINITY ? "affinity"
                                                     : "unknown");
}

#endif  // __x86_64__
