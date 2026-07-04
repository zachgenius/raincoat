// Raincoat — tests for the PURE, host-independent parts of the seccomp uname notifier:
// the BPF program shape and the new_utsname wire packing. The syscall machinery itself
// (filter install, supervisor loop) is exercised end-to-end by the runner, not here.
#include <gtest/gtest.h>

#include <cstring>
#include <string>

#include <linux/filter.h>
#include <linux/seccomp.h>

#include "seccomp_notify.hpp"

using namespace raincoat;

// ---------------------------------------------------------------------------
// BPF program shape (x86_64): traps uname as USER_NOTIF, everything else ALLOW.
// ---------------------------------------------------------------------------

#if defined(__x86_64__)
TEST(SeccompNotify, ProgramTrapsUnameAllowsRest) {
    auto p = build_uname_filter_program();
    ASSERT_EQ(p.size(), 6u);
    // Structure: LD arch / JEQ arch / LD nr / JEQ uname / RET USER_NOTIF / RET ALLOW.
    EXPECT_EQ(p[0].code, (BPF_LD | BPF_W | BPF_ABS));
    EXPECT_EQ(p[1].code, (BPF_JMP | BPF_JEQ | BPF_K));
    EXPECT_EQ(p[3].code, (BPF_JMP | BPF_JEQ | BPF_K));
    EXPECT_EQ(p[4].code, (BPF_RET | BPF_K));
    EXPECT_EQ(p[4].k, static_cast<__u32>(SECCOMP_RET_USER_NOTIF));
    EXPECT_EQ(p[5].code, (BPF_RET | BPF_K));
    EXPECT_EQ(p[5].k, static_cast<__u32>(SECCOMP_RET_ALLOW));
}

TEST(SeccompNotify, SupportedOnX86) { EXPECT_TRUE(seccomp_uname_supported()); }
#endif

TEST(SeccompNotify, ProgramEndsInAllow) {
    // On any arch the program must terminate in a RET (never fall off the end).
    auto p = build_uname_filter_program();
    ASSERT_FALSE(p.empty());
    EXPECT_EQ(p.back().code, (BPF_RET | BPF_K));
    EXPECT_EQ(p.back().k, static_cast<__u32>(SECCOMP_RET_ALLOW));
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
