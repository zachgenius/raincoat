// Raincoat — seccomp user-notify supervisor for faking identity syscalls.
//
// Tier-2 fingerprint masking (see docs/FINGERPRINT-SYSCALLS.md): the /proc file overlays hide
// the host from *file* reads, but the underlying SYSCALLS still return the real host to a
// static/Go binary that issues them directly. This module installs a seccomp filter that traps
// a configurable set of identity syscalls as SECCOMP_RET_USER_NOTIF and services them from a
// supervisor in the (unfiltered) parent, writing fake results into the child's buffers.
//
// Currently: uname(2) and sysinfo(2). Linux-only, x86_64-only (syscall numbers are per-arch).
// Best-effort: every entry point fails soft so an unsupported kernel just leaves the syscalls
// real, exactly like the other masks.
#pragma once

#include <atomic>
#include <array>
#include <cstdint>
#include <string>
#include <vector>

#include <linux/filter.h>

namespace raincoat {

// The six NUL-terminated fields of `struct new_utsname`, each 65 bytes on Linux.
constexpr std::size_t kUtsField = 65;
constexpr std::size_t kUtsFields = 6;
constexpr std::size_t kUtsBufLen = kUtsField * kUtsFields;  // 390

// What the child sees from uname(2). Kept consistent with the /proc file masks.
struct UtsnameSpoof {
    std::string sysname = "Linux";
    std::string nodename = "sandbox";
    std::string release = "6.1.0-generic";
    std::string version = "#1 SMP PREEMPT_DYNAMIC Generic";
    std::string machine = "x86_64";
    std::string domainname = "(none)";
};

// What the child sees from sysinfo(2). Kept consistent with the /proc/meminfo + /proc/uptime
// overlays. Values are bytes / seconds / counts; the supervisor packs them into `struct
// sysinfo` (mem_unit = 1).
struct SysinfoSpoof {
    std::uint64_t uptime_seconds = 3600;                     // 1h — a neutral constant
    std::uint64_t total_ram_bytes = 16ULL * 1024 * 1024 * 1024;  // 16 GiB
    std::uint64_t free_ram_bytes = 8ULL * 1024 * 1024 * 1024;    // 8 GiB
    std::uint16_t procs = 128;
};

// The full set of values the supervisor hands back, plus which syscalls to trap.
struct IdentitySpoof {
    bool trap_uname = false;
    bool trap_sysinfo = false;
    UtsnameSpoof uts;
    SysinfoSpoof sys;
};

// PURE + testable. Classic-BPF program: USER_NOTIF for the requested syscalls on x86_64,
// ALLOW for everything else (including non-x86_64 personalities). With neither flag set it is
// a bare ALLOW.
std::vector<sock_filter> build_identity_filter_program(bool trap_uname, bool trap_sysinfo);

// PURE + testable. Pack the spoof into the 390-byte `struct new_utsname` wire layout (six
// 65-byte NUL-padded fields), truncating any over-long field to fit.
std::array<char, kUtsBufLen> pack_new_utsname(const UtsnameSpoof& s);

// CHILD side (post-fork, pre-execve). Set no_new_privs, install `prog` (built by the parent so
// this path allocates nothing) with SECCOMP_FILTER_FLAG_NEW_LISTENER, and send the returned
// listener fd to the parent over `sock_fd` (SCM_RIGHTS). Returns 0 on success, -1 on failure.
int seccomp_child_install_and_send(int sock_fd, const sock_filter* prog, unsigned int len);

// PARENT side. Receive the listener fd the child sent over `sock_fd` (SCM_RIGHTS).
// Returns the fd (>=0) or -1 on failure.
int seccomp_recv_listener_fd(int sock_fd);

// PARENT side. Service identity notifications on `listener_fd` until `stop` is set (checked on
// a short poll timeout) or the filtered process tree is gone. Dispatches per trapped syscall,
// writing fakes into the caller's buffer, guarding PID reuse with NOTIF_ID_VALID. Intended to
// run on its own thread so it never contends with the main thread's waitpid().
void seccomp_supervise_identity(int listener_fd, const IdentitySpoof& spoof,
                                std::atomic<bool>& stop);

// True iff this build/host can run the notifier (x86_64).
bool seccomp_identity_supported();

}  // namespace raincoat
