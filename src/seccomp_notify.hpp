// Raincoat — seccomp user-notify supervisor for faking identity syscalls.
//
// Tier-2 fingerprint masking (see docs/FINGERPRINT-SYSCALLS.md): the /proc file overlays
// hide the host CPU/kernel from *file* reads, but the uname(2) SYSCALL still returns the
// real host to a static/Go binary that issues it directly. This module installs a seccomp
// filter that traps uname(2) as SECCOMP_RET_USER_NOTIF and services it from a supervisor in
// the (unfiltered) parent, writing a fake `struct new_utsname` into the child's buffer.
//
// Linux-only, x86_64-only for now (syscall numbers are per-arch). Best-effort: every entry
// point fails soft (returns an error the caller ignores) so an unsupported kernel just leaves
// uname() real, exactly like the other masks.
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

// PURE + testable. The classic-BPF program: USER_NOTIF for uname(2) on x86_64, ALLOW for
// everything else (including non-x86_64 personalities, which pass through untouched).
std::vector<sock_filter> build_uname_filter_program();

// PURE + testable. Pack the spoof into the exact 390-byte `struct new_utsname` wire layout
// (six 65-byte NUL-padded fields), truncating any over-long field to fit.
std::array<char, kUtsBufLen> pack_new_utsname(const UtsnameSpoof& s);

// CHILD side (post-fork, pre-execve). Set no_new_privs, install the uname filter with
// SECCOMP_FILTER_FLAG_NEW_LISTENER, and send the returned listener fd to the parent over
// `sock_fd` (SCM_RIGHTS). Returns 0 on success, -1 on any failure (errno set). Uses only
// raw syscalls / stack storage — safe to call between fork() and execve() in a process that
// may have other threads. On a non-x86_64 host it is a no-op success (nothing to trap).
int seccomp_child_install_and_send(int sock_fd);

// PARENT side. Receive the listener fd the child sent over `sock_fd` (SCM_RIGHTS).
// Returns the fd (>=0) or -1 on failure.
int seccomp_recv_listener_fd(int sock_fd);

// PARENT side. Service uname notifications on `listener_fd` until `stop` is set (checked on a
// short poll timeout) or the filtered process tree is gone. Writes `spoof` into each caller's
// buffer, guarding PID reuse with SECCOMP_IOCTL_NOTIF_ID_VALID. Intended to run on its own
// thread so it never contends with the main thread's waitpid().
void seccomp_supervise_uname(int listener_fd, const UtsnameSpoof& spoof,
                             std::atomic<bool>& stop);

// True iff this build/host can run the uname notifier (x86_64). Lets the runner decide
// whether to set up the socketpair + supervisor at all.
bool seccomp_uname_supported();

}  // namespace raincoat
