// Raincoat — seccomp user-notify supervisor for faking identity syscalls (see header).
#include "seccomp_notify.hpp"

#include <algorithm>
#include <cerrno>
#include <cstddef>
#include <cstdio>
#include <cstring>

#include <fcntl.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/sysinfo.h>
#include <sys/utsname.h>
#include <unistd.h>

#include <linux/audit.h>
#include <linux/seccomp.h>

namespace raincoat {

std::vector<sock_filter> build_identity_filter_program(bool trap_uname, bool trap_sysinfo) {
    std::vector<sock_filter> p;
    if (!trap_uname && !trap_sysinfo) {  // nothing to trap -> bare ALLOW
        p.push_back(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));
        return p;
    }
#if defined(__x86_64__)
    // Load arch; if it is not x86_64, jump straight to the trailing ALLOW (we only know
    // x86_64 syscall numbers). The offset is computed after the body is built.
    p.push_back(BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)));
    p.push_back(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 0, 0));  // jf patched
    const std::size_t arch_jmp = p.size() - 1;

    // Load nr, then one JEQ per trapped syscall that jumps to the USER_NOTIF return.
    p.push_back(BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)));
    std::vector<std::size_t> match_jumps;
    auto add_match = [&](int nr) {
        p.push_back(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, static_cast<__u32>(nr), 0, 0));  // jt patched
        match_jumps.push_back(p.size() - 1);
    };
    if (trap_uname) add_match(__NR_uname);
    if (trap_sysinfo) add_match(__NR_sysinfo);

    // Fall-through (no match) -> ALLOW; then the USER_NOTIF return.
    p.push_back(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));
    const std::size_t allow_idx = p.size() - 1;
    p.push_back(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF));
    const std::size_t notif_idx = p.size() - 1;

    // Patch jump offsets (relative to the instruction AFTER the jump).
    p[arch_jmp].jf = static_cast<__u8>(allow_idx - arch_jmp - 1);
    for (std::size_t j : match_jumps) p[j].jt = static_cast<__u8>(notif_idx - j - 1);
#else
    (void)trap_uname;
    (void)trap_sysinfo;
    p.push_back(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));
#endif
    return p;
}

std::array<char, kUtsBufLen> pack_new_utsname(const UtsnameSpoof& s) {
    std::array<char, kUtsBufLen> b{};  // zero-filled => fields NUL-padded for free
    auto put = [&](std::size_t field, const std::string& v) {
        char* dst = b.data() + field * kUtsField;
        const std::size_t n = std::min(v.size(), kUtsField - 1);  // keep the trailing NUL
        std::memcpy(dst, v.data(), n);
    };
    put(0, s.sysname);
    put(1, s.nodename);
    put(2, s.release);
    put(3, s.version);
    put(4, s.machine);
    put(5, s.domainname);
    return b;
}

bool seccomp_identity_supported() {
#if defined(__x86_64__)
    return true;
#else
    return false;
#endif
}

int seccomp_child_install_and_send(int sock_fd, const sock_filter* prog, unsigned int len) {
#if defined(__x86_64__)
    if (::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) return -1;

    struct sock_fprog fprog;
    fprog.len = static_cast<unsigned short>(len);
    fprog.filter = const_cast<struct sock_filter*>(prog);

    const long lfd = ::syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER,
                               SECCOMP_FILTER_FLAG_NEW_LISTENER, &fprog);
    if (lfd < 0) return -1;

    // Hand the listener fd to the parent (SCM_RIGHTS needs >=1 payload byte).
    char dummy = 'F';
    struct iovec iov;
    iov.iov_base = &dummy;
    iov.iov_len = 1;

    union {
        char buf[CMSG_SPACE(sizeof(int))];
        struct cmsghdr align;
    } u;
    std::memset(&u, 0, sizeof(u));

    struct msghdr msg;
    std::memset(&msg, 0, sizeof(msg));
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = u.buf;
    msg.msg_controllen = sizeof(u.buf);

    struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));
    const int fdint = static_cast<int>(lfd);
    std::memcpy(CMSG_DATA(cmsg), &fdint, sizeof(int));

    ssize_t n;
    do {
        n = ::sendmsg(sock_fd, &msg, 0);
    } while (n < 0 && errno == EINTR);

    ::close(static_cast<int>(lfd));  // parent holds its own copy after SCM_RIGHTS
    return (n < 0) ? -1 : 0;
#else
    (void)sock_fd;
    (void)prog;
    (void)len;
    return 0;  // nothing to trap on non-x86_64
#endif
}

int seccomp_recv_listener_fd(int sock_fd) {
    char dummy = 0;
    struct iovec iov;
    iov.iov_base = &dummy;
    iov.iov_len = 1;

    union {
        char buf[CMSG_SPACE(sizeof(int))];
        struct cmsghdr align;
    } u;
    std::memset(&u, 0, sizeof(u));

    struct msghdr msg;
    std::memset(&msg, 0, sizeof(msg));
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = u.buf;
    msg.msg_controllen = sizeof(u.buf);

    ssize_t n;
    do {
        n = ::recvmsg(sock_fd, &msg, 0);
    } while (n < 0 && errno == EINTR);
    if (n < 0) return -1;

    struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
    if (!cmsg || cmsg->cmsg_level != SOL_SOCKET || cmsg->cmsg_type != SCM_RIGHTS ||
        cmsg->cmsg_len != CMSG_LEN(sizeof(int))) {
        return -1;
    }
    int fd = -1;
    std::memcpy(&fd, CMSG_DATA(cmsg), sizeof(int));
    return fd;
}

#if defined(__x86_64__)
// Write `len` bytes from `src` into the trapped caller's memory at `addr`. The caller is
// blocked in the syscall until we SEND, so its buffer is stable; we only guard PID reuse.
static bool write_child_mem(int listener_fd, const struct seccomp_notif& req, const void* src,
                            std::size_t len) {
    char path[64];
    std::snprintf(path, sizeof(path), "/proc/%u/mem", static_cast<unsigned>(req.pid));
    const int mfd = ::open(path, O_WRONLY);
    if (mfd < 0) return false;
    bool ok = false;
    __u64 id = req.id;
    if (::ioctl(listener_fd, SECCOMP_IOCTL_NOTIF_ID_VALID, &id) == 0) {
        const off_t addr = static_cast<off_t>(req.data.args[0]);
        const ssize_t w = ::pwrite(mfd, src, len, addr);
        ok = (w == static_cast<ssize_t>(len));
    }
    ::close(mfd);
    return ok;
}
#endif

void seccomp_supervise_identity(int listener_fd, const IdentitySpoof& spoof,
                                std::atomic<bool>& stop) {
#if defined(__x86_64__)
    for (;;) {
        if (stop.load()) break;

        struct pollfd pfd;
        pfd.fd = listener_fd;
        pfd.events = POLLIN;
        pfd.revents = 0;
        const int pr = ::poll(&pfd, 1, 200);  // short timeout so `stop` is honored promptly
        if (pr < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (pr == 0) continue;  // timeout -> re-check stop
        if (pfd.revents & (POLLHUP | POLLERR)) break;
        if (!(pfd.revents & POLLIN)) continue;

        struct seccomp_notif req;
        std::memset(&req, 0, sizeof(req));
        if (::ioctl(listener_fd, SECCOMP_IOCTL_NOTIF_RECV, &req) != 0) {
            if (errno == EINTR) continue;
            break;  // ENOENT/ENOTCONN: the filtered process tree is gone
        }

        struct seccomp_notif_resp resp;
        std::memset(&resp, 0, sizeof(resp));
        resp.id = req.id;
        resp.val = 0;
        resp.error = 0;

        bool ok = true;
        if (req.data.nr == __NR_uname) {
            // Baseline from the host's REAL uname, then override only the requested fields
            // (nodename always; release/version when set) so unset fields stay the real value.
            UtsnameSpoof u;
            struct utsname real;
            if (::uname(&real) == 0) {
                u.sysname = real.sysname;
                u.release = real.release;
                u.version = real.version;
                u.machine = real.machine;
            }
            u.nodename = spoof.uts_nodename;
            if (spoof.uts_release) u.release = *spoof.uts_release;
            if (spoof.uts_version) u.version = *spoof.uts_version;
            const std::array<char, kUtsBufLen> buf = pack_new_utsname(u);
            ok = write_child_mem(listener_fd, req, buf.data(), buf.size());
        } else if (req.data.nr == __NR_sysinfo) {
            // Baseline from the host's REAL sysinfo, then override memory / uptime when set.
            struct sysinfo si;
            if (::sysinfo(&si) == 0) {
                if (spoof.sys_uptime_seconds)
                    si.uptime = static_cast<long>(*spoof.sys_uptime_seconds);
                if (spoof.sys_total_ram_bytes) {
                    si.totalram = *spoof.sys_total_ram_bytes;
                    si.freeram = *spoof.sys_total_ram_bytes / 2;
                    si.sharedram = 0;
                    si.bufferram = 0;
                    si.totalswap = 0;
                    si.freeswap = 0;
                    si.totalhigh = 0;
                    si.freehigh = 0;
                    si.mem_unit = 1;  // totalram/freeram are now in bytes
                }
                ok = write_child_mem(listener_fd, req, &si, sizeof(si));
            } else {
                ok = false;
            }
        }
        // else: a syscall we did not mean to trap — answer success (val=0) harmlessly.
        if (!ok) resp.error = -EFAULT;  // make the syscall fail cleanly rather than half-lie

        if (::ioctl(listener_fd, SECCOMP_IOCTL_NOTIF_SEND, &resp) != 0) {
            if (errno == ENOENT || errno == EINTR) continue;  // caller died mid-handle
        }
    }
#else
    (void)listener_fd;
    (void)spoof;
    (void)stop;
#endif
}

}  // namespace raincoat
