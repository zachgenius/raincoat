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
#include <unistd.h>

#include <linux/audit.h>
#include <linux/seccomp.h>

namespace raincoat {

#if defined(__x86_64__)
// USER_NOTIF for uname(2) on x86_64, ALLOW everything else. Static + const so the child can
// point a sock_fprog at it between fork() and execve() without any heap allocation.
static const struct sock_filter kUnameProg[] = {
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
    // arch != x86_64 -> ALLOW (idx 5). Non-x86_64 personalities pass through untouched.
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 0, 3),
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
    // nr != uname -> ALLOW (idx 5).
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_uname, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
};
#endif

std::vector<sock_filter> build_uname_filter_program() {
#if defined(__x86_64__)
    const std::size_t n = sizeof(kUnameProg) / sizeof(kUnameProg[0]);
    return std::vector<sock_filter>(kUnameProg, kUnameProg + n);
#else
    struct sock_filter allow = BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
    return std::vector<sock_filter>{allow};
#endif
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

bool seccomp_uname_supported() {
#if defined(__x86_64__)
    return true;
#else
    return false;
#endif
}

int seccomp_child_install_and_send(int sock_fd) {
#if defined(__x86_64__)
    if (::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) return -1;

    struct sock_fprog prog;
    prog.len = static_cast<unsigned short>(sizeof(kUnameProg) / sizeof(kUnameProg[0]));
    prog.filter = const_cast<struct sock_filter*>(kUnameProg);

    const long lfd = ::syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER,
                               SECCOMP_FILTER_FLAG_NEW_LISTENER, &prog);
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

void seccomp_supervise_uname(int listener_fd, const UtsnameSpoof& spoof,
                             std::atomic<bool>& stop) {
#if defined(__x86_64__)
    const std::array<char, kUtsBufLen> buf = pack_new_utsname(spoof);

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

        if (req.data.nr == __NR_uname) {
            // The caller is blocked in uname() until we SEND, so args[0] (its `struct
            // utsname*`) and its memory are stable. Write the fake struct straight into it.
            char path[64];
            std::snprintf(path, sizeof(path), "/proc/%u/mem", static_cast<unsigned>(req.pid));
            bool ok = false;
            const int mfd = ::open(path, O_WRONLY);
            if (mfd >= 0) {
                // Guard PID reuse: only trust req.pid while the notify id is still valid.
                if (::ioctl(listener_fd, SECCOMP_IOCTL_NOTIF_ID_VALID, &req.id) == 0) {
                    const off_t addr = static_cast<off_t>(req.data.args[0]);
                    const ssize_t w = ::pwrite(mfd, buf.data(), buf.size(), addr);
                    ok = (w == static_cast<ssize_t>(buf.size()));
                }
                ::close(mfd);
            }
            if (!ok) resp.error = -EFAULT;  // make uname() fail cleanly rather than lie half-way
        }

        if (::ioctl(listener_fd, SECCOMP_IOCTL_NOTIF_SEND, &resp) != 0) {
            // ENOENT: caller died between RECV and SEND — just move on.
            if (errno == ENOENT || errno == EINTR) continue;
        }
    }
#else
    (void)listener_fd;
    (void)spoof;
    (void)stop;
#endif
}

}  // namespace raincoat
