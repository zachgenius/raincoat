// Raincoat — macOS identity interposer (best-effort Tier-2 fingerprint faking).
//
// A tiny __DATA,__interpose dylib injected into the sandboxed child via
// DYLD_INSERT_LIBRARIES. It rewrites the return of a few libc identity/fingerprint calls
// that Seatbelt cannot fake (it only allows/denies) — closing the hostname, username, and
// CPU/kernel/RAM leaks. Fake values come from RC_FAKE_* env vars the runner sets; an unset
// (or empty) var means "don't fake this one — return the real value".
//
// HONEST LIMITS (see docs/MACOS.md / docs/FINGERPRINT-SYSCALLS.md):
//   * Interposition only affects dynamically-linked libc callers. A static binary, or one
//     issuing a raw syscall / Mach trap, bypasses it — macOS has no seccomp-notify backstop.
//   * SIP-protected / hardened-runtime binaries ignore DYLD_INSERT_LIBRARIES entirely, so
//     they are never faked. This is why the runner applies the Seatbelt profile in-process
//     (sandbox_init) and execs the target itself, instead of going through the SIP-protected
//     /usr/bin/sandbox-exec (which would strip the injection).
#include <pwd.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sysctl.h>
#include <sys/time.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>

#define DYLD_INTERPOSE(_repl, _orig)                                                    \
    __attribute__((used)) static struct {                                              \
        const void* repl;                                                              \
        const void* orig;                                                              \
    } _interpose_##_orig __attribute__((section("__DATA,__interpose"))) = {            \
        (const void*)(uintptr_t)&_repl, (const void*)(uintptr_t)&_orig};

static const char* rc_env(const char* k) {
    const char* v = getenv(k);
    return (v && *v) ? v : NULL;
}

// ---- gethostname --------------------------------------------------------------------
static int rc_gethostname(char* name, size_t namelen) {
    const char* h = rc_env("RC_FAKE_HOSTNAME");
    if (!h) return gethostname(name, namelen);
    if (namelen == 0) return 0;
    strncpy(name, h, namelen);
    name[namelen - 1] = '\0';
    return 0;
}
DYLD_INTERPOSE(rc_gethostname, gethostname)

// ---- uname (nodename / release / version) -------------------------------------------
static void rc_setfield(char* field, size_t cap, const char* v) {
    if (!v) return;
    strncpy(field, v, cap);
    field[cap - 1] = '\0';
}
static int rc_uname(struct utsname* u) {
    int r = uname(u);
    if (r == 0 && u) {
        rc_setfield(u->nodename, sizeof(u->nodename), rc_env("RC_FAKE_HOSTNAME"));
        rc_setfield(u->release, sizeof(u->release), rc_env("RC_FAKE_OSRELEASE"));
        rc_setfield(u->version, sizeof(u->version), rc_env("RC_FAKE_OSVERSION"));
    }
    return r;
}
DYLD_INTERPOSE(rc_uname, uname)

// ---- getlogin / getlogin_r ----------------------------------------------------------
static char* rc_getlogin(void) {
    const char* u = rc_env("RC_FAKE_USER");
    if (u) return (char*)u;  // libc getlogin() also returns a static buffer; safe to alias
    return getlogin();
}
DYLD_INTERPOSE(rc_getlogin, getlogin)

static int rc_getlogin_r(char* name, size_t len) {
    const char* u = rc_env("RC_FAKE_USER");
    if (!u) return getlogin_r(name, len);
    if (len == 0) return -1;
    strncpy(name, u, len);
    name[len - 1] = '\0';
    return 0;
}
DYLD_INTERPOSE(rc_getlogin_r, getlogin_r)

// ---- getpwuid / getpwnam (username + home dir) --------------------------------------
static struct passwd* rc_fix_pw(struct passwd* p) {
    if (!p) return p;
    const char* u = rc_env("RC_FAKE_USER");
    const char* h = rc_env("RC_FAKE_HOME");
    if (u) p->pw_name = (char*)u;
    if (h) p->pw_dir = (char*)h;
    return p;
}
static struct passwd* rc_getpwuid(uid_t uid) { return rc_fix_pw(getpwuid(uid)); }
DYLD_INTERPOSE(rc_getpwuid, getpwuid)
static struct passwd* rc_getpwnam(const char* n) { return rc_fix_pw(getpwnam(n)); }
DYLD_INTERPOSE(rc_getpwnam, getpwnam)

// ---- gethostuuid (per-install hardware UUID) ----------------------------------------
// Parse a hex string (dashes/other separators ignored) into up to 16 bytes.
static void rc_parse_hex16(const char* s, unsigned char out[16]) {
    memset(out, 0, 16);
    int n = 0, hi = -1;
    for (const char* p = s; *p && n < 16; ++p) {
        int v;
        if (*p >= '0' && *p <= '9') v = *p - '0';
        else if (*p >= 'a' && *p <= 'f') v = *p - 'a' + 10;
        else if (*p >= 'A' && *p <= 'F') v = *p - 'A' + 10;
        else continue;
        if (hi < 0) { hi = v; } else { out[n++] = (unsigned char)((hi << 4) | v); hi = -1; }
    }
}
static int rc_gethostuuid(unsigned char* id, const struct timespec* wait) {
    const char* v = rc_env("RC_FAKE_HOSTUUID");
    if (!v) return gethostuuid(id, wait);
    rc_parse_hex16(v, id);
    return 0;
}
DYLD_INTERPOSE(rc_gethostuuid, gethostuuid)

// ---- sysctlbyname (kern.hostname, CPU brand, kernel, RAM) ----------------------------
// Return a fake string for a name when RC_FAKE_* is set, honoring the two-call
// size-probe/read protocol (oldp==NULL just reports the length). Fall through otherwise.
static int rc_return_str(const char* val, void* oldp, size_t* oldlenp) {
    size_t need = strlen(val) + 1;
    if (oldlenp && !oldp) {
        *oldlenp = need;
        return 0;
    }
    if (oldp && oldlenp) {
        if (*oldlenp < need) {
            *oldlenp = need;
            return -1;  // ENOMEM-ish; caller retries with a bigger buffer
        }
        memcpy(oldp, val, need);
        *oldlenp = need;
        return 0;
    }
    return 0;
}
static int rc_return_u64(uint64_t val, void* oldp, size_t* oldlenp) {
    if (oldlenp && !oldp) {
        *oldlenp = sizeof(uint64_t);
        return 0;
    }
    if (oldp && oldlenp && *oldlenp >= sizeof(uint64_t)) {
        memcpy(oldp, &val, sizeof(uint64_t));
        *oldlenp = sizeof(uint64_t);
        return 0;
    }
    return 0;
}
// hw.ncpu / hw.logicalcpu / ... are int32.
static int rc_return_i32(int32_t val, void* oldp, size_t* oldlenp) {
    if (oldlenp && !oldp) {
        *oldlenp = sizeof(int32_t);
        return 0;
    }
    if (oldp && oldlenp && *oldlenp >= sizeof(int32_t)) {
        memcpy(oldp, &val, sizeof(int32_t));
        *oldlenp = sizeof(int32_t);
        return 0;
    }
    return 0;
}
static int rc_sysctlbyname(const char* name, void* oldp, size_t* oldlenp, void* newp,
                           size_t newlen) {
    if (name && !newp) {  // only intercept reads, never sets
        const char* v;
        if (strcmp(name, "kern.hostname") == 0 && (v = rc_env("RC_FAKE_HOSTNAME")))
            return rc_return_str(v, oldp, oldlenp);
        if (strcmp(name, "machdep.cpu.brand_string") == 0 && (v = rc_env("RC_FAKE_CPU_BRAND")))
            return rc_return_str(v, oldp, oldlenp);
        if (strcmp(name, "machdep.cpu.vendor") == 0 && (v = rc_env("RC_FAKE_CPU_VENDOR")))
            return rc_return_str(v, oldp, oldlenp);
        if (strcmp(name, "kern.uuid") == 0 && (v = rc_env("RC_FAKE_HOSTUUID")))
            return rc_return_str(v, oldp, oldlenp);
        if (strcmp(name, "kern.bootsessionuuid") == 0 && (v = rc_env("RC_FAKE_BOOTUUID")))
            return rc_return_str(v, oldp, oldlenp);
        // kern.boottime is a struct timeval; derive it from the requested uptime so
        // (now - boottime) == uptime, keeping /usr/bin/uptime and sysctl consistent.
        if (strcmp(name, "kern.boottime") == 0 && (v = rc_env("RC_FAKE_UPTIME"))) {
            struct timeval bt;
            bt.tv_sec = time(NULL) - (time_t)strtoll(v, NULL, 10);
            bt.tv_usec = 0;
            if (oldlenp && !oldp) {
                *oldlenp = sizeof(bt);
                return 0;
            }
            if (oldp && oldlenp && *oldlenp >= sizeof(bt)) {
                memcpy(oldp, &bt, sizeof(bt));
                *oldlenp = sizeof(bt);
                return 0;
            }
            return 0;
        }
        if (strcmp(name, "kern.osrelease") == 0 && (v = rc_env("RC_FAKE_OSRELEASE")))
            return rc_return_str(v, oldp, oldlenp);
        if (strcmp(name, "kern.osversion") == 0 && (v = rc_env("RC_FAKE_OSVERSION")))
            return rc_return_str(v, oldp, oldlenp);
        if (strcmp(name, "hw.memsize") == 0 && (v = rc_env("RC_FAKE_MEMSIZE")))
            return rc_return_u64(strtoull(v, NULL, 10), oldp, oldlenp);
        // Logical CPU count (nproc / os.cpus() read these). Fake all the count views to the
        // same value so they stay self-consistent.
        if ((strcmp(name, "hw.ncpu") == 0 || strcmp(name, "hw.logicalcpu") == 0 ||
             strcmp(name, "hw.logicalcpu_max") == 0 || strcmp(name, "hw.physicalcpu") == 0 ||
             strcmp(name, "hw.physicalcpu_max") == 0 || strcmp(name, "hw.activecpu") == 0 ||
             strcmp(name, "hw.availcpu") == 0) &&
            (v = rc_env("RC_FAKE_NCPU")))
            return rc_return_i32((int32_t)strtol(v, NULL, 10), oldp, oldlenp);
    }
    return sysctlbyname(name, oldp, oldlenp, newp, newlen);
}
DYLD_INTERPOSE(rc_sysctlbyname, sysctlbyname)
