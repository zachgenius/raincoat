// Raincoat — doctor: host capability checks for the bubblewrap backend.
#include "doctor.hpp"

#include <array>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <sstream>
#include <string>
#include <vector>

#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>

namespace raincoat {

namespace {

// Is `path` an existing, executable regular file?
bool is_executable_file(const std::string& path) {
    struct stat st{};
    if (::stat(path.c_str(), &st) != 0) return false;
    if (!S_ISREG(st.st_mode)) return false;
    return ::access(path.c_str(), X_OK) == 0;
}

std::vector<std::string> split_path(const std::string& value, char delim) {
    std::vector<std::string> out;
    std::string cur;
    for (char c : value) {
        if (c == delim) {
            out.push_back(cur);
            cur.clear();
        } else {
            cur.push_back(c);
        }
    }
    out.push_back(cur);
    return out;
}

#ifndef __APPLE__
std::string rstrip(std::string s) {
    while (!s.empty() && (s.back() == '\n' || s.back() == '\r' ||
                          s.back() == ' ' || s.back() == '\t')) {
        s.pop_back();
    }
    return s;
}

// Run `tool_path --version` and capture its stdout/stderr text (first line-ish).
std::string capture_version(const std::string& tool_path) {
    int pipefd[2];
    if (::pipe(pipefd) != 0) return "";

    pid_t pid = ::fork();
    if (pid < 0) {
        ::close(pipefd[0]);
        ::close(pipefd[1]);
        return "";
    }
    if (pid == 0) {
        // child
        ::dup2(pipefd[1], STDOUT_FILENO);
        ::dup2(pipefd[1], STDERR_FILENO);
        ::close(pipefd[0]);
        ::close(pipefd[1]);
        ::execl(tool_path.c_str(), tool_path.c_str(), "--version",
                static_cast<char*>(nullptr));
        _exit(127);
    }
    // parent
    ::close(pipefd[1]);
    std::string out;
    std::array<char, 256> buf{};
    for (;;) {
        ssize_t n = ::read(pipefd[0], buf.data(), buf.size());
        if (n > 0) {
            out.append(buf.data(), static_cast<size_t>(n));
            continue;
        }
        if (n < 0 && errno == EINTR) continue;  // interrupted; retry rather than stop
        break;  // n == 0 (EOF) or an unrecoverable error
    }
    ::close(pipefd[0]);
    int status = 0;
    ::waitpid(pid, &status, 0);
    return rstrip(out);
}

// Run a minimal `bwrap ... true` inside a real sandbox; return true on exit 0.
bool run_smoke_test(const std::string& bwrap_path) {
    pid_t pid = ::fork();
    if (pid < 0) return false;
    if (pid == 0) {
        // Silence output.
        int devnull = ::open("/dev/null", O_WRONLY);
        if (devnull >= 0) {
            ::dup2(devnull, STDOUT_FILENO);
            ::dup2(devnull, STDERR_FILENO);
            if (devnull > STDERR_FILENO) ::close(devnull);
        }
        // Mirror the runner's base mount so the smoke test is representative.
        ::execl(bwrap_path.c_str(), bwrap_path.c_str(),
                "--die-with-parent",
                "--unshare-pid", "--unshare-uts", "--unshare-ipc",
                "--ro-bind", "/usr", "/usr",
                "--symlink", "usr/bin", "/bin",
                "--symlink", "usr/lib", "/lib",
                "--symlink", "usr/lib64", "/lib64",
                "--symlink", "usr/sbin", "/sbin",
                "--proc", "/proc",
                "--dev", "/dev",
                "/bin/true",
                static_cast<char*>(nullptr));
        _exit(127);
    }
    int status = 0;
    if (::waitpid(pid, &status, 0) < 0) return false;
    return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

// Best-effort probe: are unprivileged user namespaces available?
bool probe_userns() {
    // If a distro exposes the toggle, honour it; default to true otherwise.
    FILE* f = std::fopen("/proc/sys/kernel/unprivileged_userns_clone", "r");
    if (f) {
        int v = -1;
        if (std::fscanf(f, "%d", &v) == 1) {
            std::fclose(f);
            return v != 0;
        }
        std::fclose(f);
    }
    // Some kernels expose a max-count that is 0 when disabled.
    f = std::fopen("/proc/sys/user/max_user_namespaces", "r");
    if (f) {
        long v = -1;
        if (std::fscanf(f, "%ld", &v) == 1) {
            std::fclose(f);
            return v != 0;
        }
        std::fclose(f);
    }
    return true;  // assume available; the smoke test is the real arbiter
}
#endif  // !__APPLE__

#ifdef __APPLE__
// macOS SBPL smoke test: load a trivial `(version 1)(allow default)` profile via
// sandbox-exec and run /usr/bin/true inside it. Exit 0 => sandbox-exec can compile and
// enter a profile on this host. Mirrors run_smoke_test's fork+execl+silence style.
bool run_sbpl_smoke_test(const std::string& sandbox_exec_path) {
    pid_t pid = ::fork();
    if (pid < 0) return false;
    if (pid == 0) {
        int devnull = ::open("/dev/null", O_WRONLY);
        if (devnull >= 0) {
            ::dup2(devnull, STDOUT_FILENO);
            ::dup2(devnull, STDERR_FILENO);
            if (devnull > STDERR_FILENO) ::close(devnull);
        }
        ::execl(sandbox_exec_path.c_str(), sandbox_exec_path.c_str(),
                "-p", "(version 1)(allow default)",
                "/usr/bin/true", static_cast<char*>(nullptr));
        _exit(127);
    }
    int status = 0;
    if (::waitpid(pid, &status, 0) < 0) return false;
    return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}
#endif  // __APPLE__

// Search PATH (absolute dirs only) then a set of conventional fallback dirs for
// an executable named `tool`.
std::optional<std::string> find_on_path(const std::string& tool) {
    const char* path_env = std::getenv("PATH");
    std::string path = path_env ? path_env : "/usr/bin:/bin:/usr/local/bin";

    for (const std::string& dir : split_path(path, ':')) {
        if (dir.empty()) continue;
        if (dir[0] != '/') continue;  // require an absolute location
        std::string candidate = dir;
        if (candidate.back() != '/') candidate.push_back('/');
        candidate += tool;
        if (is_executable_file(candidate)) return candidate;
    }

    // Fall back to the conventional locations.
    for (const char* dir : {"/usr/bin/", "/bin/", "/usr/local/bin/",
                            "/usr/sbin/", "/sbin/"}) {
        std::string candidate = std::string(dir) + tool;
        if (is_executable_file(candidate)) return candidate;
    }
    return std::nullopt;
}

}  // namespace

std::optional<std::string> find_bwrap() { return find_on_path("bwrap"); }
std::optional<std::string> find_pasta() { return find_on_path("pasta"); }
std::optional<std::string> find_slirp4netns() { return find_on_path("slirp4netns"); }

#ifdef __APPLE__

// The macOS backend is Seatbelt (sandbox-exec). run_doctor() reuses the DoctorReport
// fields with macOS meanings: bwrap_found == sandbox-exec present, bwrap_version is a
// fixed label (sandbox-exec has no --version), userns_ok is N/A (reported true), and
// smoke_ok is a real SBPL smoke test. pasta/slirp4netns are irrelevant (the egress
// firewall is kernel-level), so they stay unset.
DoctorReport run_doctor() {
    DoctorReport r;
    const char* kSandboxExec = "/usr/bin/sandbox-exec";

    r.bwrap_found = (::access(kSandboxExec, X_OK) == 0);
    r.bwrap_path = kSandboxExec;
    r.bwrap_version = "seatbelt (sandbox-exec)";
    r.userns_ok = true;  // user namespaces are a Linux concept; N/A on macOS

    if (!r.bwrap_found) {
        r.notes.push_back(
            "/usr/bin/sandbox-exec was not found or is not executable (it ships with "
            "macOS; check your macOS version / system integrity)");
    } else {
        r.smoke_ok = run_sbpl_smoke_test(kSandboxExec);
        if (!r.smoke_ok) {
            r.notes.push_back(
                "sandbox-exec SBPL smoke test "
                "(`sandbox-exec -p '(version 1)(allow default)' /usr/bin/true`) failed");
        }
    }

    // ALWAYS emit the honest deprecation warning — even on PASS. Seatbelt still works
    // today but Apple has deprecated it with no supported replacement for wrapping
    // arbitrary CLIs (App Sandbox requires an app bundle + entitlements + code signing).
    r.notes.push_back(
        "[WARN] Seatbelt / sandbox-exec is Apple-DEPRECATED. It works today but has no "
        "supported replacement for wrapping arbitrary CLIs (App Sandbox needs a bundle + "
        "entitlements + code signing); Raincoat's macOS backend is best-effort. See "
        "docs/MACOS.md.");
    r.notes.push_back(
        "The egress firewall on macOS is kernel-level (Seatbelt (deny network*) + allow "
        "only the loopback proxy port); no pasta/slirp4netns helper is needed.");

    return r;
}

#else  // !__APPLE__

DoctorReport run_doctor() {
    DoctorReport r;

    auto path = find_bwrap();
    if (!path.has_value()) {
        r.bwrap_found = false;
        r.notes.push_back("bwrap not found on PATH");
        return r;
    }

    r.bwrap_found = true;
    r.bwrap_path = *path;

    r.bwrap_version = capture_version(*path);
    if (r.bwrap_version.empty()) {
        r.notes.push_back("could not read `bwrap --version`");
    }

    r.userns_ok = probe_userns();
    if (!r.userns_ok) {
        r.notes.push_back("unprivileged user namespaces appear to be disabled");
    }

    r.smoke_ok = run_smoke_test(*path);
    if (!r.smoke_ok) {
        r.notes.push_back("bwrap smoke test (`bwrap ... true`) failed");
    }

    // Optional egress-network-jail helpers. Their absence is not a failure; it
    // only means the egress bridge falls back to the shared host loopback.
    if (auto pasta = find_pasta()) {
        r.pasta_found = true;
        r.pasta_path = *pasta;
        r.pasta_version = capture_version(*pasta);
    }
    if (auto slirp = find_slirp4netns()) {
        r.slirp4netns_found = true;
        r.slirp4netns_path = *slirp;
        r.slirp4netns_version = capture_version(*slirp);
    }
    if (!r.egress_jail_available()) {
        r.notes.push_back(
            "no egress network-jail helper (pasta / slirp4netns) found; the "
            "egress bridge shares the host network namespace (see EGRESS.md)");
    }

    return r;
}

#endif  // !__APPLE__

#ifdef __APPLE__

std::string format_doctor(const DoctorReport& r) {
    std::ostringstream os;
    os << "Raincoat doctor (macOS / Seatbelt)\n";
    os << "==================================\n";

    auto line = [&](bool ok, const std::string& label, const std::string& detail) {
        os << (ok ? "  [ OK ] " : "  [FAIL] ") << label;
        if (!detail.empty()) os << ": " << detail;
        os << "\n";
    };

    // sandbox-exec presence + the real SBPL smoke test.
    line(r.bwrap_found, "sandbox-exec found",
         r.bwrap_found ? r.bwrap_path : std::string("not found"));
    line(r.smoke_ok,
         "sandbox-exec SBPL smoke test (`sandbox-exec -p '(version 1)(allow default)' true`)",
         r.smoke_ok ? std::string("passed") : std::string("failed"));

    // The deprecation WARN is ALWAYS rendered, even on PASS — the macOS backend is a
    // best-effort, Apple-deprecated path. No apt/dnf/pacman hints here (that is Linux).
    os << "  [WARN] Seatbelt / sandbox-exec is Apple-DEPRECATED — it works today but has "
          "no supported replacement for wrapping arbitrary CLIs (App Sandbox needs a "
          "bundle + entitlements + signing). Raincoat's macOS backend is best-effort. See "
          "docs/MACOS.md.\n";
    os << "  [INFO] egress firewall is kernel-level (Seatbelt (deny network*)); no "
          "pasta/slirp4netns helper is needed.\n";

    if (!r.notes.empty()) {
        os << "\nNotes:\n";
        for (const auto& n : r.notes) os << "  - " << n << "\n";
    }

    os << "\n";
    if (r.usable()) {
        os << "Result: PASS — host is usable. sandbox-exec is present and the SBPL smoke "
              "test passed. (Best-effort backend — see the deprecation warning above.)\n";
    } else {
        os << "Result: FAIL — host is NOT usable for Raincoat.\n";
        if (!r.bwrap_found) {
            os << "\n";
            os << "/usr/bin/sandbox-exec was not found or is not executable.\n";
            os << "It ships with macOS; check your macOS version / system integrity.\n";
        } else if (!r.smoke_ok) {
            os << "\n";
            os << "sandbox-exec is present but the SBPL smoke test failed; check your "
                  "macOS version and that /usr/bin/sandbox-exec can load a profile.\n";
        }
    }

    return os.str();
}

#else  // !__APPLE__

std::string format_doctor(const DoctorReport& r) {
    std::ostringstream os;
    os << "Raincoat doctor\n";
    os << "===============\n";

    auto line = [&](bool ok, const std::string& label, const std::string& detail) {
        os << (ok ? "  [ OK ] " : "  [FAIL] ") << label;
        if (!detail.empty()) os << ": " << detail;
        os << "\n";
    };

    // bwrap presence
    line(r.bwrap_found, "bubblewrap (bwrap) found",
         r.bwrap_found ? r.bwrap_path : std::string("not found"));

    // version
    if (r.bwrap_found) {
        line(!r.bwrap_version.empty(), "bwrap version",
             r.bwrap_version.empty() ? std::string("unknown") : r.bwrap_version);
    }

    // user namespaces
    line(r.userns_ok, "user namespaces available",
         r.userns_ok ? std::string("yes") : std::string("no"));

    // smoke test
    line(r.smoke_ok, "bwrap smoke test (`bwrap ... true`)",
         r.smoke_ok ? std::string("passed") : std::string("failed"));

    // egress network jail — optional. Absence is informational, not a failure,
    // so it is never rendered as [FAIL].
    {
        std::string detail;
        if (r.pasta_found) {
            detail = "available (pasta)";
            if (!r.pasta_path.empty()) detail += " " + r.pasta_path;
        } else if (r.slirp4netns_found) {
            detail = "available (slirp4netns)";
            if (!r.slirp4netns_path.empty()) detail += " " + r.slirp4netns_path;
        } else {
            detail =
                "unavailable — egress bridge shares the host network namespace "
                "(see EGRESS.md)";
        }
        os << (r.egress_jail_available() ? "  [ OK ] " : "  [INFO] ")
           << "egress network jail" << ": " << detail << "\n";
    }

    if (!r.notes.empty()) {
        os << "\nNotes:\n";
        for (const auto& n : r.notes) os << "  - " << n << "\n";
    }

    os << "\n";
    if (r.usable()) {
        os << "Result: PASS — host is usable. bwrap is present and the smoke test passed.\n";
    } else {
        os << "Result: FAIL — host is NOT usable for Raincoat.\n";
        if (!r.bwrap_found) {
            os << "\n";
            os << "bubblewrap / bwrap was not found.\n";
            os << "\n";
            os << "Install it with your package manager, for example:\n";
            os << "  Ubuntu/Debian: sudo apt install bubblewrap\n";
            os << "  Fedora:        sudo dnf install bubblewrap\n";
            os << "  Arch:          sudo pacman -S bubblewrap\n";
        } else if (!r.smoke_ok) {
            os << "bwrap is installed but the smoke test failed; check that "
                  "unprivileged user namespaces are enabled.\n";
        }
    }

    return os.str();
}

#endif  // !__APPLE__

}  // namespace raincoat
