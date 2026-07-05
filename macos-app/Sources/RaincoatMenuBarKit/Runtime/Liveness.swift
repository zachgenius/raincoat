import Darwin

// Liveness check per the GUI contract: a run is stale if `kill(supervisor_pid, 0)`
// fails with ESRCH (no such process). EPERM means the process exists but we may not
// signal it — still alive. This covers a SIGKILLed raincoat that never got to run
// cleanup_root() and so left its status file behind.
enum Liveness {
    static func isAlive(pid: pid_t) -> Bool {
        guard pid > 0 else { return false }
        if kill(pid, 0) == 0 { return true }
        return errno == EPERM
    }
}
