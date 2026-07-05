import Darwin

// Liveness check per the GUI contract. A run is shown only if its supervisor pid is BOTH alive
// AND actually a `raincoat` process. The bare `kill(pid, 0)` existence test is not enough: a
// stale file left by a SIGKILLed raincoat (no cleanup_root()), a hand-planted sample, or a file
// whose supervisor_pid has been RECYCLED by an unrelated process would all read as "alive". We
// additionally confirm the process's executable is named `raincoat`, so the tray never shows a
// sandbox that isn't really one.
enum Liveness {
    static func isAlive(pid: pid_t) -> Bool {
        guard pid > 0 else { return false }
        // Must exist (EPERM = exists but we may not signal it — still alive).
        let exists = (kill(pid, 0) == 0) || (errno == EPERM)
        guard exists else { return false }
        // ...and must actually be raincoat, not just any live pid.
        return isRaincoat(pid: pid)
    }

    // True if `pid`'s running executable is named `raincoat`. Returns false when the path can't
    // be read (process gone, or not permitted — e.g. a root-owned pid like launchd), which is
    // exactly the conservative answer we want.
    static func isRaincoat(pid: pid_t) -> Bool {
        var buf = [CChar](repeating: 0, count: 4096)  // PROC_PIDPATHINFO_MAXSIZE
        let n = proc_pidpath(pid, &buf, UInt32(buf.count))
        guard n > 0 else { return false }
        let path = String(cString: buf)
        let name = path.split(separator: "/").last.map(String.init) ?? path
        return name == "raincoat"
    }
}
