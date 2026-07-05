import Darwin
import Foundation

// Reads the run directory and produces the set of LIVE runs. Pure reader:
// its only mutation of the filesystem is opportunistically unlinking status files
// whose supervisor process is already dead (best-effort, matching the contract).
// It never writes a sandbox, never applies a policy.
@MainActor
final class RunStore {
    private(set) var runs: [RunStatus] = []
    private let runDirectory: URL
    private let decoder = JSONDecoder()

    init(runDirectory: URL = RunPaths.runDirectory) {
        self.runDirectory = runDirectory
    }

    /// Re-scan the directory. Returns true if the visible set of live runs changed.
    @discardableResult
    func reload() -> Bool {
        let fresh = scan()
        guard fresh != runs else { return false }
        runs = fresh
        return true
    }

    private func scan() -> [RunStatus] {
        let fm = FileManager.default
        guard let entries = try? fm.contentsOfDirectory(
            at: runDirectory,
            includingPropertiesForKeys: nil,
            options: [.skipsHiddenFiles]
        ) else {
            return []  // dir missing / unreadable -> no runs
        }

        var live: [RunStatus] = []
        for url in entries where url.pathExtension == "json" {
            guard let data = try? Data(contentsOf: url) else { continue }
            guard let status = try? decoder.decode(RunStatus.self, from: data) else {
                // Malformed / partial JSON: skip this file, keep going.
                log.debug("skipping unparseable run file \(url.lastPathComponent, privacy: .public)")
                continue
            }
            guard status.schema == 1 else { continue }

            guard let spid = status.supervisorPidT, Liveness.isAlive(pid: spid) else {
                // Stale (supervisor gone). Best-effort unlink, then skip.
                try? fm.removeItem(at: url)
                continue
            }
            live.append(status)
        }

        // Stable order: newest first, then by command for equal timestamps.
        live.sort { lhs, rhs in
            lhs.startedAt != rhs.startedAt
                ? lhs.startedAt > rhs.startedAt
                : lhs.command < rhs.command
        }
        return live
    }
}
