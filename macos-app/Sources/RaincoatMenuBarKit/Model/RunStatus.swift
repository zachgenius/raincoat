import Foundation

// Swift mirror of the schema-1 run-status file written by the raincoat CLI
// (see src/run_status.{hpp,cpp} and docs/GUI-MACOS.md). This JSON is the ENTIRE
// contract between the C++ core and this app — the app never links the core.
//
// Decoding is deliberately lenient: every field except `schema` / `supervisor_pid`
// has a sensible fallback, so a partially written or slightly-newer file still yields
// a usable row rather than throwing. The reader additionally skips any file whose
// `schema` is not 1.
struct RunStatus: Decodable, Equatable {
    let schema: Int
    let supervisorPID: Int
    let childPID: Int
    let command: String
    let auditLog: String
    let backend: String
    let netMode: String
    let startedAt: Int
    let capabilities: Capabilities
    let notes: [String]

    private enum CodingKeys: String, CodingKey {
        case schema
        case supervisorPID = "supervisor_pid"
        case childPID = "child_pid"
        case command
        case auditLog = "audit_log"
        case backend
        case netMode = "net_mode"
        case startedAt = "started_at"
        case capabilities
        case notes
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        schema = try c.decode(Int.self, forKey: .schema)
        supervisorPID = try c.decode(Int.self, forKey: .supervisorPID)
        childPID = try c.decodeIfPresent(Int.self, forKey: .childPID) ?? 0
        command = (try c.decodeIfPresent(String.self, forKey: .command))?
            .trimmingCharacters(in: .whitespacesAndNewlines).nonEmpty ?? "(unknown command)"
        auditLog = try c.decodeIfPresent(String.self, forKey: .auditLog) ?? ""
        backend = try c.decodeIfPresent(String.self, forKey: .backend) ?? ""
        netMode = try c.decodeIfPresent(String.self, forKey: .netMode) ?? ""
        startedAt = try c.decodeIfPresent(Int.self, forKey: .startedAt) ?? 0
        capabilities = try c.decodeIfPresent(Capabilities.self, forKey: .capabilities) ?? Capabilities()
        notes = try c.decodeIfPresent([String].self, forKey: .notes) ?? []
    }

    /// pid_t view of the supervisor pid for `kill(2)`, or nil if out of range / non-positive.
    var supervisorPidT: pid_t? { pid_t(exactly: supervisorPID).flatMap { $0 > 0 ? $0 : nil } }
    /// pid_t view of the child pid for `kill(2)`, or nil if out of range / non-positive.
    var childPidT: pid_t? { pid_t(exactly: childPID).flatMap { $0 > 0 ? $0 : nil } }

    /// `audit_log` as a file URL, or nil when the CLI wrote an empty path.
    var auditLogURL: URL? { auditLog.isEmpty ? nil : URL(fileURLWithPath: auditLog) }
}

private extension String {
    var nonEmpty: String? { isEmpty ? nil : self }
}
