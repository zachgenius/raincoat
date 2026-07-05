import Foundation

// Per-capability honesty. The tray NEVER collapses these into a single green check.
// Each enum keeps an `.unknown(String)` case so an unexpected value from a newer CLI is
// surfaced verbatim instead of being silently dropped or mislabeled.

enum FilesystemCapability: Equatable {
    case confined
    case unknown(String)

    init(raw: String?) {
        switch raw {
        case "confined": self = .confined
        default: self = .unknown(raw ?? "")
        }
    }

    var display: String {
        switch self {
        case .confined: return "confined"
        case .unknown(let s): return s.isEmpty ? "unknown" : s
        }
    }
}

enum NetworkCapability: Equatable {
    case blocked
    case open
    case proxied
    case unknown(String)

    init(raw: String?) {
        switch raw {
        case "blocked": self = .blocked
        case "open": self = .open
        case "proxied": self = .proxied
        default: self = .unknown(raw ?? "")
        }
    }

    var display: String {
        switch self {
        case .blocked: return "blocked"
        case .open: return "open"
        case .proxied: return "proxied"
        case .unknown(let s): return s.isEmpty ? "unknown" : s
        }
    }
}

enum IdentityCapability: Equatable {
    case faked
    case partial
    case off
    case unknown(String)

    init(raw: String?) {
        switch raw {
        case "faked": self = .faked
        case "partial": self = .partial
        case "off": self = .off
        default: self = .unknown(raw ?? "")
        }
    }

    var display: String {
        switch self {
        case .faked: return "faked"
        case .partial: return "partial"
        case .off: return "off"
        case .unknown(let s): return s.isEmpty ? "unknown" : s
        }
    }
}

// Mirrors the schema-1 `capabilities` object: a map of well-known keys to honest values.
struct Capabilities: Decodable, Equatable {
    let filesystem: FilesystemCapability
    let network: NetworkCapability
    let identity: IdentityCapability

    init(
        filesystem: FilesystemCapability = .unknown(""),
        network: NetworkCapability = .unknown(""),
        identity: IdentityCapability = .unknown("")
    ) {
        self.filesystem = filesystem
        self.network = network
        self.identity = identity
    }

    private enum CodingKeys: String, CodingKey {
        case filesystem, network, identity
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        filesystem = FilesystemCapability(raw: try c.decodeIfPresent(String.self, forKey: .filesystem))
        network = NetworkCapability(raw: try c.decodeIfPresent(String.self, forKey: .network))
        identity = IdentityCapability(raw: try c.decodeIfPresent(String.self, forKey: .identity))
    }

    // Compact, honest one-liner, e.g. "fs ✓ · net proxied · identity faked".
    // Only a genuinely `confined` filesystem earns the check; everything else is spelled out.
    var summary: String {
        let fsPart = (filesystem == .confined) ? "fs ✓" : "fs \(filesystem.display)"
        return "\(fsPart) · net \(network.display) · identity \(identity.display)"
    }
}
