import Foundation

// Simple subsequence fuzzy match. Returns nil when `query` is not an ordered
// subsequence of `candidate`; otherwise a score where higher is a better match
// (contiguous runs and a leading match are rewarded).
enum FuzzyMatcher {
    static func score(query: String, candidate: String) -> Int? {
        if query.isEmpty { return 0 }
        let q = Array(query.lowercased())
        let c = Array(candidate.lowercased())
        guard q.count <= c.count else { return nil }

        var qi = 0
        var total = 0
        var lastMatch = -2
        for (ci, ch) in c.enumerated() {
            guard qi < q.count, ch == q[qi] else { continue }
            if ci == 0 {
                total += 12                    // strong reward for matching at the very start
            } else if ci == lastMatch + 1 {
                total += 6                     // contiguous with previous match
            } else {
                total += 1
            }
            lastMatch = ci
            qi += 1
        }
        return qi == q.count ? total : nil
    }
}
