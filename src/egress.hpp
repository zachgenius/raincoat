// Raincoat — egress: host-side HTTP(S) forward proxy ("egress bridge").
//
// Phase 2. The child process is handed a generic loopback endpoint (child_endpoint)
// via an injected env var; Raincoat runs a small forward proxy on that loopback
// address and privately relays each request to the real upstream_endpoint, which is
// never shown to the child. See docs/EGRESS.md.
//
// NETWORKING MODEL (MVP, honest): the bridge listens on the host loopback and the
// child reaches it because egress-bridge mode shares the host network namespace
// (NOT --unshare-net). That means the child ALSO retains general network access —
// the bridge hides the upstream URL from the child's ENV/config, it does NOT jail
// the network. This is a documented limitation, not a bug.
//
// This header exposes small PURE helpers (parse_url / parse_request_head /
// content_length / build_upstream_head) that are unit-testable without any sockets,
// plus a runnable EgressServer class.
#pragma once

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "config.hpp"

namespace raincoat {

// ---------------------------------------------------------------------------
// Pure helpers (no sockets)
// ---------------------------------------------------------------------------

// A parsed absolute URL. `port` is always populated (default 80/443 by scheme).
// `path` includes the query string (everything from the first '/' of the target,
// or empty when the URL had no path component).
struct Url {
    std::string scheme;  // "http" | "https" (lower-cased)
    std::string host;
    std::string port;    // decimal string, e.g. "80"
    std::string path;    // e.g. "/v1/chat?x=1"; empty if absent
};

// Parse "scheme://host[:port][/path[?query]]". Only http/https are accepted.
// On success fills `out` and returns true. On failure returns false and sets `err`.
bool parse_url(const std::string& url, Url& out, std::string& err);

// A parsed HTTP request head (request-line + headers), i.e. the bytes up to and
// including the terminating CRLFCRLF, minus the body.
struct HttpRequestHead {
    std::string method;
    std::string target;   // request-target (origin-form path, or absolute-form)
    std::string version;  // e.g. "HTTP/1.1"
    std::vector<std::pair<std::string, std::string>> headers;  // name, value (order preserved)
};

// Parse a raw request head (must NOT include the body). `raw_head` is the bytes up
// to the CRLFCRLF (the terminator itself may or may not be present). Returns false
// and sets `err` on a malformed request-line or header line.
bool parse_request_head(const std::string& raw_head, HttpRequestHead& out, std::string& err);

// Value of the Content-Length header (case-insensitive), or -1 if absent/invalid.
long content_length(const HttpRequestHead& head);

// Case-insensitive header lookup helper. Returns the first matching value, or
// std::nullopt-equivalent via the bool return.
bool find_header(const HttpRequestHead& head, const std::string& name, std::string& value_out);

// Why a request head must be REJECTED for HTTP request-smuggling / ambiguous body framing,
// or None when the request is safe to forward. This is the pure decision the connection
// handler enforces BEFORE it ever connects upstream (a rejected request is answered 400 and
// never relayed).
enum class FramingReject {
    None,           // safe to forward
    ClTe,           // both Content-Length and Transfer-Encoding present (CL.TE)
    ConflictingCl,  // multiple Content-Length headers with differing values (CL.CL)
    MalformedCl,    // a Content-Length header whose value is malformed or negative
};

// Analyze the request head's body-framing headers for request-smuggling safety, with no
// I/O. Returns FramingReject::None when the request may be forwarded; otherwise names why it
// MUST be rejected. Duplicate-but-identical Content-Length values are NOT a conflict (they
// are collapsed to a single line by build_upstream_head).
FramingReject check_request_framing(const HttpRequestHead& head);

// Build the request head to send upstream, applying a bridge's policy:
//   * request-line: preserve method + target + version (paths/queries preserved).
//   * Host: upstream host (with :port when non-default) unless b.preserve_host, in
//     which case the child's original Host is kept.
//   * remove every header named in b.strip_headers (case-insensitive), plus any
//     hop-by-hop Connection/Proxy-Connection headers.
//   * append b.inject_headers.
//   * force "Connection: close" (MVP: no keep-alive; lets us stream by piping until EOF).
// Returns the full head including the terminating CRLFCRLF, ready to write to the socket.
std::string build_upstream_head(const HttpRequestHead& req, const EgressBridge& b, const Url& upstream);

// ---------------------------------------------------------------------------
// Runnable server
// ---------------------------------------------------------------------------

class EgressServer {
public:
    EgressServer() = default;
    ~EgressServer();

    EgressServer(const EgressServer&) = delete;
    EgressServer& operator=(const EgressServer&) = delete;

    // Bind+listen each bridge's child_endpoint on its loopback address and spawn an
    // accept thread per bridge. Returns false and sets `err` if any bridge fails to
    // bind (and rolls back any already-started listeners). Idempotent-unfriendly: call
    // stop() before start() again.
    bool start(const EgressConfig& cfg, std::string& err);

    // Close listeners, wake accept threads, and join every thread (accept + per-connection).
    void stop();

    // The actual listening port for a bridge (useful when child_endpoint used ":0").
    // Returns -1 if the bridge is unknown / not listening.
    int port_for(const std::string& bridge_name) const;

private:
    struct Listener {
        EgressBridge bridge;
        std::string  name;
        int          fd   = -1;
        int          port = -1;
        std::thread  accept_thread;
    };

    void accept_loop(Listener* l);
    void handle_connection(int child_fd, EgressBridge bridge);

    EgressConfig cfg_;
    std::atomic<bool> running_{false};
    int shutdown_fd_ = -1;  // eventfd used to wake accept threads out of poll()

    std::vector<std::unique_ptr<Listener>> listeners_;

    // Per-connection workers run detached and are reaped continuously: each increments
    // active_conns_ on spawn and decrements + notifies on completion, so a finished
    // connection's thread/stack is reclaimed immediately (not held until stop()). stop()
    // waits on conn_cv_ until active_conns_ drains to zero.
    std::mutex conn_mu_;
    std::condition_variable conn_cv_;
    int active_conns_ = 0;
};

}  // namespace raincoat
