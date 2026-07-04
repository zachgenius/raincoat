// Raincoat — proxy: host-side FILTERING FORWARD PROXY (phase 4).
//
// When [network_policy].enabled, the runner starts this small loopback HTTP(S) proxy and
// injects http_proxy/https_proxy/all_proxy into the child pointing at it. The proxy checks
// each request's target HOST against the NetworkPolicy (allow/block/metadata rules) and:
//   * plain HTTP   — parses the absolute-form request line, applies policy, and (if allowed)
//                    forwards the request to the origin and streams the response back. A
//                    blocked host gets "HTTP/1.1 403 Forbidden".
//   * HTTPS/CONNECT — applies policy on the host; if allowed replies "200 Connection
//                    Established" and BLIND-TUNNELS bytes both ways (no TLS interception);
//                    if blocked replies 403 and closes.
//
// Composed with the STRICT netns jail (which blocks all direct egress and forwards only the
// proxy port) the allow/block list becomes a real domain-level egress firewall. WITHOUT the
// jail it only constrains proxy-aware clients — a documented, honest limitation.
//
// Post-resolution SSRF guard: after policy passes on the literal request host, the proxy
// re-checks EVERY address getaddrinfo returns before dialing and refuses (403) if any resolved
// address is a block_hosts IP literal or (when enabled) a metadata/link-local address. This
// closes the "name that resolves to a blocked/metadata IP" bypass on both the HTTP and CONNECT
// paths.
//
// NAME-vs-IP asymmetry (inherent to name-based filtering, NOT closed by the guard above):
// block_hosts entries that are NAMES only constrain the literal name. In default_action=allow,
// a host blocked purely by name (e.g. block_hosts={"localhost"}) is still reachable by asking
// for its IP (127.0.0.1) directly, because the proxy cannot reverse-map an IP back to the
// blocked name. To use a name block-list as a real egress firewall, ALSO list the pinned IP
// literal(s), and/or use default_action=deny with an explicit allow-list, and compose the netns
// jail. Allow-lists that require strong control should enumerate both names and their IPs.
//
// host_allowed() is a PURE, unit-testable policy engine with no sockets.
#pragma once

#include <atomic>
#include <condition_variable>
#include <mutex>
#include <string>
#include <thread>

#include "config.hpp"

namespace raincoat {

// ---------------------------------------------------------------------------
// Pure policy engine (no sockets)
// ---------------------------------------------------------------------------

// Decide whether a request to `host` (a hostname or IP literal, with or without
// surrounding [] for IPv6) is permitted by policy `p`. Rules, in order:
//   1. block_hosts WINS — exact match or dot-suffix match ("evil.com" blocks
//      "api.evil.com"). A blocked host is never allowed regardless of default_action.
//   2. metadata blocking (when p.block_private_metadata_endpoints): blocks the cloud
//      metadata endpoints 169.254.169.254, [fd00:ec2::254], metadata.google.internal and
//      "metadata", every entry in p.metadata_endpoints, ANY link-local 169.254.0.0/16
//      literal, and the IPv4/IPv6 numeric form of a metadata address.
//   3. default_action: "deny" => allow ONLY hosts matching allow_hosts (exact/dot-suffix);
//      "allow" => allow anything not blocked above.
// An empty/unparseable host fails CLOSED (returns false).
bool host_allowed(const std::string& host, const NetworkPolicy& p);

// ---------------------------------------------------------------------------
// Runnable filtering forward proxy
// ---------------------------------------------------------------------------

class ProxyServer {
public:
    ProxyServer() = default;
    ~ProxyServer();

    ProxyServer(const ProxyServer&) = delete;
    ProxyServer& operator=(const ProxyServer&) = delete;

    // Bind+listen on the numeric LOOPBACK address `loopback_addr` (e.g. "127.0.0.1" or
    // "::1") and `port` (0 => ephemeral), then serve the filtering proxy governed by
    // `policy`. `timeout_seconds` bounds per-connection idle waits (clamped to >= 1).
    // Returns false and sets `err` on a bad/non-loopback address or bind failure. Call
    // stop() before start() again.
    bool start(const std::string& loopback_addr, int port, const NetworkPolicy& policy,
               int timeout_seconds, std::string& err);

    // Close the listener, wake the accept thread, and join every thread (accept + workers).
    void stop();

    // The actual listening port (resolves an ephemeral ":0" bind). -1 when not listening.
    int port() const { return port_; }
    // Alias matching the EgressServer vocabulary; the proxy has a single listener so the
    // bridge-name argument is ignored.
    int port_for(const std::string& = std::string()) const { return port_; }

private:
    void accept_loop();
    void handle_connection(int client_fd);

    NetworkPolicy policy_;
    int timeout_s_ = 30;
    std::atomic<bool> running_{false};
    int listen_fd_ = -1;
    int port_ = -1;
    int shutdown_fd_ = -1;
    std::thread accept_thread_;

    // Detached per-connection workers, reaped continuously like EgressServer: each bumps
    // active_conns_ on spawn and decrements + notifies on exit; stop() waits until it drains.
    std::mutex conn_mu_;
    std::condition_variable conn_cv_;
    int active_conns_ = 0;
};

}  // namespace raincoat
