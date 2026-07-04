// Raincoat — proxy: filtering forward proxy implementation. See proxy.hpp for the contract.
//
// The PURE HTTP head/URL parsers (parse_url / parse_request_head / find_header /
// content_length / check_request_framing) are reused from the egress module; the small
// socket helpers below are local so this TU has no cross-module link into egress internals.
#include "proxy.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <functional>

#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <signal.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "egress.hpp"  // parse_url / parse_request_head / find_header / content_length / framing

namespace raincoat {

// ===========================================================================
// Pure policy engine
// ===========================================================================

namespace {

std::string ascii_lower(std::string s) {
    for (char& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

// Lower-case, strip a single pair of surrounding [] (IPv6 literal authority) and one
// trailing '.' (FQDN root), so "API.Evil.Com.", "[FD00:EC2::254]" normalize predictably.
std::string normalize_host(const std::string& raw) {
    std::string h = ascii_lower(raw);
    if (h.size() >= 2 && h.front() == '[' && h.back() == ']') h = h.substr(1, h.size() - 2);
    if (!h.empty() && h.back() == '.') h.pop_back();
    return h;
}

// Exact OR dot-suffix match: pattern "evil.com" matches "evil.com" and "api.evil.com" (but
// NOT "notevil.com"). Both arguments are expected already normalized.
bool host_matches(const std::string& host, const std::string& pattern) {
    if (pattern.empty()) return false;
    if (host == pattern) return true;
    if (host.size() > pattern.size() &&
        host.compare(host.size() - pattern.size(), pattern.size(), pattern) == 0 &&
        host[host.size() - pattern.size() - 1] == '.') {
        return true;
    }
    return false;
}

bool ipv6_of(const std::string& h, std::array<uint8_t, 16>& out) {
    struct in6_addr a;
    if (::inet_pton(AF_INET6, h.c_str(), &a) == 1) {
        std::memcpy(out.data(), &a, 16);
        return true;
    }
    return false;
}

// Canonicalize `h` to a 32-bit IPv4 address (host byte order) the SAME way the resolver
// (getaddrinfo, which the proxy actually dials with) does, so obfuscated numeric encodings
// cannot slip past IP-based policy. Returns true and fills `out` for:
//   * canonical + shorthand dotted decimal, a bare 32-bit integer, and octal (0-prefixed) /
//     hex (0x-prefixed) parts — every form ::inet_aton accepts, which is exactly what glibc
//     getaddrinfo treats as a numeric IPv4 (e.g. "2852039166", "0xA9FEA9FE", "0251.0376...").
//   * IPv4-mapped IPv6 literals (::ffff:a.b.c.d and ::ffff:hhhh:hhhh) — unwrapped to the
//     embedded v4, since getaddrinfo yields a sockaddr that connects to that v4 address.
// A genuine (non-mapped) IPv6 literal returns false (it is not an IPv4 address).
bool ipv4_of(const std::string& h, uint32_t& out) {
    // IPv4-mapped IPv6 first: inet_aton would reject the colons, so unwrap here.
    struct in6_addr a6;
    if (::inet_pton(AF_INET6, h.c_str(), &a6) == 1) {
        if (IN6_IS_ADDR_V4MAPPED(&a6)) {
            out = (static_cast<uint32_t>(a6.s6_addr[12]) << 24) |
                  (static_cast<uint32_t>(a6.s6_addr[13]) << 16) |
                  (static_cast<uint32_t>(a6.s6_addr[14]) << 8) |
                  static_cast<uint32_t>(a6.s6_addr[15]);
            return true;
        }
        return false;  // real IPv6 address, not an IPv4
    }
    // inet_aton accepts the resolver's numeric forms (decimal/hex/octal + a / a.b / a.b.c
    // shorthands); it is a strict superset of inet_pton's canonical dotted-quad.
    struct in_addr a;
    if (::inet_aton(h.c_str(), &a) != 0) {
        out = ntohl(a.s_addr);
        return true;
    }
    return false;
}

// Match `host` against `pattern` (both already normalized). When `pattern` denotes an IP
// literal (in ANY encoding), match IFF `host` canonicalizes to the SAME IP — so a single
// listed IP literal catches every decimal/hex/octal/v4-mapped encoding of that address.
// Otherwise `pattern` is a NAME: an IP-literal host never matches it, a name host matches
// by exact/dot-suffix. This closes obfuscated-encoding bypasses of block/allow/metadata.
bool host_or_ip_matches(const std::string& host, const std::string& pattern) {
    uint32_t hv4 = 0, pv4 = 0;
    const bool p_v4 = ipv4_of(pattern, pv4);
    if (p_v4) return ipv4_of(host, hv4) && hv4 == pv4;

    std::array<uint8_t, 16> hv6{}, pv6{};
    const bool p_v6 = ipv6_of(pattern, pv6);
    if (p_v6) return ipv6_of(host, hv6) && hv6 == pv6;

    // Name pattern: never let an IP-literal host match a name.
    if (ipv4_of(host, hv4) || ipv6_of(host, hv6)) return false;
    return host_matches(host, pattern);
}

// True when `host` (normalized) denotes a cloud metadata endpoint that must be blocked:
// a link-local 169.254.0.0/16 literal, one of the built-in metadata names/IPs, or any
// caller-supplied metadata_endpoints entry (compared IP-canonically when both sides parse
// as IPs, else by exact/dot-suffix name match).
bool host_is_metadata(const std::string& host, const std::vector<std::string>& extra) {
    uint32_t hv4 = 0;
    // Link-local 169.254.0.0/16 in ANY IPv4 literal form the resolver accepts (dotted,
    // decimal/hex/octal integer, IPv4-mapped IPv6).
    if (ipv4_of(host, hv4) && (hv4 >> 16) == 0xA9FE) return true;

    static const char* kDefaults[] = {
        "169.254.169.254", "fd00:ec2::254", "metadata.google.internal", "metadata"};

    for (const char* d : kDefaults)
        if (host_or_ip_matches(host, normalize_host(d))) return true;
    for (const std::string& e : extra)
        if (host_or_ip_matches(host, normalize_host(e))) return true;
    return false;
}

}  // namespace

bool host_allowed(const std::string& raw_host, const NetworkPolicy& p) {
    const std::string host = normalize_host(raw_host);
    if (host.empty()) return false;  // fail closed

    // 1. block_hosts WINS over everything else. IP literals match IP-canonically, so an
    //    obfuscated numeric encoding of a blocked address (decimal/hex/octal/v4-mapped) is
    //    still rejected.
    for (const std::string& b : p.block_hosts)
        if (host_or_ip_matches(host, normalize_host(b))) return false;

    // 2. metadata endpoints (SSRF hardening) when enabled.
    if (p.block_private_metadata_endpoints && host_is_metadata(host, p.metadata_endpoints))
        return false;

    // 3. default action.
    if (p.default_action == "deny") {
        for (const std::string& a : p.allow_hosts)
            if (host_or_ip_matches(host, normalize_host(a))) return true;
        return false;  // allow-list mode: nothing else gets out
    }
    // "allow" (the default): permitted unless it was blocked above.
    return true;
}

// ===========================================================================
// ProxyServer
// ===========================================================================

namespace {

void ignore_sigpipe_once() {
    static std::once_flag once;
    std::call_once(once, [] { ::signal(SIGPIPE, SIG_IGN); });
}

void set_socket_timeout(int fd, int seconds) {
    if (seconds <= 0) return;
    struct timeval tv;
    tv.tv_sec = seconds;
    tv.tv_usec = 0;
    ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}

bool write_all_fd(int fd, const char* buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        ssize_t n = ::send(fd, buf + off, len - off, MSG_NOSIGNAL);
        if (n < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        if (n == 0) return false;
        off += static_cast<size_t>(n);
    }
    return true;
}

bool iequals(const std::string& a, const std::string& b) {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i)
        if (std::tolower(static_cast<unsigned char>(a[i])) !=
            std::tolower(static_cast<unsigned char>(b[i])))
            return false;
    return true;
}

// Hop-by-hop / proxy-management headers that must NEVER be forwarded to the origin. NOTE:
// Content-Length and Transfer-Encoding are intentionally NOT here — the body is relayed
// verbatim, so the origin needs the original framing headers to delimit it.
bool is_hop_by_hop(const std::string& name) {
    static const char* kHop[] = {"connection",   "proxy-connection", "proxy-authorization",
                                 "proxy-authenticate", "keep-alive",  "upgrade"};
    for (const char* h : kHop)
        if (iequals(name, h)) return true;
    return false;
}

const char* kForbidden =
    "HTTP/1.1 403 Forbidden\r\n"
    "Connection: close\r\n"
    "\r\n";
const char* kBadRequest =
    "HTTP/1.1 400 Bad Request\r\n"
    "Connection: close\r\n"
    "\r\n";
const char* kBadGateway =
    "HTTP/1.1 502 Bad Gateway\r\n"
    "Connection: close\r\n"
    "\r\n";
const char* kConnectOk = "HTTP/1.1 200 Connection Established\r\n\r\n";

// Read the request head from `fd` up to and including CRLFCRLF. On success `head` holds
// those bytes and `leftover` any body bytes read past the terminator. Bounded head size and
// an absolute wall-clock deadline defeat a slowloris client that dribbles bytes.
bool read_request_head(int fd, std::string& head, std::string& leftover, int timeout_s) {
    static const std::string kTerm = "\r\n\r\n";
    static const size_t kMaxHead = 64 * 1024;
    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::seconds(timeout_s > 0 ? timeout_s : 1);
    std::string buf;
    char tmp[4096];
    for (;;) {
        ssize_t n = ::recv(fd, tmp, sizeof(tmp), 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        if (n == 0) return false;
        buf.append(tmp, static_cast<size_t>(n));
        size_t t = buf.find(kTerm);
        if (t != std::string::npos) {
            size_t body_start = t + kTerm.size();
            head = buf.substr(0, body_start);
            leftover = buf.substr(body_start);
            return true;
        }
        if (buf.size() > kMaxHead) return false;
        if (std::chrono::steady_clock::now() >= deadline) return false;
    }
}

// Render a resolved sockaddr's numeric address to a string (e.g. "169.254.169.254", "::1").
// Returns false for an address family we cannot canonicalize.
bool sockaddr_to_ip(const struct sockaddr* sa, std::string& out) {
    char buf[INET6_ADDRSTRLEN];
    if (sa->sa_family == AF_INET) {
        const auto* s = reinterpret_cast<const struct sockaddr_in*>(sa);
        if (!::inet_ntop(AF_INET, &s->sin_addr, buf, sizeof(buf))) return false;
        out = buf;
        return true;
    }
    if (sa->sa_family == AF_INET6) {
        const auto* s = reinterpret_cast<const struct sockaddr_in6*>(sa);
        if (!::inet_ntop(AF_INET6, &s->sin6_addr, buf, sizeof(buf))) return false;
        out = buf;
        return true;
    }
    return false;
}

// Post-resolution SSRF guard. `ip` is a RESOLVED numeric address getaddrinfo handed back for
// the request target. Returns true if that address is fenced off by the BLOCK-side rules of
// policy `p` — a block_hosts IP literal (matched IP-canonically) or, when metadata blocking is
// on, any metadata/link-local address. The allow-list is deliberately NOT consulted here: the
// literal request host already passed host_allowed(); this second pass only stops a NAME from
// resolving INTO an address policy blocks by IP (defeating block_hosts IP literals and the
// default-on cloud-metadata guard). Fails CLOSED for an unrenderable address.
bool resolved_ip_blocked(const std::string& ip, const NetworkPolicy& p) {
    const std::string host = normalize_host(ip);
    if (host.empty()) return true;  // fail closed
    for (const std::string& b : p.block_hosts)
        if (host_or_ip_matches(host, normalize_host(b))) return true;
    if (p.block_private_metadata_endpoints && host_is_metadata(host, p.metadata_endpoints))
        return true;
    return false;
}

// Non-blocking TCP connect to host:port with a bounded wait. Returns fd or -1.
//
// Before dialing, EVERY address getaddrinfo returns for `host` is re-checked against the
// block-side policy (resolved_ip_blocked): if ANY resolved address is a blocked/metadata
// address the whole attempt is refused (fail closed) and `blocked` is set true so the caller
// answers 403 rather than 502 — this is the post-resolution SSRF fix. We connect only to
// addresses from this already-vetted result set (no re-resolve) to avoid a TOCTOU window.
int tcp_connect(const std::string& host, const std::string& port, int timeout_s,
                const NetworkPolicy& policy, bool& blocked) {
    blocked = false;
    struct addrinfo hints;
    std::memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    struct addrinfo* res = nullptr;
    if (::getaddrinfo(host.c_str(), port.c_str(), &hints, &res) != 0 || !res) return -1;
    // Vet the entire resolved set FIRST: a name that maps (even partially) to a fenced-off
    // address is refused outright, so it can never be reached by picking a different record.
    for (struct addrinfo* ai = res; ai; ai = ai->ai_next) {
        std::string ip;
        if (!sockaddr_to_ip(ai->ai_addr, ip) || resolved_ip_blocked(ip, policy)) {
            ::freeaddrinfo(res);
            blocked = true;
            return -1;
        }
    }
    int fd = -1;
    for (struct addrinfo* ai = res; ai; ai = ai->ai_next) {
        fd = ::socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) continue;
        int flags = ::fcntl(fd, F_GETFL, 0);
        ::fcntl(fd, F_SETFL, flags | O_NONBLOCK);
        int rc = ::connect(fd, ai->ai_addr, ai->ai_addrlen);
        if (rc == 0) {
            ::fcntl(fd, F_SETFL, flags);
            break;
        }
        if (errno != EINPROGRESS) {
            ::close(fd);
            fd = -1;
            continue;
        }
        struct pollfd pfd;
        pfd.fd = fd;
        pfd.events = POLLOUT;
        int pr = ::poll(&pfd, 1, timeout_s > 0 ? timeout_s * 1000 : -1);
        if (pr <= 0) {
            ::close(fd);
            fd = -1;
            continue;
        }
        int soerr = 0;
        socklen_t slen = sizeof(soerr);
        if (::getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &slen) < 0 || soerr != 0) {
            ::close(fd);
            fd = -1;
            continue;
        }
        ::fcntl(fd, F_SETFL, flags);
        break;
    }
    ::freeaddrinfo(res);
    if (fd >= 0) set_socket_timeout(fd, timeout_s);
    return fd;
}

// Parse a CONNECT/authority "host[:port]" (IPv6 in [..]). Defaults the port to "443".
bool parse_authority(const std::string& s, std::string& host, std::string& port) {
    host.clear();
    port.clear();
    if (s.empty()) return false;
    if (s.front() == '[') {
        size_t c = s.find(']');
        if (c == std::string::npos) return false;
        host = s.substr(1, c - 1);
        if (c + 1 < s.size()) {
            if (s[c + 1] != ':') return false;
            port = s.substr(c + 2);
        }
    } else {
        size_t colon = s.rfind(':');
        if (colon == std::string::npos) {
            host = s;
        } else {
            host = s.substr(0, colon);
            port = s.substr(colon + 1);
        }
    }
    if (host.empty()) return false;
    if (port.empty()) port = "443";
    for (char c : port)
        if (!std::isdigit(static_cast<unsigned char>(c))) return false;
    return true;
}

// Build the origin-form request head to send to the origin server: request-line rewritten
// to origin form ("GET /path?query HTTP/1.1"), Host set from the target authority, hop-by-hop
// and proxy headers stripped, Connection: close forced (close-delimited response => stream to
// EOF). Content-Length is de-duplicated defensively.
std::string build_origin_head(const HttpRequestHead& req, const Url& target) {
    std::string version = req.version.empty() ? "HTTP/1.1" : req.version;
    std::string path = target.path.empty() ? "/" : target.path;

    std::string host_value = target.host;
    bool default_port = (target.scheme == "http" && target.port == "80") ||
                        (target.scheme == "https" && target.port == "443");
    if (!target.port.empty() && !default_port) host_value += ":" + target.port;

    std::string out;
    out.reserve(256);
    out += req.method + " " + path + " " + version + "\r\n";
    out += "Host: " + host_value + "\r\n";

    bool cl_emitted = false;
    for (const auto& kv : req.headers) {
        const std::string& name = kv.first;
        if (iequals(name, "Host")) continue;  // set explicitly above
        if (is_hop_by_hop(name)) continue;     // never forward hop-by-hop / proxy headers
        if (iequals(name, "Content-Length")) {
            if (cl_emitted) continue;  // collapse duplicates
            cl_emitted = true;
        }
        out += name + ": " + kv.second + "\r\n";
    }
    out += "Connection: close\r\n\r\n";
    return out;
}

// Full-duplex byte relay between `a` and `b` until BOTH read-halves reach EOF, a write
// fails, stop() fires (shutdown_fd), or the connection sits idle past `idle_ms`. When one
// side's read half closes, the peer's write half is shut down so it observes EOF. Used for
// both the CONNECT blind tunnel and the HTTP request-body/response phase.
void bidi_relay(int a, int b, int shutdown_fd, int idle_ms) {
    bool a_open = true, b_open = true;
    char buf[16384];
    while (a_open || b_open) {
        struct pollfd pfds[3];
        int nf = 0;
        int ia = -1, ib = -1, is = -1;
        if (a_open) {
            pfds[nf].fd = a;
            pfds[nf].events = POLLIN;
            ia = nf++;
        }
        if (b_open) {
            pfds[nf].fd = b;
            pfds[nf].events = POLLIN;
            ib = nf++;
        }
        if (shutdown_fd >= 0) {
            pfds[nf].fd = shutdown_fd;
            pfds[nf].events = POLLIN;
            is = nf++;
        }
        int pr = ::poll(pfds, static_cast<nfds_t>(nf), idle_ms);
        if (pr < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (pr == 0) break;  // idle timeout
        if (is >= 0 && (pfds[is].revents & POLLIN)) break;  // stop() signalled

        if (ia >= 0 && (pfds[ia].revents & (POLLIN | POLLHUP | POLLERR))) {
            ssize_t r = ::recv(a, buf, sizeof(buf), 0);
            if (r > 0) {
                if (!write_all_fd(b, buf, static_cast<size_t>(r))) break;
            } else {
                a_open = false;
                ::shutdown(b, SHUT_WR);
            }
        }
        if (ib >= 0 && (pfds[ib].revents & (POLLIN | POLLHUP | POLLERR))) {
            ssize_t r = ::recv(b, buf, sizeof(buf), 0);
            if (r > 0) {
                if (!write_all_fd(a, buf, static_cast<size_t>(r))) break;
            } else {
                b_open = false;
                ::shutdown(a, SHUT_WR);
            }
        }
    }
}

// True iff `sa` is an IPv4 (127.0.0.0/8) or IPv6 (::1) loopback address.
bool is_loopback_sockaddr(const struct sockaddr* sa) {
    if (sa->sa_family == AF_INET) {
        const auto* s = reinterpret_cast<const struct sockaddr_in*>(sa);
        return (ntohl(s->sin_addr.s_addr) >> 24) == 127;
    }
    if (sa->sa_family == AF_INET6) {
        const auto* s = reinterpret_cast<const struct sockaddr_in6*>(sa);
        if (IN6_IS_ADDR_LOOPBACK(&s->sin6_addr)) return true;
        if (IN6_IS_ADDR_V4MAPPED(&s->sin6_addr)) return s->sin6_addr.s6_addr[12] == 127;
        return false;
    }
    return false;
}

struct ConnExit {
    std::function<void()> fn;
    explicit ConnExit(std::function<void()> f) : fn(std::move(f)) {}
    ConnExit(const ConnExit&) = delete;
    ConnExit& operator=(const ConnExit&) = delete;
    ~ConnExit() {
        if (fn) fn();
    }
};

}  // namespace

ProxyServer::~ProxyServer() { stop(); }

bool ProxyServer::start(const std::string& loopback_addr, int port, const NetworkPolicy& policy,
                        int timeout_seconds, std::string& err) {
    ignore_sigpipe_once();
    policy_ = policy;
    timeout_s_ = timeout_seconds >= 1 ? timeout_seconds : 1;

    shutdown_fd_ = ::eventfd(0, EFD_NONBLOCK);
    if (shutdown_fd_ < 0) {
        err = "eventfd() failed: " + std::string(std::strerror(errno));
        return false;
    }

    std::string port_str = std::to_string(port);
    struct addrinfo hints;
    std::memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE | AI_NUMERICHOST;  // literal loopback address only, no DNS
    struct addrinfo* res = nullptr;
    if (::getaddrinfo(loopback_addr.c_str(), port_str.c_str(), &hints, &res) != 0 || !res) {
        err = "proxy listen address must be a numeric loopback address: " + loopback_addr;
        stop();
        return false;
    }
    // AI_NUMERICHOST still admits wildcard ("0.0.0.0") / routable literals: the proxy relays
    // to arbitrary origins and can carry the child's credentials, so it MUST bind loopback.
    if (!is_loopback_sockaddr(res->ai_addr)) {
        ::freeaddrinfo(res);
        err = "proxy must bind a loopback address (127.0.0.0/8 or ::1), got: " + loopback_addr;
        stop();
        return false;
    }

    int lfd = ::socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (lfd < 0) {
        ::freeaddrinfo(res);
        err = "proxy socket() failed: " + std::string(std::strerror(errno));
        stop();
        return false;
    }
    int one = 1;
    ::setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    if (::bind(lfd, res->ai_addr, res->ai_addrlen) < 0) {
        std::string be = std::strerror(errno);
        ::close(lfd);
        ::freeaddrinfo(res);
        err = "proxy bind(" + loopback_addr + ":" + port_str + ") failed: " + be;
        stop();
        return false;
    }
    ::freeaddrinfo(res);

    if (::listen(lfd, 64) < 0) {
        std::string le = std::strerror(errno);
        ::close(lfd);
        err = "proxy listen() failed: " + le;
        stop();
        return false;
    }

    int actual_port = 0;
    struct sockaddr_storage ss;
    socklen_t slen = sizeof(ss);
    if (::getsockname(lfd, reinterpret_cast<struct sockaddr*>(&ss), &slen) == 0) {
        if (ss.ss_family == AF_INET)
            actual_port = ntohs(reinterpret_cast<struct sockaddr_in*>(&ss)->sin_port);
        else if (ss.ss_family == AF_INET6)
            actual_port = ntohs(reinterpret_cast<struct sockaddr_in6*>(&ss)->sin6_port);
    }

    listen_fd_ = lfd;
    port_ = actual_port;
    running_.store(true);
    accept_thread_ = std::thread(&ProxyServer::accept_loop, this);
    return true;
}

void ProxyServer::accept_loop() {
    for (;;) {
        struct pollfd pfds[2];
        pfds[0].fd = listen_fd_;
        pfds[0].events = POLLIN;
        pfds[1].fd = shutdown_fd_;
        pfds[1].events = POLLIN;
        int pr = ::poll(pfds, 2, -1);
        if (pr < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (pfds[1].revents & POLLIN) break;
        if (!(pfds[0].revents & POLLIN)) continue;

        int cfd = ::accept(listen_fd_, nullptr, nullptr);
        if (cfd < 0) {
            if (errno == EINTR || errno == ECONNABORTED) continue;
            if (!running_.load()) break;
            continue;
        }
        if (!running_.load()) {
            ::close(cfd);
            break;
        }
        {
            std::lock_guard<std::mutex> lk(conn_mu_);
            ++active_conns_;
        }
        try {
            std::thread(&ProxyServer::handle_connection, this, cfd).detach();
        } catch (...) {
            ::close(cfd);
            std::lock_guard<std::mutex> lk(conn_mu_);
            if (--active_conns_ == 0) conn_cv_.notify_all();
        }
    }
}

void ProxyServer::handle_connection(int client_fd) {
    ConnExit reap([this] {
        std::lock_guard<std::mutex> lk(conn_mu_);
        if (--active_conns_ == 0) conn_cv_.notify_all();
    });

    const int timeout_s = timeout_s_;
    set_socket_timeout(client_fd, timeout_s);
    {
        int one = 1;
        ::setsockopt(client_fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    }

    auto reply = [&](const char* msg) {
        write_all_fd(client_fd, msg, std::strlen(msg));
        ::shutdown(client_fd, SHUT_RDWR);
        ::close(client_fd);
    };

    // 1. Read + parse the client's request head.
    std::string raw_head, leftover;
    if (!read_request_head(client_fd, raw_head, leftover, timeout_s)) {
        reply(kBadRequest);
        return;
    }
    HttpRequestHead req;
    std::string perr;
    if (!parse_request_head(raw_head, req, perr)) {
        reply(kBadRequest);
        return;
    }

    const int idle_ms = timeout_s > 0 ? timeout_s * 1000 : -1;

    // -----------------------------------------------------------------------
    // CONNECT (HTTPS tunnel): target is authority-form "host:port".
    // -----------------------------------------------------------------------
    if (iequals(req.method, "CONNECT")) {
        std::string host, port;
        if (!parse_authority(req.target, host, port)) {
            reply(kBadRequest);
            return;
        }
        // Policy is applied on the HOST BEFORE any upstream connection is attempted, so a
        // blocked target (e.g. the metadata IP) is NEVER dialed.
        if (!host_allowed(host, policy_)) {
            reply(kForbidden);
            return;
        }
        bool blocked = false;
        int up_fd = tcp_connect(host, port, timeout_s, policy_, blocked);
        if (up_fd < 0) {
            // A name that RESOLVED to a blocked/metadata address is a policy refusal (403),
            // not an upstream failure (502) — never open the tunnel to it.
            reply(blocked ? kForbidden : kBadGateway);
            return;
        }
        set_socket_timeout(up_fd, timeout_s);
        if (!write_all_fd(client_fd, kConnectOk, std::strlen(kConnectOk))) {
            ::close(up_fd);
            ::close(client_fd);
            return;
        }
        // Blind byte tunnel — no TLS interception. Any client body bytes already buffered
        // past the CONNECT head are forwarded first.
        if (!leftover.empty() && !write_all_fd(up_fd, leftover.data(), leftover.size())) {
            ::close(up_fd);
            ::close(client_fd);
            return;
        }
        bidi_relay(client_fd, up_fd, shutdown_fd_, idle_ms);
        ::shutdown(up_fd, SHUT_RDWR);
        ::close(up_fd);
        ::shutdown(client_fd, SHUT_RDWR);
        ::close(client_fd);
        return;
    }

    // -----------------------------------------------------------------------
    // Plain HTTP: request-line target is ABSOLUTE-form "http://host:port/path".
    // -----------------------------------------------------------------------
    Url target;
    std::string uerr;
    if (!parse_url(req.target, target, uerr) || target.scheme != "http") {
        // Not an absolute-form http URL: this proxy speaks absolute-form + CONNECT only.
        reply(kBadRequest);
        return;
    }
    // Reject ambiguous body framing (CL.TE / CL.CL / malformed CL) BEFORE connecting — the
    // same request-smuggling hardening the egress bridge enforces.
    if (check_request_framing(req) != FramingReject::None) {
        reply(kBadRequest);
        return;
    }
    // Policy on the target host, BEFORE connecting. A blocked host gets a bare 403 that
    // reveals no internal detail and no upstream is dialed.
    if (!host_allowed(target.host, policy_)) {
        reply(kForbidden);
        return;
    }

    bool blocked = false;
    int up_fd = tcp_connect(target.host, target.port, timeout_s, policy_, blocked);
    if (up_fd < 0) {
        // Resolved-to-blocked address => 403 (post-resolution SSRF guard); any other dial
        // failure => 502. Either way the upstream is never used.
        reply(blocked ? kForbidden : kBadGateway);
        return;
    }
    set_socket_timeout(up_fd, timeout_s);

    std::string head = build_origin_head(req, target);
    if (!write_all_fd(up_fd, head.data(), head.size())) {
        ::close(up_fd);
        reply(kBadGateway);
        return;
    }
    // Forward any request-body bytes already buffered past the head, then relay both
    // directions verbatim until EOF. Because we forced Connection: close upstream, the
    // origin's response is close-delimited and streams transparently (chunked/SSE included).
    if (!leftover.empty() && !write_all_fd(up_fd, leftover.data(), leftover.size())) {
        ::close(up_fd);
        ::close(client_fd);
        return;
    }
    bidi_relay(client_fd, up_fd, shutdown_fd_, idle_ms);
    ::shutdown(up_fd, SHUT_RDWR);
    ::close(up_fd);
    ::shutdown(client_fd, SHUT_RDWR);
    ::close(client_fd);
}

void ProxyServer::stop() {
    running_.exchange(false);

    if (shutdown_fd_ >= 0) {
        uint64_t one = 1;
        ssize_t w = ::write(shutdown_fd_, &one, sizeof(one));
        (void)w;
    }

    if (accept_thread_.joinable()) accept_thread_.join();
    if (listen_fd_ >= 0) {
        ::close(listen_fd_);
        listen_fd_ = -1;
    }

    // Wait for every detached worker to finish. The accept thread is joined above so no new
    // workers spawn; socket timeouts + the shutdown_fd poll bound how long an in-flight
    // worker can still block, so this terminates.
    {
        std::unique_lock<std::mutex> lk(conn_mu_);
        conn_cv_.wait(lk, [this] { return active_conns_ == 0; });
    }

    if (shutdown_fd_ >= 0) {
        ::close(shutdown_fd_);
        shutdown_fd_ = -1;
    }
    port_ = -1;
}

}  // namespace raincoat
