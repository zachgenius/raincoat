// Raincoat — egress: host-side HTTP(S) forward proxy implementation.
//
// See egress.hpp for the contract and the honest networking-model caveat.
#include "egress.hpp"

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <chrono>
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

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

namespace raincoat {

namespace {

// ---- tiny string helpers (kept local so the pure helpers have no link deps) ----

std::string ascii_lower(std::string s) {
    for (char& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

bool iequals(const std::string& a, const std::string& b) {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i) {
        if (std::tolower(static_cast<unsigned char>(a[i])) !=
            std::tolower(static_cast<unsigned char>(b[i])))
            return false;
    }
    return true;
}

std::string trim_ws(const std::string& s) {
    size_t b = 0, e = s.size();
    while (b < e && std::isspace(static_cast<unsigned char>(s[b]))) ++b;
    while (e > b && std::isspace(static_cast<unsigned char>(s[e - 1]))) --e;
    return s.substr(b, e - b);
}

const char* kBadGateway =
    "HTTP/1.1 502 Bad Gateway\r\n"
    "Connection: close\r\n"
    "Content-Length: 0\r\n"
    "\r\n";

const char* kGatewayTimeout =
    "HTTP/1.1 504 Gateway Timeout\r\n"
    "Connection: close\r\n"
    "Content-Length: 0\r\n"
    "\r\n";

const char* kBadRequest =
    "HTTP/1.1 400 Bad Request\r\n"
    "Connection: close\r\n"
    "Content-Length: 0\r\n"
    "\r\n";

}  // namespace

// ---------------------------------------------------------------------------
// parse_url
// ---------------------------------------------------------------------------

bool parse_url(const std::string& url, Url& out, std::string& err) {
    out = Url{};
    const std::string sep = "://";
    size_t scheme_end = url.find(sep);
    if (scheme_end == std::string::npos) {
        err = "URL missing scheme://: " + url;
        return false;
    }
    std::string scheme = ascii_lower(url.substr(0, scheme_end));
    if (scheme != "http" && scheme != "https") {
        err = "unsupported URL scheme (want http/https): " + url;
        return false;
    }
    size_t auth_start = scheme_end + sep.size();
    size_t path_start = url.find('/', auth_start);
    std::string authority =
        (path_start == std::string::npos) ? url.substr(auth_start)
                                          : url.substr(auth_start, path_start - auth_start);
    std::string path = (path_start == std::string::npos) ? "" : url.substr(path_start);

    if (authority.empty()) {
        err = "URL missing host: " + url;
        return false;
    }

    std::string host, port;
    if (authority.front() == '[') {
        // IPv6 literal: [::1] or [::1]:port
        size_t close = authority.find(']');
        if (close == std::string::npos) {
            err = "URL malformed IPv6 authority: " + url;
            return false;
        }
        host = authority.substr(1, close - 1);
        if (close + 1 < authority.size()) {
            if (authority[close + 1] != ':') {
                err = "URL malformed IPv6 authority: " + url;
                return false;
            }
            port = authority.substr(close + 2);
        }
    } else {
        size_t colon = authority.rfind(':');
        if (colon == std::string::npos) {
            host = authority;
        } else {
            host = authority.substr(0, colon);
            port = authority.substr(colon + 1);
        }
    }

    if (host.empty()) {
        err = "URL missing host: " + url;
        return false;
    }
    if (!port.empty()) {
        for (char c : port) {
            if (!std::isdigit(static_cast<unsigned char>(c))) {
                err = "URL has non-numeric port: " + url;
                return false;
            }
        }
    } else {
        port = (scheme == "https") ? "443" : "80";
    }

    out.scheme = scheme;
    out.host = host;
    out.port = port;
    out.path = path;
    return true;
}

// ---------------------------------------------------------------------------
// parse_request_head
// ---------------------------------------------------------------------------

bool parse_request_head(const std::string& raw_head, HttpRequestHead& out, std::string& err) {
    out = HttpRequestHead{};

    // Work on the head only: cut at CRLFCRLF (or LFLF) if present.
    std::string head = raw_head;
    size_t term = head.find("\r\n\r\n");
    if (term != std::string::npos) head = head.substr(0, term);

    // Split into lines on CRLF (tolerate bare LF).
    std::vector<std::string> lines;
    size_t pos = 0;
    while (pos <= head.size()) {
        size_t nl = head.find('\n', pos);
        std::string line;
        if (nl == std::string::npos) {
            line = head.substr(pos);
            pos = head.size() + 1;
        } else {
            line = head.substr(pos, nl - pos);
            pos = nl + 1;
        }
        if (!line.empty() && line.back() == '\r') line.pop_back();
        lines.push_back(line);
    }
    // Drop a possible trailing empty element from a terminating newline.
    while (!lines.empty() && lines.back().empty()) lines.pop_back();

    // RFC 7230 §3.5: a server SHOULD ignore at least one empty line before the
    // request-line (some clients emit a stray leading CRLF). Skip a small, bounded
    // number of leading blank lines rather than rejecting the request.
    {
        size_t skipped = 0;
        while (!lines.empty() && lines.front().empty() && skipped < 8) {
            lines.erase(lines.begin());
            ++skipped;
        }
    }

    if (lines.empty() || lines.front().empty()) {
        err = "empty request head";
        return false;
    }

    // Request line: METHOD SP TARGET SP VERSION
    const std::string& rl = lines.front();
    size_t sp1 = rl.find(' ');
    if (sp1 == std::string::npos) {
        err = "malformed request line: " + rl;
        return false;
    }
    size_t sp2 = rl.find(' ', sp1 + 1);
    if (sp2 == std::string::npos) {
        err = "malformed request line (missing version): " + rl;
        return false;
    }
    out.method = rl.substr(0, sp1);
    out.target = rl.substr(sp1 + 1, sp2 - sp1 - 1);
    out.version = trim_ws(rl.substr(sp2 + 1));
    if (out.method.empty() || out.target.empty() || out.version.empty()) {
        err = "malformed request line: " + rl;
        return false;
    }

    for (size_t i = 1; i < lines.size(); ++i) {
        const std::string& hl = lines[i];
        if (hl.empty()) continue;  // tolerate stray blank lines
        size_t colon = hl.find(':');
        if (colon == std::string::npos) {
            err = "malformed header line: " + hl;
            return false;
        }
        std::string name = trim_ws(hl.substr(0, colon));
        std::string value = trim_ws(hl.substr(colon + 1));
        if (name.empty()) {
            err = "malformed header line (empty name): " + hl;
            return false;
        }
        // Reject embedded control characters (bytes < 0x20, except HTAB) in the
        // name or value. trim_ws already strips a trailing bare CR, but a lone CR
        // (or other control byte) in the MIDDLE of a value would otherwise survive
        // and be re-emitted verbatim to the upstream — harden against that.
        auto has_ctl = [](const std::string& s) {
            for (unsigned char c : s) {
                if (c < 0x20 && c != '\t') return true;
            }
            return false;
        };
        if (has_ctl(name) || has_ctl(value)) {
            err = "malformed header line (control character): " + hl;
            return false;
        }
        out.headers.emplace_back(std::move(name), std::move(value));
    }
    return true;
}

// ---------------------------------------------------------------------------
// content_length / find_header
// ---------------------------------------------------------------------------

bool find_header(const HttpRequestHead& head, const std::string& name, std::string& value_out) {
    for (const auto& kv : head.headers) {
        if (iequals(kv.first, name)) {
            value_out = kv.second;
            return true;
        }
    }
    return false;
}

long content_length(const HttpRequestHead& head) {
    std::string v;
    if (!find_header(head, "Content-Length", v)) return -1;
    v = trim_ws(v);
    if (v.empty()) return -1;
    errno = 0;
    char* end = nullptr;
    long n = std::strtol(v.c_str(), &end, 10);
    if (errno != 0 || end == v.c_str() || *end != '\0' || n < 0) return -1;
    return n;
}

// ---------------------------------------------------------------------------
// build_upstream_head
// ---------------------------------------------------------------------------

std::string build_upstream_head(const HttpRequestHead& req, const EgressBridge& b,
                                const Url& upstream) {
    std::string version = req.version.empty() ? "HTTP/1.1" : req.version;

    // Host value.
    std::string host_value;
    if (b.preserve_host) {
        if (!find_header(req, "Host", host_value)) {
            // No child Host to preserve; fall back to upstream host.
            host_value = upstream.host;
        }
    } else {
        host_value = upstream.host;
        bool default_port = (upstream.scheme == "https" && upstream.port == "443") ||
                            (upstream.scheme == "http" && upstream.port == "80");
        if (!upstream.port.empty() && !default_port) {
            host_value += ":" + upstream.port;
        }
    }

    // Request-line method + target, honoring the preserve_* knobs. Defaults are all
    // true, in which case method == req.method and target reconstructs to req.target
    // byte-for-byte (so default behavior is unchanged).
    std::string method = b.preserve_method ? req.method : "GET";

    std::string path = req.target;
    std::string query;  // includes the leading '?' when present
    size_t qpos = req.target.find('?');
    if (qpos != std::string::npos) {
        path = req.target.substr(0, qpos);
        query = req.target.substr(qpos);
    }
    if (!b.preserve_path) {
        // Substitute the upstream's configured path (its own query part dropped); "/" if none.
        std::string up_path = upstream.path;
        size_t uq = up_path.find('?');
        if (uq != std::string::npos) up_path = up_path.substr(0, uq);
        path = up_path.empty() ? "/" : up_path;
    }
    if (!b.preserve_query) query.clear();
    std::string target = path + query;

    // CL.TE framing hygiene: if the request declares chunked transfer-encoding, do NOT
    // also forward a Content-Length — carrying both is the classic request-smuggling
    // shape. Chunked framing wins (handle_connection() rejects CL+TE outright; this keeps
    // the pure builder safe if ever called directly).
    bool req_chunked = false;
    {
        std::string te;
        if (find_header(req, "Transfer-Encoding", te) &&
            ascii_lower(te).find("chunked") != std::string::npos) {
            req_chunked = true;
        }
    }

    std::string out;
    out.reserve(256);
    out += method;
    out += ' ';
    out += target;
    out += ' ';
    out += version;
    out += "\r\n";

    out += "Host: " + host_value + "\r\n";

    for (const auto& kv : req.headers) {
        const std::string& name = kv.first;
        if (iequals(name, "Host")) continue;               // set explicitly above
        if (iequals(name, "Connection")) continue;         // forced to close below
        if (iequals(name, "Proxy-Connection")) continue;   // hop-by-hop, never forward
        if (req_chunked && iequals(name, "Content-Length"))
            continue;  // CL.TE hygiene: chunked framing wins, never forward both
        bool stripped = false;
        for (const std::string& s : b.strip_headers) {
            if (iequals(name, s)) {
                stripped = true;
                break;
            }
        }
        if (stripped) continue;
        out += name + ": " + kv.second + "\r\n";
    }

    for (const auto& kv : b.inject_headers) {
        out += kv.first + ": " + kv.second + "\r\n";
    }

    out += "Connection: close\r\n";
    out += "\r\n";
    return out;
}

// ===========================================================================
// EgressServer
// ===========================================================================

namespace {

// Ignore SIGPIPE process-wide once; writing to a peer-closed socket must not kill us.
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

// Write all bytes; retries partial writes and EINTR; MSG_NOSIGNAL avoids SIGPIPE.
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

// A read/write endpoint that is either a plain fd or an OpenSSL connection.
struct Stream {
    int fd = -1;
    SSL* ssl = nullptr;

    ssize_t read(char* buf, size_t len) {
        if (ssl) {
            int n = SSL_read(ssl, buf, static_cast<int>(len));
            return n;  // <=0 => closed/error
        }
        for (;;) {
            ssize_t n = ::recv(fd, buf, len, 0);
            if (n < 0 && errno == EINTR) continue;
            return n;
        }
    }

    bool write_all(const char* buf, size_t len) {
        if (ssl) {
            size_t off = 0;
            while (off < len) {
                int n = SSL_write(ssl, buf + off, static_cast<int>(len - off));
                if (n <= 0) return false;
                off += static_cast<size_t>(n);
            }
            return true;
        }
        return write_all_fd(fd, buf, len);
    }
};

// Connect a TCP socket to host:port honoring a timeout. Returns fd or -1.
int tcp_connect(const std::string& host, const std::string& port, int timeout_s) {
    struct addrinfo hints;
    std::memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    struct addrinfo* res = nullptr;
    if (::getaddrinfo(host.c_str(), port.c_str(), &hints, &res) != 0 || !res) {
        return -1;
    }
    int fd = -1;
    for (struct addrinfo* ai = res; ai; ai = ai->ai_next) {
        fd = ::socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) continue;

        // Non-blocking connect with a bounded wait.
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

// Establish a verified TLS client connection over an already-connected fd.
// Returns an SSL* (with its own SSL_CTX owned via app-data-free teardown) or nullptr.
// On success, *ctx_out owns the context that must be freed alongside the SSL.
SSL* tls_connect(int fd, const std::string& sni_host, SSL_CTX** ctx_out) {
    static std::once_flag ssl_init;
    std::call_once(ssl_init, [] {
        OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS | OPENSSL_INIT_LOAD_CRYPTO_STRINGS,
                        nullptr);
    });

    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) return nullptr;
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    // Verify the peer certificate against the system trust store by default.
    if (SSL_CTX_set_default_verify_paths(ctx) != 1) {
        SSL_CTX_free(ctx);
        return nullptr;
    }
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);

    SSL* ssl = SSL_new(ctx);
    if (!ssl) {
        SSL_CTX_free(ctx);
        return nullptr;
    }
    SSL_set_fd(ssl, fd);
    // SNI.
    SSL_set_tlsext_host_name(ssl, sni_host.c_str());
    // Enable built-in hostname verification: SSL_connect fails on mismatch.
    SSL_set_hostflags(ssl, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
    SSL_set1_host(ssl, sni_host.c_str());

    if (SSL_connect(ssl) != 1) {
        // Handshake OR verification failure: clear, no crash, caller emits 502.
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        return nullptr;
    }
    *ctx_out = ctx;
    return ssl;
}

// Read the request head from the child until CRLFCRLF. Returns false on error/timeout.
// On success, `head` holds the bytes up to and including CRLFCRLF, and `leftover`
// holds any body bytes that were read past the terminator.
bool read_request_head(int fd, std::string& head, std::string& leftover, int timeout_s) {
    static const std::string kTerm = "\r\n\r\n";
    static const size_t kMaxHead = 64 * 1024;
    // Absolute wall-clock deadline across the WHOLE head read. Per-recv SO_RCVTIMEO alone
    // does not stop a slowloris client that dribbles one byte just under each timeout: it
    // would pin this worker thread indefinitely. Bound the total elapsed time too.
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(timeout_s);
    std::string buf;
    char tmp[4096];
    for (;;) {
        ssize_t n = ::recv(fd, tmp, sizeof(tmp), 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        if (n == 0) return false;  // peer closed before full head
        buf.append(tmp, static_cast<size_t>(n));
        size_t t = buf.find(kTerm);
        if (t != std::string::npos) {
            size_t body_start = t + kTerm.size();
            head = buf.substr(0, body_start);
            leftover = buf.substr(body_start);
            return true;
        }
        if (buf.size() > kMaxHead) return false;
        if (timeout_s > 0 && std::chrono::steady_clock::now() >= deadline) return false;
    }
}

// Read an HTTP message head (up to and including CRLFCRLF) off a Stream (plain fd or
// TLS). On success `head` holds the head and `leftover` any bytes read past it. Returns
// false on EOF/error/timeout before a full head, or if the head exceeds a bound.
bool read_head_from_stream(Stream& s, std::string& head, std::string& leftover) {
    static const std::string kTerm = "\r\n\r\n";
    static const size_t kMaxHead = 64 * 1024;
    std::string buf;
    char tmp[4096];
    for (;;) {
        ssize_t n = s.read(tmp, sizeof(tmp));
        if (n <= 0) return false;
        buf.append(tmp, static_cast<size_t>(n));
        size_t t = buf.find(kTerm);
        if (t != std::string::npos) {
            size_t body_start = t + kTerm.size();
            head = buf.substr(0, body_start);
            leftover = buf.substr(body_start);
            return true;
        }
        if (buf.size() > kMaxHead) return false;
    }
}

// Parse the numeric status code out of an HTTP status line ("HTTP/1.1 100 Continue").
// Returns -1 if it cannot be parsed.
int parse_status_code(const std::string& head) {
    size_t sp = head.find(' ');
    if (sp == std::string::npos) return -1;
    size_t start = sp + 1;
    while (start < head.size() && head[start] == ' ') ++start;
    int code = 0;
    int ndigits = 0;
    for (size_t i = start; i < head.size(); ++i) {
        char c = head[i];
        if (c == ' ' || c == '\r' || c == '\n') break;
        if (!std::isdigit(static_cast<unsigned char>(c))) return -1;
        // An HTTP status code is exactly three digits (RFC 7230 §3.1.2). Bound the
        // accumulator so a malformed/hostile upstream status line ("HTTP/1.1 100000...")
        // cannot overflow `int` (signed-overflow UB) or wrap into a bogus 1xx/2xx class.
        if (++ndigits > 3) return -1;
        code = code * 10 + (c - '0');
    }
    return ndigits == 3 ? code : -1;
}

// Wait until `fd` is readable, a shutdown was requested via `shutdown_fd`, or the
// timeout elapses. Lets stop() interrupt a relay blocked on a slow/dribbling peer
// instead of waiting out the socket timeout.
enum class WaitResult { Readable, Shutdown, TimedOut, Error };
WaitResult wait_readable(int fd, int shutdown_fd, int timeout_ms) {
    struct pollfd pfds[2];
    pfds[0].fd = fd;
    pfds[0].events = POLLIN;
    nfds_t nf = 1;
    if (shutdown_fd >= 0) {
        pfds[1].fd = shutdown_fd;
        pfds[1].events = POLLIN;
        nf = 2;
    }
    for (;;) {
        int pr = ::poll(pfds, nf, timeout_ms);
        if (pr < 0) {
            if (errno == EINTR) continue;
            return WaitResult::Error;
        }
        if (pr == 0) return WaitResult::TimedOut;
        if (nf == 2 && (pfds[1].revents & POLLIN)) return WaitResult::Shutdown;
        if (pfds[0].revents & (POLLIN | POLLHUP | POLLERR)) return WaitResult::Readable;
        return WaitResult::Error;
    }
}

// True iff `sa` is an IPv4 loopback (127.0.0.0/8) or IPv6 loopback (::1). Used to enforce
// the docs' loopback-only guarantee: AI_NUMERICHOST blocks DNS names but NOT routable or
// wildcard numeric addresses (e.g. "0.0.0.0" binds every interface, "8.8.8.8" is routable).
bool is_loopback_sockaddr(const struct sockaddr* sa) {
    if (sa->sa_family == AF_INET) {
        const auto* s = reinterpret_cast<const struct sockaddr_in*>(sa);
        return (ntohl(s->sin_addr.s_addr) >> 24) == 127;
    }
    if (sa->sa_family == AF_INET6) {
        const auto* s = reinterpret_cast<const struct sockaddr_in6*>(sa);
        if (IN6_IS_ADDR_LOOPBACK(&s->sin6_addr)) return true;
        // Accept an IPv4-mapped loopback (::ffff:127.0.0.0/8) too: the embedded IPv4
        // lives in the last four bytes. Fails closed either way.
        if (IN6_IS_ADDR_V4MAPPED(&s->sin6_addr)) {
            return s->sin6_addr.s6_addr[12] == 127;
        }
        return false;
    }
    return false;
}

// Incremental parser for an HTTP/1.1 chunked request body. We forward the child's chunked
// bytes to the upstream verbatim (the upstream de-chunks); this parser only tells us WHEN
// the body is complete so we stop blocking on the child socket. Unlike a fixed-literal scan
// for "\r\n0\r\n\r\n", it parses real chunk framing and therefore recognizes end-of-body
// even when the last chunk carries a chunk-extension ("0;ext\r\n\r\n") or trailer fields
// ("0\r\nX-Checksum: abc\r\n\r\n"). Feed each received slice; done() latches true once the
// terminating 0-length chunk + trailer section is consumed. error() latches on malformed or
// oversized framing (caller then stops relaying and lets the upstream see EOF on close).
class ChunkedBodyParser {
public:
    // Returns true once the whole body has been seen. Sets error on malformed framing.
    bool feed(const char* data, size_t len) {
        if (done_ || error_) return done_;
        acc_.append(data, len);
        for (;;) {
            // Guard the unparsed backlog. In Data state we drain immediately below, so acc_
            // only accumulates while awaiting a size line or trailer line — cap that so a peer
            // withholding a CRLF cannot grow it without bound.
            if (state_ != State::Data && acc_.size() > kMaxLine) { error_ = true; return false; }
            switch (state_) {
                case State::Size: {
                    size_t nl = acc_.find("\r\n");
                    if (nl == std::string::npos) return false;  // need more bytes
                    // chunk-size is hex up to an optional ";chunk-ext".
                    size_t hexlen = 0;
                    while (hexlen < nl && is_hex(acc_[hexlen])) ++hexlen;
                    if (hexlen == 0) { error_ = true; return false; }  // no size digits
                    unsigned long long sz = 0;
                    for (size_t i = 0; i < hexlen; ++i) {
                        sz = sz * 16 + hex_val(acc_[i]);
                        if (sz > (1ull << 40)) { error_ = true; return false; }  // absurd size
                    }
                    acc_.erase(0, nl + 2);
                    if (sz == 0) {
                        state_ = State::Trailer;  // last chunk: consume trailer section
                    } else {
                        remaining_ = static_cast<size_t>(sz);
                        state_ = State::Data;
                    }
                    break;
                }
                case State::Data: {
                    size_t take = std::min(remaining_, acc_.size());
                    acc_.erase(0, take);
                    remaining_ -= take;
                    if (remaining_ > 0) return false;  // need more data bytes
                    state_ = State::DataCrlf;
                    break;
                }
                case State::DataCrlf: {
                    if (acc_.size() < 2) return false;
                    // Expect the CRLF that terminates the chunk-data.
                    if (acc_[0] != '\r' || acc_[1] != '\n') { error_ = true; return false; }
                    acc_.erase(0, 2);
                    state_ = State::Size;
                    break;
                }
                case State::Trailer: {
                    // Trailer fields, one per line, terminated by a blank line. A body with no
                    // trailers has the blank line immediately (acc_ begins with CRLF).
                    size_t nl = acc_.find("\r\n");
                    if (nl == std::string::npos) return false;  // need more bytes
                    if (nl == 0) { acc_.erase(0, 2); done_ = true; return true; }  // blank line
                    acc_.erase(0, nl + 2);  // consume one trailer field line
                    break;
                }
            }
        }
    }
    bool done() const { return done_; }
    bool error() const { return error_; }

private:
    static bool is_hex(char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
    }
    static int hex_val(char c) {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        return c - 'A' + 10;
    }
    enum class State { Size, Data, DataCrlf, Trailer };
    static const size_t kMaxLine = 16 * 1024;  // cap for a chunk-size/trailer line backlog
    State state_ = State::Size;
    size_t remaining_ = 0;
    std::string acc_;
    bool done_ = false;
    bool error_ = false;
};

// Runs a cleanup callback on scope exit (non-copyable, non-movable so the callback fires
// exactly once). Used to reap a detached connection worker no matter which path it returns on.
struct ConnExit {
    std::function<void()> fn;
    explicit ConnExit(std::function<void()> f) : fn(std::move(f)) {}
    ConnExit(const ConnExit&) = delete;
    ConnExit& operator=(const ConnExit&) = delete;
    ~ConnExit() { if (fn) fn(); }
};

}  // namespace

EgressServer::~EgressServer() { stop(); }

bool EgressServer::start(const EgressConfig& cfg, std::string& err) {
    ignore_sigpipe_once();
    cfg_ = cfg;

    shutdown_fd_ = ::eventfd(0, EFD_NONBLOCK);
    if (shutdown_fd_ < 0) {
        err = "eventfd() failed: " + std::string(std::strerror(errno));
        return false;
    }

    for (const EgressBridge& br : cfg.bridges) {
        Url u;
        std::string perr;
        if (!parse_url(br.child_endpoint, u, perr)) {
            err = "bridge '" + br.name + "' has invalid child_endpoint: " + perr;
            stop();
            return false;
        }

        struct addrinfo hints;
        std::memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_flags = AI_PASSIVE | AI_NUMERICHOST;  // bind ONLY to the literal loopback addr
        struct addrinfo* res = nullptr;
        if (::getaddrinfo(u.host.c_str(), u.port.c_str(), &hints, &res) != 0 || !res) {
            err = "bridge '" + br.name + "' child_endpoint host must be a numeric loopback address: " +
                  u.host;
            stop();
            return false;
        }

        // AI_NUMERICHOST only rejects DNS names; a numeric wildcard ("0.0.0.0") or routable
        // ("8.8.8.8") address still resolves. The bridge relays to the real upstream and can
        // carry injected credentials, so it MUST bind loopback only (docs/EGRESS.md).
        if (!is_loopback_sockaddr(res->ai_addr)) {
            ::freeaddrinfo(res);
            err = "bridge '" + br.name +
                  "' child_endpoint must bind a loopback address (127.0.0.0/8 or ::1), got: " + u.host;
            stop();
            return false;
        }

        int lfd = ::socket(res->ai_family, res->ai_socktype, res->ai_protocol);
        if (lfd < 0) {
            ::freeaddrinfo(res);
            err = "bridge '" + br.name + "' socket() failed: " + std::string(std::strerror(errno));
            stop();
            return false;
        }
        int one = 1;
        ::setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        if (::bind(lfd, res->ai_addr, res->ai_addrlen) < 0) {
            std::string be = std::strerror(errno);
            ::close(lfd);
            ::freeaddrinfo(res);
            err = "bridge '" + br.name + "' bind(" + u.host + ":" + u.port + ") failed: " + be;
            stop();
            return false;
        }
        ::freeaddrinfo(res);

        if (::listen(lfd, 64) < 0) {
            std::string le = std::strerror(errno);
            ::close(lfd);
            err = "bridge '" + br.name + "' listen() failed: " + le;
            stop();
            return false;
        }

        // Resolve the actual bound port (handles ":0").
        int actual_port = 0;
        struct sockaddr_storage ss;
        socklen_t slen = sizeof(ss);
        if (::getsockname(lfd, reinterpret_cast<struct sockaddr*>(&ss), &slen) == 0) {
            if (ss.ss_family == AF_INET) {
                actual_port = ntohs(reinterpret_cast<struct sockaddr_in*>(&ss)->sin_port);
            } else if (ss.ss_family == AF_INET6) {
                actual_port = ntohs(reinterpret_cast<struct sockaddr_in6*>(&ss)->sin6_port);
            }
        }

        auto l = std::make_unique<Listener>();
        l->bridge = br;
        l->name = br.name;
        l->fd = lfd;
        l->port = actual_port;
        listeners_.push_back(std::move(l));
    }

    running_.store(true);
    for (auto& l : listeners_) {
        l->accept_thread = std::thread(&EgressServer::accept_loop, this, l.get());
    }
    return true;
}

void EgressServer::accept_loop(Listener* l) {
    for (;;) {
        struct pollfd pfds[2];
        pfds[0].fd = l->fd;
        pfds[0].events = POLLIN;
        pfds[1].fd = shutdown_fd_;
        pfds[1].events = POLLIN;
        int pr = ::poll(pfds, 2, -1);
        if (pr < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (pfds[1].revents & POLLIN) break;  // stop() signalled
        if (!(pfds[0].revents & POLLIN)) continue;

        int cfd = ::accept(l->fd, nullptr, nullptr);
        if (cfd < 0) {
            if (errno == EINTR || errno == ECONNABORTED) continue;
            if (!running_.load()) break;
            continue;
        }
        if (!running_.load()) {
            ::close(cfd);
            break;
        }
        EgressBridge bridge = l->bridge;
        {
            std::lock_guard<std::mutex> lk(conn_mu_);
            ++active_conns_;
        }
        try {
            std::thread(&EgressServer::handle_connection, this, cfd, bridge).detach();
        } catch (...) {
            // Thread spawn failed: undo the count and drop the connection cleanly.
            ::close(cfd);
            std::lock_guard<std::mutex> lk(conn_mu_);
            if (--active_conns_ == 0) conn_cv_.notify_all();
        }
    }
}

void EgressServer::handle_connection(int child_fd, EgressBridge bridge) {
    // Reap this detached worker on every return path: decrement the live count and wake
    // stop() when it drains. This bounds resident thread stacks to in-flight connections.
    ConnExit reap([this] {
        std::lock_guard<std::mutex> lk(conn_mu_);
        if (--active_conns_ == 0) conn_cv_.notify_all();
    });

    int timeout_s = cfg_.timeout_seconds;
    set_socket_timeout(child_fd, timeout_s);
    {
        int one = 1;
        ::setsockopt(child_fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));  // flush promptly
    }

    auto fail502 = [&]() {
        write_all_fd(child_fd, kBadGateway, std::strlen(kBadGateway));
        ::close(child_fd);
    };
    auto fail400 = [&]() {
        write_all_fd(child_fd, kBadRequest, std::strlen(kBadRequest));
        ::close(child_fd);
    };

    // 1. Read + parse the child's request head.
    std::string raw_head, body_leftover;
    if (!read_request_head(child_fd, raw_head, body_leftover, timeout_s)) {
        fail502();
        return;
    }
    HttpRequestHead req;
    std::string perr;
    if (!parse_request_head(raw_head, req, perr)) {
        fail502();
        return;
    }

    // 1b. Determine request-body framing and reject the ambiguous CL.TE shape up front.
    long clen = content_length(req);
    bool te_chunked = false;
    {
        std::string te;
        if (find_header(req, "Transfer-Encoding", te) &&
            ascii_lower(te).find("chunked") != std::string::npos) {
            te_chunked = true;
        }
    }
    // A request carrying BOTH Content-Length and Transfer-Encoding: chunked is a classic
    // request-smuggling vector (the two headers frame the body differently). Refuse it
    // rather than pick a winner and forward an ambiguous message upstream.
    bool has_cl_header = false;
    { std::string v; has_cl_header = find_header(req, "Content-Length", v); }
    if (has_cl_header && te_chunked) {
        fail400();
        return;
    }

    // Detect a strict Expect: 100-continue so we can relay the upstream's interim status
    // to the child BEFORE blocking on the request body (otherwise a client that withholds
    // its body until it sees 100-continue deadlocks against the unread upstream response).
    bool expect_continue = false;
    {
        std::string ev;
        if (find_header(req, "Expect", ev) &&
            ascii_lower(trim_ws(ev)).find("100-continue") != std::string::npos) {
            expect_continue = true;
        }
    }
    bool has_body = (clen > 0) || te_chunked;

    // 2. Resolve upstream + connect.
    Url up;
    std::string uerr;
    if (!parse_url(bridge.upstream_endpoint, up, uerr)) {
        fail502();
        return;
    }
    int up_fd = tcp_connect(up.host, up.port, timeout_s);
    if (up_fd < 0) {
        fail502();
        return;
    }

    SSL* ssl = nullptr;
    SSL_CTX* ssl_ctx = nullptr;
    if (up.scheme == "https") {
        ssl = tls_connect(up_fd, up.host, &ssl_ctx);
        if (!ssl) {
            ::close(up_fd);
            fail502();  // verification/handshake failure -> clean 502, never crash
            return;
        }
    }
    Stream upstream{up_fd, ssl};

    auto teardown_upstream = [&]() {
        if (ssl) {
            SSL_shutdown(ssl);
            SSL_free(ssl);
        }
        if (ssl_ctx) SSL_CTX_free(ssl_ctx);
        if (up_fd >= 0) ::close(up_fd);
    };

    // 3. Send the rewritten head, then relay the request body.
    std::string head = build_upstream_head(req, bridge, up);
    if (!upstream.write_all(head.data(), head.size())) {
        teardown_upstream();
        fail502();
        return;
    }

    // 3a. Expect: 100-continue — relay the upstream's interim response before reading the
    //     child's body. A strict client won't send its body until it sees the interim
    //     status, and the upstream won't send the final response until it gets the body:
    //     reading (and forwarding) the interim head here breaks that deadlock. If the
    //     upstream instead answered with a FINAL (>= 200) status, we skip the body and let
    //     phase 4 stream the rest (early_response carries any bytes already read past it).
    std::string early_response;
    bool skip_body = false;
    if (expect_continue && has_body) {
        std::string ihead, ileftover;
        if (read_head_from_stream(upstream, ihead, ileftover)) {
            if (!write_all_fd(child_fd, ihead.data(), ihead.size())) {
                teardown_upstream();
                ::close(child_fd);
                return;
            }
            int code = parse_status_code(ihead);
            if (!(code >= 100 && code < 200)) {
                skip_body = true;  // upstream gave a final response; don't send the body
            }
            early_response = std::move(ileftover);
        }
        // If read failed (upstream sent nothing / timed out), fall through and send the
        // body anyway — the final response is still handled by phase 4.
    }

    if (skip_body) {
        // Nothing to relay from the child; fall through to phase 4.
    } else if (clen > 0) {
        // Forward already-buffered body bytes first.
        size_t remaining = static_cast<size_t>(clen);
        size_t from_leftover = std::min(remaining, body_leftover.size());
        if (from_leftover > 0) {
            if (!upstream.write_all(body_leftover.data(), from_leftover)) {
                teardown_upstream();
                fail502();
                return;
            }
            remaining -= from_leftover;
        }
        char buf[16384];
        while (remaining > 0) {
            ssize_t n = ::recv(child_fd, buf, std::min(sizeof(buf), remaining), 0);
            if (n < 0) {
                if (errno == EINTR) continue;
                teardown_upstream();
                fail502();
                return;
            }
            if (n == 0) break;  // child closed early
            if (!upstream.write_all(buf, static_cast<size_t>(n))) {
                teardown_upstream();
                ::close(child_fd);  // already sent head upstream; can't 502 cleanly mid-stream
                return;
            }
            remaining -= static_cast<size_t>(n);
        }
    } else if (te_chunked) {
        // Chunked request body: no Content-Length, so relay raw bytes verbatim (the upstream
        // de-chunks) while parsing the chunk framing to know WHEN the body ends. A proper
        // parser recognizes the terminating 0-length chunk even when it carries a
        // chunk-extension ("0;ext\r\n\r\n") or trailer fields ("0\r\nX-Checksum: abc\r\n\r\n"),
        // which a fixed "\r\n0\r\n\r\n" literal scan would miss — leaving us blocked on the
        // child socket until SO_RCVTIMEO despite the whole body already being forwarded.
        ChunkedBodyParser parser;
        bool done = false;
        if (!body_leftover.empty()) {
            if (!upstream.write_all(body_leftover.data(), body_leftover.size())) {
                teardown_upstream();
                fail502();
                return;
            }
            done = parser.feed(body_leftover.data(), body_leftover.size());
        }
        char buf[16384];
        while (!done && !parser.error()) {
            ssize_t n = ::recv(child_fd, buf, sizeof(buf), 0);
            if (n < 0) {
                if (errno == EINTR) continue;
                break;  // timeout/error: stop relaying; upstream will see EOF on our close
            }
            if (n == 0) break;  // child half-closed
            if (!upstream.write_all(buf, static_cast<size_t>(n))) {
                teardown_upstream();
                ::close(child_fd);  // already streaming upstream; can't 502 cleanly mid-stream
                return;
            }
            done = parser.feed(buf, static_cast<size_t>(n));
        }
    }

    // 4. Stream the upstream response back until the upstream closes. Because we forced
    //    Connection: close, EOF marks the end — this transparently handles chunked/SSE.
    char buf[16384];
    bool any_response = false;
    bool timed_out = false;
    // Flush any response bytes already read while handling Expect: 100-continue.
    if (!early_response.empty()) {
        any_response = true;
        if (!write_all_fd(child_fd, early_response.data(), early_response.size())) {
            teardown_upstream();
            ::close(child_fd);
            return;
        }
    }
    int first_byte_timeout_ms = timeout_s > 0 ? timeout_s * 1000 : -1;
    for (;;) {
        // Wait for upstream data, but also watch shutdown_fd_ so stop() can interrupt a
        // relay blocked on a slow/dribbling upstream instead of waiting out SO_RCVTIMEO.
        // Skip the wait when TLS already has buffered plaintext (poll on the fd wouldn't
        // see it).
        //
        // timeout_seconds bounds a HUNG upstream — i.e. the wait for the FIRST response
        // byte. Once any bytes have been relayed the response is a live stream (SSE /
        // close-delimited); an inter-chunk idle gap does NOT mean end-of-response, so we
        // must NOT treat it as one — that would silently truncate a paused-but-alive stream
        // and hand the child a clean close it cannot distinguish from a complete body. Past
        // the first byte we wait indefinitely for more data and rely on shutdown_fd_ (stop())
        // for liveness rather than timeout_seconds.
        int wait_ms = any_response ? -1 : first_byte_timeout_ms;
        if (!(upstream.ssl && SSL_pending(upstream.ssl) > 0)) {
            WaitResult w = wait_readable(up_fd, shutdown_fd_, wait_ms);
            if (w == WaitResult::Shutdown || w == WaitResult::Error) break;
            if (w == WaitResult::TimedOut) {
                if (!any_response) timed_out = true;
                break;
            }
        }
        ssize_t n = upstream.read(buf, sizeof(buf));
        if (n > 0) {
            any_response = true;
            if (!write_all_fd(child_fd, buf, static_cast<size_t>(n))) break;  // child gone
            continue;
        }
        // n <= 0: distinguish a read timeout (SO_RCVTIMEO) from a clean EOF, but only when
        // nothing has been relayed yet — mid-stream we can't inject a status.
        if (!any_response) {
            if (upstream.ssl) {
                int e = SSL_get_error(upstream.ssl, static_cast<int>(n));
                if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE ||
                    (e == SSL_ERROR_SYSCALL && (errno == EAGAIN || errno == EWOULDBLOCK)))
                    timed_out = true;
            } else if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                timed_out = true;
            }
        }
        break;  // upstream EOF or error
    }

    // If the upstream timed out before sending any response, tell the child it was a
    // gateway timeout (504) rather than closing with zero bytes it can't interpret.
    if (!any_response && timed_out) {
        write_all_fd(child_fd, kGatewayTimeout, std::strlen(kGatewayTimeout));
    }

    // 5. Clean teardown, no fd leaks.
    teardown_upstream();
    ::shutdown(child_fd, SHUT_RDWR);
    ::close(child_fd);
}

void EgressServer::stop() {
    bool was_running = running_.exchange(false);

    // Wake accept threads out of poll().
    if (shutdown_fd_ >= 0) {
        uint64_t one = 1;
        ssize_t w = ::write(shutdown_fd_, &one, sizeof(one));
        (void)w;
    }

    for (auto& l : listeners_) {
        if (l->accept_thread.joinable()) l->accept_thread.join();
        if (l->fd >= 0) {
            ::close(l->fd);
            l->fd = -1;
        }
    }
    listeners_.clear();

    // Wait for every detached per-connection worker to finish. Accept threads are already
    // joined above so no new workers can spawn; socket timeouts bound how long any in-flight
    // worker can still be blocked, so this terminates.
    {
        std::unique_lock<std::mutex> lk(conn_mu_);
        conn_cv_.wait(lk, [this] { return active_conns_ == 0; });
    }

    if (shutdown_fd_ >= 0) {
        ::close(shutdown_fd_);
        shutdown_fd_ = -1;
    }
    (void)was_running;
}

int EgressServer::port_for(const std::string& bridge_name) const {
    for (const auto& l : listeners_) {
        if (l->name == bridge_name) return l->port;
    }
    return -1;
}

}  // namespace raincoat
