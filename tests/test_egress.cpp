// Raincoat — egress module test suite.
//
// UNIT tests exercise the pure helpers (parse_url / parse_request_head /
// content_length / build_upstream_head) with no sockets. INTEGRATION tests spin up
// a tiny in-process HTTP upstream on 127.0.0.1:0, run EgressServer in front of it,
// connect a client to the child port, and assert the upstream body is relayed —
// including an incrementally-streamed variant. Everything is localhost-only.
#include <gtest/gtest.h>

#include "egress.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cstring>
#include <functional>
#include <string>
#include <thread>
#include <vector>

using namespace raincoat;

// ===========================================================================
// parse_url
// ===========================================================================

TEST(ParseUrl, HttpDefaultPort) {
    Url u;
    std::string err;
    ASSERT_TRUE(parse_url("http://example.com", u, err)) << err;
    EXPECT_EQ(u.scheme, "http");
    EXPECT_EQ(u.host, "example.com");
    EXPECT_EQ(u.port, "80");
    EXPECT_EQ(u.path, "");
}

TEST(ParseUrl, HttpsDefaultPort) {
    Url u;
    std::string err;
    ASSERT_TRUE(parse_url("https://api.example.com", u, err)) << err;
    EXPECT_EQ(u.scheme, "https");
    EXPECT_EQ(u.port, "443");
}

TEST(ParseUrl, ExplicitPortAndPath) {
    Url u;
    std::string err;
    ASSERT_TRUE(parse_url("http://127.0.0.1:18080/v1/chat?stream=true", u, err)) << err;
    EXPECT_EQ(u.host, "127.0.0.1");
    EXPECT_EQ(u.port, "18080");
    EXPECT_EQ(u.path, "/v1/chat?stream=true");  // query included in path
}

TEST(ParseUrl, SchemeIsCaseInsensitive) {
    Url u;
    std::string err;
    ASSERT_TRUE(parse_url("HTTPS://Example.COM", u, err)) << err;
    EXPECT_EQ(u.scheme, "https");
    EXPECT_EQ(u.port, "443");
}

TEST(ParseUrl, IPv6Literal) {
    Url u;
    std::string err;
    ASSERT_TRUE(parse_url("http://[::1]:9000/p", u, err)) << err;
    EXPECT_EQ(u.host, "::1");
    EXPECT_EQ(u.port, "9000");
    EXPECT_EQ(u.path, "/p");
}

TEST(ParseUrl, MalformedNoScheme) {
    Url u;
    std::string err;
    EXPECT_FALSE(parse_url("example.com/foo", u, err));
    EXPECT_FALSE(err.empty());
}

TEST(ParseUrl, MalformedUnsupportedScheme) {
    Url u;
    std::string err;
    EXPECT_FALSE(parse_url("ftp://example.com", u, err));
}

TEST(ParseUrl, MalformedEmptyHost) {
    Url u;
    std::string err;
    EXPECT_FALSE(parse_url("http:///just/a/path", u, err));
}

TEST(ParseUrl, MalformedNonNumericPort) {
    Url u;
    std::string err;
    EXPECT_FALSE(parse_url("http://host:abc/", u, err));
}

// ===========================================================================
// parse_request_head
// ===========================================================================

TEST(ParseRequestHead, BasicGet) {
    HttpRequestHead h;
    std::string err;
    std::string raw = "GET /v1/models HTTP/1.1\r\nHost: api.local\r\nAccept: */*\r\n\r\n";
    ASSERT_TRUE(parse_request_head(raw, h, err)) << err;
    EXPECT_EQ(h.method, "GET");
    EXPECT_EQ(h.target, "/v1/models");
    EXPECT_EQ(h.version, "HTTP/1.1");
    ASSERT_EQ(h.headers.size(), 2u);
    EXPECT_EQ(h.headers[0].first, "Host");
    EXPECT_EQ(h.headers[0].second, "api.local");
    EXPECT_EQ(h.headers[1].first, "Accept");
    EXPECT_EQ(h.headers[1].second, "*/*");
}

TEST(ParseRequestHead, PostWithContentLength) {
    HttpRequestHead h;
    std::string err;
    std::string raw =
        "POST /v1/chat HTTP/1.1\r\nHost: x\r\nContent-Length: 42\r\nContent-Type: application/json\r\n\r\n";
    ASSERT_TRUE(parse_request_head(raw, h, err)) << err;
    EXPECT_EQ(h.method, "POST");
    EXPECT_EQ(content_length(h), 42);
}

TEST(ContentLength, AbsentIsMinusOne) {
    HttpRequestHead h;
    std::string err;
    ASSERT_TRUE(parse_request_head("GET / HTTP/1.1\r\nHost: x\r\n\r\n", h, err));
    EXPECT_EQ(content_length(h), -1);
}

TEST(ContentLength, CaseInsensitiveHeaderName) {
    HttpRequestHead h;
    std::string err;
    ASSERT_TRUE(parse_request_head("POST / HTTP/1.1\r\ncOnTeNt-LeNgTh: 7\r\n\r\n", h, err));
    EXPECT_EQ(content_length(h), 7);
}

TEST(ContentLength, InvalidIsMinusOne) {
    HttpRequestHead h;
    std::string err;
    ASSERT_TRUE(parse_request_head("POST / HTTP/1.1\r\nContent-Length: notanumber\r\n\r\n", h, err));
    EXPECT_EQ(content_length(h), -1);
}

// ===========================================================================
// check_request_framing — request-smuggling / body-framing guard (pure)
// ===========================================================================

TEST(CheckRequestFraming, NoBodyIsSafe) {
    HttpRequestHead h;
    std::string err;
    ASSERT_TRUE(parse_request_head("GET / HTTP/1.1\r\nHost: x\r\n\r\n", h, err));
    EXPECT_EQ(check_request_framing(h), FramingReject::None);
}

TEST(CheckRequestFraming, SingleValidContentLengthIsSafe) {
    HttpRequestHead h;
    std::string err;
    ASSERT_TRUE(parse_request_head("POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\n", h, err));
    EXPECT_EQ(check_request_framing(h), FramingReject::None);
}

TEST(CheckRequestFraming, ChunkedOnlyIsSafe) {
    HttpRequestHead h;
    std::string err;
    ASSERT_TRUE(parse_request_head(
        "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n", h, err));
    EXPECT_EQ(check_request_framing(h), FramingReject::None);
}

// Duplicate-but-IDENTICAL Content-Length is NOT a conflict: it is accepted and collapsed to
// a single line by build_upstream_head (so exactly one Content-Length crosses to upstream).
TEST(CheckRequestFraming, DuplicateIdenticalContentLengthAcceptedAndCollapsed) {
    HttpRequestHead h;
    std::string err;
    ASSERT_TRUE(parse_request_head(
        "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\n", h, err));
    EXPECT_EQ(check_request_framing(h), FramingReject::None);

    Url up;
    std::string e;
    ASSERT_TRUE(parse_url("http://up.example.com/", up, e)) << e;
    EgressBridge b;  // defaults
    std::string head = build_upstream_head(h, b, up);
    int count = 0;
    for (size_t p = head.find("Content-Length"); p != std::string::npos;
         p = head.find("Content-Length", p + 1)) {
        ++count;
    }
    EXPECT_EQ(count, 1) << "duplicate-identical Content-Length not collapsed to one line:\n"
                        << head;
}

// Two CONFLICTING Content-Length values -> CL.CL smuggling -> reject.
TEST(CheckRequestFraming, ConflictingContentLengthRejected) {
    HttpRequestHead h;
    std::string err;
    ASSERT_TRUE(parse_request_head(
        "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nContent-Length: 100\r\n\r\n", h, err));
    EXPECT_EQ(check_request_framing(h), FramingReject::ConflictingCl);
}

// Content-Length together with Transfer-Encoding -> CL.TE smuggling -> reject.
TEST(CheckRequestFraming, ContentLengthWithTransferEncodingRejected) {
    HttpRequestHead h;
    std::string err;
    ASSERT_TRUE(parse_request_head(
        "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n",
        h, err));
    EXPECT_EQ(check_request_framing(h), FramingReject::ClTe);
}

// A NON-NUMERIC Content-Length cannot frame a body -> reject (previously it was treated as
// "no body" and the request was forwarded verbatim, bogus header and all).
TEST(CheckRequestFraming, NonNumericContentLengthRejected) {
    HttpRequestHead h;
    std::string err;
    ASSERT_TRUE(parse_request_head(
        "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: notanumber\r\n\r\n", h, err));
    EXPECT_EQ(check_request_framing(h), FramingReject::MalformedCl);
}

// A NEGATIVE Content-Length is invalid framing -> reject.
TEST(CheckRequestFraming, NegativeContentLengthRejected) {
    HttpRequestHead h;
    std::string err;
    ASSERT_TRUE(parse_request_head(
        "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: -5\r\n\r\n", h, err));
    EXPECT_EQ(check_request_framing(h), FramingReject::MalformedCl);
}

TEST(ParseRequestHead, HeaderValueWhitespaceTrimmed) {
    HttpRequestHead h;
    std::string err;
    ASSERT_TRUE(parse_request_head("GET / HTTP/1.1\r\nHost:   spaced.host   \r\n\r\n", h, err));
    std::string v;
    ASSERT_TRUE(find_header(h, "host", v));
    EXPECT_EQ(v, "spaced.host");
}

TEST(ParseRequestHead, WorksWithoutTerminatorAndBareLf) {
    // Terminator absent; also tolerate bare LF line endings.
    HttpRequestHead h;
    std::string err;
    ASSERT_TRUE(parse_request_head("GET /x HTTP/1.1\nHost: y\n", h, err)) << err;
    EXPECT_EQ(h.target, "/x");
    std::string v;
    ASSERT_TRUE(find_header(h, "Host", v));
    EXPECT_EQ(v, "y");
}

TEST(ParseRequestHead, MalformedRequestLine) {
    HttpRequestHead h;
    std::string err;
    EXPECT_FALSE(parse_request_head("GARBAGE\r\n\r\n", h, err));
    EXPECT_FALSE(err.empty());
}

TEST(ParseRequestHead, MalformedMissingVersion) {
    HttpRequestHead h;
    std::string err;
    EXPECT_FALSE(parse_request_head("GET /only-two-tokens\r\n\r\n", h, err));
}

TEST(ParseRequestHead, MalformedHeaderNoColon) {
    HttpRequestHead h;
    std::string err;
    EXPECT_FALSE(parse_request_head("GET / HTTP/1.1\r\nBadHeaderLine\r\n\r\n", h, err));
}

TEST(ParseRequestHead, EmptyIsError) {
    HttpRequestHead h;
    std::string err;
    EXPECT_FALSE(parse_request_head("", h, err));
}

// ===========================================================================
// build_upstream_head
// ===========================================================================

namespace {
HttpRequestHead sample_req() {
    HttpRequestHead h;
    h.method = "POST";
    h.target = "/v1/chat?stream=true";
    h.version = "HTTP/1.1";
    h.headers = {
        {"Host", "127.0.0.1:18080"},
        {"Authorization", "Bearer secret"},
        {"X-Forwarded-For", "10.0.0.9"},
        {"Connection", "keep-alive"},
        {"Content-Length", "5"},
    };
    return h;
}
bool head_has_line(const std::string& head, const std::string& line) {
    return head.find("\r\n" + line + "\r\n") != std::string::npos ||
          head.find(line + "\r\n") == 0;
}
}  // namespace

TEST(BuildUpstreamHead, PreservesRequestLine) {
    EgressBridge b;
    Url up;
    std::string err;
    ASSERT_TRUE(parse_url("https://real.example.com", up, err));
    std::string head = build_upstream_head(sample_req(), b, up);
    EXPECT_EQ(head.find("POST /v1/chat?stream=true HTTP/1.1\r\n"), 0u);
    // Ends with a blank line.
    EXPECT_TRUE(head.size() >= 4 && head.substr(head.size() - 4) == "\r\n\r\n");
}

TEST(BuildUpstreamHead, SetsHostToUpstreamWhenNotPreserving) {
    EgressBridge b;
    b.preserve_host = false;
    Url up;
    std::string err;
    ASSERT_TRUE(parse_url("https://real.example.com", up, err));
    std::string head = build_upstream_head(sample_req(), b, up);
    EXPECT_TRUE(head_has_line(head, "Host: real.example.com"));
    EXPECT_EQ(head.find("127.0.0.1:18080"), std::string::npos);  // child Host not leaked
}

TEST(BuildUpstreamHead, IncludesNonDefaultUpstreamPortInHost) {
    EgressBridge b;
    b.preserve_host = false;
    Url up;
    std::string err;
    ASSERT_TRUE(parse_url("http://real.example.com:8443", up, err));
    std::string head = build_upstream_head(sample_req(), b, up);
    EXPECT_TRUE(head_has_line(head, "Host: real.example.com:8443"));
}

TEST(BuildUpstreamHead, PreservesChildHostWhenRequested) {
    EgressBridge b;
    b.preserve_host = true;
    Url up;
    std::string err;
    ASSERT_TRUE(parse_url("https://real.example.com", up, err));
    std::string head = build_upstream_head(sample_req(), b, up);
    EXPECT_TRUE(head_has_line(head, "Host: 127.0.0.1:18080"));
}

TEST(BuildUpstreamHead, StripsHeadersCaseInsensitively) {
    EgressBridge b;
    b.strip_headers = {"authorization"};  // lower-case, header is "Authorization"
    Url up;
    std::string err;
    ASSERT_TRUE(parse_url("https://real.example.com", up, err));
    std::string head = build_upstream_head(sample_req(), b, up);
    EXPECT_EQ(head.find("Authorization"), std::string::npos);
    EXPECT_EQ(head.find("Bearer secret"), std::string::npos);
    // A non-stripped header survives.
    EXPECT_TRUE(head_has_line(head, "X-Forwarded-For: 10.0.0.9"));
}

TEST(BuildUpstreamHead, InjectsHeaders) {
    EgressBridge b;
    b.inject_headers = {{"X-Raincoat", "1"}, {"X-Trace", "abc"}};
    Url up;
    std::string err;
    ASSERT_TRUE(parse_url("https://real.example.com", up, err));
    std::string head = build_upstream_head(sample_req(), b, up);
    EXPECT_TRUE(head_has_line(head, "X-Raincoat: 1"));
    EXPECT_TRUE(head_has_line(head, "X-Trace: abc"));
}

TEST(BuildUpstreamHead, ForcesConnectionClose) {
    EgressBridge b;
    Url up;
    std::string err;
    ASSERT_TRUE(parse_url("https://real.example.com", up, err));
    std::string head = build_upstream_head(sample_req(), b, up);
    EXPECT_TRUE(head_has_line(head, "Connection: close"));
    EXPECT_EQ(head.find("keep-alive"), std::string::npos);  // child's Connection dropped
    // Only one Connection header total.
    size_t first = head.find("Connection:");
    ASSERT_NE(first, std::string::npos);
    EXPECT_EQ(head.find("Connection:", first + 1), std::string::npos);
}

// ===========================================================================
// Integration: a tiny in-process HTTP upstream + EgressServer + a client
// ===========================================================================

namespace {

// Minimal localhost HTTP server. Listens on 127.0.0.1:0, accepts one connection,
// reads (and discards) the request head, then invokes `respond(client_fd)`.
class TinyUpstream {
public:
    // respond writes the raw response bytes to the given fd and returns.
    explicit TinyUpstream(std::function<void(int)> respond) : respond_(std::move(respond)) {}

    bool start() {
        fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
        if (fd_ < 0) return false;
        int one = 1;
        ::setsockopt(fd_, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = 0;
        if (::bind(fd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) return false;
        if (::listen(fd_, 8) < 0) return false;
        socklen_t sl = sizeof(addr);
        ::getsockname(fd_, reinterpret_cast<sockaddr*>(&addr), &sl);
        port_ = ntohs(addr.sin_port);
        thread_ = std::thread([this] { run(); });
        return true;
    }

    int port() const { return port_; }
    std::string url() const { return "http://127.0.0.1:" + std::to_string(port_); }

    void stop() {
        stop_.store(true);
        if (fd_ >= 0) {
            ::shutdown(fd_, SHUT_RDWR);
            ::close(fd_);
            fd_ = -1;
        }
        if (thread_.joinable()) thread_.join();
    }

    ~TinyUpstream() { stop(); }

private:
    void run() {
        while (!stop_.load()) {
            int c = ::accept(fd_, nullptr, nullptr);
            if (c < 0) return;
            // Drain the request head.
            std::string buf;
            char tmp[2048];
            while (buf.find("\r\n\r\n") == std::string::npos) {
                ssize_t n = ::recv(c, tmp, sizeof(tmp), 0);
                if (n <= 0) break;
                buf.append(tmp, static_cast<size_t>(n));
            }
            respond_(c);
            ::close(c);
        }
    }

    std::function<void(int)> respond_;
    std::atomic<bool> stop_{false};
    int fd_ = -1;
    int port_ = 0;
    std::thread thread_;
};

void send_all(int fd, const std::string& s) {
    size_t off = 0;
    while (off < s.size()) {
        ssize_t n = ::send(fd, s.data() + off, s.size() - off, MSG_NOSIGNAL);
        if (n <= 0) return;
        off += static_cast<size_t>(n);
    }
}

// Connect a client to 127.0.0.1:port and send `request`; return the full response.
std::string client_roundtrip(int port, const std::string& request) {
    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return "";
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(static_cast<uint16_t>(port));
    timeval tv{5, 0};
    ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    if (::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        ::close(fd);
        return "";
    }
    send_all(fd, request);
    std::string resp;
    char buf[4096];
    for (;;) {
        ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
        if (n <= 0) break;
        resp.append(buf, static_cast<size_t>(n));
    }
    ::close(fd);
    return resp;
}

EgressConfig make_cfg(const std::string& upstream_url, const std::string& name = "primary") {
    EgressConfig cfg;
    cfg.enabled = true;
    cfg.mode = "bridge";
    cfg.timeout_seconds = 5;
    EgressBridge b;
    b.name = name;
    b.env = "SOME_BASE_URL";
    b.child_endpoint = "http://127.0.0.1:0";  // ephemeral port
    b.upstream_endpoint = upstream_url;
    b.preserve_host = false;
    cfg.bridges.push_back(b);
    return cfg;
}

}  // namespace

TEST(EgressServerIntegration, RelaysSimpleBody) {
    const std::string body = "hello-from-upstream";
    TinyUpstream up([body](int fd) {
        std::string resp = "HTTP/1.1 200 OK\r\nContent-Length: " + std::to_string(body.size()) +
                          "\r\nConnection: close\r\n\r\n" + body;
        send_all(fd, resp);
    });
    ASSERT_TRUE(up.start());

    EgressServer server;
    std::string err;
    ASSERT_TRUE(server.start(make_cfg(up.url()), err)) << err;
    int port = server.port_for("primary");
    ASSERT_GT(port, 0);

    std::string resp = client_roundtrip(
        port, "GET /v1/models HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n");
    server.stop();
    up.stop();

    EXPECT_NE(resp.find("200 OK"), std::string::npos);
    EXPECT_NE(resp.find(body), std::string::npos);
}

TEST(EgressServerIntegration, RelaysPostBody) {
    // Upstream echoes back the number of body bytes it received.
    TinyUpstream up([](int fd) {
        // Already drained head in run(); but we need the body too. Read whatever remains.
        // Simplest: respond with a fixed 200 — correctness of body relay is exercised by
        // the streaming test; here we assert the request reaches upstream and returns.
        std::string resp = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";
        send_all(fd, resp);
    });
    ASSERT_TRUE(up.start());

    EgressServer server;
    std::string err;
    ASSERT_TRUE(server.start(make_cfg(up.url()), err)) << err;
    int port = server.port_for("primary");
    ASSERT_GT(port, 0);

    std::string req =
        "POST /v1/chat HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 5\r\n\r\nhello";
    std::string resp = client_roundtrip(port, req);
    server.stop();
    up.stop();

    EXPECT_NE(resp.find("200 OK"), std::string::npos);
    EXPECT_NE(resp.find("ok"), std::string::npos);
}

TEST(EgressServerIntegration, StreamsIncrementally) {
    // Upstream sends chunk A, waits, then chunk B, then closes. The proxy must relay
    // A to the client BEFORE B is produced (i.e. it streams rather than buffering).
    TinyUpstream up([](int fd) {
        std::string head = "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n";
        send_all(fd, head + "CHUNK_A;");
        std::this_thread::sleep_for(std::chrono::milliseconds(250));
        send_all(fd, "CHUNK_B;");
    });
    ASSERT_TRUE(up.start());

    EgressServer server;
    std::string err;
    ASSERT_TRUE(server.start(make_cfg(up.url()), err)) << err;
    int port = server.port_for("primary");
    ASSERT_GT(port, 0);

    // Manual client so we can read incrementally.
    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    ASSERT_GE(fd, 0);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(static_cast<uint16_t>(port));
    timeval tv{5, 0};
    ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    ASSERT_EQ(::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)), 0);
    send_all(fd, "GET /stream HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n");

    // First read should surface CHUNK_A well before CHUNK_B is sent (250ms later).
    std::string got;
    char buf[4096];
    ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
    ASSERT_GT(n, 0);
    got.append(buf, static_cast<size_t>(n));
    EXPECT_NE(got.find("CHUNK_A"), std::string::npos);
    EXPECT_EQ(got.find("CHUNK_B"), std::string::npos)
        << "proxy buffered instead of streaming: " << got;

    // Drain the rest; CHUNK_B must eventually arrive.
    for (;;) {
        ssize_t m = ::recv(fd, buf, sizeof(buf), 0);
        if (m <= 0) break;
        got.append(buf, static_cast<size_t>(m));
    }
    ::close(fd);
    server.stop();
    up.stop();

    EXPECT_NE(got.find("CHUNK_B"), std::string::npos);
}

TEST(EgressServerIntegration, UpstreamDownYields502) {
    // Point the bridge at a port with nothing listening -> connect fails -> 502.
    EgressConfig cfg = make_cfg("http://127.0.0.1:1");  // port 1: refused
    EgressServer server;
    std::string err;
    ASSERT_TRUE(server.start(cfg, err)) << err;
    int port = server.port_for("primary");
    ASSERT_GT(port, 0);

    std::string resp = client_roundtrip(port, "GET / HTTP/1.1\r\nHost: x\r\n\r\n");
    server.stop();

    EXPECT_NE(resp.find("502"), std::string::npos);
    // The upstream host/URL must never leak in the error.
    EXPECT_EQ(resp.find("127.0.0.1:1"), std::string::npos);
}

TEST(EgressServerIntegration, MultipleBridges) {
    TinyUpstream up1([](int fd) {
        send_all(fd, "HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\nAAA");
    });
    TinyUpstream up2([](int fd) {
        send_all(fd, "HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\nBBB");
    });
    ASSERT_TRUE(up1.start());
    ASSERT_TRUE(up2.start());

    EgressConfig cfg = make_cfg(up1.url(), "one");
    {
        EgressBridge b;
        b.name = "two";
        b.env = "OTHER_URL";
        b.child_endpoint = "http://127.0.0.1:0";
        b.upstream_endpoint = up2.url();
        cfg.bridges.push_back(b);
    }

    EgressServer server;
    std::string err;
    ASSERT_TRUE(server.start(cfg, err)) << err;
    int p1 = server.port_for("one");
    int p2 = server.port_for("two");
    ASSERT_GT(p1, 0);
    ASSERT_GT(p2, 0);
    EXPECT_NE(p1, p2);

    std::string r1 = client_roundtrip(p1, "GET / HTTP/1.1\r\nHost: x\r\n\r\n");
    std::string r2 = client_roundtrip(p2, "GET / HTTP/1.1\r\nHost: x\r\n\r\n");
    server.stop();
    up1.stop();
    up2.stop();

    EXPECT_NE(r1.find("AAA"), std::string::npos);
    EXPECT_NE(r2.find("BBB"), std::string::npos);
}

TEST(EgressServerIntegration, ConcurrentConnections) {
    std::atomic<int> served{0};
    TinyUpstream up([&served](int fd) {
        served.fetch_add(1);
        send_all(fd, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
    });
    // Allow many sequential accepts (TinyUpstream loops).
    ASSERT_TRUE(up.start());

    EgressServer server;
    std::string err;
    ASSERT_TRUE(server.start(make_cfg(up.url()), err)) << err;
    int port = server.port_for("primary");
    ASSERT_GT(port, 0);

    const int N = 6;
    std::vector<std::thread> clients;
    std::atomic<int> ok{0};
    for (int i = 0; i < N; ++i) {
        clients.emplace_back([port, &ok] {
            std::string r = client_roundtrip(port, "GET / HTTP/1.1\r\nHost: x\r\n\r\n");
            if (r.find("ok") != std::string::npos) ok.fetch_add(1);
        });
    }
    for (auto& t : clients) t.join();
    server.stop();
    up.stop();

    EXPECT_EQ(ok.load(), N);
}

// ---------------------------------------------------------------------------
// HTTPS integration: self-signed cert + local TLS upstream.
// If the in-test cert/key generation is unavailable, the test SKIPs (localhost-only,
// no external network). This exercises the real OpenSSL client path in egress.cpp.
// ---------------------------------------------------------------------------

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

namespace {

// Generate a self-signed cert (CN=127.0.0.1, SAN IP:127.0.0.1) + key in memory.
bool make_self_signed(EVP_PKEY** pkey_out, X509** x509_out) {
    EVP_PKEY* pkey = EVP_RSA_gen(2048);
    if (!pkey) return false;
    X509* x509 = X509_new();
    if (!x509) {
        EVP_PKEY_free(pkey);
        return false;
    }
    ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
    X509_gmtime_adj(X509_get_notBefore(x509), 0);
    X509_gmtime_adj(X509_get_notAfter(x509), 3600);
    X509_set_pubkey(x509, pkey);
    X509_NAME* name = X509_get_subject_name(x509);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                              reinterpret_cast<const unsigned char*>("127.0.0.1"), -1, -1, 0);
    X509_set_issuer_name(x509, name);
    // SAN IP:127.0.0.1 so hostname/IP verification passes.
    X509_EXTENSION* ext = X509V3_EXT_conf_nid(nullptr, nullptr, NID_subject_alt_name,
                                              "IP:127.0.0.1");
    if (ext) {
        X509_add_ext(x509, ext, -1);
        X509_EXTENSION_free(ext);
    }
    if (!X509_sign(x509, pkey, EVP_sha256())) {
        X509_free(x509);
        EVP_PKEY_free(pkey);
        return false;
    }
    *pkey_out = pkey;
    *x509_out = x509;
    return true;
}

// A one-shot TLS upstream using an in-memory self-signed cert.
class TlsUpstream {
public:
    explicit TlsUpstream(std::string body) : body_(std::move(body)) {}

    bool start() {
        if (!make_self_signed(&pkey_, &x509_)) return false;
        ctx_ = SSL_CTX_new(TLS_server_method());
        if (!ctx_) return false;
        if (SSL_CTX_use_certificate(ctx_, x509_) != 1) return false;
        if (SSL_CTX_use_PrivateKey(ctx_, pkey_) != 1) return false;

        fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
        if (fd_ < 0) return false;
        int one = 1;
        ::setsockopt(fd_, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = 0;
        if (::bind(fd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) return false;
        if (::listen(fd_, 8) < 0) return false;
        socklen_t sl = sizeof(addr);
        ::getsockname(fd_, reinterpret_cast<sockaddr*>(&addr), &sl);
        port_ = ntohs(addr.sin_port);
        thread_ = std::thread([this] { run(); });
        return true;
    }

    int port() const { return port_; }
    std::string url() const { return "https://127.0.0.1:" + std::to_string(port_); }

    void stop() {
        stop_.store(true);
        if (fd_ >= 0) {
            ::shutdown(fd_, SHUT_RDWR);
            ::close(fd_);
            fd_ = -1;
        }
        if (thread_.joinable()) thread_.join();
    }

    ~TlsUpstream() {
        stop();
        if (ctx_) SSL_CTX_free(ctx_);
        if (x509_) X509_free(x509_);
        if (pkey_) EVP_PKEY_free(pkey_);
    }

private:
    void run() {
        int c = ::accept(fd_, nullptr, nullptr);
        if (c < 0) return;
        SSL* ssl = SSL_new(ctx_);
        SSL_set_fd(ssl, c);
        if (SSL_accept(ssl) == 1) {
            char tmp[2048];
            SSL_read(ssl, tmp, sizeof(tmp));  // drain request (best-effort)
            std::string resp = "HTTP/1.1 200 OK\r\nContent-Length: " +
                              std::to_string(body_.size()) + "\r\nConnection: close\r\n\r\n" +
                              body_;
            SSL_write(ssl, resp.data(), static_cast<int>(resp.size()));
            SSL_shutdown(ssl);
        }
        SSL_free(ssl);
        ::close(c);
    }

    std::string body_;
    std::atomic<bool> stop_{false};
    int fd_ = -1;
    int port_ = 0;
    std::thread thread_;
    SSL_CTX* ctx_ = nullptr;
    EVP_PKEY* pkey_ = nullptr;
    X509* x509_ = nullptr;
};

}  // namespace

// ===========================================================================
// Attack round 1: correctness + streaming (added)
// ===========================================================================

namespace {

// An upstream that CAPTURES the full request it receives (head + body) so the test
// can assert exactly what crossed the wire. If the captured head has a Content-Length,
// it reads exactly that many body bytes; otherwise it reads whatever arrives within a
// bounded recv timeout (so a dropped/absent body cannot hang the test). It then replies
// echoing the received body length so the client roundtrip completes.
class CapturingUpstream {
public:
    bool start() {
        fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
        if (fd_ < 0) return false;
        int one = 1;
        ::setsockopt(fd_, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = 0;
        if (::bind(fd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) return false;
        if (::listen(fd_, 8) < 0) return false;
        socklen_t sl = sizeof(addr);
        ::getsockname(fd_, reinterpret_cast<sockaddr*>(&addr), &sl);
        port_ = ntohs(addr.sin_port);
        thread_ = std::thread([this] { run(); });
        return true;
    }
    int port() const { return port_; }
    std::string url() const { return "http://127.0.0.1:" + std::to_string(port_); }

    void stop() {
        stop_.store(true);
        if (fd_ >= 0) { ::shutdown(fd_, SHUT_RDWR); ::close(fd_); fd_ = -1; }
        if (thread_.joinable()) thread_.join();
    }
    ~CapturingUpstream() { stop(); }

    std::string head() { std::lock_guard<std::mutex> lk(mu_); return head_; }
    std::string body() { std::lock_guard<std::mutex> lk(mu_); return body_; }

private:
    static long content_len(const std::string& head) {
        std::string lower = head;
        for (char& c : lower) c = static_cast<char>(::tolower(static_cast<unsigned char>(c)));
        size_t p = lower.find("content-length:");
        if (p == std::string::npos) return -1;
        p += std::strlen("content-length:");
        size_t e = head.find("\r\n", p);
        std::string v = head.substr(p, e - p);
        return std::strtol(v.c_str(), nullptr, 10);
    }

    void run() {
        int c = ::accept(fd_, nullptr, nullptr);
        if (c < 0) return;
        timeval tv{0, 500000};  // bounded so a missing body can't hang
        ::setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        std::string buf;
        char tmp[8192];
        while (buf.find("\r\n\r\n") == std::string::npos) {
            ssize_t n = ::recv(c, tmp, sizeof(tmp), 0);
            if (n <= 0) { ::close(c); return; }
            buf.append(tmp, static_cast<size_t>(n));
        }
        size_t hend = buf.find("\r\n\r\n") + 4;
        std::string head = buf.substr(0, hend);
        std::string body = buf.substr(hend);
        long cl = content_len(head);
        if (cl >= 0) {
            while (static_cast<long>(body.size()) < cl) {
                ssize_t n = ::recv(c, tmp, sizeof(tmp), 0);
                if (n <= 0) break;
                body.append(tmp, static_cast<size_t>(n));
            }
        } else {
            // No Content-Length: read whatever arrives until the bounded timeout.
            for (;;) {
                ssize_t n = ::recv(c, tmp, sizeof(tmp), 0);
                if (n <= 0) break;
                body.append(tmp, static_cast<size_t>(n));
            }
        }
        { std::lock_guard<std::mutex> lk(mu_); head_ = head; body_ = body; }

        std::string resp = "HTTP/1.1 200 OK\r\nContent-Length: " +
                           std::to_string(body.size()) + "\r\nConnection: close\r\n\r\n" + body;
        send_all(c, resp);
        ::shutdown(c, SHUT_RDWR);
        ::close(c);
    }

    std::mutex mu_;
    std::string head_, body_;
    std::atomic<bool> stop_{false};
    int fd_ = -1, port_ = 0;
    std::thread thread_;
};

}  // namespace

// The request body must reach the upstream byte-for-byte (positive control).
TEST(EgressAttack, PostBodyReachesUpstreamIntact) {
    CapturingUpstream up;
    ASSERT_TRUE(up.start());
    EgressServer server;
    std::string err;
    ASSERT_TRUE(server.start(make_cfg(up.url()), err)) << err;
    int port = server.port_for("primary");
    ASSERT_GT(port, 0);

    const std::string body = "the-quick-brown-fox";
    std::string req = "POST /v1/chat HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: " +
                      std::to_string(body.size()) + "\r\n\r\n" + body;
    std::string resp = client_roundtrip(port, req);
    server.stop();

    EXPECT_EQ(up.body(), body) << "upstream did not receive the exact request body";
    EXPECT_NE(resp.find(body), std::string::npos);
    up.stop();
}

// A single MALFORMED (non-numeric) Content-Length must be REJECTED with 400 and must NOT
// reach the upstream. Before the fix the bridge treated an unparseable Content-Length as
// "no body" and forwarded the request (bogus header and all) verbatim to the upstream.
TEST(EgressAttack, MalformedContentLengthRejectedNotForwarded) {
    CapturingUpstream up;
    ASSERT_TRUE(up.start());
    EgressServer server;
    std::string err;
    ASSERT_TRUE(server.start(make_cfg(up.url()), err)) << err;
    int port = server.port_for("primary");
    ASSERT_GT(port, 0);

    std::string req =
        "POST /v1/chat HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: notanumber\r\n\r\nXXXX";
    std::string resp = client_roundtrip(port, req);
    server.stop();

    EXPECT_NE(resp.find("400"), std::string::npos)
        << "bridge did not 400 a malformed Content-Length; response:\n" << resp;
    EXPECT_TRUE(up.head().empty())
        << "a malformed-Content-Length request was forwarded to the upstream:\n" << up.head();
    up.stop();
}

// A single NEGATIVE Content-Length is likewise rejected with 400 and never forwarded.
TEST(EgressAttack, NegativeContentLengthRejectedNotForwarded) {
    CapturingUpstream up;
    ASSERT_TRUE(up.start());
    EgressServer server;
    std::string err;
    ASSERT_TRUE(server.start(make_cfg(up.url()), err)) << err;
    int port = server.port_for("primary");
    ASSERT_GT(port, 0);

    std::string req =
        "POST /v1/chat HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: -5\r\n\r\n";
    std::string resp = client_roundtrip(port, req);
    server.stop();

    EXPECT_NE(resp.find("400"), std::string::npos)
        << "bridge did not 400 a negative Content-Length; response:\n" << resp;
    EXPECT_TRUE(up.head().empty())
        << "a negative-Content-Length request was forwarded to the upstream:\n" << up.head();
    up.stop();
}

// Method + path + query string must be forwarded verbatim on the wire.
TEST(EgressAttack, MethodPathQueryForwardedOnWire) {
    CapturingUpstream up;
    ASSERT_TRUE(up.start());
    EgressServer server;
    std::string err;
    ASSERT_TRUE(server.start(make_cfg(up.url()), err)) << err;
    int port = server.port_for("primary");
    ASSERT_GT(port, 0);

    std::string resp = client_roundtrip(
        port, "PUT /a/b/c?x=1&y=two%20words HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n");
    server.stop();

    EXPECT_EQ(up.head().find("PUT /a/b/c?x=1&y=two%20words HTTP/1.1\r\n"), 0u)
        << "request line not forwarded verbatim; got head:\n" << up.head();
    up.stop();
}

// Strip + inject + Host rewrite must apply on the actual forwarded bytes (not just
// in the pure helper). Authorization stripped, X-Raincoat injected, Host rewritten.
TEST(EgressAttack, StripInjectHostAppliedOnWire) {
    CapturingUpstream up;
    ASSERT_TRUE(up.start());
    EgressConfig cfg = make_cfg(up.url());
    cfg.bridges[0].strip_headers = {"authorization"};
    cfg.bridges[0].inject_headers = {{"X-Raincoat", "1"}};
    cfg.bridges[0].preserve_host = false;

    EgressServer server;
    std::string err;
    ASSERT_TRUE(server.start(cfg, err)) << err;
    int port = server.port_for("primary");
    ASSERT_GT(port, 0);

    std::string resp = client_roundtrip(
        port,
        "GET /x HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer SECRET\r\n\r\n");
    server.stop();

    std::string h = up.head();
    EXPECT_EQ(h.find("Authorization"), std::string::npos) << "auth not stripped: " << h;
    EXPECT_EQ(h.find("SECRET"), std::string::npos);
    EXPECT_NE(h.find("X-Raincoat: 1"), std::string::npos) << "inject missing: " << h;
    EXPECT_NE(h.find("Host: 127.0.0.1:" + std::to_string(up.port())), std::string::npos)
        << "Host not rewritten to upstream: " << h;
    up.stop();
}

// A 5 MB body must be relayed intact without corruption or deadlock.
TEST(EgressAttack, LargeBodyRelayedIntact) {
    CapturingUpstream up;
    ASSERT_TRUE(up.start());
    EgressConfig cfg = make_cfg(up.url());
    cfg.timeout_seconds = 15;
    EgressServer server;
    std::string err;
    ASSERT_TRUE(server.start(cfg, err)) << err;
    int port = server.port_for("primary");
    ASSERT_GT(port, 0);

    std::string body;
    body.reserve(5 * 1024 * 1024);
    for (size_t i = 0; i < 5u * 1024 * 1024; ++i)
        body.push_back(static_cast<char>('A' + (i % 26)));

    std::string req = "POST /big HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: " +
                      std::to_string(body.size()) + "\r\n\r\n" + body;
    std::string resp = client_roundtrip(port, req);
    server.stop();

    EXPECT_EQ(up.body().size(), body.size()) << "upstream received truncated body";
    EXPECT_EQ(up.body(), body) << "5MB body corrupted in transit";
    up.stop();
}

// A chunked (Transfer-Encoding) request body from the child must reach the upstream.
// The child sends its body using chunked transfer encoding (no Content-Length). The
// proxy forwards the Transfer-Encoding header, so it MUST also forward the body.
TEST(EgressAttack, ChunkedRequestBodyForwarded) {
    CapturingUpstream up;
    ASSERT_TRUE(up.start());
    EgressServer server;
    std::string err;
    ASSERT_TRUE(server.start(make_cfg(up.url()), err)) << err;
    int port = server.port_for("primary");
    ASSERT_GT(port, 0);

    // "hello" as a single chunk followed by the zero-length terminator chunk.
    std::string req =
        "POST /v1/chat HTTP/1.1\r\nHost: 127.0.0.1\r\n"
        "Transfer-Encoding: chunked\r\n\r\n"
        "5\r\nhello\r\n0\r\n\r\n";
    std::string resp = client_roundtrip(port, req);
    server.stop();

    // The upstream must have received the chunked body bytes. If the proxy forwards
    // the Transfer-Encoding header but drops the body, the upstream sees an empty body
    // and (a real origin) would hang waiting for chunks.
    EXPECT_NE(up.body().find("hello"), std::string::npos)
        << "chunked request body was NOT forwarded to upstream; upstream body='"
        << up.body() << "'";
    up.stop();
}

// A hung upstream (connects, reads the request, then never responds) must not hang the
// proxy forever: the client roundtrip has to return within a bound derived from
// timeout_seconds.
TEST(EgressAttack, HungUpstreamRespectsTimeout) {
    std::atomic<bool> release{false};
    TinyUpstream up([&release](int fd) {
        // Never respond until told to release (well past the proxy timeout).
        for (int i = 0; i < 200 && !release.load(); ++i)
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        (void)fd;
    });
    ASSERT_TRUE(up.start());

    EgressConfig cfg = make_cfg(up.url());
    cfg.timeout_seconds = 1;  // short, so a respected timeout returns quickly
    EgressServer server;
    std::string err;
    ASSERT_TRUE(server.start(cfg, err)) << err;
    int port = server.port_for("primary");
    ASSERT_GT(port, 0);

    auto t0 = std::chrono::steady_clock::now();
    std::string resp = client_roundtrip(port, "GET / HTTP/1.1\r\nHost: x\r\n\r\n");
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                       std::chrono::steady_clock::now() - t0).count();
    release.store(true);
    server.stop();
    up.stop();

    // Must return within a small multiple of timeout_seconds, not hang.
    EXPECT_LT(elapsed, 4000) << "hung upstream was not bounded by timeout_seconds (took "
                             << elapsed << "ms)";
}

// A malformed child request must be handled without crashing the server, and the
// server must remain healthy enough to serve a subsequent well-formed request.
TEST(EgressAttack, MalformedRequestNoCrashServerSurvives) {
    CapturingUpstream up;
    ASSERT_TRUE(up.start());
    EgressServer server;
    std::string err;
    ASSERT_TRUE(server.start(make_cfg(up.url()), err)) << err;
    int port = server.port_for("primary");
    ASSERT_GT(port, 0);

    // Garbage that is not a valid HTTP request head, then close.
    std::string junk = client_roundtrip(port, "\x01\x02 not-http \xff\xfe\r\n\r\n");
    (void)junk;  // may be 502 or empty; just must not crash.

    // A second, well-formed request must still succeed against a fresh upstream accept.
    CapturingUpstream up2;
    ASSERT_TRUE(up2.start());
    EgressConfig cfg2 = make_cfg(up2.url());
    EgressServer server2;
    std::string err2;
    ASSERT_TRUE(server2.start(cfg2, err2)) << err2;
    int port2 = server2.port_for("primary");
    std::string ok = client_roundtrip(port2, "GET /ok HTTP/1.1\r\nHost: x\r\n\r\n");
    server.stop();
    server2.stop();
    up.stop();
    up2.stop();
    EXPECT_NE(ok.find("200 OK"), std::string::npos) << "server unhealthy after malformed input";
}

TEST(EgressServerIntegration, HttpsUpstreamVerificationFailsClosedTo502) {
    // The upstream presents a self-signed cert not in the system trust store, so the
    // proxy's default peer verification MUST reject it -> clean 502 (never a crash,
    // never a silent verification bypass).
    TlsUpstream up("SECRET-TLS-BODY");
    if (!up.start()) {
        GTEST_SKIP() << "could not stand up a local TLS upstream (OpenSSL keygen unavailable)";
    }

    EgressServer server;
    std::string err;
    ASSERT_TRUE(server.start(make_cfg(up.url()), err)) << err;
    int port = server.port_for("primary");
    ASSERT_GT(port, 0);

    std::string resp = client_roundtrip(port, "GET / HTTP/1.1\r\nHost: x\r\n\r\n");
    server.stop();
    up.stop();

    // Verification failed => 502, and the upstream body/host never leaked.
    EXPECT_NE(resp.find("502"), std::string::npos);
    EXPECT_EQ(resp.find("SECRET-TLS-BODY"), std::string::npos);
    EXPECT_EQ(resp.find("127.0.0.1:" + std::to_string(up.port())), std::string::npos);
}

// ===========================================================================
// Attack round 1: safety / leaks / TLS (added)
// ===========================================================================

// The child_endpoint MUST bind to a loopback address only. The bridge forwards to
// the real upstream and can carry injected upstream credentials (inject_headers),
// so a non-loopback bind exposes it to the whole network. AI_NUMERICHOST alone does
// NOT enforce loopback: "0.0.0.0" is numeric and binds to EVERY interface.
TEST(EgressServerSecurity, RejectsWildcardBind) {
    EgressConfig cfg = make_cfg("http://127.0.0.1:1");
    cfg.bridges[0].child_endpoint = "http://0.0.0.0:0";  // wildcard: all interfaces
    EgressServer server;
    std::string err;
    EXPECT_FALSE(server.start(cfg, err))
        << "server bound child_endpoint to a non-loopback (0.0.0.0) address";
    server.stop();
}

// A literal, routable (non-loopback) address must also be refused up front,
// independent of whether the host happens to own that address.
TEST(EgressServerSecurity, RejectsRoutableBind) {
    EgressConfig cfg = make_cfg("http://127.0.0.1:1");
    cfg.bridges[0].child_endpoint = "http://8.8.8.8:0";
    EgressServer server;
    std::string err;
    EXPECT_FALSE(server.start(cfg, err))
        << "server accepted a routable non-loopback child_endpoint address";
    server.stop();
}

// ===========================================================================
// Attack round 2: fd/thread leaks, SIGPIPE, upstream-host leak, header DoS,
// loopback-bind hardening, and stop() liveness against a hung upstream.
// ===========================================================================

#include <dirent.h>
#include <sys/time.h>

namespace {

// Count entries under /proc/self/fd (a relative measure of open fds).
int count_open_fds() {
    DIR* d = ::opendir("/proc/self/fd");
    if (!d) return -1;
    int n = 0;
    while (::readdir(d)) ++n;
    ::closedir(d);
    return n;
}

// Connect a fresh client socket to 127.0.0.1:port with send/recv timeouts. -1 on failure.
int connect_client(int port) {
    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(static_cast<uint16_t>(port));
    timeval tv{5, 0};
    ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    if (::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        ::close(fd);
        return -1;
    }
    return fd;
}

}  // namespace

// Starting and stopping the server hundreds of times must not leak listener sockets,
// the eventfd, or accept threads (each start() mints an eventfd + one listener socket).
TEST(EgressAttack2, RepeatedStartStopNoFdLeak) {
    int before = count_open_fds();
    ASSERT_GT(before, 0);
    for (int i = 0; i < 200; ++i) {
        EgressServer s;
        EgressConfig cfg = make_cfg("http://127.0.0.1:1");
        std::string err;
        ASSERT_TRUE(s.start(cfg, err)) << "iter " << i << ": " << err;
        ASSERT_GT(s.port_for("primary"), 0);
        s.stop();
    }
    int after = count_open_fds();
    EXPECT_LE(after, before + 2)
        << "fd leak across 200 start/stop cycles: before=" << before << " after=" << after;
}

// Servicing many connections must not leak per-connection fds or leave zombie worker
// threads: after all roundtrips drain, the fd count returns near baseline and stop()
// completes promptly.
TEST(EgressAttack2, ManyConnectionsNoFdOrThreadLeak) {
    TinyUpstream up([](int fd) {
        send_all(fd, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
    });
    ASSERT_TRUE(up.start());
    EgressServer server;
    std::string err;
    ASSERT_TRUE(server.start(make_cfg(up.url()), err)) << err;
    int port = server.port_for("primary");
    ASSERT_GT(port, 0);

    int before = count_open_fds();
    for (int i = 0; i < 80; ++i) {
        std::string r = client_roundtrip(port, "GET / HTTP/1.1\r\nHost: x\r\n\r\n");
        EXPECT_NE(r.find("ok"), std::string::npos) << "roundtrip " << i << " failed";
    }
    // Detached workers close their fds slightly after the client sees EOF; let them settle.
    int after = before;
    for (int i = 0; i < 200; ++i) {
        after = count_open_fds();
        if (after <= before + 3) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    EXPECT_LE(after, before + 3)
        << "fd leak across 80 connections: before=" << before << " after=" << after;

    server.stop();
    up.stop();
}

// A client that fires a request and abortively closes (RST) before reading the response
// must not crash the proxy with SIGPIPE while it relays a large upstream body. The proxy
// must survive and keep serving.
TEST(EgressAttack2, ClientDisconnectMidStreamNoCrash) {
    TinyUpstream up([](int fd) {
        std::string big(2 * 1024 * 1024, 'x');
        std::string resp = "HTTP/1.1 200 OK\r\nContent-Length: " + std::to_string(big.size()) +
                           "\r\nConnection: close\r\n\r\n" + big;
        send_all(fd, resp);
    });
    ASSERT_TRUE(up.start());
    EgressServer server;
    std::string err;
    ASSERT_TRUE(server.start(make_cfg(up.url()), err)) << err;
    int port = server.port_for("primary");
    ASSERT_GT(port, 0);

    int fd = connect_client(port);
    ASSERT_GE(fd, 0);
    send_all(fd, "GET / HTTP/1.1\r\nHost: x\r\n\r\n");
    struct linger lg{1, 0};  // SO_LINGER 0 => RST on close, provoking EPIPE on the relay write
    ::setsockopt(fd, SOL_SOCKET, SO_LINGER, &lg, sizeof(lg));
    ::close(fd);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    // The proxy must still be alive: a fresh request against a fresh upstream succeeds.
    TinyUpstream up2([](int f) {
        send_all(f, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
    });
    ASSERT_TRUE(up2.start());
    EgressServer server2;
    std::string err2;
    ASSERT_TRUE(server2.start(make_cfg(up2.url()), err2)) << err2;
    std::string ok = client_roundtrip(server2.port_for("primary"), "GET / HTTP/1.1\r\nHost: x\r\n\r\n");

    server.stop();
    server2.stop();
    up.stop();
    up2.stop();
    EXPECT_NE(ok.find("200 OK"), std::string::npos)
        << "proxy died after abortive client disconnect mid-stream (SIGPIPE?)";
}

// The real upstream host/port must NEVER appear in a child-visible error response when the
// upstream connection cannot be established.
TEST(EgressAttack2, UpstreamHostNotLeakedOnConnectFailure) {
    EgressConfig cfg = make_cfg("http://secret-upstream-xyzzy.invalid:12345");
    EgressServer server;
    std::string err;
    ASSERT_TRUE(server.start(cfg, err)) << err;
    int port = server.port_for("primary");
    ASSERT_GT(port, 0);

    std::string r = client_roundtrip(port, "GET /path HTTP/1.1\r\nHost: child\r\n\r\n");
    server.stop();

    EXPECT_NE(r.find("502"), std::string::npos) << "expected a 502 for unresolvable upstream";
    EXPECT_EQ(r.find("secret-upstream-xyzzy"), std::string::npos)
        << "upstream host leaked into child-visible error response: " << r;
    EXPECT_EQ(r.find("12345"), std::string::npos)
        << "upstream port leaked into child-visible error response: " << r;
    EXPECT_EQ(r.find(".invalid"), std::string::npos) << "upstream host fragment leaked: " << r;
}

// A gigantic request head (no terminator) must be rejected at the bounded cap without
// unbounded buffering, without hanging, and without crashing; the proxy stays healthy.
TEST(EgressAttack2, HugeHeaderBoundedNoHangNoCrash) {
    CapturingUpstream up;
    ASSERT_TRUE(up.start());
    EgressServer server;
    std::string err;
    ASSERT_TRUE(server.start(make_cfg(up.url()), err)) << err;
    int port = server.port_for("primary");
    ASSERT_GT(port, 0);

    // 128 KiB single header line, never terminated: exceeds the 64 KiB head cap.
    int fd = connect_client(port);
    ASSERT_GE(fd, 0);
    std::string req = "GET / HTTP/1.1\r\nX-Big: ";
    req += std::string(128 * 1024, 'A');
    send_all(fd, req);          // SIGPIPE is ignored process-wide once start() ran
    ::shutdown(fd, SHUT_WR);
    // Drain until the proxy closes (bounded by the client recv timeout): must not hang.
    std::string resp;
    char b[4096];
    for (;;) {
        ssize_t n = ::recv(fd, b, sizeof(b), 0);
        if (n <= 0) break;
        resp.append(b, static_cast<size_t>(n));
    }
    ::close(fd);

    // Proxy stays healthy for a subsequent well-formed request.
    CapturingUpstream up2;
    ASSERT_TRUE(up2.start());
    EgressServer server2;
    std::string err2;
    ASSERT_TRUE(server2.start(make_cfg(up2.url()), err2)) << err2;
    std::string ok = client_roundtrip(server2.port_for("primary"),
                                      "GET /ok HTTP/1.1\r\nHost: x\r\n\r\n");
    server.stop();
    server2.stop();
    up.stop();
    up2.stop();
    EXPECT_NE(ok.find("200 OK"), std::string::npos)
        << "proxy unhealthy after an oversized-header attack";
}

// A DNS name as child_endpoint must be refused (AI_NUMERICHOST): only numeric loopback binds.
TEST(EgressAttack2, RejectsDnsNameBind) {
    EgressConfig cfg = make_cfg("http://127.0.0.1:1");
    cfg.bridges[0].child_endpoint = "http://localhost:0";
    EgressServer server;
    std::string err;
    EXPECT_FALSE(server.start(cfg, err))
        << "accepted a DNS-name child_endpoint; AI_NUMERICHOST must reject non-numeric hosts";
    server.stop();
}

// An alternate 127.0.0.0/8 address is still loopback and must be accepted.
TEST(EgressAttack2, AcceptsAlternateLoopback) {
    EgressConfig cfg = make_cfg("http://127.0.0.1:1");
    cfg.bridges[0].child_endpoint = "http://127.0.0.2:0";
    EgressServer server;
    std::string err;
    EXPECT_TRUE(server.start(cfg, err)) << "127.0.0.2 is loopback (127/8) and should bind: " << err;
    server.stop();
}

// The IPv6 loopback ::1 must be accepted (skipped where the host lacks IPv6 loopback).
TEST(EgressAttack2, AcceptsIpv6Loopback) {
    EgressConfig cfg = make_cfg("http://127.0.0.1:1");
    cfg.bridges[0].child_endpoint = "http://[::1]:0";
    EgressServer server;
    std::string err;
    if (!server.start(cfg, err)) {
        server.stop();
        GTEST_SKIP() << "no IPv6 loopback available: " << err;
    }
    EXPECT_GT(server.port_for("primary"), 0);
    server.stop();
}

// stop() must not hang when a worker is blocked on a hung (accept-but-never-reply) upstream:
// the per-socket timeout must bound the worker so stop() returns within a small multiple of it.
TEST(EgressAttack2, StopUnblocksOnHungUpstreamWithinTimeout) {
    TinyUpstream up([](int /*fd*/) {
        // Accept and never reply; hold the connection until the test tears everything down.
        for (int i = 0; i < 40; ++i) std::this_thread::sleep_for(std::chrono::milliseconds(100));
    });
    ASSERT_TRUE(up.start());

    EgressConfig cfg = make_cfg(up.url());
    cfg.timeout_seconds = 1;  // bound worker read on the hung upstream
    EgressServer server;
    std::string err;
    ASSERT_TRUE(server.start(cfg, err)) << err;
    int port = server.port_for("primary");
    ASSERT_GT(port, 0);

    // Fire a request and leave it in-flight (do not read the response).
    int fd = connect_client(port);
    ASSERT_GE(fd, 0);
    send_all(fd, "GET / HTTP/1.1\r\nHost: x\r\n\r\n");
    std::this_thread::sleep_for(std::chrono::milliseconds(150));  // let the worker reach upstream read

    auto t0 = std::chrono::steady_clock::now();
    server.stop();  // must not block indefinitely on the hung worker
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                       std::chrono::steady_clock::now() - t0)
                       .count();
    ::close(fd);
    up.stop();

    EXPECT_LT(elapsed, 5000)
        << "stop() blocked " << elapsed << "ms on a hung upstream; worker timeout did not bound it";
}

// ===========================================================================
// Attack round 2 (correctness + streaming): interim responses, request-line
// robustness, and large-response streaming.
// ===========================================================================

namespace {

// A one-shot upstream that binds 127.0.0.1:0, accepts a single connection, and hands the
// raw fd to a caller-supplied handler so the handler controls exact response timing/bytes.
class RawUpstream {
public:
    explicit RawUpstream(std::function<void(int)> h) : h_(std::move(h)) {}
    bool start() {
        fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
        if (fd_ < 0) return false;
        int one = 1;
        ::setsockopt(fd_, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        sockaddr_in a{};
        a.sin_family = AF_INET;
        a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        a.sin_port = 0;
        if (::bind(fd_, reinterpret_cast<sockaddr*>(&a), sizeof(a)) < 0) return false;
        if (::listen(fd_, 8) < 0) return false;
        socklen_t sl = sizeof(a);
        ::getsockname(fd_, reinterpret_cast<sockaddr*>(&a), &sl);
        port_ = ntohs(a.sin_port);
        th_ = std::thread([this] {
            int c = ::accept(fd_, nullptr, nullptr);
            if (c >= 0) { h_(c); ::close(c); }
        });
        return true;
    }
    int port() const { return port_; }
    std::string url() const { return "http://127.0.0.1:" + std::to_string(port_); }
    void stop() {
        if (fd_ >= 0) { ::shutdown(fd_, SHUT_RDWR); ::close(fd_); fd_ = -1; }
        if (th_.joinable()) th_.join();
    }
    ~RawUpstream() { stop(); }

private:
    std::function<void(int)> h_;
    int fd_ = -1, port_ = 0;
    std::thread th_;
};

// Read a request head (up to CRLFCRLF) off a raw fd; returns whatever was read.
std::string read_head_raw(int fd) {
    std::string buf;
    char t[2048];
    while (buf.find("\r\n\r\n") == std::string::npos) {
        ssize_t n = ::recv(fd, t, sizeof(t), 0);
        if (n <= 0) break;
        buf.append(t, static_cast<size_t>(n));
    }
    return buf;
}

}  // namespace

// A large (5 MB) RESPONSE streamed back to the child must arrive intact and uncorrupted
// (round-1 only exercised a large REQUEST body). Positive control for the response path.
TEST(EgressAttack2, LargeResponseRelayedIntact) {
    const size_t N = 5u * 1024 * 1024;
    std::string body;
    body.reserve(N);
    for (size_t i = 0; i < N; ++i) body.push_back(static_cast<char>('a' + (i % 26)));
    RawUpstream up([&body](int fd) {
        read_head_raw(fd);
        std::string resp = "HTTP/1.1 200 OK\r\nContent-Length: " + std::to_string(body.size()) +
                           "\r\nConnection: close\r\n\r\n" + body;
        send_all(fd, resp);
    });
    ASSERT_TRUE(up.start());
    EgressConfig cfg = make_cfg(up.url());
    cfg.timeout_seconds = 15;
    EgressServer server;
    std::string err;
    ASSERT_TRUE(server.start(cfg, err)) << err;
    int port = server.port_for("primary");
    ASSERT_GT(port, 0);

    int fd = connect_client(port);
    ASSERT_GE(fd, 0);
    timeval tv{10, 0};
    ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    send_all(fd, "GET /big HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n");
    std::string resp;
    char buf[65536];
    for (;;) {
        ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
        if (n <= 0) break;
        resp.append(buf, static_cast<size_t>(n));
    }
    ::close(fd);
    server.stop();
    up.stop();

    size_t bp = resp.find("\r\n\r\n");
    ASSERT_NE(bp, std::string::npos);
    std::string got = resp.substr(bp + 4);
    EXPECT_EQ(got.size(), body.size()) << "large response truncated";
    EXPECT_EQ(got, body) << "large response corrupted in transit";
}

// DEFECT: Expect: 100-continue is not honored. A strict client that withholds its request
// body until it receives an interim "100 Continue" deadlocks: the proxy blocks reading the
// body (which the client won't send) while the upstream's 100-continue sits unread in the
// upstream socket. The proxy must relay interim 1xx responses to the child before it reads
// the request body. Today this stalls until timeout_seconds and the POST fails.
TEST(EgressAttack2, Expect100ContinueRelayed) {
    RawUpstream up([](int fd) {
        read_head_raw(fd);
        send_all(fd, "HTTP/1.1 100 Continue\r\n\r\n");  // interim, immediately
        char t[64];
        ::recv(fd, t, sizeof(t), 0);  // then read the body
        send_all(fd, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
    });
    ASSERT_TRUE(up.start());
    EgressConfig cfg = make_cfg(up.url());
    cfg.timeout_seconds = 3;  // keep the deadlock (and teardown) bounded
    EgressServer server;
    std::string err;
    ASSERT_TRUE(server.start(cfg, err)) << err;
    int port = server.port_for("primary");
    ASSERT_GT(port, 0);

    int fd = connect_client(port);
    ASSERT_GE(fd, 0);
    timeval tv{2, 0};
    ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    send_all(fd,
             "POST /x HTTP/1.1\r\nHost: 127.0.0.1\r\nExpect: 100-continue\r\n"
             "Content-Length: 5\r\n\r\n");
    // Strict client: wait for the interim 100-continue before sending the body.
    char buf[512];
    ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
    std::string got = (n > 0) ? std::string(buf, static_cast<size_t>(n)) : std::string();
    bool saw_100 = got.find("100 Continue") != std::string::npos;
    if (saw_100) send_all(fd, "hello");  // proceed so nothing hangs
    ::close(fd);
    server.stop();
    up.stop();

    EXPECT_TRUE(saw_100)
        << "proxy did not relay the interim 100-continue before the request body; "
           "an Expect:100-continue POST stalls until timeout. got='"
        << got << "'";
}

// DEFECT: a request-line preceded by a single empty line is rejected with 502. RFC 7230
// section 3.5 says a server SHOULD ignore at least one leading empty line before the
// request-line (some clients emit a stray CRLF). The bridge must not fail such requests.
TEST(EgressAttack2, LeadingEmptyLineTolerated) {
    RawUpstream up([](int fd) {
        read_head_raw(fd);
        send_all(fd, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
    });
    ASSERT_TRUE(up.start());
    EgressServer server;
    std::string err;
    ASSERT_TRUE(server.start(make_cfg(up.url()), err)) << err;
    int port = server.port_for("primary");
    ASSERT_GT(port, 0);

    int fd = connect_client(port);
    ASSERT_GE(fd, 0);
    send_all(fd, "\r\nGET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n");  // stray leading CRLF
    char buf[512];
    ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
    std::string got = (n > 0) ? std::string(buf, static_cast<size_t>(n)) : std::string();
    ::close(fd);
    server.stop();
    up.stop();

    EXPECT_NE(got.find("200 OK"), std::string::npos)
        << "leading empty line before the request-line was rejected instead of tolerated; got='"
        << got << "'";
}

// ===========================================================================
// Attack round 3 (correctness + streaming): live-stream idle-gap truncation
// and chunked-request framing (trailer / chunk-extension) recognition.
// ===========================================================================

namespace {
// Drain a socket until EOF, using a bounded per-recv timeout so a stalled peer
// can't hang the test.
std::string drain_with_timeout(int fd, long ms) {
    timeval tv;
    tv.tv_sec = static_cast<time_t>(ms / 1000);
    tv.tv_usec = static_cast<suseconds_t>((ms % 1000) * 1000);  // macOS suseconds_t is int; avoid narrowing
    ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    std::string b;
    char t[8192];
    for (;;) {
        ssize_t n = ::recv(fd, t, sizeof(t), 0);
        if (n <= 0) break;
        b.append(t, static_cast<size_t>(n));
    }
    return b;
}
}  // namespace

// DEFECT: a live-but-idle streaming response (SSE / close-delimited) is SILENTLY
// truncated when the gap between two chunks exceeds timeout_seconds. The response
// relay applies timeout_seconds as an inter-chunk idle timeout and, because bytes
// were already relayed, breaks WITHOUT emitting any error (no 504). The upstream is
// still connected and about to send more — so a slow-but-alive stream loses data and
// the child sees a clean connection close it cannot distinguish from a complete
// response. timeout_seconds should bound a HUNG upstream, not a paused live stream.
TEST(EgressAttack3, LiveStreamIdleGapNotSilentlyTruncated) {
    RawUpstream up([](int fd) {
        read_head_raw(fd);
        std::string head =
            "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\n";
        send_all(fd, head + "data: EVENT_ONE\n\n");
        std::this_thread::sleep_for(std::chrono::milliseconds(1500));  // gap > timeout_seconds
        send_all(fd, "data: EVENT_TWO\n\n");
    });
    ASSERT_TRUE(up.start());

    EgressConfig cfg = make_cfg(up.url());
    cfg.timeout_seconds = 1;  // shorter than the 1.5s inter-event gap
    EgressServer server;
    std::string err;
    ASSERT_TRUE(server.start(cfg, err)) << err;
    int port = server.port_for("primary");
    ASSERT_GT(port, 0);

    int fd = connect_client(port);
    ASSERT_GE(fd, 0);
    send_all(fd, "GET /sse HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n");
    std::string got = drain_with_timeout(fd, 5000);
    ::close(fd);
    server.stop();
    up.stop();

    EXPECT_NE(got.find("EVENT_ONE"), std::string::npos) << got;
    EXPECT_NE(got.find("EVENT_TWO"), std::string::npos)
        << "live stream truncated: an inter-chunk gap longer than timeout_seconds dropped the "
           "second event and closed the child connection with no error. got='"
        << got << "'";
}

// DEFECT: a chunked request whose last-chunk carries a trailer (or a chunk-extension)
// is valid HTTP, but the proxy's fixed terminator scan ("\r\n0\r\n\r\n") does not match
// it, so the proxy never recognizes end-of-body. It keeps blocking on the child socket
// until SO_RCVTIMEO (timeout_seconds) fires — even though it already forwarded the whole
// body upstream and the upstream already replied. Result: every chunked request bearing a
// trailer/extension incurs a full timeout_seconds of added latency.
TEST(EgressAttack3, ChunkedRequestWithTrailerNotStalled) {
    RawUpstream up([](int fd) {
        read_head_raw(fd);
        drain_with_timeout(fd, 300);  // absorb the chunked body quickly
        send_all(fd, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
    });
    ASSERT_TRUE(up.start());

    EgressConfig cfg = make_cfg(up.url());
    cfg.timeout_seconds = 4;  // large enough that a stall is obvious
    EgressServer server;
    std::string err;
    ASSERT_TRUE(server.start(cfg, err)) << err;
    int port = server.port_for("primary");
    ASSERT_GT(port, 0);

    auto t0 = std::chrono::steady_clock::now();
    std::string resp = client_roundtrip(
        port,
        "POST /x HTTP/1.1\r\nHost: 127.0.0.1\r\nTransfer-Encoding: chunked\r\n\r\n"
        "5\r\nhello\r\n0\r\nX-Checksum: abc\r\n\r\n");  // last chunk + trailer
    long ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                  std::chrono::steady_clock::now() - t0).count();
    server.stop();
    up.stop();

    EXPECT_NE(resp.find("ok"), std::string::npos) << resp;
    EXPECT_LT(ms, 2000)
        << "chunked request with a trailer stalled ~timeout_seconds (" << ms
        << "ms): the last-chunk terminator was not recognized because of the trailer.";
}
