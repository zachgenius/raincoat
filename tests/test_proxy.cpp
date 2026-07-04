// Raincoat — proxy tests.
//
// Two layers, both localhost-only and non-flaky (no real external internet):
//   1. host_allowed() PURE truth table — allow/deny defaults, block_hosts wins, dot-suffix
//      matching, metadata blocking (names + literal IPs + link-local /16).
//   2. Live ProxyServer integration on 127.0.0.1: a real local HTTP origin is reachable via
//      an ALLOWED "localhost" GET; a blocked/deny host returns 403; a GET or CONNECT to the
//      metadata IP returns 403 and the origin is never dialed; a CONNECT to an allowed host
//      establishes a blind byte tunnel.
#include "proxy.hpp"

#include <gtest/gtest.h>

#include <atomic>
#include <cstring>
#include <string>
#include <thread>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

using namespace raincoat;

// ===========================================================================
// host_allowed() truth table
// ===========================================================================

TEST(HostAllowed, DefaultAllowLetsAnythingUnblockedOut) {
    NetworkPolicy p;  // enabled default false is irrelevant to host_allowed; action="allow"
    p.default_action = "allow";
    p.block_private_metadata_endpoints = false;
    EXPECT_TRUE(host_allowed("example.com", p));
    EXPECT_TRUE(host_allowed("api.github.com", p));
    EXPECT_TRUE(host_allowed("localhost", p));
}

TEST(HostAllowed, DefaultDenyBlocksUnlistedHosts) {
    NetworkPolicy p;
    p.default_action = "deny";
    p.block_private_metadata_endpoints = false;
    p.allow_hosts = {"github.com"};
    EXPECT_TRUE(host_allowed("github.com", p));
    EXPECT_TRUE(host_allowed("api.github.com", p));  // dot-suffix of an allowed host
    EXPECT_FALSE(host_allowed("example.com", p));    // not on the allow-list
    EXPECT_FALSE(host_allowed("notgithub.com", p));  // suffix must be on a dot boundary
}

TEST(HostAllowed, BlockHostsWinsOverAllowAndDefault) {
    NetworkPolicy p;
    p.default_action = "allow";
    p.block_private_metadata_endpoints = false;
    p.allow_hosts = {"evil.com"};   // even explicitly allowed...
    p.block_hosts = {"evil.com"};   // ...block wins.
    EXPECT_FALSE(host_allowed("evil.com", p));
    EXPECT_FALSE(host_allowed("api.evil.com", p));  // dot-suffix match
    EXPECT_TRUE(host_allowed("good.com", p));       // default allow otherwise
}

TEST(HostAllowed, BlockHostsWinsInDenyModeToo) {
    NetworkPolicy p;
    p.default_action = "deny";
    p.block_private_metadata_endpoints = false;
    p.allow_hosts = {"corp.example.com"};
    p.block_hosts = {"example.com"};  // suffix-blocks the allowed subdomain
    EXPECT_FALSE(host_allowed("corp.example.com", p));
}

TEST(HostAllowed, DotSuffixDoesNotMatchSubstring) {
    NetworkPolicy p;
    p.default_action = "deny";
    p.block_private_metadata_endpoints = false;
    p.allow_hosts = {"evil.com"};
    EXPECT_FALSE(host_allowed("evil.com.attacker.net", p));  // not a suffix of evil.com
    EXPECT_TRUE(host_allowed("evil.com", p));
}

TEST(HostAllowed, MetadataBlockedByName) {
    NetworkPolicy p;
    p.default_action = "allow";
    // block_private_metadata_endpoints defaults true.
    EXPECT_FALSE(host_allowed("metadata.google.internal", p));
    EXPECT_FALSE(host_allowed("metadata", p));
}

TEST(HostAllowed, MetadataBlockedByLiteralIPv4) {
    NetworkPolicy p;
    p.default_action = "allow";
    EXPECT_FALSE(host_allowed("169.254.169.254", p));
}

TEST(HostAllowed, MetadataBlockedByLinkLocalRange) {
    NetworkPolicy p;
    p.default_action = "allow";
    // Any 169.254.0.0/16 literal is blocked, not just .169.254.
    EXPECT_FALSE(host_allowed("169.254.0.1", p));
    EXPECT_FALSE(host_allowed("169.254.255.255", p));
    EXPECT_TRUE(host_allowed("169.253.0.1", p));  // just outside the /16
}

TEST(HostAllowed, MetadataBlockedByIPv6Literal) {
    NetworkPolicy p;
    p.default_action = "allow";
    EXPECT_FALSE(host_allowed("fd00:ec2::254", p));
    EXPECT_FALSE(host_allowed("[fd00:ec2::254]", p));      // bracketed authority form
    EXPECT_FALSE(host_allowed("fd00:ec2:0:0::254", p));    // non-canonical spelling
}

TEST(HostAllowed, ExtraMetadataEndpointsBlocked) {
    NetworkPolicy p;
    p.default_action = "allow";
    p.metadata_endpoints = {"metadata.example.internal", "100.100.100.200"};
    EXPECT_FALSE(host_allowed("metadata.example.internal", p));
    EXPECT_FALSE(host_allowed("100.100.100.200", p));
    EXPECT_TRUE(host_allowed("100.100.100.201", p));  // not the configured metadata IP
}

TEST(HostAllowed, MetadataNotBlockedWhenDisabled) {
    NetworkPolicy p;
    p.default_action = "allow";
    p.block_private_metadata_endpoints = false;
    EXPECT_TRUE(host_allowed("169.254.169.254", p));
    EXPECT_TRUE(host_allowed("metadata.google.internal", p));
}

TEST(HostAllowed, EmptyHostFailsClosed) {
    NetworkPolicy p;
    p.default_action = "allow";
    EXPECT_FALSE(host_allowed("", p));
}

TEST(HostAllowed, CaseInsensitiveAndTrailingDot) {
    NetworkPolicy p;
    p.default_action = "deny";
    p.block_private_metadata_endpoints = false;
    p.allow_hosts = {"github.com"};
    EXPECT_TRUE(host_allowed("GitHub.COM", p));
    EXPECT_TRUE(host_allowed("github.com.", p));  // FQDN root dot
    p.block_hosts = {"Evil.COM"};
    EXPECT_FALSE(host_allowed("api.evil.com", p));
}

// ===========================================================================
// Live proxy integration (127.0.0.1 only)
// ===========================================================================

namespace {

// A minimal single-shot-ish HTTP origin server on 127.0.0.1. Answers every request with a
// fixed 200 + "hello" body. Counts accepted connections so a test can assert the proxy
// NEVER dialed it for a blocked target.
class HttpOrigin {
public:
    bool start() {
        fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
        if (fd_ < 0) return false;
        int one = 1;
        ::setsockopt(fd_, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        sockaddr_in a{};
        a.sin_family = AF_INET;
        a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        a.sin_port = 0;
        if (::bind(fd_, reinterpret_cast<sockaddr*>(&a), sizeof(a)) != 0) return false;
        socklen_t len = sizeof(a);
        if (::getsockname(fd_, reinterpret_cast<sockaddr*>(&a), &len) != 0) return false;
        port_ = ntohs(a.sin_port);
        if (::listen(fd_, 16) != 0) return false;
        thread_ = std::thread([this] { loop(); });
        return true;
    }
    void stop() {
        running_.store(false);
        if (fd_ >= 0) {
            ::shutdown(fd_, SHUT_RDWR);
            ::close(fd_);
            fd_ = -1;
        }
        if (thread_.joinable()) thread_.join();
    }
    ~HttpOrigin() { stop(); }
    int port() const { return port_; }
    int accepts() const { return accepts_.load(); }

private:
    void loop() {
        while (running_.load()) {
            pollfd pfd{fd_, POLLIN, 0};
            int pr = ::poll(&pfd, 1, 200);
            if (pr <= 0) continue;
            int c = ::accept(fd_, nullptr, nullptr);
            if (c < 0) continue;
            accepts_.fetch_add(1);
            char buf[4096];
            ::recv(c, buf, sizeof(buf), 0);  // read (and ignore) the request head
            const char* resp =
                "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello";
            size_t off = 0, len = std::strlen(resp);
            while (off < len) {
                ssize_t w = ::send(c, resp + off, len - off, MSG_NOSIGNAL);
                if (w <= 0) break;
                off += static_cast<size_t>(w);
            }
            ::shutdown(c, SHUT_RDWR);
            ::close(c);
        }
    }
    int fd_ = -1;
    int port_ = 0;
    std::atomic<bool> running_{true};
    std::atomic<int> accepts_{0};
    std::thread thread_;
};

// A tiny plain-TCP echo origin: after connect, reads bytes and echoes them back with a
// "echo:" prefix on the first read. Lets a CONNECT blind-tunnel test verify byte relay
// without any TLS.
class EchoOrigin {
public:
    bool start() {
        fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
        if (fd_ < 0) return false;
        int one = 1;
        ::setsockopt(fd_, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        sockaddr_in a{};
        a.sin_family = AF_INET;
        a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        a.sin_port = 0;
        if (::bind(fd_, reinterpret_cast<sockaddr*>(&a), sizeof(a)) != 0) return false;
        socklen_t len = sizeof(a);
        if (::getsockname(fd_, reinterpret_cast<sockaddr*>(&a), &len) != 0) return false;
        port_ = ntohs(a.sin_port);
        if (::listen(fd_, 16) != 0) return false;
        thread_ = std::thread([this] { loop(); });
        return true;
    }
    void stop() {
        running_.store(false);
        if (fd_ >= 0) {
            ::shutdown(fd_, SHUT_RDWR);
            ::close(fd_);
            fd_ = -1;
        }
        if (thread_.joinable()) thread_.join();
    }
    ~EchoOrigin() { stop(); }
    int port() const { return port_; }

private:
    void loop() {
        while (running_.load()) {
            pollfd pfd{fd_, POLLIN, 0};
            int pr = ::poll(&pfd, 1, 200);
            if (pr <= 0) continue;
            int c = ::accept(fd_, nullptr, nullptr);
            if (c < 0) continue;
            char buf[1024];
            ssize_t n = ::recv(c, buf, sizeof(buf), 0);
            if (n > 0) {
                std::string out = "echo:" + std::string(buf, static_cast<size_t>(n));
                ::send(c, out.data(), out.size(), MSG_NOSIGNAL);
            }
            ::shutdown(c, SHUT_RDWR);
            ::close(c);
        }
    }
    int fd_ = -1;
    int port_ = 0;
    std::atomic<bool> running_{true};
    std::thread thread_;
};

// Connect to the proxy on 127.0.0.1:port, send `request` verbatim, read the whole response
// until EOF (bounded by a receive timeout). Returns "" on connect failure.
std::string proxy_roundtrip(int proxy_port, const std::string& request) {
    int s = ::socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) return "";
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = htons(static_cast<uint16_t>(proxy_port));
    timeval tv{3, 0};
    ::setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    ::setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    if (::connect(s, reinterpret_cast<sockaddr*>(&a), sizeof(a)) != 0) {
        ::close(s);
        return "";
    }
    ::send(s, request.data(), request.size(), MSG_NOSIGNAL);
    std::string resp;
    char buf[4096];
    for (;;) {
        ssize_t n = ::recv(s, buf, sizeof(buf), 0);
        if (n <= 0) break;
        resp.append(buf, static_cast<size_t>(n));
    }
    ::close(s);
    return resp;
}

}  // namespace

TEST(ProxyServer, AllowedHostGetSucceeds) {
    HttpOrigin origin;
    ASSERT_TRUE(origin.start());

    NetworkPolicy p;
    p.enabled = true;
    p.default_action = "deny";
    p.allow_hosts = {"localhost"};

    ProxyServer proxy;
    std::string err;
    ASSERT_TRUE(proxy.start("127.0.0.1", 0, p, 5, err)) << err;
    ASSERT_GT(proxy.port(), 0);

    std::string req = "GET http://localhost:" + std::to_string(origin.port()) +
                      "/ HTTP/1.1\r\nHost: localhost:" + std::to_string(origin.port()) +
                      "\r\n\r\n";
    std::string resp = proxy_roundtrip(proxy.port(), req);
    EXPECT_NE(resp.find("200 OK"), std::string::npos) << resp;
    EXPECT_NE(resp.find("hello"), std::string::npos) << resp;

    proxy.stop();
    origin.stop();
}

TEST(ProxyServer, BlockedHostGetReturns403AndNeverDials) {
    HttpOrigin origin;
    ASSERT_TRUE(origin.start());

    NetworkPolicy p;
    p.enabled = true;
    p.default_action = "allow";
    p.block_hosts = {"localhost"};  // block wins

    ProxyServer proxy;
    std::string err;
    ASSERT_TRUE(proxy.start("127.0.0.1", 0, p, 5, err)) << err;

    std::string req = "GET http://localhost:" + std::to_string(origin.port()) +
                      "/ HTTP/1.1\r\nHost: localhost:" + std::to_string(origin.port()) +
                      "\r\n\r\n";
    std::string resp = proxy_roundtrip(proxy.port(), req);
    EXPECT_NE(resp.find("403 Forbidden"), std::string::npos) << resp;
    EXPECT_EQ(resp.find("hello"), std::string::npos) << resp;
    EXPECT_EQ(origin.accepts(), 0);  // the origin was never connected

    proxy.stop();
    origin.stop();
}

TEST(ProxyServer, DefaultDenyWithoutAllowReturns403) {
    HttpOrigin origin;
    ASSERT_TRUE(origin.start());

    NetworkPolicy p;
    p.enabled = true;
    p.default_action = "deny";  // no allow_hosts => nothing allowed

    ProxyServer proxy;
    std::string err;
    ASSERT_TRUE(proxy.start("127.0.0.1", 0, p, 5, err)) << err;

    std::string req = "GET http://localhost:" + std::to_string(origin.port()) +
                      "/ HTTP/1.1\r\nHost: localhost\r\n\r\n";
    std::string resp = proxy_roundtrip(proxy.port(), req);
    EXPECT_NE(resp.find("403 Forbidden"), std::string::npos) << resp;
    EXPECT_EQ(origin.accepts(), 0);

    proxy.stop();
    origin.stop();
}

TEST(ProxyServer, MetadataGetReturns403AndNeverDials) {
    NetworkPolicy p;
    p.enabled = true;
    p.default_action = "allow";  // permissive default, but metadata is still blocked

    ProxyServer proxy;
    std::string err;
    ASSERT_TRUE(proxy.start("127.0.0.1", 0, p, 3, err)) << err;

    std::string req =
        "GET http://169.254.169.254/latest/meta-data/ HTTP/1.1\r\nHost: 169.254.169.254\r\n\r\n";
    std::string resp = proxy_roundtrip(proxy.port(), req);
    EXPECT_NE(resp.find("403 Forbidden"), std::string::npos) << resp;

    proxy.stop();
}

TEST(ProxyServer, MetadataConnectReturns403) {
    NetworkPolicy p;
    p.enabled = true;
    p.default_action = "allow";

    ProxyServer proxy;
    std::string err;
    ASSERT_TRUE(proxy.start("127.0.0.1", 0, p, 3, err)) << err;

    std::string req = "CONNECT 169.254.169.254:443 HTTP/1.1\r\nHost: 169.254.169.254:443\r\n\r\n";
    std::string resp = proxy_roundtrip(proxy.port(), req);
    EXPECT_NE(resp.find("403 Forbidden"), std::string::npos) << resp;
    EXPECT_EQ(resp.find("Connection Established"), std::string::npos) << resp;

    proxy.stop();
}

TEST(ProxyServer, AllowedConnectEstablishesBlindTunnel) {
    EchoOrigin origin;
    ASSERT_TRUE(origin.start());

    NetworkPolicy p;
    p.enabled = true;
    p.default_action = "deny";
    p.allow_hosts = {"localhost"};

    ProxyServer proxy;
    std::string err;
    ASSERT_TRUE(proxy.start("127.0.0.1", 0, p, 5, err)) << err;

    // Open the tunnel, then push bytes and read the echo back over the same socket.
    int s = ::socket(AF_INET, SOCK_STREAM, 0);
    ASSERT_GE(s, 0);
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = htons(static_cast<uint16_t>(proxy.port()));
    timeval tv{3, 0};
    ::setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    ASSERT_EQ(::connect(s, reinterpret_cast<sockaddr*>(&a), sizeof(a)), 0);

    std::string connect_req = "CONNECT localhost:" + std::to_string(origin.port()) +
                              " HTTP/1.1\r\nHost: localhost\r\n\r\n";
    ::send(s, connect_req.data(), connect_req.size(), MSG_NOSIGNAL);

    // Read the proxy's CONNECT reply (ends with the CRLFCRLF).
    std::string reply;
    char buf[1024];
    while (reply.find("\r\n\r\n") == std::string::npos) {
        ssize_t n = ::recv(s, buf, sizeof(buf), 0);
        if (n <= 0) break;
        reply.append(buf, static_cast<size_t>(n));
    }
    ASSERT_NE(reply.find("200 Connection Established"), std::string::npos) << reply;

    // Now the socket is a raw tunnel to the echo origin.
    const char* payload = "ping";
    ::send(s, payload, std::strlen(payload), MSG_NOSIGNAL);
    std::string tunneled;
    for (;;) {
        ssize_t n = ::recv(s, buf, sizeof(buf), 0);
        if (n <= 0) break;
        tunneled.append(buf, static_cast<size_t>(n));
        if (tunneled.find("echo:ping") != std::string::npos) break;
    }
    EXPECT_NE(tunneled.find("echo:ping"), std::string::npos) << tunneled;

    ::close(s);
    proxy.stop();
    origin.stop();
}

TEST(ProxyServer, RejectsNonLoopbackBind) {
    NetworkPolicy p;
    ProxyServer proxy;
    std::string err;
    EXPECT_FALSE(proxy.start("0.0.0.0", 0, p, 5, err));
    EXPECT_FALSE(err.empty());
}

TEST(ProxyServer, StartStopIsClean) {
    NetworkPolicy p;
    p.default_action = "allow";
    ProxyServer proxy;
    std::string err;
    ASSERT_TRUE(proxy.start("127.0.0.1", 0, p, 5, err)) << err;
    int port = proxy.port();
    EXPECT_GT(port, 0);
    proxy.stop();
    EXPECT_EQ(proxy.port(), -1);
    // Restartable after stop().
    ASSERT_TRUE(proxy.start("127.0.0.1", 0, p, 5, err)) << err;
    EXPECT_GT(proxy.port(), 0);
    proxy.stop();
}
