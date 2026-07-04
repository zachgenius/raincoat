// Raincoat — proxy/policy ATTACK ROUND 2 regression tests.
//
// These encode SECURE behavior the policy engine CLAIMS to provide and that the current
// implementation VIOLATES. They are localhost-only and deterministic (no external internet).
//
// Headline defect (post-resolution SSRF bypass):
//   host_allowed() filters the LITERAL request target string, and ProxyServer then hands that
//   same string to getaddrinfo()/connect() WITHOUT ever re-checking the RESOLVED address. So a
//   host that policy blocks by IP literal (including the cloud-metadata IPs that
//   block_private_metadata_endpoints is supposed to fence off "for SSRF hardening") is reached
//   trivially by asking for ANY NAME that resolves to that IP. The name is not the blocked
//   literal, so it sails past policy; the resolver then maps it straight to the blocked address
//   and the proxy dials it.
//
// This is the canonical cloud-metadata SSRF: block_private_metadata_endpoints defaults TRUE and
// blocks 169.254.169.254, but "http://<anything-that-resolves-to-169.254.169.254>/" is NOT the
// blocked literal, so the proxy happily fetches instance credentials. It works in BOTH
// default_action=allow AND deny (an allow-listed name that resolves to metadata) modes.
//
// We demonstrate the exact MECHANISM deterministically on loopback: "localhost" reliably
// resolves to 127.0.0.1, so blocking the IP 127.0.0.1 (structurally identical to how the
// metadata IPs are blocked) must also refuse a request for "localhost" — otherwise the block is
// cosmetic. A local origin bound on 127.0.0.1 lets us prove the proxy actually DIALED the
// address it claims to block.
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

namespace {

// Minimal loopback HTTP origin on 127.0.0.1 that counts accepted connections, so a test can
// prove the proxy NEVER dialed a target it is supposed to block.
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
            ::recv(c, buf, sizeof(buf), 0);
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

int connect_proxy() {
    int s = ::socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) return -1;
    return s;
}

std::string proxy_roundtrip(int proxy_port, const std::string& request) {
    int s = connect_proxy();
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

// ===========================================================================
// 1. A block_hosts IP literal is defeated by a NAME that resolves to it.
// ===========================================================================
//
// Policy blocks the IP 127.0.0.1. A request for "localhost" (which resolves to 127.0.0.1) is
// NOT the blocked literal, so host_allowed() lets it through and the proxy dials the very
// address it was told to block. Secure behavior: the proxy must not reach a blocked address via
// a name that resolves to it (it must re-check the RESOLVED address).
TEST(ProxyAttackR2, BlockedIpLiteralBypassedByResolvingName) {
    HttpOrigin origin;
    ASSERT_TRUE(origin.start());

    NetworkPolicy p;
    p.enabled = true;
    p.default_action = "allow";
    p.block_private_metadata_endpoints = false;
    p.block_hosts = {"127.0.0.1"};  // the loopback origin's address is explicitly blocked

    ProxyServer proxy;
    std::string err;
    ASSERT_TRUE(proxy.start("127.0.0.1", 0, p, 3, err)) << err;

    std::string req = "GET http://localhost:" + std::to_string(origin.port()) +
                      "/ HTTP/1.1\r\nHost: x\r\n\r\n";
    std::string resp = proxy_roundtrip(proxy.port(), req);

    EXPECT_NE(resp.find("403 Forbidden"), std::string::npos)
        << "a name resolving to a blocked IP was not refused; resp=" << resp;
    EXPECT_EQ(origin.accepts(), 0)
        << "proxy dialed a blocked IP by resolving a name that maps to it";

    proxy.stop();
    origin.stop();
}

// ===========================================================================
// 2. The cloud-metadata block is defeated by a NAME that resolves to a metadata IP.
// ===========================================================================
//
// This exercises the ACTUAL metadata code path (block_private_metadata_endpoints + a configured
// metadata_endpoints IP). Using loopback as a stand-in metadata IP so the test is deterministic
// and needs no external DNS: metadata_endpoints={"127.0.0.1"} means the proxy must fence off
// 127.0.0.1 "for SSRF hardening", yet "localhost" (which resolves to 127.0.0.1) reaches it.
// Against a real cloud host this is exactly "http://<name-that-resolves-to-169.254.169.254>/"
// stealing instance credentials.
TEST(ProxyAttackR2, MetadataEndpointBypassedByResolvingName) {
    HttpOrigin origin;
    ASSERT_TRUE(origin.start());

    NetworkPolicy p;
    p.enabled = true;
    p.default_action = "allow";
    p.block_private_metadata_endpoints = true;
    p.metadata_endpoints = {"127.0.0.1"};  // treat loopback as a metadata endpoint to fence off

    ProxyServer proxy;
    std::string err;
    ASSERT_TRUE(proxy.start("127.0.0.1", 0, p, 3, err)) << err;

    std::string req = "GET http://localhost:" + std::to_string(origin.port()) +
                      "/ HTTP/1.1\r\nHost: x\r\n\r\n";
    std::string resp = proxy_roundtrip(proxy.port(), req);

    EXPECT_NE(resp.find("403 Forbidden"), std::string::npos)
        << "a name resolving to a metadata IP was not refused (SSRF hardening bypass); resp="
        << resp;
    EXPECT_EQ(origin.accepts(), 0)
        << "proxy dialed a metadata endpoint by resolving a name that maps to it";

    proxy.stop();
    origin.stop();
}

// ===========================================================================
// 3. CONNECT (HTTPS tunnel) to a NAME that resolves to a metadata IP is not fenced off.
// ===========================================================================
//
// Same defect via the CONNECT path: a blind TLS tunnel to "localhost" is established even though
// the address it resolves to (127.0.0.1) is a configured metadata endpoint. For a real cloud
// this tunnels straight to 169.254.169.254:443 (or the IMDS port), fully defeating the metadata
// guard for HTTPS clients.
TEST(ProxyAttackR2, MetadataEndpointConnectBypassedByResolvingName) {
    HttpOrigin origin;  // any listener on 127.0.0.1 is enough to accept the tunnel's TCP connect
    ASSERT_TRUE(origin.start());

    NetworkPolicy p;
    p.enabled = true;
    p.default_action = "allow";
    p.block_private_metadata_endpoints = true;
    p.metadata_endpoints = {"127.0.0.1"};

    ProxyServer proxy;
    std::string err;
    ASSERT_TRUE(proxy.start("127.0.0.1", 0, p, 3, err)) << err;

    int s = connect_proxy();
    ASSERT_GE(s, 0);
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = htons(static_cast<uint16_t>(proxy.port()));
    timeval tv{3, 0};
    ::setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    ASSERT_EQ(::connect(s, reinterpret_cast<sockaddr*>(&a), sizeof(a)), 0);

    std::string req = "CONNECT localhost:" + std::to_string(origin.port()) +
                      " HTTP/1.1\r\nHost: localhost\r\n\r\n";
    ::send(s, req.data(), req.size(), MSG_NOSIGNAL);

    std::string reply;
    char buf[1024];
    while (reply.find("\r\n\r\n") == std::string::npos) {
        ssize_t n = ::recv(s, buf, sizeof(buf), 0);
        if (n <= 0) break;
        reply.append(buf, static_cast<size_t>(n));
    }

    EXPECT_NE(reply.find("403 Forbidden"), std::string::npos)
        << "CONNECT to a name resolving to a metadata IP was not refused; reply=" << reply;
    EXPECT_EQ(reply.find("200 Connection Established"), std::string::npos)
        << "proxy established a blind tunnel to a metadata endpoint via its resolving name";

    ::close(s);
    proxy.stop();
    origin.stop();
}
