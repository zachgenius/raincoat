// Raincoat — proxy/policy ATTACK ROUND 1 regression tests.
//
// These encode the SECURE behavior the policy engine claims to provide and that the current
// implementation VIOLATES. They are localhost-only and deterministic (no external internet).
//
// Headline defect: host_allowed()'s metadata / SSRF hardening canonicalizes IPv4 with strict
// inet_pton (dotted-decimal only), but the resolver the proxy actually dials with
// (getaddrinfo) also accepts DECIMAL / HEX / OCTAL integer forms and IPv4-mapped IPv6 forms.
// So a metadata address written as e.g. "2852039166", "0xA9FEA9FE", "0251.0376.0251.0376" or
// "::ffff:169.254.169.254" sails past the "block cloud metadata" guarantee and the proxy will
// happily dial 169.254.169.254 — a real cloud-credential SSRF hole.
//
// proxy.hpp DOCUMENTS this as blocked: "...ANY link-local 169.254.0.0/16 literal, and the
// IPv4/IPv6 numeric form of a metadata address." Decimal/hex/octal integers and v4-mapped v6
// ARE numeric forms of a metadata address, so these tests hold the code to its own contract.
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
// Pure host_allowed() bypasses (no sockets) — the headline metadata SSRF holes
// ===========================================================================

// A metadata address written as a single 32-bit DECIMAL integer. getaddrinfo() resolves
// "2852039166" to 169.254.169.254, but the strict-dotted metadata check misses it.
TEST(ProxyAttackR1, MetadataDecimalIntegerFormBypassesBlock) {
    NetworkPolicy p;
    p.default_action = "allow";  // block_private_metadata_endpoints defaults true
    EXPECT_FALSE(host_allowed("2852039166", p)) << "decimal 169.254.169.254 not blocked";
}

// HEX integer form of the metadata address (getaddrinfo -> 169.254.169.254).
TEST(ProxyAttackR1, MetadataHexIntegerFormBypassesBlock) {
    NetworkPolicy p;
    p.default_action = "allow";
    EXPECT_FALSE(host_allowed("0xA9FEA9FE", p)) << "hex 169.254.169.254 not blocked";
}

// OCTAL dotted form of the metadata address (getaddrinfo -> 169.254.169.254).
TEST(ProxyAttackR1, MetadataOctalDottedFormBypassesBlock) {
    NetworkPolicy p;
    p.default_action = "allow";
    EXPECT_FALSE(host_allowed("0251.0376.0251.0376", p)) << "octal 169.254.169.254 not blocked";
}

// IPv4-MAPPED IPv6 form of the metadata address. getaddrinfo resolves it to a v4-mapped
// sockaddr that connects to 169.254.169.254, yet the /16 link-local check only fires for a
// pure-v4 literal, so the mapped form escapes.
TEST(ProxyAttackR1, MetadataV4MappedIPv6FormBypassesBlock) {
    NetworkPolicy p;
    p.default_action = "allow";
    EXPECT_FALSE(host_allowed("::ffff:169.254.169.254", p)) << "v4-mapped metadata not blocked";
    EXPECT_FALSE(host_allowed("[::ffff:169.254.169.254]", p)) << "bracketed v4-mapped not blocked";
    EXPECT_FALSE(host_allowed("::ffff:a9fe:a9fe", p)) << "hex v4-mapped metadata not blocked";
}

// The whole 169.254.0.0/16 link-local range is supposed to be blocked "in ANY IPv4 literal
// form"; the integer forms of an in-range address are not.
TEST(ProxyAttackR1, LinkLocalRangeIntegerFormBypassesBlock) {
    NetworkPolicy p;
    p.default_action = "allow";
    // 169.254.0.1 == 2852034561 decimal.
    EXPECT_FALSE(host_allowed("2852034561", p)) << "decimal 169.254.0.1 not blocked";
}

// ===========================================================================
// Live proxy: a block_hosts entry defeated by an obfuscated numeric encoding of the SAME IP
// ===========================================================================
//
// This demonstrates the exploit MECHANISM end-to-end on loopback: the policy lists the literal
// "127.0.0.1" (and "localhost") as blocked, but a request to the DECIMAL form "2130706433"
// (== 127.0.0.1) is not canonicalized by the policy, so the proxy resolves it and DIALS the
// otherwise-blocked origin. Same non-canonicalization that lets the metadata IP through.

namespace {

// Minimal loopback HTTP origin that counts accepted connections.
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

TEST(ProxyAttackR1, BlockedIpReachedViaDecimalIntegerForm) {
    HttpOrigin origin;
    ASSERT_TRUE(origin.start());

    NetworkPolicy p;
    p.enabled = true;
    p.default_action = "allow";
    p.block_hosts = {"127.0.0.1", "localhost"};  // the loopback origin is explicitly blocked

    ProxyServer proxy;
    std::string err;
    ASSERT_TRUE(proxy.start("127.0.0.1", 0, p, 3, err)) << err;

    // 2130706433 == 127.0.0.1. The policy blocks the literal but not this integer encoding.
    std::string req = "GET http://2130706433:" + std::to_string(origin.port()) +
                      "/ HTTP/1.1\r\nHost: x\r\n\r\n";
    std::string resp = proxy_roundtrip(proxy.port(), req);

    // Secure behavior: the proxy must NOT dial a blocked host reached by an obfuscated IP form.
    EXPECT_NE(resp.find("403 Forbidden"), std::string::npos)
        << "decimal-IP form of a blocked host was not rejected; resp=" << resp;
    EXPECT_EQ(origin.accepts(), 0)
        << "proxy dialed the blocked origin via its decimal-integer address";

    proxy.stop();
    origin.stop();
}
