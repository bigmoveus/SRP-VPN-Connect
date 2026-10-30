// SETest main.m — macOS E2E harness for the SoftEther client core.
// Connects to softether.srp.services:443 (hub DEFAULT), waits for DHCP,
// pings the gateway, and optionally does a UDP DNS query through the tunnel.
#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <arpa/inet.h>

#include "SRPSEClient.h"

static SRPSEClient *g_client;
static dispatch_queue_t g_q;
static bool g_connected, g_dhcp, g_pingOk, g_dnsOk, g_failed, g_v6, g_ping6Ok;
static uint32_t g_err;
static uint32_t g_gwIp;            // host order
static uint32_t g_myIp;
static uint8_t g_myIp6[16];
static uint8_t g_gwIp6[16];
static NSString *g_mode;

// ---- trust hook (same SecTrust code as the iOS extension will use) ----
static uint32_t trustHook(void *ctx, const uint8_t *const *chainDer,
                          const size_t *chainLen, int chainCount, const char *hostname)
{
    NSMutableArray *certs = [NSMutableArray array];
    for (int i = 0; i < chainCount; i++) {
        NSData *d = [NSData dataWithBytes:chainDer[i] length:chainLen[i]];
        SecCertificateRef cert = SecCertificateCreateWithData(NULL, (__bridge CFDataRef)d);
        if (cert) [certs addObject:(__bridge id)cert];
    }
    if (certs.count == 0) return 85; // ERR_CERT_NOT_TRUSTED

    SecPolicyRef policy = SecPolicyCreateSSL(true, (__bridge CFStringRef)@(hostname));
    SecTrustRef trust = NULL;
    if (SecTrustCreateWithCertificates((__bridge CFArrayRef)certs, policy, &trust) != errSecSuccess)
        return 85;

    CFErrorRef err = NULL;
    bool ok = SecTrustEvaluateWithError(trust, &err);
    if (!ok && err) {
        NSLog(@"[trust] FAILED: %@", (__bridge NSError *)err);
    } else {
        NSLog(@"[trust] OK for %s (%d certs)", hostname, chainCount);
    }
    if (trust) CFRelease(trust);
    return ok ? 0 : 85;
}

// ---- checksum helpers ----
static uint16_t cksum(const void *data, uint32_t len) {
    const uint16_t *p = data; uint32_t s = 0;
    while (len > 1) { s += ntohs(*p++); len -= 2; }
    if (len) s += *(const uint8_t *)p << 8;
    while (s >> 16) s = (s & 0xFFFF) + (s >> 16);
    return htons((uint16_t)~s);
}

static void sendPing(uint32_t dstIp) {
    NSLog(@"[dbg] sendPing called gw=%08X myip=%08X client=%p", dstIp, g_myIp, g_client);
    uint8_t pkt[20 + 16];
    memset(pkt, 0, sizeof(pkt));
    pkt[0] = 0x45; *(uint16_t *)(pkt + 2) = htons(sizeof(pkt));
    *(uint16_t *)(pkt + 4) = htons(0x1234);
    pkt[8] = 64; pkt[9] = 1;
    *(uint32_t *)(pkt + 12) = htonl(g_myIp);
    *(uint32_t *)(pkt + 16) = htonl(dstIp);
    *(uint16_t *)(pkt + 10) = 0;
    *(uint16_t *)(pkt + 10) = cksum(pkt, 20);
    uint8_t *icmp = pkt + 20;
    icmp[0] = 8; icmp[1] = 0;
    *(uint16_t *)(icmp + 4) = htons(0xBEEF);
    *(uint16_t *)(icmp + 6) = htons(1);
    memset(icmp + 8, 0xAA, 8);
    *(uint16_t *)(icmp + 2) = 0;
    *(uint16_t *)(icmp + 2) = cksum(icmp, 16);
    SRPSEClientInjectPacket(g_client, pkt, sizeof(pkt), 4);
}

static void sendDnsQuery(uint32_t dnsIp) {
    NSLog(@"[dbg] sendDnsQuery called dns=%08X", dnsIp);
    // minimal DNS A query for apple.com
    static const uint8_t qname[] = {5,'a','p','p','l','e',3,'c','o','m',0};
    uint8_t pkt[20 + 8 + 12 + sizeof(qname) + 4];
    memset(pkt, 0, sizeof(pkt));
    uint32_t dnsLen = 12 + sizeof(qname) + 4;
    uint32_t udpLen = 8 + dnsLen;
    uint32_t ipLen = 20 + udpLen;
    pkt[0] = 0x45; *(uint16_t *)(pkt + 2) = htons(ipLen);
    pkt[8] = 64; pkt[9] = 17;
    *(uint32_t *)(pkt + 12) = htonl(g_myIp);
    *(uint32_t *)(pkt + 16) = htonl(dnsIp);
    *(uint16_t *)(pkt + 10) = cksum(pkt, 20);
    uint8_t *udp = pkt + 20;
    *(uint16_t *)(udp + 0) = htons(53222);
    *(uint16_t *)(udp + 2) = htons(53);
    *(uint16_t *)(udp + 4) = htons(udpLen);
    *(uint16_t *)(udp + 6) = 0;
    // UDP checksum with pseudo-header
    {
        uint8_t ph[12];
        memcpy(ph, pkt + 12, 8);              // src, dst
        ph[8] = 0; ph[9] = 17;
        *(uint16_t *)(ph + 10) = htons(udpLen);
        uint32_t s = 0;
        const uint16_t *w = (const uint16_t *)ph;
        for (int i = 0; i < 6; i++) s += ntohs(w[i]);
        const uint16_t *u = (const uint16_t *)udp;
        for (uint32_t i = 0; i + 2 <= udpLen; i += 2) s += ntohs(u[i/2]);
        while (s >> 16) s = (s & 0xFFFF) + (s >> 16);
        uint16_t c = (uint16_t)~s;
        if (c == 0) c = 0xFFFF;
        *(uint16_t *)(udp + 6) = htons(c);
    }
    uint8_t *dns = udp + 8;
    *(uint16_t *)(dns + 0) = htons(0xCAFE);
    *(uint16_t *)(dns + 2) = htons(0x0100);   // RD
    *(uint16_t *)(dns + 4) = htons(1);        // QDCOUNT
    memcpy(dns + 12, qname, sizeof(qname));
    *(uint16_t *)(dns + 12 + sizeof(qname)) = htons(1);      // A
    *(uint16_t *)(dns + 14 + sizeof(qname)) = htons(1);      // IN
    SRPSEClientInjectPacket(g_client, pkt, ipLen, 4);
}

static void parseIp6(const char *s, uint8_t *out) {
    struct in6_addr a;
    if (inet_pton(AF_INET6, s, &a) == 1) memcpy(out, &a, 16);
}

static void sendPing6(const uint8_t *dstIp6) {
    uint8_t pkt[40 + 16];
    memset(pkt, 0, sizeof(pkt));
    pkt[0] = 0x60;
    *(uint16_t *)(pkt + 4) = htons(16);   // payload len
    pkt[6] = 58;                          // ICMPv6
    pkt[7] = 64;
    memcpy(pkt + 8, g_myIp6, 16);
    memcpy(pkt + 24, dstIp6, 16);
    uint8_t *icmp = pkt + 40;
    icmp[0] = 128; icmp[1] = 0;           // echo request
    *(uint16_t *)(icmp + 4) = htons(0xBEEF);
    *(uint16_t *)(icmp + 6) = htons(1);
    memset(icmp + 8, 0x66, 8);
    // checksum: pseudo-header + payload
    uint32_t s = 0;
    for (int i = 8; i < 40; i += 2) s += (pkt[i] << 8) | pkt[i+1];
    s += 16 + 58;
    for (int i = 0; i < 16; i += 2) s += (icmp[i] << 8) | icmp[i+1];
    while (s >> 16) s = (s & 0xFFFF) + (s >> 16);
    *(uint16_t *)(icmp + 2) = htons((uint16_t)~s ?: 0xFFFF);
    SRPSEClientInjectPacket(g_client, pkt, sizeof(pkt), 6);
}

// ---- client callbacks ----
static void onIPv4(void *ctx, const uint8_t *pkt, uint32_t len, int family) {
    if (family == 6) {
        if (len >= 40 + 4 && pkt[6] == 58) {
            const uint8_t *icmp = pkt + 40;
            if (icmp[0] == 129 && ntohs(*(uint16_t *)(icmp + 4)) == 0xBEEF) {
                NSLog(@"[data] ICMPv6 echo reply received — IPv6 connectivity OK");
                g_ping6Ok = true;
            }
        }
        return;
    }
    if (len < 20) return;
    uint8_t proto = pkt[9];
    if (proto == 1 && len >= 28) {
        const uint8_t *icmp = pkt + (pkt[0] & 0x0F) * 4;
        if (icmp[0] == 0 && ntohs(*(uint16_t *)(icmp + 4)) == 0xBEEF) {
            NSLog(@"[data] ICMP echo reply received — L3 connectivity OK");
            g_pingOk = true;
        }
    }
    if (proto == 17 && len >= 28 + 8 + 12) {
        uint32_t ihl = (pkt[0] & 0x0F) * 4;
        const uint8_t *udp = pkt + ihl;
        if (ntohs(*(uint16_t *)(udp + 0)) == 53) {
            const uint8_t *dns = udp + 8;
            if (ntohs(*(uint16_t *)(dns + 0)) == 0xCAFE && (dns[3] & 0x80)) {
                uint16_t ancount = ntohs(*(uint16_t *)(dns + 6));
                NSLog(@"[data] DNS reply received (answers=%u) — UDP through tunnel OK", ancount);
                if (ancount > 0) g_dnsOk = true;
            }
        }
    }
}

static void onConfig(void *ctx, const char *ip, const char *mask, const char *gw,
                     const char *dnsCsv, uint32_t leaseSec) {
    NSLog(@"[dhcp] ip=%s mask=%s gw=%s dns=%s lease=%u", ip, mask, gw, dnsCsv, leaseSec);
    unsigned a,b,c,d;
    if (sscanf(gw, "%u.%u.%u.%u", &a,&b,&c,&d) == 4)
        g_gwIp = (a<<24)|(b<<16)|(c<<8)|d;
    if (sscanf(ip, "%u.%u.%u.%u", &a,&b,&c,&d) == 4)
        g_myIp = (a<<24)|(b<<16)|(c<<8)|d;
    g_dhcp = true;
}

static void onConfig6(void *ctx, const char *addr6, int prefixLen,
                      const char *gw6, const char *dns6Csv, uint32_t lifetimeSec) {
    NSLog(@"[slaac] addr=%s/%d gw=%s dns=%s lifetime=%u", addr6, prefixLen, gw6, dns6Csv, lifetimeSec);
    parseIp6(addr6, g_myIp6);
    parseIp6(gw6, g_gwIp6);
    g_v6 = true;
}

static void onState(void *ctx, int clientStatus, uint32_t err) {
    NSLog(@"[state] status=%d err=%u (%s)", clientStatus, err, SRPSEErrorName(err));
    if (clientStatus == 3) g_connected = true;
    if (clientStatus == 5 && !g_connected) { g_failed = true; g_err = err; }
    if (clientStatus == 5 && g_connected) { /* disconnected after connect */ }
}

static void onLog(void *ctx, const char *line) {
    NSLog(@"[adapter] %s", line);
}

int main(int argc, const char *argv[]) {
    @autoreleasepool {
        NSString *dir = @"/tmp/seharness";
        [[NSFileManager defaultManager] createDirectoryAtPath:dir withIntermediateDirectories:YES attributes:nil error:nil];

        const char *user = "sstp-test1";
        const char *pass = "srp-test-password";
        const char *p12Path = NULL;
        bool tlsVerify = true;
        if (argc > 1) g_mode = @(argv[1]);
        if (argc > 2) user = argv[2];
        if (argc > 3) pass = argv[3];
        if (argc > 4) p12Path = argv[4];
        if (g_mode == nil) g_mode = @"password";

        SRPSEGlobalInit(dir.UTF8String, true);
        SRPSESetTrustHook(NULL, tlsVerify ? trustHook : NULL);

        SRPSEClientConfig cfg;
        memset(&cfg, 0, sizeof(cfg));
        if (getenv("SE_HUB")) snprintf(cfg.hub, sizeof(cfg.hub), "%s", getenv("SE_HUB"));
        if (getenv("SE_PROXY_TYPE")) {
            cfg.proxyType = [@"socks5" isEqualToString:@(getenv("SE_PROXY_TYPE"))] ? SRPSEProxySOCKS5 : SRPSEProxyHTTP;
            snprintf(cfg.proxyHost, sizeof(cfg.proxyHost), "%s", getenv("SE_PROXY_HOST") ?: "");
            cfg.proxyPort = (uint16_t)atoi(getenv("SE_PROXY_PORT") ?: "0");
            if (getenv("SE_PROXY_USER")) {
                snprintf(cfg.proxyUsername, sizeof(cfg.proxyUsername), "%s", getenv("SE_PROXY_USER"));
                snprintf(cfg.proxyPassword, sizeof(cfg.proxyPassword), "%s", getenv("SE_PROXY_PASS") ?: "");
            }
        }
        snprintf(cfg.hostname, sizeof(cfg.hostname), "%s", (argc > 7 && strlen(argv[7]) > 0) ? argv[7] : "softether.srp.services");
        cfg.port = 443;
        snprintf(cfg.hub, sizeof(cfg.hub), "%s", getenv("SE_HUB") ? getenv("SE_HUB") : "DEFAULT");
        snprintf(cfg.username, sizeof(cfg.username), "%s", user);
        cfg.tlsVerify = tlsVerify;
        cfg.maxConnections = (argc > 5) ? atoi(argv[5]) : 1;
        cfg.useCompress = true;
        cfg.retryIntervalSec = 5;
        if (getenv("SE_FRAG")) {
            cfg.tlsFragFirst = 43;
            cfg.tlsFragFollowing = 256;
            cfg.tlsFragGapMs = 3;
            NSLog(@"SE_FRAG on: first=43 following=256 gap=3");
        }
        if (argc > 6 && strlen(argv[6]) > 0) {
            snprintf(cfg.sniOverride, sizeof(cfg.sniOverride), "%s", argv[6]);
        }

        NSData *p12Data = nil;
        if ([g_mode isEqualToString:@"password"]) {
            cfg.authType = SRPSEAuthPassword;
            snprintf(cfg.password, sizeof(cfg.password), "%s", pass);
        } else if ([g_mode isEqualToString:@"plain"]) {
            cfg.authType = SRPSEAuthPlainPassword;
            snprintf(cfg.password, sizeof(cfg.password), "%s", pass);
        } else if ([g_mode isEqualToString:@"anonymous"]) {
            cfg.authType = SRPSEAuthAnonymous;
        } else if ([g_mode isEqualToString:@"cert"]) {
            cfg.authType = SRPSEAuthCertificate;
            p12Data = [NSData dataWithContentsOfFile:@(p12Path ? p12Path : "")];
            if (!p12Data) { NSLog(@"no p12 file"); return 2; }
            cfg.p12 = p12Data.bytes;
            cfg.p12Len = p12Data.length;
            NSString *pwFile = [[NSString stringWithUTF8String:p12Path] stringByAppendingString:@".password.txt"];
            NSString *pw = [NSString stringWithContentsOfFile:pwFile encoding:NSUTF8StringEncoding error:nil];
            pw = [pw stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
            snprintf(cfg.p12Passphrase, sizeof(cfg.p12Passphrase), "%s", pw ? pw.UTF8String : "");
        } else if ([g_mode isEqualToString:@"noverify"]) {
            cfg.authType = SRPSEAuthPassword;
            snprintf(cfg.password, sizeof(cfg.password), "%s", pass);
            cfg.tlsVerify = false;
            SRPSESetTrustHook(NULL, NULL);
        }

        g_client = SRPSEClientCreate(&cfg, NULL, onIPv4, onConfig, onConfig6, onState, onLog);
        if (!g_client) { NSLog(@"create failed"); return 2; }
        int r = SRPSEClientStart(g_client);
        if (r != 0) { NSLog(@"start failed: %d", r); return 2; }

        // poll + timed actions
        NSDate *start = [NSDate date];
        bool pingSent = false, dnsSent = false;
        NSTimeInterval lastSend = 0, lastSend6 = 0;
        while ([[NSDate date] timeIntervalSinceDate:start] < 60) {
            if (g_failed) break;
            if (g_dhcp && !(g_pingOk && g_dnsOk)) {
                NSTimeInterval el = [[NSDate date] timeIntervalSinceDate:start];
                if (!pingSent || el - lastSend >= 2.0) {
                    lastSend = el;
                    pingSent = true; dnsSent = true;
                    sendPing(g_gwIp);
                    sendDnsQuery(0x01010101);   // 1.1.1.1
                }
            }
            if (g_v6 && !g_ping6Ok) {
                NSTimeInterval el = [[NSDate date] timeIntervalSinceDate:start];
                if (el - lastSend6 >= 2.0) {
                    lastSend6 = el;
                    uint8_t dns66[16];
                    parseIp6("fd66::1", dns66);
                    sendPing6(dns66);
                }
            }
            if (g_pingOk && g_dnsOk && (!g_v6 || g_ping6Ok)) {
                // IPv4 done; give IPv6 RA/SLAAC up to 25s total before concluding
                if ([[NSDate date] timeIntervalSinceDate:start] > 25 || g_ping6Ok) break;
            }
            if (g_dnsOk && !g_pingOk && [[NSDate date] timeIntervalSinceDate:start] > 15) break;
            [NSThread sleepForTimeInterval:0.2];
            int st; uint32_t err;
            SRPSEClientGetStatus(g_client, &st, &err);
            static int lastSt = -2;
            if (st != lastSt) { lastSt = st; }
        }

        NSLog(@"=== RESULT: connected=%d dhcp=%d ping=%d dns=%d v6=%d ping6=%d failed=%d err=%u(%s)",
              g_connected, g_dhcp, g_pingOk, g_dnsOk, g_v6, g_ping6Ok, g_failed, g_err, SRPSEErrorName(g_err));

        SRPSEClientFree(g_client);
        BOOL ok4 = g_connected && g_dhcp && (g_pingOk || g_dnsOk);
        BOOL ok6 = !g_v6 || g_ping6Ok;   // v6 optional, but if configured it must work
        return (ok4 && ok6) ? 0 : 1;
    }
}
