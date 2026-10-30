//
//  main.m — SSH VPN engine test harness (macOS)
//
//  Drives SRPSSHClient end-to-end: SSH connect, packet engine, then injects
//  raw IP packets (ICMP echo, TCP SYN, UDP DNS) and checks the replies.
//
//  Usage: sshtest <user> <pass> <host> [port] [relayUser] [relayPass]
//

#import <Foundation/Foundation.h>
#import <NetworkExtension/NetworkExtension.h>
#import <arpa/inet.h>

#import "SRPSSHClient.h"

// engine stats (prefixed symbols in libSRPSSHEngine.a)
extern void srpssh_hev_socks5_tunnel_stats(size_t *tx_packets, size_t *tx_bytes,
                                           size_t *rx_packets, size_t *rx_bytes);

static BOOL g_ready = NO;
static BOOL g_failed = NO;
static BOOL g_icmpOk = NO;
static BOOL g_tcpOk = NO;
static BOOL g_dnsOk = NO;
static BOOL g_mappedOk = NO;
static uint8_t g_mappedIp[4];
static BOOL g_haveMappedIp = NO;

static uint16_t g_icmpId, g_icmpSeq;
static uint16_t g_dnsTx;
static uint16_t g_tcpSport;

#pragma mark - checksum helpers

static uint16_t csum(const uint8_t *d, size_t n) {
    uint32_t s = 0;
    while (n > 1) { s += (d[0] << 8) | d[1]; d += 2; n -= 2; }
    if (n) s += d[0] << 8;
    while (s >> 16) s = (s & 0xFFFF) + (s >> 16);
    return (uint16_t)~s;
}

#pragma mark - packet builders (source 198.18.0.1)

static void ipHeader(uint8_t *p, uint8_t proto, size_t total, const char *dst) {
    memset(p, 0, 20);
    p[0] = 0x45;
    p[2] = (total >> 8) & 0xFF; p[3] = total & 0xFF;
    p[8] = 64; p[9] = proto;
    inet_pton(AF_INET, "198.18.0.1", p + 12);
    inet_pton(AF_INET, dst, p + 16);
    uint16_t c = csum(p, 20);
    p[10] = c >> 8; p[11] = c & 0xFF;
}

static NSData *buildIcmpEcho(const char *dst) {
    uint8_t pkt[20 + 16];
    memset(pkt + 20, 0, 16);
    pkt[20] = 8; // echo request
    g_icmpId = arc4random() & 0xFFFF; g_icmpSeq = 1;
    pkt[24] = g_icmpId >> 8; pkt[25] = g_icmpId & 0xFF;
    pkt[26] = 0; pkt[27] = 1;
    uint16_t c = csum(pkt + 20, 16);
    pkt[22] = c >> 8; pkt[23] = c & 0xFF;
    ipHeader(pkt, 1, sizeof(pkt), dst);
    return [NSData dataWithBytes:pkt length:sizeof(pkt)];
}

static NSData *buildUdpDns(const char *resolver, const char *name) {
    // DNS query
    uint8_t q[512]; size_t qn = 0;
    g_dnsTx = arc4random() & 0xFFFF;
    q[qn++] = g_dnsTx >> 8; q[qn++] = g_dnsTx & 0xFF;
    q[qn++] = 0x01; q[qn++] = 0x00; // RD
    q[qn++] = 0; q[qn++] = 1;       // QDCOUNT
    memset(q + qn, 0, 6); qn += 6;  // AN/NS/AR counts
    for (const char *lbl = name; *lbl;) {
        const char *dot = strchr(lbl, '.');
        size_t l = dot ? (size_t)(dot - lbl) : strlen(lbl);
        q[qn++] = (uint8_t)l;
        memcpy(q + qn, lbl, l); qn += l;
        lbl += l + (dot ? 1 : 0);
    }
    q[qn++] = 0;
    q[qn++] = 0; q[qn++] = 1;  // A
    q[qn++] = 0; q[qn++] = 1;  // IN

    // UDP header
    uint16_t sport = 40000 + (arc4random() % 10000);
    size_t udpLen = 8 + qn;
    uint8_t pkt[20 + 8 + 512];
    memset(pkt + 20, 0, 8);
    pkt[20] = sport >> 8; pkt[21] = sport & 0xFF;
    pkt[22] = 0; pkt[23] = 53;
    pkt[24] = (udpLen >> 8) & 0xFF; pkt[25] = udpLen & 0xFF;
    memcpy(pkt + 28, q, qn);
    ipHeader(pkt, 17, 20 + udpLen, resolver);
    return [NSData dataWithBytes:pkt length:20 + udpLen];
}

static NSData *buildTcpSyn(const char *dst, uint16_t dport) {
    g_tcpSport = 40000 + (arc4random() % 10000);
    uint8_t pkt[20 + 20];
    memset(pkt + 20, 0, 20);
    pkt[20] = g_tcpSport >> 8; pkt[21] = g_tcpSport & 0xFF;
    pkt[22] = dport >> 8; pkt[23] = dport & 0xFF;
    pkt[32] = 0x50;                    // data offset: 5 x 32-bit words
    pkt[33] = 0x02;                    // SYN
    pkt[34] = 0x72; pkt[35] = 0x10;    // window
    // pseudo-header checksum
    uint8_t ph[12 + 20];
    memset(ph, 0, sizeof(ph));
    inet_pton(AF_INET, "198.18.0.1", ph);
    inet_pton(AF_INET, dst, ph + 4);
    ph[9] = 6;
    ph[11] = 20;
    memcpy(ph + 12, pkt + 20, 20);
    uint16_t c = csum(ph, sizeof(ph));
    pkt[36] = c >> 8; pkt[37] = c & 0xFF;
    ipHeader(pkt, 6, sizeof(pkt), dst);
    return [NSData dataWithBytes:pkt length:sizeof(pkt)];
}

#pragma mark - reply inspection

static void handlePacket(NSData *pkt, int family) {
    if (family != AF_INET || pkt.length < 20) return;
    const uint8_t *b = pkt.bytes;
    uint8_t proto = b[9];
    size_t ihl = (b[0] & 0x0F) * 4;
    if (proto == 1 && pkt.length >= ihl + 8) {
        if (b[ihl] == 0) {  // echo reply
            uint16_t rid = (b[ihl+4] << 8) | b[ihl+5];
            if (rid == g_icmpId) g_icmpOk = YES;
        }
    } else if (proto == 17 && pkt.length >= ihl + 12) {
        const uint8_t *u = b + ihl;
        NSLog(@"[test] udp reply from %d.%d.%d.%d:%d len=%lu first bytes: %02x %02x %02x %02x",
              b[12], b[13], b[14], b[15], (u[0] << 8) | u[1], (unsigned long)pkt.length,
              u[8], u[9], u[10], u[11]);
        uint16_t tx = (b[ihl+8] << 8) | b[ihl+8+1];
        if (tx == g_dnsTx && (b[ihl+8+2] & 0x80)) {
            uint16_t answers = (b[ihl+8+6] << 8) | b[ihl+8+7];
            if (answers > 0) g_dnsOk = YES;
        }
        // mapped-DNS reply comes FROM 198.18.0.2 — grab any 198.18.x.x answer
        if (b[12] == 198 && b[13] == 18 && b[14] == 0 && b[15] == 2) {
            const uint8_t *dns = b + ihl + 8;
            size_t dlen = pkt.length - ihl - 8;
            for (size_t i = 12; i + 4 <= dlen; i++) {
                if (dns[i] == 198 && dns[i+1] == 18) {
                    memcpy(g_mappedIp, dns + i, 4);
                    g_haveMappedIp = YES;
                    break;
                }
            }
        }
    } else if (proto == 6 && pkt.length >= ihl + 20) {
        uint16_t dport = (b[ihl+2] << 8) | b[ihl+3];
        uint8_t flags = b[ihl+13];
        if (dport == g_tcpSport && (flags & 0x12) == 0x12) g_tcpOk = YES;  // SYN-ACK
        if (dport == g_tcpSport && (flags & 0x12) == 0x12 &&
            b[12] == 198 && b[13] == 18) g_mappedOk = YES;  // SYN-ACK via mapped IP
    }
}

int main(int argc, const char *argv[]) {
    @autoreleasepool {
        if (argc < 4) {
            NSLog(@"usage: sshtest <user> <pass> <host> [port] [relayUser] [relayPass]");
            return 2;
        }
        NSString *user = @(argv[1]), *pass = @(argv[2]), *host = @(argv[3]);
        int port = argc > 4 ? atoi(argv[4]) : 22;
        BOOL udp = (argc > 5 && strcmp(argv[5], "udp") == 0) || argc > 6;

        SRPSSHClient *c = [SRPSSHClient new];
        c.host = host; c.port = port; c.username = user; c.password = pass;
        c.logLevel = 2;
        if (udp && argc > 6) {
            c.udpEnabled = YES;
            c.relayUsername = @(argv[5]);
            c.relayPassword = @(argv[6]);
        } else if (udp) {
            c.udpEnabled = YES;
        }

        [c startWithOutputCallback:^(NSData *pkt, int family) { handlePacket(pkt, family); }
             networkSettingsCallback:^(NEPacketTunnelNetworkSettings *s) {
                 NSLog(@"[test] settings: %@ dns=%@", s.IPv4Settings.addresses, s.DNSSettings.servers);
             } connectedCallback:^{
                 g_ready = YES;
                 NSLog(@"[test] READY");
             } disconnectedCallback:^{
                 NSLog(@"[test] disconnected");
             } failureCallback:^(NSString *reason) {
                 g_failed = YES;
                 NSLog(@"[test] FAILED: %@", reason);
             }];

        NSDate *deadline = [NSDate dateWithTimeIntervalSinceNow:15];
        while (!g_ready && !g_failed && [deadline timeIntervalSinceNow] > 0)
            [[NSRunLoop currentRunLoop] runUntilDate:[NSDate dateWithTimeIntervalSinceNow:0.1]];
        if (!g_ready) { NSLog(@"=== RESULT: ready=0 (fail=%d)", g_failed); return 1; }

        // ICMP echo to the tunnel gateway — the engine answers locally when
        // icmp: reply is configured (tests the packet path only).
        [c injectPacket:buildIcmpEcho("198.18.0.1") family:AF_INET];
        [NSThread sleepForTimeInterval:1.0];

        // TCP SYN to 1.1.1.1:443 — exercises SSH direct-tcpip end to end.
        [c injectPacket:buildTcpSyn("1.1.1.1", 443) family:AF_INET];
        // burst of concurrent flows (the phone opens dozens at connect)
        for (int i = 0; i < 20; i++) {
            [c injectPacket:buildTcpSyn("1.1.1.1", 443) family:AF_INET];
        }
        [NSThread sleepForTimeInterval:3.0];

        // UDP DNS via the HEV relay — several flows from different source
        // ports at once (the phone does this; exercises concurrent channels).
        if (udp) {
            [c injectPacket:buildUdpDns("1.1.1.1", "apple.com") family:AF_INET];
            [c injectPacket:buildUdpDns("1.1.1.1", "example.org") family:AF_INET];
            [c injectPacket:buildUdpDns("8.8.8.8", "cloudflare.com") family:AF_INET];
            [NSThread sleepForTimeInterval:4.0];
        }

        // Mapped DNS (works without the relay): query the engine's local
        // resolver, then connect to the fake IP — the channel carries the
        // real hostname and the SSH server resolves it.
        [c injectPacket:buildUdpDns("198.18.0.2", "apple.com") family:AF_INET];
        [NSThread sleepForTimeInterval:2.0];
        if (g_haveMappedIp) {
            char fake[16];
            snprintf(fake, sizeof(fake), "%d.%d.%d.%d",
                     g_mappedIp[0], g_mappedIp[1], g_mappedIp[2], g_mappedIp[3]);
            NSLog(@"[test] mapped DNS answered %s — connecting", fake);
            [c injectPacket:buildTcpSyn(fake, 443) family:AF_INET];
            [NSThread sleepForTimeInterval:3.0];
        }

        size_t txp = 0, txb = 0, rxp = 0, rxb = 0;
        srpssh_hev_socks5_tunnel_stats(&txp, &txb, &rxp, &rxb);
        NSLog(@"=== RESULT: ready=1 icmp=%d tcp=%d dns=%d mapped=%d | engine tx=%zu rx=%zu", g_icmpOk, g_tcpOk, g_dnsOk, g_mappedOk, txp, rxp);
        [c close];
        [NSThread sleepForTimeInterval:0.5];
        return (g_tcpOk && (!udp || g_dnsOk)) ? 0 : 1;
    }
}
