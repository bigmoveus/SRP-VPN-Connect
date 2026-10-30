//
//  main.m — OpenVPN engine test harness (macOS)
//
//  Drives SRPOpenVPNClient end-to-end: eval_config + connect, waits for
//  settings, then injects ICMP echo + UDP DNS + TCP SYN and checks replies.
//
//  Usage: ovpntest <profile.ovpn>
//

#import <Foundation/Foundation.h>
#import <NetworkExtension/NetworkExtension.h>
#import <arpa/inet.h>

#import "SRPOpenVPNClient.h"

static BOOL g_ready = NO;
static BOOL g_failed = NO;
static BOOL g_icmpOk = NO;
static BOOL g_tcpOk = NO;
static BOOL g_dnsOk = NO;
static NSString *g_myIp = @"10.77.0.2";

static uint16_t g_icmpId, g_dnsTx, g_tcpSport;

static uint16_t csum(const uint8_t *d, size_t n) {
    uint32_t s = 0;
    while (n > 1) { s += (d[0] << 8) | d[1]; d += 2; n -= 2; }
    if (n) s += d[0] << 8;
    while (s >> 16) s = (s & 0xFFFF) + (s >> 16);
    return (uint16_t)~s;
}

static void ipHeader(uint8_t *p, uint8_t proto, size_t total, const char *src, const char *dst) {
    memset(p, 0, 20);
    p[0] = 0x45;
    p[2] = (total >> 8) & 0xFF; p[3] = total & 0xFF;
    p[8] = 64; p[9] = proto;
    inet_pton(AF_INET, src, p + 12);
    inet_pton(AF_INET, dst, p + 16);
    uint16_t c = csum(p, 20);
    p[10] = c >> 8; p[11] = c & 0xFF;
}

static NSData *buildIcmpEcho(const char *dst) {
    uint8_t pkt[20 + 16];
    memset(pkt + 20, 0, 16);
    pkt[20] = 8;
    g_icmpId = arc4random() & 0xFFFF;
    pkt[24] = g_icmpId >> 8; pkt[25] = g_icmpId & 0xFF;
    pkt[26] = 0; pkt[27] = 1;
    uint16_t c = csum(pkt + 20, 16);
    pkt[22] = c >> 8; pkt[23] = c & 0xFF;
    ipHeader(pkt, 1, sizeof(pkt), g_myIp.UTF8String, dst);
    return [NSData dataWithBytes:pkt length:sizeof(pkt)];
}

static NSData *buildUdpDns(const char *resolver, const char *name) {
    uint8_t q[512]; size_t qn = 0;
    g_dnsTx = arc4random() & 0xFFFF;
    q[qn++] = g_dnsTx >> 8; q[qn++] = g_dnsTx & 0xFF;
    q[qn++] = 0x01; q[qn++] = 0x00;
    q[qn++] = 0; q[qn++] = 1;
    memset(q + qn, 0, 6); qn += 6;
    for (const char *lbl = name; *lbl;) {
        const char *dot = strchr(lbl, '.');
        size_t l = dot ? (size_t)(dot - lbl) : strlen(lbl);
        q[qn++] = (uint8_t)l;
        memcpy(q + qn, lbl, l); qn += l;
        lbl += l + (dot ? 1 : 0);
    }
    q[qn++] = 0;
    q[qn++] = 0; q[qn++] = 1;
    q[qn++] = 0; q[qn++] = 1;

    uint16_t sport = 40000 + (arc4random() % 10000);
    size_t udpLen = 8 + qn;
    uint8_t pkt[20 + 8 + 512];
    memset(pkt + 20, 0, 8);
    pkt[20] = sport >> 8; pkt[21] = sport & 0xFF;
    pkt[22] = 0; pkt[23] = 53;
    pkt[24] = (udpLen >> 8) & 0xFF; pkt[25] = udpLen & 0xFF;
    memcpy(pkt + 28, q, qn);
    ipHeader(pkt, 17, 20 + udpLen, g_myIp.UTF8String, resolver);
    return [NSData dataWithBytes:pkt length:20 + udpLen];
}

static NSData *buildTcpSyn(const char *dst, uint16_t dport) {
    g_tcpSport = 40000 + (arc4random() % 10000);
    uint8_t pkt[40];
    memset(pkt + 20, 0, 20);
    pkt[20] = g_tcpSport >> 8; pkt[21] = g_tcpSport & 0xFF;
    pkt[22] = dport >> 8; pkt[23] = dport & 0xFF;
    pkt[32] = 0x50;
    pkt[33] = 0x02;
    pkt[34] = 0x72; pkt[35] = 0x10;
    uint8_t ph[32];
    memset(ph, 0, 32);
    inet_pton(AF_INET, g_myIp.UTF8String, ph);
    inet_pton(AF_INET, dst, ph + 4);
    ph[9] = 6; ph[11] = 20;
    memcpy(ph + 12, pkt + 20, 20);
    uint16_t c = csum(ph, 32);
    pkt[36] = c >> 8; pkt[37] = c & 0xFF;
    ipHeader(pkt, 6, sizeof(pkt), g_myIp.UTF8String, dst);
    return [NSData dataWithBytes:pkt length:sizeof(pkt)];
}

static void handlePacket(NSData *pkt, int family) {
    if (family != AF_INET || pkt.length < 20) return;
    const uint8_t *b = (const uint8_t *)pkt.bytes;
    uint8_t proto = b[9];
    size_t ihl = (b[0] & 0x0F) * 4;
    if (proto == 1 && pkt.length >= ihl + 8) {
        if (b[ihl] == 0) {
            uint16_t rid = (b[ihl+4] << 8) | b[ihl+5];
            if (rid == g_icmpId) g_icmpOk = YES;
        }
    } else if (proto == 17 && pkt.length >= ihl + 12) {
        uint16_t tx = (b[ihl+8] << 8) | b[ihl+8+1];
        if (tx == g_dnsTx && (b[ihl+8+2] & 0x80)) {
            uint16_t answers = (b[ihl+8+6] << 8) | b[ihl+8+7];
            if (answers > 0) g_dnsOk = YES;
        }
    } else if (proto == 6 && pkt.length >= ihl + 20) {
        uint16_t dport = (b[ihl+2] << 8) | b[ihl+3];
        uint8_t flags = b[ihl+13];
        if (dport == g_tcpSport && (flags & 0x12) == 0x12) g_tcpOk = YES;
    }
}

int main(int argc, const char *argv[]) {
    @autoreleasepool {
        if (argc < 2) {
            NSLog(@"usage: ovpntest <profile.ovpn>");
            return 2;
        }
        NSString *profile = [NSString stringWithContentsOfFile:@(argv[1])
                                                      encoding:NSUTF8StringEncoding error:nil];
        if (!profile) { NSLog(@"cannot read profile"); return 2; }

        SRPOpenVPNClient *c = [SRPOpenVPNClient new];
        c.profileText = profile;
        c.logLevel = 2;
        if (argc > 2 && strcmp(argv[2], "stunnel") == 0) {
            c.stunnelEnabled = YES;
            c.stunnelHost = @"openvpn.srp.services";
            c.stunnelPort = 9443;
            c.stunnelSNI = @"openvpn.srp.services";
            c.outerCAPEM = [NSString stringWithContentsOfFile:@"/tmp/outer-ca.crt"
                                                     encoding:NSUTF8StringEncoding error:nil];
        }

        [c startWithOutputCallback:^(NSData *pkt, int family) { handlePacket(pkt, family); }
             networkSettingsCallback:^(NEPacketTunnelNetworkSettings *s) {
                 g_myIp = s.IPv4Settings.addresses.firstObject ?: g_myIp;
                 NSLog(@"[test] settings: %@ dns=%@", s.IPv4Settings.addresses, s.DNSSettings.servers);
                 g_ready = YES;
             } connectedCallback:^{
                 NSLog(@"[test] CONNECTED");
             } disconnectedCallback:^{
                 NSLog(@"[test] disconnected");
             } failureCallback:^(NSString *reason) {
                 g_failed = YES;
                 NSLog(@"[test] FAILED: %@", reason);
             }];

        NSDate *deadline = [NSDate dateWithTimeIntervalSinceNow:25];
        while (!g_ready && !g_failed && [deadline timeIntervalSinceNow] > 0)
            [[NSRunLoop currentRunLoop] runUntilDate:[NSDate dateWithTimeIntervalSinceNow:0.1]];
        if (!g_ready) { NSLog(@"=== RESULT: ready=0 (fail=%d)", g_failed); return 1; }

        [NSThread sleepForTimeInterval:0.5];
        // ping the server's tunnel address
        [c injectPacket:buildIcmpEcho("10.77.0.1") family:AF_INET];
        [NSThread sleepForTimeInterval:2.0];
        [c injectPacket:buildUdpDns("1.1.1.1", "apple.com") family:AF_INET];
        [NSThread sleepForTimeInterval:3.0];
        [c injectPacket:buildTcpSyn("1.1.1.1", 443) family:AF_INET];
        [NSThread sleepForTimeInterval:3.0];

        NSLog(@"=== RESULT: ready=1 icmp=%d dns=%d tcp=%d", g_icmpOk, g_dnsOk, g_tcpOk);
        [c closeAndWait];
        return (g_dnsOk && g_tcpOk) ? 0 : 1;
    }
}
