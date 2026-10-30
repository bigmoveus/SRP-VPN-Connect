// OCTest main.m — macOS E2E harness for libopenconnect (AnyConnect/ocserv).
// Connects to openconnect.srp.services, applies IP settings, and verifies
// data plane via DNS query through the tunnel (+ ICMP ping).
#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <arpa/inet.h>

#include <sys/socket.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

#include "openconnect.h"

static struct openconnect_info *g_vpn;
static int g_tunFd = -1;          // our end of the packet channel
static int g_cmdFd = -1;          // write side of the command pipe
@interface OCHarness : NSObject
+ (BOOL)validateServerCert:(struct openconnect_info *)vpn reason:(NSString *)reason;
@end
static bool g_established, g_pingOk, g_dnsOk, g_failed;
static NSString *g_mode, *g_user, *g_pass;
static char g_myIp[64];
static char g_verifyHost[256];

static uint16_t cksum(const void *data, uint32_t len) {
    const uint16_t *p = data; uint32_t s = 0;
    while (len > 1) { s += ntohs(*p++); len -= 2; }
    if (len) s += *(const uint8_t *)p << 8;
    while (s >> 16) s = (s & 0xFFFF) + (s >> 16);
    return htons((uint16_t)~s);
}

// ---- callbacks ----
static void onProgress(void *privdata, int level, const char *fmt, ...) {
    char buf[1024];
    va_list ap; va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    NSLog(@"[oc] %s", buf);
}

static int onValidatePeerCert(void *privdata, const char *reason) {
    // 0 = accept, non-zero = abort
    if (getenv("OC_NOVERIFY")) { NSLog(@"[trust] disabled (OC_NOVERIFY): %s", reason); return 0; }
    return [OCHarness validateServerCert:g_vpn reason:@(reason ?: "")] ? 0 : 1;
}

static int onWriteNewConfig(void *privdata, const char *buf, int buflen) {
    return 0;   // no config persistence
}

static int g_authAttempts;
static int onAuthForm(void *privdata, struct oc_auth_form *form) {
    NSLog(@"[oc] auth form: method=%s action=%s error=%s", form->method, form->action,
          form->error ? form->error : "(none)");
    if (form->error != NULL) {
        // Server rejected our credentials — surface it, don't resubmit
        NSLog(@"[oc] AUTH FAILED: %s", form->error);
        g_failed = true;
        return 1;
    }
    if (++g_authAttempts > 2) {
        NSLog(@"[oc] AUTH FAILED: too many form rounds");
        g_failed = true;
        return 1;
    }
    struct oc_form_opt *opt = form->opts;
    while (opt) {
        NSLog(@"[oc]   opt: type=%d name=%s label=%s", opt->type,
              opt->name ? opt->name : "(null)", opt->label ? opt->label : "(null)");
        if (opt->type == OC_FORM_OPT_TEXT && opt->name &&
            (strcmp(opt->name, "username") == 0 || strcmp(opt->name, "user") == 0)) {
            openconnect_set_option_value(opt, g_user.UTF8String);
        }
        else if (opt->type == OC_FORM_OPT_PASSWORD) {
            openconnect_set_option_value(opt, g_pass.UTF8String);
        }
        else if (opt->type == OC_FORM_OPT_TEXT && opt->label && [g_user length] &&
                 strcasestr(opt->label, "user")) {
            openconnect_set_option_value(opt, g_user.UTF8String);
        }
        opt = opt->next;
    }
    return 0;
}

// ---- packets ----
static void injectPing(void) {
    uint8_t pkt[20 + 16];
    memset(pkt, 0, sizeof(pkt));
    pkt[0] = 0x45; *(uint16_t *)(pkt + 2) = htons(sizeof(pkt));
    *(uint16_t *)(pkt + 4) = htons(0x1234);
    pkt[8] = 64; pkt[9] = 1;
    inet_pton(AF_INET, g_myIp, pkt + 12);
    inet_pton(AF_INET, "1.1.1.1", pkt + 16);   // ping the DNS server through NAT
    *(uint16_t *)(pkt + 10) = cksum(pkt, 20);
    uint8_t *icmp = pkt + 20;
    icmp[0] = 8; icmp[1] = 0;
    *(uint16_t *)(icmp + 4) = htons(0xBEEF);
    *(uint16_t *)(icmp + 6) = htons(1);
    memset(icmp + 8, 0xAA, 8);
    *(uint16_t *)(icmp + 2) = cksum(icmp, 16);
    uint32_t af = htonl(AF_INET);
    NSMutableData *d = [NSMutableData dataWithBytes:&af length:4];
    [d appendBytes:pkt length:sizeof(pkt)];
    (void)write(g_tunFd, d.bytes, d.length);
}

static void injectDns(void) {
    static const uint8_t qname[] = {5,'a','p','p','l','e',3,'c','o','m',0};
    uint32_t dnsLen = 12 + sizeof(qname) + 4;
    uint32_t udpLen = 8 + dnsLen;
    uint32_t ipLen = 20 + udpLen;
    uint8_t pkt[20 + 8 + 12 + sizeof(qname) + 4];
    memset(pkt, 0, sizeof(pkt));
    pkt[0] = 0x45; *(uint16_t *)(pkt + 2) = htons(ipLen);
    pkt[8] = 64; pkt[9] = 17;
    inet_pton(AF_INET, g_myIp, pkt + 12);
    inet_pton(AF_INET, "1.1.1.1", pkt + 16);
    *(uint16_t *)(pkt + 10) = cksum(pkt, 20);
    uint8_t *udp = pkt + 20;
    *(uint16_t *)(udp + 0) = htons(53223);
    *(uint16_t *)(udp + 2) = htons(53);
    *(uint16_t *)(udp + 4) = htons(udpLen);
    uint8_t *dns = udp + 8;
    *(uint16_t *)(dns + 0) = htons(0xCAFE);
    *(uint16_t *)(dns + 2) = htons(0x0100);
    *(uint16_t *)(dns + 4) = htons(1);
    memcpy(dns + 12, qname, sizeof(qname));
    *(uint16_t *)(dns + 12 + sizeof(qname)) = htons(1);
    *(uint16_t *)(dns + 14 + sizeof(qname)) = htons(1);
    // UDP checksum (mandatory correctness; ocserv's stack may care)
    uint32_t s = 0;
    for (int i = 12; i < 20; i += 2) s += (pkt[i] << 8) | pkt[i+1];
    s += 17 + udpLen;
    for (uint32_t i = 0; i + 1 < udpLen; i += 2) s += (udp[i] << 8) | udp[i+1];
    if (udpLen & 1) s += udp[udpLen-1] << 8;
    while (s >> 16) s = (s & 0xFFFF) + (s >> 16);
    uint16_t c = (uint16_t)~s; if (!c) c = 0xFFFF;
    *(uint16_t *)(udp + 6) = htons(c);
    uint32_t af = htonl(AF_INET);
    NSMutableData *d = [NSMutableData dataWithBytes:&af length:4];
    [d appendBytes:pkt length:ipLen];
    (void)write(g_tunFd, d.bytes, d.length);
}

static void pumpThread(void) {
    uint8_t buf[2048];
    while (g_tunFd >= 0) {
        ssize_t n = read(g_tunFd, buf, sizeof(buf));
        if (n <= 4) continue;
        uint8_t *ip = buf + 4;   // skip AF prefix
        ssize_t iplen = n - 4;
        if (iplen < 20 || (ip[0] >> 4) != 4) continue;
        if (ip[9] == 1 && iplen >= 28) {
            uint8_t *icmp = ip + (ip[0] & 0x0F) * 4;
            if (icmp[0] == 0 && ntohs(*(uint16_t *)(icmp + 4)) == 0xBEEF) {
                NSLog(@"[data] ICMP echo reply — tunnel works");
                g_pingOk = true;
            }
        }
        if (ip[9] == 17 && iplen >= 28) {
            uint32_t ihl = (ip[0] & 0x0F) * 4;
            uint8_t *udp = ip + ihl;
            if (ntohs(*(uint16_t *)udp) == 53) {
                uint8_t *dns = udp + 8;
                if (ntohs(*(uint16_t *)dns) == 0xCAFE && (dns[3] & 0x80)) {
                    NSLog(@"[data] DNS reply (answers=%u) — UDP through tunnel OK", ntohs(*(uint16_t *)(dns + 6)));
                    g_dnsOk = true;
                }
            }
        }
    }
}

@implementation OCHarness
+ (BOOL)validateServerCert:(struct openconnect_info *)vpn reason:(NSString *)reason {
    // Build a SecTrust from the server-sent chain
    struct oc_cert *chain_c = NULL;
    int n = openconnect_get_peer_cert_chain(vpn, &chain_c);
    NSMutableArray *chain = [NSMutableArray array];
    for (int i = 0; i < n; i++) {
        NSData *der = [NSData dataWithBytes:chain_c[i].der_data length:chain_c[i].der_len];
        SecCertificateRef c = SecCertificateCreateWithData(NULL, (__bridge CFDataRef)der);
        if (c) [chain addObject:(__bridge_transfer id)c];
    }
    if (chain_c) openconnect_free_peer_cert_chain(vpn, chain_c);
    if (chain.count == 0) return NO;
    const char *host = g_verifyHost;
    SecPolicyRef policy = SecPolicyCreateSSL(true, (__bridge CFStringRef)@(host));
    SecTrustRef trust = NULL;
    if (SecTrustCreateWithCertificates((__bridge CFArrayRef)chain, policy, &trust) != errSecSuccess)
        return NO;
    CFErrorRef err = NULL;
    BOOL ok = SecTrustEvaluateWithError(trust, &err);
    if (!ok) NSLog(@"[trust] FAILED: %@", (__bridge NSError *)err);
    else NSLog(@"[trust] OK");
    if (trust) CFRelease(trust);
    return ok;
}
@end

int main(int argc, const char *argv[]) {
    @autoreleasepool {
        g_user = argc > 1 ? @(argv[1]) : @"sstp-test1";
        g_pass = argc > 2 ? @(argv[2]) : @"srp-test-password";
        const char *url = argc > 3 ? argv[3] : "https://openconnect.srp.services";
        {
            NSURL *u = [NSURL URLWithString:@(url)];
            snprintf(g_verifyHost, sizeof(g_verifyHost), "%s", (u.host ?: @"openconnect.srp.services").UTF8String);
        }

        g_vpn = openconnect_vpninfo_new("SRP VPN Connect", NULL, NULL, NULL, NULL, NULL);
        // Re-create with proper callback binding via the documented pattern:
        openconnect_vpninfo_free(g_vpn);
        g_vpn = openconnect_vpninfo_new("SRP VPN Connect",
                                        (void *)onValidatePeerCert,
                                        (void *)onWriteNewConfig,
                                        (void *)onAuthForm,
                                        (void *)onProgress,
                                        NULL);
        openconnect_set_loglevel(g_vpn, 2);
        const char *proto = argc > 4 ? argv[4] : "anyconnect";
        openconnect_set_protocol(g_vpn, proto);
        if (openconnect_parse_url(g_vpn, url)) {
            NSLog(@"parse_url failed"); return 2;
        }

        int fds[2];
        if (socketpair(AF_UNIX, SOCK_DGRAM, 0, fds) != 0) { NSLog(@"socketpair failed"); return 2; }
        g_tunFd = fds[1];

        int r = openconnect_obtain_cookie(g_vpn);
        NSLog(@"[oc] obtain_cookie -> %d", r);
        if (r) { NSLog(@"=== RESULT: established=0 ping=0 dns=0 (auth error surfaced)"); return 1; }

        r = openconnect_make_cstp_connection(g_vpn);
        NSLog(@"[oc] cstp_connection -> %d", r);
        if (r) return 1;

        // DTLS is best-effort
        if (openconnect_setup_dtls(g_vpn, 60) == 0) {
            NSLog(@"[oc] DTLS established");
        } else {
            NSLog(@"[oc] DTLS unavailable — TLS only");
        }

        if (openconnect_setup_tun_fd(g_vpn, fds[0])) {
            NSLog(@"[oc] setup_tun_fd failed"); return 1;
        }
        g_established = true;

        [NSThread detachNewThreadWithBlock:^{ pumpThread(); }];

        // mainloop on a background thread
        [NSThread detachNewThreadWithBlock:^{
            int ret = openconnect_mainloop(g_vpn, 300, 10);
            NSLog(@"[oc] mainloop exited: %d", ret);
        }];

        // PPP backends (F5/Fortinet) assign the address via IPCP during the
        // mainloop — poll for it (CSTP backends have it immediately).
        const struct oc_ip_info *info = NULL;
        for (int i = 0; i < 40; i++) {
            if (openconnect_get_ip_info(g_vpn, &info, NULL, NULL) == 0 && info && info->addr) break;
            [NSThread sleepForTimeInterval:0.25];
        }
        if (info && info->addr) {
            NSLog(@"[oc] ip=%s mask=%s dns=%s mtu=%d", info->addr, info->netmask,
                  info->dns[0] ? info->dns[0] : "?", info->mtu);
            strncpy(g_myIp, info->addr, sizeof(g_myIp) - 1);
        } else {
            NSLog(@"[oc] no IP address assigned (timeout)");
        }

        NSDate *start = [NSDate date];
        bool sent = false;
        while ([[NSDate date] timeIntervalSinceDate:start] < 45) {
            if (g_established && !sent) {
                sent = true;
                [NSThread sleepForTimeInterval:1.0];
                injectPing();
                injectDns();
            }
            if (g_pingOk && g_dnsOk) break;
            [NSThread sleepForTimeInterval:0.2];
        }
        NSLog(@"=== RESULT: established=%d ping=%d dns=%d", g_established, g_pingOk, g_dnsOk);
        return (g_established && g_dnsOk) ? 0 : 1;
    }
}
