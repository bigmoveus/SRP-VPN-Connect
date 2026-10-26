//
//  SRPWireGuardClient.m
//  SRPCore
//

#import "SRPWireGuardClient.h"
#import "SSLog.h"
#import <NetworkExtension/NetworkExtension.h>
#import <arpa/inet.h>
#import <netdb.h>
#import <sys/ioctl.h>
#import <sys/socket.h>
#import <sys/types.h>
#import <unistd.h>
#import "wireguard.h"
#import "awg.h"

// Private on the iOS SDK — minimal copies (stable kernel ABI since forever).
#ifndef AF_SYS_CONTROL
#define AF_SYS_CONTROL 2
#endif
#define SRP_MAX_KCTL_NAME 96
struct srp_ctl_info {
    u_int32_t ctl_id;
    char ctl_name[SRP_MAX_KCTL_NAME];
};
#define SRP_CTLIOCGINFO _IOWR('N', 3, struct srp_ctl_info)
struct srp_sockaddr_ctl {
    u_char sc_len;
    u_char sc_family;
    u_int16_t ss_sysaddr;
    u_int32_t sc_id;
    u_int32_t sc_unit;
    u_int32_t sc_reserved[5];
};

#pragma mark - wg-quick config parsing

@interface SRPWGConfig : NSObject
@property (nonatomic, strong) NSString *privateKey;   // base64
@property (nonatomic, strong) NSMutableArray<NSString *> *addresses;  // CIDR strings
@property (nonatomic, strong) NSMutableArray<NSString *> *dnsServers;
@property (nonatomic, assign) NSInteger mtu;          // 0 = default 1420
// AmneziaWG obfuscation ([Interface]): -1/nil = absent. H1-H4 and the
// content padding are kept as strings because the engine accepts ranges
// ("100-200"), not only single values.
@property (nonatomic, assign) NSInteger jc, jmin, jmax, s1, s2, s3, s4;
@property (nonatomic, strong) NSString *h1, *h2, *h3, *h4;
@property (nonatomic, strong) NSString *i1, *i2, *i3, *i4, *i5;
@property (nonatomic, strong) NSString *contentPaddingAddition;
@property (nonatomic, assign) NSInteger randomTrailers;   // -1 unset, 0 off, 1 on
@property (nonatomic, assign) NSInteger disableCookies;   // -1 unset, 0 off, 1 on
@property (nonatomic, strong) NSString *peerPublicKey;
@property (nonatomic, strong) NSString *presharedKey;
@property (nonatomic, strong) NSString *endpointHost;
@property (nonatomic, assign) NSInteger endpointPort;
@property (nonatomic, strong) NSMutableArray<NSString *> *allowedIPs;
@property (nonatomic, assign) NSInteger keepalive;    // seconds, 0 = off
@end

@implementation SRPWGConfig
@end

static NSString *SRPWGTrim(NSString *s) {
    // Strip inline comments and whitespace
    NSRange hash = [s rangeOfString:@"#"];
    if (hash.location != NSNotFound) s = [s substringToIndex:hash.location];
    NSRange semi = [s rangeOfString:@";"];
    if (semi.location != NSNotFound) s = [s substringToIndex:semi.location];
    return [s stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
}

static SRPWGConfig *SRPWGParseConfig(NSString *text, NSString **errorOut) {
    SRPWGConfig *cfg = [SRPWGConfig new];
    cfg.jc = cfg.jmin = cfg.jmax = cfg.s1 = cfg.s2 = cfg.s3 = cfg.s4 = -1;
    cfg.randomTrailers = cfg.disableCookies = -1;
    cfg.addresses = [NSMutableArray array];
    cfg.dnsServers = [NSMutableArray array];
    cfg.allowedIPs = [NSMutableArray array];

    NSString *section = nil;
    for (NSString *raw in [text componentsSeparatedByCharactersInSet:NSCharacterSet.newlineCharacterSet]) {
        NSString *line = SRPWGTrim(raw);
        if (line.length == 0) continue;
        if ([line hasPrefix:@"["] && [line containsString:@"]"] ) {
            section = [[line substringWithRange:NSMakeRange(1, [line rangeOfString:@"]"].location - 1)] lowercaseString];
            continue;
        }
        NSArray<NSString *> *kv = [line componentsSeparatedByString:@"="];
        if (kv.count < 2) continue;
        NSString *key = [[kv.firstObject stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceCharacterSet] lowercaseString];
        NSString *value = [[kv subarrayWithRange:NSMakeRange(1, kv.count - 1)] componentsJoinedByString:@"="];
        value = [value stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceCharacterSet];

        if ([section isEqualToString:@"interface"]) {
            if ([key isEqualToString:@"privatekey"]) cfg.privateKey = value;
            else if ([key isEqualToString:@"address"]) {
                for (NSString *a in [value componentsSeparatedByString:@","])
                    if (SRPWGTrim(a).length > 0) [cfg.addresses addObject:SRPWGTrim(a)];
            }
            else if ([key isEqualToString:@"dns"]) {
                for (NSString *d in [value componentsSeparatedByString:@","])
                    if (SRPWGTrim(d).length > 0) [cfg.dnsServers addObject:SRPWGTrim(d)];
            }
            else if ([key isEqualToString:@"mtu"]) cfg.mtu = value.integerValue;
            else if ([key isEqualToString:@"jc"]) cfg.jc = value.integerValue;
            else if ([key isEqualToString:@"jmin"]) cfg.jmin = value.integerValue;
            else if ([key isEqualToString:@"jmax"]) cfg.jmax = value.integerValue;
            else if ([key isEqualToString:@"s1"]) cfg.s1 = value.integerValue;
            else if ([key isEqualToString:@"s2"]) cfg.s2 = value.integerValue;
            else if ([key isEqualToString:@"s3"]) cfg.s3 = value.integerValue;
            else if ([key isEqualToString:@"s4"]) cfg.s4 = value.integerValue;
            else if ([key isEqualToString:@"h1"]) cfg.h1 = value;
            else if ([key isEqualToString:@"h2"]) cfg.h2 = value;
            else if ([key isEqualToString:@"h3"]) cfg.h3 = value;
            else if ([key isEqualToString:@"h4"]) cfg.h4 = value;
            else if ([key isEqualToString:@"i1"]) cfg.i1 = value;
            else if ([key isEqualToString:@"i2"]) cfg.i2 = value;
            else if ([key isEqualToString:@"i3"]) cfg.i3 = value;
            else if ([key isEqualToString:@"i4"]) cfg.i4 = value;
            else if ([key isEqualToString:@"i5"]) cfg.i5 = value;
            else if ([key isEqualToString:@"contentpaddingaddition"]) cfg.contentPaddingAddition = value;
            else if ([key isEqualToString:@"randomtrailers"]) cfg.randomTrailers = [value isEqualToString:@"true"] ? 1 : 0;
            else if ([key isEqualToString:@"disablecookies"]) cfg.disableCookies = [value isEqualToString:@"true"] ? 1 : 0;
        }
        else if ([section isEqualToString:@"peer"]) {
            if ([key isEqualToString:@"publickey"]) cfg.peerPublicKey = value;
            else if ([key isEqualToString:@"presharedkey"]) cfg.presharedKey = value;
            else if ([key isEqualToString:@"endpoint"]) {
                NSString *ep = value;
                if ([ep hasPrefix:@"["]) {
                    // [v6]:port
                    NSRange close = [ep rangeOfString:@"]"];
                    if (close.location != NSNotFound) {
                        cfg.endpointHost = [ep substringWithRange:NSMakeRange(1, close.location - 1)];
                        NSString *rest = [ep substringFromIndex:close.location + 1];
                        if ([rest hasPrefix:@":"]) cfg.endpointPort = [[rest substringFromIndex:1] integerValue];
                    }
                } else {
                    NSRange colon = [ep rangeOfString:@":" options:NSBackwardsSearch];
                    if (colon.location != NSNotFound) {
                        cfg.endpointHost = [ep substringToIndex:colon.location];
                        cfg.endpointPort = [[ep substringFromIndex:colon.location + 1] integerValue];
                    } else {
                        cfg.endpointHost = ep;
                    }
                }
            }
            else if ([key isEqualToString:@"allowedips"]) {
                for (NSString *a in [value componentsSeparatedByString:@","])
                    if (SRPWGTrim(a).length > 0) [cfg.allowedIPs addObject:SRPWGTrim(a)];
            }
            else if ([key isEqualToString:@"persistentkeepalive"]) cfg.keepalive = value.integerValue;
        }
    }

    if (cfg.privateKey.length == 0) { *errorOut = @"The config has no [Interface] PrivateKey."; return nil; }
    if (cfg.peerPublicKey.length == 0) { *errorOut = @"The config has no [Peer] PublicKey."; return nil; }
    if (cfg.endpointHost.length == 0 || cfg.endpointPort <= 0) { *errorOut = @"The config has no valid [Peer] Endpoint."; return nil; }
    if (cfg.addresses.count == 0) { *errorOut = @"The config has no [Interface] Address."; return nil; }
    return cfg;
}

#pragma mark - helpers

/// UAPI wants hex-encoded keys; wg-quick configs carry base64.
static NSString *SRPWGBase64ToHex(NSString *b64) {
    NSData *raw = [[NSData alloc] initWithBase64EncodedString:b64 options:0];
    if (raw.length != 32) return nil;
    const uint8_t *bytes = raw.bytes;
    NSMutableString *hex = [NSMutableString stringWithCapacity:64];
    for (NSUInteger i = 0; i < raw.length; i++) [hex appendFormat:@"%02x", bytes[i]];
    return hex;
}

static NSString *SRPWGResolveIPv4(NSString *host) {
    struct in_addr a4;
    if (inet_pton(AF_INET, host.UTF8String, &a4) == 1) return host;
    struct addrinfo hints = {0}, *res = NULL;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    if (getaddrinfo(host.UTF8String, NULL, &hints, &res) == 0 && res) {
        char buf[INET_ADDRSTRLEN];
        struct sockaddr_in *sa = (struct sockaddr_in *)res->ai_addr;
        NSString *r = inet_ntop(AF_INET, &sa->sin_addr, buf, sizeof(buf)) ? @(buf) : nil;
        freeaddrinfo(res);
        return r;
    }
    return nil;
}

/// The Network Extension owns a real utun fd once the tunnel settings are
/// applied; find it like the official WireGuard app does.
static int SRPWGFindUTUNFd(void) {
    struct srp_ctl_info ctlInfo;
    memset(&ctlInfo, 0, sizeof(ctlInfo));
    strlcpy(ctlInfo.ctl_name, "com.apple.net.utun_control", sizeof(ctlInfo.ctl_name));
    for (int fd = 0; fd < 1024; fd++) {
        struct srp_sockaddr_ctl addr;
        socklen_t len = sizeof(addr);
        int ret = getpeername(fd, (struct sockaddr *)&addr, &len);
        if (ret != 0 || addr.sc_family != AF_SYSTEM)
            continue;
        if (ctlInfo.ctl_id == 0) {
            ret = ioctl(fd, SRP_CTLIOCGINFO, &ctlInfo);
            if (ret != 0)
                continue;
        }
        if (addr.sc_id == ctlInfo.ctl_id)
            return fd;
    }
    return -1;
}

static void SRPWGLogToObjC(void *ctx, int level, const char *msg) {
    SRPWireGuardClient *self = (__bridge SRPWireGuardClient *)ctx;
    if (level == 0 && self.logLevel < 2) return;   // verbose only in Debug level
    if (!msg) return;
    SSLogM(@"[wg] %s", msg);
}

@implementation SRPWireGuardClient {


    SRPWGNetworkSettingsCallback _settingsCb;
    SRPWGFailureCallback _failureCb;
    NSString *_uapi;         // prepared UAPI settings (keys are hex)
    int32_t _handle;         // wireguard-go tunnel handle, -1 when down
    dispatch_queue_t _worker;
}

- (instancetype)init {
    self = [super init];
    if (self) {
        _worker = dispatch_queue_create("srp.wg", DISPATCH_QUEUE_SERIAL);
        _handle = -1;
    }
    return self;
}

- (void)startWithNetworkSettingsCallback:(SRPWGNetworkSettingsCallback)settings
                          failureCallback:(SRPWGFailureCallback)failure {
    _settingsCb = settings;
    _failureCb = failure;
    if (_amnezia) awgSetLogger((__bridge void *)self, SRPWGLogToObjC);
    else wgSetLogger((__bridge void *)self, SRPWGLogToObjC);
    dispatch_async(_worker, ^{ [self startLocked]; });
}

- (void)startLocked {
    NSString *parseError = nil;
    SRPWGConfig *cfg = SRPWGParseConfig(self.configText, &parseError);
    if (!cfg) {
        _failureCb([NSString stringWithFormat:@"Invalid WireGuard config: %@", parseError]);
        return;
    }
    NSString *endpointIP = SRPWGResolveIPv4(cfg.endpointHost);
    SSLogM(@"WireGuard: parsed config — addrs=%@ dns=%@ allowed=%@ endpoint=%@:%ld",
           cfg.addresses, cfg.dnsServers, cfg.allowedIPs, cfg.endpointHost, (long)cfg.endpointPort);
    if (!endpointIP) {
        _failureCb([NSString stringWithFormat:@"The WireGuard endpoint %@ could not be resolved.", cfg.endpointHost]);
        return;
    }
    NSString *privHex = SRPWGBase64ToHex(cfg.privateKey);
    NSString *pubHex = SRPWGBase64ToHex(cfg.peerPublicKey);
    if (!privHex || !pubHex) {
        _failureCb(@"Invalid WireGuard config: a key is not valid base64 (32 bytes).");
        return;
    }

    // UAPI settings (one peer)
    NSMutableString *uapi = [NSMutableString new];
    [uapi appendFormat:@"private_key=%@\n", privHex];
    [uapi appendString:@"listen_port=0\n"];
    // AmneziaWG obfuscation is device-level: it must precede the first peer
    if (cfg.jc >= 0)   [uapi appendFormat:@"jc=%ld\n", (long)cfg.jc];
    if (cfg.jmin >= 0) [uapi appendFormat:@"jmin=%ld\n", (long)cfg.jmin];
    if (cfg.jmax >= 0) [uapi appendFormat:@"jmax=%ld\n", (long)cfg.jmax];
    if (cfg.s1 >= 0)   [uapi appendFormat:@"s1=%ld\n", (long)cfg.s1];
    if (cfg.s2 >= 0)   [uapi appendFormat:@"s2=%ld\n", (long)cfg.s2];
    if (cfg.s3 >= 0)   [uapi appendFormat:@"s3=%ld\n", (long)cfg.s3];
    if (cfg.s4 >= 0)   [uapi appendFormat:@"s4=%ld\n", (long)cfg.s4];
    if (cfg.h1.length) [uapi appendFormat:@"h1=%@\n", cfg.h1];
    if (cfg.h2.length) [uapi appendFormat:@"h2=%@\n", cfg.h2];
    if (cfg.h3.length) [uapi appendFormat:@"h3=%@\n", cfg.h3];
    if (cfg.h4.length) [uapi appendFormat:@"h4=%@\n", cfg.h4];
    if (cfg.i1.length) [uapi appendFormat:@"i1=%@\n", cfg.i1];
    if (cfg.i2.length) [uapi appendFormat:@"i2=%@\n", cfg.i2];
    if (cfg.i3.length) [uapi appendFormat:@"i3=%@\n", cfg.i3];
    if (cfg.i4.length) [uapi appendFormat:@"i4=%@\n", cfg.i4];
    if (cfg.i5.length) [uapi appendFormat:@"i5=%@\n", cfg.i5];
    if (cfg.contentPaddingAddition.length) [uapi appendFormat:@"content_padding_addition=%@\n", cfg.contentPaddingAddition];
    if (cfg.randomTrailers >= 0) [uapi appendFormat:@"random_trailers=%@\n", cfg.randomTrailers ? @"true" : @"false"];
    if (cfg.disableCookies >= 0) [uapi appendFormat:@"disable_cookies=%@\n", cfg.disableCookies ? @"true" : @"false"];
    [uapi appendString:@"replace_peers=true\n"];
    [uapi appendFormat:@"public_key=%@\n", pubHex];
    if (cfg.presharedKey.length > 0) {
        NSString *pskHex = SRPWGBase64ToHex(cfg.presharedKey);
        if (!pskHex) {
            _failureCb(@"Invalid WireGuard config: the PresharedKey is not valid base64 (32 bytes).");
            return;
        }
        [uapi appendFormat:@"preshared_key=%@\n", pskHex];
    }
    [uapi appendFormat:@"endpoint=%@:%ld\n", endpointIP, (long)cfg.endpointPort];
    for (NSString *ip in cfg.allowedIPs) [uapi appendFormat:@"allowed_ip=%@\n", ip];
    if (cfg.keepalive > 0) [uapi appendFormat:@"persistent_keepalive_interval=%ld\n", (long)cfg.keepalive];
    _uapi = uapi;

    if (_settingsCb) _settingsCb([self buildSettingsFromConfig:cfg endpointIP:endpointIP]);
}

- (BOOL)activateWithError:(NSError **)error {
    __block BOOL ok = NO;
    __block NSString *msg = nil;
    dispatch_sync(_worker, ^{
        if (self->_uapi.length == 0) {
            msg = @"WireGuard: startWithNetworkSettingsCallback did not complete.";
            return;
        }
        int fd = SRPWGFindUTUNFd();
        if (fd < 0) {
            msg = @"WireGuard: the tunnel interface (utun) was not found — were the network settings applied?";
            return;
        }
        int32_t handle = self->_amnezia ? awgTurnOn(self->_uapi.UTF8String, fd)
                                        : wgTurnOn(self->_uapi.UTF8String, fd);
        if (handle < 0) {
            msg = @"WireGuard: the engine refused the configuration (see log).";
            return;
        }
        self->_handle = handle;
        ok = YES;
    });
    if (ok) {
        SSLogM(@"WireGuard: device up (utun attached)");
    } else if (error) {
        *error = [NSError errorWithDomain:@"SRPVPN" code:-1 userInfo:@{NSLocalizedDescriptionKey: msg ?: @"WireGuard failed to start"}];
    }
    return ok;
}

- (NEPacketTunnelNetworkSettings *)buildSettingsFromConfig:(SRPWGConfig *)cfg endpointIP:(NSString *)endpointIP {
    NEPacketTunnelNetworkSettings *settings =
        [[NEPacketTunnelNetworkSettings alloc] initWithTunnelRemoteAddress:endpointIP];
    settings.MTU = @(cfg.mtu > 0 ? cfg.mtu : 1420);

    NSMutableArray<NSString *> *v4Addrs = [NSMutableArray array];
    NSMutableArray<NSString *> *v4Masks = [NSMutableArray array];
    NSMutableArray<NSString *> *v6Addrs = [NSMutableArray array];
    NSMutableArray<NSNumber *> *v6Prefixes = [NSMutableArray array];
    NSMutableArray<NEIPv4Route *> *v4Routes = [NSMutableArray array];
    NSMutableArray<NEIPv6Route *> *v6Routes = [NSMutableArray array];

    for (NSString *cidr in cfg.addresses) {
        NSArray<NSString *> *parts = [cidr componentsSeparatedByString:@"/"];
        NSString *addr = parts.firstObject;
        NSInteger prefix = parts.count > 1 ? [parts[1] integerValue] : 32;
        struct in_addr a4;
        if (inet_pton(AF_INET, addr.UTF8String, &a4) == 1) {
            [v4Addrs addObject:addr];
            uint32_t m = prefix >= 32 ? UINT32_MAX : (prefix <= 0 ? 0 : htonl(0xFFFFFFFFu << (32 - prefix)));
            struct in_addr ma; ma.s_addr = m;
            char mbuf[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &ma, mbuf, sizeof(mbuf));
            [v4Masks addObject:@(mbuf)];
        } else {
            [v6Addrs addObject:addr];
            [v6Prefixes addObject:@(prefix)];
        }
    }

    for (NSString *cidr in cfg.allowedIPs) {
        NSArray<NSString *> *parts = [cidr componentsSeparatedByString:@"/"];
        NSString *addr = parts.firstObject;
        NSInteger prefix = parts.count > 1 ? [parts[1] integerValue] : ([addr containsString:@":"] ? 128 : 32);
        struct in_addr a4;
        if (inet_pton(AF_INET, addr.UTF8String, &a4) == 1) {
            if (prefix == 0) {
                // A hand-built 0.0.0.0/0 route is NOT the default route from
                // iOS's point of view (reachability stays "offline") — use
                // the dedicated defaultRoute object.
                [v4Routes addObject:NEIPv4Route.defaultRoute];
                continue;
            }
            uint32_t m = prefix >= 32 ? UINT32_MAX : (prefix <= 0 ? 0 : htonl(0xFFFFFFFFu << (32 - prefix)));
            struct in_addr ma; ma.s_addr = m;
            char mbuf[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &ma, mbuf, sizeof(mbuf));
            [v4Routes addObject:[[NEIPv4Route alloc] initWithDestinationAddress:addr subnetMask:@(mbuf)]];
        } else {
            if (prefix == 0) {
                [v6Routes addObject:NEIPv6Route.defaultRoute];
                continue;
            }
            [v6Routes addObject:[[NEIPv6Route alloc] initWithDestinationAddress:addr networkPrefixLength:@(prefix)]];
        }
    }

    NEIPv4Settings *v4 = [[NEIPv4Settings alloc] initWithAddresses:v4Addrs subnetMasks:v4Masks];
    v4.includedRoutes = v4Routes.count > 0 ? v4Routes : @[NEIPv4Route.defaultRoute];
    // The endpoint itself must stay outside the tunnel
    v4.excludedRoutes = @[[[NEIPv4Route alloc] initWithDestinationAddress:endpointIP subnetMask:@"255.255.255.255"]];
    settings.IPv4Settings = v4;

    if (v6Addrs.count > 0) {
        NEIPv6Settings *v6 = [[NEIPv6Settings alloc] initWithAddresses:v6Addrs networkPrefixLengths:v6Prefixes];
        if (v6Routes.count > 0) v6.includedRoutes = v6Routes;
        settings.IPv6Settings = v6;
    }

    if (cfg.dnsServers.count > 0) {
        NEDNSSettings *dns = [[NEDNSSettings alloc] initWithServers:cfg.dnsServers];
        // Like the official app: the tunnel DNS is the default resolver —
        // without an explicit empty match-domain the system path reports
        // "no DNS" and URLSession fails with -1009 (offline).
        dns.matchDomains = @[@""];
        settings.DNSSettings = dns;
    }
    return settings;
}

- (void)close {
    dispatch_async(_worker, ^{
        if (self->_handle >= 0) {
            if (self->_amnezia) awgTurnOff(self->_handle); else wgTurnOff(self->_handle);
            self->_handle = -1;
        }
    });
}

- (void)closeAndWait {
    dispatch_sync(_worker, ^{
        if (self->_handle >= 0) {
            if (self->_amnezia) awgTurnOff(self->_handle); else wgTurnOff(self->_handle);
            self->_handle = -1;
        }
    });
}

- (void)pauseForSleep {
    // Nothing to do: WireGuard tolerates sleep; sockets are re-bound on wake.
}

- (void)wakeFromSleep {
    dispatch_async(_worker, ^{
        if (self->_handle >= 0) {
            if (self->_amnezia) {
                awgBumpSockets(self->_handle);
                awgDisableSomeRoamingForBrokenMobileSemantics(self->_handle);
            } else {
                wgBumpSockets(self->_handle);
                wgDisableSomeRoamingForBrokenMobileSemantics(self->_handle);
            }
            SSLogM(@"WireGuard: wake — sockets re-bound");
        }
    });
}

- (void)dealloc {
    [self closeAndWait];
}

+ (NSDictionary<NSString *, NSString *> *)netstackParametersFromConfig:(NSString *)configText
                                                                 error:(NSString **)errorOut {
    SRPWGConfig *cfg = SRPWGParseConfig(configText, errorOut);
    if (!cfg) return nil;
    NSString *endpointIP = SRPWGResolveIPv4(cfg.endpointHost);
    if (!endpointIP) {
        if (errorOut) *errorOut = [NSString stringWithFormat:@"The WireGuard endpoint %@ could not be resolved.", cfg.endpointHost];
        return nil;
    }
    NSString *privHex = SRPWGBase64ToHex(cfg.privateKey);
    NSString *pubHex = SRPWGBase64ToHex(cfg.peerPublicKey);
    if (!privHex || !pubHex) {
        if (errorOut) *errorOut = @"Invalid WireGuard config: a key is not valid base64 (32 bytes).";
        return nil;
    }
    // Plain-WireGuard UAPI (the netstack engine does not take Amnezia keys)
    NSMutableString *uapi = [NSMutableString new];
    [uapi appendFormat:@"private_key=%@\n", privHex];
    [uapi appendString:@"listen_port=0\n"];
    [uapi appendString:@"replace_peers=true\n"];
    [uapi appendFormat:@"public_key=%@\n", pubHex];
    if (cfg.presharedKey.length > 0) {
        NSString *pskHex = SRPWGBase64ToHex(cfg.presharedKey);
        if (!pskHex) {
            if (errorOut) *errorOut = @"Invalid WireGuard config: the PresharedKey is not valid base64 (32 bytes).";
            return nil;
        }
        [uapi appendFormat:@"preshared_key=%@\n", pskHex];
    }
    [uapi appendFormat:@"endpoint=%@:%ld\n", endpointIP, (long)cfg.endpointPort];
    for (NSString *ip in cfg.allowedIPs) [uapi appendFormat:@"allowed_ip=%@\n", ip];
    if (cfg.keepalive > 0) [uapi appendFormat:@"persistent_keepalive_interval=%ld\n", (long)cfg.keepalive];
    NSString *addr = nil;
    for (NSString *a in cfg.addresses) {
        NSString *host = [[a componentsSeparatedByString:@"/"] firstObject];
        if ([host containsString:@"."]) { addr = host; break; }
    }
    if (addr.length == 0) {
        if (errorOut) *errorOut = @"The WireGuard config has no interface IPv4 address.";
        return nil;
    }
    return @{@"uapi": uapi, @"endpointIP": endpointIP, @"address": addr};
}

@end
