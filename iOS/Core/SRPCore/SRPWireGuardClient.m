//
//  SRPWireGuardClient.m
//  SRPCore
//

#import "SRPWireGuardClient.h"
#import "SSLog.h"
#import <NetworkExtension/NetworkExtension.h>
#import <Network/Network.h>
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
// AmneziaWG obfuscation ([Interface]): -1/nil = absent. H1-H4, the content padding and the timings are kept as
// strings because the engine accepts ranges ("100-200"), not only single values.
@property (nonatomic, assign) NSInteger jc, jmin, jmax, s1, s2, s3, s4;
@property (nonatomic, strong) NSString *h1, *h2, *h3, *h4;
@property (nonatomic, strong) NSString *i1, *i2, *i3, *i4, *i5;
@property (nonatomic, strong) NSString *headerProtectionKey;   // base64, like the other keys
@property (nonatomic, strong) NSString *contentPaddingAddition;
@property (nonatomic, strong) NSString *rekeyAfterTime, *rekeyTimeout, *rejectAfterTime, *keepaliveTimeout, *maxHandshakeAttempts;
@property (nonatomic, assign) NSInteger randomTrailers;   // -1 unset, 0 off, 1 on
@property (nonatomic, assign) NSInteger disableCookies;   // -1 unset, 0 off, 1 on
/// The AmneziaWG settings of the file as written (Jc, S1, H1, …): WireGuard itself refuses them
@property (nonatomic, strong) NSMutableArray<NSString *> *amneziaKeys;
@property (nonatomic, strong) NSString *peerPublicKey;
@property (nonatomic, strong) NSString *presharedKey;
@property (nonatomic, strong) NSString *endpointHost;
@property (nonatomic, assign) NSInteger endpointPort;
@property (nonatomic, strong) NSMutableArray<NSString *> *allowedIPs;
@property (nonatomic, assign) NSInteger keepalive;    // seconds, 0 = off (AmneziaWG: the low end of a range)
@property (nonatomic, strong) NSString *keepaliveSpec; // PersistentKeepalive as the engine takes it ("25", or "20-30")
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

/// "N" or "N-M" with N <= M <= max (the AmneziaWG engine's ranges), normalized; nil when the value is not one
static NSString *SRPWGRange(NSString *value, unsigned long long max, BOOL allowRange) {
    NSArray<NSString *> *parts = [value componentsSeparatedByString:@"-"];
    if (parts.count < 1 || parts.count > (allowRange ? 2 : 1)) return nil;
    NSCharacterSet *notDigit = [NSCharacterSet characterSetWithCharactersInString:@"0123456789"].invertedSet;
    unsigned long long bounds[2] = {0, 0};
    for (NSUInteger i = 0; i < parts.count; i++) {
        NSString *part = [parts[i] stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceCharacterSet];
        if (part.length == 0 || part.length > 10 || [part rangeOfCharacterFromSet:notDigit].location != NSNotFound) return nil;
        bounds[i] = strtoull(part.UTF8String, NULL, 10);
        if (bounds[i] > max) return nil;
    }
    if (parts.count == 2 && bounds[1] < bounds[0]) return nil;
    return parts.count == 2 ? [NSString stringWithFormat:@"%llu-%llu", bounds[0], bounds[1]] : [NSString stringWithFormat:@"%llu", bounds[0]];
}

/// The awg tool's booleans (on/off or a number) and the usual true/false; -1 when the value is none of them
static NSInteger SRPWGBool(NSString *value) {
    NSString *v = value.lowercaseString;
    if ([@[@"on", @"true", @"yes"] containsObject:v]) return 1;
    if ([@[@"off", @"false", @"no"] containsObject:v]) return 0;
    NSString *number = SRPWGRange(v, UINT32_MAX, NO);
    return number ? (number.longLongValue != 0) : -1;
}

static SRPWGConfig *SRPWGParseConfig(NSString *text, NSString **errorOut) {
    SRPWGConfig *cfg = [SRPWGConfig new];
    cfg.jc = cfg.jmin = cfg.jmax = cfg.s1 = cfg.s2 = cfg.s3 = cfg.s4 = -1;
    cfg.randomTrailers = cfg.disableCookies = -1;
    cfg.addresses = [NSMutableArray array];
    cfg.dnsServers = [NSMutableArray array];
    cfg.allowedIPs = [NSMutableArray array];
    cfg.amneziaKeys = [NSMutableArray array];

    // The AmneziaWG settings: numbers (Jc, Jmin, Jmax, S1-S4 up to 65535), ranges (H1-H4 up to 2^32-1, the padding and
    // timings up to 65535, as the awg tool takes them), booleans, the header protection key and the I1-I5 chains
    NSDictionary<NSString *, NSString *> *awgNames = @{@"jc": @"Jc", @"jmin": @"Jmin", @"jmax": @"Jmax", @"s1": @"S1", @"s2": @"S2",
        @"s3": @"S3", @"s4": @"S4", @"h1": @"H1", @"h2": @"H2", @"h3": @"H3", @"h4": @"H4", @"i1": @"I1", @"i2": @"I2", @"i3": @"I3",
        @"i4": @"I4", @"i5": @"I5", @"headerprotectionkey": @"HeaderProtectionKey", @"contentpaddingaddition": @"ContentPaddingAddition",
        @"rekeyaftertime": @"RekeyAfterTime", @"rekeytimeout": @"RekeyTimeout", @"rejectaftertime": @"RejectAfterTime",
        @"keepalivetimeout": @"KeepaliveTimeout", @"maxhandshakeattempts": @"MaxHandshakeAttempts",
        @"randomtrailers": @"RandomTrailers", @"disablecookies": @"DisableCookies"};
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
            NSString *awgName = awgNames[key];
            NSString *number = nil, *range = nil;
            if (awgName) {
                [cfg.amneziaKeys addObject:awgName];
                BOOL isNumber = [@[@"jc", @"jmin", @"jmax", @"s1", @"s2", @"s3", @"s4"] containsObject:key];
                BOOL isRange = [@[@"h1", @"h2", @"h3", @"h4", @"contentpaddingaddition", @"rekeyaftertime", @"rekeytimeout",
                                  @"rejectaftertime", @"keepalivetimeout", @"maxhandshakeattempts"] containsObject:key];
                if (isNumber && !(number = SRPWGRange(value, 65535, NO))) {
                    *errorOut = [NSString stringWithFormat:@"%@ must be a whole number from 0 to 65535.", awgName];
                    return nil;
                }
                if (isRange && !(range = SRPWGRange(value, [key hasPrefix:@"h"] ? UINT32_MAX : 65535, YES))) {
                    *errorOut = [NSString stringWithFormat:@"%@ must be a number or a range such as %@.", awgName,
                                 [key hasPrefix:@"h"] ? @"1000000-1999999" : @"10-20"];
                    return nil;
                }
                if (([key isEqualToString:@"randomtrailers"] || [key isEqualToString:@"disablecookies"]) && SRPWGBool(value) < 0) {
                    *errorOut = [NSString stringWithFormat:@"%@ must be on or off.", awgName];
                    return nil;
                }
            }
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
            else if ([key isEqualToString:@"jc"]) cfg.jc = number.integerValue;
            else if ([key isEqualToString:@"jmin"]) cfg.jmin = number.integerValue;
            else if ([key isEqualToString:@"jmax"]) cfg.jmax = number.integerValue;
            else if ([key isEqualToString:@"s1"]) cfg.s1 = number.integerValue;
            else if ([key isEqualToString:@"s2"]) cfg.s2 = number.integerValue;
            else if ([key isEqualToString:@"s3"]) cfg.s3 = number.integerValue;
            else if ([key isEqualToString:@"s4"]) cfg.s4 = number.integerValue;
            else if ([key isEqualToString:@"h1"]) cfg.h1 = range;
            else if ([key isEqualToString:@"h2"]) cfg.h2 = range;
            else if ([key isEqualToString:@"h3"]) cfg.h3 = range;
            else if ([key isEqualToString:@"h4"]) cfg.h4 = range;
            else if ([key isEqualToString:@"i1"]) cfg.i1 = value;
            else if ([key isEqualToString:@"i2"]) cfg.i2 = value;
            else if ([key isEqualToString:@"i3"]) cfg.i3 = value;
            else if ([key isEqualToString:@"i4"]) cfg.i4 = value;
            else if ([key isEqualToString:@"i5"]) cfg.i5 = value;
            else if ([key isEqualToString:@"headerprotectionkey"]) cfg.headerProtectionKey = value;
            else if ([key isEqualToString:@"contentpaddingaddition"]) cfg.contentPaddingAddition = range;
            else if ([key isEqualToString:@"rekeyaftertime"]) cfg.rekeyAfterTime = range;
            else if ([key isEqualToString:@"rekeytimeout"]) cfg.rekeyTimeout = range;
            else if ([key isEqualToString:@"rejectaftertime"]) cfg.rejectAfterTime = range;
            else if ([key isEqualToString:@"keepalivetimeout"]) cfg.keepaliveTimeout = range;
            else if ([key isEqualToString:@"maxhandshakeattempts"]) cfg.maxHandshakeAttempts = range;
            else if ([key isEqualToString:@"randomtrailers"]) cfg.randomTrailers = SRPWGBool(value);
            else if ([key isEqualToString:@"disablecookies"]) cfg.disableCookies = SRPWGBool(value);
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
            else if ([key isEqualToString:@"persistentkeepalive"]) {
                // wg takes a number or "off"; the AmneziaWG engine also a range, picking a value in it each time
                NSString *spec = [value.lowercaseString isEqualToString:@"off"] ? @"0" : SRPWGRange(value, 65535, YES);
                if (!spec) {
                    *errorOut = @"PersistentKeepalive must be a number of seconds (AmneziaWG also takes a range such as 20-30).";
                    return nil;
                }
                cfg.keepaliveSpec = spec;
                cfg.keepalive = spec.integerValue;   // the low end of a range
                if ([spec containsString:@"-"]) [cfg.amneziaKeys addObject:@"a PersistentKeepalive range"];
            }
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

/// The tunnel's MTU: the file's, else 1420; AmneziaWG adds S4 bytes to every data packet, so without an MTU in the file it
/// takes S4 off, and a full-size packet stays within a 1500-byte path as WireGuard's own does
static NSInteger SRPWGEffectiveMTU(SRPWGConfig *cfg, BOOL amnezia) {
    if (cfg.mtu > 0) return cfg.mtu;
    return amnezia && cfg.s4 > 0 ? MAX(1280, 1420 - cfg.s4) : 1420;
}

/// Sent bytes that are more than keepalives, for the silence check: WireGuard's keepalive is 32 bytes, so 296 bytes (two
/// handshake initiations) mean data or handshakes. AmneziaWG pads every data packet with S4 bytes, and its content padding
/// and random trailers can grow a keepalive to the largest packet sent (S4 + 32 + MTU): the bound covers the keepalives a
/// 30-second window can hold (persistent ones, one passive one, one more for rounding).
static long long SRPWGSilenceBytes(SRPWGConfig *cfg, BOOL amnezia) {
    if (!amnezia) return 296;
    long long s4 = MAX(0, cfg.s4);
    long long keepalive = s4 + 32;
    if (cfg.contentPaddingAddition.length > 0 || cfg.randomTrailers == 1) {
        keepalive = MAX(500, s4 + 32 + SRPWGEffectiveMTU(cfg, YES));   // 500: the engine's first window
    }
    long long count = (cfg.keepalive > 0 ? 30 / cfg.keepalive + 1 : 0) + 2;
    return MAX(296, count * keepalive);
}

/// The engine's settings (UAPI, keys in hex) for one peer at endpointIP; nil with errorOut set when a key does not decode
static NSString *SRPWGBuildUAPI(SRPWGConfig *cfg, NSString *endpointIP, BOOL amnezia, NSString **errorOut) {
    NSString *privHex = SRPWGBase64ToHex(cfg.privateKey);
    NSString *pubHex = SRPWGBase64ToHex(cfg.peerPublicKey);
    if (!privHex || !pubHex) {
        *errorOut = @"a key is not valid base64 (32 bytes).";
        return nil;
    }
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
    if (cfg.headerProtectionKey.length) {
        NSString *hpkHex = SRPWGBase64ToHex(cfg.headerProtectionKey);
        if (!hpkHex) {
            *errorOut = @"the HeaderProtectionKey is not valid base64 (32 bytes).";
            return nil;
        }
        [uapi appendFormat:@"header_protection_key=%@\n", hpkHex];
    }
    if (cfg.contentPaddingAddition.length) [uapi appendFormat:@"content_padding_addition=%@\n", cfg.contentPaddingAddition];
    if (cfg.rekeyAfterTime.length) [uapi appendFormat:@"rekey_after_time=%@\n", cfg.rekeyAfterTime];
    if (cfg.rekeyTimeout.length) [uapi appendFormat:@"rekey_timeout=%@\n", cfg.rekeyTimeout];
    if (cfg.rejectAfterTime.length) [uapi appendFormat:@"reject_after_time=%@\n", cfg.rejectAfterTime];
    if (cfg.keepaliveTimeout.length) [uapi appendFormat:@"keepalive_timeout=%@\n", cfg.keepaliveTimeout];
    if (cfg.maxHandshakeAttempts.length) [uapi appendFormat:@"max_handshake_attempts=%@\n", cfg.maxHandshakeAttempts];
    if (cfg.randomTrailers >= 0) [uapi appendFormat:@"random_trailers=%@\n", cfg.randomTrailers ? @"true" : @"false"];
    if (cfg.disableCookies >= 0) [uapi appendFormat:@"disable_cookies=%@\n", cfg.disableCookies ? @"true" : @"false"];
    [uapi appendString:@"replace_peers=true\n"];
    [uapi appendFormat:@"public_key=%@\n", pubHex];
    if (cfg.presharedKey.length > 0) {
        NSString *pskHex = SRPWGBase64ToHex(cfg.presharedKey);
        if (!pskHex) {
            *errorOut = @"the PresharedKey is not valid base64 (32 bytes).";
            return nil;
        }
        [uapi appendFormat:@"preshared_key=%@\n", pskHex];
    }
    [uapi appendFormat:@"endpoint=%@:%ld\n", endpointIP, (long)cfg.endpointPort];
    for (NSString *ip in cfg.allowedIPs) [uapi appendFormat:@"allowed_ip=%@\n", ip];
    if (cfg.keepalive > 0) {
        [uapi appendFormat:@"persistent_keepalive_interval=%@\n", amnezia ? cfg.keepaliveSpec : @(cfg.keepalive).stringValue];
    }
    return uapi;
}

@interface SRPWireGuardClient ()
/// The engine's last error line (for example why it refused the settings), from its log callback
@property (atomic, copy, nullable) NSString *lastEngineError;
@end

static void SRPWGLogToObjC(void *ctx, int level, const char *msg) {
    SRPWireGuardClient *self = (__bridge SRPWireGuardClient *)ctx;
    if (!msg) return;
    if (level == 1) self.lastEngineError = @(msg);
    if (level == 0 && self.logLevel < 2) return;   // verbose only in Debug level
    SSLogM(@"[%@] %s", self.amnezia ? @"awg" : @"wg", msg);
}

@implementation SRPWireGuardClient {


    SRPWGNetworkSettingsCallback _settingsCb;
    SRPWGFailureCallback _failureCb;
    NSString *_uapi;         // prepared UAPI settings (keys are hex)
    int32_t _handle;         // wireguard-go tunnel handle, -1 when down
    dispatch_queue_t _worker;
    // activateAndWaitForHandshake: (WireGuard and AmneziaWG), all on _worker
    SRPWGConfig *_cfg;
    NSString *_endpointIP;
    NSString *_peerHex;
    BOOL _managed;           // the session is watched (handshake, silence, sleep, network changes)
    BOOL _up;                // the first handshake happened
    BOOL _reconnecting;
    BOOL _paused;            // closed for sleep (On Sleep Pause or Off)
    BOOL _closed;
    BOOL _keepaliveTemp;     // a keepalive switched on only to start a handshake
    BOOL _peerFresh;         // the device was just turned on: its peer has sent nothing yet
    NSInteger _attempts;
    CFAbsoluteTime _attemptStart;
    long long _handshakeBefore;
    long long _silenceBytes;     // sent bytes in 30 s of silence that are more than keepalives (SRPWGSilenceBytes)
    void (^_activateCompletion)(NSString *);
    dispatch_source_t _pollTimer;
    dispatch_source_t _monitorTimer;
    NSMutableArray<NSArray<NSNumber *> *> *_samples;   // (time, rx, tx, last handshake) every 5 s
    CFAbsoluteTime _lastCounterLine;
    nw_path_monitor_t _pathMonitor;
    NSString *_pathKey;
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

- (NSString *)protocolName {
    return _amnezia ? @"AmneziaWG" : @"WireGuard";
}

// The profile's engine: wireguard-go (wg*) or amneziawg-go (awg*), both in one Go runtime
- (int32_t)engineTurnOn:(NSString *)settings fd:(int)fd {
    return _amnezia ? awgTurnOn(settings.UTF8String, fd) : wgTurnOn(settings.UTF8String, fd);
}

- (void)engineTurnOff:(int32_t)handle {
    if (_amnezia) awgTurnOff(handle); else wgTurnOff(handle);
}

- (void)engineSetConfig:(int32_t)handle settings:(NSString *)settings {
    if (_amnezia) awgSetConfig(handle, settings.UTF8String); else wgSetConfig(handle, settings.UTF8String);
}

- (char *)engineGetConfig:(int32_t)handle {
    return _amnezia ? awgGetConfig(handle) : wgGetConfig(handle);
}

- (void)engineBumpSockets:(int32_t)handle {
    if (_amnezia) awgBumpSockets(handle); else wgBumpSockets(handle);
}

- (void)engineDisableRoaming:(int32_t)handle {
    if (_amnezia) awgDisableSomeRoamingForBrokenMobileSemantics(handle); else wgDisableSomeRoamingForBrokenMobileSemantics(handle);
}

/// WireGuard takes none of AmneziaWG's settings: a file that has them belongs to an AmneziaWG profile
static NSString *SRPWGAmneziaKeysMessage(SRPWGConfig *cfg) {
    NSArray<NSString *> *keys = cfg.amneziaKeys;
    NSString *shown = [[keys subarrayWithRange:NSMakeRange(0, MIN(keys.count, 4))] componentsJoinedByString:@", "];
    return [NSString stringWithFormat:@"This configuration has AmneziaWG settings (%@%@): use the AmneziaWG VPN protocol for it.",
            shown, keys.count > 4 ? @", …" : @""];
}

- (void)startLocked {
    NSString *parseError = nil;
    SRPWGConfig *cfg = SRPWGParseConfig(self.configText, &parseError);
    if (!cfg) {
        _failureCb([NSString stringWithFormat:@"Invalid %@ config: %@", self.protocolName, parseError]);
        return;
    }
    if (!_amnezia && cfg.amneziaKeys.count > 0) {
        _failureCb(SRPWGAmneziaKeysMessage(cfg));
        return;
    }
    NSString *endpointIP = SRPWGResolveIPv4(cfg.endpointHost);
    SSLogM(@"%@: parsed config — addrs=%@ dns=%@ allowed=%@ endpoint=%@:%ld", self.protocolName,
           cfg.addresses, cfg.dnsServers, cfg.allowedIPs, cfg.endpointHost, (long)cfg.endpointPort);
    if (!endpointIP) {
        _failureCb([NSString stringWithFormat:@"The %@ endpoint %@ could not be resolved.", self.protocolName, cfg.endpointHost]);
        return;
    }
    NSString *uapiError = nil;
    NSString *uapi = SRPWGBuildUAPI(cfg, endpointIP, _amnezia, &uapiError);
    if (!uapi) {
        _failureCb([NSString stringWithFormat:@"Invalid %@ config: %@", self.protocolName, uapiError]);
        return;
    }
    _cfg = cfg;
    _endpointIP = endpointIP;
    _peerHex = SRPWGBase64ToHex(cfg.peerPublicKey);
    _silenceBytes = SRPWGSilenceBytes(cfg, _amnezia);
    NSString *keepalive = cfg.keepalive > 0 ? [NSString stringWithFormat:@"%@ s", _amnezia ? cfg.keepaliveSpec : @(cfg.keepalive)] : @"off";
    SSLogM(@"%@: connecting to %@ (%@) port %ld over UDP, keepalive %@, preshared key %@", self.protocolName, cfg.endpointHost,
           endpointIP, (long)cfg.endpointPort, keepalive, cfg.presharedKey.length > 0 ? @"yes" : @"no");
    if (_amnezia) {
        // What the file sets (names only: the header protection key is a secret, the I1-I5 chains are long)
        NSMutableArray<NSString *> *set = [NSMutableArray new];
        for (NSString *key in cfg.amneziaKeys) {
            if (![set containsObject:key]) [set addObject:key];
        }
        SSLogM(@"AmneziaWG: obfuscation %@, MTU %ld", set.count > 0 ? [set componentsJoinedByString:@" "] : @"none (WireGuard's own format)",
               (long)SRPWGEffectiveMTU(cfg, YES));
        BOOL ranges = [cfg.h1 containsString:@"-"] || [cfg.h2 containsString:@"-"] || [cfg.h3 containsString:@"-"];
        // The app's engine (our amneziawg-go fork) keeps these packets, and with header protection it also sends packets the
        // server's first-match classification reads right; without it the server can still drop some of the phone's packets
        if (cfg.randomTrailers == 1 && ranges && cfg.headerProtectionKey.length == 0) {
            SSLogM(@"AmneziaWG: note: with RandomTrailers on, ranges in H1-H3 and no HeaderProtectionKey, the server's AmneziaWG may take "
                   "some of the phone's data packets for handshake messages and drop them (uploads slow down); a HeaderProtectionKey "
                   "or single values in H1-H3 avoid it");
        }
    }
    _uapi = uapi;

    if (_settingsCb) _settingsCb([self buildSettingsFromConfig:cfg endpointIP:endpointIP]);
}

+ (NSDictionary<NSString *, id> *)engineSettingsFromConfig:(NSString *)configText amnezia:(BOOL)amnezia
                                                     error:(NSString **)errorOut {
    NSString *error = nil;
    SRPWGConfig *cfg = SRPWGParseConfig(configText, &error);
    if (cfg && !amnezia && cfg.amneziaKeys.count > 0) {
        error = SRPWGAmneziaKeysMessage(cfg);
        cfg = nil;
    }
    NSString *endpointIP = cfg ? SRPWGResolveIPv4(cfg.endpointHost) : nil;
    if (cfg && !endpointIP) {
        error = [NSString stringWithFormat:@"The endpoint %@ could not be resolved.", cfg.endpointHost];
    }
    NSString *uapi = endpointIP ? SRPWGBuildUAPI(cfg, endpointIP, amnezia, &error) : nil;
    if (!uapi) {
        if (errorOut) *errorOut = error;
        return nil;
    }
    return @{@"uapi": uapi, @"mtu": @(SRPWGEffectiveMTU(cfg, amnezia)), @"silenceBytes": @(SRPWGSilenceBytes(cfg, amnezia))};
}

- (BOOL)activateWithError:(NSError **)error {
    return [self turnOnWithoutKeepalive:NO error:error];
}

/// The settings without the peer's keepalive: a device that starts with one sends a handshake initiation at once, and a
/// second one from the first attempt within the same few milliseconds is dropped by the server as a replay
- (NSString *)uapiWithoutKeepaliveLocked {
    NSMutableArray<NSString *> *lines = [NSMutableArray new];
    for (NSString *line in [_uapi componentsSeparatedByString:@"\n"]) {
        if (![line hasPrefix:@"persistent_keepalive_interval="]) {
            [lines addObject:line];
        }
    }
    return [lines componentsJoinedByString:@"\n"];
}

- (BOOL)turnOnWithoutKeepalive:(BOOL)withoutKeepalive error:(NSError **)error {
    __block BOOL ok = NO;
    __block NSString *msg = nil;
    dispatch_sync(_worker, ^{
        if (self->_uapi.length == 0) {
            msg = [NSString stringWithFormat:@"%@: startWithNetworkSettingsCallback did not complete.", self.protocolName];
            return;
        }
        int fd = SRPWGFindUTUNFd();
        if (fd < 0) {
            msg = [NSString stringWithFormat:@"%@: the tunnel interface (utun) was not found — were the network settings applied?", self.protocolName];
            return;
        }
        NSString *settings = withoutKeepalive ? [self uapiWithoutKeepaliveLocked] : self->_uapi;
        self.lastEngineError = nil;
        int32_t handle = [self engineTurnOn:settings fd:fd];
        if (handle < 0) {
            msg = [self refusedMessage];
            return;
        }
        self->_handle = handle;
        ok = YES;
    });
    if (ok) {
        SSLogM(@"%@: device up (utun attached)", self.protocolName);
    } else if (error) {
        *error = [NSError errorWithDomain:@"SRPVPN" code:-1 userInfo:@{NSLocalizedDescriptionKey: msg ?: [NSString stringWithFormat:@"%@ failed to start", self.protocolName]}];
    }
    return ok;
}

/// Why the engine refused the settings, from its log ("Unable to set IPC settings: IPC error -22: failed to parse I1: …"):
/// the I1-I5 chains are the only values the app passes on without checking them itself
- (NSString *)refusedMessage {
    NSString *engine = self.lastEngineError;
    NSRange ipc = engine ? [engine rangeOfString:@"IPC error -?[0-9]+: " options:NSRegularExpressionSearch] : NSMakeRange(NSNotFound, 0);
    if (ipc.location != NSNotFound) {
        return [NSString stringWithFormat:@"%@ refused the configuration: %@", self.protocolName, [engine substringFromIndex:NSMaxRange(ipc)]];
    }
    return [NSString stringWithFormat:@"%@: the engine refused the configuration (see log).", self.protocolName];
}

- (NEPacketTunnelNetworkSettings *)buildSettingsFromConfig:(SRPWGConfig *)cfg endpointIP:(NSString *)endpointIP {
    NEPacketTunnelNetworkSettings *settings =
        [[NEPacketTunnelNetworkSettings alloc] initWithTunnelRemoteAddress:endpointIP];
    settings.MTU = @(SRPWGEffectiveMTU(cfg, _amnezia));

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
        [self stopWatchingLocked];
        if (self->_handle >= 0) {
            [self engineTurnOff:self->_handle];
            self->_handle = -1;
        }
    });
}

- (void)closeAndWait {
    dispatch_sync(_worker, ^{
        [self stopWatchingLocked];
        if (self->_handle >= 0) {
            [self engineTurnOff:self->_handle];
            self->_handle = -1;
        }
    });
}

- (void)pauseForSleep {
    // Called for On Sleep Pause and Off. Unwatched (Aether): nothing to do, sockets are re-bound on wake.
    dispatch_async(_worker, ^{
        if (!self->_managed || self->_handle < 0 || self->_paused) {
            return;
        }
        [self cancelTimer:&self->_pollTimer];
        [self cancelTimer:&self->_monitorTimer];
        [self engineTurnOff:self->_handle];
        self->_handle = -1;
        self->_paused = YES;
        SSLogM(@"%@: closed for sleep (On Sleep %@)", self.protocolName, self->_onSleep == 0 ? @"Off" : @"Pause");
    });
}

- (void)wakeFromSleep {
    dispatch_async(_worker, ^{
        if (self->_managed && self->_paused) {
            [self wakeFromPauseLocked];
            return;
        }
        if (self->_handle >= 0) {
            [self engineBumpSockets:self->_handle];
            [self engineDisableRoaming:self->_handle];
            SSLogM(@"%@: wake — sockets re-bound", self.protocolName);
        }
    });
}

#pragma mark - WireGuard and AmneziaWG: handshake, session watch, sleep and network changes

/// Two handshake initiations: wireguard-go sends one at once and retries every 5 seconds
static const CFAbsoluteTime SRPWGAttemptSeconds = 10;
/// Nothing back for this long while the phone sends: the server stopped answering. A live server answers every data
/// packet within 10 s (a passive keepalive at the latest), and re-handshakes every 2 minutes.
static const CFAbsoluteTime SRPWGSilenceSeconds = 30;
/// The window in which handshakes answered without any traffic show S3, S4 or H4 other than the server's (AmneziaWG)
static const CFAbsoluteTime SRPWGHandshakeOnlySeconds = 40;

+ (NSDictionary<NSString *, NSNumber *> *)peerStateFromUAPI:(NSString *)uapi {
    NSMutableDictionary<NSString *, NSNumber *> *state = [NSMutableDictionary new];
    for (NSString *line in [uapi componentsSeparatedByString:@"\n"]) {
        NSRange equals = [line rangeOfString:@"="];
        if (equals.location == NSNotFound) {
            continue;
        }
        NSString *key = [line substringToIndex:equals.location];
        if ([key isEqualToString:@"last_handshake_time_sec"] || [key isEqualToString:@"rx_bytes"] || [key isEqualToString:@"tx_bytes"]) {
            state[key] = @([[line substringFromIndex:equals.location + 1] longLongValue]);
        }
    }
    return state.count == 3 ? state : nil;
}

- (NSDictionary<NSString *, NSNumber *> *)peerStateLocked {
    if (_handle < 0) {
        return nil;
    }
    char *raw = [self engineGetConfig:_handle];
    if (!raw) {
        return nil;
    }
    NSString *text = [NSString stringWithUTF8String:raw];   // holds the private key: parsed here, never logged
    free(raw);
    return text ? [SRPWireGuardClient peerStateFromUAPI:text] : nil;
}

- (void)setPeerLocked:(NSString *)line {
    if (_handle < 0) {
        return;
    }
    NSString *uapi = [NSString stringWithFormat:@"public_key=%@\nupdate_only=true\n%@\n", _peerHex, line];
    [self engineSetConfig:_handle settings:uapi];
}

- (dispatch_source_t)timerEvery:(NSTimeInterval)seconds handler:(dispatch_block_t)handler {
    dispatch_source_t timer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, _worker);
    dispatch_source_set_timer(timer, dispatch_time(DISPATCH_TIME_NOW, (int64_t)(seconds * NSEC_PER_SEC)),
                              (uint64_t)(seconds * NSEC_PER_SEC), (uint64_t)(0.05 * NSEC_PER_SEC));
    dispatch_source_set_event_handler(timer, handler);
    dispatch_resume(timer);
    return timer;
}

- (void)cancelTimer:(dispatch_source_t __strong *)timer {
    if (*timer) {
        dispatch_source_cancel(*timer);
        *timer = nil;
    }
}

- (void)stopWatchingLocked {
    _closed = YES;
    [self cancelTimer:&_pollTimer];
    [self cancelTimer:&_monitorTimer];
    if (_pathMonitor) {
        nw_path_monitor_cancel(_pathMonitor);
        _pathMonitor = nil;
    }
}

- (void)activateAndWaitForHandshake:(void (^)(NSString *))completion {
    NSError *error = nil;
    if (![self turnOnWithoutKeepalive:YES error:&error]) {
        completion(error.localizedDescription ?: [NSString stringWithFormat:@"%@ failed to start", self.protocolName]);
        return;
    }
    dispatch_async(_worker, ^{
        self->_managed = YES;
        self->_peerFresh = YES;
        self->_activateCompletion = [completion copy];
        self->_attempts = 0;
        [self startPathMonitorLocked];
        [self startAttemptLocked];
    });
}

/// Retry Times: before the first handshake 1 attempt, or 1 + Retry Times with Auto Reconnect (as the other protocols
/// try their remotes); afterwards Retry Times attempts (0 = no limit), one without Auto Reconnect (a wake from Pause)
- (NSInteger)attemptBudgetLocked {
    if (!_up) {
        return (_autoReconnect && _retryTimes > 0) ? 1 + _retryTimes : 1;
    }
    if (!_autoReconnect) {
        return 1;
    }
    return _retryTimes > 0 ? _retryTimes : NSIntegerMax;
}

/// One attempt: a persistent keepalive switched on (from 0) makes wireguard-go send a handshake initiation at once. On a
/// device just turned on that is all; later attempts set the peer up afresh, without the session it had (after a server
/// restart the phone's old session key would only be dropped, and wireguard-go would re-handshake on its own only 2
/// minutes later).
- (void)startAttemptLocked {
    if (_closed || _handle < 0) {
        return;
    }
    _attempts++;
    _attemptStart = CFAbsoluteTimeGetCurrent();
    if (_peerFresh) {
        _peerFresh = NO;
        [self setPeerLocked:[NSString stringWithFormat:@"persistent_keepalive_interval=%ld", (long)(_cfg.keepalive > 0 ? _cfg.keepalive : 25)]];
        _keepaliveTemp = _cfg.keepalive == 0;
        _handshakeBefore = [[self peerStateLocked][@"last_handshake_time_sec"] longLongValue];
        if (_attempts > 1 || _up) {
            SSLogM(@"%@: handshake attempt %ld", self.protocolName, (long)_attempts);
        }
        [self cancelTimer:&_pollTimer];
        __weak SRPWireGuardClient *weakSelf = self;
        _pollTimer = [self timerEvery:0.25 handler:^{ [weakSelf pollAttemptLocked]; }];
        return;
    }
    NSMutableString *peer = [NSMutableString stringWithFormat:@"replace_peers=true\npublic_key=%@\n", _peerHex];
    if (_cfg.presharedKey.length > 0) {
        [peer appendFormat:@"preshared_key=%@\n", SRPWGBase64ToHex(_cfg.presharedKey)];
    }
    [peer appendFormat:@"endpoint=%@:%ld\n", _endpointIP, (long)_cfg.endpointPort];
    for (NSString *ip in _cfg.allowedIPs) {
        [peer appendFormat:@"allowed_ip=%@\n", ip];
    }
    [peer appendFormat:@"persistent_keepalive_interval=%ld\n", (long)(_cfg.keepalive > 0 ? _cfg.keepalive : 25)];
    [self engineSetConfig:_handle settings:peer];
    _keepaliveTemp = _cfg.keepalive == 0;
    _handshakeBefore = [[self peerStateLocked][@"last_handshake_time_sec"] longLongValue];
    if (_attempts > 1 || _up) {
        SSLogM(@"%@: handshake attempt %ld", self.protocolName, (long)_attempts);
    }
    [self cancelTimer:&_pollTimer];
    __weak SRPWireGuardClient *weakSelf = self;
    _pollTimer = [self timerEvery:0.25 handler:^{ [weakSelf pollAttemptLocked]; }];
}

- (void)restoreKeepaliveLocked {
    if (_keepaliveTemp) {
        [self setPeerLocked:@"persistent_keepalive_interval=0"];
        _keepaliveTemp = NO;
    }
}

- (void)pollAttemptLocked {
    NSDictionary<NSString *, NSNumber *> *state = [self peerStateLocked];
    CFAbsoluteTime waited = CFAbsoluteTimeGetCurrent() - _attemptStart;
    if (state && [state[@"last_handshake_time_sec"] longLongValue] > _handshakeBefore) {
        [self cancelTimer:&_pollTimer];
        [self restoreKeepaliveLocked];
        if (!_up) {
            _up = YES;
            SSLogM(@"%@: session established: handshake with %@:%ld after %.1f s", self.protocolName, _cfg.endpointHost, (long)_cfg.endpointPort, waited);
            void (^completion)(NSString *) = _activateCompletion;
            _activateCompletion = nil;
            if (completion) {
                completion(nil);
            }
        } else {
            SSLogM(@"%@: the server answers again: handshake after %.1f s (attempt %ld)", self.protocolName, waited, (long)_attempts);
        }
        _reconnecting = NO;
        _attempts = 0;
        [self startMonitorLocked];
        return;
    }
    if (waited < SRPWGAttemptSeconds) {
        return;
    }
    [self cancelTimer:&_pollTimer];
    SSLogM(@"%@: no handshake in %.0f seconds (attempt %ld)", self.protocolName, SRPWGAttemptSeconds, (long)_attempts);
    if (_attempts < [self attemptBudgetLocked] && !_closed) {
        [self refreshEndpointLocked];
        [self startAttemptLocked];
        return;
    }
    [self restoreKeepaliveLocked];
    NSString *reason = _amnezia ?
        [NSString stringWithFormat:@"The server did not answer the AmneziaWG handshake: the server's public key or the preshared key may not match, the server may not have this profile's public key as a peer, its obfuscation settings (S1-S4, H1-H4, HeaderProtectionKey, RandomTrailers) may differ from this profile's, or UDP port %ld may be closed.", (long)_cfg.endpointPort] :
        [NSString stringWithFormat:@"The server did not answer the WireGuard handshake: the server's public key or the preshared key may not match, the server may not have this profile's public key as a peer, or UDP port %ld may be closed.", (long)_cfg.endpointPort];
    if (_attempts > 1) {
        reason = [NSString stringWithFormat:@"Could not %@ after %ld attempt%@. (The server did not answer the %@ handshake.)",
                  _up ? @"reconnect" : @"connect", (long)_attempts, _attempts == 1 ? @"" : @"s", self.protocolName];
    } else if (_up) {
        reason = [NSString stringWithFormat:@"Could not reconnect: the server did not answer the %@ handshake.", self.protocolName];
    }
    if (!_up) {
        SSLogM(@"%@: closing with reason: %@", self.protocolName, reason);
        void (^completion)(NSString *) = _activateCompletion;
        _activateCompletion = nil;
        if (completion) {
            completion(reason);
        }
        return;
    }
    [self giveUpLocked:reason];
}

- (void)giveUpLocked:(NSString *)reason {
    SSLogM(@"%@: closing with reason: %@", self.protocolName, reason);
    [self stopWatchingLocked];
    if (_handle >= 0) {
        [self engineTurnOff:_handle];
        _handle = -1;
    }
    if (_lostCallback) {
        _lostCallback(reason);
    }
}

- (void)startMonitorLocked {
    [self cancelTimer:&_monitorTimer];
    _samples = [NSMutableArray new];
    _lastCounterLine = CFAbsoluteTimeGetCurrent();
    __weak SRPWireGuardClient *weakSelf = self;
    _monitorTimer = [self timerEvery:5 handler:^{ [weakSelf monitorLocked]; }];
}

- (void)monitorLocked {
    if (_reconnecting || _paused || _handle < 0) {
        return;
    }
    NSDictionary<NSString *, NSNumber *> *state = [self peerStateLocked];
    if (!state) {
        return;
    }
    CFAbsoluteTime now = CFAbsoluteTimeGetCurrent();
    long long rx = [state[@"rx_bytes"] longLongValue], tx = [state[@"tx_bytes"] longLongValue];
    long long handshake = [state[@"last_handshake_time_sec"] longLongValue];
    [_samples addObject:@[@(now), @(rx), @(tx), @(handshake)]];
    while (_samples.count > 0 && now - _samples.firstObject[0].doubleValue > 60) {
        [_samples removeObjectAtIndex:0];
    }
    if (_logLevel >= 1 && now - _lastCounterLine >= 30) {
        _lastCounterLine = now;
        SSLogM(@"%@: last handshake %lld s ago, received %lld bytes, sent %lld bytes", self.protocolName,
               handshake > 0 ? (long long)NSDate.date.timeIntervalSince1970 - handshake : -1, rx, tx);
    }
    NSArray<NSNumber *> *base = nil;
    for (NSArray<NSNumber *> *sample in _samples) {
        if (now - sample[0].doubleValue >= SRPWGSilenceSeconds) {
            base = sample;
        }
    }
    if (base && rx == base[1].longLongValue && tx - base[2].longLongValue >= _silenceBytes) {
        [self peerLostLocked];
        return;
    }
    // AmneziaWG: a server whose S3, S4 or H4 differ from the profile's answers every handshake (S1, S2, H1 and H2 match) and drops
    // every data packet. The engine, hearing nothing back while it sends, starts a new handshake every 15 s or so, each answered,
    // so the server never falls silent. Two or more handshakes in 40 s that brought back nothing but their answers (92 + S2
    // bytes, a random trailer at most 500 more), while the phone sent, end the VPN with that reason: a new handshake would only
    // be answered the same way.
    NSArray<NSNumber *> *older = nil;
    for (NSArray<NSNumber *> *sample in _samples) {
        if (now - sample[0].doubleValue >= SRPWGHandshakeOnlySeconds) {
            older = sample;
        }
    }
    if (_amnezia && older) {
        NSInteger handshakes = 0;
        long long last = older[3].longLongValue;
        for (NSArray<NSNumber *> *sample in _samples) {
            if (sample[0].doubleValue > older[0].doubleValue && sample[3].longLongValue != last) {
                handshakes++;
                last = sample[3].longLongValue;
            }
        }
        long long answers = handshakes * (92 + MAX(0, _cfg.s2) + 500);
        if (handshakes >= 2 && rx - older[1].longLongValue <= answers && tx - older[2].longLongValue >= _silenceBytes) {
            NSString *reason = @"The server answers the AmneziaWG handshake but none of the traffic: S3, S4 or H4 may differ from the server's.";
            SSLogM(@"AmneziaWG: %ld handshakes in %.0f seconds were answered, nothing else came back", (long)handshakes, SRPWGHandshakeOnlySeconds);
            [self giveUpLocked:reason];
        }
    }
}

- (void)peerLostLocked {
    NSString *reason = [NSString stringWithFormat:@"The server stopped answering: nothing came back for %.0f seconds", SRPWGSilenceSeconds];
    SSLogM(@"%@: %@", self.protocolName, reason);
    if (!_autoReconnect) {
        [self giveUpLocked:[reason stringByAppendingString:@" (auto reconnect is off)."]];
        return;
    }
    [self cancelTimer:&_monitorTimer];
    _reconnecting = YES;
    _attempts = 0;
    [self refreshEndpointLocked];
    [self startAttemptLocked];
}

/// The endpoint's name may point elsewhere now (or resolve differently on the new network); the sockets move to the
/// network the phone uses now, as the official WireGuard app does on every network change
- (void)refreshEndpointLocked {
    if (_handle < 0) {
        return;
    }
    NSString *ip = SRPWGResolveIPv4(_cfg.endpointHost);
    if (ip && ![ip isEqualToString:_endpointIP]) {
        SSLogM(@"%@: %@ is now %@", self.protocolName, _cfg.endpointHost, ip);
        _endpointIP = ip;
        [self setPeerLocked:[NSString stringWithFormat:@"endpoint=%@:%ld", ip, (long)_cfg.endpointPort]];
        if (_settingsCb) {
            _settingsCb([self buildSettingsFromConfig:_cfg endpointIP:ip]);
        }
    }
    [self engineBumpSockets:_handle];
}

- (void)startPathMonitorLocked {
    if (_pathMonitor) {
        return;
    }
    _pathMonitor = nw_path_monitor_create();
    nw_path_monitor_set_queue(_pathMonitor, _worker);
    __weak SRPWireGuardClient *weakSelf = self;
    nw_path_monitor_set_update_handler(_pathMonitor, ^(nw_path_t path) {
        [weakSelf pathUpdatedLocked:path];
    });
    nw_path_monitor_start(_pathMonitor);
}

- (void)pathUpdatedLocked:(nw_path_t)path {
    if (nw_path_get_status(path) != nw_path_status_satisfied) {
        return;
    }
    NSMutableArray<NSString *> *names = [NSMutableArray new];
    nw_path_enumerate_interfaces(path, ^bool(nw_interface_t interface) {
        [names addObject:@(nw_interface_get_name(interface))];
        return true;
    });
    NSString *key = [names componentsJoinedByString:@","];
    BOOL first = _pathKey == nil;
    BOOL changed = ![key isEqualToString:_pathKey];
    _pathKey = key;
    if (first || !changed || _handle < 0 || _paused) {
        return;
    }
    NSString *kind = nw_path_uses_interface_type(path, nw_interface_type_wifi) ? @"Wi-Fi" :
                     nw_path_uses_interface_type(path, nw_interface_type_cellular) ? @"cellular" : key;
    SSLogM(@"%@: network changed (%@): the sockets move to it", self.protocolName, kind);
    [self refreshEndpointLocked];
    [self engineDisableRoaming:_handle];
}

- (void)switchNetworkPath {
    dispatch_async(_worker, ^{
        if (!self->_managed || self->_handle < 0) {
            return;
        }
        SSLogM(@"%@: re-binding the sockets on the current network", self.protocolName);
        [self refreshEndpointLocked];
        [self engineDisableRoaming:self->_handle];
    });
}

- (void)wakeFromPauseLocked {
    _paused = NO;
    if (_onSleep == 0 && !_autoReconnect) {
        [self giveUpLocked:@"The connection was closed while the device slept."];
        return;
    }
    SSLogM(@"%@: awake: connecting again", self.protocolName);
    int fd = SRPWGFindUTUNFd();
    int32_t handle = fd >= 0 ? [self engineTurnOn:[self uapiWithoutKeepaliveLocked] fd:fd] : -1;
    if (handle < 0) {
        [self giveUpLocked:[NSString stringWithFormat:@"%@ could not start again after sleep.", self.protocolName]];
        return;
    }
    _handle = handle;
    _reconnecting = YES;
    _peerFresh = YES;
    _attempts = 0;
    [self startAttemptLocked];
}

- (void)dealloc {
    [self closeAndWait];
}

@end
