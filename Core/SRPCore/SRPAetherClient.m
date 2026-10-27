//
//  SRPAetherClient.m
//  SRPCore
//

#import "SRPAetherClient.h"
#import "SSLog.h"
#import <NetworkExtension/NetworkExtension.h>
#import <arpa/inet.h>
#import <fcntl.h>
#import <sys/socket.h>
#import <unistd.h>

// Aether engine (Rust, staticlib) — pinned commit; see Aether/build_aether.sh
extern char *aether_version(void);
extern char *aether_identity_open(const char *payload);
extern char *aether_scan_start(uint64_t identity, const char *payload);
extern char *aether_verify_start(uint64_t identity, const char *payload);
extern char *aether_tunnel_start(uint64_t identity, const char *payload);
extern char *aether_job_poll(uint64_t id);
extern char *aether_job_cancel(uint64_t id);
extern char *aether_job_free(uint64_t id);
extern void aether_string_free(char *s);

// hev-socks5-tunnel core (built into the SSH engine lib, srpssh_ prefix)
extern int srpssh_hev_socks5_tunnel_main_from_str(const unsigned char *conf, unsigned int len, int tun_fd);
extern void srpssh_hev_socks5_tunnel_quit(void);

#define SRPAETHER_SOCKS_PORT 1819
#define SRPAETHER_RELAY_PORT 18191

// wireguard-go netstack relay (WireGuard bridge, srpwg_* symbols)
extern int32_t srpwgNetstackStart(const char *uapi, const char *ifAddr, const char *listenAddr, const char *targetAddr);
extern void srpwgNetstackStop(int32_t handle);
extern void wgSetLogger(void *ctx, void *fn);

static void SRPAetherWGLog(void *ctx, int level, const char *msg) {
    (void)ctx;
    if (!msg) return;
    if (level == 0 && !SSLogEnabled(SSLogLevelDebug)) return;
    SSLogM(@"[wg-ns] %s", msg);
}

@implementation SRPAetherClient {
    SRPAetherOutputCallback _outputCb;
    SRPAetherNetworkSettingsCallback _settingsCb;
    SRPAetherConnectedCallback _connectedCb;
    SRPAetherFailureCallback _failureCb;
    dispatch_queue_t _worker;
    dispatch_source_t _readSource;
    dispatch_source_t _monitorTimer;
    BOOL _retryScheduled;
    NSArray<NSData *> *_pendingPackets;
    NSUInteger _pendingPacketIndex;
    dispatch_block_t _injectionCompletion;
    NSString *_endpointIP;
    int _tunFd;             // our end of the hev channel
    int _socksPort;         // hev's SOCKS5 upstream (engine or WG relay)
    BOOL _privateMode;      // WG->Aether-proxy chain (mapdns, no engine)
    uint64_t _identityId;
    uint64_t _tunnelJobId;
    int32_t _nsHandle;      // netstack WireGuard relay (private mode)
    NSThread *_hevThread;
    BOOL _closed;
    BOOL _up;
    SRPWireGuardClient *_wgClient;   // WARP WireGuard transport
    BOOL _usingWireGuardEngine;
}

- (instancetype)init {
    self = [super init];
    if (self) {
        _worker = dispatch_queue_create("srp.aether", DISPATCH_QUEUE_SERIAL);
        _transport = @"masque";
        _scanProfile = @"balanced";
        _tunFd = -1;
        _nsHandle = -1;
        _socksPort = SRPAETHER_SOCKS_PORT;
    }
    return self;
}

#pragma mark - engine JSON calls

/// One synchronous FFI call; returns the parsed JSON object.
- (NSDictionary *)callJson:(char *(^)(void))fn {
    char *raw = fn();
    if (!raw) return @{@"ok": @NO, @"error": @"no reply from the engine"};
    NSString *text = @(raw);
    aether_string_free(raw);
    return [NSJSONSerialization JSONObjectWithData:[text dataUsingEncoding:NSUTF8StringEncoding]
                                           options:0 error:nil] ?: @{@"ok": @NO, @"error": @"bad engine reply"};
}

/// Poll a job to completion; returns the result object or nil on error.
- (NSDictionary *)waitJob:(uint64_t)jobId timeoutSec:(NSInteger)timeoutSec {
    NSDate *deadline = [NSDate dateWithTimeIntervalSinceNow:timeoutSec];
    while (YES) {
        if (_closed) { aether_job_cancel(jobId); return nil; }
        NSDictionary *poll = [self callJson:^{ return aether_job_poll(jobId); }];
        NSString *state = poll[@"state"];
        if ([state isEqualToString:@"done"]) {
            NSDictionary *result = poll[@"result"];
            aether_job_free(jobId);
            if ([result isKindOfClass:NSDictionary.class] && [result[@"ok"] boolValue]) {
                return result;
            }
            NSString *err = [result isKindOfClass:NSDictionary.class] ? result[@"error"] : nil;
            SSLogM(@"Aether: job %llu failed: %@", jobId, err ?: @"unknown");
            return nil;
        }
        if ([[NSDate date] compare:deadline] == NSOrderedDescending) {
            SSLogM(@"Aether: job %llu timed out", jobId);
            aether_job_cancel(jobId);
            aether_job_free(jobId);
            return nil;
        }
        usleep(150000);
    }
}

- (uint64_t)startJob:(char *(^)(void))fn {
    NSDictionary *reply = [self callJson:fn];
    if (![reply[@"ok"] boolValue]) {
        SSLogM(@"Aether: job start failed: %@", reply[@"error"] ?: @"unknown");
        return 0;
    }
    return [reply[@"job"] unsignedLongLongValue];
}

#pragma mark - lifecycle

- (void)startWithOutputCallback:(SRPAetherOutputCallback)output
         networkSettingsCallback:(SRPAetherNetworkSettingsCallback)settings
               connectedCallback:(SRPAetherConnectedCallback)connected
                 failureCallback:(SRPAetherFailureCallback)failure {
    _outputCb = output;
    _settingsCb = settings;
    _connectedCb = connected;
    _failureCb = failure;
    _closed = NO;
    SSLogSetLevel((SSLogLevel)_logLevel);
    // Engine logs (env_logger) go to stderr -> the tunnel log
    setenv("RUST_LOG", _logLevel >= 2 ? "trace" : "info", 1);
    // SPKI pinning on — the upstream default is NO verification (spec P0)
    setenv("AETHER_TLS_VERIFY", "1", 1);
    unsetenv("AETHER_UPSTREAM");
    unsetenv("AETHER_MASQUE_HTTP2");
    unsetenv("AETHER_MASQUE_H2_FRAGMENT");
    unsetenv("AETHER_MASQUE_H2_FRAGMENT_SIZE");
    unsetenv("AETHER_MASQUE_H2_FRAGMENT_SNI");
    SSLogM(@"Aether: transport=%@ scan=%@ fragMode=%ld", _transport, _scanProfile, (long)_fragMode);
    dispatch_async(_worker, ^{ [self startLocked]; });
}

- (void)startLocked {
    if (_privateConfig.length > 0) {
        [self startPrivateLocked];
        return;
    }
    if ([_torMode isEqualToString:@"only"]) {
        [self startTorOnlyLocked];
        return;
    }
    if ([_torMode isEqualToString:@"reverse"]) {
        NSString *torDir = [_identityDir stringByAppendingPathComponent:@"tor"];
        [[NSFileManager defaultManager] createDirectoryAtPath:torDir
                                  withIntermediateDirectories:YES attributes:nil error:nil];
        setenv("AETHER_TOR_DIR", torDir.UTF8String, 1);
        if (![_transport hasPrefix:@"masque"]) {
            SSLogM(@"Aether: tor-reverse needs MASQUE H2 — overriding the selected transport");
        }
        _transport = @"masque-h2";
    }

    BOOL wireGuard = [_transport isEqualToString:@"wg"];
    NSString *engineTransport = wireGuard ? @"wg" : @"masque";
    if (!wireGuard) {
        [self configureMasqueCarrierLocked:![_transport isEqualToString:@"masque"]];
    }
    NSString *base = [_identityDir stringByAppendingPathComponent:@"identity.toml"];
    [[NSFileManager defaultManager] createDirectoryAtPath:_identityDir
                              withIntermediateDirectories:YES attributes:nil error:nil];
    NSDictionary *openPayload = @{
        @"path": base,
        @"transport": engineTransport,
        @"model": @"PC",
        @"locale": @"en",
    };
    NSString *openJson = [[NSString alloc] initWithData:[NSJSONSerialization dataWithJSONObject:openPayload options:0 error:nil] encoding:NSUTF8StringEncoding];
    uint64_t job = [self startJob:^{ return aether_identity_open(openJson.UTF8String); }];
    NSDictionary *opened = job ? [self waitJob:job timeoutSec:120] : nil;
    if (!opened) {
        if (!_closed) _failureCb(@"Aether: identity provisioning failed (network unreachable?)");
        return;
    }
    _identityId = [opened[@"identity"] unsignedLongLongValue];
    SSLogM(@"Aether: identity ready (id %llu)", _identityId);

    if (_licenseKey.length > 0) {
        NSString *license = [_licenseKey stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
        NSString *dir = _identityDir;
        dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
            [SRPAetherClient applyWarpLicense:license identityDir:dir transport:engineTransport];
        });
    }

    if (wireGuard) {
        unsetenv("AETHER_MASQUE_HTTP2");
        NSString *endpoint = [self findEndpointLockedUsingH2:NO];
        if (endpoint.length == 0) {
            if (!_closed) _failureCb(@"Aether: no reachable WireGuard endpoint found");
            return;
        }
        [self startWireGuardLocked:endpoint];
        return;
    }

    NSArray *carriers;
    if ([_torMode isEqualToString:@"reverse"] || [_transport isEqualToString:@"masque-h2"]) {
        carriers = @[@YES];
    } else if ([_transport isEqualToString:@"masque-both"]) {
        carriers = @[@NO, @YES];
    } else {
        carriers = @[@NO];
    }
    for (NSNumber *carrier in carriers) {
        if (_closed) return;
        BOOL h2 = carrier.boolValue;
        [self configureMasqueCarrierLocked:h2];
        NSString *endpoint = [self findEndpointLockedUsingH2:h2];
        if (endpoint.length > 0 && [self startMasqueTunnelLocked:endpoint usingH2:h2]) {
            return;
        }
        [self stopTunnelAttemptLocked];
        if (![carrier isEqual:carriers.lastObject] && !_closed) {
            SSLogM(@"Aether: MASQUE H3 unavailable — falling back to H2");
        }
    }
    if (!_closed) _failureCb(@"Aether: no reachable MASQUE endpoint or the tunnel data-plane did not come up");
}

- (void)configureMasqueCarrierLocked:(BOOL)h2 {
    if (h2) {
        setenv("AETHER_MASQUE_HTTP2", "1", 1);
    } else {
        unsetenv("AETHER_MASQUE_HTTP2");
    }
    if (h2 && _fragMode > 0) {
        setenv("AETHER_MASQUE_H2_FRAGMENT", "1", 1);
        if (_fragMode == 2 && _fragMin > 0 && _fragMax >= _fragMin) {
            NSString *range = [NSString stringWithFormat:@"%ld-%ld", (long)_fragMin, (long)_fragMax];
            setenv("AETHER_MASQUE_H2_FRAGMENT_SIZE", range.UTF8String, 1);
            unsetenv("AETHER_MASQUE_H2_FRAGMENT_SNI");
        } else {
            unsetenv("AETHER_MASQUE_H2_FRAGMENT_SIZE");
            setenv("AETHER_MASQUE_H2_FRAGMENT_SNI", "1", 1);
        }
    } else {
        unsetenv("AETHER_MASQUE_H2_FRAGMENT");
        unsetenv("AETHER_MASQUE_H2_FRAGMENT_SIZE");
        unsetenv("AETHER_MASQUE_H2_FRAGMENT_SNI");
    }
}

- (NSString *)findEndpointLockedUsingH2:(BOOL)h2 {
    if ([_torMode isEqualToString:@"reverse"]) {
        _endpointIP = @"162.159.198.2";
        return @"162.159.198.2:443";
    }
    BOOL wireGuard = [_transport isEqualToString:@"wg"];
    NSString *engineTransport = wireGuard ? @"wg" : @"masque";
    NSString *cacheKey = wireGuard ? @"SRPAetherLastGoodWG" : (h2 ? @"SRPAetherLastGoodH2" : @"SRPAetherLastGoodH3");
    NSUserDefaults *shared = [[NSUserDefaults alloc] initWithSuiteName:@"group.tr.com.srp.vpn"];
    NSString *cached = [shared stringForKey:cacheKey];
    if (cached.length == 0 && !wireGuard && !h2) {
        cached = [shared stringForKey:@"SRPAetherLastGood"];
    }
    NSMutableArray *candidates = [NSMutableArray arrayWithObjects:@"162.159.198.2:443", @"162.159.198.1:443", nil];
    if (cached.length > 0 && ![candidates containsObject:cached]) {
        [candidates insertObject:cached atIndex:0];
    }
    NSInteger verifyTimeout = [_transport isEqualToString:@"masque-both"] && !h2 ? 10 : 20;
    for (NSString *candidate in candidates) {
        if (_closed) return nil;
        NSDictionary *verifyPayload = @{@"peer": candidate, @"transport": engineTransport};
        NSString *verifyJson = [[NSString alloc] initWithData:[NSJSONSerialization dataWithJSONObject:verifyPayload options:0 error:nil] encoding:NSUTF8StringEncoding];
        uint64_t job = [self startJob:^{ return aether_verify_start(self->_identityId, verifyJson.UTF8String); }];
        NSDictionary *verified = job ? [self waitJob:job timeoutSec:verifyTimeout] : nil;
        if ([verified[@"reachable"] boolValue]) {
            SSLogM(@"Aether: verified %@ endpoint %@ (fast path)", h2 ? @"H2" : (wireGuard ? @"WG" : @"H3"), candidate);
            [shared setObject:candidate forKey:cacheKey];
            _endpointIP = [[candidate componentsSeparatedByString:@":"] firstObject];
            return candidate;
        }
    }

    NSString *mode = _scanProfile.length > 0 ? _scanProfile : @"balanced";
    NSDictionary *scanPayload = @{@"transport": engineTransport, @"mode": mode};
    NSString *scanJson = [[NSString alloc] initWithData:[NSJSONSerialization dataWithJSONObject:scanPayload options:0 error:nil] encoding:NSUTF8StringEncoding];
    uint64_t job = [self startJob:^{ return aether_scan_start(self->_identityId, scanJson.UTF8String); }];
    NSDictionary *scanned = job ? [self waitJob:job timeoutSec:[mode isEqualToString:@"turbo"] ? 90 : 240] : nil;
    id ep = scanned[@"endpoint"];
    NSString *endpoint;
    if ([ep isKindOfClass:NSString.class]) {
        endpoint = ep;
    } else if ([ep isKindOfClass:NSDictionary.class]) {
        endpoint = [NSString stringWithFormat:@"%@:%@", ep[@"ip"], ep[@"port"]];
    }
    if (endpoint.length == 0) return nil;
    SSLogM(@"Aether: %@ endpoint %@ (%@ scan)", h2 ? @"H2" : (wireGuard ? @"WG" : @"H3"), endpoint, mode);
    [shared setObject:endpoint forKey:cacheKey];
    _endpointIP = [[endpoint componentsSeparatedByString:@":"] firstObject];
    return endpoint;
}

- (void)monitorTunnelJobLocked {
    if (_monitorTimer || _tunnelJobId == 0 || _closed) return;
    _monitorTimer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, _worker);
    dispatch_source_set_timer(_monitorTimer, dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC), 5 * NSEC_PER_SEC, NSEC_PER_SEC);
    dispatch_source_set_event_handler(_monitorTimer, ^{
        if (self->_closed || self->_tunnelJobId == 0) return;
        uint64_t jobId = self->_tunnelJobId;
        NSDictionary *poll = [self callJson:^{ return aether_job_poll(jobId); }];
        if (![poll[@"state"] isEqualToString:@"done"]) return;
        self->_tunnelJobId = 0;
        aether_job_free(jobId);
        dispatch_source_cancel(self->_monitorTimer);
        self->_monitorTimer = nil;
        self->_up = NO;
        if (self->_failureCb) self->_failureCb(@"Aether: the tunnel stopped unexpectedly");
    });
    dispatch_resume(_monitorTimer);
}

- (BOOL)startMasqueTunnelLocked:(NSString *)endpoint usingH2:(BOOL)h2 {
    NSMutableDictionary *tunnelPayload = [@{
        @"peer": endpoint,
        @"transport": @"masque",
        @"socks": [NSString stringWithFormat:@"127.0.0.1:%d", SRPAETHER_SOCKS_PORT],
    } mutableCopy];
    if ([_torMode isEqualToString:@"reverse"]) {
        tunnelPayload[@"tor"] = @"reverse";
    }
    NSString *tunnelJson = [[NSString alloc] initWithData:[NSJSONSerialization dataWithJSONObject:tunnelPayload options:0 error:nil] encoding:NSUTF8StringEncoding];
    _tunnelJobId = [self startJob:^{ return aether_tunnel_start(self->_identityId, tunnelJson.UTF8String); }];
    if (_tunnelJobId == 0) return NO;

    NSInteger readyTimeout = [_torMode isEqualToString:@"reverse"] ? 180 : 60;
    if (![self waitSocksReadyLocked:readyTimeout]) return NO;
    if (![self startHevLocked]) return NO;

    if (_settingsCb) _settingsCb([self buildSettings:_endpointIP]);
    _up = YES;
    if (_connectedCb) _connectedCb();
    [self monitorTunnelJobLocked];
    SSLogM(@"Aether: session established over MASQUE %@", h2 ? @"H2" : @"H3");
    [self monitorTunnelJobLocked];
    return YES;
}

- (void)stopTunnelAttemptLocked {
    if (_tunnelJobId == 0) return;
    uint64_t jobId = _tunnelJobId;
    _tunnelJobId = 0;
    aether_job_cancel(jobId);
    NSDate *deadline = [NSDate dateWithTimeIntervalSinceNow:15];
    while ([[NSDate date] compare:deadline] != NSOrderedDescending) {
        NSDictionary *poll = [self callJson:^{ return aether_job_poll(jobId); }];
        if ([poll[@"state"] isEqualToString:@"done"]) break;
        usleep(100000);
    }
    aether_job_free(jobId);
}

/// Tor-only: the engine runs arti alone and serves SOCKS5 — no identity, no
/// WARP. Tor carries TCP only, so DNS goes through hev's mapped-DNS (fake
/// 198.18.x.x addresses; connections carry the hostname, Tor resolves it).
- (void)startTorOnlyLocked {
    _privateMode = YES;   // reuse the mapped-DNS hev layout and settings
    NSString *torDir = [_identityDir stringByAppendingPathComponent:@"tor"];
    [[NSFileManager defaultManager] createDirectoryAtPath:torDir
                              withIntermediateDirectories:YES attributes:nil error:nil];
    setenv("AETHER_TOR_DIR", torDir.UTF8String, 1);

    NSDictionary *tunnelPayload = @{
        @"peer": @"127.0.0.1:443",   // unused in tor-only
        @"transport": @"masque",
        @"socks": [NSString stringWithFormat:@"127.0.0.1:%d", SRPAETHER_SOCKS_PORT],
        @"tor": @"only",
    };
    NSString *tunnelJson = [[NSString alloc] initWithData:[NSJSONSerialization dataWithJSONObject:tunnelPayload options:0 error:nil] encoding:NSUTF8StringEncoding];
    _tunnelJobId = [self startJob:^{ return aether_tunnel_start(0, tunnelJson.UTF8String); }];
    if (_tunnelJobId == 0) {
        _failureCb(@"Aether: the Tor job did not start");
        return;
    }
    SSLogM(@"Aether: tor-only — bootstrapping Tor (can take a minute on first run)");
    if (![self waitSocksReadyLocked:180]) {
        _failureCb(@"Aether: Tor did not come up in time");
        aether_job_cancel(_tunnelJobId);
        return;
    }
    if (![self startHevLocked]) {
        _failureCb(@"Aether: the packet bridge failed to start");
        aether_job_cancel(_tunnelJobId);
        return;
    }
    if (_settingsCb) _settingsCb([self buildSettings:@""]);
    _up = YES;
    if (_connectedCb) _connectedCb();
    [self monitorTunnelJobLocked];
    SSLogM(@"Aether: session established (tor-only)");
}

/// Private mode: own server per Docs/Aether_VPS_Personal_Deployment_Guide —
/// the device runs no engine. utun -> hev -> SOCKS5 -> loopback relay ->
/// WireGuard (netstack, no real utun) -> Aether SOCKS5 on the VPS -> WARP.
- (void)startPrivateLocked {
    _privateMode = YES;
    NSString *parseError = nil;
    NSDictionary *params = [SRPWireGuardClient netstackParametersFromConfig:_privateConfig error:&parseError];
    if (!params) {
        _failureCb([NSString stringWithFormat:@"Aether private: %@", parseError ?: @"invalid WireGuard config"]);
        return;
    }
    _endpointIP = params[@"endpointIP"];

    // The VPS-hosted Aether proxy listens on the server's tunnel address —
    // per the guide, <wg-subnet>.1:1819 derived from the client's address.
    NSString *clientAddr = params[@"address"];
    NSArray *octets = [clientAddr componentsSeparatedByString:@"."];
    if (octets.count != 4) {
        _failureCb(@"Aether private: the interface address must be IPv4");
        return;
    }
    NSString *target = [NSString stringWithFormat:@"%@.%@.%@.1:%d",
                        octets[0], octets[1], octets[2], SRPAETHER_SOCKS_PORT];

    wgSetLogger(NULL, SRPAetherWGLog);
    _socksPort = SRPAETHER_RELAY_PORT;
    NSString *listen = [NSString stringWithFormat:@"127.0.0.1:%d", SRPAETHER_RELAY_PORT];
    _nsHandle = srpwgNetstackStart([params[@"uapi"] UTF8String], clientAddr.UTF8String,
                                   listen.UTF8String, target.UTF8String);
    if (_nsHandle < 0) {
        _failureCb(@"Aether private: the WireGuard relay failed to start");
        return;
    }
    SSLogM(@"Aether private: WG relay up — %@ via %@", target, _endpointIP);

    // End-to-end readiness: relay + WG handshake + the server's Aether proxy
    if (![self waitSocksReadyLocked:30]) {
        _failureCb(@"Aether private: the server's Aether proxy did not answer (is the container up?)");
        return;
    }
    if (![self startHevLocked]) {
        _failureCb(@"Aether: the packet bridge failed to start");
        return;
    }
    if (_settingsCb) _settingsCb([self buildSettings:_endpointIP]);
    _up = YES;
    if (_connectedCb) _connectedCb();
    [self monitorTunnelJobLocked];
    SSLogM(@"Aether: session established (private)");
}

- (BOOL)startHevLocked {
    int fds[2];
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, fds) != 0) return NO;
    _tunFd = fds[0];
    int hevFd = fds[1];   // C arrays cannot be captured by blocks

    // Default local-dgram buffers are ~4KB — a phone's connect-time burst
    // overruns them instantly (same fix as the SSH bridge).
    int bufsz = 512 * 1024;
    setsockopt(fds[0], SOL_SOCKET, SO_RCVBUF, &bufsz, sizeof(bufsz));
    setsockopt(fds[0], SOL_SOCKET, SO_SNDBUF, &bufsz, sizeof(bufsz));
    setsockopt(fds[1], SOL_SOCKET, SO_RCVBUF, &bufsz, sizeof(bufsz));
    setsockopt(fds[1], SOL_SOCKET, SO_SNDBUF, &bufsz, sizeof(bufsz));
    // The dispatch-source read loop below must never park on a blocking
    // read() — that would seize the worker queue and freeze injectPacket.
    fcntl(fds[0], F_SETFL, O_NONBLOCK);

    // Private mode: the relay is TCP-only, so UDP cannot ride the SOCKS5
    // link — DNS is answered locally by hev's mapped-DNS instead (fake IPs;
    // connections then carry the hostname, and the VPS Aether proxy resolves
    // it), exactly like the SSH VPN path.
    NSString *conf;
    if (_privateMode) {
        conf = [NSString stringWithFormat:
            @"tunnel:\n"
            @"  mtu: 1400\n"
            @"  ipv4: 198.18.0.1\n"
            @"socks5:\n"
            @"  port: %d\n"
            @"  address: '127.0.0.1'\n"
            @"  udp: 'tcp'\n"
            @"  pipeline: true\n"
            @"mapdns:\n"
            @"  address: 198.18.0.2\n"
            @"  port: 53\n"
            @"  network: 198.18.0.0\n"
            @"  netmask: 255.255.0.0\n"
            @"  cache-size: 2048\n"
            @"misc:\n"
            @"  log-file: stderr\n"
            @"  log-level: %@\n",
            _socksPort, _logLevel >= 2 ? @"debug" : @"info"];
    } else {
    conf = [NSString stringWithFormat:
        @"tunnel:\n"
        @"  mtu: 1400\n"
        @"  ipv4: 10.89.0.1\n"
        @"socks5:\n"
        @"  port: %d\n"
        @"  address: '127.0.0.1'\n"
        @"  udp: 'udp'\n"
        @"  pipeline: true\n"
        @"misc:\n"
        @"  log-file: stderr\n"
        @"  log-level: %@\n",
        _socksPort, _logLevel >= 2 ? @"debug" : @"info"];
    }

    __weak SRPAetherClient *weakSelf = self;
    _hevThread = [[NSThread alloc] initWithBlock:^{
        int r = srpssh_hev_socks5_tunnel_main_from_str((const unsigned char *)conf.UTF8String,
                                                       (unsigned int)strlen(conf.UTF8String), hevFd);
        SSLogM(@"Aether: packet bridge exited (%d)", r);
        SRPAetherClient *strongSelf = weakSelf;
        if (strongSelf && !strongSelf->_closed && strongSelf->_failureCb)
            strongSelf->_failureCb(@"Aether: the packet bridge stopped");
    }];
    _hevThread.name = @"aether-hev";
    [_hevThread start];

    // read from the bridge -> output (phone)
    _readSource = dispatch_source_create(DISPATCH_SOURCE_TYPE_READ, _tunFd, 0, _worker);
    dispatch_source_set_event_handler(_readSource, ^{
        SRPAetherClient *strongSelf = weakSelf;
        if (!strongSelf) return;
        uint8_t buf[65535];
        ssize_t n;
        while ((n = read(strongSelf->_tunFd, buf, sizeof(buf))) > 0) {
            if (n < 24) continue;
            // strip the 4-byte Darwin utun header the hev core prepends
            uint8_t *pkt = buf + 4;
            int fam = (pkt[0] >> 4) == 6 ? AF_INET6 : AF_INET;
            if (strongSelf->_outputCb)
                strongSelf->_outputCb([NSData dataWithBytes:pkt length:(NSUInteger)(n - 4)], fam);
        }
    });
    dispatch_source_set_cancel_handler(_readSource, ^{
        SRPAetherClient *strongSelf = weakSelf;
        if (strongSelf && strongSelf->_tunFd >= 0) { close(strongSelf->_tunFd); strongSelf->_tunFd = -1; }
    });
    dispatch_resume(_readSource);
    return YES;
}

- (NEPacketTunnelNetworkSettings *)buildSettings:(NSString *)endpointIP {
    // The tunnel remote is the WARP edge (also excluded from the tunnel
    // routes); the engine's local SOCKS5 is loopback
    NSString *remote = endpointIP.length > 0 ? endpointIP : @"162.159.192.1";
    NEPacketTunnelNetworkSettings *settings =
        [[NEPacketTunnelNetworkSettings alloc] initWithTunnelRemoteAddress:remote];
    if (_privateMode) {
        // Mapped-DNS layout (same as the SSH bridge): 198.18.0.2 answers DNS
        // locally with fake 198.18.x.x addresses; connections carry the name.
        NEIPv4Settings *v4 = [[NEIPv4Settings alloc] initWithAddresses:@[@"198.18.0.1"]
                                                           subnetMasks:@[@"255.255.255.255"]];
        v4.includedRoutes = @[NEIPv4Route.defaultRoute];
        if (endpointIP.length > 0) {
            v4.excludedRoutes = @[[[NEIPv4Route alloc] initWithDestinationAddress:endpointIP
                                                                      subnetMask:@"255.255.255.255"]];
        }
        settings.IPv4Settings = v4;
        settings.MTU = @(1400);
        settings.DNSSettings = [[NEDNSSettings alloc] initWithServers:@[@"198.18.0.2"]];
        return settings;
    }
    NEIPv4Settings *v4 = [[NEIPv4Settings alloc] initWithAddresses:@[@"10.89.0.1"]
                                                       subnetMasks:@[@"255.255.255.0"]];
    v4.includedRoutes = @[NEIPv4Route.defaultRoute];
    if (endpointIP.length > 0) {
        v4.excludedRoutes = @[[[NEIPv4Route alloc] initWithDestinationAddress:endpointIP
                                                                   subnetMask:@"255.255.255.255"]];
    }
    settings.IPv4Settings = v4;
    settings.MTU = @(1400);
    // DNS goes straight through the tunnel (hev UDP associate -> engine)
    settings.DNSSettings = [[NEDNSSettings alloc] initWithServers:@[@"1.1.1.1", @"1.0.0.1"]];
    return settings;
}

/// WARP WireGuard transport: the identity file holds the WARP keypair and
/// assigned addresses; our proven WireGuard engine drives the tunnel.
- (void)startWireGuardLocked:(NSString *)endpoint {
    NSString *identityPath = [_identityDir stringByAppendingPathComponent:@"identity.toml"];
    NSString *toml = [NSString stringWithContentsOfFile:identityPath encoding:NSUTF8StringEncoding error:nil];
    NSString *priv = [self tomlValue:toml key:@"wg_private_key"];
    NSString *peerPub = [self tomlValue:toml key:@"wg_peer_public_key"];
    NSString *ipv4 = [self tomlValue:toml key:@"ipv4"];
    NSString *ipv6 = [self tomlValue:toml key:@"ipv6"];
    if (priv.length == 0 || peerPub.length == 0 || ipv4.length == 0) {
        _failureCb(@"Aether: the identity file is missing the WireGuard keys");
        return;
    }
    NSMutableString *conf = [NSMutableString new];
    [conf appendString:@"[Interface]\n"];
    [conf appendFormat:@"PrivateKey = %@\n", priv];
    [conf appendFormat:@"Address = %@/32%@\n", ipv4, ipv6.length > 0 ? [NSString stringWithFormat:@", %@/128", ipv6] : @""];
    [conf appendString:@"DNS = 1.1.1.1, 1.0.0.1\n"];
    [conf appendString:@"\n[Peer]\n"];
    [conf appendFormat:@"PublicKey = %@\n", peerPub];
    [conf appendFormat:@"Endpoint = %@\n", endpoint];
    [conf appendString:@"AllowedIPs = 0.0.0.0/0, ::/0\n"];
    [conf appendString:@"PersistentKeepalive = 25\n"];

    _usingWireGuardEngine = YES;
    SRPWireGuardClient *wg = [[SRPWireGuardClient alloc] init];
    wg.configText = conf;
    wg.logLevel = _logLevel;
    _wgClient = wg;

    [wg startWithNetworkSettingsCallback:^(NEPacketTunnelNetworkSettings *setting) {
        if (self->_settingsCb) self->_settingsCb(setting);
    } failureCallback:^(NSString *reason) {
        if (self->_failureCb) self->_failureCb(reason);
    }];
}

/// Bind a WARP+ license key to the saved device registration. The binding
/// call is PATCH /v0a4471/reg/<device_id>/account {"license": key} (the
/// /reg/<id> PATCH silently ignores the field); a GET then confirms
/// account_type flipped to "unlimited". Runs best-effort; the result is
/// logged and the applied key is remembered per device so later connects
/// skip the call.
+ (void)applyWarpLicense:(NSString *)license identityDir:(NSString *)dir transport:(NSString *)transport {
    SSLogM(@"Aether: WARP+ license apply starting (transport %@)", transport);
    // Each transport has its own device registration — bind the license to
    // the one actually in use
    NSArray *names = [transport isEqualToString:@"masque"]
        ? @[@"identity-masque.toml", @"identity.toml"]
        : @[@"identity.toml", @"identity-masque.toml"];
    NSString *toml = nil;
    for (NSString *name in names) {
        toml = [NSString stringWithContentsOfFile:[dir stringByAppendingPathComponent:name]
                                         encoding:NSUTF8StringEncoding error:nil];
        if ([toml containsString:@"device_id"]) break;
    }
    NSString *deviceId = [self tomlValueStatic:toml key:@"device_id"];
    NSString *token = [self tomlValueStatic:toml key:@"access_token"];
    SSLogM(@"Aether: WARP+ apply: identity read, device=%@", deviceId ?: @"none");
    if (deviceId.length == 0 || token.length == 0) {
        SSLogM(@"Aether: WARP+ license skipped (identity file has no device_id)");
        return;
    }
    // The applied key is remembered in a marker file next to the identity —
    // NSUserDefaults with a suite can block on cfprefsd in this context
    NSString *markerFile = [dir stringByAppendingPathComponent:
                            [NSString stringWithFormat:@".license-%@", deviceId]];
    NSString *applied = [NSString stringWithContentsOfFile:markerFile encoding:NSUTF8StringEncoding error:nil];
    if ([applied isEqualToString:license]) {
        return;   // already bound
    }
    SSLogM(@"Aether: WARP+ apply: device %@, patching /account…", deviceId);

    NSData *(^request)(NSString *, NSString *, NSData *, NSInteger *) = ^(NSString *method, NSString *path, NSData *body, NSInteger *status) {
        NSURL *url = [NSURL URLWithString:
            [NSString stringWithFormat:@"https://api.cloudflareclient.com/v0a4471/reg/%@%@", deviceId, path]];
        NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:url
                                                           cachePolicy:NSURLRequestReloadIgnoringLocalCacheData
                                                       timeoutInterval:15];
        req.HTTPMethod = method;
        [req setValue:[NSString stringWithFormat:@"Bearer %@", token] forHTTPHeaderField:@"Authorization"];
        [req setValue:@"application/json" forHTTPHeaderField:@"Content-Type"];
        req.HTTPBody = body;
        __block NSHTTPURLResponse *resp = nil;
        __block NSData *respData = nil;
        __block NSError *reqErr = nil;
        dispatch_semaphore_t sem = dispatch_semaphore_create(0);
        [[NSURLSession.sharedSession dataTaskWithRequest:req
                                      completionHandler:^(NSData *d, NSURLResponse *r, NSError *e) {
            respData = d; resp = (NSHTTPURLResponse *)r; reqErr = e;
            dispatch_semaphore_signal(sem);
        }] resume];
        long waited = dispatch_semaphore_wait(sem, dispatch_time(DISPATCH_TIME_NOW, 20 * NSEC_PER_SEC));
        SSLogM(@"Aether: WARP+ %@ %@ -> http=%ld err=%@ timeout=%ld", method, path,
               (long)resp.statusCode, reqErr.localizedDescription ?: @"none", waited);
        if (status) *status = resp.statusCode;
        return respData;
    };

    NSInteger status = 0;
    NSData *body = [NSJSONSerialization dataWithJSONObject:@{@"license": license} options:0 error:nil];
    request(@"PATCH", @"/account", body, &status);
    if (status != 200) {
        SSLogE(@"Aether: WARP+ license bind failed (HTTP %ld) — continuing with free WARP", (long)status);
        return;
    }
    // Confirm via a fresh read of the registration
    NSData *data = request(@"GET", @"", nil, &status);
    NSDictionary *json = data ? [NSJSONSerialization JSONObjectWithData:data options:0 error:nil] : nil;
    NSString *accountType = [json isKindOfClass:NSDictionary.class] ? json[@"account"][@"account_type"] : nil;
    if (![accountType isEqualToString:@"unlimited"] && ![accountType isEqualToString:@"plus"]) {
        SSLogE(@"Aether: WARP+ license not applied (account_type=%@) — continuing with free WARP",
               accountType ?: @"unknown");
        return;
    }
    [license writeToFile:markerFile atomically:YES encoding:NSUTF8StringEncoding error:nil];
    SSLogM(@"Aether: WARP+ license bound — account_type=%@", accountType);
}

+ (NSString *)tomlValueStatic:(NSString *)toml key:(NSString *)key {
    for (NSString *line in [toml componentsSeparatedByCharactersInSet:NSCharacterSet.newlineCharacterSet]) {
        NSString *t = [line stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceCharacterSet];
        if ([t hasPrefix:[key stringByAppendingString:@" ="]]) {
            NSArray *parts = [t componentsSeparatedByString:@"="];
            if (parts.count >= 2) {
                NSString *v = [[parts subarrayWithRange:NSMakeRange(1, parts.count - 1)] componentsJoinedByString:@"="];
                return [v stringByTrimmingCharactersInSet:[NSCharacterSet characterSetWithCharactersInString:@" \t\""]];
            }
        }
    }
    return nil;
}

- (NSString *)tomlValue:(NSString *)toml key:(NSString *)key {    for (NSString *line in [toml componentsSeparatedByCharactersInSet:NSCharacterSet.newlineCharacterSet]) {
        NSString *t = [line stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceCharacterSet];
        if ([t hasPrefix:[key stringByAppendingString:@" ="]]) {
            NSArray *parts = [t componentsSeparatedByString:@"="];
            if (parts.count >= 2) {
                NSString *v = [[parts subarrayWithRange:NSMakeRange(1, parts.count - 1)] componentsJoinedByString:@"="];
                return [v stringByTrimmingCharactersInSet:[NSCharacterSet characterSetWithCharactersInString:@" \t\""]];
            }
        }
    }
    return nil;
}

- (void)tunApplied {
    // The utun fd exists now — attach the WG engine (MASQUE/hev mode has no
    // WG engine; messaging nil would return NO and read as a failure)
    if (!_wgClient) return;
    NSError *err = nil;
    if (![_wgClient activateWithError:&err]) {
        if (_failureCb) _failureCb(err.localizedDescription ?: @"Aether: the WireGuard engine failed to start");
    }
}

- (BOOL)usingWireGuardEngine {
    return _usingWireGuardEngine;
}

- (void)finishInjectionLocked {
    _pendingPackets = nil;
    _pendingPacketIndex = 0;
    dispatch_block_t completion = _injectionCompletion;
    _injectionCompletion = nil;
    if (completion) completion();
}

- (void)drainInjectedPacketsLocked {
    _retryScheduled = NO;
    if (_closed || _tunFd < 0) return;
    while (_pendingPacketIndex < _pendingPackets.count) {
        NSData *packet = _pendingPackets[_pendingPacketIndex];
        ssize_t written = write(_tunFd, packet.bytes, packet.length);
        if (written == (ssize_t)packet.length) {
            _pendingPacketIndex++;
            continue;
        }
        if (written < 0 && errno == EINTR) continue;
        if (written < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == ENOBUFS)) {
            if (!_retryScheduled) {
                _retryScheduled = YES;
                dispatch_after(dispatch_time(DISPATCH_TIME_NOW, NSEC_PER_MSEC), _worker, ^{
                    [self drainInjectedPacketsLocked];
                });
            }
            return;
        }
        SSLogE(@"Aether: tunnel write failed (%d)", errno);
        if (_failureCb) _failureCb(@"Aether: the packet channel stopped accepting data");
        return;
    }
    [self finishInjectionLocked];
}

- (void)injectPackets:(NSArray<NSData *> *)packets completion:(dispatch_block_t)completion {
    dispatch_async(_worker, ^{
        if (self->_closed || self->_pendingPackets != nil) return;
        if (self->_usingWireGuardEngine) {
            if (completion) completion();
            return;
        }
        NSMutableArray<NSData *> *framed = [NSMutableArray arrayWithCapacity:packets.count];
        for (NSData *packet in packets) {
            if (packet.length < 20 || packet.length > 2048) continue;
            NSMutableData *data = [NSMutableData dataWithCapacity:packet.length + 4];
            uint32_t header = 0;
            [data appendBytes:&header length:4];
            [data appendData:packet];
            [framed addObject:data];
        }
        self->_pendingPackets = framed;
        self->_pendingPacketIndex = 0;
        self->_injectionCompletion = completion;
        [self drainInjectedPacketsLocked];
    });
}

- (BOOL)readExactLocked:(int)fd buffer:(uint8_t *)buffer length:(NSUInteger)length timeoutSec:(NSInteger)timeoutSec {
    NSDate *deadline = [NSDate dateWithTimeIntervalSinceNow:timeoutSec];
    NSUInteger offset = 0;
    while (offset < length && !_closed) {
        ssize_t n = read(fd, buffer + offset, length - offset);
        if (n > 0) {
            offset += (NSUInteger)n;
            continue;
        }
        if (n == 0) return NO;
        if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) return NO;
        if ([[NSDate date] compare:deadline] == NSOrderedDescending) return NO;
        usleep(100000);
    }
    return offset == length;
}

- (BOOL)waitSocksReadyLocked:(NSInteger)timeoutSec {
    NSDate *deadline = [NSDate dateWithTimeIntervalSinceNow:timeoutSec];
    int fd = -1;
    BOOL greeted = NO;
    while (!_closed) {
        if (_tunnelJobId != 0) {
            NSDictionary *poll = [self callJson:^{ return aether_job_poll(self->_tunnelJobId); }];
            if ([poll[@"state"] isEqualToString:@"done"]) {
                SSLogM(@"Aether: tunnel ended while waiting for SOCKS5: %@", poll[@"result"]);
                if (fd >= 0) close(fd);
                return NO;
            }
        }
        if (fd < 0) {
            fd = socket(AF_INET, SOCK_STREAM, 0);
            struct timeval rcvto = { .tv_sec = 2 };
            setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &rcvto, sizeof(rcvto));
            struct sockaddr_in sa = {0};
            sa.sin_family = AF_INET;
            sa.sin_port = htons(_socksPort);
            inet_pton(AF_INET, "127.0.0.1", &sa.sin_addr);
            if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
                close(fd);
                fd = -1;
                goto next_attempt;
            }
        }
        if (!greeted) {
            const uint8_t hello[3] = {0x05, 0x01, 0x00};
            uint8_t reply[2] = {0};
            if (write(fd, hello, sizeof(hello)) != sizeof(hello) ||
                ![self readExactLocked:fd buffer:reply length:sizeof(reply) timeoutSec:10] ||
                reply[0] != 0x05 || reply[1] != 0x00) {
                close(fd);
                fd = -1;
                goto next_attempt;
            }
            greeted = YES;
        }
        const uint8_t conn[10] = {0x05, 0x01, 0x00, 0x01, 1,1,1,1, 0x01, 0xBB};
        uint8_t cr[10] = {0};
        BOOL connected = write(fd, conn, sizeof(conn)) == sizeof(conn) &&
            [self readExactLocked:fd buffer:cr length:sizeof(cr) timeoutSec:30];
        if (connected && cr[0] == 0x05 && cr[1] == 0x00) {
            SSLogM(@"Aether: socks5 end-to-end connect test succeeded");
            close(fd);
            return YES;
        }
        close(fd);
        fd = -1;
        greeted = NO;
next_attempt:
        if ([[NSDate date] compare:deadline] == NSOrderedDescending) {
            if (fd >= 0) close(fd);
            return NO;
        }
        usleep(300000);
    }
    if (fd >= 0) close(fd);
    return NO;
}

- (void)close {
    _closed = YES;
    dispatch_async(_worker, ^{ [self closeLocked]; });
}

- (void)closeAndWait {
    _closed = YES;
    dispatch_sync(_worker, ^{ [self closeLocked]; });
}

- (void)closeLocked {
    if (_monitorTimer) {
        dispatch_source_cancel(_monitorTimer);
        _monitorTimer = nil;
    }
    _pendingPackets = nil;
    _pendingPacketIndex = 0;
    _injectionCompletion = nil;
    [_wgClient closeAndWait];
    _wgClient = nil;
    if (_nsHandle >= 0) {
        srpwgNetstackStop(_nsHandle);
        _nsHandle = -1;
    }
    [self stopTunnelAttemptLocked];
    srpssh_hev_socks5_tunnel_quit();
    if (_readSource) {
        dispatch_source_cancel(_readSource);
        _readSource = nil;
    } else if (_tunFd >= 0) {
        close(_tunFd);
        _tunFd = -1;
    }
}

- (void)pauseForSleep { [_wgClient pauseForSleep]; }
- (void)wakeFromSleep { [_wgClient wakeFromSleep]; }

- (void)dealloc {
    [self closeAndWait];
}

@end
