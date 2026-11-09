//
//  SRPAetherClient.m
//  SRPCore
//

#import "SRPAetherClient.h"
#import "SSLog.h"
#import <NetworkExtension/NetworkExtension.h>
#import <Network/Network.h>
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
// A test connection through the tunnel every 20 s (at once after a network change); two failures in a row end the
// session. The engine's QUIC alone notices a dead path only after 120 s.
#define SRPAETHER_PROBE_SECONDS 20
#define SRPAETHER_PROBE_TIMEOUT 10
#define SRPAETHER_BUSY_BYTES (64 * 1024)   // what a working tunnel brings to the phone between two tests while it is busy
#define SRPAETHER_RETRY_DELAY 2

/// One SOCKS5 CONNECT to 1.1.1.1:443 through the tunnel's SOCKS5 port (the engine, Tor, or Private mode's relay to the
/// server's Aether proxy): YES when the far end answered it, which only a working session gives.
static BOOL SRPAetherSocksProbe(int port, int timeoutSec) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return NO;
    struct timeval timeout = { .tv_sec = timeoutSec };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    int nosigpipe = 1;
    setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &nosigpipe, sizeof(nosigpipe));
    struct sockaddr_in sa = {0};
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    inet_pton(AF_INET, "127.0.0.1", &sa.sin_addr);
    BOOL ok = NO;
    if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) == 0) {
        const uint8_t hello[3] = {0x05, 0x01, 0x00};
        const uint8_t request[10] = {0x05, 0x01, 0x00, 0x01, 1, 1, 1, 1, 0x01, 0xBB};
        uint8_t reply[10] = {0};
        if (write(fd, hello, sizeof(hello)) == sizeof(hello) && recv(fd, reply, 2, MSG_WAITALL) == 2 &&
            reply[0] == 0x05 && reply[1] == 0x00 &&
            write(fd, request, sizeof(request)) == sizeof(request) && recv(fd, reply, sizeof(reply), MSG_WAITALL) == sizeof(reply)) {
            ok = reply[0] == 0x05 && reply[1] == 0x00;
        }
    }
    close(fd);
    return ok;
}

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

#if DEBUG
#import <os/proc.h>
#import <mach/task.h>
#import <mach/task_info.h>
#import <mach/mach_init.h>

static void SRPAMemoryUsage(void) {
    task_vm_info_data_t info = {0};
    mach_msg_type_number_t count = TASK_VM_INFO_COUNT;
    if (task_info(mach_task_self(), TASK_VM_INFO, (task_info_t)&info, &count) == KERN_SUCCESS) {
        NSLog(@"Aether memory: %.1f MiB; available: %.1f MiB",
              (double)info.phys_footprint / (1024.0 * 1024.0),
              (double)os_proc_available_memory() / (1024.0 * 1024.0));
    }
}
#endif

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
    NSUInteger _packetsSinceMemorySample;
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
    NSInteger _attempts;             // connection attempts since the last working session
    BOOL _paused;                    // the session is closed while the device sleeps
    dispatch_source_t _probeTimer;
    dispatch_queue_t _probeQueue;    // the test connection waits here, never on the packet worker
    BOOL _probing;
    NSInteger _probeFailures;
    nw_path_monitor_t _pathMonitor;
    NSString *_pathName;             // the network the session runs on: Wi-Fi, cellular, wired, other, none
    BOOL _socksClosed;               // the last readiness check's far end closed instead of timing out
    long long _bytesToPhone;         // through the tunnel since the first session (Expert's line)
    long long _bytesAtLastProbe;     // _bytesToPhone at the last test connection (a busy tunnel's failed test is not counted)
    long long _bytesFromPhone;
    CFAbsoluteTime _sessionStart;
}

- (instancetype)init {
    self = [super init];
    if (self) {
        _worker = dispatch_queue_create("srp.aether", DISPATCH_QUEUE_SERIAL);
        dispatch_queue_set_specific(_worker, (__bridge const void *)self, (__bridge void *)self, NULL);
        _probeQueue = dispatch_queue_create("srp.aether.probe", DISPATCH_QUEUE_SERIAL);
        _autoReconnect = YES;
        _onSleep = 2;
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
    setenv("AETHER_PERF_PROFILE", "low", 1);
    // Engine logs (env_logger) go to stderr -> the tunnel log; the SOCKS5 requests' destinations only at Debug
    setenv("RUST_LOG", _logLevel >= 2 ? "trace" : "info,aether::socks=warn", 1);
    // SPKI pinning on — the upstream default is NO verification (spec P0)
    setenv("AETHER_TLS_VERIFY", "1", 1);
    unsetenv("AETHER_UPSTREAM");
    unsetenv("AETHER_MASQUE_HTTP2");
    unsetenv("AETHER_MASQUE_H2_FRAGMENT");
    unsetenv("AETHER_MASQUE_H2_FRAGMENT_SIZE");
    unsetenv("AETHER_MASQUE_H2_FRAGMENT_SNI");
    SSLogM(@"Aether: transport=%@ scan=%@ fragMode=%ld", _transport, _scanProfile, (long)_fragMode);
    SSLogM(@"Aether: auto reconnect %@, retry times %@, on sleep %@", _autoReconnect ? @"on" : @"off",
           _retryTimes > 0 ? @(_retryTimes).stringValue : @"no limit", @[@"off", @"pause", @"stay"][MIN(MAX(_onSleep, 0), 2)]);
    dispatch_async(_worker, ^{
        [self startPathMonitorLocked];
        [self startLocked];
    });
}

/// One connection attempt: a new session under the tunnel (the first one also brings up the packet bridge and the
/// tunnel's settings). A session that fails before it works goes to attemptFailedLocked.
- (void)startLocked {
    if (_closed || _paused) return;
    _attempts++;
    if (_attempts > 1 || _up) {
        SSLogM(@"Aether: connection attempt %ld", (long)_attempts);
    }
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
    // The device identity is opened once per connection; later attempts reuse it
    BOOL firstIdentity = _identityId == 0;
    if (firstIdentity) {
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
            [self attemptFailedLocked:@"Aether: identity provisioning failed (network unreachable?)"];
            return;
        }
        _identityId = [opened[@"identity"] unsignedLongLongValue];
        SSLogM(@"Aether: identity ready (id %llu)", _identityId);
    }

    if (firstIdentity && _licenseKey.length > 0) {
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
            [self attemptFailedLocked:@"Aether: no reachable WireGuard endpoint found"];
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
    [self attemptFailedLocked:@"Aether: no reachable MASQUE endpoint or the tunnel data-plane did not come up"];
}

#pragma mark - attempts, drops, test connections, sleep

/// Retry Times: before the first connection 1 attempt, or 1 + Retry Times with Auto Reconnect (as the other protocols);
/// after a drop Retry Times attempts (0 = no limit), one without Auto Reconnect (a wake from Pause)
- (NSInteger)attemptBudgetLocked {
    if (!_up) {
        return (_autoReconnect && _retryTimes > 0) ? 1 + _retryTimes : 1;
    }
    if (!_autoReconnect) {
        return 1;
    }
    return _retryTimes > 0 ? _retryTimes : NSIntegerMax;
}

/// An attempt that gave no working session: another one shortly while the budget lasts, otherwise the end
- (void)attemptFailedLocked:(NSString *)reason {
    if (_closed) return;
    [self stopSessionLocked];
    if (_paused) return;
    if (_attempts < [self attemptBudgetLocked]) {
        SSLogM(@"Aether: attempt %ld failed: %@; trying again in %d seconds", (long)_attempts, reason, SRPAETHER_RETRY_DELAY);
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)SRPAETHER_RETRY_DELAY * NSEC_PER_SEC), _worker, ^{
            [self startLocked];
        });
        return;
    }
    NSString *message = reason;
    if (_attempts > 1) {
        message = [NSString stringWithFormat:@"Could not %@ after %ld attempts. (%@)",
                   _up ? @"reconnect" : @"connect", (long)_attempts, reason];
    }
    SSLogM(@"Aether: closing with reason: %@", message);
    if (_failureCb) _failureCb(message);
}

/// Ends the session under the tunnel (the engine's job, or Private mode's WireGuard relay) and its checks; the packet
/// bridge and the tunnel's settings stay, so the next session takes over the same tunnel
- (void)stopSessionLocked {
    [self stopProbeLocked];
    if (_monitorTimer) {
        dispatch_source_cancel(_monitorTimer);
        _monitorTimer = nil;
    }
    [self stopTunnelAttemptLocked];
    if (_nsHandle >= 0) {
        srpwgNetstackStop(_nsHandle);
        _nsHandle = -1;
    }
}

/// A working session stopped working: Auto Reconnect sets up a new one, otherwise the VPN ends with the reason
- (void)sessionLostLocked:(NSString *)reason {
    if (_closed || _paused || !_up) return;
    SSLogM(@"Aether: %@", reason);
    [self stopSessionLocked];
    if (!_autoReconnect) {
        NSString *message = [reason stringByAppendingString:@" (auto reconnect is off)."];
        SSLogM(@"Aether: closing with reason: %@", message);
        if (_failureCb) _failureCb(message);
        return;
    }
    _attempts = 0;
    [self startLocked];
}

/// A new session works: the first one brings the packet bridge and the tunnel's settings up, later ones take over
- (BOOL)sessionWorksLocked:(NSString *)endpointIP {
    if (!_up) {
        if (![self startHevLocked]) return NO;
        if (_settingsCb) _settingsCb([self buildSettings:endpointIP]);
    } else {
        SSLogM(@"Aether: connected again (attempt %ld)", (long)_attempts);
    }
    _up = YES;
    _attempts = 0;
    _sessionStart = CFAbsoluteTimeGetCurrent();
    if (_connectedCb) _connectedCb();
    [self monitorTunnelJobLocked];
    [self startProbeLocked];
    return YES;
}

- (void)startProbeLocked {
    if (_probeTimer || _closed) return;
    _probeFailures = 0;
    _bytesAtLastProbe = _bytesToPhone;
    _probeTimer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, _worker);
    dispatch_source_set_timer(_probeTimer, dispatch_time(DISPATCH_TIME_NOW, (int64_t)SRPAETHER_PROBE_SECONDS * NSEC_PER_SEC),
                              (uint64_t)SRPAETHER_PROBE_SECONDS * NSEC_PER_SEC, NSEC_PER_SEC);
    dispatch_source_set_event_handler(_probeTimer, ^{ [self probeLocked]; });
    dispatch_resume(_probeTimer);
}

- (void)stopProbeLocked {
    if (_probeTimer) {
        dispatch_source_cancel(_probeTimer);
        _probeTimer = nil;
    }
    _probeFailures = 0;
}

/// A test connection through the tunnel, waited for on its own queue (the packet worker never blocks on it)
- (void)probeLocked {
    if (_probing || _closed || _paused || !_probeTimer) return;
    _probing = YES;
    int port = _socksPort;
    // A Tor circuit answers slower than WARP
    int timeout = (_torMode.length == 0 || [_torMode isEqualToString:@"off"]) ? SRPAETHER_PROBE_TIMEOUT : 30;
    dispatch_async(_probeQueue, ^{
        BOOL ok = SRPAetherSocksProbe(port, timeout);
        dispatch_async(self->_worker, ^{
            self->_probing = NO;
            [self probeResult:ok];
        });
    });
}

- (void)probeResult:(BOOL)ok {
    if (_closed || _paused || !_probeTimer) return;
    long long cameBack = _bytesToPhone - _bytesAtLastProbe;
    _bytesAtLastProbe = _bytesToPhone;
    if (!ok && cameBack >= SRPAETHER_BUSY_BYTES) {
        // A busy tunnel can fail a test connection (Tor gives a new stream up after 10 seconds on a full circuit);
        // one that brought this much to the phone since the last test still carries traffic
        SSLogM(@"Aether: a test connection through the tunnel failed, but %lld KB came through it since the last one: not counted",
               cameBack / 1024);
        return;
    }
    if (ok) {
        if (_probeFailures > 0) SSLogM(@"Aether: the test connection passes again");
        _probeFailures = 0;
        SSLogI(@"Aether: test connection passed; session up %.0f s; received %lld bytes, sent %lld bytes in all",
               CFAbsoluteTimeGetCurrent() - _sessionStart, _bytesToPhone, _bytesFromPhone);
        return;
    }
    _probeFailures++;
    SSLogM(@"Aether: a test connection through the tunnel failed (%ld in a row)", (long)_probeFailures);
    if (_probeFailures >= 2) {
        [self sessionLostLocked:_privateMode && _privateConfig.length > 0
            ? @"The server stopped carrying traffic: two test connections through it failed"
            : [_torMode isEqualToString:@"only"] ? @"Tor stopped carrying traffic: two test connections through it failed"
                                                 : @"Cloudflare WARP stopped carrying traffic: two test connections through it failed"];
        return;
    }
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 3 * NSEC_PER_SEC), _worker, ^{ [self probeLocked]; });
}

static NSString *SRPAetherPathName(nw_path_t path) {
    if (nw_path_get_status(path) != nw_path_status_satisfied) return @"none";
    if (nw_path_uses_interface_type(path, nw_interface_type_wifi)) return @"Wi-Fi";
    if (nw_path_uses_interface_type(path, nw_interface_type_cellular)) return @"cellular";
    if (nw_path_uses_interface_type(path, nw_interface_type_wired)) return @"wired";
    return @"other";
}

/// The phone's network: on a change the session is tested at once, so a session the old network carried and the new
/// one does not is noticed in seconds and set up again on the new network (the WireGuard transport moves its own sockets)
- (void)startPathMonitorLocked {
    if (_pathMonitor) return;
    _pathMonitor = nw_path_monitor_create();
    nw_path_monitor_set_queue(_pathMonitor, _worker);
    __weak SRPAetherClient *weakSelf = self;
    nw_path_monitor_set_update_handler(_pathMonitor, ^(nw_path_t path) {
        SRPAetherClient *strongSelf = weakSelf;
        NSString *name = SRPAetherPathName(path);
        if (!strongSelf || [name isEqualToString:strongSelf->_pathName ?: @""]) return;
        BOOL first = strongSelf->_pathName == nil;
        strongSelf->_pathName = name;
        if (!first) [strongSelf networkChangedLocked:name];
    });
    nw_path_monitor_start(_pathMonitor);
}

- (void)networkChangedLocked:(NSString *)name {
    if (_closed || _paused || !_up || _usingWireGuardEngine) return;
    SSLogM(@"Aether: network changed (%@): testing the session", name);
    if ([name isEqualToString:@"none"]) return;   // nothing to test on; the next network brings a test
    _probeFailures = 0;
    [self probeLocked];
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
        [self sessionLostLocked:[self->_torMode isEqualToString:@"only"] ? @"The Tor session ended" : @"The WARP session ended"];
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
    if (![self sessionWorksLocked:_endpointIP]) return NO;
    SSLogM(@"Aether: session established over MASQUE %@", h2 ? @"H2" : @"H3");
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
        [self attemptFailedLocked:@"Aether: the Tor job did not start"];
        return;
    }
    SSLogM(@"Aether: tor-only — bootstrapping Tor (can take a minute on first run)");
    if (![self waitSocksReadyLocked:180]) {
        [self attemptFailedLocked:@"Aether: Tor did not come up in time"];
        return;
    }
    if (![self sessionWorksLocked:@""]) {
        [self stopSessionLocked];
        if (_failureCb) _failureCb(@"Aether: the packet bridge failed to start");
        return;
    }
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
        if (_failureCb) _failureCb(@"Aether private: the WireGuard relay failed to start");
        return;
    }
    SSLogM(@"Aether private: WG relay up — %@ via %@", target, _endpointIP);

    // End-to-end readiness: relay + WG handshake + the server's Aether proxy. Through a WireGuard that gets no handshake
    // the relay's connection to the proxy never completes (a timeout); a server that answers but has no proxy on the
    // port refuses it at once, and the relay closes the test connection
    if (![self waitSocksReadyLocked:30]) {
        NSString *port = [[params[@"uapi"] componentsSeparatedByString:@"\n"] filteredArrayUsingPredicate:
                          [NSPredicate predicateWithFormat:@"SELF BEGINSWITH 'endpoint='"]].firstObject;
        port = [port componentsSeparatedByString:@":"].lastObject ?: @"51820";
        [self attemptFailedLocked:_socksClosed
            ? [NSString stringWithFormat:@"Aether private: the server answers over WireGuard, but its Aether proxy (port %d on %@) refused the connection: is the aether container running?", SRPAETHER_SOCKS_PORT, [target componentsSeparatedByString:@":"].firstObject]
            : [NSString stringWithFormat:@"Aether private: the server did not answer the WireGuard handshake: the server's public key or the preshared key may not match, the server may not have this profile's public key as a peer, or UDP port %@ may be closed.", port]];
        return;
    }
    if (![self sessionWorksLocked:_endpointIP]) {
        [self stopSessionLocked];
        if (_failureCb) _failureCb(@"Aether: the packet bridge failed to start");
        return;
    }
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
            // The stand-in addresses come from 198.19.0.0/16: hev hands them out from the network's first address on, and
            // from 198.18.0.0/16 the second name got 198.18.0.1, the tunnel's own address, which the system keeps local
            @"mapdns:\n"
            @"  address: 198.18.0.2\n"
            @"  port: 53\n"
            @"  network: 198.19.0.0\n"
            @"  netmask: 255.255.0.0\n"
            @"  cache-size: 2048\n"
            @"misc:\n"
            @"  log-file: stderr\n"
            @"  log-level: %@\n",
            _socksPort, _logLevel >= 2 ? @"debug" : @"warn"];
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
        _socksPort, _logLevel >= 2 ? @"debug" : @"warn"];
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
            @autoreleasepool {
                if (n < 24) continue;
                strongSelf->_bytesToPhone += n - 4;
                // strip the 4-byte Darwin utun header the hev core prepends
                uint8_t *pkt = buf + 4;
                int fam = (pkt[0] >> 4) == 6 ? AF_INET6 : AF_INET;
                if (strongSelf->_outputCb)
                    strongSelf->_outputCb([NSData dataWithBytes:pkt length:(NSUInteger)(n - 4)], fam);
#if DEBUG
                strongSelf->_packetsSinceMemorySample++;
                if (strongSelf->_packetsSinceMemorySample % 10000 == 0) SRPAMemoryUsage();
#endif
            }
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
    // The WireGuard client keeps its own handshake check, reconnects and sleep handling with the profile's options
    wg.autoReconnect = _autoReconnect;
    wg.retryTimes = _retryTimes;
    wg.onSleep = _onSleep;
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
            self->_bytesFromPhone += (long long)packet.length;
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
        // The far end closed (or reset) the connection: an answer of its own, as Private mode's relay closes it at once when the
        // server refused the proxy port; a timeout is the other way to fail
        if (n == 0 || errno == ECONNRESET || errno == EPIPE) {
            _socksClosed = YES;
            return NO;
        }
        if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) return NO;
        if ([[NSDate date] compare:deadline] == NSOrderedDescending) return NO;
        usleep(100000);
    }
    return offset == length;
}

- (BOOL)waitSocksReadyLocked:(NSInteger)timeoutSec {
    _socksClosed = NO;
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
            int nosigpipe = 1;   // a write to a connection the far end closed must not raise SIGPIPE
            setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &nosigpipe, sizeof(nosigpipe));
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
            ssize_t sent = write(fd, hello, sizeof(hello));
            if (sent < 0 && (errno == EPIPE || errno == ECONNRESET)) _socksClosed = YES;
            if (sent != sizeof(hello) ||
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
    if (dispatch_get_specific((__bridge const void *)self)) {
        [self closeLocked];
    } else {
        dispatch_sync(_worker, ^{ [self closeLocked]; });
    }
}

- (void)closeLocked {
    if (_monitorTimer) {
        dispatch_source_cancel(_monitorTimer);
        _monitorTimer = nil;
    }
    [self stopProbeLocked];
    if (_pathMonitor) {
        nw_path_monitor_cancel(_pathMonitor);
        _pathMonitor = nil;
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
    _outputCb = nil;
    _settingsCb = nil;
    _connectedCb = nil;
    _failureCb = nil;
}

/// Off and Pause close the session while the device sleeps (the tunnel and the packet bridge stay); the WARP WireGuard
/// transport does the same in its own client
- (void)pauseForSleep {
    dispatch_async(_worker, ^{
        if (self->_usingWireGuardEngine) {
            [self->_wgClient pauseForSleep];
            return;
        }
        if (self->_closed || !self->_up || self->_paused) return;
        self->_paused = YES;
        SSLogM(@"Aether: the device sleeps: the session is closed until it wakes");
        [self stopSessionLocked];
    });
}

/// Pause, and Off with Auto Reconnect, connect again at wake; Off without it ends the VPN
- (void)wakeFromSleep {
    dispatch_async(_worker, ^{
        if (self->_usingWireGuardEngine) {
            [self->_wgClient wakeFromSleep];
            return;
        }
        if (self->_closed || !self->_paused) return;
        self->_paused = NO;
        if (self->_onSleep == 0 && !self->_autoReconnect) {
            SSLogM(@"Aether: closing with reason: The connection was closed while the device slept.");
            if (self->_failureCb) self->_failureCb(@"The connection was closed while the device slept.");
            return;
        }
        SSLogM(@"Aether: the device is awake: connecting again");
        self->_attempts = 0;
        [self startLocked];
    });
}

- (void)switchNetworkPath {
    dispatch_async(_worker, ^{
        if (self->_usingWireGuardEngine) {
            [self->_wgClient switchNetworkPath];
            return;
        }
        [self networkChangedLocked:self->_pathName ?: @"other"];
    });
}

#if DEBUG
- (void)debugDropSession {
    dispatch_async(_worker, ^{
        if (self->_tunnelJobId != 0) {
            SSLogM(@"Aether: debug: ending the engine's session");
            aether_job_cancel(self->_tunnelJobId);
        } else if (self->_nsHandle >= 0) {
            SSLogM(@"Aether: debug: ending the WireGuard relay");
            srpwgNetstackStop(self->_nsHandle);
            self->_nsHandle = -1;
        }
    });
}
#endif

- (void)dealloc {
    [self closeAndWait];
}

@end
