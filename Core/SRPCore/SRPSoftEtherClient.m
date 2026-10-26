//
//  SRPSoftEtherClient.m
//  SRPCore
//

#import "SRPSoftEtherClient.h"
#import "SSLog.h"
#import "SSNetOptions.h"

#import <NetworkExtension/NetworkExtension.h>
#import <Security/Security.h>
#import <Network/Network.h>
#import <arpa/inet.h>
#import <netdb.h>

#include "SRPSEClient.h"

@implementation SRPSoftEtherClient {
    dispatch_queue_t _worker;
    SRPSEClient *_client;

    SRPSoftEtherOutputCallback _outputCb;
    SRPSoftEtherNetworkSettingsCallback _settingsCb;
    SRPSoftEtherConnectedCallback _connectedCb;
    SRPSoftEtherDisconnectedCallback _disconnectedCb;
    SRPSoftEtherFailureCallback _failureCb;

    NEPacketTunnelNetworkSettings *_lastV4Settings;
    NSString *_lastV6Addr;
    NSInteger _lastV6PrefixLen;
    NSString *_lastV6Gw;
    NSArray<NSString *> *_lastV6Dns;
    BOOL _closedManually;
    BOOL _sleepPaused;
    BOOL _tunnelUp;               // DHCP config applied at least once
    BOOL _established;            // protocol established right now
    NSInteger _failedAttempts;
    nw_path_monitor_t _pathMonitor;
    BOOL _lastPathHadWifi;
    NSString *_resolvedRemote;    // server IP for tunnelRemoteAddress
}

static void seObjcPacket(void *ctx, const uint8_t *pkt, uint32_t len, int family);
static void seObjcConfig(void *ctx, const char *ip, const char *mask, const char *gw,
                         const char *dnsCsv, uint32_t leaseSec);
static void seObjcState(void *ctx, int clientStatus, uint32_t err);
static void seObjcLog(void *ctx, const char *line);
static uint32_t seObjcTrust(void *ctx, const uint8_t *const *chainDer,
                            const size_t *chainLen, int chainCount, const char *hostname);

+ (void)initializeCoreInDirectory:(NSString *)dir debugLog:(BOOL)debugLog {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        SRPSEGlobalInit(dir.fileSystemRepresentation, debugLog);
    });
}

- (instancetype)init {
    self = [super init];
    if (self) {
        _worker = dispatch_queue_create("srp.softether", DISPATCH_QUEUE_SERIAL);
        _port = 443;
        _hubName = @"DEFAULT";
        _connections = 1;
        _useCompress = YES;
        _tlsServerVerification = YES;
        _autoReconnect = YES;
        _switchToWifi = YES;
        _onSleep = 2;
    }
    return self;
}

#pragma mark - TLS trust hook

static uint32_t seObjcTrust(void *ctx, const uint8_t *const *chainDer,
                            const size_t *chainLen, int chainCount, const char *hostname) {
    @autoreleasepool {
        NSMutableArray *certs = [NSMutableArray array];
        for (int i = 0; i < chainCount; i++) {
            NSData *d = [NSData dataWithBytes:chainDer[i] length:chainLen[i]];
            SecCertificateRef cert = SecCertificateCreateWithData(NULL, (__bridge CFDataRef)d);
            if (cert) {
                [certs addObject:(__bridge_transfer id)cert];
            }
        }
        if (certs.count == 0) {
            return 85;   // ERR_CERT_NOT_TRUSTED
        }
        NSString *host = hostname ? @(hostname) : @"";
        SecPolicyRef policy = SecPolicyCreateSSL(true, (__bridge CFStringRef)host);
        SecTrustRef trust = NULL;
        if (SecTrustCreateWithCertificates((__bridge CFArrayRef)certs, policy, &trust) != errSecSuccess) {
            if (policy) CFRelease(policy);
            return 85;
        }
        CFErrorRef err = NULL;
        BOOL ok = SecTrustEvaluateWithError(trust, &err);
        if (!ok) {
            SSLogM(@"SoftEther TLS: certificate not trusted for %@: %@", host,
                   err ? (__bridge NSError *)err : @"unknown");
        } else {
            SSLogI(@"SoftEther TLS: server certificate trusted for %@", host);
        }
        if (err) CFRelease(err);
        CFRelease(trust);
        CFRelease(policy);
        return ok ? 0 : 85;
    }
}

#pragma mark - start / stop

- (void)startWithOutputCallback:(SRPSoftEtherOutputCallback)output
         networkSettingsCallback:(SRPSoftEtherNetworkSettingsCallback)settings
               connectedCallback:(SRPSoftEtherConnectedCallback)connected
            disconnectedCallback:(SRPSoftEtherDisconnectedCallback)disconnected
                 failureCallback:(SRPSoftEtherFailureCallback)failure {
    _outputCb = output;
    _settingsCb = settings;
    _connectedCb = connected;
    _disconnectedCb = disconnected;
    _failureCb = failure;
    SSLogSetLevel((SSLogLevel)_logLevel);
    dispatch_async(_worker, ^{
        [self startLocked];
        [self startPathMonitor];
    });
}

- (void)startLocked {
    [self stopLockedSession];

    // Resolve the server address once for tunnelRemoteAddress
    _resolvedRemote = nil;
    struct addrinfo hints = {0}, *res = NULL;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    char portStr[8];
    snprintf(portStr, sizeof(portStr), "%d", _port);
    if (getaddrinfo(_host.UTF8String, portStr, &hints, &res) == 0 && res != NULL) {
        char ipbuf[INET_ADDRSTRLEN];
        struct sockaddr_in *sa = (struct sockaddr_in *)res->ai_addr;
        if (inet_ntop(AF_INET, &sa->sin_addr, ipbuf, sizeof(ipbuf))) {
            _resolvedRemote = @(ipbuf);
        }
        freeaddrinfo(res);
    }

    // TLS trust hook: only when verification is on
    SRPSESetTrustHook(NULL, _tlsServerVerification ? seObjcTrust : NULL);

    SRPSEClientConfig cfg;
    memset(&cfg, 0, sizeof(cfg));
    snprintf(cfg.hostname, sizeof(cfg.hostname), "%s", _host.UTF8String);
    cfg.port = (uint16_t)_port;
    snprintf(cfg.hub, sizeof(cfg.hub), "%s", _hubName.UTF8String);
    if (_hostnameOverride.length > 0) {
        snprintf(cfg.sniOverride, sizeof(cfg.sniOverride), "%s", _hostnameOverride.UTF8String);
    }
    snprintf(cfg.username, sizeof(cfg.username), "%s", _username.UTF8String);
    cfg.authType = (SRPSEAuthType)_authMethod;
    if (_password != nil) {
        snprintf(cfg.password, sizeof(cfg.password), "%s", _password.UTF8String);
    }
    if (_authMethod == SRPSoftEtherAuthCertificate && _clientCertP12 != nil) {
        cfg.p12 = _clientCertP12.bytes;
        cfg.p12Len = _clientCertP12.length;
        snprintf(cfg.p12Passphrase, sizeof(cfg.p12Passphrase), "%s",
                 _clientCertPassphrase ? _clientCertPassphrase.UTF8String : "");
    }
    cfg.tlsVerify = _tlsServerVerification;
    // Optional TLS write splitting (ClientHello). Auto policy mirrors the
    // SSTP channel/OpenConnect: 43 covers record+handshake headers and the
    // client random (SNI always lands later); cellular gets tighter chunks
    // and pacing.
    if (self.tlsFragMode > 0) {
        uint32_t first = 43, following = 256, gap = 3;
        if (self.tlsFragMode == 1) {
            first = (uint32_t)self.tlsFragFirst;
            following = (uint32_t)self.tlsFragFollowing;
        } else {
            nw_path_monitor_t mon = nw_path_monitor_create();
            dispatch_semaphore_t sem = dispatch_semaphore_create(0);
            __block BOOL cellular = NO;
            nw_path_monitor_set_queue(mon, dispatch_get_global_queue(QOS_CLASS_UTILITY, 0));
            nw_path_monitor_set_update_handler(mon, ^(nw_path_t path) {
                cellular = nw_path_uses_interface_type(path, nw_interface_type_cellular);
                nw_path_monitor_cancel(mon);
                dispatch_semaphore_signal(sem);
            });
            nw_path_monitor_start(mon);
            dispatch_semaphore_wait(sem, dispatch_time(DISPATCH_TIME_NOW, 2 * NSEC_PER_SEC));
            if (cellular) { following = 128; gap = 10; }
        }
        cfg.tlsFragFirst = first;
        cfg.tlsFragFollowing = following;
        cfg.tlsFragGapMs = gap;
        SSLogM(@"SoftEther: TLS fragmentation %@ (first=%u following=%u gap=%u ms)",
               self.tlsFragMode == 2 ? @"auto" : @"manual", first, following, gap);
    }
    cfg.maxConnections = (uint32_t)MAX(1, MIN(32, _connections));
    cfg.udpAcceleration = _udpAcceleration;
    cfg.natTraversal = _natTraversal;
    if (_natTHint.length > 0) {
        snprintf(cfg.natTHint, sizeof(cfg.natTHint), "%s", _natTHint.UTF8String);
    }
    cfg.useCompress = _useCompress;

    if (_proxyMode == 1 && _proxyHost.length > 0) {
        cfg.proxyType = [_proxyType isEqualToString:@"socks5"] ? SRPSEProxySOCKS5 : SRPSEProxyHTTP;
        snprintf(cfg.proxyHost, sizeof(cfg.proxyHost), "%s", _proxyHost.UTF8String);
        cfg.proxyPort = (uint16_t)_proxyPort;
        if (_proxyUsername) snprintf(cfg.proxyUsername, sizeof(cfg.proxyUsername), "%s", _proxyUsername.UTF8String);
        if (_proxyPassword) snprintf(cfg.proxyPassword, sizeof(cfg.proxyPassword), "%s", _proxyPassword.UTF8String);
    }
    else if (_proxyMode == 2) {
        SSLogM(@"SoftEther: proxy Auto/PAC is not supported yet for this protocol; connecting directly");
    }
    cfg.retryIntervalSec = 5;

    SSLogM(@"SoftEther connecting to %@:%d hub=%@ user=%@ auth=%ld conns=%d udpAccel=%d natT=%d verify=%d",
           _host, _port, _hubName, _username, (long)_authMethod,
           (int)cfg.maxConnections, cfg.udpAcceleration, cfg.natTraversal, cfg.tlsVerify);

    _client = SRPSEClientCreate(&cfg, (__bridge void *)self,
                                seObjcPacket, seObjcConfig, seObjcConfig6, seObjcState, seObjcLog);
    if (_client == NULL) {
        [self failWithReason:@"Internal error creating the SoftEther session"];
        return;
    }
    int r = SRPSEClientStart(_client);
    if (r != 0) {
        SRPSEClientFree(_client);
        _client = NULL;
        [self failWithReason:(r == -2)
            ? @"The client certificate could not be read. Re-import it in the profile."
            : @"Internal error starting the SoftEther session"];
        return;
    }
}

- (void)stopLockedSession {
    if (_client != NULL) {
        SRPSEClient *_old = _client;
        _client = NULL;
        SRPSEClientFree(_old);   // blocks until the session thread exits
    }
}

- (void)close {
    dispatch_async(_worker, ^{
        self->_closedManually = YES;
        [self stopPathMonitor];
        [self stopLockedSession];
    });
}

- (void)closeAndWait {
    dispatch_sync(_worker, ^{
        self->_closedManually = YES;
        [self stopPathMonitor];
        [self stopLockedSession];
    });
}

#pragma mark - callbacks from the C core (arrive on SoftEther threads)

static void seObjcPacket(void *ctx, const uint8_t *pkt, uint32_t len, int family) {
    SRPSoftEtherClient *self = (__bridge SRPSoftEtherClient *)ctx;
    NSData *d = [NSData dataWithBytes:pkt length:len];
    int af = family == 6 ? AF_INET6 : AF_INET;
    dispatch_async(self->_worker, ^{
        if (self->_outputCb) self->_outputCb(d, af);
    });
}

static void seObjcConfig6(void *ctx, const char *addr6, int prefixLen,
                          const char *gw6, const char *dns6Csv, uint32_t lifetimeSec) {
    SRPSoftEtherClient *self = (__bridge SRPSoftEtherClient *)ctx;
    NSString *addr = @(addr6), *gw = @(gw6);
    NSString *dns = dns6Csv ? @(dns6Csv) : @"";
    dispatch_async(self->_worker, ^{
        [self applyV6WithAddress:addr prefixLen:prefixLen gateway:gw dnsCsv:dns];
    });
}

static void seObjcConfig(void *ctx, const char *ip, const char *mask, const char *gw,
                         const char *dnsCsv, uint32_t leaseSec) {
    SRPSoftEtherClient *self = (__bridge SRPSoftEtherClient *)ctx;
    NSString *ipStr = @(ip), *maskStr = @(mask), *gwStr = @(gw);
    NSString *dnsStr = dnsCsv ? @(dnsCsv) : @"";
    dispatch_async(self->_worker, ^{
        [self applyNetworkSettingsWithIP:ipStr mask:maskStr gateway:gwStr dnsCsv:dnsStr];
    });
}

static void seObjcState(void *ctx, int clientStatus, uint32_t err) {
    SRPSoftEtherClient *self = (__bridge SRPSoftEtherClient *)ctx;
    dispatch_async(self->_worker, ^{
        [self handleState:clientStatus error:err];
    });
}

static void seObjcLog(void *ctx, const char *line) {
    SSLogI(@"[se] %s", line);
}

#pragma mark - state machine / reconnect

- (void)handleState:(int)clientStatus error:(uint32_t)err {
    // Cedar CLIENT_STATUS_*: 0 connecting, 1 negotiation, 2 auth, 3 established, 4 retry, 5 idle
    switch (clientStatus) {
        case 0: SSLogI(@"SoftEther: connecting"); break;
        case 1: SSLogI(@"SoftEther: negotiation"); break;
        case 2: SSLogI(@"SoftEther: authenticating"); break;
        case 3:
            SSLogM(@"SoftEther: session established");
            _established = YES;
            _failedAttempts = 0;
            break;
        case 4: SSLogI(@"SoftEther: retry wait"); break;
        case 5: {
            // session thread ended
            BOOL wasUp = _tunnelUp;
            _established = NO;
            if (_closedManually || _sleepPaused) {
                return;
            }
            if (wasUp && _disconnectedCb) {
                _disconnectedCb();
            }
            _tunnelUp = NO;

            // Auth/cert errors: never retried — the user must fix the profile
            BOOL fatalAuth = (err == 9 || err == 7 || err == 8 ||
                              err == 85 || err == 106 || err == 149);
            if (!wasUp && fatalAuth) {
                [self failWithReason:[self describeError:err]];
                return;
            }
            if (!_autoReconnect) {
                [self failWithReason:[self describeError:err]];
                return;
            }
            if (!wasUp) {
                // Never established (DNS/TCP/TLS failed): SSTP semantics — fail
                // fast unless the user set an explicit Retry Times budget.
                if (!(_retryTimes > 0 && SSReconnectAttemptAllowed(_failedAttempts, _retryTimes))) {
                    [self failWithReason:[self describeError:err]];
                    return;
                }
            }
            else if (!SSReconnectAttemptAllowed(_failedAttempts, _retryTimes)) {
                [self failWithReason:[NSString stringWithFormat:
                    @"Could not reconnect after %ld attempts. (%@)",
                    (long)_retryTimes, [self describeError:err]]];
                return;
            }
            _failedAttempts++;
            SSLogM(@"SoftEther: connection ended (%@); reconnecting in 2s (attempt %ld%@)",
                   [self describeError:err], (long)_failedAttempts,
                   _retryTimes > 0 ? [NSString stringWithFormat:@" of %ld", (long)_retryTimes] : @"");
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2 * NSEC_PER_SEC)), _worker, ^{
                if (!self->_closedManually && !self->_sleepPaused) {
                    [self startLocked];
                }
            });
            break;
        }
        default: break;
    }
}

- (NSString *)describeError:(uint32_t)err {
    NSString *name = @(SRPSEErrorName(err));
    if (err == 9)  return @"Authentication failed. Check the username, password and authentication method.";
    if (err == 8)  return @"Virtual Hub not found. Check the Virtual Hub field.";
    if (err == 85) return @"The server certificate is not trusted. Enable verification only with a valid certificate, or check the Hostname field.";
    if (err == 106) return @"The server certificate has expired.";
    if (err == 149) return @"The server certificate name does not match the server. Check the Hostname field.";
    if (err == 1)  return @"Cannot reach the server (DNS lookup or TCP connection failed). Check the Server field for typos and the network connection.";
    if (err == 13) return @"Connection timed out.";
    if (err == 17) return @"Cannot connect to the proxy server.";
    if (err == 19) return @"Proxy authentication failed.";
    return [NSString stringWithFormat:@"SoftEther error %u: %@", err, name];
}

- (void)failWithReason:(NSString *)reason {
    SRPSoftEtherFailureCallback cb = _failureCb;
    [self stopLockedSession];
    [self stopPathMonitor];
    if (cb) cb(reason);
}

#pragma mark - network settings

- (void)applyNetworkSettingsWithIP:(NSString *)ip mask:(NSString *)mask
                           gateway:(NSString *)gw dnsCsv:(NSString *)dnsCsv {
    NSArray *dns = [dnsCsv length] > 0 ? [dnsCsv componentsSeparatedByString:@","] : @[@"1.1.1.1", @"8.8.8.8"];
    NSString *remote = _resolvedRemote ?: gw;

    NEPacketTunnelNetworkSettings *networkSettings =
        [[NEPacketTunnelNetworkSettings alloc] initWithTunnelRemoteAddress:remote];
    networkSettings.DNSSettings = [[NEDNSSettings alloc] initWithServers:dns];
    networkSettings.MTU = @(1500);
    NEIPv4Settings *ipv4 = [[NEIPv4Settings alloc] initWithAddresses:@[ip] subnetMasks:@[mask]];
    ipv4.includedRoutes = @[[NEIPv4Route defaultRoute]];
    // The VPN server itself must stay on the physical path — otherwise the
    // tunnel's own TLS transport gets routed into the utun and blackholed.
    if (_resolvedRemote != nil) {
        ipv4.excludedRoutes = @[[[NEIPv4Route alloc] initWithDestinationAddress:_resolvedRemote
                                                                     subnetMask:@"255.255.255.255"]];
    } else {
        ipv4.excludedRoutes = @[];
    }
    networkSettings.IPv4Settings = ipv4;
    // Keep IPv6 if SLAAC already configured (order of DHCP vs RA is not defined)
    if (_lastV6Addr != nil) {
        NEIPv6Settings *ipv6 = [[NEIPv6Settings alloc] initWithAddresses:@[_lastV6Addr]
                                                      networkPrefixLengths:@[@(_lastV6PrefixLen)]];
        ipv6.includedRoutes = @[[NEIPv6Route defaultRoute]];
        networkSettings.IPv6Settings = ipv6;
        if (_lastV6Dns.count > 0) {
            NSMutableArray *allDns = [NSMutableArray arrayWithArray:dns];
            [allDns addObjectsFromArray:_lastV6Dns];
            networkSettings.DNSSettings = [[NEDNSSettings alloc] initWithServers:allDns];
        }
    }

    SSLogM(@"SoftEther: network settings ip=%@ mask=%@ gw=%@ dns=%@", ip, mask, gw, dns);
    _lastV4Settings = networkSettings;
    _tunnelUp = YES;
    if (_settingsCb) _settingsCb(networkSettings);
    if (_connectedCb) _connectedCb();
}

#pragma mark - IPv6 (RA/SLAAC)

- (void)applyV6WithAddress:(NSString *)addr prefixLen:(NSInteger)prefixLen
                   gateway:(NSString *)gw dnsCsv:(NSString *)dnsCsv {
    _lastV6Addr = addr;
    _lastV6PrefixLen = prefixLen;
    _lastV6Gw = gw;
    _lastV6Dns = [dnsCsv length] > 0 ? [dnsCsv componentsSeparatedByString:@","] : @[];

    // Re-apply the full settings: v4 (already up) + v6
    NEPacketTunnelNetworkSettings *networkSettings = _lastV4Settings;
    if (networkSettings == nil) {
        NSString *remote = _resolvedRemote ?: gw;
        networkSettings = [[NEPacketTunnelNetworkSettings alloc] initWithTunnelRemoteAddress:remote];
    }
    NEIPv6Settings *ipv6 = [[NEIPv6Settings alloc] initWithAddresses:@[addr]
                                                  networkPrefixLengths:@[@(prefixLen)]];
    ipv6.includedRoutes = @[[NEIPv6Route defaultRoute]];
    networkSettings.IPv6Settings = ipv6;
    if (_lastV6Dns.count > 0) {
        NSMutableArray *allDns = [NSMutableArray arrayWithArray:networkSettings.DNSSettings.servers ?: @[]];
        [allDns addObjectsFromArray:_lastV6Dns];
        networkSettings.DNSSettings = [[NEDNSSettings alloc] initWithServers:allDns];
    }
    SSLogM(@"SoftEther: IPv6 settings addr=%@/%ld gw=%@ dns=%@", addr, (long)prefixLen, gw, _lastV6Dns);
    if (_settingsCb) _settingsCb(networkSettings);
}

#pragma mark - packet injection

- (void)injectPacket:(NSData *)packet family:(int)family {
    if (packet.length < 20) return;
    dispatch_async(_worker, ^{
        if (self->_client != NULL) {
            SRPSEClientInjectPacket(self->_client, packet.bytes, (uint32_t)packet.length,
                                    family == AF_INET6 ? 6 : 4);
        }
    });
}

#pragma mark - Switch to Wi-Fi

- (void)startPathMonitor {
    [self stopPathMonitor];
    if (!_switchToWifi) return;
    _lastPathHadWifi = NO;
    _pathMonitor = nw_path_monitor_create();
    __weak SRPSoftEtherClient *weakSelf = self;
    nw_path_monitor_set_queue(_pathMonitor, _worker);
    nw_path_monitor_set_update_handler(_pathMonitor, ^(nw_path_t path) {
        SRPSoftEtherClient *strongSelf = weakSelf;
        if (!strongSelf) return;
        BOOL satisfied = nw_path_get_status(path) == nw_path_status_satisfied;
        BOOL hasWifi = satisfied && nw_path_uses_interface_type(path, nw_interface_type_wifi);
        BOOL hadWifi = strongSelf->_lastPathHadWifi;
        strongSelf->_lastPathHadWifi = hasWifi;
        if (SSShouldReconnectForPathChange(hadWifi, hasWifi, satisfied, strongSelf->_tunnelUp)) {
            SSLogM(@"Wi-Fi became available; switching the SoftEther connection to the new path");
            strongSelf->_failedAttempts = 0;
            [strongSelf startLocked];   // deliberate migration: not a failure
        }
    });
    nw_path_monitor_start(_pathMonitor);
}

- (void)stopPathMonitor {
    if (_pathMonitor != nil) {
        nw_path_monitor_cancel(_pathMonitor);
        _pathMonitor = nil;
    }
}

#pragma mark - On Sleep

- (void)pauseForSleep {
    dispatch_async(_worker, ^{
        if (self->_onSleep == 2 || self->_closedManually) {
            return;   // stay: keep the connection up
        }
        SSLogM(@"device sleep: %@ the SoftEther connection", self->_onSleep == 1 ? @"pausing" : @"closing");
        self->_sleepPaused = YES;
        [self stopLockedSession];
    });
}

- (void)wakeFromSleep {
    dispatch_async(_worker, ^{
        if (!self->_sleepPaused || self->_closedManually) {
            return;
        }
        self->_sleepPaused = NO;
        if (self->_onSleep == 1 || self->_autoReconnect) {
            self->_failedAttempts = 0;
            SSLogM(@"device wake: reconnecting the SoftEther connection");
            [self startLocked];
        }
    });
}

@end
