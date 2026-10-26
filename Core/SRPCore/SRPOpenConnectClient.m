//
//  SRPOpenConnectClient.m
//  SRPCore
//

#import "SRPOpenConnectClient.h"
#import "SSLog.h"
#import "SSNetOptions.h"
#import "SSSSTPClient.h"   // SSSstp p12->PEM helpers reuse

#import <NetworkExtension/NetworkExtension.h>
#import <Security/Security.h>
#import <Network/Network.h>
#import <arpa/inet.h>
#import <netdb.h>

#include <sys/socket.h>
#include <unistd.h>
#include <string.h>

#include "openconnect.h"

@implementation SRPOpenConnectClient {
    dispatch_queue_t _worker;
    struct openconnect_info *_vpn;
    int _tunFds[2];               // [0]=library side, [1]=our pump side
    int _cmdFd;                   // write side of the OC command pipe
    NSThread *_loopThread;
    NSThread *_pumpThread;
    BOOL _pumpStop;
    dispatch_semaphore_t _loopDone;

    SRPOCOutputCallback _outputCb;
    SRPOCNetworkSettingsCallback _settingsCb;
    SRPOCConnectedCallback _connectedCb;
    SRPOCDisconnectedCallback _disconnectedCb;
    SRPOCFailureCallback _failureCb;

    BOOL _closedManually;
    BOOL _sleepPaused;
    BOOL _tunnelUp;
    BOOL _settingsApplied;
    BOOL _established;
    BOOL _authFailed;
    BOOL _certFailed;
    NSInteger _failedAttempts;
    nw_path_monitor_t _pathMonitor;
    BOOL _lastPathHadWifi;
    int _authRounds;
    long _injectCount;
    long _pumpCount;
}

static void ocProgress(void *privdata, int level, const char *fmt, ...);
static int ocValidatePeerCert(void *privdata, const char *reason);
static int ocWriteNewConfig(void *privdata, const char *buf, int buflen);
static int ocAuthForm(void *privdata, struct oc_auth_form *form);

+ (void)initializeCore {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        openconnect_init_ssl();
    });
}

- (instancetype)init {
    self = [super init];
    if (self) {
        _worker = dispatch_queue_create("srp.openconnect", DISPATCH_QUEUE_SERIAL);
        _port = 443;
        _ocProtocol = @"anyconnect";
        _tlsServerVerification = YES;
        _autoReconnect = YES;
        _switchToWifi = YES;
        _onSleep = 2;
        _tunFds[0] = _tunFds[1] = -1;
        _cmdFd = -1;
        _loopDone = dispatch_semaphore_create(0);
    }
    return self;
}

#pragma mark - libopenconnect callbacks (run on library threads)

static void ocProgress(void *privdata, int level, const char *fmt, ...) {
    char buf[1024];
    va_list ap; va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    NSString *line = [[NSString stringWithUTF8String:buf]
                      stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
    if (line.length == 0) return;
    if (level <= 1) {
        SSLogI(@"[oc] %@", line);   // err/info -> expert
    } else {
        SSLogD(@"[oc] %@", line);   // debug/trace -> debug
    }
}

static int ocWriteNewConfig(void *privdata, const char *buf, int buflen) {
    return 0;   // we don't persist server XML configs
}

static int ocValidatePeerCert(void *privdata, const char *reason) {
    SRPOpenConnectClient *self = (__bridge SRPOpenConnectClient *)privdata;
    if (!self->_tlsServerVerification) {
        SSLogM(@"OpenConnect TLS: verification disabled — accepting (%s)", reason ?: "");
        return 0;
    }
    // Rebuild the chain from the server-sent DERs and evaluate with SecTrust
    struct oc_cert *chain_c = NULL;
    int n = openconnect_get_peer_cert_chain(self->_vpn, &chain_c);
    NSMutableArray *chain = [NSMutableArray array];
    for (int i = 0; i < n; i++) {
        NSData *der = [NSData dataWithBytes:chain_c[i].der_data length:chain_c[i].der_len];
        SecCertificateRef c = SecCertificateCreateWithData(NULL, (__bridge CFDataRef)der);
        if (c) [chain addObject:(__bridge_transfer id)c];
    }
    if (chain_c) openconnect_free_peer_cert_chain(self->_vpn, chain_c);
    if (chain.count == 0) {
        SSLogM(@"OpenConnect TLS: no server certificates to evaluate");
        return 1;
    }
    NSString *host = self->_host;
    SecPolicyRef policy = SecPolicyCreateSSL(true, (__bridge CFStringRef)host);
    SecTrustRef trust = NULL;
    if (SecTrustCreateWithCertificates((__bridge CFArrayRef)chain, policy, &trust) != errSecSuccess) {
        if (policy) CFRelease(policy);
        return 1;
    }
    CFErrorRef err = NULL;
    BOOL ok = SecTrustEvaluateWithError(trust, &err);
    if (!ok) {
        SSLogM(@"OpenConnect TLS: certificate not trusted for %@: %@", host,
               err ? (__bridge NSError *)err : @"unknown");
        self->_certFailed = YES;
    } else {
        SSLogI(@"OpenConnect TLS: server certificate trusted for %@", host);
    }
    if (err) CFRelease(err);
    if (trust) CFRelease(trust);
    if (policy) CFRelease(policy);
    return ok ? 0 : 1;
}

static int ocAuthForm(void *privdata, struct oc_auth_form *form) {
    SRPOpenConnectClient *self = (__bridge SRPOpenConnectClient *)privdata;
    if (form->error != NULL) {
        SSLogM(@"OpenConnect: authentication failed: %s", form->error);
        self->_authFailed = YES;
        return 1;   // cancel — do not resubmit wrong credentials
    }
    self->_authRounds++;
    if (self->_authRounds > 3) {
        SSLogM(@"OpenConnect: authentication failed (server keeps rejecting the credentials)");
        self->_authFailed = YES;
        return 1;
    }
    SSLogI(@"OpenConnect: auth form %s %s (round %d)", form->method, form->action, self->_authRounds);
    struct oc_form_opt *opt = form->opts;
    while (opt) {
        if (opt->type == OC_FORM_OPT_TEXT && opt->name &&
            (strcmp(opt->name, "username") == 0 || strcmp(opt->name, "user") == 0)) {
            openconnect_set_option_value(opt, self->_username.UTF8String);
        } else if (opt->type == OC_FORM_OPT_PASSWORD) {
            openconnect_set_option_value(opt, self->_password ? self->_password.UTF8String : "");
        } else if (opt->type == OC_FORM_OPT_TEXT && opt->label &&
                   strcasestr(opt->label, "user") && opt->_value == NULL) {
            openconnect_set_option_value(opt, self->_username.UTF8String);
        }
        opt = opt->next;
    }
    return 0;
}

#pragma mark - lifecycle

- (void)startWithOutputCallback:(SRPOCOutputCallback)output
         networkSettingsCallback:(SRPOCNetworkSettingsCallback)settings
               connectedCallback:(SRPOCConnectedCallback)connected
            disconnectedCallback:(SRPOCDisconnectedCallback)disconnected
                 failureCallback:(SRPOCFailureCallback)failure {
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

    _authFailed = NO;
    _certFailed = NO;
    _authRounds = 0;

    _vpn = openconnect_vpninfo_new("SRP VPN Connect",
                                   ocValidatePeerCert, ocWriteNewConfig,
                                   ocAuthForm, ocProgress,
                                   (__bridge void *)self);
    if (_vpn == NULL) {
        [self failWithReason:@"Internal error creating the OpenConnect session"];
        return;
    }
    openconnect_set_loglevel(_vpn, _logLevel == 2 ? 2 : (_logLevel == 1 ? 1 : 0));

    // Optional TLS write splitting (ClientHello). Auto policy mirrors the
    // SSTP channel: 43 bytes cover the record+handshake headers and the
    // client random (the SNI always lands later); the chunk size and gap
    // follow the access technology.
    if (_tlsFragMode > 0) {
        int first = 43, following = 256, gap = 3;
        if (_tlsFragMode == 1) {
            first = (int)_tlsFragFirst;
            following = (int)_tlsFragFollowing;
            gap = 3;
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
        openconnect_set_tls_fragmentation(_vpn, first, following, gap);
        SSLogM(@"OpenConnect: TLS fragmentation %@ (first=%d following=%d gap=%d ms)",
               _tlsFragMode == 2 ? @"auto" : @"manual", first, following, gap);
    }
    if (openconnect_set_protocol(_vpn, _ocProtocol.UTF8String) != 0) {
        SSLogM(@"OpenConnect: unsupported protocol %@", _ocProtocol);
    }
    // GP defers its HTTPS tunnel until ESP (UDP) probing fails (~5s), which would
    // open a NEW TLS connection after the tunnel routes are up — blackholed on
    // iOS. Disable ESP upfront so the HTTPS tunnel connects during the initial
    // handshake, before any routes are applied. (Also: ESP to this gateway does
    // not work on our test networks anyway.)
    if ([_ocProtocol isEqualToString:@"gp"]) {
        openconnect_disable_dtls(_vpn);
    }
    openconnect_set_reported_os(_vpn, "apple-ios");
    openconnect_set_mobile_info(_vpn, NULL, "iPhone", NULL);

    // Client certificate (optional): convert the stored p12 to PEM files
    NSString *certPath = nil, *keyPath = nil;
    if (_clientCertP12 != nil) {
        SSSstp *helper = [SSSstp new];
        if ([helper setEapTlsP12:_clientCertP12 passphrase:_clientCertPassphrase ?: @""]) {
            NSString *dir = NSTemporaryDirectory();
            certPath = [dir stringByAppendingPathComponent:@"srp_oc_client.pem"];
            keyPath = [dir stringByAppendingPathComponent:@"srp_oc_key.pem"];
            [helper.eapTlsCertPem writeToFile:certPath atomically:YES];
            [helper.eapTlsKeyPem writeToFile:keyPath atomically:YES];
        } else {
            [self failWithReason:@"The client certificate could not be read. Re-import it in the profile."];
            return;
        }
    }
    if (certPath != nil &&
        openconnect_set_client_cert(_vpn, certPath.UTF8String, keyPath.UTF8String) != 0) {
        SSLogM(@"OpenConnect: client certificate rejected");
    }

    NSString *url = [NSString stringWithFormat:@"https://%@:%d/", _host, _port];
    if (openconnect_parse_url(_vpn, url.UTF8String) != 0) {
        [self failWithReason:@"Invalid server address"];
        return;
    }

    SSLogM(@"OpenConnect connecting to %@ (protocol %@, user %@, verify=%d)",
           url, _ocProtocol, _username, _tlsServerVerification);

    _loopThread = [[NSThread alloc] initWithBlock:^{ [self runLoop]; }];
    _loopThread.name = @"oc-mainloop";
    [_loopThread start];
}

// Whole connection lifecycle runs on this thread (obtain_cookie blocks).
- (void)runLoop {
    @autoreleasepool {
        if (openconnect_obtain_cookie(_vpn) != 0) {
            dispatch_semaphore_signal(_loopDone);
            [self loopFailed:_certFailed
                        ? @"The server's certificate is not trusted. Enable \"Allow Untrusted Certificate\" in the profile to connect anyway."
                        : (_authFailed
                           ? @"Authentication failed. Check the username and password."
                           : @"Cannot reach the server (DNS/TCP/TLS failed). Check the Server field and the network.")];
            return;
        }
        if (openconnect_make_cstp_connection(_vpn) != 0) {
            dispatch_semaphore_signal(_loopDone);
            [self loopFailed:_certFailed
                        ? @"The server's certificate is not trusted. Enable \"Allow Untrusted Certificate\" in the profile to connect anyway."
                        : @"TLS tunnel setup failed. Check the server and certificate settings."];
            return;
        }
        // UDP transport (DTLS) is best-effort. GP never gets here — ESP is
        // disabled at session start (see startLocked).
        if (![_ocProtocol isEqualToString:@"gp"] && openconnect_setup_dtls(_vpn, 60) == 0) {
            SSLogM(@"OpenConnect: DTLS (UDP) transport established");
        } else {
            SSLogI(@"OpenConnect: DTLS/ESP unavailable — TLS only");
        }


        if (socketpair(AF_UNIX, SOCK_DGRAM, 0, _tunFds) != 0) {
            dispatch_semaphore_signal(_loopDone);
            [self loopFailed:@"Internal error creating the packet channel"];
            return;
        }
        _cmdFd = openconnect_setup_cmd_pipe(_vpn);
        if (openconnect_setup_tun_fd(_vpn, _tunFds[0]) != 0) {
            dispatch_semaphore_signal(_loopDone);
            [self loopFailed:@"Internal error attaching packet I/O"];
            return;
        }

        _pumpStop = NO;
        _pumpThread = [[NSThread alloc] initWithBlock:^{ [self pumpLoop]; }];
        _pumpThread.name = @"oc-pump";
        [_pumpThread start];

        // Poll for tunnel settings on the worker: PPP backends (F5/Fortinet)
        // assign addresses via IPCP inside the mainloop; CSTP has them already.
        _settingsApplied = NO;
        dispatch_async(_worker, ^{ [self pollForSettings]; });

        _established = YES;
        _tunnelUp = YES;
        _failedAttempts = 0;
        SSLogM(@"OpenConnect: session established");

        int ret = openconnect_mainloop(_vpn, 300, 10);
        SSLogM(@"OpenConnect: mainloop exited (%d)", ret);
        dispatch_semaphore_signal(_loopDone);
        [self loopEnded:ret];
    }
}

- (NEPacketTunnelNetworkSettings *)buildSettingsFromInfo:(const struct oc_ip_info *)info {
    NSString *remote = _host;
    struct in_addr a4;
    if (inet_pton(AF_INET, _host.UTF8String, &a4) != 1) {
        // resolve once for tunnelRemoteAddress
        struct hostent *he = gethostbyname(_host.UTF8String);
        if (he && he->h_length == 4) {
            char buf[INET_ADDRSTRLEN];
            if (inet_ntop(AF_INET, he->h_addr_list[0], buf, sizeof(buf))) remote = @(buf);
        }
    }
    SSLogM(@"OpenConnect: tunnelRemoteAddress=%@ (host %@)", remote, _host);
    NEPacketTunnelNetworkSettings *settings =
        [[NEPacketTunnelNetworkSettings alloc] initWithTunnelRemoteAddress:remote];

    NSMutableArray<NSString *> *dns = [NSMutableArray array];
    for (int i = 0; i < 3 && info->dns[i]; i++) {
        // Some backends (F5 PPP) deliver several servers in one
        // space/comma-separated string — split into individual valid entries.
        NSString *raw = @(info->dns[i]);
        for (NSString *part in [raw componentsSeparatedByCharactersInSet:
                                [NSCharacterSet characterSetWithCharactersInString:@" ,;"]]) {
            if (part.length == 0) continue;
            struct in_addr a4; struct in6_addr a6;
            if (inet_pton(AF_INET, part.UTF8String, &a4) == 1 ||
                inet_pton(AF_INET6, part.UTF8String, &a6) == 1) {
                [dns addObject:part];
            }
        }
    }
    NEDNSSettings *dnsSettings = [[NEDNSSettings alloc] initWithServers:dns.count ? dns : @[@"1.1.1.1"]];
    if (info->domain) dnsSettings.domainName = @(info->domain);
    settings.DNSSettings = dnsSettings;
    if (info->mtu > 0) settings.MTU = @(info->mtu);

    if (info->addr) {
        // PPP backends (F5/Fortinet) may not send a netmask — 0.0.0.0 or NULL
        // breaks the iOS tunnel interface (everything becomes "local").
        NSString *mask = (info->netmask && strlen(info->netmask) > 0 &&
                          strcmp(info->netmask, "0.0.0.0") != 0)
                         ? @(info->netmask) : @"255.255.255.0";
        NEIPv4Settings *v4 = [[NEIPv4Settings alloc] initWithAddresses:@[@(info->addr)]
                                                          subnetMasks:@[mask]];
        NSMutableArray<NEIPv4Route *> *includes = [NSMutableArray array];
        BOOL split = NO;
        for (struct oc_split_include *inc = info->split_includes; inc; inc = inc->next) {
            NEIPv4Route *r = [self routeFromCIDR:@(inc->route)];
            if (r) { [includes addObject:r]; split = YES; }
        }
        if (split) {
            v4.includedRoutes = includes;
        } else {
            v4.includedRoutes = @[[NEIPv4Route defaultRoute]];
        }
        NSMutableArray<NEIPv4Route *> *excludes = [NSMutableArray array];
        for (struct oc_split_include *exc = info->split_excludes; exc; exc = exc->next) {
            NEIPv4Route *r = [self routeFromCIDR:@(exc->route)];
            if (r) [excludes addObject:r];
        }
        // The VPN server itself must stay on the physical path — otherwise the
        // tunnel's own TLS traffic is routed into the utun and blackholed.
        struct in_addr ra;
        if (inet_pton(AF_INET, remote.UTF8String, &ra) == 1) {
            [excludes addObject:[[NEIPv4Route alloc] initWithDestinationAddress:remote
                                                                   subnetMask:@"255.255.255.255"]];
        }
        if (excludes.count) v4.excludedRoutes = excludes;
        settings.IPv4Settings = v4;
    }
    if (info->addr6) {
        // addr6 is "address"; netmask6 is "address/prefix"
        NSString *addr6 = @(info->addr6);
        NSInteger prefixLen = 64;
        if (info->netmask6) {
            NSString *nm6 = @(info->netmask6);
            NSRange slash = [nm6 rangeOfString:@"/"];
            if (slash.location != NSNotFound) {
                prefixLen = [[nm6 substringFromIndex:slash.location + 1] integerValue];
            }
        }
        NEIPv6Settings *v6 = [[NEIPv6Settings alloc] initWithAddresses:@[addr6]
                                                    networkPrefixLengths:@[@(prefixLen)]];
        v6.includedRoutes = @[[NEIPv6Route defaultRoute]];
        settings.IPv6Settings = v6;
    }
    return settings;
}

- (NEIPv4Route *)routeFromCIDR:(NSString *)cidr {
    NSArray *parts = [cidr componentsSeparatedByString:@"/"];
    if (parts.count != 2) return nil;
    NSString *addr = parts[0];
    NSInteger bits = [parts[1] integerValue];
    if (bits < 0 || bits > 32) return nil;
    uint32_t mask = bits == 0 ? 0 : (0xFFFFFFFFu << (32 - bits));
    NSString *maskStr = [NSString stringWithFormat:@"%u.%u.%u.%u",
                         (mask >> 24) & 0xFF, (mask >> 16) & 0xFF, (mask >> 8) & 0xFF, mask & 0xFF];
    return [[NEIPv4Route alloc] initWithDestinationAddress:addr subnetMask:maskStr];
}

- (void)pollForSettings {
    // Runs on _worker. Reads ip_info while mainloop runs on _loopThread —
    // acceptable for v1: fields transition NULL -> set once during connect.
    if (_closedManually || _sleepPaused || _settingsApplied || _vpn == NULL) return;
    const struct oc_ip_info *info = NULL;
    for (int i = 0; i < 60; i++) {
        if (_closedManually || _sleepPaused || _settingsApplied || _vpn == NULL) return;
        if (openconnect_get_ip_info(_vpn, &info, NULL, NULL) == 0 &&
            info != NULL && (info->addr != NULL || info->addr6 != NULL)) {
            _settingsApplied = YES;
            SSLogM(@"OpenConnect: got settings addr=%s mask=%s dns=%s mtu=%d",
                   info->addr ? info->addr : "-",
                   info->netmask ? info->netmask : "-",
                   info->dns[0] ? info->dns[0] : "-", info->mtu);
            NEPacketTunnelNetworkSettings *settings = [self buildSettingsFromInfo:info];
            [self applySettings:settings];
            return;
        }
        [NSThread sleepForTimeInterval:0.25];
    }
    SSLogM(@"OpenConnect: server did not assign tunnel settings (timeout)");
}

- (void)applySettings:(NEPacketTunnelNetworkSettings *)settings {
    SRPOCNetworkSettingsCallback cb = _settingsCb;
    dispatch_async(_worker, ^{
        if (cb) cb(settings);
        if (self->_connectedCb) self->_connectedCb();
    });
}

// Packet pump: library-side fd -> packetFlow; packetFlow -> injectPacket -> our fd.
- (void)pumpLoop {
    uint8_t buf[2200];
    while (!_pumpStop && _tunFds[1] >= 0) {
        ssize_t n = read(_tunFds[1], buf, sizeof(buf));
        if (n <= 4) {
            if (n < 0 && (errno == EAGAIN || errno == EINTR)) continue;
            if (n <= 0) break;
            continue;
        }
        _pumpCount++;
        if (_pumpCount <= 5 || _pumpCount % 100 == 0) {
            SSLogD(@"OpenConnect: pump #%ld len=%zd", _pumpCount, n - 4);
        }
        uint32_t af = ntohl(*(uint32_t *)buf);
        int family = (af == AF_INET6) ? AF_INET6 : AF_INET;
        NSData *pkt = [NSData dataWithBytes:buf + 4 length:n - 4];
        SRPOCOutputCallback cb = _outputCb;
        if (cb) cb(pkt, family);
    }
    SSLogM(@"OpenConnect: pumpLoop exited (total %ld packets)", _pumpCount);
}

- (void)injectPacket:(NSData *)packet family:(int)family {
    if (packet.length < 20 || packet.length > 2048) return;
    uint32_t af = htonl(family == AF_INET6 ? AF_INET6 : AF_INET);
    NSMutableData *d = [NSMutableData dataWithCapacity:packet.length + 4];
    [d appendBytes:&af length:4];
    [d appendBytes:packet.bytes length:packet.length];
    dispatch_async(_worker, ^{
        int fd = self->_tunFds[1];
        self->_injectCount++;
        if (self->_injectCount <= 5 || self->_injectCount % 100 == 0) {
            SSLogD(@"OpenConnect: inject #%ld len=%lu fd=%d established=%d",
                   self->_injectCount, (unsigned long)packet.length, fd, self->_established);
        }
        if (fd >= 0 && self->_established) {
            ssize_t w = write(fd, d.bytes, d.length);
            if (w < 0) {
                SSLogE(@"OpenConnect: inject write failed: errno=%d (%s)", errno, strerror(errno));
            }
        }
    });
}

#pragma mark - end of life / reconnect

- (void)loopFailed:(NSString *)reason {
    dispatch_async(_worker, ^{
        [self teardownLocked];
        if (self->_closedManually) return;
        [self failWithReason:reason];
    });
}

- (void)loopEnded:(int)ret {
    dispatch_async(_worker, ^{
        BOOL wasUp = self->_tunnelUp;
        [self teardownLocked];
        if (self->_closedManually || self->_sleepPaused) return;
        if (wasUp && self->_disconnectedCb) self->_disconnectedCb();
        self->_tunnelUp = NO;
        if (ret == 0) return;   // clean exit

        if (!wasUp || self->_authFailed) {
            [self failWithReason:self->_authFailed
                ? @"Authentication failed. Check the username and password."
                : @"Connection failed before the tunnel was established."];
            return;
        }
        if (!self->_autoReconnect) {
            [self failWithReason:@"Connection lost (auto reconnect is off)."];
            return;
        }
        if (!SSReconnectAttemptAllowed(self->_failedAttempts, self->_retryTimes)) {
            [self failWithReason:[NSString stringWithFormat:
                @"Could not reconnect after %ld attempts.", (long)self->_retryTimes]];
            return;
        }
        self->_failedAttempts++;
        SSLogM(@"OpenConnect: reconnecting in 2s (attempt %ld%@)",
               (long)self->_failedAttempts,
               self->_retryTimes > 0 ? [NSString stringWithFormat:@" of %ld", (long)self->_retryTimes] : @"");
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2 * NSEC_PER_SEC)), self->_worker, ^{
            if (!self->_closedManually && !self->_sleepPaused) {
                [self startLocked];
            }
        });
    });
}

- (void)teardownLocked {
    _established = NO;
    _pumpStop = YES;
    if (_cmdFd >= 0 && _vpn != NULL) {
        char cmd = OC_CMD_CANCEL;
        (void)write(_cmdFd, &cmd, 1);
    }
    // Wait until the library thread has left openconnect_mainloop before
    // freeing the vpninfo (freeing mid-loop would crash)
    if (_loopThread != nil) {
        dispatch_semaphore_wait(_loopDone, dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC));
    }
    // Wake the pump read
    if (_tunFds[1] >= 0) { shutdown(_tunFds[1], SHUT_RDWR); }
    // vpninfo_free closes cmd pipe + tun fd [0]; we own [1]
    if (_vpn != NULL) {
        openconnect_vpninfo_free(_vpn);
        _vpn = NULL;
    }
    if (_tunFds[1] >= 0) { close(_tunFds[1]); _tunFds[1] = -1; }
    _tunFds[0] = -1;
    _cmdFd = -1;
    _pumpThread = nil;
    _loopThread = nil;
}

- (void)stopLockedSession {
    if (_vpn != NULL) {
        [self teardownLocked];
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

- (void)failWithReason:(NSString *)reason {
    SRPOCFailureCallback cb = _failureCb;
    [self stopLockedSession];
    [self stopPathMonitor];
    if (cb) cb(reason);
}

#pragma mark - Switch to Wi-Fi

- (void)startPathMonitor {
    [self stopPathMonitor];
    if (!_switchToWifi) return;
    _lastPathHadWifi = NO;
    _pathMonitor = nw_path_monitor_create();
    __weak SRPOpenConnectClient *weakSelf = self;
    nw_path_monitor_set_queue(_pathMonitor, _worker);
    nw_path_monitor_set_update_handler(_pathMonitor, ^(nw_path_t path) {
        SRPOpenConnectClient *strongSelf = weakSelf;
        if (!strongSelf) return;
        BOOL satisfied = nw_path_get_status(path) == nw_path_status_satisfied;
        BOOL hasWifi = satisfied && nw_path_uses_interface_type(path, nw_interface_type_wifi);
        BOOL hadWifi = strongSelf->_lastPathHadWifi;
        strongSelf->_lastPathHadWifi = hasWifi;
        if (SSShouldReconnectForPathChange(hadWifi, hasWifi, satisfied, strongSelf->_tunnelUp)) {
            SSLogM(@"Wi-Fi became available; switching the OpenConnect connection to the new path");
            strongSelf->_failedAttempts = 0;
            [strongSelf startLocked];
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
        if (self->_onSleep == 2 || self->_closedManually) return;
        SSLogM(@"device sleep: %@ the OpenConnect connection", self->_onSleep == 1 ? @"pausing" : @"closing");
        self->_sleepPaused = YES;
        [self stopLockedSession];
    });
}

- (void)wakeFromSleep {
    dispatch_async(_worker, ^{
        if (!self->_sleepPaused || self->_closedManually) return;
        self->_sleepPaused = NO;
        if (self->_onSleep == 1 || self->_autoReconnect) {
            self->_failedAttempts = 0;
            SSLogM(@"device wake: reconnecting the OpenConnect connection");
            [self startLocked];
        }
    });
}

@end
