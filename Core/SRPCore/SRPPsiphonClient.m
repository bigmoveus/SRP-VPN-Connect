//
//  SRPPsiphonClient.m
//  SRPCore
//

#import "SRPPsiphonClient.h"
#import "SSLog.h"
#import <NetworkExtension/NetworkExtension.h>
#import <arpa/inet.h>
#import <fcntl.h>
#import <sys/socket.h>
#import <unistd.h>

// Psiphon clientlib (in the WG bridge Go archive)
extern char *srppsiStart(const char *configJSON, const char *entries, const char *dataRoot);
extern void srppsiStop(void);
extern void wgSetLogger(void *ctx, void *fn);   // the bridge's shared Go logger

static void SRPPsiGoLog(void *ctx, int level, const char *msg) {
    (void)ctx;
    if (!msg) return;
    if (level == 0 && !SSLogEnabled(SSLogLevelDebug)) return;
    SSLogM(@"[psi-go] %s", msg);
}

// hev-socks5-tunnel core (built into the SSH engine lib, srpssh_ prefix)
extern int srpssh_hev_socks5_tunnel_main_from_str(const unsigned char *conf, unsigned int len, int tun_fd);
extern void srpssh_hev_socks5_tunnel_quit(void);

@implementation SRPPsiphonClient {
    SRPPsiphonOutputCallback _outputCb;
    SRPPsiphonNetworkSettingsCallback _settingsCb;
    SRPPsiphonConnectedCallback _connectedCb;
    SRPPsiphonFailureCallback _failureCb;
    dispatch_queue_t _worker;
    dispatch_source_t _readSource;
    int _tunFd;
    NSArray<NSString *> *_serverIPs;
    BOOL _retriedWithCleanState;
    NSThread *_hevThread;
    BOOL _closed;
}

- (instancetype)init {
    self = [super init];
    if (self) {
        _worker = dispatch_queue_create("srp.psiphon", DISPATCH_QUEUE_SERIAL);
        _tunFd = -1;
    }
    return self;
}

- (void)startWithOutputCallback:(SRPPsiphonOutputCallback)output
         networkSettingsCallback:(SRPPsiphonNetworkSettingsCallback)settings
               connectedCallback:(SRPPsiphonConnectedCallback)connected
                 failureCallback:(SRPPsiphonFailureCallback)failure {
    _outputCb = output;
    _settingsCb = settings;
    _connectedCb = connected;
    _failureCb = failure;
    _closed = NO;
    SSLogSetLevel((SSLogLevel)_logLevel);
    dispatch_async(_worker, ^{ [self startLocked]; });
}

- (void)startLocked {
    // The Psiphon data root must be writable by the extension
    NSURL *container = [[NSFileManager defaultManager]
        containerURLForSecurityApplicationGroupIdentifier:@"group.tr.com.srp.vpn"];
    NSString *dataRoot = [container.path stringByAppendingPathComponent:@"Library/psiphon"];
    [[NSFileManager defaultManager] createDirectoryAtPath:dataRoot
                              withIntermediateDirectories:YES attributes:nil error:nil];

    // One or more hex-encoded psiphond server entries (whitespace/comma
    // separated); the core rotates between them with its tactics
    NSString *raw = [_serverEntry stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet] ?: @"";
    NSMutableArray *entries = [NSMutableArray new];
    for (NSString *p in [raw componentsSeparatedByCharactersInSet:
                         [NSCharacterSet characterSetWithCharactersInString:@" \t\r\n,"]]) {
        if (p.length > 0) [entries addObject:p];
    }
    if (entries.count == 0) {
        _failureCb(@"Psiphon: no server entry — paste your psiphond server entry");
        return;
    }
    NSString *entryList = [entries componentsJoinedByString:@"\n"];

    // The servers' own addresses must stay on the physical path
    NSMutableArray<NSString *> *ips = [NSMutableArray new];
    if (_serverIP.length > 0) [ips addObject:_serverIP];
    for (NSString *hex in entries) {
        NSMutableData *data = [NSMutableData new];
        for (NSUInteger i = 0; i + 1 < hex.length; i += 2) {
            unsigned int byte = 0;
            [[NSScanner scannerWithString:[hex substringWithRange:NSMakeRange(i, 2)]] scanHexInt:&byte];
            [data appendBytes:&byte length:1];
        }
        // The .dat format prefixes the JSON with legacy fields ("0 0 0 0 ")
        NSString *text = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
        NSUInteger brace = [text rangeOfString:@"{"].location;
        if (brace == NSNotFound) continue;
        NSDictionary *j = [NSJSONSerialization JSONObjectWithData:
                           [[text substringFromIndex:brace] dataUsingEncoding:NSUTF8StringEncoding]
                                                          options:0 error:nil];
        NSString *ip = j[@"ipAddress"];
        if ([ip isKindOfClass:NSString.class] && ip.length > 0 && ![ips containsObject:ip]) {
            [ips addObject:ip];
        }
    }
    _serverIPs = ips;

    NSMutableDictionary *config = [@{
        @"LocalSocksProxyPort": @0,          // auto-pick; the port comes back in the result
        @"DisableLocalHTTPProxy": @YES,
        @"PropagationChannelId": @"24BCA4EE20BEB92C",
        @"SponsorId": @"721AE60D76700F5A",
        @"ClientPlatform": @"iOS_tr.com.srp.vpn",
        @"NetworkID": @"WIFI",
    } mutableCopy];
    // DEBUG/testing: psi_protos=OSSH,QUIC-OSSH,... limits the transports
    NSArray *limit = [_limitProtocols componentsSeparatedByString:@","];
    if (limit.count > 0 && [limit[0] length] > 0) {
        config[@"LimitTunnelProtocols"] = limit;
    }
    NSData *configData = [NSJSONSerialization dataWithJSONObject:config options:0 error:nil];
    NSString *configJson = [[NSString alloc] initWithData:configData encoding:NSUTF8StringEncoding];

    SSLogM(@"Psiphon: starting tunnel core (%lu server entries)", (unsigned long)entries.count);
    wgSetLogger(NULL, SRPPsiGoLog);   // the core's notices (chosen transport, errors)
    char *result = srppsiStart(configJson.UTF8String, entryList.UTF8String, dataRoot.UTF8String);
    NSString *reply = result ? @(result) : nil;   // owned by the lib; do not free
    NSDictionary *r = reply ? [NSJSONSerialization JSONObjectWithData:[reply dataUsingEncoding:NSUTF8StringEncoding]
                                                            options:0 error:nil] : nil;
    if (![r[@"ok"] boolValue]) {
        // A poisoned tactics database (learned from failed dials, e.g. while
        // the network was down) can make the core give up on every candidate
        // — wipe the state once and retry with a clean slate
        if (_retriedWithCleanState) {
            _failureCb([NSString stringWithFormat:@"Psiphon: %@", r[@"error"] ?: @"failed to start"]);
            return;
        }
        SSLogM(@"Psiphon: establishment failed (%@) — wiping the tactics state and retrying once",
               r[@"error"] ?: @"unknown");
        srppsiStop();
        _retriedWithCleanState = YES;
        [[NSFileManager defaultManager] removeItemAtPath:dataRoot error:nil];
        [[NSFileManager defaultManager] createDirectoryAtPath:dataRoot
                                  withIntermediateDirectories:YES attributes:nil error:nil];
        [self startLocked];
        return;
    }
    NSInteger socksPort = [r[@"socks"] integerValue];
    SSLogM(@"Psiphon: tunnel core up, SOCKS5 on 127.0.0.1:%ld", (long)socksPort);

    if (![self startHevLocked:(int)socksPort]) {
        _failureCb(@"Psiphon: the packet bridge failed to start");
        return;
    }
    if (_settingsCb) _settingsCb([self buildSettings]);
    if (_connectedCb) _connectedCb();
    SSLogM(@"Psiphon: session established");
#if DEBUG
    [self debugProbeSocks:(int)socksPort];
#endif
}

#if DEBUG
/// DEBUG: raw SOCKS5 CONNECT through the psiphon core to 1.1.1.1:443 + a TLS
/// ClientHello; logs the reply and the first TLS record bytes — isolates
/// hev/NSURLSession from the psiphon path when bare-IP TLS fails.
- (void)debugProbeSocks:(int)port {
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        struct timeval tv = { .tv_sec = 8 };
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        struct sockaddr_in sa = {0};
        sa.sin_family = AF_INET;
        sa.sin_port = htons(port);
        inet_pton(AF_INET, "127.0.0.1", &sa.sin_addr);
        if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
            SSLogM(@"Psiphon dbg: socks connect failed (%d)", errno);
            return;
        }
        // greeting + CONNECT 1.1.1.1:443
        const uint8_t hello[3] = {0x05, 0x01, 0x00};
        write(fd, hello, 3);
        uint8_t buf[64];
        ssize_t n = read(fd, buf, 2);
        const uint8_t conn[10] = {0x05, 0x01, 0x00, 0x01, 1,1,1,1, 0x01, 0xBB};
        write(fd, conn, sizeof(conn));
        n = read(fd, buf, 10);
        SSLogM(@"Psiphon dbg: socks5 connect reply n=%zd rep=%02x", n, n > 1 ? buf[1] : 0xff);
        if (n >= 2 && buf[1] == 0) {
            // minimal TLS 1.2 ClientHello with SNI cloudflare-dns.com
            static const char ch[] =
                "\x16\x03\x01\x00\x00";   // we only want the server's first record back
            (void)ch;
            // send nothing valid; just read the server banner timeout
            uint8_t tls[256];
            n = read(fd, tls, sizeof(tls));
            SSLogM(@"Psiphon dbg: post-connect read n=%zd errno=%d", n, errno);
        }
        close(fd);
    });
}
#endif

/// utun <-> SOCKS5 bridge (hev core). Mapped-DNS layout: Psiphon carries
/// TCP only, so DNS is answered locally with fake 198.18.x.x addresses and
/// connections carry the hostname for Psiphon to resolve.
- (BOOL)startHevLocked:(int)socksPort {
    int fds[2];
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, fds) != 0) return NO;
    _tunFd = fds[0];
    int hevFd = fds[1];   // C arrays cannot be captured by blocks

    // Default local-dgram buffers are ~4KB — a connect-time burst overruns
    // them instantly (same fix as the SSH bridge)
    int bufsz = 512 * 1024;
    setsockopt(fds[0], SOL_SOCKET, SO_RCVBUF, &bufsz, sizeof(bufsz));
    setsockopt(fds[0], SOL_SOCKET, SO_SNDBUF, &bufsz, sizeof(bufsz));
    setsockopt(fds[1], SOL_SOCKET, SO_RCVBUF, &bufsz, sizeof(bufsz));
    setsockopt(fds[1], SOL_SOCKET, SO_SNDBUF, &bufsz, sizeof(bufsz));
    // The dispatch-source read loop must never park on a blocking read()
    fcntl(fds[0], F_SETFL, O_NONBLOCK);

    NSString *conf = [NSString stringWithFormat:
        @"tunnel:\n"
        @"  mtu: 1400\n"
        @"  ipv4: 198.18.0.1\n"
        @"socks5:\n"
        @"  port: %d\n"
        @"  address: '127.0.0.1'\n"
        @"  udp: 'tcp'\n"
        // Psiphon's own SOCKS5 parser mishandles hev's pipelined
        // greeting+request depending on TCP segmentation timing — send them
        // in order instead (the intermittent first-connect rejections)
        @"  pipeline: false\n"
        @"mapdns:\n"
        @"  address: 198.18.0.2\n"
        @"  port: 53\n"
        @"  network: 198.18.0.0\n"
        @"  netmask: 255.255.0.0\n"
        @"  cache-size: 2048\n"
        @"misc:\n"
        @"  log-file: stderr\n"
        @"  log-level: %@\n",
        socksPort, _logLevel >= 2 ? @"debug" : @"info"];

    __weak SRPPsiphonClient *weakSelf = self;
    _hevThread = [[NSThread alloc] initWithBlock:^{
        int r = srpssh_hev_socks5_tunnel_main_from_str((const unsigned char *)conf.UTF8String,
                                                       (unsigned int)strlen(conf.UTF8String), hevFd);
        SSLogM(@"Psiphon: packet bridge exited (%d)", r);
        SRPPsiphonClient *strongSelf = weakSelf;
        if (strongSelf && !strongSelf->_closed && strongSelf->_failureCb)
            strongSelf->_failureCb(@"Psiphon: the packet bridge stopped");
    }];
    _hevThread.name = @"psiphon-hev";
    [_hevThread start];

    _readSource = dispatch_source_create(DISPATCH_SOURCE_TYPE_READ, _tunFd, 0, _worker);
    dispatch_source_set_event_handler(_readSource, ^{
        SRPPsiphonClient *strongSelf = weakSelf;
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
        SRPPsiphonClient *strongSelf = weakSelf;
        if (strongSelf && strongSelf->_tunFd >= 0) { close(strongSelf->_tunFd); strongSelf->_tunFd = -1; }
    });
    dispatch_resume(_readSource);
    return YES;
}

- (NEPacketTunnelNetworkSettings *)buildSettings {
    NSString *remote = _serverIPs.count > 0 ? _serverIPs.firstObject
                     : (_serverIP.length > 0 ? _serverIP : @"127.0.0.1");
    NEPacketTunnelNetworkSettings *settings =
        [[NEPacketTunnelNetworkSettings alloc] initWithTunnelRemoteAddress:remote];
    NEIPv4Settings *v4 = [[NEIPv4Settings alloc] initWithAddresses:@[@"198.18.0.1"]
                                                       subnetMasks:@[@"255.255.255.255"]];
    v4.includedRoutes = @[NEIPv4Route.defaultRoute];
    if (_serverIPs.count > 0) {
        NSMutableArray *excluded = [NSMutableArray new];
        for (NSString *ip in _serverIPs) {
            [excluded addObject:[[NEIPv4Route alloc] initWithDestinationAddress:ip
                                                                   subnetMask:@"255.255.255.255"]];
        }
        v4.excludedRoutes = excluded;
    }
    settings.IPv4Settings = v4;
    settings.MTU = @(1400);
    settings.DNSSettings = [[NEDNSSettings alloc] initWithServers:@[@"198.18.0.2"]];
    return settings;
}

- (void)injectPacket:(NSData *)packet family:(int)family {
    if (packet.length < 20 || packet.length > 2048) return;
    // The hev core speaks the Darwin utun format: 4-byte header + IP packet
    NSMutableData *d = [NSMutableData dataWithCapacity:packet.length + 4];
    uint32_t zero = 0;
    [d appendBytes:&zero length:4];
    [d appendBytes:packet.bytes length:packet.length];
    dispatch_async(_worker, ^{
        if (self->_tunFd < 0) return;
        ssize_t n = write(self->_tunFd, d.bytes, d.length);
        if (n < 0 && errno != EAGAIN) {
            SSLogE(@"Psiphon: tunnel write failed (%d)", errno);
        }
    });
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
    srppsiStop();
    srpssh_hev_socks5_tunnel_quit();
    if (_readSource) {
        dispatch_source_cancel(_readSource);   // closes _tunFd
        _readSource = nil;
    } else if (_tunFd >= 0) {
        close(_tunFd);
        _tunFd = -1;
    }
}

- (void)dealloc {
    [self closeAndWait];
}

@end
