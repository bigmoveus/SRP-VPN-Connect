//
//  SRPSSHClient.m
//  SRPCore
//
//  Session owner for the SSH VPN engine. Threading model mirrors
//  SRPOpenConnectClient: a worker queue owns lifecycle, a pump thread
//  moves packets from the engine's tun socketpair to packetFlow, and
//  injectPacket writes the other way (4-byte header + IP packet, like
//  Darwin utun — the engine's hev_tunnel_read/write format).
//

#import "SRPSSHClient.h"
#import "SRPSSHBridge.h"
#import "SSLog.h"

#import <NetworkExtension/NetworkExtension.h>
#import <arpa/inet.h>
#import <netdb.h>
#import <errno.h>
#import <string.h>
#import <unistd.h>
#import <sys/socket.h>

@implementation SRPSSHClient {
    dispatch_queue_t _worker;
    int _tunFds[2];                 // [0] engine, [1] ours
    NSThread *_pumpThread;
    BOOL _pumpStop;

    SRPSSHOutputCallback _outputCb;
    SRPSSHNetworkSettingsCallback _settingsCb;
    SRPSSHConnectedCallback _connectedCb;
    SRPSSHDisconnectedCallback _disconnectedCb;
    SRPSSHFailureCallback _failureCb;

    BOOL _closedManually;
    BOOL _sleepPaused;
    BOOL _up;
    long _injectCount;
    long _pumpCount;
}

- (instancetype)init {
    self = [super init];
    if (self) {
        _worker = dispatch_queue_create("srp.ssh", DISPATCH_QUEUE_SERIAL);
        _port = 22;
        _tunFds[0] = _tunFds[1] = -1;
        _autoReconnect = YES;
        _switchToWifi = YES;
        _onSleep = 2;
    }
    return self;
}

#pragma mark - bridge callbacks

static void srpsshOnLog(void *ctx, const char *line) {
    (void)ctx;
    SSLogM(@"[ssh] %s", line);   // bridge only logs connect milestones
}

static void srpsshOnReady(void *ctx) {
    SRPSSHClient *self = (__bridge SRPSSHClient *)ctx;
    dispatch_async(self->_worker, ^{ [self bridgeReady]; });
}

static void srpsshOnFail(void *ctx, SRPSSHError err, const char *detail) {
    SRPSSHClient *self = (__bridge SRPSSHClient *)ctx;
    NSString *msg;
    switch (err) {
        case SRPSSH_ERR_CONNECT:
            msg = @"Cannot reach the SSH server. Check the Server field and the network."; break;
        case SRPSSH_ERR_HANDSHAKE:
            msg = @"SSH handshake failed. Check the server address and port."; break;
        case SRPSSH_ERR_HOSTKEY:
            msg = @"The SSH host key does not match the pinned fingerprint."; break;
        case SRPSSH_ERR_AUTH:
            msg = @"Authentication failed. Check the username and password."; break;
        case SRPSSH_ERR_RELAY:
            msg = @"The UDP relay (HEV) is unavailable on the server or rejected the relay credentials. Ask the administrator to install/start it."; break;
        default:
            msg = detail ? @(detail) : @"SSH connection failed."; break;
    }
    dispatch_async(self->_worker, ^{
        SRPSSHFailureCallback cb = self->_failureCb;
        if (cb && !self->_closedManually) cb(msg);
    });
}

static void srpsshOnGone(void *ctx) {
    SRPSSHClient *self = (__bridge SRPSSHClient *)ctx;
    dispatch_async(self->_worker, ^{
        if (self->_closedManually || self->_sleepPaused) return;
        SRPSSHDisconnectedCallback cb = self->_disconnectedCb;
        if (cb) cb();
    });
}

#pragma mark - lifecycle

- (void)startWithOutputCallback:(SRPSSHOutputCallback)output
         networkSettingsCallback:(SRPSSHNetworkSettingsCallback)settings
               connectedCallback:(SRPSSHConnectedCallback)connected
            disconnectedCallback:(SRPSSHDisconnectedCallback)disconnected
                 failureCallback:(SRPSSHFailureCallback)failure {
    _outputCb = output;
    _settingsCb = settings;
    _connectedCb = connected;
    _disconnectedCb = disconnected;
    _failureCb = failure;
    SSLogSetLevel((SSLogLevel)_logLevel);
    dispatch_async(_worker, ^{ [self startLocked]; });
}

- (void)startLocked {
    _closedManually = NO;
    _up = NO;

    if (_useRealTun) {
        // macOS test harness: the engine opens a real utun itself
        _tunFds[0] = -1;
        _tunFds[1] = -1;
    } else if (socketpair(AF_UNIX, SOCK_DGRAM, 0, _tunFds) != 0) {
        _failureCb(@"Internal error creating the packet channel");
        return;
    }
    if (_tunFds[0] >= 0) {
        // Default local-dgram buffers are ~4KB — a phone's connect-time burst
        // overruns them instantly (inject ENOBUFS, engine-side write drops).
        int bufsz = 512 * 1024;
        setsockopt(_tunFds[0], SOL_SOCKET, SO_RCVBUF, &bufsz, sizeof(bufsz));
        setsockopt(_tunFds[0], SOL_SOCKET, SO_SNDBUF, &bufsz, sizeof(bufsz));
        setsockopt(_tunFds[1], SOL_SOCKET, SO_RCVBUF, &bufsz, sizeof(bufsz));
        setsockopt(_tunFds[1], SOL_SOCKET, SO_SNDBUF, &bufsz, sizeof(bufsz));
    }

    SRPSSHBridgeConfig cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.host = _host.UTF8String;
    cfg.port = _port;
    cfg.username = _username.UTF8String;
    cfg.password = _password ? _password.UTF8String : "";
    cfg.hostkey_sha256 = _hostKeySHA256.length > 0 ? _hostKeySHA256.UTF8String : NULL;
    cfg.udp_enabled = _udpEnabled ? 1 : 0;
    cfg.relay_host = _relayHost.length > 0 ? _relayHost.UTF8String : "127.0.0.1";
    cfg.relay_port = _relayPort > 0 ? _relayPort : 1080;
    cfg.relay_user = _relayUsername ? _relayUsername.UTF8String : NULL;
    cfg.relay_pass = _relayPassword ? _relayPassword.UTF8String : NULL;
    cfg.mtu = 1400;   // must match the iOS tunnel MTU — packetFlow drops
                      // packets larger than the tunnel MTU
    cfg.tun_ipv4 = "198.18.0.1";
    cfg.log_level = (int)_logLevel;

    SSLogM(@"SSH connecting to %@:%d (user %@, udp=%d)", _host, _port, _username, cfg.udp_enabled);

    int r = srpssh_start(&cfg, _tunFds[0],
                         srpsshOnLog, (__bridge void *)self,
                         srpsshOnReady, srpsshOnFail, srpsshOnGone,
                         (__bridge void *)self);
    if (r != 0) {
        _failureCb(@"Internal error starting the SSH engine");
        return;
    }

    if (!_useRealTun) {
        _pumpStop = NO;
        _pumpThread = [[NSThread alloc] initWithBlock:^{ [self pumpLoop]; }];
        _pumpThread.name = @"ssh-pump";
        [_pumpThread start];
    }
}

/// Bridge is fully up (SSH authenticated, relay verified, engine running).
- (void)bridgeReady {
    NEPacketTunnelNetworkSettings *settings = [self buildSettings];
    SRPSSHNetworkSettingsCallback cb = _settingsCb;
    if (cb) cb(settings);
    if (_connectedCb) _connectedCb();
    _up = YES;
    SSLogM(@"SSH: session established");
}

- (NEPacketTunnelNetworkSettings *)buildSettings {
    // tunnelRemoteAddress must be numeric — resolve once
    NSString *remote = _host;
    struct in_addr a4;
    if (inet_pton(AF_INET, _host.UTF8String, &a4) != 1) {
        struct hostent *he = gethostbyname(_host.UTF8String);
        if (he && he->h_length == 4) {
            char buf[INET_ADDRSTRLEN];
            if (inet_ntop(AF_INET, he->h_addr_list[0], buf, sizeof(buf))) remote = @(buf);
        }
    }
    NEPacketTunnelNetworkSettings *settings =
        [[NEPacketTunnelNetworkSettings alloc] initWithTunnelRemoteAddress:remote];
    settings.MTU = @(1400);
    // 198.18.0.2 is the engine's mapped-DNS address: queries are answered
    // locally with fake IPs and the resulting connections carry the real
    // hostname through the SSH channel — DNS works with or without the
    // UDP relay.
    settings.DNSSettings = [[NEDNSSettings alloc] initWithServers:@[@"198.18.0.2"]];

    NEIPv4Settings *v4 = [[NEIPv4Settings alloc] initWithAddresses:@[@"198.18.0.1"]
                                                       subnetMasks:@[@"255.255.255.255"]];
    v4.includedRoutes = @[[NEIPv4Route defaultRoute]];
    // The tunnel's own SSH transport must stay on the physical path.
    if (inet_pton(AF_INET, remote.UTF8String, &a4) == 1) {
        v4.excludedRoutes = @[[[NEIPv4Route alloc] initWithDestinationAddress:remote
                                                                   subnetMask:@"255.255.255.255"]];
    }
    settings.IPv4Settings = v4;
    return settings;
}

#pragma mark - packet pump

// Engine writes [4-byte header][IP packet] per datagram; reads the same.
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
        uint8_t *pkt = buf + 4;
        uint8_t ver = pkt[0] >> 4;
        int family = (ver == 6) ? AF_INET6 : AF_INET;
        NSData *d = [NSData dataWithBytes:pkt length:n - 4];
        SRPSSHOutputCallback cb = _outputCb;
        if (cb) cb(d, family);
    }
    SSLogI(@"SSH: pumpLoop exited (total %ld packets)", _pumpCount);
}

- (void)injectPacket:(NSData *)packet family:(int)family {
    if (packet.length < 20 || packet.length > 2048) return;
    NSMutableData *d = [NSMutableData dataWithCapacity:packet.length + 4];
    uint32_t zero = 0;
    [d appendBytes:&zero length:4];
    [d appendBytes:packet.bytes length:packet.length];
    dispatch_async(_worker, ^{
        int fd = self->_tunFds[1];
        if (fd >= 0 && self->_up) {
            ssize_t w = write(fd, d.bytes, d.length);
            if (w < 0 && errno != EAGAIN) {
                self->_injectCount++;
                if (self->_injectCount <= 5 || self->_injectCount % 100 == 0) {
                    SSLogE(@"SSH: inject write failed: errno=%d (%s)", errno, strerror(errno));
                }
            }
        }
    });
}

#pragma mark - end of life

- (void)close {
    _closedManually = YES;
    [self teardownLocked];
}

- (void)closeAndWait {
    _closedManually = YES;
    [self teardownLocked];
}

- (void)teardownLocked {
    if (_tunFds[1] < 0 && _tunFds[0] < 0) return;
    _up = NO;
    _pumpStop = YES;
    srpssh_stop();
    if (_tunFds[1] >= 0) { close(_tunFds[1]); _tunFds[1] = -1; }
    if (_tunFds[0] >= 0) { close(_tunFds[0]); _tunFds[0] = -1; }
    _pumpThread = nil;
}

- (void)pauseForSleep {
    if (_onSleep == 2) return;          // stay
    _sleepPaused = YES;
    [self teardownLocked];
}

- (void)wakeFromSleep {
    if (!_sleepPaused) return;
    _sleepPaused = NO;
    if (_onSleep == 1 || _autoReconnect) {
        SSLogM(@"SSH: device wake — reconnecting");
        dispatch_async(_worker, ^{ [self startLocked]; });
    }
}

@end
