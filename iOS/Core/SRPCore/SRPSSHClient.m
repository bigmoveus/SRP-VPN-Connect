//
//  SRPSSHClient.m
//  SRPCore
//
//  Session owner for the SSH VPN engine. Threading model mirrors
//  SRPOpenConnectClient: a worker queue owns lifecycle (start, reconnect,
//  Switch to Wi-Fi, On Sleep), a pump thread moves packets from the engine's
//  tun socketpair to packetFlow, and injectPacket writes the other way
//  (4-byte header + IP packet, like Darwin utun — the engine's
//  hev_tunnel_read/write format). An SSH session cannot resume: every
//  reconnect is a new session.
//

#import "SRPSSHClient.h"
#import "SRPSSHBridge.h"
#import "SSLog.h"
#import "SSNetOptions.h"

#import <NetworkExtension/NetworkExtension.h>
#import <Network/Network.h>
#import <arpa/inet.h>
#import <netdb.h>
#import <errno.h>
#import <string.h>
#import <unistd.h>
#import <sys/socket.h>
#import <os/lock.h>

@implementation SRPSSHClient {
    dispatch_queue_t _worker;
    int _tunFds[2];                 // [0] engine, [1] ours
    os_unfair_lock _fdLock;         // injectPacket (packetFlow's thread) against the teardown closing _tunFds[1]
    dispatch_semaphore_t _pumpDone; // the pump thread of the current session has left
    volatile BOOL _pumpStop;

    SRPSSHOutputCallback _outputCb;
    SRPSSHNetworkSettingsCallback _settingsCb;
    SRPSSHConnectedCallback _connectedCb;
    SRPSSHDisconnectedCallback _disconnectedCb;
    SRPSSHFailureCallback _failureCb;

    NSUInteger _generation;         // bumped by every session start; an older session's callbacks change nothing
    BOOL _bridgeRunning;            // srpssh_start ran and srpssh_stop has not
    BOOL _closedManually;
    BOOL _sleepPaused;
    volatile BOOL _up;              // the current session carries packets
    BOOL _everEstablished;          // a session of this connection was up once
    NSInteger _failedAttempts;
    nw_path_monitor_t _pathMonitor;
    BOOL _lastPathHadWifi;
    long _injectFailures;
}

- (instancetype)init {
    self = [super init];
    if (self) {
        _worker = dispatch_queue_create("srp.ssh", DISPATCH_QUEUE_SERIAL);
        _port = 22;
        _tunFds[0] = _tunFds[1] = -1;
        _fdLock = OS_UNFAIR_LOCK_INIT;
        _autoReconnect = YES;
        _switchToWifi = YES;
        _onSleep = 2;
    }
    return self;
}

#pragma mark - bridge callbacks (session thread)

static void srpsshOnLog(void *ctx, int level, const char *line) {
    (void)ctx;
    if (level <= 0) SSLogM(@"[ssh] %s", line);
    else if (level == 1) SSLogI(@"[ssh] %s", line);
    else SSLogD(@"[ssh] %s", line);
}

static void srpsshOnReady(void *ctx) {
    SRPSSHClient *self = (__bridge SRPSSHClient *)ctx;
    NSUInteger generation = self->_generation;
    dispatch_async(self->_worker, ^{ [self sessionReadyForGeneration:generation]; });
}

static void srpsshOnFail(void *ctx, SRPSSHError err, const char *detail) {
    SRPSSHClient *self = (__bridge SRPSSHClient *)ctx;
    NSUInteger generation = self->_generation;
    NSString *text = detail ? @(detail) : nil;
    dispatch_async(self->_worker, ^{ [self sessionFailed:err detail:text generation:generation]; });
}

static void srpsshOnGone(void *ctx, const char *reason) {
    SRPSSHClient *self = (__bridge SRPSSHClient *)ctx;
    NSUInteger generation = self->_generation;
    NSString *why = reason ? @(reason) : @"the connection was lost";
    dispatch_async(self->_worker, ^{ [self sessionEnded:why generation:generation]; });
}

+ (NSString *)messageForError:(int)error detail:(NSString *)detail port:(int)port {
    switch (error) {
        case SRPSSH_ERR_CONNECT:
            if ([detail isEqualToString:@"resolve"]) return @"Cannot find the server. Check the Server field and the network.";
            if ([detail isEqualToString:@"refused"])
                return [NSString stringWithFormat:@"The server refused the connection on port %d. Check the Port field.", port];
            if ([detail isEqualToString:@"timeout"])
                return [NSString stringWithFormat:@"The server did not answer on port %d. Check the Server and Port fields and the network.", port];
            return @"Cannot reach the SSH server. Check the Server field and the network.";
        case SRPSSH_ERR_HANDSHAKE:
            if ([detail isEqualToString:@"timeout"])
                return @"The SSH handshake did not finish in time. Check that Port is the server's SSH port.";
            if (detail.length > 0)
                return [NSString stringWithFormat:@"SSH handshake failed (%@). Check that Port is the server's SSH port.", detail];
            return @"SSH handshake failed. Check that Port is the server's SSH port.";
        case SRPSSH_ERR_HOSTKEY:
            return [NSString stringWithFormat:@"The server's host key does not match Host Key. The server presented %@.", detail ?: @"another key"];
        case SRPSSH_ERR_AUTH:
            return @"Authentication failed. Check the username and password.";
        case SRPSSH_ERR_AUTH_METHOD:
            return [NSString stringWithFormat:@"The server does not take a password for this user (it offers: %@).", detail ?: @"other methods"];
        case SRPSSH_ERR_FORWARDING:
            return @"The server does not let this user forward TCP connections (AllowTcpForwarding or PermitOpen on the server).";
        case SRPSSH_ERR_RELAY:
            return @"The UDP relay (HEV) is unavailable on the server. Turn UDP Relay off, or ask the administrator to install or start it.";
        default:
            return detail.length > 0 ? detail : @"SSH connection failed.";
    }
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
    dispatch_async(_worker, ^{
        self->_closedManually = NO;
        self->_everEstablished = NO;
        self->_failedAttempts = 0;
        [self startPathMonitor];
        [self startLocked];
    });
}

// One SSH session: a new packet channel, the bridge, the pump. Ends the current session first.
- (void)startLocked {
    if (_bridgeRunning || _tunFds[1] >= 0) [self teardownLocked];
    ++_generation;
    _up = NO;

    if (_useRealTun) {
        // macOS test harness: the engine opens a real utun itself
        _tunFds[0] = _tunFds[1] = -1;
    } else {
        int fds[2];
        if (socketpair(AF_UNIX, SOCK_DGRAM, 0, fds) != 0) {
            [self failWithReason:@"Internal error creating the packet channel"];
            return;
        }
        // A full local datagram socket refuses the engine's packet (ENOBUFS) and lwIP drops it, and a TCP flow that
        // loses packets that way backs off for long (16 downloads at once overran 512 KB: each sends up to 64 KB in a
        // burst). 4 MB where the system allows it, 2 MB otherwise.
        for (int i = 0; i < 2; i++) {
            for (int size = 4 * 1024 * 1024; size >= 2 * 1024 * 1024; size /= 2) {
                if (setsockopt(fds[i], SOL_SOCKET, SO_RCVBUF, &size, sizeof(size)) == 0 &&
                    setsockopt(fds[i], SOL_SOCKET, SO_SNDBUF, &size, sizeof(size)) == 0) break;
            }
        }
        _tunFds[0] = fds[0];
        os_unfair_lock_lock(&_fdLock);
        _tunFds[1] = fds[1];
        os_unfair_lock_unlock(&_fdLock);
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
    cfg.keepalive_seconds = 15;

    SSLogM(@"SSH connecting to %@:%d (user %@, UDP relay %@)", _host, _port, _username, _udpEnabled ? @"on" : @"off");

    if (srpssh_start(&cfg, _tunFds[0], srpsshOnLog, (__bridge void *)self,
                     srpsshOnReady, srpsshOnFail, srpsshOnGone, (__bridge void *)self) != 0) {
        [self failWithReason:@"Internal error starting the SSH engine"];
        return;
    }
    _bridgeRunning = YES;

    if (!_useRealTun) {
        _pumpStop = NO;
        dispatch_semaphore_t done = dispatch_semaphore_create(0);
        _pumpDone = done;
        int fd = _tunFds[1];
        NSThread *pump = [[NSThread alloc] initWithBlock:^{ [self pumpLoopFd:fd done:done]; }];
        pump.name = @"ssh-pump";
        [pump start];
    }
}

/// The session is up (SSH authenticated, relay verified, engine running).
- (void)sessionReadyForGeneration:(NSUInteger)generation {
    if (generation != _generation || _closedManually || _sleepPaused) return;
    BOOL again = _everEstablished;
    _up = YES;
    _everEstablished = YES;
    _failedAttempts = 0;
    // Every session: a reconnect's engine gives the names new placeholder addresses, and applying the settings again
    // makes the system drop the old ones from its DNS cache (as SSL VPN's reconnect does)
    SRPSSHNetworkSettingsCallback cb = _settingsCb;
    if (cb) cb([self buildSettings]);
    if (_connectedCb) _connectedCb();
    SSLogM(@"SSH: session established%@", again ? @" again" : @"");
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
- (void)pumpLoopFd:(int)fd done:(dispatch_semaphore_t)done {
    uint8_t buf[2200];
    long count = 0;
    while (!_pumpStop) {
        ssize_t n = read(fd, buf, sizeof(buf));
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) break;   // the teardown shut the socket down
        if (n <= 4) continue;
        // Each packet's objects go at once: this loop runs for the whole session, and without its own pool every
        // received packet stayed in memory until the session ended (the 50 MB extension limit within seconds)
        @autoreleasepool {
            count++;
            uint8_t ver = buf[4] >> 4;
            int family = (ver == 6) ? AF_INET6 : AF_INET;
            NSData *d = [NSData dataWithBytes:buf + 4 length:n - 4];
            SRPSSHOutputCallback cb = _outputCb;
            if (cb) cb(d, family);
        }
    }
    SSLogI(@"SSH: pumpLoop exited (total %ld packets)", count);
    dispatch_semaphore_signal(done);
}

- (void)injectPacket:(NSData *)packet family:(int)family {
    if (!_up || packet.length < 20 || packet.length > 2048) return;
    uint8_t buf[2052];
    uint32_t af = htonl(family == AF_INET6 ? AF_INET6 : AF_INET);
    memcpy(buf, &af, 4);
    memcpy(buf + 4, packet.bytes, packet.length);
    os_unfair_lock_lock(&_fdLock);
    int fd = _tunFds[1];
    ssize_t w = fd >= 0 ? send(fd, buf, packet.length + 4, MSG_DONTWAIT) : 0;
    int err = errno;
    os_unfair_lock_unlock(&_fdLock);
    if (w < 0) {
        // a full queue drops packets in bursts: name the first ones, then every thousandth
        _injectFailures++;
        if (_injectFailures <= 5 || _injectFailures % 1000 == 0) {
            SSLogE(@"SSH: inject write failed (%ld so far): errno=%d (%s)", _injectFailures, err, strerror(err));
        }
    }
}

#pragma mark - end of life / reconnect

// A connect or login that failed. A refused login, host key, forwarding or relay never gets better by trying again:
// the profile or the server must change first. Before the tunnel was ever up only an explicit Retry Times budget
// retries (as SSTP, SoftEther and SSL VPN).
- (void)sessionFailed:(int)error detail:(NSString *)detail generation:(NSUInteger)generation {
    if (generation != _generation) return;   // an older session; the current one is not affected
    [self teardownLocked];
    if (_closedManually || _sleepPaused) return;
    NSString *message = [SRPSSHClient messageForError:error detail:detail port:_port];
    BOOL final = error == SRPSSH_ERR_AUTH || error == SRPSSH_ERR_AUTH_METHOD || error == SRPSSH_ERR_HOSTKEY ||
                 error == SRPSSH_ERR_FORWARDING || error == SRPSSH_ERR_RELAY;
    if (final || !_autoReconnect || (!_everEstablished && _retryTimes == 0)) {
        [self failWithReason:message];
        return;
    }
    if (!SSReconnectAttemptAllowed(_failedAttempts, _retryTimes)) {
        [self failWithReason:[NSString stringWithFormat:@"Could not %@ after %ld attempts. (%@)",
                              _everEstablished ? @"reconnect" : @"connect", (long)_retryTimes, message]];
        return;
    }
    [self scheduleReconnect:message];
}

// A session that was up has ended (the server closed it, the connection broke, or keepalives went unanswered)
- (void)sessionEnded:(NSString *)why generation:(NSUInteger)generation {
    if (generation != _generation) return;
    BOOL wasUp = _up;
    [self teardownLocked];
    if (_closedManually || _sleepPaused) return;
    if (wasUp && _disconnectedCb) _disconnectedCb();
    if (!_autoReconnect) {
        NSString *reason = why.length > 0 ? [[why substringToIndex:1].uppercaseString stringByAppendingString:[why substringFromIndex:1]] : @"Connection lost";
        [self failWithReason:[NSString stringWithFormat:@"%@ (auto reconnect is off).", reason]];
        return;
    }
    [self scheduleReconnect:why];
}

- (void)scheduleReconnect:(NSString *)why {
    _failedAttempts++;
    SSLogM(@"SSH: %@; reconnecting in 2s (attempt %ld%@)", why, (long)_failedAttempts,
           _retryTimes > 0 ? [NSString stringWithFormat:@" of %ld", (long)_retryTimes] : @"");
    NSUInteger generation = _generation;
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2 * NSEC_PER_SEC)), _worker, ^{
        // a wake or a network switch may have started a session meanwhile
        if (generation == self->_generation && !self->_closedManually && !self->_sleepPaused) {
            [self startLocked];
        }
    });
}

- (void)teardownLocked {
    _up = NO;
    if (_bridgeRunning) {
        srpssh_stop();   // joins the session thread: no bridge callback comes after this
        _bridgeRunning = NO;
    }
    _pumpStop = YES;
    os_unfair_lock_lock(&_fdLock);
    int ours = _tunFds[1];
    _tunFds[1] = -1;
    os_unfair_lock_unlock(&_fdLock);
    if (ours >= 0) shutdown(ours, SHUT_RDWR);   // wakes the pump's read
    if (_pumpDone != nil) {
        // the pump leaves before its descriptor closes, so it never reads a reused one
        dispatch_semaphore_wait(_pumpDone, dispatch_time(DISPATCH_TIME_NOW, 2 * NSEC_PER_SEC));
        _pumpDone = nil;
    }
    if (ours >= 0) close(ours);
    if (_tunFds[0] >= 0) { close(_tunFds[0]); _tunFds[0] = -1; }
}

- (void)close {
    dispatch_async(_worker, ^{
        self->_closedManually = YES;
        [self stopPathMonitor];
        [self teardownLocked];
    });
}

- (void)closeAndWait {
    dispatch_sync(_worker, ^{
        self->_closedManually = YES;
        [self stopPathMonitor];
        [self teardownLocked];
    });
}

- (void)failWithReason:(NSString *)reason {
    SSLogM(@"SSH: closing with reason: %@", reason);
    [self teardownLocked];
    [self stopPathMonitor];
    SRPSSHFailureCallback cb = _failureCb;
    if (cb) cb(reason);
}

#pragma mark - Switch to Wi-Fi

- (void)startPathMonitor {
    [self stopPathMonitor];
    if (!_switchToWifi) return;
    _lastPathHadWifi = NO;
    _pathMonitor = nw_path_monitor_create();
    __weak SRPSSHClient *weakSelf = self;
    nw_path_monitor_set_queue(_pathMonitor, _worker);
    nw_path_monitor_set_update_handler(_pathMonitor, ^(nw_path_t path) {
        SRPSSHClient *strongSelf = weakSelf;
        if (!strongSelf) return;
        BOOL satisfied = nw_path_get_status(path) == nw_path_status_satisfied;
        BOOL hasWifi = satisfied && nw_path_uses_interface_type(path, nw_interface_type_wifi);
        BOOL hadWifi = strongSelf->_lastPathHadWifi;
        strongSelf->_lastPathHadWifi = hasWifi;
        if (SSShouldReconnectForPathChange(hadWifi, hasWifi, satisfied, strongSelf->_up)) {
            SSLogM(@"Wi-Fi became available; moving the SSH connection to it");
            [strongSelf moveToNewPathLocked];
        }
    });
    nw_path_monitor_start(_pathMonitor);
}

// An SSH session cannot move to another path: a new one replaces it there
- (void)moveToNewPathLocked {
    if (!_up) return;
    _failedAttempts = 0;
    [self startLocked];
}

- (void)switchNetworkPath {
    dispatch_async(_worker, ^{
        SSLogM(@"SSH: network path switch requested");
        [self moveToNewPathLocked];
    });
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
        SSLogM(@"device sleep: %@ the SSH connection", self->_onSleep == 1 ? @"pausing" : @"closing");
        self->_sleepPaused = YES;
        [self teardownLocked];
    });
}

- (void)wakeFromSleep {
    dispatch_async(_worker, ^{
        if (!self->_sleepPaused || self->_closedManually) return;
        self->_sleepPaused = NO;
        if (self->_onSleep == 1 || self->_autoReconnect) {
            self->_failedAttempts = 0;
            SSLogM(@"device wake: reconnecting the SSH connection");
            [self startLocked];
        } else {
            // Off without Auto Reconnect leaves no connection; end the tunnel instead of keeping a VPN that drops every
            // packet (as SoftEther, SSTP and SSL VPN do)
            [self failWithReason:@"The connection was closed while the device slept."];
        }
    });
}

@end
