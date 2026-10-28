#import "SRPWaterWallClient.h"
#import "SRPWaterWallBridge.h"
#import "SSLog.h"
#import <NetworkExtension/NetworkExtension.h>
#import <arpa/inet.h>
#import <errno.h>
#import <netdb.h>
#import <os/proc.h>
#import <mach/task.h>
#import <mach/task_info.h>
#import <mach/mach_init.h>

@interface SRPWaterWallClient () {
    SRPWaterWallBridge *_bridge;
    dispatch_queue_t _worker;
    SRPWaterWallOutputCallback _outputCb;
    SRPWaterWallNetworkSettingsCallback _settingsCb;
    SRPWaterWallConnectedCallback _connectedCb;
    SRPWaterWallFailureBlock _failureCb;
    BOOL _closed;
    BOOL _up;
    NSInteger _probeStage;
    uint16_t _probeDnsId;
    NSInteger _probeAttempts;
    NSUInteger _packetsSinceMemorySample;
    dispatch_source_t _probeTimer;
    NSArray<NSData *> *_pendingPackets;
    NSUInteger _pendingPacketIndex;
    dispatch_block_t _injectionCompletion;
    BOOL _retryScheduled;
}
@end

@implementation SRPWaterWallClient

static void SRPWWPut16(uint8_t *p, uint16_t value) {
    p[0] = value >> 8;
    p[1] = value & 0xff;
}

static uint32_t SRPWWSum(const uint8_t *bytes, size_t length, uint32_t sum) {
    for (size_t i = 0; i + 1 < length; i += 2) {
        sum += ((uint32_t)bytes[i] << 8) | bytes[i + 1];
    }
    if (length & 1) sum += (uint32_t)bytes[length - 1] << 8;
    return sum;
}

static uint16_t SRPWWChecksum(uint32_t sum) {
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    return (uint16_t)~sum;
}

static void SRPWWIP(uint8_t *p, size_t length, uint8_t protocol, NSString *source, NSString *destination) {
    p[0] = 0x45;
    SRPWWPut16(p + 2, (uint16_t)length);
    SRPWWPut16(p + 4, 0x4242);
    p[8] = 64;
    p[9] = protocol;
    inet_pton(AF_INET, source.UTF8String, p + 12);
    inet_pton(AF_INET, destination.UTF8String, p + 16);
    SRPWWPut16(p + 10, SRPWWChecksum(SRPWWSum(p, 20, 0)));
}

static NSData *SRPWWSynPacket(NSString *source, NSString *destination) {
    uint8_t p[40] = {0};
    SRPWWIP(p, sizeof(p), IPPROTO_TCP, source, destination);
    SRPWWPut16(p + 20, 12345);
    SRPWWPut16(p + 22, 443);
    p[24] = 1;
    p[32] = 5 << 4;
    p[33] = 0x02;
    SRPWWPut16(p + 34, 0xffff);
    uint32_t sum = SRPWWSum(p + 12, 8, IPPROTO_TCP + 20);
    SRPWWPut16(p + 36, SRPWWChecksum(SRPWWSum(p + 20, 20, sum)));
    return [NSData dataWithBytes:p length:sizeof(p)];
}

static NSData *SRPWWDnsPacket(NSString *source, uint16_t identifier, NSString *destination) {
    static const uint8_t query[] = {
        0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        7, 'e','x','a','m','p','l','e', 3, 'c','o','m', 0, 0x00, 0x01, 0x00, 0x01
    };
    uint8_t p[20 + 8 + sizeof(query)] = {0};
    SRPWWIP(p, sizeof(p), IPPROTO_UDP, source, destination);
    uint8_t *udp = p + 20;
    SRPWWPut16(udp, 12353);
    SRPWWPut16(udp + 2, 53);
    SRPWWPut16(udp + 4, (uint16_t)(8 + sizeof(query)));
    memcpy(udp + 8, query, sizeof(query));
    SRPWWPut16(udp + 8, identifier);
    SRPWWPut16(udp + 6, 0);
    return [NSData dataWithBytes:p length:sizeof(p)];
}

static void SRPWWPacket(void *context, const uint8_t *packet, size_t length) {
    SRPWaterWallClient *client = (__bridge SRPWaterWallClient *)context;
    if (client == nil || packet == NULL || length < 20) return;
    @autoreleasepool {
        NSData *data = [NSData dataWithBytes:packet length:length];
        int family = (packet[0] >> 4) == 6 ? AF_INET6 : AF_INET;
#if DEBUG
        static NSUInteger outputPackets = 0;
        outputPackets++;
        if (outputPackets % 1000 == 0) SRPWWMemoryUsage();
        if (client->_probeStage > 0 && client->_probeStage < 3) {
            NSLog(@"WaterWall: callback v=%u proto=%u src=%u.%u.%u.%u sport=%u dport=%u flags=%x stage=%ld",
                  packet[0] >> 4, packet[9], packet[16], packet[17], packet[18], packet[19],
                  (packet[20] << 8) | packet[21], (packet[22] << 8) | packet[23], packet[33], (long)client->_probeStage);
        }
#endif
        if (client->_outputCb) client->_outputCb(data, family);
        if (!client->_closed && client->_probeStage > 0 && client->_probeStage < 3) {
            dispatch_async(client->_worker, ^{ [client handleProbePacket:data]; });
        }
    }
}

static void SRPWWLog(void *context, int level, const char *message, size_t length) {
#if DEBUG
    (void)context;
    (void)level;
    if (message == NULL) return;
    NSURL *container = [NSFileManager.defaultManager containerURLForSecurityApplicationGroupIdentifier:@"group.tr.com.srp.vpn"];
    NSString *path = [container.path stringByAppendingPathComponent:@"Library/ww-native.log"];
    if (![NSFileManager.defaultManager fileExistsAtPath:path]) {
        [NSFileManager.defaultManager createFileAtPath:path contents:nil attributes:nil];
    }
    NSFileHandle *handle = [NSFileHandle fileHandleForWritingAtPath:path];
    [handle seekToEndOfFile];
    [handle writeData:[[NSString stringWithFormat:@"%.*s\n", (int)length, message] dataUsingEncoding:NSUTF8StringEncoding]];
    [handle closeFile];
#else
    (void)context;
    (void)level;
    (void)message;
    (void)length;
#endif
}

static void SRPWWMemoryUsage(void) {
#if DEBUG
    task_vm_info_data_t info = {0};
    mach_msg_type_number_t count = TASK_VM_INFO_COUNT;
    if (task_info(mach_task_self(), TASK_VM_INFO, (task_info_t)&info, &count) == KERN_SUCCESS) {
        NSLog(@"WaterWall memory: %.1f MiB; available: %.1f MiB",
              (double)info.phys_footprint / (1024.0 * 1024.0),
              (double)os_proc_available_memory() / (1024.0 * 1024.0));
    }
#endif
}

static void SRPWWReady(void *context) {
    SRPWaterWallClient *client = (__bridge SRPWaterWallClient *)context;
    dispatch_async(client->_worker, ^{
        if (client->_closed || client->_up || client->_probeStage != 0) return;
        [client beginDataPlaneProbe];
    });
}

static void SRPWWFailure(void *context, int code, const char *message) {
    SRPWaterWallClient *client = (__bridge SRPWaterWallClient *)context;
    dispatch_async(client->_worker, ^{
        if (client->_closed) return;
        NSString *reason = message ? @(message) : @"WaterWall runtime stopped";
        if (client->_failureCb) client->_failureCb([NSString stringWithFormat:@"%@ (%d)", reason, code]);
    });
}

- (void)submitProbePacket:(NSData *)packet {
    if (_closed || _bridge == NULL) return;
    int result = SRPWaterWallBridgeSubmitPacket(_bridge, packet.bytes, packet.length);
#if DEBUG
    NSLog(@"WaterWall: probe packet stage=%ld submit=%d", (long)_probeStage, result);
#endif
    if (result != 0) [self probeFailed:[NSString stringWithFormat:@"WaterWall probe submission failed (%d)", result]];
}

- (void)sendSynProbe {
    if (_closed || _probeStage != 1) return;
    _probeAttempts++;
    [self submitProbePacket:SRPWWSynPacket(_tunnelAddress, _probeAddress)];
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, NSEC_PER_SEC), _worker, ^{
        if (self->_probeStage != 1 || self->_closed) return;
        if (self->_probeAttempts >= 15) {
            [self probeFailed:@"WaterWall TCP probe failed after fifteen attempts"];
        } else {
            [self sendSynProbe];
        }
    });
}

- (void)sendDnsProbe {
    if (_closed || _probeStage != 2) return;
    _probeAttempts++;
    [self submitProbePacket:SRPWWDnsPacket(_tunnelAddress, _probeDnsId, _dnsProbeAddress)];
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, NSEC_PER_SEC), _worker, ^{
        if (self->_probeStage != 2 || self->_closed) return;
        if (self->_probeAttempts >= 5) {
            [self probeFailed:@"WaterWall UDP/DNS probe failed after five attempts"];
        } else {
            [self sendDnsProbe];
        }
    });
}

- (void)beginDataPlaneProbe {
    NSLog(@"WaterWall: native chain ready; starting data-plane probe");
    SRPWWMemoryUsage();
    _packetsSinceMemorySample = 0;
    _probeStage = _probeTCP ? 1 : 2;
    _probeAttempts = 0;
    _probeDnsId = arc4random_uniform(65535) + 1;
    _probeTimer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, _worker);
    dispatch_source_set_timer(_probeTimer, dispatch_time(DISPATCH_TIME_NOW, 20 * NSEC_PER_SEC), DISPATCH_TIME_FOREVER, 0);
    dispatch_source_set_event_handler(_probeTimer, ^{
        [self probeFailed:@"WaterWall data-plane probe timed out"];
    });
    dispatch_resume(_probeTimer);
    if (_probeTCP) {
        [self sendSynProbe];
    } else if (_probeUDP) {
        [self sendDnsProbe];
    } else {
        [self finishProbe];
    }
}

- (void)finishProbe {
    if (_probeTimer) {
        dispatch_source_cancel(_probeTimer);
        _probeTimer = nil;
    }
    _probeStage = 3;
    _up = YES;
    if (_probeTCP && _probeUDP) {
        SSLogM(@"WaterWall: TCP and UDP/DNS data-plane probes passed");
    } else if (_probeTCP) {
        SSLogM(@"WaterWall: TCP data-plane probe passed");
    } else if (_probeUDP) {
        SSLogM(@"WaterWall: UDP/DNS data-plane probe passed");
    } else {
        SSLogM(@"WaterWall: no external data-plane probe required");
    }
    if (_settingsCb) _settingsCb([self buildSettings]);
    if (_connectedCb) _connectedCb();
}

- (void)probeFailed:(NSString *)reason {
    if (_closed || _up || _probeStage < 0) return;
    _probeStage = -1;
    if (_probeTimer) {
        dispatch_source_cancel(_probeTimer);
        _probeTimer = nil;
    }
    if (_failureCb) _failureCb(reason);
}

- (void)stopProbe {
    if (_probeTimer) {
        dispatch_source_cancel(_probeTimer);
        _probeTimer = nil;
    }
    _probeStage = 0;
}

- (void)handleProbePacket:(NSData *)packet {
    if (_closed || _up || _probeStage <= 0 || packet.length < 28) return;
    const uint8_t *p = packet.bytes;
    if ((p[0] >> 4) != 4) return;
    NSUInteger ihl = (p[0] & 0x0f) * 4;
    if (ihl < 20 || packet.length < ihl + 8) return;
    uint8_t probeIP[4];
    NSString *expectedSource = _probeStage == 2 ? _dnsProbeAddress : _probeAddress;
    if (inet_pton(AF_INET, expectedSource.UTF8String, probeIP) != 1 || memcmp(p + 12, probeIP, 4) != 0) return;
    if (_probeStage == 1 && p[9] == IPPROTO_TCP && packet.length >= ihl + 20) {
        const uint8_t *tcp = p + ihl;
        if (tcp[0] == 1 && tcp[1] == 0xbb && tcp[2] == 0x30 && tcp[3] == 0x39 &&
            (tcp[13] & 0x12) == 0x12) {
            if (_probeUDP) {
                _probeStage = 2;
                _probeAttempts = 0;
                [self sendDnsProbe];
            } else {
                [self finishProbe];
            }
        }
    } else if (_probeStage == 2 && p[9] == IPPROTO_UDP && packet.length >= ihl + 20) {
        const uint8_t *udp = p + ihl;
        uint16_t sourcePort = (udp[0] << 8) | udp[1];
        uint16_t destinationPort = (udp[2] << 8) | udp[3];
        uint16_t identifier = (udp[8] << 8) | udp[9];
        uint16_t flags = (udp[10] << 8) | udp[11];
        uint16_t answers = (udp[14] << 8) | udp[15];
        if (sourcePort == 53 && destinationPort == 12353 && identifier == _probeDnsId &&
            (flags & 0x8000) != 0 && (flags & 0x000f) == 0 && answers > 0) {
            [self finishProbe];
        }
    }
}

- (instancetype)init {
    self = [super init];
    if (self) {
        _worker = dispatch_queue_create("srp.waterwall", DISPATCH_QUEUE_SERIAL);
        dispatch_queue_set_specific(_worker, (__bridge const void *)self, (__bridge void *)self, NULL);
        _remoteAddress = @"127.0.0.1";
        _tunnelAddress = @"10.89.0.1";
        _probeAddress = @"1.1.1.1";
        _dnsProbeAddress = @"1.1.1.1";
        _probeTCP = YES;
        _probeUDP = YES;
        _dnsServers = @[@"1.1.1.1", @"1.0.0.1"];
        _mtu = 1420;
    }
    return self;
}

- (void)startWithOutputCallback:(SRPWaterWallOutputCallback)output
         networkSettingsCallback:(SRPWaterWallNetworkSettingsCallback)settings
               connectedCallback:(SRPWaterWallConnectedCallback)connected
                 failureCallback:(SRPWaterWallFailureBlock)failure {
    _outputCb = output;
    _settingsCb = settings;
    _connectedCb = connected;
    _failureCb = failure;
    _closed = NO;
    dispatch_async(_worker, ^{
        if (self->_coreJSON.length == 0 || self->_nodesJSON.length == 0) {
            if (self->_failureCb) self->_failureCb(@"WaterWall configuration is missing");
            return;
        }
        SRPWaterWallConfig config = {
            .core_json = self->_coreJSON.UTF8String,
            .nodes_json = self->_nodesJSON.UTF8String,
        };
        SRPWaterWallCallbacks callbacks = {
            .packet = SRPWWPacket,
            .log = SRPWWLog,
            .ready = SRPWWReady,
            .failure = SRPWWFailure,
            .context = (__bridge void *)self,
        };
        self->_bridge = SRPWaterWallBridgeStart(&config, &callbacks);
        if (self->_bridge == NULL && self->_failureCb) {
            self->_failureCb(@"WaterWall could not start (invalid configuration or another session is active)");
        }
    });
}

- (NSString *)resolvedAddressForHost:(NSString *)value {
    struct in_addr address;
    if (inet_pton(AF_INET, value.UTF8String, &address) == 1) return value;
    struct addrinfo hints = {0}, *addresses = NULL;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(value.UTF8String, NULL, &hints, &addresses) != 0 || addresses == NULL) return nil;
    char host[NI_MAXHOST] = {0};
    getnameinfo(addresses->ai_addr, (socklen_t)addresses->ai_addrlen, host, sizeof(host), NULL, 0, NI_NUMERICHOST);
    freeaddrinfo(addresses);
    return host[0] ? @(host) : nil;
}

- (NEPacketTunnelNetworkSettings *)buildSettings {
    NSString *endpoint = [self resolvedAddressForHost:_endpointIP.length > 0 ? _endpointIP : _remoteAddress];
    NEPacketTunnelNetworkSettings *settings =
        [[NEPacketTunnelNetworkSettings alloc] initWithTunnelRemoteAddress:endpoint.length > 0 ? endpoint : _remoteAddress];
    NEIPv4Settings *v4 = [[NEIPv4Settings alloc] initWithAddresses:@[_tunnelAddress]
                                                       subnetMasks:@[@"255.255.255.0"]];
    NSMutableArray<NEIPv4Route *> *includedRoutes = [NSMutableArray new];
    for (NSString *entry in [_allowedIPs componentsSeparatedByString:@","]) {
        NSString *cidr = [entry stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
        NSArray<NSString *> *parts = [cidr componentsSeparatedByString:@"/"];
        struct in_addr address;
        NSInteger prefix = parts.count == 2 ? parts[1].integerValue : -1;
        if (parts.count == 2 && prefix >= 0 && prefix <= 32 && inet_pton(AF_INET, parts[0].UTF8String, &address) == 1) {
            if (prefix == 0) {
                [includedRoutes addObject:NEIPv4Route.defaultRoute];
            } else {
                uint32_t mask = htonl(UINT32_MAX << (32 - prefix));
                NSString *maskString = @(inet_ntoa((struct in_addr){.s_addr = mask}));
                [includedRoutes addObject:[[NEIPv4Route alloc] initWithDestinationAddress:parts[0] subnetMask:maskString]];
            }
        }
    }
    v4.includedRoutes = _allowedIPs.length > 0 ? includedRoutes : @[NEIPv4Route.defaultRoute];
    NSMutableArray<NEIPv4Route *> *excludedRoutes = [NSMutableArray new];
    for (NSString *host in _endpointIPs.count > 0 ? _endpointIPs : @[_endpointIP ?: _remoteAddress]) {
        NSString *resolved = [self resolvedAddressForHost:host];
        if (resolved.length > 0) {
            [excludedRoutes addObject:[[NEIPv4Route alloc] initWithDestinationAddress:resolved subnetMask:@"255.255.255.255"]];
        }
    }
    v4.excludedRoutes = excludedRoutes;
    settings.IPv4Settings = v4;
    settings.DNSSettings = [[NEDNSSettings alloc] initWithServers:_dnsServers];
    settings.MTU = @(_mtu);
    return settings;
}

- (void)drainInjectedPacketsLocked {
    _retryScheduled = NO;
    if (_closed || _bridge == NULL) return;
    while (_pendingPacketIndex < _pendingPackets.count) {
        NSData *packet = _pendingPackets[_pendingPacketIndex];
#if DEBUG
        _packetsSinceMemorySample++;
        if (_packetsSinceMemorySample % 1000 == 1) SRPWWMemoryUsage();
#endif
        int result = SRPWaterWallBridgeSubmitPacket(_bridge, packet.bytes, packet.length);
        if (result == 0) {
            _pendingPacketIndex++;
            continue;
        }
        if (result == -EAGAIN) {
            if (!_retryScheduled) {
                _retryScheduled = YES;
                dispatch_after(dispatch_time(DISPATCH_TIME_NOW, NSEC_PER_MSEC), _worker, ^{
                    [self drainInjectedPacketsLocked];
                });
            }
            return;
        }
        if (_failureCb) {
            _failureCb([NSString stringWithFormat:@"WaterWall packet channel stopped (%d)", result]);
        }
        return;
    }
    _pendingPackets = nil;
    _pendingPacketIndex = 0;
    dispatch_block_t completion = _injectionCompletion;
    _injectionCompletion = nil;
    if (completion) completion();
}

- (void)injectPackets:(NSArray<NSData *> *)packets completion:(dispatch_block_t)completion {
    dispatch_async(_worker, ^{
        if (self->_closed || self->_pendingPackets != nil) return;
        self->_pendingPackets = packets;
        self->_pendingPacketIndex = 0;
        self->_injectionCompletion = completion;
        [self drainInjectedPacketsLocked];
    });
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
    [self stopProbe];
    _pendingPackets = nil;
    _pendingPacketIndex = 0;
    _injectionCompletion = nil;
    if (_bridge != NULL) {
        int result = SRPWaterWallBridgeStop(_bridge);
        if (result != 0) SSLogE(@"WaterWall: stop returned %d", result);
        _bridge = NULL;
    }
    _outputCb = nil;
    _settingsCb = nil;
    _connectedCb = nil;
    _failureCb = nil;
}

- (void)pauseForSleep {
}

- (void)wakeFromSleep {
}

- (void)dealloc {
    [self closeAndWait];
}

@end
