#import "SRPWaterWallClient.h"
#import "SRPWaterWallBridge.h"
#import "SSLog.h"
#import "SSNetOptions.h"
#import <NetworkExtension/NetworkExtension.h>
#import <Network/Network.h>
#import <arpa/inet.h>
#import <errno.h>
#import <netdb.h>
#include <stdio.h>
#include <string.h>
#include <stdatomic.h>

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
    uint16_t _probeTcpPort;
    NSInteger _probeAttempts;
    BOOL _probeHTTPStarted;
    uint32_t _probeResponseSequence;
    NSMutableData *_probeResponseHeader;
    NSMutableArray<NSData *> *_pendingProbePackets;
    BOOL _probeSubmissionScheduled;
    dispatch_source_t _probeTimer;
    dispatch_source_t _healthTimer;
    dispatch_source_t _startupTimer;
    NSArray<NSData *> *_pendingPackets;
    NSUInteger _pendingPacketIndex;
    dispatch_block_t _injectionCompletion;
    NSMutableArray<NSDictionary *> *_queuedInjections;
    BOOL _retryScheduled;
    BOOL _sleepPaused;
    BOOL _reconnectPending;
    NSInteger _failedAttempts;
    nw_path_monitor_t _pathMonitor;
    BOOL _lastPathHadWifi;
    _Atomic(NSTimeInterval) _lastOutputAt;
    NSArray<SRPWaterWallCandidate *> *_candidates;
    NSUInteger _candidateIndex;
    NSMutableIndexSet *_lossyCandidates;
    SRPWaterWallLinkQuality *_linkQuality;
    dispatch_source_t _qualityTimer;
    NSUInteger _qualityReadings;
    BOOL _lossHandled;
}
@property (nonatomic) NSTimeInterval lastOutputAt;
@end

@implementation SRPWaterWallCandidate

- (instancetype)init {
    self = [super init];
    if (self) {
        _name = @"WaterWall";
        _remoteAddress = @"127.0.0.1";
        _tunnelAddress = @"10.89.0.1";
        _probeAddress = @"1.1.1.1";
        _dnsProbeAddress = @"1.1.1.1";
        _probeTCP = YES;
        _probeUDP = YES;
        _dnsServers = @[@"1.1.1.1", @"1.0.0.1"];
    }
    return self;
}

@end

typedef struct {
    uint64_t sent;
    uint64_t retransmitted;
    uint64_t received;
    uint64_t timedOut;
    uint32_t srtt;
    uint32_t rto;
} SRPWWLinkSample;

enum {
    SRPWWLinkHistory = 24,   // samples kept: two minutes at the default interval
    SRPWWLossSamples = 6,    // samples judged for retransmissions: 30 seconds
};
static const uint64_t SRPWWLossMinimumPackets = 500;
static const uint64_t SRPWWLossPercent = 15;
static const uint64_t SRPWWTimeoutLimit = 2;

static uint64_t SRPWWGrowth(uint64_t now, uint64_t before) {
    return now > before ? now - before : 0;
}

static SRPWaterWallLinkTotals SRPWWReadLinkTotals(void) {
    SRPWaterWallTCPQuality quality = {0};
    SRPWaterWallBridgeReadTCPQuality(&quality);
    return (SRPWaterWallLinkTotals){
        .sentPackets = quality.tx_packets,
        .retransmittedPackets = quality.retransmitted_packets,
        .receivedBytes = quality.rx_bytes,
        .timedOutConnections = quality.timed_out_connections,
        .maxRTTMilliseconds = quality.max_srtt_ms,
        .maxRTOMilliseconds = quality.max_rto_ms,
    };
}

@implementation SRPWaterWallLinkQuality {
    SRPWaterWallLinkTotals _last;
    BOOL _hasBaseline;
    SRPWWLinkSample _samples[SRPWWLinkHistory];
    NSUInteger _count;
    NSUInteger _next;
}

- (instancetype)init {
    self = [super init];
    if (self) _interval = 5;
    return self;
}

- (void)addTotals:(SRPWaterWallLinkTotals)totals {
    if (_hasBaseline) {
        _samples[_next] = (SRPWWLinkSample){
            .sent = SRPWWGrowth(totals.sentPackets, _last.sentPackets),
            .retransmitted = SRPWWGrowth(totals.retransmittedPackets, _last.retransmittedPackets),
            .received = SRPWWGrowth(totals.receivedBytes, _last.receivedBytes),
            .timedOut = SRPWWGrowth(totals.timedOutConnections, _last.timedOutConnections),
            .srtt = totals.maxRTTMilliseconds,
            .rto = totals.maxRTOMilliseconds,
        };
        _next = (_next + 1) % SRPWWLinkHistory;
        _count = MIN(_count + 1, (NSUInteger)SRPWWLinkHistory);
    }
    _last = totals;
    _hasBaseline = YES;
}

- (void)clearSamples {
    _hasBaseline = NO;
    _count = 0;
    _next = 0;
}

- (SRPWWLinkSample)sumOfLastSamples:(NSUInteger)count {
    SRPWWLinkSample sum = {0};
    for (NSUInteger index = 0; index < MIN(count, _count); index++) {
        SRPWWLinkSample sample = _samples[(_next + SRPWWLinkHistory - 1 - index) % SRPWWLinkHistory];
        sum.sent += sample.sent;
        sum.retransmitted += sample.retransmitted;
        sum.received += sample.received;
        sum.timedOut += sample.timedOut;
        sum.srtt = MAX(sum.srtt, sample.srtt);
        sum.rto = MAX(sum.rto, sample.rto);
    }
    return sum;
}

- (NSString *)lossReason {
    SRPWWLinkSample recent = [self sumOfLastSamples:SRPWWLossSamples];
    if (_count >= SRPWWLossSamples && recent.sent >= SRPWWLossMinimumPackets &&
        recent.retransmitted * 100 >= recent.sent * SRPWWLossPercent) {
        return [NSString stringWithFormat:@"%llu%% of the packets sent to the server were retransmitted in the last %.0f seconds",
                recent.retransmitted * 100 / recent.sent, (double)SRPWWLossSamples * _interval];
    }
    SRPWWLinkSample history = [self sumOfLastSamples:SRPWWLinkHistory];
    if (history.timedOut >= SRPWWTimeoutLimit) {
        return [NSString stringWithFormat:@"the network dropped %llu connections to the server in the last %.0f seconds",
                history.timedOut, MIN(_count, (NSUInteger)SRPWWLinkHistory) * _interval];
    }
    return nil;
}

- (NSString *)summaryOfLastSamples:(NSUInteger)count {
    SRPWWLinkSample sum = [self sumOfLastSamples:count];
    if (sum.sent == 0 && sum.received == 0 && sum.timedOut == 0) return nil;
    return [NSString stringWithFormat:@"%llu packets sent, %.1f%% retransmitted, %llu KB received, "
            "%llu connections dropped by the network, RTT up to %u ms, RTO up to %u ms",
            sum.sent, sum.sent > 0 ? 100.0 * sum.retransmitted / sum.sent : 0, sum.received / 1024,
            sum.timedOut, sum.srtt, sum.rto];
}

@end

@implementation SRPWaterWallClient

- (NSTimeInterval)lastOutputAt {
    return atomic_load_explicit(&_lastOutputAt, memory_order_relaxed);
}

- (void)setLastOutputAt:(NSTimeInterval)value {
    atomic_store_explicit(&_lastOutputAt, value, memory_order_relaxed);
}

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

static void SRPWWPut32(uint8_t *p, uint32_t value) {
    SRPWWPut16(p, value >> 16);
    SRPWWPut16(p + 2, value & 0xffff);
}

static NSData *SRPWWTcpPacketWithPayload(NSString *source, NSString *destination, uint16_t sourcePort,
                                         uint16_t destinationPort, uint8_t flags, uint32_t sequence,
                                         uint32_t acknowledgement, const uint8_t *payload, size_t payloadLength) {
    NSMutableData *data = [NSMutableData dataWithLength:40 + payloadLength];
    uint8_t *p = data.mutableBytes;
    SRPWWIP(p, data.length, IPPROTO_TCP, source, destination);
    SRPWWPut16(p + 20, sourcePort);
    SRPWWPut16(p + 22, destinationPort);
    SRPWWPut32(p + 24, sequence);
    SRPWWPut32(p + 28, acknowledgement);
    p[32] = 5 << 4;
    p[33] = flags;
    SRPWWPut16(p + 34, 0xffff);
    if (payloadLength > 0) memcpy(p + 40, payload, payloadLength);
    uint32_t sum = SRPWWSum(p + 12, 8, IPPROTO_TCP + 20 + payloadLength);
    SRPWWPut16(p + 36, SRPWWChecksum(SRPWWSum(p + 20, 20 + payloadLength, sum)));
    return data;
}

static NSData *SRPWWTcpPacket(NSString *source, NSString *destination, uint16_t sourcePort,
                              uint8_t flags, uint32_t sequence, uint32_t acknowledgement) {
    return SRPWWTcpPacketWithPayload(source, destination, sourcePort, 80, flags, sequence, acknowledgement, NULL, 0);
}

static NSData *SRPWWSynPacket(NSString *source, NSString *destination, uint16_t sourcePort) {
    return SRPWWTcpPacket(source, destination, sourcePort, 0x02, 1, 0);
}

static NSData *SRPWWHealthPacket(NSString *source, NSString *destination, uint16_t sourcePort, uint32_t acknowledgement) {
    static const uint8_t request[] = "GET / HTTP/1.1\r\nHost: 1.1.1.1\r\nConnection: close\r\n\r\n";
    return SRPWWTcpPacketWithPayload(source, destination, sourcePort, 80, 0x18, 2, acknowledgement,
                                     request, sizeof(request) - 1);
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

// PacketsToConnection answers handshakes, acknowledges and resets flows and serves
// fake DNS on the device itself, so only relayed payload shows the server path works.
static BOOL SRPWWPacketCarriesRemotePayload(const uint8_t *packet, size_t length) {
    if ((packet[0] >> 4) != 4) return NO;
    size_t ihl = (size_t)(packet[0] & 0x0f) * 4;
    size_t total = MIN(length, ((size_t)packet[2] << 8) | packet[3]);
    if (ihl < 20 || total < ihl + 8) return NO;
    if (packet[9] == IPPROTO_TCP) {
        if (total < ihl + 20) return NO;
        size_t header = (size_t)(packet[ihl + 12] >> 4) * 4;
        return header >= 20 && total > ihl + header;
    }
    return packet[9] == IPPROTO_UDP && (((uint16_t)packet[ihl] << 8) | packet[ihl + 1]) != 53;
}

static void SRPWWPacket(void *context, const uint8_t *packet, size_t length) {
    SRPWaterWallClient *client = (__bridge SRPWaterWallClient *)context;
    if (client == nil || packet == NULL || length < 20) return;
    if (SRPWWPacketCarriesRemotePayload(packet, length)) {
        atomic_store_explicit(&client->_lastOutputAt, NSProcessInfo.processInfo.systemUptime, memory_order_relaxed);
    }
    @autoreleasepool {
        NSData *data = [NSData dataWithBytes:packet length:length];
        int family = (packet[0] >> 4) == 6 ? AF_INET6 : AF_INET;
        if (client->_outputCb) client->_outputCb(data, family);
        if (!client->_closed && client->_probeStage > 0 && client->_probeStage < 6) {
            dispatch_async(client->_worker, ^{ [client handleProbePacket:data]; });
        }
    }
}

static NSString *SRPWWNativeLogPath(void) {
    NSURL *container = [NSFileManager.defaultManager containerURLForSecurityApplicationGroupIdentifier:@"group.tr.com.srp.vpn"];
    NSString *directory = [(container ? container.path : NSHomeDirectory()) stringByAppendingPathComponent:@"Library"];
    [NSFileManager.defaultManager createDirectoryAtPath:directory withIntermediateDirectories:YES attributes:nil error:nil];
    return [directory stringByAppendingPathComponent:@"ww-native-current.log"];
}

static void SRPWWLog(void *context, int level, const char *message, size_t length) {
    SRPWaterWallClient *client = (__bridge SRPWaterWallClient *)context;
    if (!client.liveDiagnostics) return;
    @autoreleasepool {
        if (message == NULL) return;
        // A debug-level diagnostic run keeps every line; otherwise only errors and known flow events.
        if (level < 4 && client.logLevel < 2) {
            static const char *const prefixes[] = {
                "VmessClient:", "TcpConnector: received close", "PacketsToConnection: closing flow",
                "PacketsToConnection: closing TCP flow",
            };
            BOOL keep = NO;
            for (NSUInteger index = 0; index < sizeof(prefixes) / sizeof(prefixes[0]); index++) {
                if (strstr(message, prefixes[index]) != NULL) {
                    keep = YES;
                    break;
                }
            }
            if (!keep) return;
        }
        FILE *file = fopen(SRPWWNativeLogPath().fileSystemRepresentation, "a");
        if (file != NULL) {
            fprintf(file, "%.*s\n", (int)length, message);
            fclose(file);
        }
    }
}

static void SRPWWReady(void *context) {
    SRPWaterWallClient *client = (__bridge SRPWaterWallClient *)context;
    dispatch_async(client->_worker, ^{
        if (client->_closed || client->_sleepPaused || client->_up || client->_probeStage != 0) return;
        [client beginDataPlaneProbe];
    });
}

static void SRPWWFailure(void *context, int code, const char *message) {
    SRPWaterWallClient *client = (__bridge SRPWaterWallClient *)context;
    NSLog(@"WaterWall: native runtime exited with code %d", code);
    dispatch_async(client->_worker, ^{
        if (client->_closed || client->_sleepPaused) return;
        NSString *reason = message ? @(message) : @"WaterWall runtime stopped";
        [client handleRuntimeFailure:[NSString stringWithFormat:@"%@ (%d)", reason, code]];
    });
}

- (void)scheduleProbeSubmission {
    if (_closed || _probeSubmissionScheduled || _pendingProbePackets.count == 0) return;
    _probeSubmissionScheduled = YES;
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, NSEC_PER_MSEC), _worker, ^{
        self->_probeSubmissionScheduled = NO;
        if (self->_closed || self->_pendingProbePackets.count == 0) return;
        NSData *packet = self->_pendingProbePackets.firstObject;
        [self->_pendingProbePackets removeObjectAtIndex:0];
        [self submitProbePacket:packet];
    });
}

- (void)submitProbePacket:(NSData *)packet {
    if (_closed || _bridge == NULL) return;
    if (_pendingProbePackets.count > 0) {
        [_pendingProbePackets addObject:packet];
        [self scheduleProbeSubmission];
        return;
    }
    int result = SRPWaterWallBridgeSubmitPacket(_bridge, packet.bytes, packet.length);
    if (result == -EAGAIN) {
        if (_pendingProbePackets == nil) _pendingProbePackets = [NSMutableArray new];
        [_pendingProbePackets addObject:packet];
        [self scheduleProbeSubmission];
        return;
    }
    if (result != 0) {
        if (_probeStage >= 4) [self healthProbeFailed:@"WaterWall health probe submission failed"];
        else [self probeFailed:[NSString stringWithFormat:@"WaterWall probe submission failed (%d)", result]];
    }
}

- (void)sendSynProbe {
    if (_closed || _pendingProbePackets.count > 0 || (_probeStage != 1 && _probeStage != 4)) return;
    _probeAttempts++;
    _probeHTTPStarted = NO;
    _probeResponseHeader = nil;
    [self submitProbePacket:SRPWWSynPacket(_tunnelAddress, _probeAddress, _probeTcpPort)];
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (_probeStage == 1 ? 1 : 5) * NSEC_PER_SEC), _worker, ^{
        if ((self->_probeStage != 1 && self->_probeStage != 4) || self->_closed || self->_pendingProbePackets.count > 0) return;
        if (self->_probeAttempts >= (self->_probeStage == 1 ? 15 : 3)) {
            if (self->_probeStage == 1) [self probeFailed:@"WaterWall TCP probe failed after fifteen attempts"];
            else [self healthProbeFailed:@"WaterWall TCP health probe failed"];
        } else {
            [self sendSynProbe];
        }
    });
}

- (void)sendHTTPProbe:(uint32_t)acknowledgement {
    if (_pendingProbePackets.count > 0) return;
    _probeHTTPStarted = YES;
    _probeResponseSequence = acknowledgement;
    _probeResponseHeader = [NSMutableData new];
    [self submitProbePacket:SRPWWHealthPacket(_tunnelAddress, _probeAddress, _probeTcpPort, acknowledgement)];
}

- (void)sendDnsProbe {
    if (_closed || _pendingProbePackets.count > 0 || (_probeStage != 2 && _probeStage != 5)) return;
    _probeAttempts++;
    [self submitProbePacket:SRPWWDnsPacket(_tunnelAddress, _probeDnsId, _dnsProbeAddress)];
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, NSEC_PER_SEC), _worker, ^{
        if ((self->_probeStage != 2 && self->_probeStage != 5) || self->_closed || self->_pendingProbePackets.count > 0) return;
        if (self->_probeAttempts >= (self->_probeStage == 2 ? 5 : 3)) {
            if (self->_probeStage == 2) [self probeFailed:@"WaterWall UDP/DNS probe failed after five attempts"];
            else [self healthProbeFailed:@"WaterWall UDP/DNS health probe failed"];
        } else {
            [self sendDnsProbe];
        }
    });
}

- (void)startHealthMonitor {
    if (_healthTimer || (!_probeTCP && !_probeUDP)) return;
    _healthTimer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, _worker);
    // Check often, but probe only after 15 seconds without relayed payload.
    dispatch_source_set_timer(_healthTimer, dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC), 5 * NSEC_PER_SEC, NSEC_PER_SEC);
    dispatch_source_set_event_handler(_healthTimer, ^{
        if (self->_closed || self->_sleepPaused || !self->_up || self->_probeStage != 3) return;
        NSTimeInterval age = NSProcessInfo.processInfo.systemUptime -
            atomic_load_explicit(&self->_lastOutputAt, memory_order_relaxed);
        if (age >= 0 && age < 15) return;
        self->_probeStage = self->_probeTCP ? 4 : 5;
        self->_probeAttempts = 0;
        self->_probeTcpPort = arc4random_uniform(40000) + 20000;
        if (self->_probeTCP) [self sendSynProbe];
        else [self sendDnsProbe];
    });
    dispatch_resume(_healthTimer);
}

- (void)finishHealthCheck {
    if (_closed || _sleepPaused) return;
    _probeStage = 3;
    _probeAttempts = 0;
}

- (void)healthProbeFailed:(NSString *)reason {
    if (_closed || _sleepPaused || _probeStage < 4) return;
    NSTimeInterval age = NSProcessInfo.processInfo.systemUptime -
        atomic_load_explicit(&self->_lastOutputAt, memory_order_relaxed);
    if (age >= 0 && age < 15) {
        [self finishHealthCheck];
        return;
    }
    _probeStage = -1;
    [self handleRuntimeFailure:reason];
}

- (void)beginDataPlaneProbe {
    NSLog(@"WaterWall: native chain ready; starting data-plane probe");
    _probeStage = _probeTCP ? 1 : 2;
    _probeAttempts = 0;
    _probeDnsId = arc4random_uniform(65535) + 1;
    _probeTcpPort = arc4random_uniform(40000) + 20000;
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
    if (_closed || _sleepPaused) return;
    if (_probeTimer) {
        dispatch_source_cancel(_probeTimer);
        _probeTimer = nil;
    }
    _probeStage = 6;
    _failedAttempts = 0;
    if (_probeTCP && _probeUDP) {
        SSLogM(@"WaterWall: TCP and UDP/DNS data-plane probes passed");
    } else if (_probeTCP) {
        SSLogM(@"WaterWall: TCP data-plane probe passed");
    } else if (_probeUDP) {
        SSLogM(@"WaterWall: UDP/DNS data-plane probe passed");
    } else {
        SSLogM(@"WaterWall: no external data-plane probe required");
    }
    void (^applied)(NSError *) = ^(NSError *error) {
        dispatch_async(self->_worker, ^{
            if (self->_closed || self->_sleepPaused || self->_probeStage != 6) return;
            if (error != nil) {
                [self handleRuntimeFailure:[NSString stringWithFormat:@"WaterWall network settings failed: %@",
                                            error.localizedDescription]];
                return;
            }
            self->_probeStage = 3;
            self->_up = YES;
            if (self->_connectedCb) self->_connectedCb();
            [self drainInjectedPacketsLocked];
            [self startHealthMonitor];
            [self startQualityMonitor];
        });
    };
    if (_settingsCb) {
        _settingsCb([self buildSettings], applied);
    } else {
        applied(nil);
    }
}

- (void)probeFailed:(NSString *)reason {
    if (_closed || _sleepPaused || _up || _probeStage < 0) return;
    _probeStage = -1;
    if (_probeTimer) {
        dispatch_source_cancel(_probeTimer);
        _probeTimer = nil;
    }
    [self handleRuntimeFailure:reason];
}

- (void)stopProbe {
    if (_probeTimer) {
        dispatch_source_cancel(_probeTimer);
        _probeTimer = nil;
    }
    if (_healthTimer) {
        dispatch_source_cancel(_healthTimer);
        _healthTimer = nil;
    }
    if (_qualityTimer) {
        dispatch_source_cancel(_qualityTimer);
        _qualityTimer = nil;
    }
    _probeStage = 0;
    _probeHTTPStarted = NO;
    _probeResponseHeader = nil;
    _pendingProbePackets = nil;
    _probeSubmissionScheduled = NO;
}

- (void)handleProbePacket:(NSData *)packet {
    if (_closed || _probeStage <= 0 || packet.length < 28) return;
    const uint8_t *p = packet.bytes;
    if ((p[0] >> 4) != 4) return;
    NSUInteger ihl = (p[0] & 0x0f) * 4;
    if (ihl < 20 || packet.length < ihl + 8) return;
    uint8_t probeIP[4];
    NSString *expectedSource = (_probeStage == 2 || _probeStage == 5) ? _dnsProbeAddress : _probeAddress;
    if (inet_pton(AF_INET, expectedSource.UTF8String, probeIP) != 1 || memcmp(p + 12, probeIP, 4) != 0) return;
    if ((_probeStage == 1 || _probeStage == 4) && p[9] == IPPROTO_TCP && packet.length >= ihl + 20) {
        const uint8_t *tcp = p + ihl;
        const NSUInteger tcpHeaderLength = (tcp[12] >> 4) * 4;
        if (tcpHeaderLength < 20 || packet.length < ihl + tcpHeaderLength) return;
        const uint16_t sourcePort = ((uint16_t)tcp[0] << 8) | tcp[1];
        const uint16_t destinationPort = ((uint16_t)tcp[2] << 8) | tcp[3];
        if (sourcePort != 80 || destinationPort != _probeTcpPort) return;
        const uint32_t peerSequence = ((uint32_t)tcp[4] << 24) | ((uint32_t)tcp[5] << 16) |
                                    ((uint32_t)tcp[6] << 8) | tcp[7];
        if (_probeHTTPStarted) {
            const NSUInteger payloadLength = packet.length - ihl - tcpHeaderLength;
            if (payloadLength == 0 || peerSequence != _probeResponseSequence) return;
            _probeResponseSequence += (uint32_t)payloadLength;
            const uint8_t *payload = tcp + tcpHeaderLength;
            for (NSUInteger index = 0; index < payloadLength && _probeResponseHeader.length < 64; ++index) {
                UInt8 byte = payload[index];
                [_probeResponseHeader appendBytes:&byte length:1];
            }
            if (_probeResponseHeader.length >= 5 && memcmp(_probeResponseHeader.bytes, "HTTP/", 5) == 0) {
                if (_probeUDP) {
                    _probeStage = _probeStage == 4 ? 5 : 2;
                    _probeAttempts = 0;
                    [self sendDnsProbe];
                } else if (_probeStage == 4) {
                    [self finishHealthCheck];
                } else {
                    [self finishProbe];
                }
            }
            return;
        }
        if ((tcp[13] & 0x12) == 0x12) {
            [self sendHTTPProbe:peerSequence + 1];
        }
    } else if ((_probeStage == 2 || _probeStage == 5) && p[9] == IPPROTO_UDP && packet.length >= ihl + 20) {
        const uint8_t *udp = p + ihl;
        uint16_t sourcePort = (udp[0] << 8) | udp[1];
        uint16_t destinationPort = (udp[2] << 8) | udp[3];
        uint16_t identifier = (udp[8] << 8) | udp[9];
        uint16_t flags = (udp[10] << 8) | udp[11];
        uint16_t answers = (udp[14] << 8) | udp[15];
        if (sourcePort == 53 && destinationPort == 12353 && identifier == _probeDnsId &&
            (flags & 0x8000) != 0 && (flags & 0x000f) == 0 && answers > 0) {
            if (_probeStage == 5) [self finishHealthCheck];
            else [self finishProbe];
        }
    }
}

- (instancetype)init {
    self = [super init];
    if (self) {
        _worker = dispatch_queue_create("srp.waterwall", DISPATCH_QUEUE_SERIAL);
        dispatch_queue_set_specific(_worker, (__bridge const void *)self, (__bridge void *)self, NULL);
        [self applyCandidate:[SRPWaterWallCandidate new]];
        _fallbacks = @[];
        _qualityInterval = 5;
        _mtu = 1420;
        _autoReconnect = YES;
        _switchToWifi = YES;
        _onSleep = 2;
    }
    return self;
}

+ (SRPWaterWallLinkTotals)currentLinkTotals {
    return SRPWWReadLinkTotals();
}

- (void)applyCandidate:(SRPWaterWallCandidate *)candidate {
    _profileName = candidate.name;
    _nodesJSON = candidate.nodesJSON;
    _remoteAddress = candidate.remoteAddress;
    _endpointIP = candidate.endpointIP;
    _endpointIPs = candidate.endpointIPs;
    _tunnelAddress = candidate.tunnelAddress;
    _probeAddress = candidate.probeAddress;
    _dnsProbeAddress = candidate.dnsProbeAddress;
    _probeTCP = candidate.probeTCP;
    _probeUDP = candidate.probeUDP;
    _dnsServers = candidate.dnsServers;
    _allowedIPs = candidate.allowedIPs;
    _udpCarrier = candidate.udpCarrier;
}

- (SRPWaterWallCandidate *)currentCandidate {
    SRPWaterWallCandidate *candidate = [SRPWaterWallCandidate new];
    candidate.name = _profileName;
    candidate.nodesJSON = _nodesJSON;
    candidate.remoteAddress = _remoteAddress;
    candidate.endpointIP = _endpointIP;
    candidate.endpointIPs = _endpointIPs;
    candidate.tunnelAddress = _tunnelAddress;
    candidate.probeAddress = _probeAddress;
    candidate.dnsProbeAddress = _dnsProbeAddress;
    candidate.probeTCP = _probeTCP;
    candidate.probeUDP = _probeUDP;
    candidate.dnsServers = _dnsServers;
    candidate.allowedIPs = _allowedIPs;
    candidate.udpCarrier = _udpCarrier;
    return candidate;
}

- (void)switchToCandidate:(NSUInteger)index {
    _candidateIndex = index;
    [self applyCandidate:_candidates[index]];
}

// After heavy loss: the next profile with the other carrier, else the next one,
// skipping every profile that already lost packets on this network.
- (NSUInteger)candidateAfterLoss {
    NSUInteger sameCarrier = NSNotFound;
    for (NSUInteger step = 1; step < _candidates.count; step++) {
        NSUInteger index = (_candidateIndex + step) % _candidates.count;
        if ([_lossyCandidates containsIndex:index]) continue;
        if (_candidates[index].udpCarrier != _udpCarrier) return index;
        if (sameCarrier == NSNotFound) sameCarrier = index;
    }
    return sameCarrier;
}

- (void)startQualityMonitor {
    if (_qualityTimer || _qualityInterval <= 0) return;
    _linkQuality.interval = _qualityInterval;
    [_linkQuality clearSamples];
    [_linkQuality addTotals:SRPWWReadLinkTotals()];
    _qualityReadings = 0;
    _lossHandled = NO;
    uint64_t interval = (uint64_t)(_qualityInterval * NSEC_PER_SEC);
    _qualityTimer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, _worker);
    dispatch_source_set_timer(_qualityTimer, dispatch_time(DISPATCH_TIME_NOW, (int64_t)interval), interval, interval / 10);
    dispatch_source_set_event_handler(_qualityTimer, ^{ [self readLinkQuality]; });
    dispatch_resume(_qualityTimer);
}

- (void)readLinkQuality {
    if (_closed || _sleepPaused || !_up) return;
    [_linkQuality addTotals:SRPWWReadLinkTotals()];
    NSUInteger perMinute = MAX((NSUInteger)1, (NSUInteger)llround(60 / _qualityInterval));
    if (++_qualityReadings % perMinute == 0) {
        NSString *summary = [_linkQuality summaryOfLastSamples:perMinute];
        if (summary) SSLogM(@"WaterWall: last minute on %@: %@", _profileName, summary);
    }
    NSString *reason = _linkQuality.lossReason;
    if (reason == nil || _lossHandled) return;
    _lossHandled = YES;
    [_lossyCandidates addIndex:_candidateIndex];
    NSUInteger next = [self candidateAfterLoss];
    if (next == NSNotFound) {
        SSLogM(@"WaterWall: %@ on %@; %@", reason, _profileName,
               _candidates.count > 1 ? @"the other profiles of this server lost packets on this network too, so it stays"
                                     : @"no other profile of this server can take over");
        return;
    }
    SSLogM(@"WaterWall: %@ on %@; switching to %@", reason, _profileName, _candidates[next].name);
    [self switchToCandidate:next];
    _failedAttempts = 0;
    [self startRuntimeLocked];
}

- (void)stopRuntimeLocked {
    [self stopProbe];
    if (_startupTimer) {
        dispatch_source_cancel(_startupTimer);
        _startupTimer = nil;
    }
    if (_bridge != NULL) {
        int result = SRPWaterWallBridgeStop(_bridge);
        if (result != 0) SSLogE(@"WaterWall: stop returned %d", result);
        _bridge = NULL;
    }
}

- (void)startRuntimeLocked {
    if (_closed || _sleepPaused) return;
    [self stopRuntimeLocked];
    _up = NO;
    atomic_store_explicit(&_lastOutputAt, 0, memory_order_relaxed);
    if (_coreJSON.length == 0 || _nodesJSON.length == 0) {
        [self failWithReason:@"WaterWall configuration is missing"];
        return;
    }
    SRPWaterWallConfig config = {
        .core_json = _coreJSON.UTF8String,
        .nodes_json = _nodesJSON.UTF8String,
    };
    SRPWaterWallCallbacks callbacks = {
        .packet = SRPWWPacket,
        .log = SRPWWLog,
        .ready = SRPWWReady,
        .failure = SRPWWFailure,
        .context = (__bridge void *)self,
    };
    NSLog(@"WaterWall native log path: %@", SRPWWNativeLogPath());
    SRPWWLog(NULL, 0, "WaterWall native logging started", 32);
    _bridge = SRPWaterWallBridgeStart(&config, &callbacks);
    if (_bridge == NULL) {
        [self failWithReason:@"WaterWall could not start (invalid configuration or another session is active)"];
        return;
    }
    _startupTimer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, _worker);
    dispatch_source_set_timer(_startupTimer, dispatch_time(DISPATCH_TIME_NOW, 30 * NSEC_PER_SEC), DISPATCH_TIME_FOREVER, 0);
    dispatch_source_set_event_handler(_startupTimer, ^{
        if (!self->_closed && !self->_sleepPaused && !self->_up) {
            [self handleRuntimeFailure:@"WaterWall data-plane validation timed out"];
        }
    });
    dispatch_resume(_startupTimer);
}

- (void)handleRuntimeFailure:(NSString *)reason {
    if (_closed || _sleepPaused || _reconnectPending) return;
    NSLog(@"WaterWall: handling runtime failure: %@", reason);
    SSLogM(@"WaterWall: handling runtime failure: %@", reason);
    _up = NO;
    [self stopRuntimeLocked];
    if (!_autoReconnect || !SSReconnectAttemptAllowed(_failedAttempts, _retryTimes)) {
        NSString *terminalReason = reason;
        if (_autoReconnect && _retryTimes > 0) {
            terminalReason = [NSString stringWithFormat:@"Could not reconnect after %ld attempts. (%@)",
                              (long)_retryTimes, reason];
        }
        [self failWithReason:terminalReason];
        return;
    }
    _failedAttempts++;
    _reconnectPending = YES;
    SSLogM(@"WaterWall: %@; reconnecting in 2s (attempt %ld%@)", reason, (long)_failedAttempts,
           _retryTimes > 0 ? [NSString stringWithFormat:@" of %ld", (long)_retryTimes] : @"");
    if (_candidates.count > 1) {
        [self switchToCandidate:(_candidateIndex + 1) % _candidates.count];
        SSLogM(@"WaterWall: the next attempt uses %@", _profileName);
    }
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 2 * NSEC_PER_SEC), _worker, ^{
        self->_reconnectPending = NO;
        if (!self->_closed && !self->_sleepPaused) [self startRuntimeLocked];
    });
}

- (void)failWithReason:(NSString *)reason {
    SSLogM(@"WaterWall: closing with reason: %@", reason);
    _closed = YES;
    _up = NO;
    [self stopRuntimeLocked];
    [self stopPathMonitor];
    if (_failureCb) _failureCb(reason);
}

- (void)startPathMonitor {
    [self stopPathMonitor];
    if (!_switchToWifi || _closed || _sleepPaused) return;
    _lastPathHadWifi = NO;
    _pathMonitor = nw_path_monitor_create();
    __weak SRPWaterWallClient *weakSelf = self;
    nw_path_monitor_set_queue(_pathMonitor, _worker);
    nw_path_monitor_set_update_handler(_pathMonitor, ^(nw_path_t path) {
        SRPWaterWallClient *strongSelf = weakSelf;
        if (!strongSelf) return;
        BOOL satisfied = nw_path_get_status(path) == nw_path_status_satisfied;
        BOOL hasWifi = nw_path_uses_interface_type(path, nw_interface_type_wifi);
        BOOL hadWifi = strongSelf->_lastPathHadWifi;
        if (!satisfied) return;
        strongSelf->_lastPathHadWifi = hasWifi;
        BOOL shouldMigrate = SSShouldReconnectForPathChange(hadWifi, hasWifi, satisfied, strongSelf->_up) ||
            (hadWifi && !hasWifi && satisfied && strongSelf->_up);
        if (shouldMigrate && !strongSelf->_closed && !strongSelf->_sleepPaused) {
            SSLogM(@"WaterWall: %@; migrating the connection to the new path",
                   hasWifi ? @"Wi-Fi became available" : @"Wi-Fi became unavailable");
            strongSelf->_failedAttempts = 0;
            // What failed or lost packets on the previous network says nothing about this one.
            [strongSelf->_lossyCandidates removeAllIndexes];
            if (strongSelf->_candidateIndex != 0) {
                [strongSelf switchToCandidate:0];
                SSLogM(@"WaterWall: returning to %@ on the new network", strongSelf->_profileName);
            }
            [strongSelf startRuntimeLocked];
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

- (void)startWithOutputCallback:(SRPWaterWallOutputCallback)output
         networkSettingsCallback:(SRPWaterWallNetworkSettingsCallback)settings
               connectedCallback:(SRPWaterWallConnectedCallback)connected
                 failureCallback:(SRPWaterWallFailureBlock)failure {
    _outputCb = output;
    _settingsCb = settings;
    _connectedCb = connected;
    _failureCb = failure;
    _closed = NO;
    _sleepPaused = NO;
    _reconnectPending = NO;
    _failedAttempts = 0;
    _candidates = [@[[self currentCandidate]] arrayByAddingObjectsFromArray:_fallbacks];
    _candidateIndex = 0;
    _lossyCandidates = [NSMutableIndexSet new];
    _linkQuality = [SRPWaterWallLinkQuality new];
    if (_fallbacks.count > 0) {
        SSLogM(@"WaterWall: Auto Switch can move %@ to %lu other profiles of the same server",
               _profileName, (unsigned long)_fallbacks.count);
    }
    SSLogSetLevel((SSLogLevel)_logLevel);
    dispatch_async(_worker, ^{
        [self startRuntimeLocked];
        [self startPathMonitor];
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

- (BOOL)runtimeCanAcceptPackets {
    return !_closed && !_sleepPaused && _up && _bridge != NULL;
}

- (int)submitPacketToRuntime:(NSData *)packet {
    return SRPWaterWallBridgeSubmitPacket(_bridge, packet.bytes, packet.length);
}

- (void)drainInjectedPacketsLocked {
    _retryScheduled = NO;
    if (![self runtimeCanAcceptPackets]) return;
    while (_pendingPackets != nil) {
        while (_pendingPacketIndex < _pendingPackets.count) {
            NSData *packet = _pendingPackets[_pendingPacketIndex];
            int result = [self submitPacketToRuntime:packet];
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
            if (result == -ENOTCONN) {
                [self handleRuntimeFailure:[NSString stringWithFormat:@"WaterWall packet channel stopped (%d)", result]];
            } else {
                [self failWithReason:[NSString stringWithFormat:@"WaterWall packet submission failed (%d)", result]];
            }
            return;
        }
        _pendingPackets = nil;
        _pendingPacketIndex = 0;
        dispatch_block_t completion = _injectionCompletion;
        _injectionCompletion = nil;
        if (completion) completion();
        if (_queuedInjections.count == 0) return;
        NSDictionary *next = _queuedInjections.firstObject;
        [_queuedInjections removeObjectAtIndex:0];
        _pendingPackets = next[@"packets"];
        _pendingPacketIndex = 0;
        _injectionCompletion = next[@"completion"] == NSNull.null ? nil : next[@"completion"];
    }
}

- (void)injectPackets:(NSArray<NSData *> *)packets completion:(dispatch_block_t)completion {
    dispatch_async(_worker, ^{
        if (self->_closed) {
            if (completion) completion();
            return;
        }
        if (self->_pendingPackets != nil) {
            if (self->_queuedInjections == nil) self->_queuedInjections = [NSMutableArray new];
            [self->_queuedInjections addObject:@{
                @"packets": packets,
                @"completion": completion ? [completion copy] : NSNull.null,
            }];
            return;
        }
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
    _closed = YES;
    _up = NO;
    [self stopPathMonitor];
    [self stopRuntimeLocked];
    _pendingPackets = nil;
    _pendingPacketIndex = 0;
    _injectionCompletion = nil;
    _queuedInjections = nil;
    _outputCb = nil;
    _settingsCb = nil;
    _connectedCb = nil;
    _failureCb = nil;
}

- (void)pauseForSleep {
    dispatch_async(_worker, ^{
        if (self->_onSleep == 2 || self->_closed) return;
        SSLogM(@"WaterWall: device sleep: %@ the connection", self->_onSleep == 1 ? @"pausing" : @"closing");
        self->_sleepPaused = YES;
        self->_reconnectPending = NO;
        self->_up = NO;
        [self stopRuntimeLocked];
    });
}

- (void)wakeFromSleep {
    dispatch_async(_worker, ^{
        if (!self->_sleepPaused || self->_closed) return;
        self->_sleepPaused = NO;
        if (self->_onSleep == 1 || self->_autoReconnect) {
            self->_failedAttempts = 0;
            SSLogM(@"WaterWall: device wake: reconnecting the connection");
            [self startRuntimeLocked];
        } else {
            // Off without Auto Reconnect leaves no data plane; end the tunnel
            // instead of keeping a VPN that silently drops every packet.
            [self failWithReason:@"The connection was closed while the device slept."];
        }
    });
}

- (void)dealloc {
    [self closeAndWait];
}

@end
