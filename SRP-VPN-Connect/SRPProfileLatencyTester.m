#import "SRPProfileLatencyTester.h"
#import "NodeModel.h"
#import <SRPParser/SRPParser.h>
#import "../Core/SRPCore/SRPWaterWallChainConfig.h"
#import <Network/Network.h>
#import <QuartzCore/QuartzCore.h>
#if TARGET_OS_IPHONE
#import <UIKit/UIKit.h>
#endif

@interface SRPProfileLatencyTester () {
    NSUInteger _runID;
    NSString *_activeNodeID;
    NSURLSession *_session;
    SRPProfileLatencyUpdate _update;
    dispatch_block_t _finished;
}
@end

@implementation SRPProfileLatencyTester

+ (NSArray<NSURL *> *)endpointURLs {
    return @[[NSURL URLWithString:@"https://gstatic.com/generate_204"],
             [NSURL URLWithString:@"https://connectivitycheck.gstatic.com/generate_204"]];
}

+ (NSString *)textForMilliseconds:(NSTimeInterval)milliseconds {
    return [NSString stringWithFormat:@"Ping: %.0f ms", milliseconds];
}

+ (NSString *)textForFailure:(NSError *)error {
    return error.domain == NSURLErrorDomain && error.code == NSURLErrorTimedOut ? @"Timeout" : @"Failed";
}

+ (BOOL)isSuccessfulResponse:(NSURLResponse *)response error:(NSError *)error {
    return error == nil && [response isKindOfClass:NSHTTPURLResponse.class] &&
           ((NSHTTPURLResponse *)response).statusCode == 204;
}

#if TARGET_OS_IPHONE
+ (UIColor *)colorForMilliseconds:(NSInteger)milliseconds {
    if (milliseconds < 0 || milliseconds >= 500) return UIColor.systemRedColor;
    return milliseconds < 200 ? UIColor.systemGreenColor : UIColor.systemOrangeColor;
}
#endif

- (void)measureProfile:(NodeModel *)profile
                update:(SRPProfileLatencyUpdate)update
              finished:(dispatch_block_t)finished {
    if (!NSThread.isMainThread) {
        dispatch_async(dispatch_get_main_queue(), ^{
            [self measureProfile:profile update:update finished:finished];
        });
        return;
    }
    if (profile.nodeId.length == 0) {
        if (finished) finished();
        return;
    }
    [self cancel];
    NSUInteger runID = ++_runID;
    _activeNodeID = [profile.nodeId copy];
    _update = [update copy];
    _finished = [finished copy];
    _update(_activeNodeID, @"Testing…", NSNotFound);
    [self probeEndpointAtIndex:0 runID:runID];
}

- (void)probeEndpointAtIndex:(NSUInteger)endpointIndex runID:(NSUInteger)runID {
    if (runID != _runID) return;
    if (endpointIndex >= self.class.endpointURLs.count) {
        [self finishWithText:[self.class textForFailure:nil] milliseconds:-1 runID:runID];
        return;
    }
    NSURLSessionConfiguration *configuration = NSURLSessionConfiguration.ephemeralSessionConfiguration;
    configuration.timeoutIntervalForRequest = 10;
    configuration.timeoutIntervalForResource = 15;
    configuration.requestCachePolicy = NSURLRequestReloadIgnoringLocalCacheData;
    _session = [NSURLSession sessionWithConfiguration:configuration];
    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:self.class.endpointURLs[endpointIndex]];
    request.cachePolicy = NSURLRequestReloadIgnoringLocalCacheData;
    request.HTTPMethod = @"GET";
    [request setValue:@"no-cache" forHTTPHeaderField:@"Cache-Control"];
    NSTimeInterval started = CACurrentMediaTime();
    __weak typeof(self) weakSelf = self;
    NSURLSessionDataTask *task = [_session dataTaskWithRequest:request
                                            completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
        dispatch_async(dispatch_get_main_queue(), ^{
            SRPProfileLatencyTester *strongSelf = weakSelf;
            if (!strongSelf || runID != strongSelf->_runID) return;
            [strongSelf->_session finishTasksAndInvalidate];
            strongSelf->_session = nil;
            if (PDVPNManager.sharedManager.status != YDVPNStatusConnected) {
                [strongSelf cancel];
            } else if ([strongSelf.class isSuccessfulResponse:response error:error]) {
                NSTimeInterval milliseconds = (CACurrentMediaTime() - started) * 1000;
                [strongSelf finishWithText:[strongSelf.class textForMilliseconds:milliseconds]
                              milliseconds:(NSInteger)llround(milliseconds) runID:runID];
            } else if (endpointIndex + 1 < strongSelf.class.endpointURLs.count) {
                [strongSelf probeEndpointAtIndex:endpointIndex + 1 runID:runID];
            } else {
                [strongSelf finishWithText:[strongSelf.class textForFailure:error] milliseconds:-1 runID:runID];
            }
        });
    }];
    [task resume];
}

- (void)finishWithText:(NSString *)text milliseconds:(NSInteger)milliseconds runID:(NSUInteger)runID {
    if (runID != _runID) return;
    _update(_activeNodeID, text, milliseconds);
    [self cancel];
}

- (void)cancel {
    if (!NSThread.isMainThread) {
        dispatch_async(dispatch_get_main_queue(), ^{ [self cancel]; });
        return;
    }
    _runID += 1;
    [_session invalidateAndCancel];
    _session = nil;
    _activeNodeID = nil;
    _update = nil;
    dispatch_block_t finished = _finished;
    _finished = nil;
    if (finished) finished();
}

@end

static const NSUInteger kSRPTCPPingConcurrency = 16;
static const NSTimeInterval kSRPTCPPingTimeout = 2.5;

@interface SRPProfileTCPPinger () {
    NSUInteger _runID;
    NSMutableArray<NSDictionary *> *_pending;
    NSMutableArray *_connections;
    NSUInteger _active;
    NSUInteger _completed;
    NSUInteger _total;
    SRPProfileTCPPingResult _result;
    SRPProfileTCPPingProgress _progress;
    dispatch_block_t _finished;
    // The physical interfaces that carry a VPN tunnel, from their first path update on
    nw_path_monitor_t _wifiMonitor;
    nw_path_monitor_t _cellularMonitor;
    nw_interface_t _wifiInterface;
    nw_interface_t _cellularInterface;
    NSUInteger _monitorsReported;
    NSMutableArray<dispatch_block_t> *_waitingForInterfaces;
}
@end

@implementation SRPProfileTCPPinger

- (instancetype)init {
    self = [super init];
    if (self) {
        _pending = [NSMutableArray new];
        _connections = [NSMutableArray new];
        _waitingForInterfaces = [NSMutableArray new];
        _wifiMonitor = [self startMonitorForInterfaceType:nw_interface_type_wifi];
        _cellularMonitor = [self startMonitorForInterfaceType:nw_interface_type_cellular];
    }
    return self;
}

- (void)dealloc {
    nw_path_monitor_cancel(_wifiMonitor);
    nw_path_monitor_cancel(_cellularMonitor);
}

- (nw_path_monitor_t)startMonitorForInterfaceType:(nw_interface_type_t)type {
    nw_path_monitor_t monitor = nw_path_monitor_create_with_type(type);
    __weak typeof(self) weakSelf = self;
    __block BOOL reported = NO;
    nw_path_monitor_set_queue(monitor, dispatch_get_main_queue());
    nw_path_monitor_set_update_handler(monitor, ^(nw_path_t path) {
        SRPProfileTCPPinger *strongSelf = weakSelf;
        if (!strongSelf) return;
        __block nw_interface_t interface = nil;
        if (nw_path_get_status(path) == nw_path_status_satisfied) {
            nw_path_enumerate_interfaces(path, ^bool(nw_interface_t candidate) {
                interface = candidate;
                return false;
            });
        }
        if (type == nw_interface_type_wifi) {
            strongSelf->_wifiInterface = interface;
        } else {
            strongSelf->_cellularInterface = interface;
        }
        if (!reported) {
            reported = YES;
            strongSelf->_monitorsReported++;
            if (strongSelf->_monitorsReported == 2) [strongSelf runWaitingForInterfaces];
        }
    });
    nw_path_monitor_start(monitor);
    return monitor;
}

- (void)runWaitingForInterfaces {
    NSArray<dispatch_block_t> *blocks = [_waitingForInterfaces copy];
    [_waitingForInterfaces removeAllObjects];
    for (dispatch_block_t block in blocks) block();
}

/// Runs block once both monitors have reported, or after a second without them.
- (void)whenInterfacesKnown:(dispatch_block_t)block {
    if (_monitorsReported == 2) {
        block();
        return;
    }
    [_waitingForInterfaces addObject:[block copy]];
    __weak typeof(self) weakSelf = self;
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, NSEC_PER_SEC), dispatch_get_main_queue(), ^{
        [weakSelf runWaitingForInterfaces];
    });
}

/// OpenVPN defaults to UDP; the first remote's protocol, or else a proto line, can select TCP.
+ (BOOL)openVPNProfileUsesTCP:(NSString *)text {
    NSString *remoteProtocol = nil;
    NSString *protocol = nil;
    BOOL sawRemote = NO;
    for (NSString *line in [text componentsSeparatedByCharactersInSet:NSCharacterSet.newlineCharacterSet]) {
        NSMutableArray<NSString *> *words = [NSMutableArray new];
        for (NSString *word in [line componentsSeparatedByCharactersInSet:NSCharacterSet.whitespaceCharacterSet]) {
            if (word.length > 0) [words addObject:word];
        }
        if (words.count >= 3 && [words[0] isEqualToString:@"remote"] && !sawRemote) {
            sawRemote = YES;
            if (words.count >= 4) remoteProtocol = words[3];
        } else if (words.count >= 2 && [words[0] isEqualToString:@"proto"] && protocol == nil) {
            protocol = words[1];
        }
    }
    return [(remoteProtocol ?: protocol).lowercaseString hasPrefix:@"tcp"];
}

+ (NSString *)endpointHostForProfile:(NodeModel *)profile port:(uint16_t *)port {
    NSCharacterSet *spaces = NSCharacterSet.whitespaceAndNewlineCharacterSet;
    NSString *type = profile.protocolType;
    NSString *host = [profile.server stringByTrimmingCharactersInSet:spaces];
    // The profile's port getter falls back to 443 like the connection itself
    NSInteger value = [profile.port stringByTrimmingCharactersInSet:spaces].integerValue;
    if ([@[@"sstp", @"softether", @"openconnect", @"ssh"] containsObject:type]) {
        // Always TCP
    } else if ([type isEqualToString:@"openvpn"]) {
        if (profile.ovpnStunnelEnabled) {
            NSString *stunnelHost = [profile.ovpnStunnelHost stringByTrimmingCharactersInSet:spaces];
            if (stunnelHost.length > 0) host = stunnelHost;
            value = [profile.ovpnStunnelPort stringByTrimmingCharactersInSet:spaces].integerValue ?: 443;
        } else if (![self openVPNProfileUsesTCP:profile.ovpnProfile]) {
            return nil;
        }
    } else if ([type isEqualToString:@"waterwall"]) {
        NSDictionary *configuration = [SRPWaterWallChainConfig configurationWithJSON:profile.waterwallConfigJSON] ?:
                                      [SRPWaterWallChainConfig defaultConfiguration];
        if ([SRPWaterWallChainConfig isWireGuardConfiguration:configuration] ||
            [SRPWaterWallChainConfig isDirectConfiguration:configuration] ||
            [configuration[@"carrier"] isEqualToString:@"kcp"] || [configuration[@"outer"] isEqualToString:@"quic"]) {
            return nil;
        }
    } else {
        // WireGuard, AmneziaWG, WARP and server-entry profiles have no TCP server
        return nil;
    }
    if (host.length == 0 || value < 1 || value > 65535) return nil;
    if (port) *port = (uint16_t)value;
    return host;
}

+ (NSString *)textForMilliseconds:(NSInteger)milliseconds timedOut:(BOOL)timedOut {
    if (milliseconds >= 0) return [NSString stringWithFormat:@"TCP: %ld ms", (long)milliseconds];
    return timedOut ? @"TCP: Timeout" : @"TCP: Failed";
}

- (void)pingProfiles:(NSArray<NodeModel *> *)profiles
              result:(SRPProfileTCPPingResult)result
            progress:(SRPProfileTCPPingProgress)progress
            finished:(dispatch_block_t)finished {
    if (!NSThread.isMainThread) {
        dispatch_async(dispatch_get_main_queue(), ^{
            [self pingProfiles:profiles result:result progress:progress finished:finished];
        });
        return;
    }
    [self cancel];
    NSUInteger runID = _runID;
    _result = [result copy];
    _progress = [progress copy];
    _finished = [finished copy];
    for (NodeModel *profile in profiles) {
        uint16_t port = 0;
        NSString *host = [self.class endpointHostForProfile:profile port:&port];
        if (host.length > 0 && profile.nodeId.length > 0) {
            [_pending addObject:@{@"id": profile.nodeId, @"host": host, @"port": @(port)}];
        }
    }
    _total = _pending.count;
    _completed = 0;
    if (_total == 0) {
        [self finishRun:runID];
        return;
    }
    __weak typeof(self) weakSelf = self;
    [self whenInterfacesKnown:^{
        [weakSelf startPendingForRun:runID];
    }];
}

- (void)startPendingForRun:(NSUInteger)runID {
    while (runID == _runID && _active < kSRPTCPPingConcurrency && _pending.count > 0) {
        NSDictionary *target = _pending.firstObject;
        [_pending removeObjectAtIndex:0];
        _active++;
        [self pingTarget:target runID:runID];
    }
}

- (void)pingTarget:(NSDictionary *)target runID:(NSUInteger)runID {
    nw_endpoint_t endpoint = nw_endpoint_create_host([target[@"host"] UTF8String], [target[@"port"] stringValue].UTF8String);
    nw_parameters_t parameters = nw_parameters_create_secure_tcp(NW_PARAMETERS_DISABLE_PROTOCOL,
                                                                 NW_PARAMETERS_DEFAULT_CONFIGURATION);
    // Inside a tunnel whose own TCP stack accepts every connection the handshake would
    // complete on the device, so bind to the physical interface that carries the tunnel.
    YDVPNStatus status = PDVPNManager.sharedManager.status;
    BOOL tunnel = status == YDVPNStatusConnecting || status == YDVPNStatusConnected || status == YDVPNStatusDisconnecting;
    nw_interface_t physical = _wifiInterface ?: _cellularInterface;
    if (tunnel && physical != nil) nw_parameters_require_interface(parameters, physical);
    nw_connection_t connection = nw_connection_create(endpoint, parameters);
    [_connections addObject:connection];
    __block BOOL settled = NO;
    __weak typeof(self) weakSelf = self;
    CFTimeInterval started = CACurrentMediaTime();
    void (^settle)(NSInteger, BOOL) = ^(NSInteger milliseconds, BOOL timedOut) {
        if (settled) return;
        settled = YES;
        nw_connection_cancel(connection);
        SRPProfileTCPPinger *strongSelf = weakSelf;
        if (!strongSelf || runID != strongSelf->_runID) return;
        [strongSelf->_connections removeObject:connection];
        strongSelf->_active--;
        strongSelf->_completed++;
        if (strongSelf->_result) strongSelf->_result(target[@"id"], milliseconds, timedOut);
        if (strongSelf->_progress) strongSelf->_progress(strongSelf->_completed, strongSelf->_total);
        if (strongSelf->_completed == strongSelf->_total) {
            [strongSelf finishRun:runID];
        } else {
            [strongSelf startPendingForRun:runID];
        }
    };
    nw_connection_set_queue(connection, dispatch_get_main_queue());
    nw_connection_set_state_changed_handler(connection, ^(nw_connection_state_t state, nw_error_t error) {
        (void)error;
        if (state == nw_connection_state_ready) {
            NSInteger elapsed = (NSInteger)llround((CACurrentMediaTime() - started) * 1000);
            nw_connection_access_establishment_report(connection, dispatch_get_main_queue(), ^(nw_establishment_report_t report) {
                // The TCP handshake time leaves out name resolution
                __block NSInteger handshake = -1;
                if (report != nil) {
                    nw_protocol_definition_t tcp = nw_protocol_copy_tcp_definition();
                    nw_establishment_report_enumerate_protocols(report, ^bool(nw_protocol_definition_t protocol,
                                                                            uint64_t milliseconds, uint64_t rtt) {
                        (void)rtt;
                        if (!nw_protocol_definition_is_equal(protocol, tcp)) return true;
                        handshake = (NSInteger)milliseconds;
                        return false;
                    });
                }
                settle(handshake >= 0 ? handshake : elapsed, NO);
            });
        } else if (state == nw_connection_state_waiting || state == nw_connection_state_failed) {
            settle(-1, NO);
        }
    });
    nw_connection_start(connection);
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(kSRPTCPPingTimeout * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        settle(-1, YES);
    });
}

- (void)finishRun:(NSUInteger)runID {
    if (runID != _runID) return;
    dispatch_block_t finished = _finished;
    _finished = nil;
    _result = nil;
    _progress = nil;
    if (finished) finished();
}

- (void)cancel {
    if (!NSThread.isMainThread) {
        dispatch_async(dispatch_get_main_queue(), ^{ [self cancel]; });
        return;
    }
    _runID += 1;
    for (nw_connection_t connection in _connections) nw_connection_cancel(connection);
    [_connections removeAllObjects];
    [_pending removeAllObjects];
    _active = 0;
    dispatch_block_t finished = _finished;
    _finished = nil;
    _result = nil;
    _progress = nil;
    if (finished) finished();
}

@end
