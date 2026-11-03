#import <Foundation/Foundation.h>

@class NEPacketTunnelNetworkSettings;

NS_ASSUME_NONNULL_BEGIN

typedef void(^SRPWaterWallOutputCallback)(NSData *ipPacket, int family);
typedef void(^SRPWaterWallNetworkSettingsCallback)(NEPacketTunnelNetworkSettings *setting,
                                                    void(^completion)(NSError *_Nullable error));
typedef void(^SRPWaterWallConnectedCallback)(void);
typedef void(^SRPWaterWallFailureBlock)(NSString *reason);

// One WaterWall profile the client can run: its node graph and the tunnel settings it needs.
@interface SRPWaterWallCandidate : NSObject
@property (nonatomic, copy) NSString *name;
@property (nonatomic, copy, nullable) NSString *nodesJSON;
@property (nonatomic, copy) NSString *remoteAddress;
@property (nonatomic, copy, nullable) NSString *endpointIP;
@property (nonatomic, copy, nullable) NSArray<NSString *> *endpointIPs;
@property (nonatomic, copy) NSString *tunnelAddress;
@property (nonatomic, copy) NSString *probeAddress;
@property (nonatomic, copy) NSString *dnsProbeAddress;
@property (nonatomic) BOOL probeTCP;
@property (nonatomic) BOOL probeUDP;
@property (nonatomic, copy) NSArray<NSString *> *dnsServers;
@property (nonatomic, copy, nullable) NSString *allowedIPs;
// Reaches the server over UDP (KCP or QUIC datagrams) instead of a TCP connection.
@property (nonatomic) BOOL udpCarrier;
@end

// Counters of WaterWall's connections to the server (TCP, KCP and QUIC): the counts
// are cumulative, the maxima cover what was sampled since the previous reading.
typedef struct SRPWaterWallLinkTotals {
    uint64_t sentPackets;
    uint64_t retransmittedPackets;
    uint64_t receivedBytes;
    uint64_t timedOutConnections;
    uint32_t maxRTTMilliseconds;
    uint32_t maxRTOMilliseconds;
} SRPWaterWallLinkTotals;

// Rates WaterWall's connections to the server from counters read at a fixed interval.
@interface SRPWaterWallLinkQuality : NSObject
// Seconds between two readings, used for the wording of reasons and summaries.
@property (nonatomic) NSTimeInterval interval;
// The growth since the previous reading becomes one sample; the first reading is the baseline.
- (void)addTotals:(SRPWaterWallLinkTotals)totals;
// Starts a new observation; the next reading becomes the baseline again.
- (void)clearSamples;
// Why the recent samples count as lossy, or nil.
@property (nonatomic, readonly, nullable) NSString *lossReason;
// Traffic of the most recent samples for the diagnostic log, or nil when there was none.
- (nullable NSString *)summaryOfLastSamples:(NSUInteger)count;
@end

@interface SRPWaterWallClient : NSObject

@property (nonatomic, copy) NSString *coreJSON;
@property (nonatomic, copy) NSString *nodesJSON;
@property (nonatomic, copy) NSString *remoteAddress;
@property (nonatomic, copy, nullable) NSString *endpointIP;
@property (nonatomic, copy, nullable) NSArray<NSString *> *endpointIPs;
@property (nonatomic, copy) NSString *tunnelAddress;
@property (nonatomic, copy) NSString *probeAddress;
@property (nonatomic, copy) NSString *dnsProbeAddress;
@property (nonatomic) BOOL probeTCP;
@property (nonatomic) BOOL probeUDP;
@property (nonatomic, copy) NSArray<NSString *> *dnsServers;
@property (nonatomic, copy, nullable) NSString *allowedIPs;
@property (nonatomic, copy) NSString *profileName;
@property (nonatomic) BOOL udpCarrier;
// Other profiles of the same server. A failed connection reconnects with the next one
// (with Auto Reconnect); heavy loss moves to one with a different carrier. Empty keeps
// the selected profile, which a network change always restores.
@property (nonatomic, copy) NSArray<SRPWaterWallCandidate *> *fallbacks;
// Seconds between link quality readings; 5 by default.
@property (nonatomic) NSTimeInterval qualityInterval;
@property (nonatomic) NSUInteger mtu;
@property (nonatomic) NSInteger logLevel;
@property (nonatomic) BOOL liveDiagnostics;
@property (nonatomic) BOOL autoReconnect;
@property (nonatomic) NSInteger retryTimes;
@property (nonatomic) BOOL switchToWifi;
@property (nonatomic) NSInteger onSleep;

// The counters of the process's connections to the server; reading restarts the two maxima.
+ (SRPWaterWallLinkTotals)currentLinkTotals;
- (nullable NSString *)resolvedAddressForHost:(NSString *)value;
// Copies the profile's node graph and tunnel settings; call it before starting.
- (void)applyCandidate:(SRPWaterWallCandidate *)candidate;
- (void)startWithOutputCallback:(SRPWaterWallOutputCallback)output
         networkSettingsCallback:(SRPWaterWallNetworkSettingsCallback)settings
               connectedCallback:(nullable SRPWaterWallConnectedCallback)connected
                 failureCallback:(SRPWaterWallFailureBlock)failure;
// Provider batches are injected FIFO; each completion resumes its packetFlow read.
- (void)injectPackets:(NSArray<NSData *> *)packets completion:(nullable dispatch_block_t)completion;
- (void)close;
- (void)closeAndWait;
- (void)pauseForSleep;
- (void)wakeFromSleep;

@end

NS_ASSUME_NONNULL_END
