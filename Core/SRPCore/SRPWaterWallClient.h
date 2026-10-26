#import <Foundation/Foundation.h>

@class NEPacketTunnelNetworkSettings;

NS_ASSUME_NONNULL_BEGIN

typedef void(^SRPWaterWallOutputCallback)(NSData *ipPacket, int family);
typedef void(^SRPWaterWallNetworkSettingsCallback)(NEPacketTunnelNetworkSettings *setting);
typedef void(^SRPWaterWallConnectedCallback)(void);
typedef void(^SRPWaterWallFailureBlock)(NSString *reason);

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
@property (nonatomic) NSUInteger mtu;
@property (nonatomic) NSInteger logLevel;

- (void)startWithOutputCallback:(SRPWaterWallOutputCallback)output
         networkSettingsCallback:(SRPWaterWallNetworkSettingsCallback)settings
               connectedCallback:(nullable SRPWaterWallConnectedCallback)connected
                 failureCallback:(SRPWaterWallFailureBlock)failure;
- (void)injectPacket:(NSData *)packet family:(int)family;
- (void)close;
- (void)closeAndWait;
- (void)pauseForSleep;
- (void)wakeFromSleep;

@end

NS_ASSUME_NONNULL_END
