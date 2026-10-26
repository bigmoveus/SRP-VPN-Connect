
#import <Foundation/Foundation.h>



@class SSProtocol;
@class NEPacketTunnelNetworkSettings;

typedef void(^lwSetupNetworkSettingsCallback)(NEPacketTunnelNetworkSettings *setting);

typedef void(^lwIPOutputCallback)(NSData *ipPackets, int family);

typedef void(^lwFailureCallback)(NSString *reason);

@interface lwIP : NSObject

+(instancetype)shared;

/// The global worker queue
@property (nonatomic, readonly, strong)dispatch_queue_t worker;

/// Set the GEOIP database path
/// - Parameter geoip: database path
+(void)setup:(NSString *)geoip;

/// Set the proxy server configuration
/// - Parameter protcol: configuration
-(void)setup:(SSProtocol *)protcol;

/// Inject an IP packet
/// - Parameters:
///   - packet: IP Packet
///   - family: AF_INET, AF_INET6
-(void)WriteIPPacket:(NSData *)packet family:(int)family;

/// Set the packet output callback
/// - Parameter callback: IP packet callback
-(void)SetlwIPOutputCallback:(lwIPOutputCallback)callback;

/// Set the packet output callback
/// - Parameter callback: network settings callback
-(void)SetlwSetupNetworkSettingsCallback:(lwSetupNetworkSettingsCallback)callback;

/// Failure callback (fired when the tunnel drops before it is established)
/// - Parameter callback: failure callback
-(void)SetlwFailureCallback:(lwFailureCallback)callback;

/// Whether the current call is running on the worker queue
-(BOOL)InQueue;

/// Whether the current call is running on the worker queue
+(BOOL)InQueue;


-(BOOL)close;

/// On Sleep option: call from NEPacketTunnelProvider sleepWithCompletionHandler.
/// pause mode closes the SSTP client until wakeFromSleep; off drops the
/// connection (wake reconnects only when Auto Reconnect is on).
-(void)pauseForSleep;

/// On Sleep option: call from the provider's wake handler.
-(void)wakeFromSleep;

@end
