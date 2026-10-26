
#import <Foundation/Foundation.h>
#import <SRPCore/SSProtocol.h>

NS_ASSUME_NONNULL_BEGIN

@interface NWRunLoop : NSObject
+(instancetype)currentRunLoop;

/// The worker queue everything runs on; may be provided externally
@property (nonatomic, strong)dispatch_queue_t worker;

/// Active protocol configuration
@property (nonatomic, strong, readonly)SSProtocol *protocol;

/// Set the GEOIP database path
/// - Parameter geoip: database path
+(void)setup:(nullable NSString *)geoip;

/// Set the active server protocol
/// - Parameter protocol: protocol configuration
-(void)setup:(SSProtocol *)protocol;

/// Check whether an IP belongs to China
/// - Parameter ip: IP address
-(BOOL)lookup:(char *)ip;

@end

NS_ASSUME_NONNULL_END
