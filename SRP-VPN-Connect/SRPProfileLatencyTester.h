#import <Foundation/Foundation.h>

@class NodeModel;
#if TARGET_OS_IPHONE
@class UIColor;
#endif

NS_ASSUME_NONNULL_BEGIN

/// milliseconds is NSNotFound while a test runs and -1 when it failed.
typedef void (^SRPProfileLatencyUpdate)(NSString *nodeID, NSString *text, NSInteger milliseconds);

@interface SRPProfileLatencyTester : NSObject

+ (NSArray<NSURL *> *)endpointURLs;
+ (NSString *)textForMilliseconds:(NSTimeInterval)milliseconds;
+ (NSString *)textForFailure:(nullable NSError *)error;
+ (BOOL)isSuccessfulResponse:(nullable NSURLResponse *)response error:(nullable NSError *)error;
#if TARGET_OS_IPHONE
/// Green below 200 ms, orange below 500 ms, red from 500 ms and for failures.
+ (UIColor *)colorForMilliseconds:(NSInteger)milliseconds;
#endif

- (void)measureProfile:(NodeModel *)profile
                update:(SRPProfileLatencyUpdate)update
              finished:(nullable dispatch_block_t)finished;
- (void)cancel;

@end

/// milliseconds is -1 when the server did not accept the connection in time.
typedef void (^SRPProfileTCPPingResult)(NSString *nodeID, NSInteger milliseconds, BOOL timedOut);
typedef void (^SRPProfileTCPPingProgress)(NSUInteger completed, NSUInteger total);

/// Times the TCP handshake to each profile's server; while the VPN is up it binds to the
/// physical interface, so results stay comparable. It shows that the server port is
/// reachable, not that the profile's protocol, credentials or TLS work.
@interface SRPProfileTCPPinger : NSObject

/// The TCP server of a profile, or nil when it has none (UDP transports, WARP, server entries).
+ (nullable NSString *)endpointHostForProfile:(NodeModel *)profile port:(nullable uint16_t *)port;
+ (NSString *)textForMilliseconds:(NSInteger)milliseconds timedOut:(BOOL)timedOut;

/// Cancels the previous run, then pings the profiles a few at a time; every block runs on the main queue.
- (void)pingProfiles:(NSArray<NodeModel *> *)profiles
              result:(SRPProfileTCPPingResult)result
            progress:(nullable SRPProfileTCPPingProgress)progress
            finished:(nullable dispatch_block_t)finished;
- (void)cancel;

@end

NS_ASSUME_NONNULL_END
