#import <Foundation/Foundation.h>

@class NodeModel;

NS_ASSUME_NONNULL_BEGIN

typedef void (^SRPProfileLatencyUpdate)(NSString *nodeID, NSString *text);

@interface SRPProfileLatencyTester : NSObject

+ (NSArray<NSURL *> *)endpointURLs;
+ (NSString *)textForMilliseconds:(NSTimeInterval)milliseconds;
+ (NSString *)textForFailure:(nullable NSError *)error;
+ (BOOL)isSuccessfulResponse:(nullable NSURLResponse *)response error:(nullable NSError *)error;

- (void)measureProfile:(NodeModel *)profile
                update:(SRPProfileLatencyUpdate)update
              finished:(nullable dispatch_block_t)finished;
- (void)cancel;

@end

NS_ASSUME_NONNULL_END
