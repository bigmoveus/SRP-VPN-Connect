
#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN


@interface TCPPinger : NSObject

/// Probe a node
/// - Parameters:
///   - node: node hostname or IP
///   - port: port to probe
///   - count: probe count
- (int)ping:(NSString *)node port:(int)port count:(int)count;

/// Whether the string is a valid IP
/// - Parameter ipStr: IP string
+ (BOOL)isValidIP:(NSString *)ipStr;


+ (NSString *)LookupIP:(NSString *)domain;

@end

NS_ASSUME_NONNULL_END
