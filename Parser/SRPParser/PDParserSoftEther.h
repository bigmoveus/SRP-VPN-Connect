//
//  PDParserSoftEther.h
//  SRPParser
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface PDParserSoftEther : NSObject
+ (void)setLogLevel:(NSString *)level;
+ (nullable NSDictionary *)parse:(NSString *)uri;
@end

NS_ASSUME_NONNULL_END
