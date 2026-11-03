
#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface PDParserSSTP : NSObject
+(nullable NSDictionary *)parse:(NSString *)uri;

+(void)setLogLevel:(NSString *)level;
@end

NS_ASSUME_NONNULL_END
