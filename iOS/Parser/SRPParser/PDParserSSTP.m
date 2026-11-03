
#import "PDParserSSTP.h"

@implementation PDParserSSTP
+(void)setLogLevel:(NSString *)level {}
+(nullable NSDictionary *)parse:(NSString *)uri {
    NSURL *url = [NSURL URLWithString:[NSString stringWithFormat:@"sstp://%@", uri]];
    NSString *remark = [uri componentsSeparatedByString:@"#"].count >= 2 ? [uri componentsSeparatedByString:@"#"].lastObject : @"sstp";
    NSMutableDictionary *body = @{@"username":url.user, @"password":url.password, @"port":url.port, @"xx":@"sstp", @"address":url.host, @"remark":remark}.mutableCopy;
    NSURLComponents *components = [NSURLComponents componentsWithURL:url resolvingAgainstBaseURL:NO];
    NSArray <NSURLQueryItem *>*queryItems = components.queryItems;
    if (queryItems.count > 0) {
        [queryItems enumerateObjectsUsingBlock:^(NSURLQueryItem * _Nonnull obj, NSUInteger idx, BOOL * _Nonnull stop) {
            if ([obj.name isEqualToString:@"sni"]) {
                body[obj.name] = obj.value ? obj.value : @"";
            }
        }];
    }
    return body;
}
@end
