//
//  PDParserSoftEther.m
//  SRPParser
//
//  Parses softether:// share URIs into profile dictionaries.
//  Format: softether://base64(user:pass)@host:port?hub=DEFAULT&auth=password|plain|cert|anonymous&conns=1&udp_accel=0&natt=0#remark
//

#import "PDParserSoftEther.h"
#import "PDBase64.h"

@implementation PDParserSoftEther

+ (void)setLogLevel:(NSString *)level {}

+ (nullable NSDictionary *)parse:(NSString *)uri {
    NSURL *url = [NSURL URLWithString:[NSString stringWithFormat:@"softether://%@", uri]];
    if (url.host.length == 0) {
        return nil;
    }
    NSString *remark = [uri componentsSeparatedByString:@"#"].count >= 2
        ? [uri componentsSeparatedByString:@"#"].lastObject : @"softether";

    NSString *username = url.user;
    NSString *password = url.password;
    if (password == nil && username != nil) {
        NSArray *up = [[PDBase64 decode:username] componentsSeparatedByString:@":"];
        if (up.count >= 1) {
            username = up[0];
            password = up.count >= 2 ? up[1] : @"";
        }
    }

    NSMutableDictionary *body = @{
        @"xx": @"softether",
        @"address": url.host,
        @"port": url.port ?: @443,
        @"username": username ?: @"",
        @"password": password ?: @"",
        @"remark": remark,
    }.mutableCopy;

    NSURLComponents *components = [NSURLComponents componentsWithURL:url resolvingAgainstBaseURL:NO];
    for (NSURLQueryItem *item in components.queryItems) {
        static NSSet *known = nil;
        static dispatch_once_t onceToken;
        dispatch_once(&onceToken, ^{
            known = [NSSet setWithArray:@[@"hub", @"auth", @"conns", @"udp_accel",
                                          @"natt", @"natt_hint", @"sni", @"allowInsecure"]];
        });
        if ([known containsObject:item.name]) {
            body[item.name] = item.value ?: @"";
        }
    }
    return body;
}

@end
