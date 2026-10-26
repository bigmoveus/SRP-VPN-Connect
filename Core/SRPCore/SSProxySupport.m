//
//  SSProxySupport.m
//  SRPCore
//

#import "SSProxySupport.h"

@implementation SSProxyHop
@end

@implementation SSProxySupport

+ (NSArray<SSProxyHop *> *)hopsFromPACResultString:(NSString *)result {
    NSMutableArray<SSProxyHop *> *hops = [NSMutableArray new];
    for (NSString *entry in [result componentsSeparatedByString:@";"]) {
        NSString *trimmed = [entry stringByTrimmingCharactersInSet:
            NSCharacterSet.whitespaceAndNewlineCharacterSet];
        if (trimmed.length == 0) {
            continue;
        }
        NSArray<NSString *> *parts = [trimmed componentsSeparatedByCharactersInSet:
            NSCharacterSet.whitespaceCharacterSet];
        NSMutableArray<NSString *> *tokens = [NSMutableArray new];
        for (NSString *p in parts) {
            if (p.length > 0) [tokens addObject:p];
        }
        if (tokens.count == 0) {
            continue;
        }
        NSString *keyword = tokens[0].uppercaseString;
        SSProxyHop *hop = [SSProxyHop new];
        if ([keyword isEqualToString:@"DIRECT"]) {
            hop.type = SSProxyHopTypeDirect;
        } else if (([keyword isEqualToString:@"PROXY"] ||
                    [keyword isEqualToString:@"SOCKS"] ||
                    [keyword isEqualToString:@"SOCKS5"]) && tokens.count >= 2) {
            hop.type = [keyword isEqualToString:@"PROXY"]
                ? SSProxyHopTypeHTTPConnect : SSProxyHopTypeSOCKS5;
            NSString *hp = tokens[1];
            NSRange colon = [hp rangeOfString:@":" options:NSBackwardsSearch];
            if (colon.location == NSNotFound || colon.location == 0) {
                continue;
            }
            hop.host = [hp substringToIndex:colon.location];
            hop.port = [[hp substringFromIndex:colon.location + 1] integerValue];
            if (hop.port <= 0 || hop.port > 65535) {
                continue;
            }
        } else {
            continue;   // unknown PAC keyword — skip
        }
        [hops addObject:hop];
    }
    return hops;
}

#pragma mark - SOCKS5 wire format

+ (NSData *)socks5GreetingWithCredentials:(BOOL)hasCredentials {
    uint8_t g[] = {0x05, 0x01, 0x00};
    uint8_t gAuth[] = {0x05, 0x02, 0x00, 0x02};
    return hasCredentials ? [NSData dataWithBytes:gAuth length:sizeof(gAuth)]
                          : [NSData dataWithBytes:g length:sizeof(g)];
}

+ (NSData *)socks5AuthWithUsername:(NSString *)username password:(NSString *)password {
    NSData *u = [username dataUsingEncoding:NSUTF8StringEncoding];
    NSData *p = [password dataUsingEncoding:NSUTF8StringEncoding];
    NSMutableData *pkt = [NSMutableData new];
    uint8_t ver = 0x01, ulen = (uint8_t)MIN(u.length, 255), plen = (uint8_t)MIN(p.length, 255);
    [pkt appendBytes:&ver length:1];
    [pkt appendBytes:&ulen length:1];
    [pkt appendBytes:u.bytes length:ulen];
    [pkt appendBytes:&plen length:1];
    [pkt appendBytes:p.bytes length:plen];
    return pkt;
}

+ (NSData *)socks5ConnectRequestToHost:(NSString *)host port:(NSInteger)port {
    NSData *h = [host dataUsingEncoding:NSUTF8StringEncoding];
    NSMutableData *pkt = [NSMutableData new];
    uint8_t head[] = {0x05, 0x01, 0x00, 0x03};  // ver, CONNECT, rsv, domain
    [pkt appendBytes:head length:sizeof(head)];
    uint8_t hlen = (uint8_t)MIN(h.length, 255);
    [pkt appendBytes:&hlen length:1];
    [pkt appendBytes:h.bytes length:hlen];
    uint8_t p[] = {(uint8_t)(port >> 8), (uint8_t)port};
    [pkt appendBytes:p length:2];
    return pkt;
}

+ (int)socks5MethodFromReply:(NSData *)reply {
    const uint8_t *b = reply.bytes;
    if (reply.length < 2 || b[0] != 0x05) {
        return -1;
    }
    return b[1];
}

+ (BOOL)socks5AuthSucceeded:(NSData *)reply {
    const uint8_t *b = reply.bytes;
    return reply.length >= 2 && b[1] == 0x00;
}

+ (int)socks5ConnectResult:(NSData *)reply {
    const uint8_t *b = reply.bytes;
    if (reply.length < 2 || b[0] != 0x05) {
        return -1;
    }
    return reply.length >= 4 ? b[1] : -1;
}

#pragma mark - HTTP CONNECT wire format

+ (NSData *)httpConnectRequestToHost:(NSString *)host port:(NSInteger)port
                            username:(NSString *)username
                            password:(NSString *)password {
    NSMutableString *req = [NSMutableString stringWithFormat:
        @"CONNECT %@:%ld HTTP/1.1\r\nHost: %@:%ld\r\nProxy-Connection: Keep-Alive\r\n",
        host, (long)port, host, (long)port];
    if (username.length > 0) {
        NSString *pair = [NSString stringWithFormat:@"%@:%@", username, password ?: @""];
        NSString *b64 = [[pair dataUsingEncoding:NSUTF8StringEncoding] base64EncodedStringWithOptions:0];
        [req appendFormat:@"Proxy-Authorization: Basic %@\r\n", b64];
    }
    [req appendString:@"\r\n"];
    return [req dataUsingEncoding:NSUTF8StringEncoding];
}

+ (int)httpConnectStatusFromResponse:(NSData *)response {
    NSString *head = [[NSString alloc] initWithData:response encoding:NSUTF8StringEncoding];
    if (![head hasPrefix:@"HTTP/"]) {
        return -1;
    }
    NSRange sp = [head rangeOfString:@" "];
    if (sp.location == NSNotFound) {
        return -1;
    }
    NSInteger status = [head substringFromIndex:sp.location + 1].integerValue;
    return status > 0 ? (int)status : -1;
}

@end
