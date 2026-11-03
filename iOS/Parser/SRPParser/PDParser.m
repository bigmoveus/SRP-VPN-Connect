
#import "PDParser.h"
#import "PDParserSSTP.h"
#import "PDParserSoftEther.h"

static uint16_t __http_proxy_port__ = 1082;
static uint16_t __socks_proxy_port__ = 1083;
static NSMutableArray *__directDomainList__ = nil;
static NSMutableArray *__proxyDomainList__ = nil;
static NSMutableArray *__blockDomainList__ = nil;

static NSMutableArray *__directIPList__ = nil;
static NSMutableArray *__proxyIPList__ = nil;
static NSMutableArray *__blockIPList__ = nil;

static bool __global_geosite_enable__ = false;
static bool __global_geoip_enable__ = false;

@implementation PDParser

+(void)setHttpProxyPort:(uint16_t)port {
    __http_proxy_port__ = port;
}

+(uint16_t)HttpProxyPort {
    return __http_proxy_port__;
}

+(uint16_t)SocksProxyPort {
    return __socks_proxy_port__;
}

+(void)setLogLevel:(NSString *)level {
    [PDParserSSTP setLogLevel:level];
}

+ (void)setGlobalProxyEnable:(BOOL)enable {
    __global_geosite_enable__ = !enable;
    __global_geoip_enable__ = !enable;
}

+ (void)setDirectDomainList:(NSArray *)list {
    __directDomainList__ = list.mutableCopy;
}

+ (void)setProxyDomainList:(NSArray *)list {
    __proxyDomainList__ = list.mutableCopy;
}

+ (void)setBlockDomainList:(NSArray *)list {
    __blockDomainList__ = list.mutableCopy;
}

+ (void)setDirectIPList:(NSArray *)list {
    __directIPList__ = [list mutableCopy];
}

+ (void)setProxyIPList:(NSArray *)list {
    __proxyIPList__ = [list mutableCopy];
}

+ (void)setBlockIPList:(NSArray *)list {
    __blockIPList__ = [list mutableCopy];
}

+ (NSDictionary *)parseURI:(NSString *)uri {
    NSArray <NSString *>*list = [uri componentsSeparatedByString:@"//"];
    if (list.count != 2) {
        list = [uri componentsSeparatedByString:@":"];
        if (list.count != 2) {
            return nil;
        }
    }
    if ([list[0] hasPrefix:@"sstp"]) {
        return [PDParserSSTP parse:list[1]];
    }
    if ([list[0] hasPrefix:@"softether"]) {
        return [PDParserSoftEther parse:list[1]];
    }
    return nil;
}

+(NSDictionary *)GetHttpInbound {
    NSDictionary *inbound = @{
        @"listen" : @"127.0.0.1",
        @"protocol" : @"http",
        @"settings" : @{
            @"timeout" : @60
        },
        @"tag" : @"httpinbound",
        @"port" : @(__http_proxy_port__)
    };
    return inbound;
}

+(NSArray *)GetRules {

    NSString *tag = @"proxy";
    NSMutableArray *rules = @[].mutableCopy;

    if (__proxyDomainList__.count > 0) {
        NSDictionary *A = @{
            @"type": @"field",
            @"domain": __proxyDomainList__,
            @"outboundTag": tag
        };
        [rules addObject:A];
    }

    if (__blockDomainList__.count > 0) {
        NSDictionary *A = @{
            @"type": @"field",
            @"domain": __blockDomainList__,
            @"outboundTag": @"block"
        };
        [rules addObject:A];
    }

    if (__directDomainList__.count > 0) {
        NSDictionary *A = @{
            @"type": @"field",
            @"domain": __directDomainList__,
            @"outboundTag": @"direct"
        };
        [rules addObject:A];
    }

    if (__proxyIPList__.count > 0) {
        NSDictionary *A = @{
            @"type": @"field",
            @"ip": __proxyIPList__,
            @"outboundTag": tag
        };
        [rules addObject:A];
    }

    if (__blockIPList__.count > 0) {
        NSDictionary *A = @{
            @"type": @"field",
            @"ip": __blockIPList__,
            @"outboundTag": @"block"
        };
        [rules addObject:A];
    }

    if (__directIPList__.count > 0) {
        NSDictionary *A = @{
            @"type": @"field",
            @"ip": __directIPList__,
            @"outboundTag": @"direct"
        };
        [rules addObject:A];
    }

    if (__global_geosite_enable__) {
        NSDictionary *A = @{
            @"type": @"field",
            @"domain": @[@"geosite:category-ads-all"],
            @"outboundTag": @"block"
        };
        NSDictionary *B = @{
            @"type": @"field",
            @"domain": @[@"geosite:cn"],
            @"outboundTag": @"direct"
        };
        [rules addObject:A];
        [rules addObject:B];
    }

    if (__global_geoip_enable__) {
        NSDictionary *A = @{
            @"type": @"field",
            @"ip": @[@"geoip:private", @"geoip:cn"],
            @"outboundTag": @"direct"
        };
        [rules addObject:A];
    }

    if (__global_geoip_enable__ || __global_geosite_enable__) {
        NSDictionary *C = @{
            @"type": @"field",
            @"domain": @[@"geosite:geolocation-!cn"],
            @"outboundTag": tag
        };
        [rules addObject:C];
    }

    if (!__global_geoip_enable__ && !__global_geosite_enable__) {
        NSDictionary *all = @{
            @"type":@"field",
            @"outboundTag":tag,
            @"port":@"0-65535"
        };
        [rules addObject:all];
    }
    return rules;
}

+(NSDictionary *)GetStatsPolicy {
    NSDictionary *policy = @{
        @"system": @{
            @"statsOutboundUplink": [NSNumber numberWithBool:true],
            @"statsOutboundDownlink": [NSNumber numberWithBool:true]
        }
    };
    return policy;
}

+ (NSDictionary *)GetShareableProxy {
    NSDictionary *base = @{
        @"remark": @"Y Proxy",
        @"log": @{
            @"loglevel": @"info"
        },
        @"inbounds": @[
            @{
                @"settings": @{
                    @"userLevel": @8
                },
                @"protocol": @"http",
                @"port": @1084,
                @"tag": @"http",
                @"listen": @"0.0.0.0"
            },
            @{
                @"settings": @{
                    @"udp": [NSNumber numberWithBool:true],
                    @"auth": @"noauth"
                },
                @"protocol": @"socks",
                @"port": @1085,
                @"sniffing": @{
                  @"enabled": [NSNumber numberWithBool:true],
                  @"destOverride": @[
                      @"http",
                      @"tls"
                  ]
                },
                @"tag": @"socks",
                @"listen": @"0.0.0.0"
            }
        ],
        @"outbounds":@[
            @{
                @"protocol": @"freedom",
                @"tag": @"direct"
            }
        ]
    };
    return base;
}

@end
