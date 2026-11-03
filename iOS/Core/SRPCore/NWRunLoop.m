
#import "NWRunLoop.h"
#import <Network/Network.h>
#include "common/utils.h"

#define NWCAT_BONJOUR_SERVICE_TCP_TYPE "_nwcat._tcp"
#define NWCAT_BONJOUR_SERVICE_UDP_TYPE "_nwcat._udp"
#define NWCAT_BONJOUR_SERVICE_DOMAIN "local"

static NSString *__geoip__ = nil;

static void x_ppp_print_function(const char *buf) {
    NSLog(@"[Y] SS => %s", buf);
}

@implementation NWRunLoop
+(instancetype)currentRunLoop {
    static NWRunLoop *__core__ = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        __core__ = [[self alloc] init];
        [__core__ configure];
    });
    return __core__;
}

+(void)setup:(NSString *)geoip {
    __geoip__ = geoip;
}

-(void)setup:(SSProtocol *)protocol {
    _protocol = protocol;
    x_set_print_func(x_ppp_print_function);
}

-(BOOL)lookup:(char *)ip_address {
    return NO;
}

-(void)configure {

}
@end
