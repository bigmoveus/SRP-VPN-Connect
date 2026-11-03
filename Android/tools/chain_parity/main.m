// Runs iOS's chain builder over the corpus from generate.py and records what it answers.
#import <Foundation/Foundation.h>
#import "SRPWaterWallChainConfig.h"

static id orNull(id value) { return value ?: NSNull.null; }

static id parsed(NSString *json) {
    if (json == nil) return NSNull.null;
    return [NSJSONSerialization JSONObjectWithData:[json dataUsingEncoding:NSUTF8StringEncoding] options:0 error:nil] ?: NSNull.null;
}

static id nullToNil(id value) { return value == NSNull.null ? nil : value; }

static NSDictionary *runChain(NSDictionary *item) {
    NSMutableDictionary *out = [NSMutableDictionary new];
    id configuration = item[@"configuration"];
    if (![configuration isKindOfClass:NSDictionary.class]) return @{@"skipped": @YES};
    NSString *error = [SRPWaterWallChainConfig validationErrorForConfiguration:configuration];
    out[@"error"] = orNull(error);
    if (error == nil) {
        out[@"json"] = parsed([SRPWaterWallChainConfig JSONWithConfiguration:configuration]);
        out[@"summary"] = [SRPWaterWallChainConfig summaryForConfiguration:configuration];
        out[@"flags"] = @[@([SRPWaterWallChainConfig isWireGuardConfiguration:configuration]),
                          @([SRPWaterWallChainConfig isDirectConfiguration:configuration]),
                          @([SRPWaterWallChainConfig configurationNeedsApplicationSecret:configuration]),
                          @([SRPWaterWallChainConfig configurationNeedsOuterSecret:configuration]),
                          @([SRPWaterWallChainConfig configurationUsesTLS:configuration]),
                          @([SRPWaterWallChainConfig configurationAllowsFragmentation:configuration]),
                          @([SRPWaterWallChainConfig configurationAllowsRouting:configuration]),
                          @([SRPWaterWallChainConfig configurationUsesUDPCarrier:configuration])];
    }
    NSString *secret = nullToNil(item[@"secret"]);
    NSString *outerSecret = nullToNil(item[@"outerSecret"]);
    NSDictionary *options = nullToNil(item[@"options"]);
    out[@"secretError"] = orNull([SRPWaterWallChainConfig validationErrorForApplicationSecret:secret forConfiguration:configuration]);
    out[@"usernameError"] = orNull([SRPWaterWallChainConfig validationErrorForApplicationUsername:options[@"username"] secret:secret forConfiguration:configuration]);
    out[@"outerError"] = orNull([SRPWaterWallChainConfig validationErrorForOuterSecret:outerSecret forConfiguration:configuration]);
    out[@"nodes"] = parsed([SRPWaterWallChainConfig nodesJSONForConfiguration:configuration
                                                                       server:nullToNil(item[@"server"])
                                                                         port:[item[@"port"] integerValue]
                                                                          sni:nullToNil(item[@"sni"])
                                                                    verifyTLS:[item[@"verifyTLS"] boolValue]
                                                                       secret:secret
                                                                  outerSecret:outerSecret
                                                                      options:options]);
    return out;
}

static NSDictionary *wireGuardResult(NSDictionary *result) {
    if (result == nil) return @{@"result": NSNull.null};
    return @{@"result": @{@"nodes": parsed(result[@"nodesJSON"]), @"tunnelAddress": orNull(result[@"tunnelAddress"]),
                          @"allowedIPs": orNull(result[@"allowedIPs"]), @"dnsServers": orNull(result[@"dnsServers"]),
                          @"endpointIP": orNull(result[@"endpointIP"]), @"endpointIPs": orNull(result[@"endpointIPs"])}};
}

int main(int argc, const char *argv[]) {
    @autoreleasepool {
        NSData *input = [NSData dataWithContentsOfFile:@(argv[1])];
        NSArray *cases = [NSJSONSerialization JSONObjectWithData:input options:0 error:nil];
        NSMutableArray *results = [NSMutableArray arrayWithCapacity:cases.count];
        for (NSDictionary *item in cases) {
            NSMutableDictionary *entry = [item mutableCopy];
            @try {
                if ([item[@"kind"] isEqualToString:@"wg-conf"]) {
                    [entry addEntriesFromDictionary:wireGuardResult([SRPWaterWallChainConfig wireGuardConfigurationWithConfig:item[@"config"]])];
                } else if ([item[@"kind"] isEqualToString:@"wg-keys"]) {
                    [entry addEntriesFromDictionary:wireGuardResult([SRPWaterWallChainConfig wireGuardConfigurationWithPrivateKey:item[@"privateKey"]
                                                                                                                  serverPublicKey:item[@"serverPublicKey"]
                                                                                                                           server:item[@"server"]
                                                                                                                             port:[item[@"port"] integerValue]
                                                                                                                     clientAddress:item[@"clientAddress"]
                                                                                                                         keepalive:[item[@"keepalive"] integerValue]])];
                } else {
                    [entry addEntriesFromDictionary:runChain(item)];
                }
            } @catch (NSException *exception) {
                entry[@"exception"] = exception.reason ?: @"exception";
            }
            [results addObject:entry];
        }
        NSData *output = [NSJSONSerialization dataWithJSONObject:results options:NSJSONWritingSortedKeys error:nil];
        [output writeToFile:@(argv[2]) atomically:YES];
    }
    return 0;
}
