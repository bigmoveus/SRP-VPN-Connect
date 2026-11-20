// Runs iOS's chain builder over the corpus from generate.py and records what it answers.
#import <Foundation/Foundation.h>
#import "SRPWaterWallChainConfig.h"

static id orNull(id value) { return value ?: NSNull.null; }

static id parsed(NSString *json) {
    if (json == nil) return NSNull.null;
    return [NSJSONSerialization JSONObjectWithData:[json dataUsingEncoding:NSUTF8StringEncoding] options:0 error:nil] ?: NSNull.null;
}

static id nullToNil(id value) { return value == NSNull.null ? nil : value; }

// One answer of the node editor can raise where another does not, so each is caught alone and marked.
static id attempt(id (^block)(void)) {
    @try {
        return orNull(block());
    } @catch (NSException *exception) {
        return @{@"__exception__": exception.reason ?: @"exception"};
    }
}

static NSDictionary *runNodeChain(NSDictionary *item) {
    id document = item[@"document"];
    NSMutableDictionary *out = [NSMutableDictionary new];
    out[@"error"] = attempt(^id { return [SRPWaterWallNodeChain validationErrorForDocument:document]; });
    if ([document isKindOfClass:NSDictionary.class]) {
        out[@"chain"] = attempt(^id { return [SRPWaterWallNodeChain chainOfDocument:document]; });
        out[@"hint"] = attempt(^id { return [SRPWaterWallNodeChain hintOfDocument:document]; });
        out[@"summary"] = attempt(^id { return [SRPWaterWallNodeChain summaryOfDocument:document]; });
        out[@"endpoints"] = attempt(^id { return [SRPWaterWallNodeChain endpointsOfDocument:document]; });
        out[@"flags"] = attempt(^id {
            return @[@([SRPWaterWallNodeChain documentUsesGeoIP:document]), @([SRPWaterWallNodeChain documentUsesUDPCarrier:document])];
        });
    }
    return out;
}

static NSDictionary *runNodeJSON(NSDictionary *item) {
    NSString *problem = nil;
    NSDictionary *document = [SRPWaterWallNodeChain documentWithJSON:nullToNil(item[@"json"]) error:&problem];
    return @{@"parsed": orNull(document), @"error": orNull(problem)};
}

static NSDictionary *runNodeEdit(NSDictionary *item) {
    NSDictionary *document = item[@"document"];
    NSString *operation = item[@"operation"];
    NSDictionary *result = [operation isEqualToString:@"replace"] ?
        [SRPWaterWallNodeChain document:document replacingNodeNamed:item[@"name"] withNode:item[@"node"]] :
        [operation isEqualToString:@"insert"] ? [SRPWaterWallNodeChain document:document insertingNode:item[@"node"] afterNodeNamed:item[@"name"]] :
        [SRPWaterWallNodeChain document:document deletingNodeNamed:item[@"name"]];
    return @{@"result": result, @"resultError": orNull([SRPWaterWallNodeChain validationErrorForDocument:result])};
}

static NSDictionary *runNodeRuntime(NSDictionary *item) {
    NSString *problem = nil;
    NSDictionary *runtime = [SRPWaterWallNodeChain runtimeDocumentForDocument:item[@"document"]
                                                                        input:item[@"input"]
                                                                      fakeDNS:[item[@"fakeDNS"] boolValue]
                                                            geoIPDatabasePath:nullToNil(item[@"geoIPDatabasePath"])
                                                                    addresses:nullToNil(item[@"addresses"])
                                                                        error:&problem];
    return @{@"runtime": orNull(runtime), @"runtimeError": orNull(problem)};
}

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
    // The node chain the conversion of a profile made with the former WaterWall form gives
    out[@"legacyDocument"] = attempt(^id {
        return [SRPWaterWallNodeChain documentForConfiguration:configuration
                                                        server:nullToNil(item[@"server"])
                                                          port:[item[@"port"] integerValue]
                                                           sni:nullToNil(item[@"sni"])
                                                     verifyTLS:[item[@"verifyTLS"] boolValue]
                                                        secret:secret
                                                   outerSecret:outerSecret
                                                       options:options];
    });
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
                } else if ([item[@"kind"] isEqualToString:@"node-chain"]) {
                    [entry addEntriesFromDictionary:runNodeChain(item)];
                } else if ([item[@"kind"] isEqualToString:@"node-json"]) {
                    [entry addEntriesFromDictionary:runNodeJSON(item)];
                } else if ([item[@"kind"] isEqualToString:@"node-edit"]) {
                    [entry addEntriesFromDictionary:runNodeEdit(item)];
                } else if ([item[@"kind"] isEqualToString:@"node-runtime"]) {
                    [entry addEntriesFromDictionary:runNodeRuntime(item)];
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
