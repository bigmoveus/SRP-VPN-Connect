// Prints the WaterWall profile the app holds for each scenario: the iPhone app's own conversion of a former form
// configuration into its node chain (SRPWaterWallNodeChain documentForConfiguration:…), for waterwall_scenarios.py.
// Input on stdin: a JSON list of {configuration, server, port, sni, verify, secret, outer, options}; output: the list of
// documents, null where the app converts nothing (WireGuard mode, or settings the form could not connect).
#import <Foundation/Foundation.h>
#import "SRPWaterWallChainConfig.h"

static id nullToNil(id value) { return value == NSNull.null ? nil : value; }

int main(void) {
    @autoreleasepool {
        NSData *input = [[NSFileHandle fileHandleWithStandardInput] readDataToEndOfFile];
        NSArray *items = [NSJSONSerialization JSONObjectWithData:input options:0 error:nil];
        NSMutableArray *out = [NSMutableArray new];
        for (NSDictionary *item in items) {
            NSDictionary *document = [SRPWaterWallNodeChain documentForConfiguration:item[@"configuration"]
                                                                              server:nullToNil(item[@"server"]) ?: @""
                                                                                port:[item[@"port"] integerValue]
                                                                                 sni:nullToNil(item[@"sni"])
                                                                           verifyTLS:[item[@"verify"] boolValue]
                                                                              secret:nullToNil(item[@"secret"])
                                                                         outerSecret:nullToNil(item[@"outer"])
                                                                             options:nullToNil(item[@"options"]) ?: @{}];
            [out addObject:document ?: NSNull.null];
        }
        NSData *json = [NSJSONSerialization dataWithJSONObject:out options:NSJSONWritingSortedKeys | NSJSONWritingWithoutEscapingSlashes error:nil];
        [[NSFileHandle fileHandleWithStandardOutput] writeData:json];
    }
    return 0;
}
