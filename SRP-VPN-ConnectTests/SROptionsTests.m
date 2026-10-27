//
//  SROptionsTests.m
//  SRP-VPN-ConnectTests / SRP-VPN-ConnectTestsMac
//
//  OPTIONS section: model defaults, serialization round-trip, migration,
//  and the pure path-switch / retry decision helpers.
//

#import <XCTest/XCTest.h>
#import "NodeModel.h"
#import "CheckConnectData.h"
#import "SSNetOptions.h"
#import "SRPWaterWallChainConfig.h"
#import "SRPGeoIPDatabase.h"
#import "SRPProfileLatencyTester.h"

@interface SRPGeoIPTestStore : SRPGeoIPDatabase
@property (nonatomic, strong) NSURL *fixtureURL;
@end

@implementation SRPGeoIPTestStore
- (NSURL *)bundledDatabaseURL {
    return _fixtureURL;
}
@end

#import <TargetConditionals.h>
#if TARGET_OS_IPHONE
#import "HomeProtocolView.h"
#import "SRPGeoIPCountryViewController.h"
#import "SRPAetherClient.h"
#import <SRPParser/SRPParser.h>
#import <fcntl.h>
#import <sys/socket.h>
#import <unistd.h>

static UILabel *SRPLatencyLabel(UIView *view, NSString *text) {
    if ([view isKindOfClass:UILabel.class] && [((UILabel *)view).text isEqualToString:text]) {
        return (UILabel *)view;
    }
    for (UIView *subview in view.subviews) {
        UILabel *result = SRPLatencyLabel(subview, text);
        if (result) return result;
    }
    return nil;
}
#endif

@interface SROptionsTests : XCTestCase
@end

@implementation SROptionsTests

- (void)testOptionDefaults {
    NodeModel *m = [NodeModel new];
    XCTAssertFalse(m.disableLegacyOuterTls);
    XCTAssertTrue(m.autoReconnect);
    XCTAssertEqual(m.retryTimes, 0);
    XCTAssertTrue(m.switchToWifi);
    XCTAssertEqual(m.onSleep, 2);    // stay
    XCTAssertEqual(m.logLevel, 0);   // normal
}

- (void)testOptionsRoundTrip {
    NodeModel *m = [NodeModel new];
    m.server = @"vpn.example.com";
    m.disableLegacyOuterTls = YES;
    m.autoReconnect = NO;
    m.retryTimes = 3;
    m.switchToWifi = NO;
    m.onSleep = 1;    // pause
    m.logLevel = 2;   // debug

    NSDictionary *d = [CheckConnectData checkConnectParmer:m];
    XCTAssertEqualObjects(d[@"disable_legacy_outer_tls"], @1);
    XCTAssertEqualObjects(d[@"auto_reconnect"], @0);
    XCTAssertEqualObjects(d[@"retry_times"], @3);
    XCTAssertEqualObjects(d[@"switch_to_wifi"], @0);
    XCTAssertEqualObjects(d[@"on_sleep"], @"pause");
    XCTAssertEqualObjects(d[@"log_level"], @"debug");

    NodeModel *r = [CheckConnectData getModalForDic:d];
    XCTAssertTrue(r.disableLegacyOuterTls);
    XCTAssertFalse(r.autoReconnect);
    XCTAssertEqual(r.retryTimes, 3);
    XCTAssertFalse(r.switchToWifi);
    XCTAssertEqual(r.onSleep, 1);
    XCTAssertEqual(r.logLevel, 2);
}

- (void)testOptionsMigrationDefaults {
    // Legacy stored profile without any OPTIONS keys gets fresh defaults
    NSDictionary *legacy = @{
        @"type": @"sstp",
        @"username": @"u",
        @"address": @"vpn.example.com",
        @"port": @"443",
    };
    NodeModel *m = [CheckConnectData getModalForDic:legacy];
    XCTAssertFalse(m.disableLegacyOuterTls);
    XCTAssertTrue(m.autoReconnect);
    XCTAssertEqual(m.retryTimes, 0);
    XCTAssertTrue(m.switchToWifi);
    XCTAssertEqual(m.onSleep, 2);
    XCTAssertEqual(m.logLevel, 0);
}

- (void)testOnSleepAndLogLevelEncodings {
    NodeModel *m = [NodeModel new];
    NSDictionary *d;
    m.onSleep = 0;
    d = [CheckConnectData checkConnectParmer:m];
    XCTAssertEqualObjects(d[@"on_sleep"], @"off");
    m.onSleep = 2;
    d = [CheckConnectData checkConnectParmer:m];
    XCTAssertEqualObjects(d[@"on_sleep"], @"stay");
    m.logLevel = 1;
    d = [CheckConnectData checkConnectParmer:m];
    XCTAssertEqualObjects(d[@"log_level"], @"expert");
}

#pragma mark - decision helpers

- (void)testPathSwitchDecision {
    // Wi-Fi appears while the tunnel is up -> reconnect
    XCTAssertTrue(SSShouldReconnectForPathChange(NO, YES, YES, YES));
    // already on Wi-Fi -> nothing
    XCTAssertFalse(SSShouldReconnectForPathChange(YES, YES, YES, YES));
    // Wi-Fi lost -> no forced reconnect (the socket dies by itself)
    XCTAssertFalse(SSShouldReconnectForPathChange(YES, NO, YES, YES));
    // tunnel not up -> nothing
    XCTAssertFalse(SSShouldReconnectForPathChange(NO, YES, YES, NO));
    // new path unusable -> nothing
    XCTAssertFalse(SSShouldReconnectForPathChange(NO, YES, NO, YES));
}

- (void)testRetryBudget {
    XCTAssertTrue(SSReconnectAttemptAllowed(0, 2));
    XCTAssertTrue(SSReconnectAttemptAllowed(1, 2));
    XCTAssertFalse(SSReconnectAttemptAllowed(2, 2));
    // 0 = unlimited
    XCTAssertTrue(SSReconnectAttemptAllowed(100, 0));
}

#pragma mark - Custom SNI

- (void)testCustomSniDefaults {
    NodeModel *m = [NodeModel new];
    XCTAssertFalse(m.customSniEnabled);
    XCTAssertNil(m.customSni);
    NSDictionary *d = [CheckConnectData checkConnectParmer:m];
    XCTAssertEqualObjects(d[@"custom_sni_enabled"], @0);
    XCTAssertNil(d[@"sni"]);
}

- (void)testCustomSniValidation {
    // valid bare hostnames
    XCTAssertTrue([NodeModel isValidCustomSni:@"vpn.example.com"]);
    XCTAssertTrue([NodeModel isValidCustomSni:@"edge.example.net"]);
    XCTAssertTrue([NodeModel isValidCustomSni:@"gateway.company.tld"]);
    // invalid: scheme, port, path, spaces, empty
    XCTAssertFalse([NodeModel isValidCustomSni:@"https://vpn.example.com"]);
    XCTAssertFalse([NodeModel isValidCustomSni:@"vpn.example.com:443"]);
    XCTAssertFalse([NodeModel isValidCustomSni:@"vpn.example.com/sstp"]);
    XCTAssertFalse([NodeModel isValidCustomSni:@"vpn example.com"]);
    XCTAssertFalse([NodeModel isValidCustomSni:@""]);
    XCTAssertFalse([NodeModel isValidCustomSni:nil]);
}

- (void)testCustomSniRoundTrip {
    NodeModel *m = [NodeModel new];
    m.server = @"203.0.113.10";
    m.customSniEnabled = YES;
    m.customSni = @"vpn.example.com";

    NSDictionary *d = [CheckConnectData checkConnectParmer:m];
    XCTAssertEqualObjects(d[@"custom_sni_enabled"], @1);
    XCTAssertEqualObjects(d[@"sni"], @"vpn.example.com");
    // the TCP destination is untouched by the SNI
    XCTAssertEqualObjects(d[@"address"], @"203.0.113.10");

    NodeModel *r = [CheckConnectData getModalForDic:d];
    XCTAssertTrue(r.customSniEnabled);
    XCTAssertEqualObjects(r.customSni, @"vpn.example.com");
}

- (void)testCustomSniMigration {
    // legacy profile without the keys: disabled, no SNI
    NSDictionary *legacy = @{
        @"type": @"sstp",
        @"username": @"u",
        @"address": @"vpn.example.com",
        @"port": @"443",
    };
    NodeModel *m = [CheckConnectData getModalForDic:legacy];
    XCTAssertFalse(m.customSniEnabled);
    XCTAssertNil(m.customSni);
}

- (NSDictionary *)waterWallConfigurationWithInput:(NSString *)input
                                      application:(NSString *)application
                                              mux:(BOOL)mux
                                            outer:(NSString *)outer
                                      nodeOptions:(NSDictionary *)nodeOptions {
    return @{@"version": @3, @"mode": @"chain", @"input": input, @"application": application,
             @"mux": @(mux), @"outer": outer, @"http": @"off", @"http-version": @1,
             @"obfuscator": @NO, @"carrier": @"tcp", @"quic-carrier": @"datagram", @"node-options": nodeOptions};
}

- (NSDictionary *)waterWallConfigurationWithApplication:(NSString *)application
                                                    mux:(BOOL)mux
                                                  outer:(NSString *)outer {
    return [self waterWallConfigurationWithInput:@"connections" application:application mux:mux outer:outer nodeOptions:@{}];
}

- (NSArray *)waterWallLegacyCases {
    NSArray *definitions = @[
        @[@"direct", @"direct", @"", @"", @NO, @""],
        @[@"vless-tls", @"chain", @"connections", @"vless", @NO, @"tls"],
        @[@"trojan-tls", @"chain", @"connections", @"trojan", @NO, @"tls"],
        @[@"vless-mux-tls", @"chain", @"connections", @"vless", @YES, @"tls"],
        @[@"trojan-mux-tls", @"chain", @"connections", @"trojan", @YES, @"tls"],
        @[@"vless-reality", @"chain", @"connections", @"vless", @NO, @"reality"],
        @[@"trojan-reality", @"chain", @"connections", @"trojan", @NO, @"reality"],
        @[@"vless-mux-reality", @"chain", @"connections", @"vless", @YES, @"reality"],
        @[@"trojan-mux-reality", @"chain", @"connections", @"trojan", @YES, @"reality"],
        @[@"vless-aead", @"chain", @"connections", @"vless", @NO, @"aead"],
        @[@"vless-mux-aead", @"chain", @"connections", @"vless", @YES, @"aead"],
        @[@"trojan-aead", @"chain", @"connections", @"trojan", @NO, @"aead"],
        @[@"trojan-mux-aead", @"chain", @"connections", @"trojan", @YES, @"aead"],
        @[@"rawip-tls", @"chain", @"raw-ipv4", @"", @NO, @"tls"],
        @[@"rawip-reality", @"chain", @"raw-ipv4", @"", @NO, @"reality"],
        @[@"rawip-aead", @"chain", @"raw-ipv4", @"", @NO, @"aead"],
        @[@"vless-quic", @"chain", @"connections", @"vless", @NO, @"quic"],
        @[@"trojan-quic", @"chain", @"connections", @"trojan", @NO, @"quic"],
        @[@"rawip-quic", @"chain", @"raw-ipv4", @"", @NO, @"quic"],
        @[@"wireguard", @"wireguard", @"", @"", @NO, @""],
    ];
    NSMutableArray *cases = [NSMutableArray new];
    for (NSArray *definition in definitions) {
        NSString *mode = definition[1];
        NSDictionary *configuration;
        if (![mode isEqualToString:@"chain"]) {
            configuration = @{@"version": @3, @"mode": mode, @"node-options": @{}};
        } else {
            configuration = [self waterWallConfigurationWithInput:definition[2]
                                                      application:definition[3]
                                                              mux:[definition[4] boolValue]
                                                            outer:definition[5]
                                                      nodeOptions:@{}];
        }
        [cases addObject:@{@"name": definition[0], @"configuration": configuration}];
    }
    return cases;
}

- (NSDictionary *)waterWallJSONObject:(NSString *)json {
    XCTAssertNotNil(json);
    if (json == nil) return nil;
    return [NSJSONSerialization JSONObjectWithData:[json dataUsingEncoding:NSUTF8StringEncoding] options:0 error:nil];
}

- (NSDictionary *)waterWallRootForConfiguration:(NSDictionary *)configuration options:(NSDictionary *)options {
    NSString *secret = [configuration[@"application"] isEqualToString:@"vless"] ?
        @"00112233-4455-6677-8899-aabbccddeeff" : @"app-secret";
    NSString *json = [SRPWaterWallChainConfig nodesJSONForConfiguration:configuration
                                                                server:@"waterwall.example.com"
                                                                  port:18443
                                                                   sni:@"edge.example.com"
                                                             verifyTLS:YES
                                                                secret:secret
                                                           outerSecret:@"outer-secret"
                                                               options:options];
    return [self waterWallJSONObject:json];
}

- (NSDictionary *)waterWallNodesByName:(NSArray *)nodes {
    NSMutableDictionary *byName = [NSMutableDictionary new];
    for (NSDictionary *node in nodes) byName[node[@"name"]] = node;
    return byName;
}

- (void)testWaterWallProfileRoundTrip {
    NodeModel *m = [NodeModel new];
    m.protocolType = @"waterwall";
    m.server = @"waterwall.example.com";
    NSDictionary *configuration = [self waterWallConfigurationWithApplication:@"vless" mux:YES outer:@"reality"];
    m.waterwallConfigJSON = [SRPWaterWallChainConfig JSONWithConfiguration:configuration];
    m.password = @"00112233-4455-6677-8899-aabbccddeeff";
    m.passwordKey = @"canonical-password-key";
    m.waterwallSecretRef = @"legacy-reference-not-used";
    m.waterwallOuterSecret = @"outer-secret";
    m.waterwallOuterSecretRef = @"outer-reference-only";
    m.waterwallProbeIP = @"1.1.1.1";
    m.waterwallDNSProbeIP = @"192.0.2.1";
    m.waterwallFakeDNS = YES;
    m.waterwallSmartRouting = YES;

    NSDictionary *d = [CheckConnectData checkConnectParmer:m];
    XCTAssertEqualObjects(d[@"ww_config"], m.waterwallConfigJSON);
    XCTAssertFalse([d.allKeys containsObject:@"ww_preset"]);
    XCTAssertEqualObjects([SRPWaterWallChainConfig configurationWithJSON:d[@"ww_config"]], configuration);
    XCTAssertEqualObjects(d[@"ww_secret_ref"], m.passwordKey);
    XCTAssertEqualObjects(d[@"ww_outer_secret_ref"], m.waterwallOuterSecretRef);
    XCTAssertNil(d[@"ww_outer_secret"]);
    NodeModel *r = [CheckConnectData getModalForDic:d];
    XCTAssertEqualObjects(r.nodeName, @"WaterWall VPN");
    XCTAssertEqualObjects([SRPWaterWallChainConfig configurationWithJSON:r.waterwallConfigJSON], configuration);
    XCTAssertEqualObjects(r.passwordKey, m.passwordKey);
    XCTAssertEqualObjects(r.waterwallOuterSecret, m.waterwallOuterSecret);
    XCTAssertEqualObjects(r.waterwallOuterSecretRef, m.waterwallOuterSecretRef);
    XCTAssertEqualObjects(r.waterwallProbeIP, m.waterwallProbeIP);
    XCTAssertEqualObjects(r.waterwallDNSProbeIP, m.waterwallDNSProbeIP);
    XCTAssertTrue(r.waterwallFakeDNS);
    XCTAssertTrue(r.waterwallSmartRouting);
}

- (void)testWaterWallMigrationDefaultsAndLegacyConfigurations {
    NodeModel *empty = [CheckConnectData getModalForDic:@{@"type": @"waterwall"}];
    XCTAssertNotNil(empty);
    XCTAssertTrue(empty.waterwallFakeDNS);
    XCTAssertNil(empty.waterwallSecretRef);
    XCTAssertEqualObjects([SRPWaterWallChainConfig configurationWithJSON:empty.waterwallConfigJSON],
                          [SRPWaterWallChainConfig defaultConfiguration]);

    for (NSDictionary *testCase in [self waterWallLegacyCases]) {
        NSString *name = testCase[@"name"];
        NSDictionary *expected = testCase[@"configuration"];
        NSDictionary *migrated = [SRPWaterWallChainConfig configurationFromLegacyPreset:name];
        XCTAssertEqualObjects(migrated, expected, @"%@", name);
        XCTAssertEqualObjects(migrated[@"version"], @3, @"%@", name);
        NodeModel *stored = [CheckConnectData getModalForDic:@{@"type": @"waterwall", @"ww_preset": name}];
        XCTAssertEqualObjects([SRPWaterWallChainConfig configurationWithJSON:stored.waterwallConfigJSON], expected, @"%@", name);
    }
}

- (void)testWaterWallChainJSONForMigratedConfigurations {
    NSDictionary *outerTypes = @{@"tls": @"TlsClient", @"reality": @"RealityClient",
                                 @"aead": @"EncryptionClient", @"quic": @"QuicClient"};
    for (NSDictionary *testCase in [self waterWallLegacyCases]) {
        NSString *name = testCase[@"name"];
        NSDictionary *configuration = [SRPWaterWallChainConfig configurationFromLegacyPreset:name];
        if ([SRPWaterWallChainConfig isWireGuardConfiguration:configuration]) {
            XCTAssertNil([SRPWaterWallChainConfig nodesJSONForConfiguration:configuration server:@"waterwall.example.com"
                                                                       port:51820 sni:nil verifyTLS:YES secret:nil outerSecret:nil options:nil]);
            continue;
        }
        NSDictionary *root = [self waterWallRootForConfiguration:configuration options:nil];
        NSArray *nodes = root[@"nodes"];
        NSDictionary *byName = [self waterWallNodesByName:nodes];
        XCTAssertEqualObjects(nodes.firstObject[@"type"], @"NEPacketDevice", @"%@", name);
        if ([SRPWaterWallChainConfig isDirectConfiguration:configuration]) {
            XCTAssertEqual(nodes.count, 3, @"%@", name);
            XCTAssertEqualObjects(nodes.firstObject[@"next"], @"ptc");
            XCTAssertEqualObjects(byName[@"ptc"][@"type"], @"PacketsToConnection");
            XCTAssertEqualObjects(byName[@"ptc"][@"next"], @"connector");
            XCTAssertEqualObjects(nodes.lastObject[@"type"], @"TcpUdpConnector");
            XCTAssertEqualObjects(nodes.lastObject[@"settings"][@"address"], @"dest_context->address");
            continue;
        }

        BOOL raw = [configuration[@"input"] isEqualToString:@"raw-ipv4"];
        BOOL mux = [configuration[@"mux"] boolValue];
        NSString *application = configuration[@"application"];
        NSString *outer = configuration[@"outer"];
        BOOL quic = [outer isEqualToString:@"quic"];
        if (raw) {
            XCTAssertNil(byName[@"ptc"], @"%@", name);
            XCTAssertEqualObjects(nodes.firstObject[@"next"], @"pts", @"%@", name);
            XCTAssertEqualObjects(byName[@"pts"][@"type"], @"PacketsToStream", @"%@", name);
            XCTAssertEqualObjects(byName[@"pts"][@"next"], outer, @"%@", name);
        } else {
            XCTAssertEqualObjects(byName[@"ptc"][@"type"], @"PacketsToConnection", @"%@", name);
            XCTAssertEqualObjects(byName[@"ptc"][@"next"], @"router", @"%@", name);
            NSDictionary *applicationNode = byName[application];
            XCTAssertEqualObjects(applicationNode[@"type"], [application isEqualToString:@"vless"] ? @"VlessClient" : @"TrojanClient", @"%@", name);
            XCTAssertEqualObjects(applicationNode[@"next"], mux ? @"mux" : outer, @"%@", name);
            NSString *credentialKey = [application isEqualToString:@"vless"] ? @"uuid" : @"password";
            NSString *expectedSecret = [application isEqualToString:@"vless"] ?
                @"00112233-4455-6677-8899-aabbccddeeff" : @"app-secret";
            XCTAssertEqualObjects(applicationNode[@"settings"][credentialKey], expectedSecret, @"%@", name);
            XCTAssertNotEqualObjects(applicationNode[@"settings"][credentialKey], @"outer-secret", @"%@", name);
        }
        if (mux) {
            XCTAssertEqualObjects(byName[@"mux"][@"type"], @"MuxClient", @"%@", name);
            XCTAssertEqualObjects(byName[@"mux"][@"next"], outer, @"%@", name);
            XCTAssertEqualObjects(byName[@"mux"][@"settings"][@"parent-write-buffer-limit"], @16777216, @"%@", name);
            XCTAssertEqualObjects(byName[@"mux"][@"settings"][@"child-buffer-limit"], @4194304, @"%@", name);
        } else {
            XCTAssertNil(byName[@"mux"], @"%@", name);
        }
        NSDictionary *outerNode = byName[outer];
        XCTAssertEqualObjects(outerNode[@"type"], outerTypes[outer], @"%@", name);
        if ([SRPWaterWallChainConfig configurationNeedsOuterSecret:configuration]) {
            XCTAssertEqualObjects(outerNode[@"settings"][@"password"], @"outer-secret", @"%@", name);
            XCTAssertNotEqualObjects(outerNode[@"settings"][@"password"], @"app-secret", @"%@", name);
        }
        if (quic) XCTAssertEqualObjects(outerNode[@"settings"][@"carrier-mode"], @"datagram", @"%@", name);

        BOOL dynamicTCPUDP = !raw && !mux && [outer isEqualToString:@"tls"];
        XCTAssertEqualObjects(nodes.lastObject[@"type"], quic ? @"UdpConnector" : dynamicTCPUDP ? @"TcpUdpConnector" : @"TcpConnector", @"%@", name);
        XCTAssertEqualObjects(nodes.lastObject[@"settings"][@"address"], @"waterwall.example.com", @"%@", name);
        XCTAssertEqualObjects(nodes.lastObject[@"settings"][@"port"], @18443, @"%@", name);
        XCTAssertNil(nodes.lastObject[@"settings"][@"protocol"], @"%@", name);
    }
}

- (void)testWaterWallGeneralJSONRoundTripAndSummaries {
    NSArray *configurations = @[
        [self waterWallConfigurationWithApplication:@"vless" mux:NO outer:@"tls"],
        [self waterWallConfigurationWithApplication:@"trojan" mux:YES outer:@"reality"],
        [self waterWallConfigurationWithInput:@"raw-ipv4" application:@"" mux:NO outer:@"aead" nodeOptions:@{}],
        [self waterWallConfigurationWithApplication:@"vless" mux:NO outer:@"quic"],
    ];
    NSArray *summaries = @[@"VLESS + TLS", @"Trojan + MUX + REALITY", @"Raw IPv4 + AEAD", @"VLESS + QUIC"];
    [configurations enumerateObjectsUsingBlock:^(NSDictionary *configuration, NSUInteger index, BOOL *stop) {
        NSString *json = [SRPWaterWallChainConfig JSONWithConfiguration:configuration];
        XCTAssertNotNil(json);
        XCTAssertEqualObjects([SRPWaterWallChainConfig configurationWithJSON:json], configuration);
        XCTAssertEqualObjects([SRPWaterWallChainConfig summaryForConfiguration:configuration], summaries[index]);
    }];
    XCTAssertEqualObjects([SRPWaterWallChainConfig summaryForConfiguration:@{@"mode": @"direct"}], @"Direct (diagnostics)");
    XCTAssertEqualObjects([SRPWaterWallChainConfig summaryForConfiguration:@{@"mode": @"wireguard"}], @"WireGuard");
}

- (void)testWaterWallRejectsMalformedAndIncompatibleConfigurations {
    NSMutableDictionary *unknownAdvanced = [[self waterWallConfigurationWithApplication:@"vless" mux:NO outer:@"tls"] mutableCopy];
    unknownAdvanced[@"node-options"] = @{@"outer": @{@"unknown-setting": @1}};
    NSArray *invalid = @[
        [self waterWallConfigurationWithApplication:@"vless" mux:YES outer:@"quic"],
        [self waterWallConfigurationWithInput:@"raw-ipv4" application:@"vless" mux:NO outer:@"tls" nodeOptions:@{}],
        [self waterWallConfigurationWithInput:@"raw-ipv4" application:@"" mux:YES outer:@"tls" nodeOptions:@{}],
        unknownAdvanced,
        (@{@"version": @1, @"mode": @"direct", @"node-options": @{}}),
    ];
    for (NSDictionary *configuration in invalid) {
        XCTAssertNotNil([SRPWaterWallChainConfig validationErrorForConfiguration:configuration]);
        XCTAssertNil([SRPWaterWallChainConfig JSONWithConfiguration:configuration]);
        NSString *json = [[NSString alloc] initWithData:[NSJSONSerialization dataWithJSONObject:configuration options:0 error:nil]
                                               encoding:NSUTF8StringEncoding];
        XCTAssertNil([SRPWaterWallChainConfig configurationWithJSON:json]);
    }
    XCTAssertNil([SRPWaterWallChainConfig configurationWithJSON:@"not-json"]);
}

- (void)testWaterWallRejectsInvalidEndpointsAndMissingSecrets {
    NSDictionary *vless = [self waterWallConfigurationWithApplication:@"vless" mux:NO outer:@"tls"];
    NSDictionary *reality = [self waterWallConfigurationWithApplication:@"trojan" mux:NO outer:@"reality"];
    XCTAssertNil([SRPWaterWallChainConfig nodesJSONForConfiguration:vless server:@"host" port:0 sni:nil verifyTLS:YES secret:@"id" outerSecret:nil options:nil]);
    XCTAssertNil([SRPWaterWallChainConfig nodesJSONForConfiguration:vless server:@"host" port:65536 sni:nil verifyTLS:YES secret:@"id" outerSecret:nil options:nil]);
    XCTAssertNil([SRPWaterWallChainConfig nodesJSONForConfiguration:vless server:@"host" port:443 sni:nil verifyTLS:YES secret:nil outerSecret:nil options:nil]);
    XCTAssertNil([SRPWaterWallChainConfig nodesJSONForConfiguration:reality server:@"host" port:443 sni:nil verifyTLS:YES secret:@"id" outerSecret:nil options:nil]);
    XCTAssertNil([SRPWaterWallChainConfig nodesJSONForConfiguration:vless server:@"" port:443 sni:nil verifyTLS:YES secret:@"id" outerSecret:nil options:nil]);
}

- (void)testWaterWallAdvancedNodeOptionsAndRequiredFields {
    NSDictionary *nodeOptions = @{
        @"packet": @{@"udp-idle-timeout-ms": @30000, @"mtu": @1500, @"max-pending-bytes": @2048},
        @"application": @{@"first-payload-timeout-ms": @1500, @"protocol": @"tcp"},
        @"mux": @{@"parent-write-buffer-resume-threshold": @2, @"parent-write-buffer-pause-threshold": @3,
                  @"parent-write-buffer-limit": @4, @"child-buffer-limit": @1000},
        @"outer": @{@"kdf-iterations": @24000, @"x25519mlkem768": @YES},
    };
    NSDictionary *configuration = [self waterWallConfigurationWithInput:@"connections" application:@"vless"
                                                                    mux:YES outer:@"reality" nodeOptions:nodeOptions];
    XCTAssertNil([SRPWaterWallChainConfig validationErrorForConfiguration:configuration]);
    NSDictionary *root = [self waterWallRootForConfiguration:configuration options:nil];
    NSDictionary *byName = [self waterWallNodesByName:root[@"nodes"]];
    NSDictionary *packet = byName[@"ptc"][@"settings"];
    XCTAssertEqualObjects(packet[@"udp-idle-timeout-ms"], @30000);
    XCTAssertEqualObjects(packet[@"mtu"], @1500);
    XCTAssertEqualObjects(packet[@"max-pending-bytes"], @2048);
    NSDictionary *application = byName[@"vless"][@"settings"];
    XCTAssertEqualObjects(application[@"first-payload-timeout-ms"], @1500);
    XCTAssertEqualObjects(application[@"protocol"], @"tcp");
    XCTAssertEqualObjects(application[@"address"], @"dest_context->address");
    XCTAssertEqualObjects(application[@"port"], @"dest_context->port");
    XCTAssertEqualObjects(application[@"uuid"], @"00112233-4455-6677-8899-aabbccddeeff");
    NSDictionary *mux = byName[@"mux"][@"settings"];
    XCTAssertEqualObjects(mux[@"parent-write-buffer-resume-threshold"], @2);
    XCTAssertEqualObjects(mux[@"parent-write-buffer-pause-threshold"], @3);
    XCTAssertEqualObjects(mux[@"parent-write-buffer-limit"], @4);
    XCTAssertEqualObjects(mux[@"child-buffer-limit"], @1000);
    XCTAssertEqualObjects(mux[@"max-children"], @256);
    NSDictionary *outer = byName[@"reality"][@"settings"];
    XCTAssertEqualObjects(outer[@"kdf-iterations"], @24000);
    XCTAssertEqualObjects(outer[@"x25519mlkem768"], @YES);
    XCTAssertEqualObjects(outer[@"password"], @"outer-secret");
    XCTAssertEqualObjects(outer[@"sni"], @"edge.example.com");
    XCTAssertEqualObjects(outer[@"verify"], @YES);

    NSDictionary *tls = [self waterWallConfigurationWithInput:@"connections" application:@"trojan" mux:NO outer:@"tls"
                                                  nodeOptions:@{@"outer": @{@"x25519mlkem768": @YES}}];
    NSDictionary *tlsRoot = [self waterWallRootForConfiguration:tls options:nil];
    NSDictionary *tlsByName = [self waterWallNodesByName:tlsRoot[@"nodes"]];
    XCTAssertEqualObjects(tlsByName[@"tls"][@"settings"][@"x25519mlkem768"], @YES);
    XCTAssertEqualObjects(tlsByName[@"trojan"][@"settings"][@"password"], @"app-secret");
    XCTAssertEqualObjects(tlsRoot[@"nodes"][0][@"type"], @"NEPacketDevice");
}

- (void)testWaterWallRejectsInvalidAdvancedRanges {
    NSArray *invalid = @[
        [self waterWallConfigurationWithInput:@"connections" application:@"vless" mux:NO outer:@"tls"
                                  nodeOptions:@{@"packet": @{@"udp-idle-timeout-ms": @0}}],
        [self waterWallConfigurationWithInput:@"connections" application:@"vless" mux:NO outer:@"tls"
                                  nodeOptions:@{@"application": @{@"first-payload-timeout-ms": @-1}}],
        [self waterWallConfigurationWithInput:@"connections" application:@"vless" mux:YES outer:@"tls"
                                  nodeOptions:@{@"mux": @{@"parent-write-buffer-resume-threshold": @9,
                                                           @"parent-write-buffer-pause-threshold": @8,
                                                           @"parent-write-buffer-limit": @10}}],
        [self waterWallConfigurationWithInput:@"connections" application:@"vless" mux:NO outer:@"reality"
                                  nodeOptions:@{@"outer": @{@"kdf-iterations": @0}}],
        [self waterWallConfigurationWithInput:@"connections" application:@"vless" mux:NO outer:@"aead"
                                  nodeOptions:@{@"outer": @{@"max-frame-size": @16357}}],
    ];
    for (NSDictionary *configuration in invalid) {
        XCTAssertNotNil([SRPWaterWallChainConfig validationErrorForConfiguration:configuration]);
        XCTAssertNil([SRPWaterWallChainConfig nodesJSONForConfiguration:configuration server:@"host" port:443
                                                                    sni:nil verifyTLS:YES secret:@"app-secret" outerSecret:@"outer-secret" options:nil]);
    }
}

- (void)testWaterWallFragmentationFakeDNSAndRouter {
    NSDictionary *options = @{@"tls_frag": @1, @"ww_fake_dns": @YES, @"ww_smart_routing": @YES};
    NSArray *testCases = @[
        @{@"configuration": [self waterWallConfigurationWithApplication:@"vless" mux:NO outer:@"tls"], @"outer": @"tls", @"cuts": @64},
        @{@"configuration": [self waterWallConfigurationWithApplication:@"trojan" mux:YES outer:@"reality"], @"outer": @"reality", @"cuts": @64},
        @{@"configuration": [self waterWallConfigurationWithApplication:@"vless" mux:NO outer:@"quic"], @"outer": @"quic", @"cuts": @0},
    ];
    for (NSDictionary *testCase in testCases) {
        NSDictionary *configuration = testCase[@"configuration"];
        NSDictionary *root = [self waterWallRootForConfiguration:configuration options:options];
        NSDictionary *byName = [self waterWallNodesByName:root[@"nodes"]];
        XCTAssertNotNil(byName[@"ptc"][@"settings"][@"fake-dns"]);
        XCTAssertEqualObjects(byName[@"ptc"][@"next"], @"router");
        XCTAssertEqualObjects(byName[@"router"][@"next"], configuration[@"application"]);
        XCTAssertEqualObjects(byName[@"router"][@"type"], @"Router");
        XCTAssertNotNil(byName[@"direct-local"]);
        NSArray *cuts = byName[testCase[@"outer"]][@"settings"][@"fragment"][@"cuts"];
        XCTAssertEqual(cuts.count, [testCase[@"cuts"] unsignedIntegerValue]);
        if (cuts.count > 0) {
            XCTAssertEqualObjects(cuts[0][0], @32);
            XCTAssertEqualObjects(cuts[1][0], @288);
        }
    }
}

- (void)testGeoIPConfigurationBuildsDirectIranRuleAndKeepsFakeDNS {
    NSMutableDictionary *configuration = [[SRPWaterWallChainConfig defaultConfiguration] mutableCopy];
    configuration[@"geoip"] = @{@"countries": @[@"IR"], @"update-url": @"https://example.com/GeoLite2-Country.mmdb"};
    XCTAssertNil([SRPWaterWallChainConfig validationErrorForConfiguration:configuration]);
    NSString *roundTrip = [SRPWaterWallChainConfig JSONWithConfiguration:configuration];
    XCTAssertEqualObjects([SRPWaterWallChainConfig configurationWithJSON:roundTrip], configuration);
    NSString *path = @"/tmp/GeoLite2-Country.mmdb";
    NSDictionary *root = [self waterWallRootForConfiguration:configuration options:@{
        @"ww_fake_dns": @YES, @"ww_smart_routing": @YES, @"ww_geoip_db_path": path,
    }];
    NSDictionary *byName = [self waterWallNodesByName:root[@"nodes"]];
    NSDictionary *router = byName[@"router"][@"settings"];
    XCTAssertEqualObjects(byName[@"ptc"][@"next"], @"router");
    XCTAssertNotNil(byName[@"ptc"][@"settings"][@"fake-dns"]);
    XCTAssertEqualObjects(router[@"resolve-domains"], @YES);
    XCTAssertEqualObjects(router[@"geoip-db-path"], path);
    NSArray *rules = router[@"rules"];
    XCTAssertEqual(rules.count, 2u);
    XCTAssertEqualObjects(router[@"rules"][1][@"destination-ip"], @[@"geoip:ir"]);
    XCTAssertEqualObjects(router[@"rules"][1][@"target"], @"direct-local");
    XCTAssertEqualObjects(byName[@"direct-local"][@"type"], @"TcpUdpConnector");
    XCTAssertNil([SRPWaterWallChainConfig nodesJSONForConfiguration:configuration
                                                            server:@"waterwall.example.com"
                                                              port:18443
                                                               sni:@"edge.example.com"
                                                         verifyTLS:YES
                                                            secret:@"00112233-4455-6677-8899-aabbccddeeff"
                                                       outerSecret:@"outer-secret"
                                                           options:@{@"ww_fake_dns": @YES}]);

    root = [self waterWallRootForConfiguration:[SRPWaterWallChainConfig defaultConfiguration] options:nil];
    router = [self waterWallNodesByName:root[@"nodes"]][@"router"][@"settings"];
    XCTAssertNil(router[@"rules"]);
    XCTAssertEqualObjects(router[@"resolve-domains"], @NO);
    configuration[@"mode"] = @"direct";
    XCTAssertNotNil([SRPWaterWallChainConfig validationErrorForConfiguration:configuration]);
    configuration = [[SRPWaterWallChainConfig defaultConfiguration] mutableCopy];
    configuration[@"geoip"] = @{@"update-url": @"http://example.com/GeoLite2-Country.mmdb"};
    XCTAssertNotNil([SRPWaterWallChainConfig validationErrorForConfiguration:configuration]);
}

- (void)testGeoIPMultipleCountriesAndLegacyMigration {
    NSMutableDictionary *configuration = [[SRPWaterWallChainConfig defaultConfiguration] mutableCopy];
    configuration[@"geoip"] = @{@"iran-direct": @YES};
    NSString *legacyJSON = [SRPWaterWallChainConfig JSONWithConfiguration:configuration];
    NSDictionary *migrated = [SRPWaterWallChainConfig configurationWithJSON:legacyJSON];
    XCTAssertEqualObjects(migrated[@"geoip"][@"countries"], (@[@"IR"]));
    XCTAssertNil(migrated[@"geoip"][@"iran-direct"]);

    configuration[@"geoip"] = @{@"countries": @[@"us", @"IR", @"us"]};
    NSDictionary *normalized = [SRPWaterWallChainConfig configurationWithJSON:
        [SRPWaterWallChainConfig JSONWithConfiguration:configuration]];
    XCTAssertEqualObjects(normalized[@"geoip"][@"countries"], (@[@"IR", @"US"]));
    XCTAssertNil([SRPWaterWallChainConfig validationErrorForConfiguration:normalized]);
    NSDictionary *root = [self waterWallRootForConfiguration:normalized options:@{
        @"ww_geoip_db_path": @"/tmp/GeoLite2-Country.mmdb",
    }];
    NSDictionary *byName = [self waterWallNodesByName:root[@"nodes"]];
    NSDictionary *router = byName[@"router"][@"settings"];
    XCTAssertEqualObjects(router[@"resolve-domains"], @YES);
    XCTAssertEqual(CFGetTypeID((__bridge CFTypeRef)router[@"resolve-domains"]), CFBooleanGetTypeID());
    XCTAssertEqual([router[@"rules"] count], 2u);
    XCTAssertEqualObjects(router[@"rules"][0][@"destination-ip"], (@[@"geoip:ir"]));
    XCTAssertEqualObjects(router[@"rules"][1][@"destination-ip"], (@[@"geoip:us"]));
    XCTAssertNotNil(byName[@"ptc"][@"settings"][@"fake-dns"]);

    for (id invalid in @[@"I", @"1A", @[@"IR", @1], @"IR"]) {
        configuration[@"geoip"] = @{@"countries": invalid};
        XCTAssertNotNil([SRPWaterWallChainConfig validationErrorForConfiguration:configuration]);
    }
    configuration[@"geoip"] = @{@"countries": @[]};
    root = [self waterWallRootForConfiguration:configuration options:nil];
    byName = [self waterWallNodesByName:root[@"nodes"]];
    router = byName[@"router"][@"settings"];
    XCTAssertEqualObjects(router[@"resolve-domains"], @NO);
    XCTAssertNil(router[@"rules"]);
    XCTAssertNil(byName[@"direct-local"]);
}

- (void)testGeoIPDatabaseValidationAndAtomicReplacement {
    NSURL *fixture = [NSBundle.mainBundle URLForResource:@"GeoLite2-Country" withExtension:@"mmdb" subdirectory:@"GeoIP"];
    if (fixture == nil) {
        fixture = [NSURL fileURLWithPath:[[NSString stringWithUTF8String:__FILE__].stringByDeletingLastPathComponent
            stringByAppendingPathComponent:@"../SRP-VPN-Connect/GeoIP/GeoLite2-Country.mmdb"]];
    }
    NSString *directory = [NSTemporaryDirectory() stringByAppendingPathComponent:NSUUID.UUID.UUIDString];
    XCTAssertTrue([NSFileManager.defaultManager createDirectoryAtPath:directory withIntermediateDirectories:YES attributes:nil error:nil]);
    SRPGeoIPTestStore *store = [[SRPGeoIPTestStore alloc] initWithDirectory:[NSURL fileURLWithPath:directory isDirectory:YES]];
    store.fixtureURL = fixture;
    NSError *error = nil;
    XCTAssertTrue([store validateDatabaseAtURL:fixture error:&error], @"%@", error);
    XCTAssertTrue([store installBundledDatabaseIfNeeded:&error], @"%@", error);
    XCTAssertEqualObjects(store.currentDatabaseURL, store.databaseURL);
    NSData *original = [NSData dataWithContentsOfURL:store.databaseURL];
    XCTAssertNotNil(original);
    XCTAssertEqualObjects([store databaseInfo][@"source"], @"Updated");
    XCTAssertTrue([[store databaseInfo][@"type"] containsString:@"Country"]);

    NSMutableData *unsupportedData = [original mutableCopy];
    NSData *countryType = [@"GeoLite2-Country" dataUsingEncoding:NSUTF8StringEncoding];
    NSRange typeRange = [unsupportedData rangeOfData:countryType options:0 range:NSMakeRange(0, unsupportedData.length)];
    XCTAssertNotEqual(typeRange.location, NSNotFound);
    if (typeRange.location == NSNotFound) return;
    NSData *unsupportedType = [@"GeoLite2-ASNxxxx" dataUsingEncoding:NSUTF8StringEncoding];
    XCTAssertEqual(unsupportedType.length, countryType.length);
    [unsupportedData replaceBytesInRange:typeRange withBytes:unsupportedType.bytes length:unsupportedType.length];
    NSURL *unsupported = [NSURL fileURLWithPath:[directory stringByAppendingPathComponent:@"unsupported.mmdb"]];
    XCTAssertTrue([unsupportedData writeToURL:unsupported atomically:YES]);
    error = nil;
    XCTAssertFalse([store validateDatabaseAtURL:unsupported error:&error]);
    XCTAssertTrue([error.localizedDescription containsString:@"GeoLite2-ASNxxxx"]);
    XCTAssertTrue([error.localizedDescription containsString:@"Country MMDB"]);

    NSURL *invalid = [NSURL fileURLWithPath:[directory stringByAppendingPathComponent:@"invalid.mmdb"]];
    XCTAssertTrue([@"not a MaxMind database" writeToURL:invalid atomically:YES encoding:NSUTF8StringEncoding error:nil]);
    error = nil;
    XCTAssertFalse([store installDatabaseAtURL:invalid error:&error]);
    XCTAssertNotNil(error);
    XCTAssertEqualObjects([NSData dataWithContentsOfURL:store.databaseURL], original);

    NSURL *oversized = [NSURL fileURLWithPath:[directory stringByAppendingPathComponent:@"oversized.mmdb"]];
    XCTAssertTrue([NSFileManager.defaultManager createFileAtPath:oversized.path contents:nil attributes:nil]);
    NSFileHandle *handle = [NSFileHandle fileHandleForWritingAtPath:oversized.path];
    [handle truncateFileAtOffset:129ULL * 1024ULL * 1024ULL];
    [handle closeFile];
    XCTAssertFalse([store installDatabaseAtURL:oversized error:nil]);
    XCTAssertEqualObjects([NSData dataWithContentsOfURL:store.databaseURL], original);
    [NSFileManager.defaultManager removeItemAtPath:directory error:nil];
}

- (void)testGeoIPRejectsInvalidDownloadLink {
    for (NSString *value in @[@"http://example.com/db.mmdb", @"https://username@example.com/db.mmdb"]) {
        SRPGeoIPDatabase *store = [[SRPGeoIPDatabase alloc] initWithDirectory:[NSURL fileURLWithPath:NSTemporaryDirectory()]];
        XCTestExpectation *expectation = [self expectationWithDescription:@"Reject unsafe GeoIP URL"];
        [store downloadDatabaseFromURLString:value completion:^(NSError *error) {
            XCTAssertEqualObjects(error.domain, SRPGeoIPDatabaseErrorDomain);
            XCTAssertEqual(error.code, SRPGeoIPDatabaseErrorInvalidURL);
            [expectation fulfill];
        }];
        [self waitForExpectations:@[expectation] timeout:2];
    }
}

- (void)testGeoIPDownloadFromConfiguredHTTPS {
    NSString *url = NSProcessInfo.processInfo.environment[@"SRP_GEOIP_TEST_URL"];
    XCTSkipIf(url.length == 0, @"Set SRP_GEOIP_TEST_URL to run the real HTTPS download test.");
    NSString *directory = [NSTemporaryDirectory() stringByAppendingPathComponent:NSUUID.UUID.UUIDString];
    SRPGeoIPDatabase *store = [[SRPGeoIPDatabase alloc] initWithDirectory:[NSURL fileURLWithPath:directory isDirectory:YES]];
    XCTestExpectation *expectation = [self expectationWithDescription:@"Download and validate country MMDB"];
    [store downloadDatabaseFromURLString:url completion:^(NSError *error) {
        XCTAssertNil(error, @"%@", error);
        [expectation fulfill];
    }];
    [self waitForExpectations:@[expectation] timeout:45];
    NSError *error = nil;
    XCTAssertTrue([store validateDatabaseAtURL:store.databaseURL error:&error], @"%@", error);
    [NSFileManager.defaultManager removeItemAtPath:directory error:nil];
}

- (void)testWaterWallLogLevelsAndSeparateAEADOuterSecret {
    for (NSInteger level = 0; level <= 2; level++) {
        NSString *json = [SRPWaterWallChainConfig coreJSONWithLogLevel:level];
        NSDictionary *core = [self waterWallJSONObject:json];
        NSString *expected = level == 2 ? @"DEBUG" : level == 1 ? @"INFO" : @"WARN";
        XCTAssertEqualObjects(core[@"log"][@"network"][@"loglevel"], expected);
    }
    NSDictionary *configuration = [self waterWallConfigurationWithInput:@"connections" application:@"vless" mux:NO outer:@"aead"
                                                            nodeOptions:@{@"outer": @{@"kdf-iterations": @24000, @"max-frame-size": @16000}}];
    NSDictionary *root = [self waterWallRootForConfiguration:configuration options:nil];
    NSDictionary *byName = [self waterWallNodesByName:root[@"nodes"]];
    XCTAssertEqualObjects(byName[@"vless"][@"settings"][@"uuid"], @"00112233-4455-6677-8899-aabbccddeeff");
    XCTAssertEqualObjects(byName[@"aead"][@"settings"][@"password"], @"outer-secret");
    XCTAssertEqualObjects(byName[@"aead"][@"settings"][@"kdf-iterations"], @24000);
    XCTAssertEqualObjects(byName[@"aead"][@"settings"][@"max-frame-size"], @16000);
}

- (void)testWaterWallValidationRejectsWrongJSONTypesWithFieldErrors {
    NSMutableArray<NSDictionary *> *cases = [NSMutableArray arrayWithArray:@[
        @{@"configuration": (@{@"version": @3, @"mode": @1, @"node-options": @{}}), @"field": @"mode"},
        @{@"configuration": [self waterWallConfigurationWithInput:(NSString *)(id)@[] application:@"vless" mux:NO outer:@"tls" nodeOptions:@{}], @"field": @"input"},
        @{@"configuration": [self waterWallConfigurationWithInput:@"connections" application:(NSString *)(id)@{} mux:NO outer:@"tls" nodeOptions:@{}], @"field": @"application"},
        @{@"configuration": [self waterWallConfigurationWithInput:@"connections" application:@"vless" mux:NO outer:(NSString *)(id)NSNull.null nodeOptions:@{}], @"field": @"outer"},
    ]];
    NSArray *layerCases = @[
        @[@"tls", @"mux", @"mode", @1, @"mode"],
        @[@"quic", @"outer", @"protocol", @YES, @"protocol"],
        @[@"quic", @"outer", @"carrier-mode", @[], @"carrier-mode"],
        @[@"tls", @"application", @"protocol", @{}, @"protocol"],
        @[@"tls", @"application", @"proto", @1, @"proto"],
        @[@"tls", @"application", @"domain-strategy", @[], @"domain-strategy"],
        @[@"reality", @"outer", @"algorithm", @YES, @"algorithm"],
        @[@"reality", @"outer", @"method", @{}, @"method"],
        @[@"aead", @"outer", @"salt", @[], @"salt"],
        @[@"tls", @"outer", @"ech-config-list", @1, @"ech-config-list"],
        @[@"tls", @"outer", @"ech-sni-trick", @[], @"ech-sni-trick"],
        @[@"quic", @"outer", @"ca-file", @{}, @"ca-file"],
    ];
    for (NSArray *testCase in layerCases) {
        NSMutableDictionary *configuration = [[self waterWallConfigurationWithApplication:@"vless" mux:YES outer:testCase[0]] mutableCopy];
        if ([testCase[0] isEqualToString:@"quic"]) configuration[@"mux"] = @NO;
        configuration[@"node-options"] = @{testCase[1]: @{testCase[2]: testCase[3]}};
        [cases addObject:@{@"configuration": configuration, @"field": testCase[4]}];
    }
    for (NSDictionary *testCase in cases) {
        NSString *error = [SRPWaterWallChainConfig validationErrorForConfiguration:testCase[@"configuration"]];
        XCTAssertNotNil(error, @"%@", testCase);
        XCTAssertTrue([error.lowercaseString containsString:[testCase[@"field"] lowercaseString]], @"%@", error);
    }
}

- (void)testWaterWallValidatesALPNs {
    NSArray *valid = @[@[], @[@"h2"], @[@"h2", @"http/1.1"]];
    for (NSArray *alpns in valid) {
        NSDictionary *configuration = [self waterWallConfigurationWithInput:@"connections" application:@"vless" mux:NO outer:@"tls"
                                                                  nodeOptions:@{@"outer": @{@"alpns": alpns}}];
        XCTAssertNil([SRPWaterWallChainConfig validationErrorForConfiguration:configuration]);
    }
    NSString *tooLong = [@"" stringByPaddingToLength:128 withString:@"é" startingAtIndex:0];
    NSMutableArray *overBudget = [NSMutableArray new];
    for (NSInteger index = 0; index < 256; index++) {
        NSString *prefix = [NSString stringWithFormat:@"%03ld", (long)index];
        [overBudget addObject:[prefix stringByPaddingToLength:255 withString:@"a" startingAtIndex:0]];
    }
    NSArray *invalid = @[@{}, @[@""], @[@"h2", @"h2"], @[tooLong], overBudget, @[@1]];
    for (id alpns in invalid) {
        NSDictionary *configuration = [self waterWallConfigurationWithInput:@"connections" application:@"vless" mux:NO outer:@"tls"
                                                                  nodeOptions:@{@"outer": @{@"alpns": alpns}}];
        XCTAssertNotNil([SRPWaterWallChainConfig validationErrorForConfiguration:configuration]);
    }
}

- (void)testWaterWallApplicationProtocolsAndFixedGeneration {
    NSArray *protocols = @[@"tcp", @"connect", @"udp", @"udp-associate", @"dest_context->protocol", @"line->dest_ctx->protocol"];
    for (NSString *key in @[@"protocol", @"proto"]) {
        for (NSString *protocol in protocols) {
            NSDictionary *configuration = [self waterWallConfigurationWithInput:@"connections" application:@"trojan" mux:NO outer:@"tls"
                                                                      nodeOptions:@{@"application": @{key: protocol}}];
            XCTAssertNil([SRPWaterWallChainConfig validationErrorForConfiguration:configuration], @"%@=%@", key, protocol);
        }
        for (id protocol in @[@"http", @"", @1]) {
            NSDictionary *configuration = [self waterWallConfigurationWithInput:@"connections" application:@"trojan" mux:NO outer:@"tls"
                                                                      nodeOptions:@{@"application": @{key: protocol}}];
            XCTAssertNotNil([SRPWaterWallChainConfig validationErrorForConfiguration:configuration]);
        }
    }
    NSDictionary *configuration = [self waterWallConfigurationWithInput:@"connections" application:@"trojan" mux:NO outer:@"tls"
                                                              nodeOptions:@{@"application": @{@"protocol": @"udp"}}];
    NSDictionary *byName = [self waterWallNodesByName:[self waterWallRootForConfiguration:configuration options:nil][@"nodes"]];
    XCTAssertEqualObjects(byName[@"trojan"][@"settings"][@"protocol"], @"udp");
    XCTAssertEqualObjects(byName[@"connector"][@"type"], @"TcpConnector");
    XCTAssertNil(byName[@"connector"][@"settings"][@"protocol"]);
    NSDictionary *aliasOnly = [self waterWallConfigurationWithInput:@"connections" application:@"trojan" mux:NO outer:@"tls"
                                                          nodeOptions:@{@"application": @{@"proto": @"udp"}}];
    byName = [self waterWallNodesByName:[self waterWallRootForConfiguration:aliasOnly options:nil][@"nodes"]];
    XCTAssertEqualObjects(byName[@"trojan"][@"settings"][@"protocol"], @"udp");
    XCTAssertEqualObjects(byName[@"connector"][@"type"], @"TcpConnector");
    XCTAssertNil(byName[@"connector"][@"settings"][@"protocol"]);
    NSDictionary *dynamicPrimary = [self waterWallConfigurationWithInput:@"connections" application:@"trojan" mux:NO outer:@"tls"
                                                               nodeOptions:@{@"application": @{@"protocol": @"dest_context->protocol", @"proto": @"udp"}}];
    byName = [self waterWallNodesByName:[self waterWallRootForConfiguration:dynamicPrimary options:nil][@"nodes"]];
    XCTAssertEqualObjects(byName[@"connector"][@"type"], @"TcpUdpConnector");
    XCTAssertNil(byName[@"connector"][@"settings"][@"protocol"]);
}

- (void)testWaterWallCanonicalizesOuterMethodAlias {
    NSDictionary *configuration = [self waterWallConfigurationWithInput:@"connections" application:@"trojan" mux:NO outer:@"reality"
                                                              nodeOptions:@{@"outer": @{@"method": @"aes-256-gcm"}}];
    NSDictionary *byName = [self waterWallNodesByName:[self waterWallRootForConfiguration:configuration options:nil][@"nodes"]];
    XCTAssertEqualObjects(byName[@"reality"][@"settings"][@"algorithm"], @"aes-256-gcm");
}

- (void)testWaterWallGlobalFakeDNSRemovesLegacyAliases {
    for (NSString *alias in @[@"mapdns", @"fake_dns"]) {
        NSDictionary *configuration = [self waterWallConfigurationWithInput:@"connections" application:@"vless" mux:NO outer:@"tls"
                                                                  nodeOptions:@{@"packet": @{alias: @NO}}];
        NSDictionary *byName = [self waterWallNodesByName:[self waterWallRootForConfiguration:configuration
                                                                                     options:@{@"ww_fake_dns": @YES}][@"nodes"]];
        NSDictionary *packet = byName[@"ptc"][@"settings"];
        XCTAssertEqualObjects(packet[@"fake-dns"][@"enabled"], @YES);
        XCTAssertNil(packet[alias], @"%@ must not coexist with required fake-dns", alias);
    }
}

- (void)testWaterWallPacketValidationAndFakeDNS {
    for (NSString *level in @[@"none", @"loose", @"hard"]) {
        NSDictionary *configuration = [self waterWallConfigurationWithInput:@"raw-ipv4" application:@"" mux:NO outer:@"tls"
                                                                  nodeOptions:@{@"packet": @{@"packet-validation-level": level}}];
        XCTAssertNil([SRPWaterWallChainConfig validationErrorForConfiguration:configuration]);
    }
    for (id level in @[@"strict", @1]) {
        NSDictionary *configuration = [self waterWallConfigurationWithInput:@"raw-ipv4" application:@"" mux:NO outer:@"tls"
                                                                  nodeOptions:@{@"packet": @{@"packet-validation-level": level}}];
        XCTAssertNotNil([SRPWaterWallChainConfig validationErrorForConfiguration:configuration]);
    }
    NSDictionary *validObject = @{@"enabled": @YES, @"address": @"198.18.0.2", @"network": @"100.64.0.0",
                                  @"netmask": @"255.192.0.0", @"port": @53, @"cache-size": @262144, @"ttl": @0};
    for (NSString *alias in @[@"fake-dns", @"mapdns", @"fake_dns"]) {
        for (id value in @[@NO, validObject]) {
            NSDictionary *configuration = [self waterWallConfigurationWithInput:@"connections" application:@"vless" mux:NO outer:@"tls"
                                                                      nodeOptions:@{@"packet": @{alias: value}}];
            XCTAssertNil([SRPWaterWallChainConfig validationErrorForConfiguration:configuration]);
        }
    }
    NSArray *invalidValues = @[@"yes", @{@"unknown": @1}, @{@"enabled": @1}, @{@"address": @1},
                               @{@"network": @YES}, @{@"netmask": @[]}, @{@"port": @0}, @{@"port": @65536},
                               @{@"cache-size": @0}, @{@"cache-size": @262145}, @{@"ttl": @-1}, @{@"ttl": @2147483648LL}];
    for (id value in invalidValues) {
        NSDictionary *configuration = [self waterWallConfigurationWithInput:@"connections" application:@"vless" mux:NO outer:@"tls"
                                                                  nodeOptions:@{@"packet": @{@"fake-dns": value}}];
        XCTAssertNotNil([SRPWaterWallChainConfig validationErrorForConfiguration:configuration], @"%@", value);
    }
    for (NSArray *aliases in @[@[@"fake-dns", @"mapdns"], @[@"fake_dns", @"mapdns"]]) {
        NSDictionary *configuration = [self waterWallConfigurationWithInput:@"connections" application:@"vless" mux:NO outer:@"tls"
                                                                  nodeOptions:@{@"packet": @{aliases[0]: @NO, aliases[1]: @NO}}];
        XCTAssertNotNil([SRPWaterWallChainConfig validationErrorForConfiguration:configuration]);
    }
}

- (void)testWaterWallNestedTLSOptions {
    NSDictionary *counter = @{@"mode": @"counter", @"count": @1, @"cuts": @[@[@32, @0, @100]],
                              @"wait-for-est": @YES, @"tls-hello-fragment": @YES, @"tls-hello-timeout-ms": @1000};
    NSDictionary *timed = @{@"mode": @"timed", @"duration-ms": @100, @"cuts": @[], @"bypass_chance": @20};
    for (NSDictionary *fragment in @[counter, timed]) {
        NSDictionary *configuration = [self waterWallConfigurationWithInput:@"connections" application:@"vless" mux:NO outer:@"tls"
                                                                  nodeOptions:@{@"outer": @{@"fragment": fragment,
                                                                                            @"tls13-record-shaping": @{@"scope": @{@"first-application-records": @1},
                                                                                                                       @"outcomes": @[@{@"probability": @100, @"padding-bytes": @32}]}}}];
        XCTAssertNil([SRPWaterWallChainConfig validationErrorForConfiguration:configuration]);
    }
    NSArray *invalidFragments = @[@{}, @[], @"counter",
        @{@"mode": @"other", @"cuts": @[]}, @{@"mode": @"counter", @"cuts": @[]},
        @{@"mode": @"timed", @"duration-ms": @100, @"count": @1, @"cuts": @[]},
        @{@"mode": @"counter", @"count": @1, @"cuts": @{}},
        @{@"mode": @"counter", @"count": @1, @"cuts": @[@[@32, @0]]},
        @{@"mode": @"counter", @"count": @1, @"cuts": @[@[@32, @-1, @100]]},
        @{@"mode": @"counter", @"count": @1, @"cuts": @[@[@32, @0, @100], @[@32, @0, @100]]},
        @{@"mode": @"counter", @"count": @1, @"cuts": @[], @"tls-hello-fragment": @1},
        @{@"mode": @"counter", @"count": @1, @"cuts": @[], @"tls-hello-timeout-ms": @0},
        @{@"mode": @"counter", @"count": @1, @"cuts": @[], @"unknown": @NO}];
    for (id fragment in invalidFragments) {
        NSDictionary *configuration = [self waterWallConfigurationWithInput:@"connections" application:@"vless" mux:NO outer:@"tls"
                                                                  nodeOptions:@{@"outer": @{@"fragment": fragment}}];
        XCTAssertNotNil([SRPWaterWallChainConfig validationErrorForConfiguration:configuration], @"%@", fragment);
    }
    for (id shaping in @[@{}, @[], @NO]) {
        NSDictionary *configuration = [self waterWallConfigurationWithInput:@"connections" application:@"vless" mux:NO outer:@"tls"
                                                                  nodeOptions:@{@"outer": @{@"tls13-record-shaping": shaping}}];
        XCTAssertNotNil([SRPWaterWallChainConfig validationErrorForConfiguration:configuration]);
    }
}

- (void)testWaterWallNonemptyAdvancedStringsAndDomainStrategy {
    for (NSString *key in @[@"algorithm", @"method", @"salt"]) {
        for (id value in @[@"", @1]) {
            NSDictionary *configuration = [self waterWallConfigurationWithInput:@"connections" application:@"vless" mux:NO outer:@"reality"
                                                                      nodeOptions:@{@"outer": @{key: value}}];
            XCTAssertNotNil([SRPWaterWallChainConfig validationErrorForConfiguration:configuration]);
        }
    }
    for (NSString *key in @[@"ech-config-list", @"ech-sni-trick"]) {
        NSDictionary *configuration = [self waterWallConfigurationWithInput:@"connections" application:@"vless" mux:NO outer:@"tls"
                                                                  nodeOptions:@{@"outer": @{key: @""}}];
        XCTAssertNotNil([SRPWaterWallChainConfig validationErrorForConfiguration:configuration]);
    }
    NSDictionary *ca = [self waterWallConfigurationWithInput:@"connections" application:@"vless" mux:NO outer:@"quic"
                                                  nodeOptions:@{@"outer": @{@"ca-file": @""}}];
    XCTAssertNotNil([SRPWaterWallChainConfig validationErrorForConfiguration:ca]);
    for (NSString *strategy in @[@"do-not-resolve-domains", @"resolve-domains-and-prefer-ipv4",
                                 @"resolve-domains-and-prefer-ipv6", @"resolve-domains-with-core-settings",
                                 @"resolve-domains-and-accept-dns-returned-order", @"resolve-domains-and-use-only-ipv4",
                                 @"resolve-domains-and-use-only-ipv6"]) {
        NSDictionary *configuration = [self waterWallConfigurationWithInput:@"connections" application:@"vless" mux:NO outer:@"tls"
                                                                  nodeOptions:@{@"application": @{@"domain-strategy": strategy}}];
        XCTAssertNil([SRPWaterWallChainConfig validationErrorForConfiguration:configuration]);
    }
    for (NSString *strategy in @[@"accept-dns-returned-order", @"prefer-ipv4", @"prefer-ipv6", @"only-ipv4", @"only-ipv6", @"resolve-domains"]) {
        NSDictionary *configuration = [self waterWallConfigurationWithInput:@"connections" application:@"vless" mux:NO outer:@"tls"
                                                                  nodeOptions:@{@"application": @{@"domain-strategy": strategy}}];
        XCTAssertNotNil([SRPWaterWallChainConfig validationErrorForConfiguration:configuration]);
    }
    NSDictionary *combinedECH = [self waterWallConfigurationWithInput:@"connections" application:@"vless" mux:NO outer:@"tls"
                                                            nodeOptions:@{@"outer": @{@"ech-config-list": @"AA==", @"ech-sni-trick": @"cover.example"}}];
    XCTAssertNotNil([SRPWaterWallChainConfig validationErrorForConfiguration:combinedECH]);
}

- (void)testWaterWallDirectAndWireGuardOptionRules {
    NSDictionary *validDirect = @{@"version": @3, @"mode": @"direct",
                                  @"node-options": @{@"packet": @{@"mtu": @1400, @"fake-dns": @NO}}};
    XCTAssertNil([SRPWaterWallChainConfig validationErrorForConfiguration:validDirect]);
    NSArray *invalidDirect = @[
        @{@"version": @3, @"mode": @"direct", @"node-options": @{@"application": @{}}},
        @{@"version": @3, @"mode": @"direct", @"node-options": @{@"packet": @{@"mtu": @1}}},
        @{@"version": @3, @"mode": @"direct", @"node-options": @{@"packet": @{@"packet-validation-level": @"hard"}}},
        @{@"version": @3, @"mode": @"direct", @"node-options": @{@"packet": @{@"fake-dns": @{@"port": @0}}}},
    ];
    for (NSDictionary *configuration in invalidDirect) {
        XCTAssertNotNil([SRPWaterWallChainConfig validationErrorForConfiguration:configuration]);
    }
    XCTAssertNil([SRPWaterWallChainConfig validationErrorForConfiguration:(@{@"version": @3, @"mode": @"wireguard", @"node-options": @{}})]);
    NSDictionary *wireGuard = @{@"version": @3, @"mode": @"wireguard", @"node-options": @{@"packet": @{@"mtu": @1400}}};
    XCTAssertNotNil([SRPWaterWallChainConfig validationErrorForConfiguration:wireGuard]);
}

- (void)testWaterWallQUICUsesEffectiveReceiveWindowAndBudgetDefaults {
    NSDictionary *implicitReceive = [self waterWallConfigurationWithInput:@"connections" application:@"vless" mux:NO outer:@"quic"
                                                                nodeOptions:@{@"outer": @{@"max-buffered-bytes": @65536}}];
    XCTAssertNotNil([SRPWaterWallChainConfig validationErrorForConfiguration:implicitReceive]);
    NSDictionary *smallReceive = [self waterWallConfigurationWithInput:@"connections" application:@"vless" mux:NO outer:@"quic"
                                                             nodeOptions:@{@"outer": @{@"max-buffered-bytes": @65536, @"receive-window-bytes": @16384}}];
    XCTAssertNil([SRPWaterWallChainConfig validationErrorForConfiguration:smallReceive]);
    NSDictionary *implicitBudget = [self waterWallConfigurationWithInput:@"connections" application:@"vless" mux:NO outer:@"quic"
                                                               nodeOptions:@{@"outer": @{@"receive-window-bytes": @2097153}}];
    XCTAssertNotNil([SRPWaterWallChainConfig validationErrorForConfiguration:implicitBudget]);
}

- (void)testWaterWallCredentialValidationAndStartupGuard {
    NSDictionary *vless = [self waterWallConfigurationWithApplication:@"vless" mux:NO outer:@"tls"];
    NSDictionary *trojan = [self waterWallConfigurationWithApplication:@"trojan" mux:NO outer:@"tls"];
    for (NSString *uuid in @[@"00112233-4455-6677-8899-aabbccddeeff", @"00112233445566778899AABBCCDDEEFF"]) {
        XCTAssertNil([SRPWaterWallChainConfig validationErrorForApplicationSecret:uuid forConfiguration:vless]);
        XCTAssertNotNil([SRPWaterWallChainConfig nodesJSONForConfiguration:vless server:@"host" port:443 sni:nil
                                                                verifyTLS:YES secret:uuid outerSecret:nil options:nil]);
    }
    for (id uuid in @[@"", @"app-secret", @"00112233-4455-6677-8899-aabbccddeezz", @1, NSNull.null]) {
        XCTAssertNotNil([SRPWaterWallChainConfig validationErrorForApplicationSecret:uuid forConfiguration:vless]);
        XCTAssertNil([SRPWaterWallChainConfig nodesJSONForConfiguration:vless server:@"host" port:443 sni:nil
                                                              verifyTLS:YES secret:uuid outerSecret:nil options:nil]);
    }
    XCTAssertNotNil([SRPWaterWallChainConfig validationErrorForApplicationSecret:@"" forConfiguration:trojan]);
    XCTAssertNil([SRPWaterWallChainConfig validationErrorForApplicationSecret:@"password" forConfiguration:trojan]);
    XCTAssertNil([SRPWaterWallChainConfig validationErrorForApplicationSecret:nil forConfiguration:(@{@"mode": @"direct"})]);

    NSDictionary *reality = [self waterWallConfigurationWithApplication:@"trojan" mux:NO outer:@"reality"];
    NSDictionary *aead = [self waterWallConfigurationWithApplication:@"trojan" mux:NO outer:@"aead"];
    NSString *thirtyTwo = [@"" stringByPaddingToLength:16 withString:@"é" startingAtIndex:0];
    NSString *thirtyThree = [thirtyTwo stringByAppendingString:@"x"];
    XCTAssertNil([SRPWaterWallChainConfig validationErrorForOuterSecret:thirtyTwo forConfiguration:reality]);
    for (id secret in @[@"", thirtyThree, @1]) {
        XCTAssertNotNil([SRPWaterWallChainConfig validationErrorForOuterSecret:secret forConfiguration:reality]);
        XCTAssertNil([SRPWaterWallChainConfig nodesJSONForConfiguration:reality server:@"host" port:443 sni:nil
                                                              verifyTLS:YES secret:@"password" outerSecret:secret options:nil]);
    }
    XCTAssertNotNil([SRPWaterWallChainConfig validationErrorForOuterSecret:@"" forConfiguration:aead]);
    XCTAssertNil([SRPWaterWallChainConfig validationErrorForOuterSecret:@"a much longer AEAD password is allowed" forConfiguration:aead]);
    XCTAssertNil([SRPWaterWallChainConfig validationErrorForOuterSecret:nil forConfiguration:vless]);
}

- (void)testWaterWallVersion3DefaultsAndV2Migration {
    NSDictionary *expected = @{@"version": @3, @"mode": @"chain", @"input": @"connections", @"application": @"vless",
                               @"mux": @NO, @"outer": @"tls", @"http": @"off", @"http-version": @1,
                               @"obfuscator": @NO, @"carrier": @"tcp", @"quic-carrier": @"datagram", @"node-options": @{}};
    XCTAssertEqualObjects([SRPWaterWallChainConfig defaultConfiguration], expected);
    NSDictionary *v2 = @{@"version": @2, @"mode": @"chain", @"input": @"connections", @"application": @"vless",
                         @"mux": @NO, @"outer": @"tls", @"node-options": @{}};
    NSData *data = [NSJSONSerialization dataWithJSONObject:v2 options:0 error:nil];
    NSString *json = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    XCTAssertEqualObjects([SRPWaterWallChainConfig configurationWithJSON:json], expected);
    NSString *saved = [SRPWaterWallChainConfig JSONWithConfiguration:v2];
    XCTAssertEqualObjects([self waterWallJSONObject:saved], expected);

    NSMutableDictionary *direct = [NSMutableDictionary new];
    direct[@"version"] = @2;
    direct[@"mode"] = @"direct";
    direct[@"node-options"] = @{@"packet": @{@"mtu": @1400}};
    data = [NSJSONSerialization dataWithJSONObject:direct options:0 error:nil];
    json = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    direct[@"version"] = @3;
    XCTAssertEqualObjects([SRPWaterWallChainConfig configurationWithJSON:json], direct);
    NSMutableDictionary *missing = [expected mutableCopy];
    [missing removeObjectForKey:@"http"];
    XCTAssertNotNil([SRPWaterWallChainConfig validationErrorForConfiguration:missing]);
}

- (void)testWaterWallOrderedExpandedGraph {
    NSMutableDictionary *configuration = [[self waterWallConfigurationWithApplication:@"vless" mux:YES outer:@"reality"] mutableCopy];
    configuration[@"http"] = @"websocket";
    configuration[@"http-version"] = @2;
    configuration[@"obfuscator"] = @YES;
    configuration[@"carrier"] = @"kcp";
    configuration[@"node-options"] = @{@"obfuscator": @{@"tls_record_header": @YES}, @"kcp": @{@"mtu": @1400}};
    NSDictionary *root = [self waterWallRootForConfiguration:configuration options:nil];
    NSArray *nodes = root[@"nodes"];
    NSArray *names = @[@"ne", @"ptc", @"vless", @"router", @"mux", @"obfuscator", @"http", @"reality", @"kcp", @"connector"];
    NSArray *types = @[@"NEPacketDevice", @"PacketsToConnection", @"VlessClient", @"Router", @"MuxClient", @"ObfuscatorClient",
                       @"HttpClient", @"RealityClient", @"TcpOverUdpClient", @"UdpConnector"];
    XCTAssertEqual(nodes.count, names.count);
    for (NSUInteger index = 0; index < names.count; index++) {
        XCTAssertEqualObjects(nodes[index][@"name"], names[index]);
        XCTAssertEqualObjects(nodes[index][@"type"], types[index]);
        if (index + 1 < names.count) {
            NSString *expectedNext;
            if ([nodes[index][@"name"] isEqualToString:@"ptc"]) {
                expectedNext = names[index + 2];
            } else if ([nodes[index][@"name"] isEqualToString:@"router"]) {
                expectedNext = names[index - 1];
            } else if ([nodes[index][@"name"] isEqualToString:configuration[@"application"]]) {
                expectedNext = names[index + 2];
            } else {
                expectedNext = names[index + 1];
            }
            XCTAssertEqualObjects(nodes[index][@"next"], expectedNext);
        }
    }
    NSDictionary *http = nodes[6][@"settings"];
    XCTAssertEqualObjects(http[@"host"], @"edge.example.com");
    XCTAssertEqualObjects(http[@"path"], @"/");
    XCTAssertEqualObjects(http[@"scheme"], @"https");
    XCTAssertEqualObjects(http[@"port"], @18443);
    XCTAssertEqualObjects(http[@"http-version"], @2);
    XCTAssertEqualObjects(http[@"websocket"], @YES);
    XCTAssertEqualObjects(nodes[7][@"settings"][@"alpns"], (@[@"h2"]));
    XCTAssertEqualObjects(nodes[5][@"settings"][@"method"], @"xor");
    XCTAssertEqualObjects(nodes[5][@"settings"][@"xor_key"], @90);
    XCTAssertEqualObjects(nodes[5][@"settings"][@"skip"], @"none");
    XCTAssertEqualObjects(nodes[5][@"settings"][@"tls_record_header"], @YES);
    XCTAssertEqualObjects(nodes[8][@"settings"][@"mtu"], @1400);
    XCTAssertNil(nodes.lastObject[@"settings"][@"protocol"]);

    configuration[@"http-version"] = @1;
    configuration[@"carrier"] = @"tcp";
    configuration[@"node-options"] = @{@"obfuscator": @{@"tls_record_header": @YES}};
    root = [self waterWallRootForConfiguration:configuration options:nil];
    nodes = root[@"nodes"];
    XCTAssertEqualObjects(nodes[7][@"settings"][@"alpns"], (@[@"http/1.1"]));
    XCTAssertEqualObjects(nodes.lastObject[@"type"], @"TcpConnector");
}

- (void)testWaterWallNoneKCPAndQUICCarrierGraphs {
    NSMutableDictionary *none = [[self waterWallConfigurationWithApplication:@"vless" mux:NO outer:@"none"] mutableCopy];
    NSArray *nodes = [self waterWallRootForConfiguration:none options:nil][@"nodes"];
    XCTAssertEqual(nodes.count, 5);
    XCTAssertEqualObjects(nodes[2][@"next"], @"connector");
    XCTAssertEqualObjects(nodes.lastObject[@"type"], @"TcpConnector");
    XCTAssertNil(nodes.lastObject[@"settings"][@"protocol"]);
    none[@"http"] = @"http";
    nodes = [self waterWallRootForConfiguration:none options:nil][@"nodes"];
    XCTAssertEqualObjects(nodes[4][@"type"], @"HttpClient");
    XCTAssertEqualObjects(nodes[4][@"settings"][@"scheme"], @"http");

    NSMutableDictionary *rawKCP = [[self waterWallConfigurationWithInput:@"raw-ipv4" application:@"" mux:NO outer:@"none" nodeOptions:@{}] mutableCopy];
    rawKCP[@"carrier"] = @"kcp";
    nodes = [self waterWallRootForConfiguration:rawKCP options:nil][@"nodes"];
    XCTAssertEqual(nodes.count, 4);
    XCTAssertEqualObjects(nodes[1][@"next"], @"kcp");
    XCTAssertEqualObjects(nodes[2][@"type"], @"TcpOverUdpClient");
    XCTAssertEqualObjects(nodes.lastObject[@"type"], @"UdpConnector");

    NSMutableDictionary *stream = [[self waterWallConfigurationWithApplication:@"vless" mux:YES outer:@"quic"] mutableCopy];
    stream[@"quic-carrier"] = @"stream";
    nodes = [self waterWallRootForConfiguration:stream options:nil][@"nodes"];
    XCTAssertEqualObjects(nodes[5][@"settings"][@"carrier-mode"], @"stream");
    XCTAssertEqualObjects(nodes.lastObject[@"type"], @"TcpConnector");
    stream[@"mux"] = @NO;
    stream[@"quic-carrier"] = @"datagram";
    nodes = [self waterWallRootForConfiguration:stream options:nil][@"nodes"];
    XCTAssertEqualObjects(nodes[4][@"settings"][@"carrier-mode"], @"datagram");
    XCTAssertEqualObjects(nodes.lastObject[@"type"], @"UdpConnector");
    stream[@"http"] = @"http";
    XCTAssertNotNil([SRPWaterWallChainConfig validationErrorForConfiguration:stream]);
    stream[@"http"] = @"off";
    stream[@"mux"] = @YES;
    XCTAssertNotNil([SRPWaterWallChainConfig validationErrorForConfiguration:stream]);
}

- (void)testWaterWallExpandedHTTPObfuscatorAndKCPValidation {
    NSMutableDictionary *http = [[self waterWallConfigurationWithApplication:@"vless" mux:NO outer:@"none"] mutableCopy];
    http[@"http"] = @"http";
    http[@"node-options"] = @{@"http": @{@"path": @"/tunnel", @"scheme": @"http", @"method": @"POST", @"user-agent": @"test",
        @"http-version": @"h2", @"upgrade": @NO, @"upgrade-protocol": @"h2c",
        @"upgrade-request-headers": @{@"x-upgrade": @"yes"}, @"upgrade-response-headers": @{@"x-response": @"yes"},
        @"headers": @{@"x-client": @"waterwall"}, @"content-type": @"application/octet-stream",
        @"websocket-origin": @"https://origin.example", @"websocket-subprotocol": @"tunnel", @"websocket-extensions": @"",
        @"http1-mode": @"single", @"split": @{}, @"verbose": @NO}};
    XCTAssertNil([SRPWaterWallChainConfig validationErrorForConfiguration:http]);
    NSArray *invalidHTTP = @[
        @{@"scheme": @"ftp"}, @{@"http-version": @3}, @{@"headers": @{@"x": @1}}, @{@"upgrade": @1},
        @{@"http1-mode": @"other"}, @{@"split": @[]}, @{@"websocket-extensions": @"permessage-deflate"}, @{@"path": @1},
        @{@"websocket": @NO}
    ];
    for (NSDictionary *settings in invalidHTTP) {
        NSMutableDictionary *configuration = [http mutableCopy];
        configuration[@"node-options"] = @{@"http": settings};
        XCTAssertNotNil([SRPWaterWallChainConfig validationErrorForConfiguration:configuration], @"%@", settings);
    }
    for (NSString *layer in @[@"http", @"obfuscator", @"kcp"]) {
        NSMutableDictionary *configuration = [[self waterWallConfigurationWithApplication:@"vless" mux:NO outer:@"tls"] mutableCopy];
        configuration[@"node-options"] = @{layer: @{}};
        XCTAssertNotNil([SRPWaterWallChainConfig validationErrorForConfiguration:configuration]);
    }

    NSMutableDictionary *obfuscator = [[self waterWallConfigurationWithApplication:@"vless" mux:NO outer:@"tls"] mutableCopy];
    obfuscator[@"obfuscator"] = @YES;
    obfuscator[@"node-options"] = @{@"obfuscator": @{@"method": @"xor", @"xor_key": @0, @"skip": @"transport",
                                                       @"tls_record_header": @YES, @"tls_header": @NO}};
    XCTAssertNil([SRPWaterWallChainConfig validationErrorForConfiguration:obfuscator]);
    for (NSDictionary *settings in @[@{@"method": @"aes"}, @{@"xor_key": @256}, @{@"skip": @"other"}, @{@"tls_header": @1}]) {
        NSMutableDictionary *configuration = [obfuscator mutableCopy];
        configuration[@"node-options"] = @{@"obfuscator": settings};
        XCTAssertNotNil([SRPWaterWallChainConfig validationErrorForConfiguration:configuration]);
    }

    NSDictionary *validKCP = @{@"mtu": @86, @"fec": @YES, @"fec-data-shards": @10, @"fec-parity-shards": @3,
        @"kcp-nodelay": @YES, @"kcp-interval-ms": @10, @"kcp-resend": @0, @"kcp-no-congestion-control": @YES,
        @"kcp-send-window": @100, @"kcp-recv-window": @100, @"kcp-initial-cwnd": @50, @"kcp-rx-minrto-ms": @1,
        @"kcp-send-buffer-limit": @0, @"ping-interval-ms": @1000, @"no-recv-timeout-ms": @2000};
    NSMutableDictionary *kcp = [[self waterWallConfigurationWithApplication:@"vless" mux:NO outer:@"none"] mutableCopy];
    kcp[@"carrier"] = @"kcp";
    kcp[@"node-options"] = @{@"kcp": validKCP};
    XCTAssertNil([SRPWaterWallChainConfig validationErrorForConfiguration:kcp]);
    NSDictionary *kcpByName = [self waterWallNodesByName:[self waterWallRootForConfiguration:kcp options:nil][@"nodes"]];
    XCTAssertEqualObjects(kcpByName[@"kcp"][@"settings"][@"kcp-recv-window"], @100);
    XCTAssertEqualObjects(kcpByName[@"kcp"][@"settings"][@"kcp-send-buffer-limit"], @0);
    kcp[@"node-options"] = @{};
    kcpByName = [self waterWallNodesByName:[self waterWallRootForConfiguration:kcp options:nil][@"nodes"]];
    XCTAssertEqualObjects(kcpByName[@"kcp"][@"settings"][@"kcp-recv-window"], @512);
    XCTAssertEqualObjects(kcpByName[@"kcp"][@"settings"][@"kcp-send-buffer-limit"], @512);
    kcp[@"node-options"] = @{@"kcp": validKCP};
    NSArray *invalidKCP = @[@{@"mtu": @77}, @{@"mtu": @85, @"fec": @YES}, @{@"fec-data-shards": @0},
        @{@"fec-data-shards": @255, @"fec-parity-shards": @1}, @{@"kcp-interval-ms": @9}, @{@"kcp-resend": @-1},
        @{@"kcp-send-window": @0}, @{@"kcp-initial-cwnd": @9000}, @{@"kcp-rx-minrto-ms": @0},
        @{@"kcp-send-buffer-limit": @-1}, @{@"ping-interval-ms": @0},
        @{@"ping-interval-ms": @1000, @"no-recv-timeout-ms": @1000}, @{@"kcp-nodelay": @1}];
    for (NSDictionary *settings in invalidKCP) {
        NSMutableDictionary *configuration = [kcp mutableCopy];
        configuration[@"node-options"] = @{@"kcp": settings};
        XCTAssertNotNil([SRPWaterWallChainConfig validationErrorForConfiguration:configuration], @"%@", settings);
    }
}

- (void)testWaterWallMUXModeAndKeepaliveValidation {
    NSArray *valid = @[
        @{@"mode": @"counter", @"connection-capacity": @10, @"keepalive": @NO, @"ping-interval": @1, @"tolerance-ms": @1},
        @{@"mode": @"counter", @"connection-capacity": @10, @"ping-interval": @60, @"tolerance-ms": @1},
        @{@"mode": @"timer", @"connection-duration-ms": @61}, @{@"mode": @"fixed-connections-count", @"per-worker-connections-count": @2}
    ];
    for (NSDictionary *settings in valid) {
        NSDictionary *configuration = [self waterWallConfigurationWithInput:@"connections" application:@"vless" mux:YES outer:@"tls"
                                                                  nodeOptions:@{@"mux": settings}];
        XCTAssertNil([SRPWaterWallChainConfig validationErrorForConfiguration:configuration]);
        NSDictionary *byName = [self waterWallNodesByName:[self waterWallRootForConfiguration:configuration options:nil][@"nodes"]];
        if ([settings[@"mode"] isEqualToString:@"timer"]) XCTAssertNil(byName[@"mux"][@"settings"][@"connection-capacity"]);
    }
    NSArray *invalid = @[
        @{@"mode": @"counter", @"connection-capacity": @10, @"connection-duration-ms": @61},
        @{@"mode": @"timer", @"connection-duration-ms": @61, @"connection-capacity": @10},
        @{@"mode": @"fixed-connections-count", @"per-worker-connections-count": @2, @"connection-capacity": @10},
        @{@"ping-interval": @0}, @{@"keepalive": @1}
    ];
    for (NSDictionary *settings in invalid) {
        NSDictionary *configuration = [self waterWallConfigurationWithInput:@"connections" application:@"vless" mux:YES outer:@"tls"
                                                                  nodeOptions:@{@"mux": settings}];
        XCTAssertNotNil([SRPWaterWallChainConfig validationErrorForConfiguration:configuration], @"%@", settings);
    }
}

- (void)testWaterWallCarrierSplitAndBuilderOwnedValidation {
    NSMutableDictionary *quicKCP = [[self waterWallConfigurationWithApplication:@"vless" mux:NO outer:@"quic"] mutableCopy];
    quicKCP[@"carrier"] = @"kcp";
    quicKCP[@"node-options"] = @{@"kcp": @{}};
    XCTAssertNotNil([SRPWaterWallChainConfig validationErrorForConfiguration:quicKCP]);
    quicKCP[@"carrier"] = @"tcp";
    quicKCP[@"node-options"] = @{@"outer": @{@"carrier-mode": @"datagram"}};
    XCTAssertNotNil([SRPWaterWallChainConfig validationErrorForConfiguration:quicKCP]);

    NSMutableDictionary *split = [[self waterWallConfigurationWithApplication:@"vless" mux:NO outer:@"none"] mutableCopy];
    split[@"http"] = @"http";
    split[@"http-version"] = @2;
    split[@"node-options"] = @{@"http": @{@"http-version": @"http1", @"http1-mode": @"split"}};
    XCTAssertNil([SRPWaterWallChainConfig validationErrorForConfiguration:split]);
    split[@"node-options"] = @{@"http": @{@"http-version": @"h2", @"http1-mode": @"split"}};
    XCTAssertNotNil([SRPWaterWallChainConfig validationErrorForConfiguration:split]);
    split[@"node-options"] = @{@"http": @{@"http1-mode": @"split"}};
    XCTAssertNotNil([SRPWaterWallChainConfig validationErrorForConfiguration:split]);
    split[@"http"] = @"websocket";
    split[@"http-version"] = @1;
    XCTAssertNotNil([SRPWaterWallChainConfig validationErrorForConfiguration:split]);

    for (NSString *outer in @[@"tls", @"reality"]) {
        NSMutableDictionary *configuration = [[self waterWallConfigurationWithApplication:@"vless" mux:NO outer:outer] mutableCopy];
        configuration[@"http"] = @"http";
        configuration[@"node-options"] = @{@"outer": @{@"alpns": @[@"h2"]}};
        XCTAssertNotNil([SRPWaterWallChainConfig validationErrorForConfiguration:configuration]);
    }
}

- (void)testWaterWallWireGuardKeepaliveRange {
    NSString *maximum = @"[Interface]\nPrivateKey=x\nAddress=10.0.0.2/32\n[Peer]\nPublicKey=p\nEndpoint=host:51820\nPersistentKeepalive=65535\n";
    NSDictionary *result = [SRPWaterWallChainConfig wireGuardConfigurationWithConfig:maximum];
    NSArray *peers = [self waterWallJSONObject:result[@"nodesJSON"]][@"nodes"][1][@"settings"][@"peers"];
    XCTAssertEqualObjects(peers[0][@"persistentkeepalive"], @65535);
    NSString *overflow = @"[Interface]\nPrivateKey=x\nAddress=10.0.0.2/32\n[Peer]\nPublicKey=p\nEndpoint=host:51820\nPersistentKeepalive=65536\n";
    XCTAssertNil([SRPWaterWallChainConfig wireGuardConfigurationWithConfig:overflow]);
    XCTAssertNotNil([SRPWaterWallChainConfig wireGuardConfigurationWithPrivateKey:@"private" serverPublicKey:@"public"
                                                                         server:@"host" port:51820 clientAddress:@"10.0.0.2/32" keepalive:65535]);
    XCTAssertNil([SRPWaterWallChainConfig wireGuardConfigurationWithPrivateKey:@"private" serverPublicKey:@"public"
                                                                      server:@"host" port:51820 clientAddress:@"10.0.0.2/32" keepalive:65536]);
    XCTAssertNil([SRPWaterWallChainConfig wireGuardConfigurationWithPrivateKey:@"private" serverPublicKey:@"public"
                                                                      server:@"host" port:51820 clientAddress:@"10.0.0.2/32" keepalive:-1]);
}

- (void)testWaterWallTLS13SaltAndAlgorithmValidation {
    NSDictionary *shaping = @{@"scope": @{@"first-application-records": @8}, @"outcomes": @[
        @{@"probability": @50, @"padding-bytes": @[@1, @100], @"delay": @{@"probability": @75, @"ms": @[@0, @10]}},
        @{@"probability": @50, @"padding-bytes": @4096}
    ]};
    NSDictionary *tls = [self waterWallConfigurationWithInput:@"connections" application:@"vless" mux:NO outer:@"tls"
                                                  nodeOptions:@{@"outer": @{@"tls13-record-shaping": shaping}}];
    XCTAssertNil([SRPWaterWallChainConfig validationErrorForConfiguration:tls]);
    NSDictionary *delayOnly = @{@"scope": @{@"first-application-records": @1}, @"outcomes": @[
        @{@"probability": @100, @"delay": @{@"probability": @1, @"ms": @1}}
    ]};
    NSDictionary *delayConfiguration = [self waterWallConfigurationWithInput:@"connections" application:@"vless" mux:NO outer:@"tls"
                                                                   nodeOptions:@{@"outer": @{@"tls13-record-shaping": delayOnly}}];
    XCTAssertNil([SRPWaterWallChainConfig validationErrorForConfiguration:delayConfiguration]);
    NSDictionary *reality = [self waterWallConfigurationWithInput:@"connections" application:@"vless" mux:NO outer:@"reality"
                                                      nodeOptions:@{@"outer": @{@"tls13-record-shaping": shaping}}];
    XCTAssertNotNil([SRPWaterWallChainConfig validationErrorForConfiguration:reality]);
    NSArray *invalidShapes = @[
        @{@"scope": @{@"first-application-records": @1}},
        @{@"scope": @{@"first-application-records": @0}, @"outcomes": @[]},
        @{@"scope": @{@"first-application-records": @1025}, @"outcomes": @[@{@"probability": @1}]},
        @{@"scope": @{@"first-application-records": @1}, @"outcomes": @[@{@"probability": @60}, @{@"probability": @60}]},
        @{@"scope": @{@"first-application-records": @1}, @"outcomes": @[@{@"probability": @100, @"padding-bytes": @0}]},
        @{@"scope": @{@"first-application-records": @1}, @"outcomes": @[@{@"probability": @100, @"padding-bytes": @4097}]},
        @{@"scope": @{@"first-application-records": @1}, @"outcomes": @[@{@"probability": @100, @"delay": @{@"probability": @100, @"ms": @1001}}]},
        @{@"scope": @{@"first-application-records": @1}, @"outcomes": @[@{@"probability": @0, @"padding-bytes": @1}]},
        @{@"scope": @{@"first-application-records": @1}, @"outcomes": @[@{@"probability": @100}]},
        @{@"scope": @{@"first-application-records": @1}, @"outcomes": @[@{@"probability": @100, @"delay": @{@"probability": @0, @"ms": @100}}]},
        @{@"scope": @{@"first-application-records": @1}, @"outcomes": @[@{@"probability": @100, @"delay": @{@"probability": @100, @"ms": @0}}]},
        @{@"scope": @{@"first-application-records": @1}, @"outcomes": @[@{@"probability": @100, @"delay": @{@"probability": @100, @"ms": @[@0, @0]}}]}
    ];
    for (NSDictionary *shape in invalidShapes) {
        NSDictionary *configuration = [self waterWallConfigurationWithInput:@"connections" application:@"vless" mux:NO outer:@"tls"
                                                                  nodeOptions:@{@"outer": @{@"tls13-record-shaping": shape}}];
        XCTAssertNotNil([SRPWaterWallChainConfig validationErrorForConfiguration:configuration], @"%@", shape);
    }
    NSString *salt32 = [@"" stringByPaddingToLength:16 withString:@"é" startingAtIndex:0];
    NSString *salt33 = [salt32 stringByAppendingString:@"x"];
    for (NSString *outer in @[@"reality", @"aead"]) {
        NSArray *algorithms = [outer isEqualToString:@"reality"] ?
            @[@"chacha20-poly1305", @"chacha20poly1305", @"aes-gcm", @"aes-256-gcm", @"aes256gcm"] :
            @[@"chacha20-poly1305", @"chacha20poly1305", @"chacha20", @"chacha", @"aes-gcm", @"aes256gcm", @"aes-256-gcm", @"aes256-gcm"];
        for (NSString *algorithm in algorithms) {
            NSDictionary *configuration = [self waterWallConfigurationWithInput:@"connections" application:@"vless" mux:NO outer:outer
                                                                      nodeOptions:@{@"outer": @{@"algorithm": algorithm, @"salt": salt32}}];
            XCTAssertNil([SRPWaterWallChainConfig validationErrorForConfiguration:configuration], @"%@ %@", outer, algorithm);
        }
        for (NSDictionary *settings in @[@{@"salt": salt33}, @{@"algorithm": @"unknown"}]) {
            NSDictionary *configuration = [self waterWallConfigurationWithInput:@"connections" application:@"vless" mux:NO outer:outer
                                                                      nodeOptions:@{@"outer": settings}];
            XCTAssertNotNil([SRPWaterWallChainConfig validationErrorForConfiguration:configuration]);
        }
    }
}

- (void)testWaterWallWireGuardMultiplePeersAndInvalidInputs {
    NSString *config = @"[Interface]\nPrivateKey = private=\nAddress = 10.0.0.2/32\nDNS = 1.1.1.1, 9.9.9.9\n"
        "[Peer]\nPublicKey = first=\nAllowedIPs = 10.0.0.0/8\nEndpoint = first.example:51820\nPersistentKeepalive = 10\nPresharedKey = first-psk=\n"
        "[Peer]\nPublicKey = second=\nAllowedIPs = 192.168.0.0/16, 172.16.0.0/12\nEndpoint = second.example:51821\nPersistentKeepalive = 25\n";
    NSDictionary *result = [SRPWaterWallChainConfig wireGuardConfigurationWithConfig:config];
    XCTAssertNotNil(result);
    XCTAssertEqualObjects(result[@"allowedIPs"], @"10.0.0.0/8, 192.168.0.0/16, 172.16.0.0/12");
    XCTAssertEqualObjects(result[@"endpointIP"], @"first.example");
    XCTAssertEqualObjects(result[@"endpointIPs"], (@[@"first.example", @"second.example"]));
    NSArray *peers = [self waterWallJSONObject:result[@"nodesJSON"]][@"nodes"][1][@"settings"][@"peers"];
    XCTAssertEqual(peers.count, 2);
    XCTAssertEqualObjects(peers[0][@"publickey"], @"first=");
    XCTAssertEqualObjects(peers[0][@"endpoint"], @"first.example:51820");
    XCTAssertEqualObjects(peers[0][@"allowedips"], @"10.0.0.0/8");
    XCTAssertEqualObjects(peers[0][@"persistentkeepalive"], @10);
    XCTAssertEqualObjects(peers[0][@"presharedkey"], @"first-psk=");
    XCTAssertEqualObjects(peers[1][@"publickey"], @"second=");
    XCTAssertEqualObjects(peers[1][@"endpoint"], @"second.example:51821");
    XCTAssertEqualObjects(peers[1][@"allowedips"], @"192.168.0.0/16, 172.16.0.0/12");
    XCTAssertEqualObjects(peers[1][@"persistentkeepalive"], @25);
    XCTAssertNil(peers[1][@"presharedkey"]);
    XCTAssertNil([SRPWaterWallChainConfig wireGuardConfigurationWithConfig:@"[Interface]\nPrivateKey=x\nAddress=10.0.0.2/32\n"]);
    XCTAssertNil([SRPWaterWallChainConfig wireGuardConfigurationWithConfig:@"[Interface]\nPrivateKey=x\nAddress=10.0.0.2/32\n[Peer]\nPublicKey=x\n"]);
    XCTAssertNil([SRPWaterWallChainConfig wireGuardConfigurationWithConfig:@"[Interface]\nPrivateKey=x\nAddress=10.0.0.2/32\n[Peer]\nEndpoint=host:1\n"]);
    NSMutableString *tooMany = [NSMutableString stringWithString:@"[Interface]\nPrivateKey=x\nAddress=10.0.0.2/32\n"];
    for (NSInteger index = 0; index < 33; index++) {
        [tooMany appendFormat:@"[Peer]\nPublicKey=k%ld\nEndpoint=host:51820\n", (long)index];
    }
    XCTAssertNil([SRPWaterWallChainConfig wireGuardConfigurationWithConfig:tooMany]);
}

- (void)testWaterWallWireGuardAllowedIPsPreservationAndDefaults {
    NSString *config = @"[Interface]\nPrivateKey = private\nAddress = 10.0.0.2/32\n[Peer]\nPublicKey = public\nAllowedIPs =   10.0.0.0/8, 192.168.0.0/16   \nEndpoint = host:51820\n";
    NSDictionary *result = [SRPWaterWallChainConfig wireGuardConfigurationWithConfig:config];
    XCTAssertEqualObjects(result[@"allowedIPs"], @"10.0.0.0/8, 192.168.0.0/16");
    XCTAssertEqualObjects(result[@"endpointIPs"], (@[@"host"]));
    NSDictionary *root = [self waterWallJSONObject:result[@"nodesJSON"]];
    XCTAssertEqualObjects(root[@"nodes"][1][@"settings"][@"peers"][0][@"allowedips"], result[@"allowedIPs"]);

    NSString *defaultConfig = @"[Interface]\nPrivateKey = private\nAddress = 10.0.0.2/32\n[Peer]\nPublicKey = public\nEndpoint = host:51820\n";
    NSDictionary *defaultResult = [SRPWaterWallChainConfig wireGuardConfigurationWithConfig:defaultConfig];
    XCTAssertEqualObjects(defaultResult[@"allowedIPs"], @"0.0.0.0/0");
    NSDictionary *defaultRoot = [self waterWallJSONObject:defaultResult[@"nodesJSON"]];
    XCTAssertEqualObjects(defaultRoot[@"nodes"][1][@"settings"][@"peers"][0][@"allowedips"], @"0.0.0.0/0");

    NSDictionary *manual = [SRPWaterWallChainConfig wireGuardConfigurationWithPrivateKey:@"private" serverPublicKey:@"public"
                                                                                  server:@"host" port:51820 clientAddress:@"10.0.0.2/32" keepalive:25];
    XCTAssertEqualObjects(manual[@"allowedIPs"], @"0.0.0.0/0");
    NSDictionary *manualRoot = [self waterWallJSONObject:manual[@"nodesJSON"]];
    XCTAssertEqualObjects(manualRoot[@"nodes"][1][@"settings"][@"peers"][0][@"allowedips"], @"0.0.0.0/0");
}

- (void)testWaterWallWireGuardConfigPreservesBase64Padding {
    NSString *config = @"[Interface]\nPrivateKey = AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=\nAddress = 10.44.0.3/32\nDNS = 192.0.2.1, 1.1.1.1\n\n[Peer]\nPublicKey = pLnfn9hJm8k6Dzld7mZnlfonFug3wy9iOkrFZPdcWRM=\nPresharedKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nAllowedIPs = 0.0.0.0/0\nEndpoint = waterwall.example.com:51820\nPersistentKeepalive = 25\n";
    NSDictionary *result = [SRPWaterWallChainConfig wireGuardConfigurationWithConfig:config];
    XCTAssertNotNil(result);
    XCTAssertEqualObjects(result[@"tunnelAddress"], @"10.44.0.3");
    XCTAssertEqualObjects(result[@"dnsServers"], (@[@"192.0.2.1", @"1.1.1.1"]));
    NSDictionary *root = [NSJSONSerialization JSONObjectWithData:[result[@"nodesJSON"] dataUsingEncoding:NSUTF8StringEncoding]
                                                        options:0 error:nil];
    NSDictionary *wg = root[@"nodes"][1];
    XCTAssertEqualObjects(wg[@"type"], @"WireGuardDevice");
    XCTAssertNil(root[@"nodes"][2][@"next"]);
    XCTAssertEqualObjects(wg[@"settings"][@"privatekey"], @"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=");
    XCTAssertEqualObjects(wg[@"settings"][@"peers"][0][@"publickey"], @"pLnfn9hJm8k6Dzld7mZnlfonFug3wy9iOkrFZPdcWRM=");
    XCTAssertEqualObjects(wg[@"settings"][@"peers"][0][@"presharedkey"], @"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
    XCTAssertEqualObjects(wg[@"settings"][@"peers"][0][@"persistentkeepalive"], @25);
}

- (void)testWaterWallVMessComposableGraphAndCredentials {
    NSMutableDictionary *configuration = [[self waterWallConfigurationWithApplication:@"vmess" mux:YES outer:@"tls"] mutableCopy];
    configuration[@"http"] = @"websocket";
    configuration[@"http-version"] = @1;
    configuration[@"node-options"] = @{@"application": @{@"security": @"chacha20-poly1305"}};
    XCTAssertNil([SRPWaterWallChainConfig validationErrorForConfiguration:configuration]);
    XCTAssertEqualObjects([SRPWaterWallChainConfig summaryForConfiguration:configuration], @"VMess + MUX + WebSocket + TLS");

    NSString *uuid = @"5783a3e7-e373-51cd-8642-c83782b807c5";
    NSString *json = [SRPWaterWallChainConfig nodesJSONForConfiguration:configuration
                                                               server:@"waterwall.example.com" port:443 sni:nil
                                                            verifyTLS:YES secret:uuid outerSecret:nil options:nil];
    NSArray *nodes = [self waterWallJSONObject:json][@"nodes"];
    XCTAssertEqualObjects([nodes valueForKey:@"type"], (@[@"NEPacketDevice", @"PacketsToConnection", @"VmessClient", @"Router",
                                                           @"MuxClient", @"HttpClient", @"TlsClient", @"TcpConnector"]));
    XCTAssertEqualObjects(nodes[2][@"settings"][@"uuid"], uuid);
    XCTAssertEqualObjects(nodes[2][@"settings"][@"security"], @"chacha20-poly1305");
    XCTAssertEqualObjects(nodes[2][@"settings"][@"protocol"], @"dest_context->protocol");
    XCTAssertEqualObjects(nodes[3][@"next"], @"vmess");
    XCTAssertEqualObjects(nodes[4][@"next"], @"http");
    XCTAssertEqualObjects(nodes[6][@"settings"][@"alpns"], (@[@"http/1.1"]));

    XCTAssertNil([SRPWaterWallChainConfig validationErrorForApplicationSecret:uuid forConfiguration:configuration]);
    XCTAssertNil([SRPWaterWallChainConfig validationErrorForApplicationSecret:@"waterwall" forConfiguration:configuration]);
    XCTAssertNotNil([SRPWaterWallChainConfig validationErrorForApplicationSecret:[@"" stringByPaddingToLength:31 withString:@"x" startingAtIndex:0]
                                                              forConfiguration:configuration]);
    XCTAssertNotNil([SRPWaterWallChainConfig validationErrorForApplicationSecret:@"" forConfiguration:configuration]);
}

- (void)testWaterWallVMessSecurityAndFramingValidation {
    for (NSString *security in @[@"aes-128-gcm", @"chacha20-poly1305", @"auto", @"none"]) {
        NSDictionary *configuration = [self waterWallConfigurationWithInput:@"connections" application:@"vmess" mux:NO outer:@"tls"
                                                                nodeOptions:@{@"application": @{@"security": security}}];
        XCTAssertNil([SRPWaterWallChainConfig validationErrorForConfiguration:configuration], @"%@", security);
    }
    NSDictionary *padding = [self waterWallConfigurationWithInput:@"connections" application:@"vmess" mux:NO outer:@"tls"
                                                      nodeOptions:@{@"application": @{@"global-padding": @YES}}];
    XCTAssertNil([SRPWaterWallChainConfig validationErrorForConfiguration:padding]);

    NSArray *invalidApplications = @[
        @{@"security": @"unknown"}, @{@"security": @"zero"},
        @{@"security": @"zero", @"protocol": @"udp"},
        @{@"security": @"aes-128-gcm", @"global-padding": @YES, @"chunk-masking": @NO},
        @{@"security": @"none", @"authenticated-length": @YES},
        @{@"security": @"zero", @"protocol": @"tcp", @"chunk-masking": @YES},
        @{@"packet-encoding": @"packetaddr"},
        @{@"encrypted-counter-policy": @"invalid"},
        @{@"packet-encoding": @"invalid"}
    ];
    for (NSDictionary *application in invalidApplications) {
        NSDictionary *configuration = [self waterWallConfigurationWithInput:@"connections" application:@"vmess" mux:NO outer:@"tls"
                                                                nodeOptions:@{@"application": application}];
        XCTAssertNotNil([SRPWaterWallChainConfig validationErrorForConfiguration:configuration], @"%@", application);
    }
    NSDictionary *zeroTCP = [self waterWallConfigurationWithInput:@"connections" application:@"vmess" mux:NO outer:@"tls"
                                                      nodeOptions:@{@"application": @{@"security": @"zero", @"protocol": @"tcp"}}];
    XCTAssertNil([SRPWaterWallChainConfig validationErrorForConfiguration:zeroTCP]);
    NSDictionary *packetaddr = [self waterWallConfigurationWithInput:@"connections" application:@"vmess" mux:NO outer:@"tls"
                                                         nodeOptions:@{@"application": @{@"packet-encoding": @"packetaddr",
                                                                                        @"domain-strategy": @"resolve-domains-and-prefer-ipv4"}}];
    XCTAssertNil([SRPWaterWallChainConfig validationErrorForConfiguration:packetaddr]);
}

- (void)testWaterWallSOCKS5AndHTTPProxyApplications {
    NSDictionary *socks = [self waterWallConfigurationWithApplication:@"socks5" mux:NO outer:@"none"];
    NSString *json = [SRPWaterWallChainConfig nodesJSONForConfiguration:socks
                                                                server:@"proxy.example.com"
                                                                  port:11080
                                                                   sni:nil
                                                             verifyTLS:YES
                                                                secret:@"test-password"
                                                           outerSecret:nil
                                                               options:@{@"username": @"test-user"}];
    NSDictionary *byName = [self waterWallNodesByName:[self waterWallJSONObject:json][@"nodes"]];
    XCTAssertEqualObjects(byName[@"ptc"][@"next"], @"router");
    XCTAssertEqualObjects(byName[@"socks5"][@"type"], @"Socks5Client");
    XCTAssertEqualObjects(byName[@"socks5"][@"settings"][@"address"], @"dest_context->address");
    XCTAssertEqualObjects(byName[@"socks5"][@"settings"][@"port"], @"dest_context->port");
    XCTAssertEqualObjects(byName[@"socks5"][@"settings"][@"protocol"], @"dest_context->protocol");
    XCTAssertEqualObjects(byName[@"socks5"][@"settings"][@"user"], @"test-user");
    XCTAssertEqualObjects(byName[@"socks5"][@"settings"][@"pass"], @"test-password");
    XCTAssertEqualObjects(byName[@"connector"][@"type"], @"TcpUdpConnector");
    XCTAssertEqualObjects(byName[@"connector"][@"settings"][@"address"], @"proxy.example.com");
    XCTAssertNil([SRPWaterWallChainConfig validationErrorForApplicationUsername:nil secret:nil forConfiguration:socks]);
    XCTAssertNotNil([SRPWaterWallChainConfig validationErrorForApplicationUsername:@"user" secret:nil forConfiguration:socks]);
    XCTAssertNotNil([SRPWaterWallChainConfig validationErrorForApplicationUsername:nil secret:@"password" forConfiguration:socks]);

    NSDictionary *http = [self waterWallConfigurationWithApplication:@"http-proxy" mux:NO outer:@"tls"];
    json = [SRPWaterWallChainConfig nodesJSONForConfiguration:http
                                                      server:@"proxy.example.com"
                                                        port:8088
                                                         sni:@"proxy.example.com"
                                                   verifyTLS:YES
                                                      secret:@"test-password"
                                                 outerSecret:nil
                                                     options:@{@"username": @"test-user"}];
    byName = [self waterWallNodesByName:[self waterWallJSONObject:json][@"nodes"]];
    XCTAssertEqualObjects(byName[@"http-proxy"][@"type"], @"HttpProxyClient");
    XCTAssertEqualObjects(byName[@"http-proxy"][@"settings"][@"mode"], @"connect");
    XCTAssertEqualObjects(byName[@"http-proxy"][@"settings"][@"target-address"], @"dest_context->address");
    XCTAssertEqualObjects(byName[@"http-proxy"][@"settings"][@"username"], @"test-user");
    XCTAssertEqualObjects(byName[@"http-proxy"][@"settings"][@"password"], @"test-password");
    XCTAssertEqualObjects(byName[@"http-proxy"][@"next"], @"tls");
    XCTAssertEqualObjects(byName[@"connector"][@"type"], @"TcpConnector");
    XCTAssertNil([SRPWaterWallChainConfig validationErrorForApplicationUsername:@"user" secret:@"password" forConfiguration:http]);
    XCTAssertNotNil([SRPWaterWallChainConfig validationErrorForApplicationUsername:@"bad:user" secret:@"password" forConfiguration:http]);
    XCTAssertNotNil([SRPWaterWallChainConfig validationErrorForApplicationUsername:@"user" secret:@"bad\npassword" forConfiguration:http]);

    for (NSString *application in @[@"socks5", @"http-proxy"]) {
        NSMutableDictionary *invalid = [[self waterWallConfigurationWithApplication:application mux:YES outer:@"tls"] mutableCopy];
        XCTAssertNotNil([SRPWaterWallChainConfig validationErrorForConfiguration:invalid]);
        invalid[@"mux"] = @NO;
        invalid[@"http"] = @"http";
        XCTAssertNotNil([SRPWaterWallChainConfig validationErrorForConfiguration:invalid]);
        invalid[@"http"] = @"off";
        invalid[@"carrier"] = @"kcp";
        XCTAssertNotNil([SRPWaterWallChainConfig validationErrorForConfiguration:invalid]);
    }
    NSMutableDictionary *quic = [[self waterWallConfigurationWithApplication:@"http-proxy" mux:NO outer:@"quic"] mutableCopy];
    XCTAssertNotNil([SRPWaterWallChainConfig validationErrorForConfiguration:quic]);
    quic[@"quic-carrier"] = @"stream";
    XCTAssertNil([SRPWaterWallChainConfig validationErrorForConfiguration:quic]);
    XCTAssertEqualObjects([SRPWaterWallChainConfig summaryForConfiguration:socks], @"SOCKS5 + none");
    XCTAssertEqualObjects([SRPWaterWallChainConfig summaryForConfiguration:http], @"HTTP CONNECT + TLS");
}

- (void)testProfileLatencyEndpoints {
    NSArray<NSURL *> *urls = SRPProfileLatencyTester.endpointURLs;
    XCTAssertEqual(urls.count, 2u);
    XCTAssertEqualObjects(urls[0].absoluteString, @"https://gstatic.com/generate_204");
    XCTAssertEqualObjects(urls[1].absoluteString, @"https://connectivitycheck.gstatic.com/generate_204");
}

- (void)testProfileLatencyFormattingAndFailures {
    XCTAssertEqualObjects([SRPProfileLatencyTester textForMilliseconds:123.4], @"Ping: 123 ms");
    NSError *timeout = [NSError errorWithDomain:NSURLErrorDomain code:NSURLErrorTimedOut userInfo:nil];
    NSError *certificate = [NSError errorWithDomain:NSURLErrorDomain code:NSURLErrorServerCertificateUntrusted userInfo:nil];
    XCTAssertEqualObjects([SRPProfileLatencyTester textForFailure:timeout], @"Timeout");
    XCTAssertEqualObjects([SRPProfileLatencyTester textForFailure:certificate], @"Failed");
    XCTAssertEqualObjects([SRPProfileLatencyTester textForFailure:nil], @"Failed");
}

- (void)testProfileLatencyRequiresAnHTTPS204Response {
    NSURL *url = SRPProfileLatencyTester.endpointURLs.firstObject;
    NSHTTPURLResponse *noContent = [[NSHTTPURLResponse alloc] initWithURL:url statusCode:204 HTTPVersion:@"HTTP/2" headerFields:nil];
    NSHTTPURLResponse *ok = [[NSHTTPURLResponse alloc] initWithURL:url statusCode:200 HTTPVersion:@"HTTP/2" headerFields:nil];
    NSError *timeout = [NSError errorWithDomain:NSURLErrorDomain code:NSURLErrorTimedOut userInfo:nil];
    XCTAssertTrue([SRPProfileLatencyTester isSuccessfulResponse:noContent error:nil]);
    XCTAssertFalse([SRPProfileLatencyTester isSuccessfulResponse:ok error:nil]);
    XCTAssertFalse([SRPProfileLatencyTester isSuccessfulResponse:noContent error:timeout]);
    XCTAssertFalse([SRPProfileLatencyTester isSuccessfulResponse:nil error:nil]);
}

- (void)testWaterWallBGP4UsesTheRegisteredOuterChain {
    NSDictionary *configuration = [self waterWallConfigurationWithApplication:@"vless" mux:NO outer:@"bgp4"];
    XCTAssertNil([SRPWaterWallChainConfig validationErrorForConfiguration:configuration]);
    XCTAssertFalse([SRPWaterWallChainConfig configurationUsesTLS:configuration]);
    XCTAssertFalse([SRPWaterWallChainConfig configurationNeedsOuterSecret:configuration]);
    XCTAssertEqualObjects([SRPWaterWallChainConfig summaryForConfiguration:configuration], @"VLESS + BGP4");

    NSDictionary *root = [self waterWallRootForConfiguration:configuration options:@{@"ww_smart_routing": @YES}];
    NSDictionary *byName = [self waterWallNodesByName:root[@"nodes"]];
    XCTAssertEqualObjects(byName[@"ptc"][@"next"], @"router");
    XCTAssertEqualObjects(byName[@"ptc"][@"settings"][@"fake-dns"][@"enabled"], @YES);
    XCTAssertEqualObjects(byName[@"ptc"][@"settings"][@"fake-dns"][@"address"], @"198.18.0.2");
    XCTAssertEqualObjects(byName[@"router"][@"settings"][@"resolve-domains"], @NO);
    XCTAssertEqualObjects(byName[@"router"][@"next"], @"vless");
    XCTAssertEqualObjects(byName[@"vless"][@"next"], @"bgp4");
    XCTAssertEqualObjects(byName[@"bgp4"][@"type"], @"Bgp4Client");
    XCTAssertEqualObjects(byName[@"bgp4"][@"next"], @"connector");
    XCTAssertEqualObjects(byName[@"connector"][@"type"], @"TcpConnector");
    XCTAssertNil(byName[@"bgp4"][@"settings"][@"sni"]);
    XCTAssertNil(byName[@"bgp4"][@"settings"][@"verify"]);
    XCTAssertNil(byName[@"bgp4"][@"settings"][@"password"]);
    XCTAssertEqual([byName[@"router"][@"settings"][@"rules"] count], 1u);

    root = [self waterWallRootForConfiguration:configuration options:nil];
    byName = [self waterWallNodesByName:root[@"nodes"]];
    XCTAssertEqualObjects(byName[@"ptc"][@"next"], @"router");
    XCTAssertEqualObjects(byName[@"router"][@"next"], @"vless");
    XCTAssertNil(byName[@"router"][@"settings"][@"rules"]);
    XCTAssertNil(byName[@"direct-local"]);

    root = [self waterWallRootForConfiguration:configuration options:@{@"ww_fake_dns": @NO}];
    byName = [self waterWallNodesByName:root[@"nodes"]];
    XCTAssertNil(byName[@"ptc"][@"settings"][@"fake-dns"]);

    NSMutableDictionary *kcp = [configuration mutableCopy];
    kcp[@"carrier"] = @"kcp";
    root = [self waterWallRootForConfiguration:kcp options:nil];
    byName = [self waterWallNodesByName:root[@"nodes"]];
    XCTAssertEqualObjects(byName[@"bgp4"][@"next"], @"kcp");
    XCTAssertEqualObjects(byName[@"kcp"][@"type"], @"TcpOverUdpClient");
    XCTAssertEqualObjects(byName[@"connector"][@"type"], @"UdpConnector");
    XCTAssertEqualObjects([SRPWaterWallChainConfig summaryForConfiguration:kcp], @"VLESS + BGP4 + KCP");
}

- (void)testWaterWallBGP4IndependentComposition {
    NSMutableDictionary *configuration = [[self waterWallConfigurationWithApplication:@"vless" mux:NO outer:@"tls"] mutableCopy];
    configuration[@"bgp4"] = @YES;
    configuration[@"carrier"] = @"kcp";
    XCTAssertNil([SRPWaterWallChainConfig validationErrorForConfiguration:configuration]);
    XCTAssertEqualObjects([SRPWaterWallChainConfig summaryForConfiguration:configuration], @"VLESS + BGP4 + TLS + KCP");
    NSString *json = [SRPWaterWallChainConfig JSONWithConfiguration:configuration];
    XCTAssertEqualObjects([SRPWaterWallChainConfig configurationWithJSON:json][@"bgp4"], @YES);
    NSDictionary *byName = [self waterWallNodesByName:[self waterWallRootForConfiguration:configuration options:nil][@"nodes"]];
    XCTAssertEqualObjects(byName[@"vless"][@"next"], @"bgp4");
    XCTAssertEqualObjects(byName[@"bgp4"][@"type"], @"Bgp4Client");
    XCTAssertEqualObjects(byName[@"bgp4"][@"next"], @"tls");
    XCTAssertEqualObjects(byName[@"tls"][@"next"], @"kcp");
    XCTAssertEqualObjects(byName[@"connector"][@"type"], @"UdpConnector");
    XCTAssertEqual([byName.allValues filteredArrayUsingPredicate:[NSPredicate predicateWithBlock:^BOOL(NSDictionary *node, NSDictionary *bindings) {
        (void)bindings;
        return [node[@"type"] isEqualToString:@"Bgp4Client"];
    }]].count, 1u);

    configuration[@"outer"] = @"bgp4";
    byName = [self waterWallNodesByName:[self waterWallRootForConfiguration:configuration options:nil][@"nodes"]];
    XCTAssertEqual([byName.allValues filteredArrayUsingPredicate:[NSPredicate predicateWithBlock:^BOOL(NSDictionary *node, NSDictionary *bindings) {
        (void)bindings;
        return [node[@"type"] isEqualToString:@"Bgp4Client"];
    }]].count, 1u);

    configuration[@"outer"] = @"quic";
    configuration[@"carrier"] = @"tcp";
    configuration[@"quic-carrier"] = @"datagram";
    XCTAssertNotNil([SRPWaterWallChainConfig validationErrorForConfiguration:configuration]);
    configuration[@"quic-carrier"] = @"stream";
    XCTAssertNil([SRPWaterWallChainConfig validationErrorForConfiguration:configuration]);
    byName = [self waterWallNodesByName:[self waterWallRootForConfiguration:configuration options:nil][@"nodes"]];
    XCTAssertEqualObjects(byName[@"bgp4"][@"next"], @"quic");
    configuration[@"mode"] = @"direct";
    XCTAssertEqualObjects(configuration[@"mode"], @"direct");
    XCTAssertEqualObjects(configuration[@"bgp4"], @YES);
    XCTAssertNotNil([SRPWaterWallChainConfig validationErrorForConfiguration:configuration]);
    configuration[@"mode"] = @"wireguard";
    XCTAssertEqualObjects(configuration[@"mode"], @"wireguard");
    XCTAssertEqualObjects(configuration[@"bgp4"], @YES);
    XCTAssertNotNil([SRPWaterWallChainConfig validationErrorForConfiguration:configuration]);
    configuration[@"bgp4"] = @1;
    XCTAssertEqualObjects(configuration[@"bgp4"], @1);
    XCTAssertNotNil([SRPWaterWallChainConfig validationErrorForConfiguration:configuration]);
}

#if TARGET_OS_IPHONE
- (BOOL)waitForLiveVPNConnection:(PDVPNManager *)manager server:(NSDictionary *)server error:(NSString **)error {
    __block BOOL issuedStart = NO;
    NSUserDefaults *shared = [[NSUserDefaults alloc] initWithSuiteName:@"group.tr.com.srp.vpn"];
    NSDate *startedAt = NSDate.date;
    XCTNSNotificationExpectation *stateChange =
        [[XCTNSNotificationExpectation alloc] initWithName:@"kApplicationVPNStatusDidChangeNotification" object:nil];
    stateChange.handler = ^BOOL(NSNotification *notification) {
        (void)notification;
        if (!issuedStart) return NO;
        if (manager.status == YDVPNStatusConnected) return YES;
        if (manager.status != YDVPNStatusDisconnected) return NO;
        NSDate *date = [shared objectForKey:@"SRPLastError"][@"date"];
        return [date isKindOfClass:NSDate.class] && [date compare:startedAt] != NSOrderedAscending;
    };
    issuedStart = YES;
    if (![manager connectUsing:server auth:^(YDUnsafeAuthResponse response) {
        if (response) response(NO);
    }]) {
        if (error) *error = @"The app rejected the generated profile.";
        return NO;
    }
    [self waitForExpectations:@[stateChange] timeout:90];
    if (manager.status == YDVPNStatusConnected) return YES;
    if (error) {
        NSString *message = [shared objectForKey:@"SRPLastError"][@"message"];
        *error = message ?: @"Connection status timed out";
    }
    [manager disconnect];
    return NO;
}

- (void)waitForLiveVPNDisconnect:(PDVPNManager *)manager {
    [manager disconnect];
    if (manager.status == YDVPNStatusDisconnected) return;
    XCTNSNotificationExpectation *stateChange =
        [[XCTNSNotificationExpectation alloc] initWithName:@"kApplicationVPNStatusDidChangeNotification" object:nil];
    stateChange.handler = ^BOOL(NSNotification *notification) {
        (void)notification;
        return manager.status == YDVPNStatusDisconnected;
    };
    [self waitForExpectations:@[stateChange] timeout:30];
}

- (BOOL)performLiveStressDownloads:(PDVPNManager *)manager environment:(NSDictionary *)environment {
    long long stressBytes = [environment[@"SRP_WW_STRESS_BYTES"] longLongValue];
    if (stressBytes <= 0) return YES;
    NSString *urlString = environment[@"SRP_WW_STRESS_URL"];
    NSUInteger connections = [environment[@"SRP_WW_STRESS_CONNECTIONS"] integerValue] ?: 4;
    if (urlString.length == 0 || connections < 1 || connections > 8 || stressBytes > 512 * 1024 * 1024) return NO;
    NSURL *baseURL = [NSURL URLWithString:urlString];
    XCTestExpectation *load = [self expectationWithDescription:@"Parallel live downloads"];
    load.expectedFulfillmentCount = connections;
    __block unsigned long long downloaded = 0;
    __block NSMutableArray<NSString *> *errors = [NSMutableArray new];
    NSLock *resultsLock = [NSLock new];
    NSURLSessionConfiguration *configuration = NSURLSessionConfiguration.ephemeralSessionConfiguration;
    configuration.HTTPMaximumConnectionsPerHost = connections;
    configuration.timeoutIntervalForResource = 120;
    NSURLSession *session = [NSURLSession sessionWithConfiguration:configuration];
    id lostObserver = [NSNotificationCenter.defaultCenter addObserverForName:@"kApplicationVPNStatusDidChangeNotification"
                                                                      object:nil
                                                                       queue:nil
                                                                  usingBlock:^(NSNotification *notification) {
        (void)notification;
        if (manager.status == YDVPNStatusDisconnected) [session invalidateAndCancel];
    }];
    for (NSUInteger index = 0; index < connections; index++) {
        NSURLComponents *components = [NSURLComponents componentsWithURL:baseURL resolvingAgainstBaseURL:NO];
        components.queryItems = [components.queryItems ?: @[] arrayByAddingObject:
            [NSURLQueryItem queryItemWithName:@"srp-live" value:@(index).stringValue]];
        [[session downloadTaskWithURL:components.URL completionHandler:^(NSURL *location, NSURLResponse *response, NSError *error) {
            unsigned long long size = [(NSNumber *)[NSFileManager.defaultManager attributesOfItemAtPath:location.path error:nil][NSFileSize] unsignedLongLongValue];
            NSInteger statusCode = [response isKindOfClass:NSHTTPURLResponse.class] ? ((NSHTTPURLResponse *)response).statusCode : 0;
            NSLog(@"Live download %lu: %llu bytes, HTTP %ld, error: %@",
                  (unsigned long)index, size, (long)statusCode, error.localizedDescription ?: @"none");
            [resultsLock lock];
            downloaded += size;
            if (error != nil) [errors addObject:error.localizedDescription];
            else if (statusCode != 200) [errors addObject:[NSString stringWithFormat:@"HTTP %ld", (long)statusCode]];
            else if (size < (unsigned long long)stressBytes) [errors addObject:@"Short download"];
            [resultsLock unlock];
            [load fulfill];
        }] resume];
    }
    [self waitForExpectations:@[load] timeout:180];
    [NSNotificationCenter.defaultCenter removeObserver:lostObserver];
    [session invalidateAndCancel];
    if (manager.status != YDVPNStatusConnected || errors.count > 0) {
        NSLog(@"Live stress failed: %@; downloaded=%llu, status=%ld", errors, downloaded, (long)manager.status);
        return NO;
    }
    return downloaded >= (unsigned long long)(stressBytes * (long long)connections);
}

- (BOOL)runLiveConnectionRoundsForModel:(NodeModel *)model manager:(PDVPNManager *)manager environment:(NSDictionary *)environment {
    NSUInteger rounds = MAX(1, [environment[@"SRP_STRESS_ROUNDS"] integerValue] ?: 3);
    for (NSUInteger connectionRound = 0; connectionRound < rounds; connectionRound++) {
        NSLog(@"Live connection round %lu/%lu starting", (unsigned long)(connectionRound + 1), (unsigned long)rounds);
        NSString *error = nil;
        if (![self waitForLiveVPNConnection:manager server:[CheckConnectData checkConnectParmer:model] error:&error]) {
            NSLog(@"Live connection failed: %@", error);
            return NO;
        }
        for (NSUInteger downloadRound = 0; downloadRound < rounds; downloadRound++) {
            if (![self waterWallLiveHTTPS204:model] || ![self performLiveStressDownloads:manager environment:environment] ||
                ![self waterWallLiveHTTPS204:model]) {
                [self waitForLiveVPNDisconnect:manager];
                return NO;
            }
            NSLog(@"Live connection %lu, download round %lu passed; VPN remains connected",
                  (unsigned long)(connectionRound + 1), (unsigned long)(downloadRound + 1));
        }
        [self waitForLiveVPNDisconnect:manager];
        if (manager.status != YDVPNStatusDisconnected) {
            NSLog(@"Live disconnect failed after connection %lu", (unsigned long)(connectionRound + 1));
            return NO;
        }
    }
    NSLog(@"Live stress finished: %lu connections, %lu download rounds per connection",
          (unsigned long)rounds, (unsigned long)rounds);
    return YES;
}

- (BOOL)waterWallLiveHTTPS204:(NodeModel *)model {
    XCTestExpectation *expectation = [self expectationWithDescription:@"HTTPS 204 through WaterWall"];
    __block NSString *result;
    SRPProfileLatencyTester *tester = [SRPProfileLatencyTester new];
    [tester measureProfile:model update:^(NSString *nodeID, NSString *text) {
        (void)nodeID;
        result = text;
    } finished:^{
        [expectation fulfill];
    }];
    [self waitForExpectations:@[expectation] timeout:35];
    return [result hasPrefix:@"Ping:"];
}

- (void)testWaterWallLiveConnectionAndThroughputWhenConfigured {
    NSDictionary *environment = NSProcessInfo.processInfo.environment;
    if (![environment[@"SRP_BGP4_LIVE_TEST"] isEqualToString:@"1"]) return;
    NSString *address = environment[@"SRP_BGP4_SERVER"];
    NSString *port = environment[@"SRP_BGP4_PORT"];
    NSString *uuid = environment[@"SRP_BGP4_UUID"];
    NSString *carrier = environment[@"SRP_BGP4_CARRIER"] ?: @"tcp";
    NSString *application = environment[@"SRP_WW_APPLICATION"] ?: @"vless";
    NSString *outer = environment[@"SRP_WW_OUTER"] ?: @"bgp4";
    if (address.length == 0 || uuid.length == 0 || port.integerValue < 1 || port.integerValue > 65535 ||
        ![@[@"tcp", @"kcp"] containsObject:carrier] || ![@[@"vless", @"vmess"] containsObject:application] ||
        ![@[@"none", @"tls", @"bgp4"] containsObject:outer]) {
        XCTFail(@"Live testing requires valid server, UUID, application, outer and carrier settings.");
        return;
    }
    PDVPNManager *manager = PDVPNManager.sharedManager;
    if (manager.status == YDVPNStatusConnected || manager.status == YDVPNStatusConnecting ||
        manager.status == YDVPNStatusDisconnecting) {
        XCTSkip(@"An existing VPN connection must be disconnected before running this test.");
    }

    NodeModel *model = [NodeModel new];
    model.protocolType = @"waterwall";
    model.nodeId = @"live-waterwall-test";
    model.desc = @"WaterWall live test";
    model.server = address;
    model.port = port;
    model.password = uuid;
    model.customSni = environment[@"SRP_WW_SNI"];
    model.TLS = [environment[@"SRP_WW_INSECURE"] boolValue];
    model.logLevel = 2;
    model.waterwallFakeDNS = YES;
    model.waterwallSmartRouting = YES;
    NSDictionary *nodeOptions = @{};
    NSString *nodeOptionsJSON = environment[@"SRP_WW_NODE_OPTIONS"];
    if (nodeOptionsJSON.length > 0) {
        NSError *parseError = nil;
        id parsed = [NSJSONSerialization JSONObjectWithData:[nodeOptionsJSON dataUsingEncoding:NSUTF8StringEncoding]
                                                    options:0
                                                      error:&parseError];
        if (![parsed isKindOfClass:NSDictionary.class]) {
            XCTFail(@"Invalid SRP_WW_NODE_OPTIONS: %@", parseError);
            return;
        }
        nodeOptions = parsed;
    }
    model.waterwallConfigJSON = [SRPWaterWallChainConfig JSONWithConfiguration:@{
        @"version": @3, @"mode": @"chain", @"input": @"connections", @"application": application,
        @"mux": @NO, @"outer": outer, @"http": @"off", @"http-version": @1,
        @"obfuscator": @NO, @"carrier": carrier, @"quic-carrier": @"datagram", @"node-options": nodeOptions,
        @"bgp4": @([environment[@"SRP_WW_BGP4"] boolValue])
    }];
    XCTAssertTrue([self runLiveConnectionRoundsForModel:model manager:manager environment:environment]);
}

- (void)testAetherLiveConnectionAndThroughputWhenConfigured {
    NSDictionary *environment = NSProcessInfo.processInfo.environment;
    if (![environment[@"SRP_AETHER_LIVE_TEST"] isEqualToString:@"1"]) return;
    PDVPNManager *manager = PDVPNManager.sharedManager;
    if (manager.status == YDVPNStatusConnected || manager.status == YDVPNStatusConnecting ||
        manager.status == YDVPNStatusDisconnecting) {
        XCTSkip(@"An existing VPN connection must be disconnected before running this test.");
    }
    NodeModel *model = [NodeModel new];
    model.protocolType = @"aether";
    model.nodeId = @"live-aether-test";
    model.desc = @"Aether live test";
    model.server = @"public";
    model.port = @"443";
    model.aetherMode = @"public";
    model.aetherTransport = environment[@"SRP_AETHER_TRANSPORT"] ?: @"masque";
    model.aetherScan = environment[@"SRP_AETHER_SCAN"] ?: @"balanced";
    model.aetherTor = @"off";
    model.logLevel = 2;
    XCTAssertTrue([self runLiveConnectionRoundsForModel:model manager:manager environment:environment]);
}

- (void)testAetherIngressBackpressurePreservesPackets {
    int sockets[2];
    XCTAssertEqual(socketpair(AF_UNIX, SOCK_DGRAM, 0, sockets), 0);
    int bufferSize = 32 * 1024;
    XCTAssertEqual(setsockopt(sockets[0], SOL_SOCKET, SO_SNDBUF, &bufferSize, sizeof(bufferSize)), 0);
    XCTAssertEqual(fcntl(sockets[0], F_SETFL, O_NONBLOCK), 0);
    SRPAetherClient *client = [SRPAetherClient new];
    [client setValue:@(sockets[0]) forKey:@"tunFd"];
    NSMutableArray<NSData *> *packets = [NSMutableArray new];
    for (NSUInteger index = 0; index < 128; index++) {
        uint8_t bytes[1400] = {0};
        memset(bytes, (int)(index % 251), sizeof(bytes));
        bytes[0] = 0x45;
        [packets addObject:[NSData dataWithBytes:bytes length:sizeof(bytes)]];
    }
    __block BOOL completed = NO;
    XCTestExpectation *completion = [self expectationWithDescription:@"The socket accepts the complete batch"];
    [client injectPackets:packets completion:^{
        completed = YES;
        [completion fulfill];
    }];
    XCTestExpectation *blocked = [self expectationWithDescription:@"Backpressure pauses packetFlow"];
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 200 * NSEC_PER_MSEC), dispatch_get_main_queue(), ^{
        XCTAssertFalse(completed);
        [blocked fulfill];
    });
    [self waitForExpectations:@[blocked] timeout:2];
    NSMutableData *received = [NSMutableData new];
    int readFD = sockets[1];
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        uint8_t bytes[65535];
        while (received.length < packets.count * 1404) {
            ssize_t count = read(readFD, bytes, sizeof(bytes));
            if (count > 0) [received appendBytes:bytes length:(NSUInteger)count];
        }
    });
    [self waitForExpectations:@[completion] timeout:5];
    XCTAssertTrue(completed);
    XCTAssertEqual(received.length, packets.count * 1404);
    for (NSUInteger index = 0; index < packets.count; index++) {
        NSData *packet = [received subdataWithRange:NSMakeRange(index * 1404 + 4, 1400)];
        XCTAssertEqualObjects(packet, packets[index], @"Packet %lu", (unsigned long)index);
    }
    [client closeAndWait];
    close(sockets[1]);
}

- (void)testProfileLatencyCardLayout {
    Class viewClass = NSClassFromString(@"HomeProtocolView");
    XCTAssertNotNil(viewClass);
    for (NSNumber *width in @[@320, @390, @1024]) {
        HomeProtocolView *cell = [[viewClass alloc] initWithStyle:UITableViewCellStyleDefault reuseIdentifier:nil];
        cell.frame = CGRectMake(0, 0, width.doubleValue, 140);
        [cell configureWithTitle:@"Test profile"
                        subtitle:@"server.example.com:443"
                           badge:@"AmneziaWG VPN"
                         latency:@"Ping: 123 ms"
                        selected:NO];
        [cell setNeedsLayout];
        [cell layoutIfNeeded];
        UILabel *badge = SRPLatencyLabel(cell.contentView, @"AmneziaWG VPN");
        UILabel *latency = SRPLatencyLabel(cell.contentView, @"Ping: 123 ms");
        XCTAssertNotNil(badge);
        XCTAssertNotNil(latency);
        XCTAssertEqualWithAccuracy(badge.intrinsicContentSize.width, badge.bounds.size.width, 0.5);
        XCTAssertLessThanOrEqual(CGRectGetMaxY(badge.frame), CGRectGetMinY(latency.frame));
        XCTAssertLessThanOrEqual(CGRectGetMaxX(latency.frame), CGRectGetWidth(cell.contentView.bounds));
    }
}

- (void)testGeoIPCountryScreenSearchAndMultipleSelection {
    Class viewClass = NSClassFromString(@"SRPGeoIPCountryViewController");
    XCTAssertNotNil(viewClass);
    __block NSSet<NSString *> *selected = nil;
    __block BOOL enabled = NO;
    id controller = [[viewClass alloc] initWithSelectedCodes:[NSSet set]
                                                geoIPEnabled:NO
                                           enabledDidChange:^BOOL(BOOL value) {
        enabled = value;
        return YES;
    }
                                                  completion:^(NSSet<NSString *> *codes) {
        selected = codes;
    }];
    [controller loadViewIfNeeded];
    UITableView *table = [controller tableView];
    XCTAssertEqual([controller tableView:table numberOfRowsInSection:0], (NSInteger)1);
    XCTAssertGreaterThan([controller tableView:table numberOfRowsInSection:1], (NSInteger)200);
    XCTAssertNotNil([controller navigationItem].rightBarButtonItem);

    UITableViewCell *toggleCell = [controller tableView:table cellForRowAtIndexPath:[NSIndexPath indexPathForRow:0 inSection:0]];
    UISwitch *routingSwitch = (UISwitch *)toggleCell.accessoryView;
    XCTAssertFalse(routingSwitch.on);
    routingSwitch.on = YES;
    [routingSwitch sendActionsForControlEvents:UIControlEventValueChanged];
    XCTAssertTrue(enabled);
    XCTAssertEqualObjects(selected, ([NSSet setWithObject:@"IR"]));

    UISearchController *search = [controller navigationItem].searchController;
    search.searchBar.text = @"Germany";
    [controller updateSearchResultsForSearchController:search];
    XCTAssertEqual([controller tableView:table numberOfRowsInSection:1], (NSInteger)1);
    NSIndexPath *path = [NSIndexPath indexPathForRow:0 inSection:1];
    UITableViewCell *cell = [controller tableView:table cellForRowAtIndexPath:path];
    XCTAssertTrue([cell.textLabel.text containsString:@"Germany"]);
    XCTAssertTrue([cell.textLabel.text containsString:@"(DE)"]);
    [controller tableView:table didSelectRowAtIndexPath:path];
    XCTAssertEqualObjects(selected, ([NSSet setWithObjects:@"IR", @"DE", nil]));
    cell = [controller tableView:table cellForRowAtIndexPath:path];
    XCTAssertEqual(cell.accessoryType, UITableViewCellAccessoryCheckmark);

    toggleCell = [controller tableView:table cellForRowAtIndexPath:[NSIndexPath indexPathForRow:0 inSection:0]];
    routingSwitch = (UISwitch *)toggleCell.accessoryView;
    routingSwitch.on = NO;
    [routingSwitch sendActionsForControlEvents:UIControlEventValueChanged];
    XCTAssertFalse(enabled);
    XCTAssertEqual(selected.count, 0u);

    __block NSSet<NSString *> *rejectedSelection = nil;
    id rejecting = [[viewClass alloc] initWithSelectedCodes:[NSSet set]
                                               geoIPEnabled:NO
                                          enabledDidChange:^BOOL(BOOL value) {
        (void)value;
        return NO;
    }
                                                 completion:^(NSSet<NSString *> *codes) {
        rejectedSelection = codes;
    }];
    [rejecting loadViewIfNeeded];
    toggleCell = [rejecting tableView:table cellForRowAtIndexPath:[NSIndexPath indexPathForRow:0 inSection:0]];
    routingSwitch = (UISwitch *)toggleCell.accessoryView;
    routingSwitch.on = YES;
    [routingSwitch sendActionsForControlEvents:UIControlEventValueChanged];
    XCTAssertFalse(routingSwitch.on);
    XCTAssertNil(rejectedSelection);
}
#endif

- (void)testWaterWallMatrixGenerationForLocalTesting {
    NSDictionary *environment = NSProcessInfo.processInfo.environment;
    NSString *inputPath = environment[@"SRP_MATRIX_INPUT"];
    NSString *outputPath = environment[@"SRP_MATRIX_OUTPUT"];
    XCTSkipIf(inputPath.length == 0 && outputPath.length == 0,
              @"Set SRP_MATRIX_INPUT and SRP_MATRIX_OUTPUT to generate configurations with the app builder.");
    XCTAssertTrue(inputPath.length > 0 && outputPath.length > 0);
    if (inputPath.length == 0 || outputPath.length == 0) return;
    NSError *error = nil;
    NSData *input = [NSData dataWithContentsOfFile:inputPath options:0 error:&error];
    XCTAssertNotNil(input, @"%@", error);
    if (input == nil) return;
    id inputJSON = [NSJSONSerialization JSONObjectWithData:input options:0 error:&error];
    XCTAssertTrue([inputJSON isKindOfClass:NSArray.class], @"%@", error);
    if (![inputJSON isKindOfClass:NSArray.class]) return;
    NSMutableArray *results = [NSMutableArray new];
    for (id entry in (NSArray *)inputJSON) {
        XCTAssertTrue([entry isKindOfClass:NSDictionary.class]);
        if (![entry isKindOfClass:NSDictionary.class]) return;
        NSDictionary *caseInput = entry;
        NSString *nodesJSON = [SRPWaterWallChainConfig nodesJSONForConfiguration:caseInput[@"configuration"]
            server:caseInput[@"server"]
            port:[caseInput[@"port"] integerValue]
            sni:caseInput[@"sni"]
            verifyTLS:caseInput[@"verifyTLS"] == nil || [caseInput[@"verifyTLS"] boolValue]
            secret:caseInput[@"secret"]
            outerSecret:caseInput[@"outerSecret"]
            options:caseInput[@"options"]];
        XCTAssertNotNil(nodesJSON, @"Builder rejected matrix input %@", caseInput[@"configuration"]);
        if (nodesJSON == nil) return;
        NSDictionary *nodes = [NSJSONSerialization JSONObjectWithData:[nodesJSON dataUsingEncoding:NSUTF8StringEncoding]
                                                               options:0
                                                                 error:&error];
        XCTAssertNotNil(nodes, @"%@", error);
        if (nodes == nil) return;
        [results addObject:nodes];
    }
    NSData *output = [NSJSONSerialization dataWithJSONObject:results options:NSJSONWritingPrettyPrinted error:&error];
    XCTAssertNotNil(output, @"%@", error);
    if (output == nil) return;
    XCTAssertTrue([output writeToFile:outputPath options:NSDataWritingAtomic error:&error], @"%@", error);
}

@end
