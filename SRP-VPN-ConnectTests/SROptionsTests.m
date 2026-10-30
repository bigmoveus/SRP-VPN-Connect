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
#import <SRPParser/PDVPNManager.h>

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
#import "CreateVC.h"
#import "HomeProtocolView.h"
#import "SRPGeoIPCountryViewController.h"
#import "SRPAetherClient.h"
#import "SRPPsiphonClient.h"
#import "SRPWaterWallClient.h"
#import "SRPWaterWallBridge.h"
#import <SRPParser/SRPParser.h>
#import <Network/Network.h>
#import <CommonCrypto/CommonDigest.h>
#import <dispatch/data.h>
#import <fcntl.h>
#import <sys/socket.h>
#import <unistd.h>

@interface UIViewController (SRPProfileEditorTesting)
- (NSString *)validationMessage;
@end

@interface SRPWaterWallClient (SRPLifecycleTesting)
- (void)startRuntimeLocked;
- (void)stopRuntimeLocked;
- (void)handleRuntimeFailure:(NSString *)reason;
- (void)drainInjectedPacketsLocked;
- (void)submitProbePacket:(NSData *)packet;
- (void)beginDataPlaneProbe;
- (void)finishProbe;
- (void)handleProbePacket:(NSData *)packet;
- (void)startHealthMonitor;
- (void)healthProbeFailed:(NSString *)reason;
- (BOOL)runtimeCanAcceptPackets;
- (int)submitPacketToRuntime:(NSData *)packet;
@end

@interface SRPWaterWallLifecycleTestClient : SRPWaterWallClient
@property (nonatomic) NSInteger runtimeStarts;
@property (nonatomic) NSInteger runtimeStops;
@property (nonatomic) NSInteger failuresBeforeSuccess;
@property (nonatomic) NSInteger submittedPackets;
@property (nonatomic, strong) NSData *lastProbePacket;
@end

@implementation SRPWaterWallLifecycleTestClient
- (void)startRuntimeLocked {
    self.runtimeStarts++;
    if (self.runtimeStarts <= self.failuresBeforeSuccess) {
        [self handleRuntimeFailure:@"Injected runtime failure"];
        return;
    }
    [self setValue:@YES forKey:@"up"];
    [self setValue:@3 forKey:@"probeStage"];
}

- (void)stopRuntimeLocked {
    self.runtimeStops++;
}

- (BOOL)runtimeCanAcceptPackets {
    return ![[self valueForKey:@"closed"] boolValue] &&
           ![[self valueForKey:@"sleepPaused"] boolValue] &&
           [[self valueForKey:@"up"] boolValue];
}

- (int)submitPacketToRuntime:(NSData *)packet {
    (void)packet;
    self.submittedPackets++;
    return 0;
}

- (void)submitProbePacket:(NSData *)packet {
    self.lastProbePacket = packet;
    self.submittedPackets++;
}
@end

// Lifecycle tests never start a bridge; the app test bundle has no engine linkage.
__attribute__((weak)) SRPWaterWallBridge *SRPWaterWallBridgeStart(const SRPWaterWallConfig *config,
                                                                 const SRPWaterWallCallbacks *callbacks) {
    (void)callbacks;
    return (SRPWaterWallBridge *)config;
}

static int SRPTestWWSubmitResult;
static NSUInteger SRPTestWWSubmitCalls;

__attribute__((weak)) int SRPWaterWallBridgeSubmitPacket(SRPWaterWallBridge *bridge, const void *packet, size_t length) {
    (void)bridge;
    (void)packet;
    (void)length;
    SRPTestWWSubmitCalls++;
    return SRPTestWWSubmitResult;
}

__attribute__((weak)) int SRPWaterWallBridgeStop(SRPWaterWallBridge *bridge) {
    (void)bridge;
    return 0;
}

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

@interface SRPTestVPNConnection : NEVPNConnection
@property (nonatomic) NEVPNStatus status;
@end

@implementation SRPTestVPNConnection {
    NEVPNStatus _testStatus;
}

- (NEVPNStatus)status {
    return _testStatus;
}

- (void)setStatus:(NEVPNStatus)status {
    _testStatus = status;
}
@end

@interface SROptionsTests : XCTestCase <NSURLSessionDelegate>
@end

@implementation SROptionsTests

- (void)testVPNStatusUsesNotifyingConnection {
    PDVPNManager *manager = PDVPNManager.sharedManager;
    YDVPNStatus originalStatus = manager.status;
    @try {
        [manager setValue:@(YDVPNStatusConnected) forKey:@"status"];
        SRPTestVPNConnection *connection = [SRPTestVPNConnection new];
        connection.status = NEVPNStatusDisconnected;
        NSNotification *notification = [NSNotification notificationWithName:NEVPNStatusDidChangeNotification object:connection];
        [manager performSelector:@selector(connectionStatusDidChangeNotification:) withObject:notification];
        XCTAssertEqual(manager.status, YDVPNStatusDisconnected);
    } @finally {
        [manager setValue:@(originalStatus) forKey:@"status"];
    }
}

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
        XCTAssertEqualObjects(packet[@"fake-dns"][@"ttl"], @60);
        XCTAssertEqualObjects(packet[@"fake-dns"][@"cache-size"], @10000);
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
    XCTAssertEqualObjects(kcpByName[@"kcp"][@"settings"][@"kcp-send-window"], @128);
    XCTAssertEqualObjects(kcpByName[@"kcp"][@"settings"][@"kcp-recv-window"], @128);
    XCTAssertEqualObjects(kcpByName[@"kcp"][@"settings"][@"kcp-initial-cwnd"], @16);
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

    NSMutableDictionary *split = [[self waterWallConfigurationWithApplication:@"vmess" mux:NO outer:@"tls"] mutableCopy];
    split[@"http"] = @"http";
    split[@"node-options"] = @{@"http": @{@"http1-mode": @"split"}};
    json = [SRPWaterWallChainConfig nodesJSONForConfiguration:split
                                                        server:@"proxy.example.com"
                                                          port:8088
                                                           sni:@"proxy.example.com"
                                                     verifyTLS:YES
                                                        secret:@"test-password"
                                                   outerSecret:nil
                                                       options:@{}];
    byName = [self waterWallNodesByName:[self waterWallJSONObject:json][@"nodes"]];
    XCTAssertEqualObjects(byName[@"http"][@"settings"][@"http1-mode"], @"split");
    XCTAssertEqualObjects(byName[@"connector"][@"type"], @"TcpConnector");

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

- (void)testWaterWallTCPAggregateBudgetDefaults {
    NSMutableDictionary *configuration = [[self waterWallConfigurationWithApplication:@"vmess" mux:NO outer:@"none"] mutableCopy];
    NSDictionary *packet = [self waterWallNodesByName:[self waterWallRootForConfiguration:configuration options:nil][@"nodes"]][@"ptc"][@"settings"];
    XCTAssertEqualObjects(packet[@"max-pending-bytes"], @65536);
    XCTAssertEqualObjects(packet[@"max-total-pending-bytes"], @16777216);
    configuration[@"node-options"] = @{@"packet": @{@"max-pending-bytes": @8192, @"max-total-pending-bytes": @65536}};
    XCTAssertNil([SRPWaterWallChainConfig validationErrorForConfiguration:configuration]);
    packet = [self waterWallNodesByName:[self waterWallRootForConfiguration:configuration options:nil][@"nodes"]][@"ptc"][@"settings"];
    XCTAssertEqualObjects(packet[@"max-pending-bytes"], @8192);
    XCTAssertEqualObjects(packet[@"max-total-pending-bytes"], @65536);
}

#if TARGET_OS_IPHONE
- (BOOL)waitForLiveVPNManagerReady:(PDVPNManager *)manager {
    if ([manager valueForKey:@"providerManager"] == nil) [manager setupVPNManager];
    NSDate *deadline = [NSDate dateWithTimeIntervalSinceNow:30];
    while ([manager valueForKey:@"providerManager"] == nil && NSDate.date.timeIntervalSince1970 < deadline.timeIntervalSince1970) {
        [NSRunLoop.currentRunLoop runMode:NSDefaultRunLoopMode beforeDate:[NSDate dateWithTimeIntervalSinceNow:0.1]];
    }
    return [manager valueForKey:@"providerManager"] != nil;
}

- (BOOL)waitForLiveVPNConnection:(PDVPNManager *)manager server:(NSDictionary *)server error:(NSString **)error {
    if (![self waitForLiveVPNManagerReady:manager]) {
        if (error) *error = @"The Network Extension manager did not become ready";
        return NO;
    }
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
    NSTimeInterval connectionTimeout = [NSProcessInfo.processInfo.environment[@"SRP_CONNECTION_TIMEOUT"] doubleValue] ?: 90;
    [self waitForExpectations:@[stateChange] timeout:MAX(1, connectionTimeout)];
    if (manager.status == YDVPNStatusConnected) return YES;
    if (error) {
        NSDictionary *lastError = [shared objectForKey:@"SRPLastError"];
        NSDate *date = lastError[@"date"];
        NSString *message = [date isKindOfClass:NSDate.class] && [date compare:startedAt] != NSOrderedAscending
            ? lastError[@"message"] : nil;
        *error = message ?: @"Connection status timed out";
    }
    [manager disconnect];
    return NO;
}

- (BOOL)waitForLiveVPNDisconnectedStatus:(PDVPNManager *)manager timeout:(NSTimeInterval)timeout {
    NSDate *deadline = [NSDate dateWithTimeIntervalSinceNow:timeout];
    while (NSDate.date.timeIntervalSince1970 < deadline.timeIntervalSince1970) {
        if (manager.status == YDVPNStatusDisconnected) return YES;
        [NSRunLoop.currentRunLoop runMode:NSDefaultRunLoopMode beforeDate:[NSDate dateWithTimeIntervalSinceNow:0.1]];
    }
    return manager.status == YDVPNStatusDisconnected;
}

- (void)waitForLiveVPNDisconnect:(PDVPNManager *)manager {
    if (![self waitForLiveVPNManagerReady:manager]) return;
    if (manager.status == YDVPNStatusDisconnected) return;
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
    if (urlString.length == 0 || connections < 1 || connections > 32 || stressBytes > 512 * 1024 * 1024) return NO;
    NSURL *baseURL = [NSURL URLWithString:urlString];
    XCTestExpectation *load = [self expectationWithDescription:@"Parallel live downloads"];
    load.expectedFulfillmentCount = connections;
    __block unsigned long long downloaded = 0;
    __block NSMutableArray<NSString *> *errors = [NSMutableArray new];
    NSLock *resultsLock = [NSLock new];
    NSURLSessionConfiguration *configuration = NSURLSessionConfiguration.ephemeralSessionConfiguration;
    configuration.HTTPMaximumConnectionsPerHost = connections;
    configuration.timeoutIntervalForResource = 120;
    NSURLSession *session = [NSURLSession sessionWithConfiguration:configuration delegate:self delegateQueue:nil];
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

- (void)startSustainedDownloadForIndex:(NSUInteger)index
                             sequence:(NSUInteger)sequence
                              session:(NSURLSession *)session
                              baseURL:(NSURL *)baseURL
                             deadline:(NSDate *)deadline
                          stressBytes:(unsigned long long)stressBytes
                          expectation:(XCTestExpectation *)load
                               errors:(NSMutableArray<NSString *> *)errors
                          resultsLock:(NSLock *)resultsLock
                           statistics:(NSMutableArray<NSMutableDictionary *> *)statistics {
    if ([NSDate.date compare:deadline] != NSOrderedAscending) {
        [resultsLock lock];
        statistics[index][@"finished"] = @YES;
        [resultsLock unlock];
        [load fulfill];
        return;
    }
    NSURLComponents *components = [NSURLComponents componentsWithURL:baseURL resolvingAgainstBaseURL:NO];
    NSString *requestID = [NSString stringWithFormat:@"%lu-%lu", (unsigned long)index, (unsigned long)sequence];
    components.queryItems = [components.queryItems ?: @[] arrayByAddingObject:
        [NSURLQueryItem queryItemWithName:@"srp-live" value:requestID]];
    [[session downloadTaskWithURL:components.URL completionHandler:^(NSURL *location, NSURLResponse *response, NSError *error) {
        unsigned long long size = [(NSNumber *)[NSFileManager.defaultManager attributesOfItemAtPath:location.path error:nil][NSFileSize] unsignedLongLongValue];
        NSInteger statusCode = [response isKindOfClass:NSHTTPURLResponse.class] ? ((NSHTTPURLResponse *)response).statusCode : 0;
        NSString *failure = error.localizedDescription;
        if (!failure && statusCode != 200) failure = [NSString stringWithFormat:@"HTTP %ld", (long)statusCode];
        if (!failure && size != stressBytes) failure = @"Short download";
        [resultsLock lock];
        NSMutableDictionary *statistic = statistics[index];
        statistic[@"requests"] = @([statistic[@"requests"] unsignedIntegerValue] + 1);
        if (failure) {
            [errors addObject:failure];
            statistic[@"errors"] = @([statistic[@"errors"] unsignedIntegerValue] + 1);
            if (error.code == NSURLErrorTimedOut) {
                statistic[@"timeouts"] = @([statistic[@"timeouts"] unsignedIntegerValue] + 1);
            }
            statistic[@"finished"] = @YES;
        } else {
            statistic[@"bytes"] = @([statistic[@"bytes"] unsignedLongLongValue] + size);
        }
        [resultsLock unlock];
        if (failure) {
            [load fulfill];
            return;
        }
        [self startSustainedDownloadForIndex:index
                                    sequence:sequence + 1
                                     session:session
                                     baseURL:baseURL
                                    deadline:deadline
                                 stressBytes:stressBytes
                                 expectation:load
                                      errors:errors
                                 resultsLock:resultsLock
                                  statistics:statistics];
    }] resume];
}

- (void)startSustainedUploadForIndex:(NSUInteger)index
                           sequence:(NSUInteger)sequence
                            session:(NSURLSession *)session
                            baseURL:(NSURL *)baseURL
                           deadline:(NSDate *)deadline
                            payload:(NSData *)payload
                    expectedDigest:(NSString *)expectedDigest
                        expectation:(XCTestExpectation *)load
                             errors:(NSMutableArray<NSString *> *)errors
                        resultsLock:(NSLock *)resultsLock
                         statistics:(NSMutableArray<NSMutableDictionary *> *)statistics {
    if ([NSDate.date compare:deadline] != NSOrderedAscending) {
        [resultsLock lock];
        statistics[index][@"finished"] = @YES;
        [resultsLock unlock];
        [load fulfill];
        return;
    }
    NSURLComponents *components = [NSURLComponents componentsWithURL:baseURL resolvingAgainstBaseURL:NO];
    NSString *requestID = [NSString stringWithFormat:@"upload-%lu-%lu", (unsigned long)index, (unsigned long)sequence];
    components.queryItems = [components.queryItems ?: @[] arrayByAddingObject:
        [NSURLQueryItem queryItemWithName:@"srp-live" value:requestID]];
    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:components.URL];
    request.HTTPMethod = @"POST";
    [[session uploadTaskWithRequest:request fromData:payload completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
        (void)data;
        NSHTTPURLResponse *httpResponse = [response isKindOfClass:NSHTTPURLResponse.class] ? (NSHTTPURLResponse *)response : nil;
        NSString *actualDigest = [httpResponse.allHeaderFields[@"X-Upload-SHA256"] description];
        unsigned long long actualBytes = [httpResponse.allHeaderFields[@"X-Upload-Bytes"] longLongValue];
        NSString *failure = error.localizedDescription;
        if (!failure && httpResponse.statusCode != 200) failure = [NSString stringWithFormat:@"HTTP %ld", (long)httpResponse.statusCode];
        if (!failure && actualBytes != payload.length) failure = @"Short upload";
        if (!failure && [actualDigest caseInsensitiveCompare:expectedDigest] != NSOrderedSame) failure = @"Upload digest mismatch";
        [resultsLock lock];
        NSMutableDictionary *statistic = statistics[index];
        statistic[@"requests"] = @([statistic[@"requests"] unsignedIntegerValue] + 1);
        if (failure) {
            [errors addObject:failure];
            statistic[@"errors"] = @([statistic[@"errors"] unsignedIntegerValue] + 1);
            if (error.code == NSURLErrorTimedOut) {
                statistic[@"timeouts"] = @([statistic[@"timeouts"] unsignedIntegerValue] + 1);
            }
            statistic[@"finished"] = @YES;
        } else {
            statistic[@"bytes"] = @([statistic[@"bytes"] unsignedLongLongValue] + actualBytes);
        }
        [resultsLock unlock];
        if (failure) {
            [load fulfill];
            return;
        }
        [self startSustainedUploadForIndex:index
                                  sequence:sequence + 1
                                   session:session
                                   baseURL:baseURL
                                  deadline:deadline
                                   payload:payload
                           expectedDigest:expectedDigest
                               expectation:load
                                    errors:errors
                               resultsLock:resultsLock
                                statistics:statistics];
    }] resume];
}

- (BOOL)performSustainedLiveFullDuplex:(PDVPNManager *)manager environment:(NSDictionary *)environment {
    unsigned long long stressBytes = [environment[@"SRP_WW_STRESS_BYTES"] longLongValue];
    NSUInteger connections = [environment[@"SRP_WW_STRESS_CONNECTIONS"] integerValue] ?: 4;
    NSTimeInterval duration = [environment[@"SRP_STRESS_DURATION"] doubleValue];
    NSURL *baseURL = [NSURL URLWithString:environment[@"SRP_WW_STRESS_URL"] ?: @""];
    if (baseURL == nil || connections < 1 || connections > 16 || stressBytes == 0 ||
        stressBytes > 64 * 1024 * 1024 || duration < 1 || duration > 3600) return NO;
    NSData *payload = [NSMutableData dataWithLength:(NSUInteger)stressBytes];
    unsigned char digest[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(payload.bytes, (CC_LONG)payload.length, digest);
    NSMutableString *expectedDigest = [NSMutableString stringWithCapacity:CC_SHA256_DIGEST_LENGTH * 2];
    for (NSUInteger index = 0; index < CC_SHA256_DIGEST_LENGTH; index++) {
        [expectedDigest appendFormat:@"%02x", digest[index]];
    }
    NSDate *startedAt = NSDate.date;
    NSDate *deadline = [startedAt dateByAddingTimeInterval:duration];
    XCTestExpectation *load = [self expectationWithDescription:@"Sustained parallel live downloads and verified uploads"];
    load.expectedFulfillmentCount = connections * 2;
    NSMutableArray<NSString *> *errors = [NSMutableArray new];
    NSLock *resultsLock = [NSLock new];
    NSMutableArray<NSMutableDictionary *> *downloads = [NSMutableArray new];
    NSMutableArray<NSMutableDictionary *> *uploads = [NSMutableArray new];
    for (NSUInteger index = 0; index < connections; index++) {
        [downloads addObject:[@{@"bytes": @0, @"requests": @0, @"errors": @0, @"timeouts": @0, @"finished": @NO} mutableCopy]];
        [uploads addObject:[@{@"bytes": @0, @"requests": @0, @"errors": @0, @"timeouts": @0, @"finished": @NO} mutableCopy]];
    }
    NSURLSessionConfiguration *configuration = NSURLSessionConfiguration.ephemeralSessionConfiguration;
    configuration.HTTPMaximumConnectionsPerHost = connections * 2;
    configuration.timeoutIntervalForRequest = 120;
    configuration.timeoutIntervalForResource = MAX(180, duration + 60);
    NSURLSession *session = [NSURLSession sessionWithConfiguration:configuration delegate:self delegateQueue:nil];
    id lostObserver = [NSNotificationCenter.defaultCenter addObserverForName:@"kApplicationVPNStatusDidChangeNotification"
                                                                      object:nil
                                                                       queue:nil
                                                                  usingBlock:^(NSNotification *notification) {
        (void)notification;
        if (manager.status == YDVPNStatusDisconnected) [session invalidateAndCancel];
    }];
    for (NSUInteger index = 0; index < connections; index++) {
        [self startSustainedDownloadForIndex:index sequence:0 session:session baseURL:baseURL deadline:deadline
                                 stressBytes:stressBytes expectation:load errors:errors resultsLock:resultsLock statistics:downloads];
        [self startSustainedUploadForIndex:index sequence:0 session:session baseURL:baseURL deadline:deadline
                                   payload:payload expectedDigest:expectedDigest expectation:load errors:errors
                               resultsLock:resultsLock statistics:uploads];
    }
    [self waitForExpectations:@[load] timeout:duration + 120];
    [NSNotificationCenter.defaultCenter removeObserver:lostObserver];
    [session finishTasksAndInvalidate];
    unsigned long long downloaded = 0;
    unsigned long long uploaded = 0;
    NSUInteger finished = 0;
    NSUInteger timeouts = 0;
    NSUInteger downloadRequests = 0;
    NSUInteger uploadRequests = 0;
    for (NSArray<NSMutableDictionary *> *statistics in @[downloads, uploads]) {
        for (NSMutableDictionary *statistic in statistics) {
            if (statistics == downloads) {
                downloaded += [statistic[@"bytes"] unsignedLongLongValue];
                downloadRequests += [statistic[@"requests"] unsignedIntegerValue];
            } else {
                uploaded += [statistic[@"bytes"] unsignedLongLongValue];
                uploadRequests += [statistic[@"requests"] unsignedIntegerValue];
            }
            finished += [statistic[@"finished"] boolValue] ? 1 : 0;
            timeouts += [statistic[@"timeouts"] unsignedIntegerValue];
        }
    }
    NSTimeInterval actualDuration = -startedAt.timeIntervalSinceNow;
    NSLog(@"Sustained full-duplex: %.2f seconds, downloaded=%llu, uploaded=%llu, download_requests=%lu, upload_requests=%lu, errors=%@, finished=%lu/%lu, timeouts=%lu, VPN status=%ld",
          actualDuration, downloaded, uploaded, (unsigned long)downloadRequests, (unsigned long)uploadRequests,
          errors, (unsigned long)finished, (unsigned long)(connections * 2), (unsigned long)timeouts, (long)manager.status);
    BOOL passed = manager.status == YDVPNStatusConnected && errors.count == 0 && timeouts == 0 &&
                  actualDuration >= duration && finished == connections * 2 && downloaded > 0 && uploaded > 0;
    if (!passed && [environment[@"SRP_FETCH_LOGS_ON_FAILURE"] boolValue]) {
        [self logWaterWallProviderFile:@"native-log" manager:manager];
        [self logWaterWallProviderFile:@"tunnel-log" manager:manager];
    }
    return passed;
}

- (BOOL)performSustainedLiveUDPProbes:(NSDictionary *)environment {
    NSURLComponents *components = [NSURLComponents componentsWithString:environment[@"SRP_WW_STRESS_URL"]];
    NSTimeInterval duration = [environment[@"SRP_STRESS_DURATION"] doubleValue];
    if (components.host.length == 0 || duration < 1 || duration > 3600) return NO;
    NSString *port = environment[@"SRP_WW_UDP_PORT"] ?: @"28481";
    nw_endpoint_t endpoint = nw_endpoint_create_host(components.host.UTF8String, port.UTF8String);
    nw_connection_t connection = nw_connection_create(endpoint,
        nw_parameters_create_secure_udp(NW_PARAMETERS_DISABLE_PROTOCOL, NW_PARAMETERS_DEFAULT_CONFIGURATION));
    dispatch_queue_t queue = dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0);
    nw_connection_set_queue(connection, queue);
    XCTestExpectation *expectation = [self expectationWithDescription:@"Sustained real UDP/DNS responses"];
    NSDate *startedAt = NSDate.date;
    __block NSDate *firstResponseAt = nil;
    __block NSDate *deadline = nil;
    __block NSDate *lastSendAt = nil;
    NSLock *lock = [NSLock new];
    __block NSUInteger sent = 0;
    __block NSUInteger received = 0;
    __block NSUInteger errors = 0;
    __block NSUInteger timeouts = 0;
    __block BOOL completed = NO;
    __block BOOL succeeded = NO;
    __block NSUInteger inflightIdentifier = 0;
    __block NSUInteger inflightAttempts = 0;
    __block BOOL receiveOutstanding = NO;
    __block NSTimeInterval rttTotal = 0;
    __block NSTimeInterval jitterTotal = 0;
    __block NSTimeInterval previousRTT = -1;
    __block NSTimeInterval maximumRTT = 0;
    __block dispatch_block_t sendNext;
    void (^finish)(BOOL) = ^(BOOL success) {
        [lock lock];
        if (completed) {
            [lock unlock];
            return;
        }
        completed = YES;
        succeeded = success;
        NSTimeInterval elapsed = firstResponseAt != nil ? -firstResponseAt.timeIntervalSinceNow : -startedAt.timeIntervalSinceNow;
        BOOL passed = success && errors == 0 && sent == received && sent >= (NSUInteger)(duration * 10) && elapsed >= duration;
        NSTimeInterval averageRTT = received > 0 ? rttTotal / received * 1000 : 0;
        NSTimeInterval averageJitter = received > 1 ? jitterTotal / (received - 1) * 1000 : 0;
        NSLog(@"Sustained UDP: %.2f seconds, sent=%lu, received=%lu, errors=%lu, timeouts=%lu, passed=%d, rtt_ms=%.3f, jitter_ms=%.3f, max_rtt_ms=%.3f",
              elapsed, (unsigned long)sent, (unsigned long)received, (unsigned long)errors, (unsigned long)timeouts, passed,
              averageRTT, averageJitter, maximumRTT * 1000);
        [lock unlock];
        nw_connection_cancel(connection);
        sendNext = nil;
        [expectation fulfill];
    };
    sendNext = ^{
        [lock lock];
        BOOL retrying = inflightIdentifier != 0 && inflightAttempts < 3;
        BOOL minimumComplete = !retrying && sent >= (NSUInteger)(duration * 10) && received >= sent;
        BOOL shouldStop = completed || (firstResponseAt != nil && NSDate.date.timeIntervalSince1970 >= deadline.timeIntervalSince1970 && minimumComplete);
        uint16_t identifier = retrying ? (uint16_t)inflightIdentifier : (uint16_t)(sent + 1);
        if (!shouldStop) {
            if (!retrying) {
                sent++;
                inflightIdentifier = identifier;
                inflightAttempts = 0;
            }
            inflightAttempts++;
            lastSendAt = NSDate.date;
        }
        [lock unlock];
        if (shouldStop) {
            finish(YES);
            return;
        }
        uint8_t query[29] = {
            identifier >> 8, identifier & 0xff, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            7, 'e','x','a','m','p','l','e', 3, 'c','o','m', 0, 0x00, 0x01, 0x00, 0x01
        };
        dispatch_data_t packet = dispatch_data_create(query, sizeof(query), NULL, DISPATCH_DATA_DESTRUCTOR_DEFAULT);
        nw_connection_send(connection, packet, NULL, true, ^(nw_error_t error) {
            if (error) {
                [lock lock];
                errors++;
                [lock unlock];
                finish(NO);
            }
        });
        [lock lock];
        BOOL startReceive = !receiveOutstanding;
        if (startReceive) receiveOutstanding = YES;
        [lock unlock];
        if (startReceive) nw_connection_receive_message(connection, ^(dispatch_data_t content, nw_content_context_t context, bool isComplete, nw_error_t error) {
            (void)context;
            (void)isComplete;
            [lock lock];
            receiveOutstanding = NO;
            [lock unlock];
            if (error) {
                [lock lock];
                errors++;
                [lock unlock];
                finish(NO);
                return;
            }
            if (content == NULL) {
                [lock lock];
                errors++;
                [lock unlock];
                finish(NO);
                return;
            }
            const uint8_t *bytes = NULL;
            size_t contentLength = 0;
            dispatch_data_t mapped = dispatch_data_create_map(content, (const void **)&bytes, &contentLength);
            BOOL valid = contentLength >= 12 && bytes[0] == (identifier >> 8) && bytes[1] == (identifier & 0xff) &&
                (bytes[2] & 0x80) && (bytes[3] & 0x0f) == 0;
            [lock lock];
            BOOL expectedResponse = valid && !completed && inflightIdentifier == identifier;
            if (expectedResponse) {
                inflightIdentifier = 0;
                if (firstResponseAt == nil) {
                    firstResponseAt = NSDate.date;
                    deadline = [firstResponseAt dateByAddingTimeInterval:duration];
                }
                received++;
                NSTimeInterval rtt = -lastSendAt.timeIntervalSinceNow;
                rttTotal += rtt;
                maximumRTT = MAX(maximumRTT, rtt);
                if (previousRTT >= 0) jitterTotal += ABS(rtt - previousRTT);
                previousRTT = rtt;
            }
            NSTimeInterval delay = lastSendAt != nil ? MAX(0, 0.1 + lastSendAt.timeIntervalSinceNow) : 0;
            int64_t delayNanoseconds = (int64_t)(delay * NSEC_PER_SEC);
            [lock unlock];
            if (expectedResponse) {
                dispatch_after(dispatch_time(DISPATCH_TIME_NOW, delayNanoseconds), queue, sendNext);
            } else if (!valid) {
                [lock lock];
                errors++;
                [lock unlock];
                finish(NO);
            }
        });
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC), queue, ^{
            [lock lock];
            BOOL timedOut = !completed && inflightIdentifier == identifier;
            BOOL retry = timedOut && inflightAttempts < 3;
            if (timedOut && !retry) {
                timeouts++;
                errors++;
            }
            [lock unlock];
            if (retry) sendNext();
            else if (timedOut) finish(NO);
        });
    };
    nw_connection_set_state_changed_handler(connection, ^(nw_connection_state_t state, nw_error_t error) {
        if (state == nw_connection_state_ready) {
            sendNext();
        } else if (state == nw_connection_state_failed || state == nw_connection_state_cancelled) {
            if (error) {
                [lock lock];
                errors++;
                [lock unlock];
            }
            finish(NO);
        }
    });
    nw_connection_start(connection);
    [self waitForExpectations:@[expectation] timeout:duration + 20];
    [lock lock];
    BOOL passed = completed && succeeded && errors == 0 && sent == received && sent >= (NSUInteger)(duration * 10);
    [lock unlock];
    return passed;
}

- (void)URLSession:(NSURLSession *)session
    didReceiveChallenge:(NSURLAuthenticationChallenge *)challenge
      completionHandler:(void (^)(NSURLSessionAuthChallengeDisposition disposition, NSURLCredential *credential))completionHandler {
    (void)session;
    NSString *encoded = NSProcessInfo.processInfo.environment[@"SRP_WW_STRESS_TRUSTED_CERT"];
    if (![challenge.protectionSpace.authenticationMethod isEqualToString:NSURLAuthenticationMethodServerTrust] || encoded.length == 0) {
        completionHandler(NSURLSessionAuthChallengePerformDefaultHandling, nil);
        return;
    }
    NSData *expected = [[NSData alloc] initWithBase64EncodedString:encoded options:NSDataBase64DecodingIgnoreUnknownCharacters];
    SecTrustRef trust = challenge.protectionSpace.serverTrust;
    NSArray *certificates = trust ? CFBridgingRelease(SecTrustCopyCertificateChain(trust)) : nil;
    NSData *actual = nil;
    if (certificates.count > 0) {
        SecCertificateRef certificate = (__bridge SecCertificateRef)certificates.firstObject;
        actual = (__bridge_transfer NSData *)SecCertificateCopyData(certificate);
    }
    BOOL matches = trust != NULL && expected != nil && [actual isEqualToData:expected];
    NSLog(@"Stress certificate pin: expectedLength=%lu actualLength=%lu accepted=%d",
          (unsigned long)expected.length, (unsigned long)actual.length, matches);
    if (matches) {
        completionHandler(NSURLSessionAuthChallengeUseCredential, [NSURLCredential credentialForTrust:trust]);
    } else {
        completionHandler(NSURLSessionAuthChallengeCancelAuthenticationChallenge, nil);
    }
}

- (BOOL)performSustainedLiveStressDownloads:(PDVPNManager *)manager environment:(NSDictionary *)environment {
    long long stressBytes = [environment[@"SRP_WW_STRESS_BYTES"] longLongValue];
    NSUInteger connections = [environment[@"SRP_WW_STRESS_CONNECTIONS"] integerValue] ?: 4;
    NSTimeInterval duration = [environment[@"SRP_STRESS_DURATION"] doubleValue];
    NSString *urlString = environment[@"SRP_WW_STRESS_URL"];
    if (stressBytes <= 0 || stressBytes > 512 * 1024 * 1024 || connections < 1 || connections > 32 ||
        duration < 1 || duration > 3600 || urlString.length == 0) return NO;
    NSURL *baseURL = [NSURL URLWithString:urlString];
    NSDate *startedAt = NSDate.date;
    NSDate *deadline = [startedAt dateByAddingTimeInterval:duration];
    XCTestExpectation *load = [self expectationWithDescription:@"Sustained parallel live downloads"];
    load.expectedFulfillmentCount = connections;
    __block NSMutableArray<NSString *> *errors = [NSMutableArray new];
    NSLock *resultsLock = [NSLock new];
    NSMutableArray<NSMutableDictionary *> *statistics = [NSMutableArray new];
    for (NSUInteger index = 0; index < connections; index++) {
        [statistics addObject:[@{@"bytes": @0, @"requests": @0, @"errors": @0, @"timeouts": @0, @"finished": @NO} mutableCopy]];
    }
    NSURLSessionConfiguration *configuration = NSURLSessionConfiguration.ephemeralSessionConfiguration;
    configuration.HTTPMaximumConnectionsPerHost = connections;
    configuration.timeoutIntervalForRequest = 45;
    configuration.timeoutIntervalForResource = MAX(120, duration + 60);
    NSURLSession *session = [NSURLSession sessionWithConfiguration:configuration delegate:self delegateQueue:nil];
    id lostObserver = [NSNotificationCenter.defaultCenter addObserverForName:@"kApplicationVPNStatusDidChangeNotification"
                                                                      object:nil
                                                                       queue:nil
                                                                  usingBlock:^(NSNotification *notification) {
        (void)notification;
        if (manager.status == YDVPNStatusDisconnected) [session invalidateAndCancel];
    }];
    BOOL requiresTCP = environment[@"SRP_WW_TCP_STRESS"] ? [environment[@"SRP_WW_TCP_STRESS"] boolValue] : YES;
    if (!requiresTCP && ![environment[@"SRP_WW_UDP_STRESS"] boolValue]) return NO;
    if (requiresTCP) {
        for (NSUInteger index = 0; index < connections; index++) {
            [self startSustainedDownloadForIndex:index
                                        sequence:0
                                         session:session
                                         baseURL:baseURL
                                        deadline:deadline
                                     stressBytes:(unsigned long long)stressBytes
                                     expectation:load
                                          errors:errors
                                     resultsLock:resultsLock
                                      statistics:statistics];
        }
    }
    XCTestExpectation *udpExpectation;
    __block BOOL udpPassed = YES;
    if ([environment[@"SRP_WW_UDP_STRESS"] boolValue]) {
        udpExpectation = [self expectationWithDescription:@"UDP transfer completes alongside TCP"];
        dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
            udpPassed = [self performSustainedLiveUDPProbes:environment];
            [udpExpectation fulfill];
        });
    }
    NSMutableArray<XCTestExpectation *> *expectations = [NSMutableArray new];
    if (requiresTCP) [expectations addObject:load];
    if (udpExpectation) [expectations addObject:udpExpectation];
    [self waitForExpectations:expectations timeout:duration + 120];
    [NSNotificationCenter.defaultCenter removeObserver:lostObserver];
    [session finishTasksAndInvalidate];
    NSTimeInterval actualDuration = -startedAt.timeIntervalSinceNow;
    unsigned long long downloaded = 0;
    NSUInteger requests = 0;
    NSUInteger finished = 0;
    NSUInteger timeouts = 0;
    for (NSUInteger index = 0; index < connections; index++) {
        NSDictionary *statistic = statistics[index];
        downloaded += [statistic[@"bytes"] unsignedLongLongValue];
        requests += [statistic[@"requests"] unsignedIntegerValue];
        finished += [statistic[@"finished"] boolValue] ? 1 : 0;
        timeouts += [statistic[@"timeouts"] unsignedIntegerValue];
        NSLog(@"Sustained connection %lu: %@ bytes, %@ requests, %@ errors, %@ timeouts",
              (unsigned long)(index + 1), statistic[@"bytes"], statistic[@"requests"], statistic[@"errors"], statistic[@"timeouts"]);
    }
    if (!requiresTCP) finished = connections;
    NSLog(@"Sustained stress: %.2f seconds, %llu bytes, %lu requests, errors: %@, VPN status: %ld, finished: %lu/%lu, timeouts: %lu",
          actualDuration, downloaded, (unsigned long)requests, errors, (long)manager.status,
          (unsigned long)finished, (unsigned long)connections, (unsigned long)timeouts);
    return manager.status == YDVPNStatusConnected && (!requiresTCP || errors.count == 0) &&
           actualDuration >= duration && finished == connections && udpPassed;
}

- (BOOL)runLiveConnectionRoundsForModel:(NodeModel *)model manager:(PDVPNManager *)manager environment:(NSDictionary *)environment {
    NSUInteger rounds = MAX(1, [environment[@"SRP_STRESS_ROUNDS"] integerValue] ?: 3);
    for (NSUInteger connectionRound = 0; connectionRound < rounds; connectionRound++) {
        NSLog(@"Live connection round %lu/%lu starting", (unsigned long)(connectionRound + 1), (unsigned long)rounds);
        NSString *error = nil;
        NSMutableDictionary *server = [[CheckConnectData checkConnectParmer:model] mutableCopy];
        if ([environment[@"SRP_WW_TEST_ID"] length] > 0) {
            server[@"ww_test_id"] = environment[@"SRP_WW_TEST_ID"];
        }
        if (![self waitForLiveVPNConnection:manager server:server error:&error]) {
            NSLog(@"Live connection failed: %@", error);
            if ([environment[@"SRP_FETCH_LOGS_ON_FAILURE"] boolValue]) {
                [self logWaterWallProviderFile:@"native-log" manager:manager];
                [self logWaterWallProviderFile:@"tunnel-log" manager:manager];
            }
            return NO;
        }
        for (NSUInteger downloadRound = 0; downloadRound < rounds; downloadRound++) {
            BOOL stressPassed = [environment[@"SRP_STRESS_DURATION"] doubleValue] > 0
                ? [self performSustainedLiveStressDownloads:manager environment:environment]
                : [self performLiveStressDownloads:manager environment:environment];
            BOOL requiresTCP = environment[@"SRP_WW_TCP_STRESS"] ? [environment[@"SRP_WW_TCP_STRESS"] boolValue] : YES;
            BOOL connectivityPassed = requiresTCP
                ? [self waterWallLiveHTTPS204:model] && stressPassed && [self waterWallLiveHTTPS204:model]
                : stressPassed;
            if (!connectivityPassed) {
                if ([environment[@"SRP_FETCH_LOGS_ON_FAILURE"] boolValue]) {
                    [self logWaterWallProviderFile:@"native-log" manager:manager];
                    [self logWaterWallProviderFile:@"tunnel-log" manager:manager];
                }
                [self waitForLiveVPNDisconnect:manager];
                return NO;
            }
            if ([environment[@"SRP_FETCH_LOGS"] boolValue]) {
                [self logWaterWallProviderFile:@"native-log" manager:manager];
                [self logWaterWallProviderFile:@"tunnel-log" manager:manager];
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
    NSLog(@"Live HTTPS 204: %@", result ?: @"no result");
    return [result hasPrefix:@"Ping:"];
}

- (NodeModel *)liveWaterWallModelFromEnvironment {
    NSDictionary *environment = NSProcessInfo.processInfo.environment;
    NSString *address = environment[@"SRP_BGP4_SERVER"];
    NSString *port = environment[@"SRP_BGP4_PORT"];
    NSString *uuid = environment[@"SRP_BGP4_UUID"];
    NSString *carrier = environment[@"SRP_BGP4_CARRIER"] ?: @"tcp";
    NSString *application = environment[@"SRP_WW_APPLICATION"] ?: @"vless";
    NSString *outer = environment[@"SRP_WW_OUTER"] ?: @"bgp4";
    NSString *customConfig = environment[@"SRP_WW_CONFIG_JSON"];
    if (address.length == 0 || (!customConfig.length && uuid.length == 0) || port.integerValue < 1 || port.integerValue > 65535 ||
        (!customConfig.length && (![@[@"tcp", @"kcp"] containsObject:carrier] ||
         ![@[@"vless", @"vmess"] containsObject:application] || ![@[@"none", @"tls", @"bgp4"] containsObject:outer]))) {
        NSLog(@"Live model diagnostics: addressLength=%lu port=%@ credentialLength=%lu carrier=%@ application=%@ outer=%@ customConfig=%d",
              (unsigned long)address.length, port, (unsigned long)uuid.length, carrier, application, outer, customConfig.length > 0);
        return nil;
    }
    NodeModel *model = [NodeModel new];
    model.protocolType = @"waterwall";
    model.nodeId = environment[@"SRP_WW_TEST_ID"] ?: @"live-waterwall-test";
    model.desc = @"WaterWall live test";
    model.server = address;
    model.port = port;
    model.username = environment[@"SRP_WW_USERNAME"];
    BOOL unauthenticatedProxy = [@[@"socks5", @"http-proxy"] containsObject:application] && model.username.length == 0;
    model.password = unauthenticatedProxy ? nil : uuid;
    model.waterwallOuterSecret = environment[@"SRP_WW_OUTER_SECRET"];
    model.wgConfig = environment[@"SRP_WW_WG_CONFIG"];
    model.customSni = environment[@"SRP_WW_SNI"];
    model.TLS = [environment[@"SRP_WW_INSECURE"] boolValue];
    model.logLevel = environment[@"SRP_WW_LOG_LEVEL"] ? [environment[@"SRP_WW_LOG_LEVEL"] integerValue] : 2;
    model.waterwallFakeDNS = environment[@"SRP_WW_FAKE_DNS"] ? [environment[@"SRP_WW_FAKE_DNS"] boolValue] : YES;
    model.waterwallSmartRouting = YES;
    model.waterwallProbeIP = environment[@"SRP_WW_PROBE_IP"];
    model.waterwallDNSProbeIP = environment[@"SRP_WW_DNS_PROBE_IP"];
    model.autoReconnect = environment[@"SRP_AUTO_RECONNECT"] ? [environment[@"SRP_AUTO_RECONNECT"] boolValue] : YES;
    model.retryTimes = [environment[@"SRP_RETRY_TIMES"] integerValue];
    model.switchToWifi = environment[@"SRP_SWITCH_WIFI"] ? [environment[@"SRP_SWITCH_WIFI"] boolValue] : YES;
    model.onSleep = environment[@"SRP_ON_SLEEP"] ? [environment[@"SRP_ON_SLEEP"] integerValue] : 2;
    NSDictionary *nodeOptions = @{};
    NSString *nodeOptionsJSON = environment[@"SRP_WW_NODE_OPTIONS"];
    if (nodeOptionsJSON.length > 0) {
        NSError *parseError = nil;
        id parsed = [NSJSONSerialization JSONObjectWithData:[nodeOptionsJSON dataUsingEncoding:NSUTF8StringEncoding]
                                                    options:0
                                                      error:&parseError];
        if (![parsed isKindOfClass:NSDictionary.class]) return nil;
        nodeOptions = parsed;
    }
    model.waterwallConfigJSON = customConfig.length > 0 ? customConfig : [SRPWaterWallChainConfig JSONWithConfiguration:@{
        @"version": @3, @"mode": @"chain", @"input": @"connections", @"application": application,
        @"mux": @NO, @"outer": outer, @"http": @"off", @"http-version": @1,
        @"obfuscator": @NO, @"carrier": carrier, @"quic-carrier": @"datagram", @"node-options": nodeOptions,
        @"bgp4": @([environment[@"SRP_WW_BGP4"] boolValue])
    }];
    if ([SRPWaterWallChainConfig configurationWithJSON:model.waterwallConfigJSON] == nil) return nil;
    return model;
}

- (void)testWaterWallLiveConnectionAndThroughputWhenConfigured {
    if (![NSProcessInfo.processInfo.environment[@"SRP_BGP4_LIVE_TEST"] isEqualToString:@"1"]) return;
    PDVPNManager *manager = PDVPNManager.sharedManager;
    if (manager.status == YDVPNStatusConnected || manager.status == YDVPNStatusConnecting ||
        manager.status == YDVPNStatusDisconnecting) {
        XCTSkip(@"An existing VPN connection must be disconnected before running this test.");
    }
    NodeModel *model = [self liveWaterWallModelFromEnvironment];
    XCTAssertNotNil(model);
    if (model == nil) return;
    XCTAssertTrue([self runLiveConnectionRoundsForModel:model manager:manager environment:NSProcessInfo.processInfo.environment]);
}

- (void)testWaterWallLiveFullDuplexWhenConfigured {
    NSDictionary *environment = NSProcessInfo.processInfo.environment;
    if (![environment[@"SRP_FULL_DUPLEX_TEST"] isEqualToString:@"1"]) return;
    PDVPNManager *manager = PDVPNManager.sharedManager;
    if (manager.status == YDVPNStatusConnected || manager.status == YDVPNStatusConnecting ||
        manager.status == YDVPNStatusDisconnecting) {
        XCTSkip(@"An existing VPN connection must be disconnected before running this test.");
    }
    NodeModel *model = [self liveWaterWallModelFromEnvironment];
    XCTAssertNotNil(model);
    if (model == nil) return;
    model.autoReconnect = NO;
    @try {
        NSString *error = nil;
        NSMutableDictionary *server = [[CheckConnectData checkConnectParmer:model] mutableCopy];
        if ([environment[@"SRP_WW_TEST_ID"] length] > 0) server[@"ww_test_id"] = environment[@"SRP_WW_TEST_ID"];
        BOOL connected = [self waitForLiveVPNConnection:manager server:server error:&error];
        XCTAssertTrue(connected, @"%@", error);
        if (!connected) return;
        NSTimeInterval profileDelay = [environment[@"SRP_PROFILE_DELAY"] doubleValue];
        if (profileDelay > 0) {
            NSLog(@"Waiting %.0f seconds for allocation recording", profileDelay);
            [NSThread sleepForTimeInterval:profileDelay];
        }
        XCTAssertTrue([self waterWallLiveHTTPS204:model]);
        XCTAssertTrue([self performSustainedLiveFullDuplex:manager environment:environment]);
        XCTAssertTrue([self waterWallLiveHTTPS204:model]);
    } @finally {
        if (manager.status != YDVPNStatusDisconnected) [self waitForLiveVPNDisconnect:manager];
        if ([environment[@"SRP_FETCH_LOGS_ON_FAILURE"] boolValue]) {
            [NSThread sleepForTimeInterval:1];
            NSUserDefaults *shared = [[NSUserDefaults alloc] initWithSuiteName:@"group.tr.com.srp.vpn"];
            NSLog(@"WaterWall last error: %@; stop reason: %@", [shared objectForKey:@"SRPLastError"], [shared objectForKey:@"SRPStopReason"]);
            [self logWaterWallProviderFile:@"native-log" manager:manager];
            [self logWaterWallProviderFile:@"tunnel-log" manager:manager];
        }
    }
}

- (void)testStopAnyLiveVPNWhenConfigured {
    if (![NSProcessInfo.processInfo.environment[@"SRP_STOP_LIVE_VPN"] isEqualToString:@"1"]) return;
    [self waitForLiveVPNDisconnect:PDVPNManager.sharedManager];
    XCTAssertEqual(PDVPNManager.sharedManager.status, YDVPNStatusDisconnected);
}

#if DEBUG
- (NSDictionary *)waterWallProviderCommand:(NSString *)command manager:(PDVPNManager *)manager {
    NETunnelProviderManager *provider = [manager valueForKey:@"providerManager"];
    NETunnelProviderSession *session = (NETunnelProviderSession *)provider.connection;
    XCTestExpectation *response = [self expectationWithDescription:command];
    __block NSDictionary *result;
    __block NSError *sendError;
    [session sendProviderMessage:[NSJSONSerialization dataWithJSONObject:@{@"type": @100, @"command": command}
                                                                  options:0
                                                                    error:nil]
                    returnError:&sendError
                responseHandler:^(NSData *responseData) {
        if (responseData != nil) {
            result = [NSJSONSerialization JSONObjectWithData:responseData options:0 error:nil];
        }
        [response fulfill];
    }];
    [self waitForExpectations:@[response] timeout:10];
    XCTAssertNil(sendError);
    if ([command isEqualToString:@"state"] && [NSProcessInfo.processInfo.environment[@"SRP_TRACE_STATE"] boolValue]) {
        NSLog(@"WaterWall test state: %@", result);
    }
    return result;
}

- (BOOL)waitForWaterWallState:(NSString *)key value:(BOOL)value manager:(PDVPNManager *)manager timeout:(NSTimeInterval)timeout {
    NSDate *deadline = [NSDate dateWithTimeIntervalSinceNow:timeout];
    while (NSDate.date.timeIntervalSince1970 < deadline.timeIntervalSince1970) {
        NSDictionary *state = [self waterWallProviderCommand:@"state" manager:manager];
        if ([state[key] boolValue] == value) return YES;
        [NSThread sleepForTimeInterval:0.1];
    }
    return NO;
}
#endif

- (void)logWaterWallProviderFile:(NSString *)command manager:(PDVPNManager *)manager {
    if (manager.status == YDVPNStatusDisconnected) {
        NSURL *container = [NSFileManager.defaultManager containerURLForSecurityApplicationGroupIdentifier:@"group.tr.com.srp.vpn"];
        NSString *name = [command isEqualToString:@"native-log"] ? @"ww-native-current.log" : @"srptunnel.log";
        NSString *path = [(container ? container.path : NSHomeDirectory()) stringByAppendingPathComponent:[@"Library/" stringByAppendingString:name]];
        NSData *data = [NSData dataWithContentsOfFile:path];
        for (NSUInteger offset = 0; offset < data.length; offset += 2048) {
            NSData *chunk = [data subdataWithRange:NSMakeRange(offset, MIN((NSUInteger)2048, data.length - offset))];
            NSLog(@"%@:\n%@", command, [[NSString alloc] initWithData:chunk encoding:NSUTF8StringEncoding]);
        }
        return;
    }
    NETunnelProviderManager *provider = [manager valueForKey:@"providerManager"];
    NETunnelProviderSession *session = (NETunnelProviderSession *)provider.connection;
    XCTestExpectation *response = [self expectationWithDescription:command];
    [session sendProviderMessage:[NSJSONSerialization dataWithJSONObject:@{@"type": @100, @"command": command}
                                                                  options:0
                                                                    error:nil]
                    returnError:nil
                responseHandler:^(NSData *responseData) {
        const NSUInteger chunkSize = 2048;
        for (NSUInteger offset = 0; offset < responseData.length; offset += chunkSize) {
            NSData *chunk = [responseData subdataWithRange:NSMakeRange(offset, MIN(chunkSize, responseData.length - offset))];
            NSLog(@"%@:\n%@", command, [[NSString alloc] initWithData:chunk encoding:NSUTF8StringEncoding]);
        }
        [response fulfill];
    }];
    [self waitForExpectations:@[response] timeout:15];
}

- (void)testWaterWallLiveLogsWhenConfigured {
    if (![NSProcessInfo.processInfo.environment[@"SRP_FETCH_LOGS"] isEqualToString:@"1"]) return;
    PDVPNManager *manager = PDVPNManager.sharedManager;
    [self logWaterWallProviderFile:@"tunnel-log" manager:manager];
    [self logWaterWallProviderFile:@"native-log" manager:manager];
    if (manager.status != YDVPNStatusDisconnected) [self waitForLiveVPNDisconnect:manager];
}

- (void)testWaterWallLiveSleepAndRuntimeRecoveryWhenConfigured {
#if DEBUG
    if (![NSProcessInfo.processInfo.environment[@"SRP_RECOVERY_TEST"] isEqualToString:@"1"]) return;
    PDVPNManager *manager = PDVPNManager.sharedManager;
    XCTAssertTrue([self waitForLiveVPNManagerReady:manager]);
    if (manager.status != YDVPNStatusDisconnected) {
        XCTSkip(@"An existing VPN connection must be disconnected before running this test.");
    }
    @try {
        NodeModel *model = [self liveWaterWallModelFromEnvironment];
        XCTAssertNotNil(model);
        if (model == nil) return;
        model.onSleep = 1;
        model.autoReconnect = YES;
        model.retryTimes = 2;
        NSDictionary *environment = NSProcessInfo.processInfo.environment;
        NSString *error = nil;
        XCTAssertTrue([self waitForLiveVPNConnection:manager server:[CheckConnectData checkConnectParmer:model] error:&error], @"%@", error);
        if (manager.status != YDVPNStatusConnected) return;
        [self waterWallProviderCommand:@"sleep" manager:manager];
        XCTAssertTrue([self waitForWaterWallState:@"sleepPaused" value:YES manager:manager timeout:5]);
        XCTAssertTrue([self waitForWaterWallState:@"up" value:NO manager:manager timeout:2]);
        [self waterWallProviderCommand:@"wake" manager:manager];
        XCTAssertTrue([self waitForWaterWallState:@"up" value:YES manager:manager timeout:25]);
        XCTAssertTrue([self performSustainedLiveStressDownloads:manager environment:environment]);
        if ([environment[@"SRP_RECOVERY_SLEEP_ONLY"] boolValue]) return;
        [self waterWallProviderCommand:@"fail-runtime" manager:manager];
        XCTAssertTrue([self waitForWaterWallState:@"up" value:YES manager:manager timeout:30]);
        XCTAssertTrue([self performSustainedLiveStressDownloads:manager environment:environment]);
        [self waitForLiveVPNDisconnect:manager];
        [NSThread sleepForTimeInterval:3];
        XCTAssertEqual(manager.status, YDVPNStatusDisconnected);
    } @finally {
        if (manager.status != YDVPNStatusDisconnected) [self waitForLiveVPNDisconnect:manager];
    }
#else
    XCTSkip(@"Runtime recovery instrumentation requires a Debug build.");
#endif
}

- (void)testWaterWallLiveRetryBudgetWhenConfigured {
#if DEBUG
    NSDictionary *environment = NSProcessInfo.processInfo.environment;
    if (![environment[@"SRP_RETRY_LIVE_TEST"] isEqualToString:@"1"]) return;
    PDVPNManager *manager = PDVPNManager.sharedManager;
    XCTAssertTrue([self waitForLiveVPNManagerReady:manager]);
    if (manager.status != YDVPNStatusDisconnected) {
        XCTSkip(@"An existing VPN connection must be disconnected before running this test.");
    }
    @try {
        NodeModel *model = [self liveWaterWallModelFromEnvironment];
        XCTAssertNotNil(model);
        if (model == nil) return;
        model.retryTimes = 1;
        model.autoReconnect = ![environment[@"SRP_RETRY_DISABLE_AUTORECONNECT"] boolValue];
        NSString *error = nil;
        XCTAssertTrue([self waitForLiveVPNConnection:manager server:[CheckConnectData checkConnectParmer:model] error:&error], @"%@", error);
        if (manager.status != YDVPNStatusConnected) return;
        if ([environment[@"SRP_REAL_PEER_RETRY"] boolValue]) {
            NSLog(@"SRP peer-failure test ready");
            XCTAssertTrue([self waitForWaterWallState:@"up" value:NO manager:manager timeout:45]);
            if (!model.autoReconnect) {
                XCTAssertTrue([self waitForLiveVPNDisconnectedStatus:manager timeout:15]);
                return;
            }
            if (![environment[@"SRP_RETRY_NO_RECOVERY"] boolValue]) {
                XCTAssertTrue([self waitForWaterWallState:@"up" value:YES manager:manager timeout:45]);
                XCTAssertTrue([self waitForWaterWallState:@"up" value:NO manager:manager timeout:30]);
            }
        } else {
            [self waterWallProviderCommand:@"fail-runtime" manager:manager];
            XCTAssertTrue([self waitForWaterWallState:@"up" value:NO manager:manager timeout:30]);
            if (!model.autoReconnect) {
                XCTAssertTrue([self waitForLiveVPNDisconnectedStatus:manager timeout:15]);
                return;
            }
            XCTAssertTrue([self waitForWaterWallState:@"up" value:YES manager:manager timeout:30]);
            [self waterWallProviderCommand:@"fail-runtime" manager:manager];
            XCTAssertTrue([self waitForWaterWallState:@"up" value:NO manager:manager timeout:30]);
            XCTAssertTrue([self waitForWaterWallState:@"up" value:YES manager:manager timeout:30]);
            [self waitForLiveVPNDisconnect:manager];
            XCTAssertEqual(manager.status, YDVPNStatusDisconnected);
            return;
        }
        NSDate *deadline = [NSDate dateWithTimeIntervalSinceNow:90];
        while (manager.status != YDVPNStatusDisconnected && NSDate.date.timeIntervalSince1970 < deadline.timeIntervalSince1970) {
            [NSRunLoop.currentRunLoop runMode:NSDefaultRunLoopMode beforeDate:[NSDate dateWithTimeIntervalSinceNow:0.2]];
        }
        if ([environment[@"SRP_TRACE_STATE"] boolValue] && manager.status != YDVPNStatusDisconnected) {
            NSLog(@"Retry budget final provider state: %@", [self waterWallProviderCommand:@"state" manager:manager]);
        }
        XCTAssertEqual(manager.status, YDVPNStatusDisconnected);
        NSUserDefaults *shared = [[NSUserDefaults alloc] initWithSuiteName:@"group.tr.com.srp.vpn"];
        NSString *message = [shared objectForKey:@"SRPLastError"][@"message"];
        XCTAssertTrue([message containsString:@"after 1 attempts"], @"%@", message);
    } @finally {
        if (manager.status != YDVPNStatusDisconnected) [self waitForLiveVPNDisconnect:manager];
    }
#else
    XCTSkip(@"Runtime recovery instrumentation requires a Debug build.");
#endif
}

- (void)testWaterWallLivePeerRecoveryWhenConfigured {
#if DEBUG
    NSDictionary *environment = NSProcessInfo.processInfo.environment;
    if (![environment[@"SRP_PEER_RECOVERY_TEST"] isEqualToString:@"1"]) return;
    PDVPNManager *manager = PDVPNManager.sharedManager;
    XCTAssertTrue([self waitForLiveVPNManagerReady:manager]);
    if (manager.status != YDVPNStatusDisconnected) {
        XCTSkip(@"An existing VPN connection must be disconnected before running this test.");
    }
    @try {
        NodeModel *model = [self liveWaterWallModelFromEnvironment];
        XCTAssertNotNil(model);
        if (model == nil) return;
        model.retryTimes = 2;
        model.autoReconnect = YES;
        NSString *error = nil;
        XCTAssertTrue([self waitForLiveVPNConnection:manager server:[CheckConnectData checkConnectParmer:model] error:&error], @"%@", error);
        if (manager.status != YDVPNStatusConnected) return;
        NSLog(@"SRP peer-failure test ready");
        XCTAssertTrue([self waitForWaterWallState:@"up" value:NO manager:manager timeout:30]);
        XCTAssertTrue([self waitForWaterWallState:@"up" value:YES manager:manager timeout:45]);
        XCTAssertTrue([self waterWallLiveHTTPS204:model]);
        XCTAssertTrue([self performSustainedLiveStressDownloads:manager environment:environment]);
        [self waitForLiveVPNDisconnect:manager];
        [NSThread sleepForTimeInterval:3];
        XCTAssertEqual(manager.status, YDVPNStatusDisconnected);
    } @finally {
        if (manager.status != YDVPNStatusDisconnected) [self waitForLiveVPNDisconnect:manager];
    }
#else
    XCTSkip(@"Runtime recovery instrumentation requires a Debug build.");
#endif
}

#if TARGET_OS_IPHONE
- (BOOL)waitForPhysicalWiFi:(BOOL)wifi currentPath:(id __strong *)currentPath timeout:(NSTimeInterval)timeout {
    NSDate *deadline = [NSDate dateWithTimeIntervalSinceNow:timeout];
    while (NSDate.date.timeIntervalSince1970 < deadline.timeIntervalSince1970) {
        nw_path_t path = (nw_path_t)*currentPath;
        if (path != nil && nw_path_get_status(path) == nw_path_status_satisfied &&
            nw_path_uses_interface_type(path, nw_interface_type_wifi) == wifi &&
            (wifi || nw_path_uses_interface_type(path, nw_interface_type_cellular))) return YES;
        [NSThread sleepForTimeInterval:0.2];
    }
    return NO;
}
#if DEBUG
- (BOOL)waitForWaterWallSettingsAfter:(NSInteger)generation manager:(PDVPNManager *)manager timeout:(NSTimeInterval)timeout {
    NSDate *deadline = [NSDate dateWithTimeIntervalSinceNow:timeout];
    while (NSDate.date.timeIntervalSince1970 < deadline.timeIntervalSince1970) {
        NSDictionary *state = [self waterWallProviderCommand:@"state" manager:manager];
        if ([state[@"settingsGeneration"] integerValue] > generation && [state[@"up"] boolValue]) return YES;
        [NSThread sleepForTimeInterval:0.1];
    }
    return NO;
}
#endif
#endif

- (void)testWaterWallLiveNetworkTransitionWhenConfigured {
#if TARGET_OS_IPHONE
    NSDictionary *environment = NSProcessInfo.processInfo.environment;
    if (![environment[@"SRP_NETWORK_TRANSITION_TEST"] isEqualToString:@"1"]) return;
    PDVPNManager *manager = PDVPNManager.sharedManager;
    XCTAssertTrue([self waitForLiveVPNManagerReady:manager]);
    if (manager.status != YDVPNStatusDisconnected) {
        XCTSkip(@"An existing VPN connection must be disconnected before running this test.");
    }
    nw_path_monitor_t monitor = nw_path_monitor_create();
    __block id currentPath;
    nw_path_monitor_set_queue(monitor, dispatch_queue_create("srp.live-network-path", DISPATCH_QUEUE_SERIAL));
    nw_path_monitor_set_update_handler(monitor, ^(nw_path_t path) {
        currentPath = path;
    });
    nw_path_monitor_start(monitor);
    @try {
        NodeModel *model = [self liveWaterWallModelFromEnvironment];
        XCTAssertNotNil(model);
        if (model == nil) return;
        model.autoReconnect = YES;
        model.retryTimes = 2;
        model.switchToWifi = YES;
        NSLog(@"Network transition: turn Wi-Fi OFF on the device; cellular data must remain available");
        if (![self waitForPhysicalWiFi:NO currentPath:&currentPath timeout:300]) {
            XCTFail(@"Physical Wi-Fi did not turn off");
            return;
        }
        NSString *error = nil;
        XCTAssertTrue([self waitForLiveVPNConnection:manager server:[CheckConnectData checkConnectParmer:model] error:&error], @"%@", error);
        if (manager.status != YDVPNStatusConnected) return;
        for (NSUInteger phase = 0; phase < 4; ++phase) {
            if (phase > 0) {
#if DEBUG
                NSInteger generation = [[self waterWallProviderCommand:@"state" manager:manager][@"settingsGeneration"] integerValue];
#endif
                BOOL wifi = phase % 2 == 1;
                NSLog(@"Network transition %lu/3: turn Wi-Fi %@", (unsigned long)phase, wifi ? @"ON" : @"OFF");
                if (![self waitForPhysicalWiFi:wifi currentPath:&currentPath timeout:300]) {
                    XCTFail(@"Physical Wi-Fi transition was not observed");
                    return;
                }
#if DEBUG
                if (![self waitForWaterWallSettingsAfter:generation manager:manager timeout:30]) {
                    XCTFail(@"The new tunnel network settings were not applied");
                    return;
                }
#endif
            }
            NSLog(@"Network traffic phase %lu/4 starting", (unsigned long)(phase + 1));
            if (![self performSustainedLiveStressDownloads:manager environment:environment]) {
                XCTFail(@"Traffic failed during a network transition phase");
                return;
            }
            if (manager.status != YDVPNStatusConnected) {
                XCTFail(@"VPN disconnected during a network transition phase");
                return;
            }
        }
        [self waitForLiveVPNDisconnect:manager];
        XCTAssertEqual(manager.status, YDVPNStatusDisconnected);
    } @finally {
        nw_path_monitor_cancel(monitor);
        currentPath = nil;
        if (manager.status != YDVPNStatusDisconnected) [self waitForLiveVPNDisconnect:manager];
    }
#else
    XCTSkip(@"Physical network-transition testing requires an iOS device.");
#endif
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
    model.tlsFragMode = [environment[@"SRP_AETHER_TLS_FRAG"] integerValue];
    model.aetherTor = @"off";
    model.logLevel = 2;
    XCTAssertTrue([self runLiveConnectionRoundsForModel:model manager:manager environment:environment]);
}

- (void)testPsiphonCloseCanReleaseTheProviderOnItsWorker {
    __weak SRPPsiphonClient *weakClient;
    @autoreleasepool {
        SRPPsiphonClient *client = [SRPPsiphonClient new];
        weakClient = client;
        [client setValue:^{ (void)[client description]; } forKey:@"outputCb"];
        [client close];
    }
    XCTestExpectation *released = [self expectationWithDescription:@"Psiphon closes without reentering its worker synchronously"];
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 300 * NSEC_PER_MSEC), dispatch_get_main_queue(), ^{
        XCTAssertNil(weakClient);
        [released fulfill];
    });
    [self waitForExpectations:@[released] timeout:2];
}

- (void)testAetherCloseCanReleaseTheProviderOnItsWorker {
    __weak SRPAetherClient *weakClient;
    @autoreleasepool {
        SRPAetherClient *client = [SRPAetherClient new];
        weakClient = client;
        [client setValue:@[[NSData data]] forKey:@"pendingPackets"];
        [client setValue:^{ (void)[client description]; } forKey:@"injectionCompletion"];
        [client close];
    }
    XCTestExpectation *released = [self expectationWithDescription:@"Aether closes without reentering its worker synchronously"];
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 300 * NSEC_PER_MSEC), dispatch_get_main_queue(), ^{
        XCTAssertNil(weakClient);
        [released fulfill];
    });
    [self waitForExpectations:@[released] timeout:2];
}

- (void)testWaterWallCloseCanReleaseTheProviderOnItsWorker {
    __weak SRPWaterWallClient *weakClient;
    @autoreleasepool {
        SRPWaterWallClient *client = [SRPWaterWallClient new];
        weakClient = client;
        [client setValue:@[[NSData data]] forKey:@"pendingPackets"];
        [client setValue:^{ (void)[client description]; } forKey:@"injectionCompletion"];
        [client close];
    }
    XCTestExpectation *released = [self expectationWithDescription:@"WaterWall closes without reentering its worker synchronously"];
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 300 * NSEC_PER_MSEC), dispatch_get_main_queue(), ^{
        XCTAssertNil(weakClient);
        [released fulfill];
    });
    [self waitForExpectations:@[released] timeout:2];
}

- (void)startWaterWallLifecycleClient:(SRPWaterWallLifecycleTestClient *)client
                             failure:(SRPWaterWallFailureBlock)failure {
    client.switchToWifi = NO;
    [client startWithOutputCallback:^(NSData *packet, int family) {
        (void)packet;
        (void)family;
    } networkSettingsCallback:^(NEPacketTunnelNetworkSettings *setting, void (^completion)(NSError *error)) {
        (void)setting;
        completion(nil);
    } connectedCallback:nil failureCallback:failure];
}

- (void)testWaterWallRetryLimitAndManualDisconnect {
    SRPWaterWallLifecycleTestClient *limited = [SRPWaterWallLifecycleTestClient new];
    limited.retryTimes = 2;
    limited.failuresBeforeSuccess = NSIntegerMax;
    XCTestExpectation *terminal = [self expectationWithDescription:@"WaterWall exhausts its configured retry budget"];
    __block NSString *terminalReason;
    [self startWaterWallLifecycleClient:limited failure:^(NSString *reason) {
        terminalReason = reason;
        [terminal fulfill];
    }];
    [self waitForExpectations:@[terminal] timeout:7];
    XCTAssertEqual(limited.runtimeStarts, 3);
    XCTAssertTrue([terminalReason containsString:@"after 2 attempts"]);
    XCTAssertTrue([[limited valueForKey:@"closed"] boolValue]);

    SRPWaterWallLifecycleTestClient *manual = [SRPWaterWallLifecycleTestClient new];
    manual.retryTimes = 5;
    manual.failuresBeforeSuccess = NSIntegerMax;
    __block NSString *manualFailure;
    [self startWaterWallLifecycleClient:manual failure:^(NSString *reason) {
        manualFailure = reason;
    }];
    XCTestExpectation *pending = [self expectationWithDescription:@"A retry is pending before the user disconnects"];
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 100 * NSEC_PER_MSEC), dispatch_get_main_queue(), ^{
        XCTAssertTrue([[manual valueForKey:@"reconnectPending"] boolValue]);
        [manual closeAndWait];
        [pending fulfill];
    });
    [self waitForExpectations:@[pending] timeout:2];
    XCTestExpectation *suppressed = [self expectationWithDescription:@"The pending retry is cancelled"];
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 2400 * NSEC_PER_MSEC), dispatch_get_main_queue(), ^{
        XCTAssertEqual(manual.runtimeStarts, 1);
        XCTAssertNil(manualFailure);
        [suppressed fulfill];
    });
    [self waitForExpectations:@[suppressed] timeout:4];
}

- (void)testWaterWallReconnectCanBeDisabled {
    SRPWaterWallLifecycleTestClient *client = [SRPWaterWallLifecycleTestClient new];
    client.autoReconnect = NO;
    client.retryTimes = 5;
    client.failuresBeforeSuccess = NSIntegerMax;
    XCTestExpectation *terminal = [self expectationWithDescription:@"Disabled auto-reconnect reports a terminal failure"];
    [self startWaterWallLifecycleClient:client failure:^(NSString *reason) {
        XCTAssertTrue([reason containsString:@"Injected runtime failure"]);
        [terminal fulfill];
    }];
    [self waitForExpectations:@[terminal] timeout:2];
    XCTAssertEqual(client.runtimeStarts, 1);
    XCTAssertTrue([[client valueForKey:@"closed"] boolValue]);
}

- (void)testWaterWallHealthProbeDoesNotDisconnectActiveTraffic {
    SRPWaterWallClient *client = [SRPWaterWallClient new];
    client.autoReconnect = NO;
    __block NSString *failure;
    [client setValue:[^(NSString *reason) { failure = reason; } copy] forKey:@"failureCb"];
    [client setValue:@YES forKey:@"up"];
    [client setValue:@4 forKey:@"probeStage"];
    [client setValue:@(NSProcessInfo.processInfo.systemUptime) forKey:@"lastOutputAt"];
    [client healthProbeFailed:@"synthetic probe failure"];
    XCTAssertNil(failure);
    XCTAssertEqual([[client valueForKey:@"probeStage"] integerValue], 3);

    [client setValue:@(NSProcessInfo.processInfo.systemUptime - 20) forKey:@"lastOutputAt"];
    [client setValue:@4 forKey:@"probeStage"];
    [client healthProbeFailed:@"idle probe failure"];
    XCTAssertEqualObjects(failure, @"idle probe failure");
    XCTAssertTrue([[client valueForKey:@"closed"] boolValue]);
}

- (void)testWaterWallProbeBackpressureRetriesWithoutReconnect {
    SRPWaterWallClient *client = [SRPWaterWallClient new];
    client.coreJSON = @"{}";
    client.nodesJSON = @"{}";
    [client startRuntimeLocked];
    [client setValue:@YES forKey:@"up"];
    SRPTestWWSubmitCalls = 0;
    SRPTestWWSubmitResult = -EAGAIN;
    NSMutableData *packet = [NSMutableData dataWithLength:40];
    ((uint8_t *)packet.mutableBytes)[0] = 0x45;
    [client submitProbePacket:packet];
    XCTAssertEqual([[client valueForKey:@"pendingProbePackets"] count], 1U);
    XCTAssertFalse([[client valueForKey:@"closed"] boolValue]);
    SRPTestWWSubmitResult = 0;
    XCTestExpectation *drained = [self expectationWithDescription:@"A queued health probe drains after backpressure"];
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 20 * NSEC_PER_MSEC), dispatch_get_main_queue(), ^{
        XCTAssertEqual(SRPTestWWSubmitCalls, 2U);
        XCTAssertEqual([[client valueForKey:@"pendingProbePackets"] count], 0U);
        XCTAssertTrue([[client valueForKey:@"up"] boolValue]);
        XCTAssertFalse([[client valueForKey:@"closed"] boolValue]);
        XCTAssertFalse([[client valueForKey:@"reconnectPending"] boolValue]);
        XCTAssertEqualObjects([client valueForKey:@"failedAttempts"], @0);
        [client closeAndWait];
        [drained fulfill];
    });
    [self waitForExpectations:@[drained] timeout:2];
}

- (void)testWaterWallStartupRequiresRealHTTPAndDNSResponses {
    SRPWaterWallLifecycleTestClient *client = [SRPWaterWallLifecycleTestClient new];
    [client beginDataPlaneProbe];
    NSMutableData *synAck = [client.lastProbePacket mutableCopy];
    XCTAssertEqual(synAck.length, 40U);
    uint8_t *bytes = synAck.mutableBytes;
    uint8_t addresses[8], ports[4];
    memcpy(addresses, bytes + 12, 8);
    memcpy(bytes + 12, addresses + 4, 4);
    memcpy(bytes + 16, addresses, 4);
    memcpy(ports, bytes + 20, 4);
    memcpy(bytes + 20, ports + 2, 2);
    memcpy(bytes + 22, ports, 2);
    bytes[33] = 0x12;
    [client handleProbePacket:synAck];
    XCTAssertFalse([[client valueForKey:@"up"] boolValue]);
    XCTAssertGreaterThan(client.lastProbePacket.length, 44U);
    XCTAssertEqual(memcmp(client.lastProbePacket.bytes + 40, "GET /", 5), 0);

    NSMutableData *response = [client.lastProbePacket mutableCopy];
    bytes = response.mutableBytes;
    memcpy(addresses, bytes + 12, 8);
    memcpy(bytes + 12, addresses + 4, 4);
    memcpy(bytes + 16, addresses, 4);
    memcpy(ports, bytes + 20, 4);
    memcpy(bytes + 20, ports + 2, 2);
    memcpy(bytes + 22, ports, 2);
    uint32_t sequence = 0;
    for (NSUInteger index = 0; index < 4; ++index) sequence = (sequence << 8) | bytes[28 + index];
    for (NSUInteger index = 0; index < 4; ++index) bytes[24 + index] = sequence >> (24 - index * 8);
    memcpy(bytes + 40, "HTTP/", 5);
    [client handleProbePacket:response];
    XCTAssertFalse([[client valueForKey:@"up"] boolValue]);
    XCTAssertEqualObjects([client valueForKey:@"probeStage"], @2);

    NSMutableData *dnsResponse = [client.lastProbePacket mutableCopy];
    bytes = dnsResponse.mutableBytes;
    memcpy(addresses, bytes + 12, 8);
    memcpy(bytes + 12, addresses + 4, 4);
    memcpy(bytes + 16, addresses, 4);
    memcpy(ports, bytes + 20, 4);
    memcpy(bytes + 20, ports + 2, 2);
    memcpy(bytes + 22, ports, 2);
    bytes[30] |= 0x80;
    bytes[31] |= 0x80;
    bytes[35] = 1;
    [client handleProbePacket:dnsResponse];
    XCTNSPredicateExpectation *applied = [[XCTNSPredicateExpectation alloc]
        initWithPredicate:[NSPredicate predicateWithFormat:@"up == YES"] object:client];
    [self waitForExpectations:@[applied] timeout:2];
    XCTAssertTrue([[client valueForKey:@"up"] boolValue]);
    [client closeAndWait];
}

- (void)testWaterWallConnectedWaitsForNetworkSettings {
    SRPWaterWallClient *client = [SRPWaterWallClient new];
    __block void (^apply)(NSError *error);
    __block NSUInteger connected = 0;
    [client setValue:[^(NEPacketTunnelNetworkSettings *settings, void (^completion)(NSError *error)) {
        (void)settings;
        apply = [completion copy];
    } copy] forKey:@"settingsCb"];
    [client setValue:[^{ connected++; } copy] forKey:@"connectedCb"];
    [client finishProbe];
    XCTAssertFalse([[client valueForKey:@"up"] boolValue]);
    XCTAssertEqual(connected, 0U);
    XCTAssertNotNil(apply);
    XCTestExpectation *ready = [self expectationWithDescription:@"Applied network settings complete the connection"];
    [client setValue:[^{ connected++; [ready fulfill]; } copy] forKey:@"connectedCb"];
    apply(nil);
    [self waitForExpectations:@[ready] timeout:2];
    XCTAssertTrue([[client valueForKey:@"up"] boolValue]);
    XCTAssertEqual(connected, 1U);
    [client closeAndWait];
}

- (void)testWaterWallNetworkSettingsFailureDoesNotConnect {
    SRPWaterWallClient *client = [SRPWaterWallClient new];
    client.autoReconnect = NO;
    __block void (^apply)(NSError *error);
    __block NSUInteger connected = 0;
    [client setValue:[^(NEPacketTunnelNetworkSettings *settings, void (^completion)(NSError *error)) {
        (void)settings;
        apply = [completion copy];
    } copy] forKey:@"settingsCb"];
    [client setValue:[^{ connected++; } copy] forKey:@"connectedCb"];
    XCTestExpectation *failed = [self expectationWithDescription:@"Settings errors surface as a connection failure"];
    [client setValue:[^(NSString *reason) {
        XCTAssertTrue([reason containsString:@"Synthetic settings error"]);
        [failed fulfill];
    } copy] forKey:@"failureCb"];
    [client finishProbe];
    apply([NSError errorWithDomain:@"SRPTests" code:1 userInfo:@{NSLocalizedDescriptionKey: @"Synthetic settings error"}]);
    [self waitForExpectations:@[failed] timeout:2];
    XCTAssertFalse([[client valueForKey:@"up"] boolValue]);
    XCTAssertEqual(connected, 0U);
    [client closeAndWait];
}

- (void)testWaterWallHealthMonitorStarts {
    SRPWaterWallLifecycleTestClient *client = [SRPWaterWallLifecycleTestClient new];
    client.autoReconnect = NO;
    [client setValue:@YES forKey:@"up"];
    [client setValue:@3 forKey:@"probeStage"];
    [client startHealthMonitor];
    XCTestExpectation *probe = [self expectationWithDescription:@"Health monitor submits a probe"];
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 17 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
        XCTAssertGreaterThan(client.submittedPackets, 0);
        [probe fulfill];
    });
    [self waitForExpectations:@[probe] timeout:19];
    [client closeAndWait];
}

- (void)testWaterWallSleepModes {
    for (NSNumber *mode in @[@2, @1, @0]) {
        SRPWaterWallLifecycleTestClient *client = [SRPWaterWallLifecycleTestClient new];
        client.onSleep = mode.integerValue;
        client.autoReconnect = NO;
        [self startWaterWallLifecycleClient:client failure:nil];
        [client pauseForSleep];
        [client wakeFromSleep];
        XCTestExpectation *transition = [self expectationWithDescription:@"Sleep mode transition"];
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 150 * NSEC_PER_MSEC), dispatch_get_main_queue(), ^{
            XCTAssertEqual(client.runtimeStarts, mode.integerValue == 1 ? 2 : 1);
            XCTAssertEqual([[client valueForKey:@"up"] boolValue], mode.integerValue != 0);
            XCTAssertFalse([[client valueForKey:@"sleepPaused"] boolValue]);
            [client closeAndWait];
            [transition fulfill];
        });
        [self waitForExpectations:@[transition] timeout:2];
    }
}

- (void)testWaterWallSleepResumePreservesPendingPackets {
    SRPWaterWallLifecycleTestClient *client = [SRPWaterWallLifecycleTestClient new];
    client.onSleep = 1;
    [self startWaterWallLifecycleClient:client failure:nil];
    [client pauseForSleep];
    XCTestExpectation *resumed = [self expectationWithDescription:@"Paused injection resumes after the runtime is ready"];
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 100 * NSEC_PER_MSEC), dispatch_get_main_queue(), ^{
        NSMutableData *packet = [NSMutableData dataWithLength:40];
        ((uint8_t *)packet.mutableBytes)[0] = 0x45;
        [client injectPackets:@[packet] completion:^{
            [resumed fulfill];
        }];
        [client wakeFromSleep];
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 100 * NSEC_PER_MSEC), dispatch_get_main_queue(), ^{
            [client drainInjectedPacketsLocked];
            XCTAssertEqual(client.runtimeStarts, 2);
            XCTAssertEqual(client.submittedPackets, 1);
            XCTAssertNil([client valueForKey:@"pendingPackets"]);
            [client closeAndWait];
        });
    });
    [self waitForExpectations:@[resumed] timeout:3];
}

- (void)testWaterWallOverlappingInjectionPreservesBothReadBatches {
    SRPWaterWallLifecycleTestClient *client = [SRPWaterWallLifecycleTestClient new];
    client.onSleep = 1;
    [self startWaterWallLifecycleClient:client failure:nil];
    [client pauseForSleep];
    XCTestExpectation *both = [self expectationWithDescription:@"Both read generations complete after resume"];
    both.expectedFulfillmentCount = 2;
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 100 * NSEC_PER_MSEC), dispatch_get_main_queue(), ^{
        NSMutableData *packet = [NSMutableData dataWithLength:40];
        ((uint8_t *)packet.mutableBytes)[0] = 0x45;
        [client injectPackets:@[packet] completion:^{ [both fulfill]; }];
        [client injectPackets:@[packet] completion:^{ [both fulfill]; }];
        [client wakeFromSleep];
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 100 * NSEC_PER_MSEC), dispatch_get_main_queue(), ^{
            [client drainInjectedPacketsLocked];
        });
    });
    [self waitForExpectations:@[both] timeout:2];
    XCTAssertEqual(client.submittedPackets, 2);
    XCTAssertNil([client valueForKey:@"pendingPackets"]);
    [client closeAndWait];
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

- (NSDictionary *)vmessNoneProfileConfiguration {
    return @{@"version": @3, @"mode": @"chain", @"input": @"connections", @"application": @"vmess",
             @"mux": @NO, @"outer": @"none", @"http": @"off", @"http-version": @1, @"obfuscator": @NO,
             @"carrier": @"tcp", @"quic-carrier": @"datagram", @"node-options": @{}, @"bgp4": @NO};
}

/// The editor's owner is weak, so the caller keeps this container alive.
- (CreateVC *)profileEditorHostForModel:(NodeModel *)model saved:(NSMutableArray<NodeModel *> *)saved {
    CreateVC *create = [NSClassFromString(@"CreateVC") new];
    create.t_modal = model;
    [create createNodeBackResult:^(NodeModel *modal) {
        [saved addObject:modal];
    }];
    [create loadViewIfNeeded];
    return create;
}

- (UIViewController *)profileEditorOfHost:(CreateVC *)create {
    UINavigationController *navigation = (UINavigationController *)create.childViewControllers.firstObject;
    UIViewController *editor = navigation.topViewController;
    [editor loadViewIfNeeded];
    return editor;
}

- (void)tapSaveOnProfileEditor:(UIViewController *)editor {
    UIBarButtonItem *save = editor.navigationItem.rightBarButtonItem;
    XCTAssertTrue(save.enabled);
    [UIApplication.sharedApplication sendAction:save.action to:save.target from:save forEvent:nil];
}

- (void)testProfileSaveTrimsPastedWaterWallValues {
    NodeModel *model = [NodeModel new];
    model.protocolType = @"waterwall";
    model.server = @" waterwall.example \n";
    model.port = @"443 ";
    model.password = @"00112233-4455-6677-8899-aabbccddeeff\n";
    model.waterwallConfigJSON = [SRPWaterWallChainConfig JSONWithConfiguration:[self vmessNoneProfileConfiguration]];
    NSMutableArray<NodeModel *> *saved = [NSMutableArray new];
    CreateVC *create = [self profileEditorHostForModel:model saved:saved];
    [self tapSaveOnProfileEditor:[self profileEditorOfHost:create]];
    XCTAssertEqual(saved.count, 1U);
    XCTAssertEqualObjects(saved.firstObject.server, @"waterwall.example");
    XCTAssertEqualObjects(saved.firstObject.port, @"443");
    XCTAssertEqualObjects(saved.firstObject.password, @"00112233-4455-6677-8899-aabbccddeeff");
}

- (void)testProfileSaveStaysTappableAndNamesMissingValue {
    NodeModel *model = [NodeModel new];
    model.protocolType = @"waterwall";
    model.server = @"waterwall.example";
    model.port = @"443";
    model.waterwallConfigJSON = [SRPWaterWallChainConfig JSONWithConfiguration:[self vmessNoneProfileConfiguration]];
    NSMutableArray<NodeModel *> *saved = [NSMutableArray new];
    CreateVC *create = [self profileEditorHostForModel:model saved:saved];
    UIViewController *editor = [self profileEditorOfHost:create];
    XCTAssertEqualObjects([editor validationMessage], @"Enter a VMess UUID or a short string ID of 1 to 30 UTF-8 bytes.");
    [self tapSaveOnProfileEditor:editor];
    XCTAssertEqual(saved.count, 0U);
}

- (void)testProfileSaveKeepsPasswordWhitespace {
    NodeModel *model = [NodeModel new];
    model.protocolType = @"sstp";
    model.authMethod = @"password";
    model.MSCHAP2 = YES;
    model.server = @"sstp.example\n";
    model.username = @"user";
    model.password = @" secret ";
    NSMutableArray<NodeModel *> *saved = [NSMutableArray new];
    CreateVC *create = [self profileEditorHostForModel:model saved:saved];
    [self tapSaveOnProfileEditor:[self profileEditorOfHost:create]];
    XCTAssertEqual(saved.count, 1U);
    XCTAssertEqualObjects(saved.firstObject.server, @"sstp.example");
    XCTAssertEqualObjects(saved.firstObject.password, @" secret ");
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
    BOOL validate = [environment[@"SRP_MATRIX_VALIDATE"] isEqualToString:@"1"];
    NSMutableArray *results = [NSMutableArray new];
    for (id entry in (NSArray *)inputJSON) {
        XCTAssertTrue([entry isKindOfClass:NSDictionary.class]);
        if (![entry isKindOfClass:NSDictionary.class]) return;
        NSDictionary *caseInput = entry;
        NSDictionary *configuration = caseInput[@"configuration"];
        if (validate) {
            NSString *validationError = [SRPWaterWallChainConfig validationErrorForConfiguration:configuration];
            if (validationError != nil) {
                [results addObject:@{@"id": caseInput[@"id"] ?: @"", @"supported": @NO,
                                     @"configuration": configuration, @"reason": validationError}];
                continue;
            }
        }
        NSString *nodesJSON;
        if ([SRPWaterWallChainConfig isWireGuardConfiguration:configuration] && caseInput[@"wireguard"] != nil) {
            nodesJSON = [SRPWaterWallChainConfig wireGuardConfigurationWithConfig:caseInput[@"wireguard"]][@"nodesJSON"];
        } else {
            nodesJSON = [SRPWaterWallChainConfig nodesJSONForConfiguration:configuration
                server:caseInput[@"server"]
                port:[caseInput[@"port"] integerValue]
                sni:caseInput[@"sni"]
                verifyTLS:caseInput[@"verifyTLS"] == nil || [caseInput[@"verifyTLS"] boolValue]
                secret:caseInput[@"secret"]
                outerSecret:caseInput[@"outerSecret"]
                options:caseInput[@"options"]];
        }
        XCTAssertNotNil(nodesJSON, @"Builder rejected matrix input %@", configuration);
        if (nodesJSON == nil) return;
        NSDictionary *nodes = [NSJSONSerialization JSONObjectWithData:[nodesJSON dataUsingEncoding:NSUTF8StringEncoding]
                                                               options:0
                                                                 error:&error];
        XCTAssertNotNil(nodes, @"%@", error);
        if (nodes == nil) return;
        if (validate) {
            [results addObject:@{@"id": caseInput[@"id"] ?: @"", @"supported": @YES,
                                 @"configuration": configuration, @"nodes": nodes}];
        } else {
            [results addObject:nodes];
        }
    }
    id result = validate ? @{@"cases": results} : results;
    NSData *output = [NSJSONSerialization dataWithJSONObject:result options:NSJSONWritingPrettyPrinted error:&error];
    XCTAssertNotNil(output, @"%@", error);
    if (output == nil) return;
    XCTAssertTrue([output writeToFile:outputPath options:NSDataWritingAtomic error:&error], @"%@", error);
}

@end
