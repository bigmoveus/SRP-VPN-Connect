//
//  SRPAuthConfigTests.m
//  SRP-VPN-ConnectTests
//
//  Phase 3 unit tests: serialization, migration, layer separation,
//  capability gating, Keychain, TTLS enum persistence.
//

#import <XCTest/XCTest.h>
#import "SRPEapConfig.h"
#import "SRPKeychain.h"
#import "NodeModel.h"
#import "CheckConnectData.h"
#import "userNodeData.h"
#import "SSAuthCapabilities.h"

@interface SRPAuthConfigTests : XCTestCase
@end

@implementation SRPAuthConfigTests

#pragma mark - 1. Serialization round-trip

- (void)testEapConfigDefaults {
    SRPEapConfig *c = [SRPEapConfig initWithDefaults];
    XCTAssertFalse(c.eapMschapv2Enabled);
    XCTAssertFalse(c.peapEnabled);
    XCTAssertFalse(c.peapRequireCryptoBinding);
    XCTAssertEqual(c.ttlsInnerMethod, SRPTtlsInnerMethodDisabled);
    XCTAssertFalse(c.teapEnabled);
    XCTAssertEqual(c.teapSecondaryMethod, SRPTeapSecondaryMethodNone);
    XCTAssertFalse(c.identityPrivacyEnabled);
    XCTAssertEqualObjects(c.anonymousIdentity, @"anonymous");
    XCTAssertTrue(c.eapTls13Enabled);
    XCTAssertTrue(c.disableLegacyEapTls);
}

- (void)testEapConfigRoundTrip {
    SRPEapConfig *c = [SRPEapConfig initWithDefaults];
    c.eapMschapv2Enabled = YES;
    c.peapEnabled = YES;
    c.peapRequireCryptoBinding = YES;
    c.ttlsInnerMethod = SRPTtlsInnerMethodMSCHAPv2;
    c.teapEnabled = YES;
    c.identityPrivacyEnabled = YES;
    c.anonymousIdentity = @"hidden@example.com";
    c.eapTls13Enabled = NO;
    c.disableLegacyEapTls = NO;

    NSDictionary *d = [c toDictionary];
    SRPEapConfig *r = [SRPEapConfig fromDictionary:d];

    XCTAssertEqual(r.eapMschapv2Enabled, c.eapMschapv2Enabled);
    XCTAssertEqual(r.peapEnabled, c.peapEnabled);
    XCTAssertEqual(r.peapRequireCryptoBinding, c.peapRequireCryptoBinding);
    XCTAssertEqual(r.ttlsInnerMethod, c.ttlsInnerMethod);
    XCTAssertEqual(r.teapEnabled, c.teapEnabled);
    XCTAssertEqual(r.teapSecondaryMethod, c.teapSecondaryMethod);
    XCTAssertEqual(r.identityPrivacyEnabled, c.identityPrivacyEnabled);
    XCTAssertEqualObjects(r.anonymousIdentity, c.anonymousIdentity);
    XCTAssertEqual(r.eapTls13Enabled, c.eapTls13Enabled);
    XCTAssertEqual(r.disableLegacyEapTls, c.disableLegacyEapTls);
}

#pragma mark - 2. Migration

- (void)testLegacyDictMigration {
    NSUserDefaults *ud = NSUserDefaults.standardUserDefaults;
    id saved = [ud objectForKey:@"nodeArray"];

    @try {
        NSDictionary *legacy = @{
            @"type": @"sstp",
            @"username": @"legacyuser",
            @"password": @"legacy-secret-pw",
            @"address": @"vpn.example.com",
            @"port": @"443",
            @"pap_enable": @1,
            @"chap_enable": @0,
            @"mschap2_enable": @1,
            @"allowInsecure": @0,
        };
        [ud setObject:@[legacy] forKey:@"nodeArray"];

        // nodeArray getter performs migration + re-save
        NSMutableArray *nodes = [userNodeData shareInstance].nodeArray;
        XCTAssertEqual(nodes.count, 1);

        NodeModel *m = nodes.firstObject;
        // allowLegacyPapChap = old pap_enable || chap_enable
        XCTAssertTrue(m.allowLegacyPapChap);
        // eapConfig falls back to defaults
        XCTAssertFalse(m.eapConfig.eapMschapv2Enabled);
        XCTAssertEqual(m.eapConfig.ttlsInnerMethod, SRPTtlsInnerMethodDisabled);
        XCTAssertEqualObjects(m.eapConfig.anonymousIdentity, @"anonymous");
        XCTAssertTrue(m.eapConfig.eapTls13Enabled);
        // password migrated into memory + keychain
        XCTAssertEqualObjects(m.password, @"legacy-secret-pw");
        XCTAssertNotNil(m.passwordKey);
        XCTAssertEqualObjects([SRPKeychain passwordForKey:m.passwordKey], @"legacy-secret-pw");

        // re-saved store must not contain plaintext
        NSArray *stored = [ud objectForKey:@"nodeArray"];
        XCTAssertEqual(stored.count, 1);
        NSDictionary *clean = stored.firstObject;
        XCTAssertNil(clean[@"password"], @"plaintext password must not persist");
        XCTAssertNotNil(clean[@"password_key"]);

        [SRPKeychain deletePasswordForKey:m.passwordKey];
    }
    @finally {
        if (saved) {
            [ud setObject:saved forKey:@"nodeArray"];
        } else {
            [ud removeObjectForKey:@"nodeArray"];
        }
        [ud synchronize];
    }
}

#pragma mark - 3. Layer separation invariants

- (void)testDirectPapIsNotTtlsPap {
    NodeModel *m = [NodeModel new];
    m.server = @"vpn.example.com";
    m.username = @"u";
    // no password -> checkConnectParmer skips Keychain sync
    m.allowLegacyPapChap = YES;
    m.eapConfig.ttlsInnerMethod = SRPTtlsInnerMethodDisabled;

    NSDictionary *d = [CheckConnectData checkConnectParmer:m];
    XCTAssertEqualObjects(d[@"pap_enable"], @1);
    XCTAssertEqualObjects(d[@"chap_enable"], @1);
    XCTAssertEqualObjects(d[@"allow_legacy_papchap"], @1);
    SRPEapConfig *ec = [SRPEapConfig fromDictionary:d[@"eap_config"]];
    XCTAssertEqual(ec.ttlsInnerMethod, SRPTtlsInnerMethodDisabled);
}

- (void)testTtlsPapDoesNotSetDirectPap {
    NodeModel *m = [NodeModel new];
    m.allowLegacyPapChap = NO;
    m.eapConfig.ttlsInnerMethod = SRPTtlsInnerMethodPAP;

    NSDictionary *d = [CheckConnectData checkConnectParmer:m];
    XCTAssertEqualObjects(d[@"pap_enable"], @0, @"TTLS-PAP must not enable direct PAP");
    XCTAssertEqualObjects(d[@"chap_enable"], @0);
    SRPEapConfig *ec = [SRPEapConfig fromDictionary:d[@"eap_config"]];
    XCTAssertEqual(ec.ttlsInnerMethod, SRPTtlsInnerMethodPAP);
}

- (void)testEapMschapv2DoesNotImplyPeap {
    SRPEapConfig *c = [SRPEapConfig initWithDefaults];
    c.eapMschapv2Enabled = YES;
    XCTAssertFalse(c.peapEnabled);

    SRPEapConfig *r = [SRPEapConfig fromDictionary:[c toDictionary]];
    XCTAssertTrue(r.eapMschapv2Enabled);
    XCTAssertFalse(r.peapEnabled);
}

- (void)testTlsOptionsLiveOnlyOnEapConfig {
    NodeModel *m = [NodeModel new];
    XCTAssertFalse([m respondsToSelector:@selector(setEapTls13Enabled:)],
                   @"NodeModel must not carry EAP TLS options");
    XCTAssertFalse([m respondsToSelector:@selector(eapTls13Enabled)]);

    SRPEapConfig *c = [SRPEapConfig initWithDefaults];
    XCTAssertFalse([c respondsToSelector:@selector(setAllowInsecure:)],
                   @"eapConfig must not carry SSTP outer-TLS settings");
    XCTAssertFalse([c respondsToSelector:@selector(setTls:)]);
}

- (void)testPeapCryptoBindingIndependentFromSstpTls {
    NodeModel *m = [NodeModel new];
    m.eapConfig.peapRequireCryptoBinding = YES;
    m.TLS = NO;
    NSDictionary *d = [CheckConnectData checkConnectParmer:m];
    XCTAssertEqualObjects(d[@"allowInsecure"], @0,
                          @"peapRequireCryptoBinding must not affect SSTP outer TLS");

    m.eapConfig.peapRequireCryptoBinding = NO;
    m.TLS = YES;
    d = [CheckConnectData checkConnectParmer:m];
    XCTAssertEqualObjects(d[@"allowInsecure"], @1);
}

#pragma mark - 4. Capability gating

- (void)testCapabilities {
    SSAuthCapabilities *caps = [SSAuthCapabilities sharedCapabilities];
    XCTAssertTrue(caps.supportsDirectPap);
    XCTAssertTrue(caps.supportsDirectChap);
    XCTAssertTrue(caps.supportsDirectMschap);
    XCTAssertTrue(caps.supportsDirectMschapv2);

    // EAP-MSCHAPv2 (bare, no inner TLS tunnel) is supported since Phase 4
    XCTAssertTrue(caps.supportsEapMschapv2);
    // PEAP (inner TLS tunnel + inner EAP-MSCHAPv2) verified against RRAS
    XCTAssertTrue(caps.supportsPeap);
    XCTAssertTrue(caps.supportsPeapCryptoBinding);
    // EAP-TTLS with inner EAP-MSCHAPv2 verified against FreeRADIUS (Phase TTLS)
    XCTAssertTrue(caps.supportsEapTtls);
    XCTAssertTrue(caps.supportsTtlsPap);
    XCTAssertTrue(caps.supportsTtlsChap);
    XCTAssertTrue(caps.supportsTtlsMschapv2);
    // TEAP with inner EAP-MSCHAPv2 (swapped-IMSK crypto binding) verified vs FreeRADIUS
    XCTAssertTrue(caps.supportsTeap);
    XCTAssertFalse(caps.supportsTeapSecondaryAuthentication);
    XCTAssertTrue(caps.supportsEapTls13);

    XCTAssertTrue(caps.eapUnsupportedReason.length > 0);
}

#pragma mark - 5. Keychain

- (void)testKeychainRoundTrip {
    NSString *key = NSUUID.UUID.UUIDString;
    XCTAssertNil([SRPKeychain passwordForKey:key]);

    XCTAssertTrue([SRPKeychain setPassword:@"s3cret-1" forKey:key]);
    XCTAssertEqualObjects([SRPKeychain passwordForKey:key], @"s3cret-1");

    // overwrite existing
    XCTAssertTrue([SRPKeychain setPassword:@"s3cret-2" forKey:key]);
    XCTAssertEqualObjects([SRPKeychain passwordForKey:key], @"s3cret-2");

    // delete
    XCTAssertTrue([SRPKeychain deletePasswordForKey:key]);
    XCTAssertNil([SRPKeychain passwordForKey:key]);

    // delete non-existent still succeeds (treated as clean)
    XCTAssertTrue([SRPKeychain deletePasswordForKey:key]);
}

#pragma mark - 6. TTLS enum persistence

- (void)testTtlsMethodEveryValueRoundTrips {
    NSArray<NSNumber *> *all = @[@(SRPTtlsInnerMethodDisabled), @(SRPTtlsInnerMethodEAP),
                                 @(SRPTtlsInnerMethodPAP), @(SRPTtlsInnerMethodCHAP),
                                 @(SRPTtlsInnerMethodMSCHAPv2)];
    for (NSNumber *n in all) {
        SRPEapConfig *c = [SRPEapConfig initWithDefaults];
        c.ttlsInnerMethod = (SRPTtlsInnerMethod)n.integerValue;
        SRPEapConfig *r = [SRPEapConfig fromDictionary:[c toDictionary]];
        XCTAssertEqual(r.ttlsInnerMethod, (SRPTtlsInnerMethod)n.integerValue,
                       @"ttlsInnerMethod %@ must survive serialization", n);
    }
}

#pragma mark - PEAP plumbing

- (void)testPeapPlumbingKeys {
    NodeModel *m = [NodeModel new];
    m.server = @"vpn.example.com";
    m.username = @"u";
    m.eapConfig.peapEnabled = YES;
    m.eapConfig.identityPrivacyEnabled = YES;
    m.eapConfig.anonymousIdentity = @"anon@example.com";
    m.eapConfig.eapTls13Enabled = NO;
    m.eapConfig.disableLegacyEapTls = YES;

    NSDictionary *d = [CheckConnectData checkConnectParmer:m];
    XCTAssertEqualObjects(d[@"peap_enable"], @1);
    XCTAssertEqualObjects(d[@"eap_identity_privacy"], @1);
    XCTAssertEqualObjects(d[@"eap_anonymous_identity"], @"anon@example.com");
    XCTAssertEqualObjects(d[@"eap_tls13"], @0);
    XCTAssertEqualObjects(d[@"eap_disable_legacy_tls"], @1);
    // PEAP must not imply bare EAP-MSCHAPv2
    XCTAssertEqualObjects(d[@"eapmschapv2_enable"], @0);
}

- (void)testPeapRequireCbPlumbingKey {
    NodeModel *m = [NodeModel new];
    m.server = @"vpn.example.com";
    m.username = @"u";
    m.eapConfig.peapEnabled = YES;
    m.eapConfig.peapRequireCryptoBinding = YES;

    NSDictionary *d = [CheckConnectData checkConnectParmer:m];
    XCTAssertEqualObjects(d[@"peap_require_cb"], @1);

    m.eapConfig.peapRequireCryptoBinding = NO;
    d = [CheckConnectData checkConnectParmer:m];
    XCTAssertEqualObjects(d[@"peap_require_cb"], @0);
}

- (void)testTtlsInnerPlumbingKeys {
    NodeModel *m = [NodeModel new];
    m.server = @"vpn.example.com";
    m.username = @"u";

    m.eapConfig.ttlsInnerMethod = SRPTtlsInnerMethodDisabled;
    NSDictionary *d = [CheckConnectData checkConnectParmer:m];
    XCTAssertEqualObjects(d[@"eapttls_enable"], @0);

    m.eapConfig.ttlsInnerMethod = SRPTtlsInnerMethodMSCHAPv2;
    d = [CheckConnectData checkConnectParmer:m];
    XCTAssertEqualObjects(d[@"eapttls_enable"], @1);
    XCTAssertEqualObjects(d[@"eapttls_inner"], @"eap"); // inner EAP-MSCHAPv2

    m.eapConfig.ttlsInnerMethod = SRPTtlsInnerMethodPAP;
    d = [CheckConnectData checkConnectParmer:m];
    XCTAssertEqualObjects(d[@"eapttls_enable"], @1);
    XCTAssertEqualObjects(d[@"eapttls_inner"], @"pap");

    m.eapConfig.ttlsInnerMethod = SRPTtlsInnerMethodCHAP;
    d = [CheckConnectData checkConnectParmer:m];
    XCTAssertEqualObjects(d[@"eapttls_inner"], @"chap");

    m.eapConfig.ttlsInnerMethod = SRPTtlsInnerMethodEAP;
    d = [CheckConnectData checkConnectParmer:m];
    XCTAssertEqualObjects(d[@"eapttls_inner"], @"eap");
}

#pragma mark - Certificate authentication (EAP-TLS)

- (void)testCertificateKeychainRoundTrip {
    NSString *key = NSUUID.UUID.UUIDString;
    NSString *pass = nil;
    XCTAssertNil([SRPKeychain certificateForKey:key passphrase:&pass]);

    NSData *p12 = [@"fake-p12-blob" dataUsingEncoding:NSUTF8StringEncoding];
    XCTAssertTrue([SRPKeychain setCertificate:p12 passphrase:@"srtp123" forKey:key]);
    NSData *read = [SRPKeychain certificateForKey:key passphrase:&pass];
    XCTAssertEqualObjects(read, p12);
    XCTAssertEqualObjects(pass, @"srtp123");

    XCTAssertTrue([SRPKeychain deleteCertificateForKey:key]);
    XCTAssertNil([SRPKeychain certificateForKey:key passphrase:&pass]);
    XCTAssertTrue([SRPKeychain deleteCertificateForKey:key]);
}

- (void)testCertificatePlumbingKeys {
    NodeModel *m = [NodeModel new];
    m.server = @"vpn.example.com";
    m.authMethod = @"certificate";
    m.certKey = @"00000000-0000-0000-0000-0000000000AB";
    m.certName = @"unit-test-identity";

    NSDictionary *d = [CheckConnectData checkConnectParmer:m];
    XCTAssertEqualObjects(d[@"cert_auth"], @1);
    XCTAssertEqualObjects(d[@"cert_key"], @"00000000-0000-0000-0000-0000000000AB");
    XCTAssertEqualObjects(d[@"cert_name"], @"unit-test-identity");
    XCTAssertNil(d[@"cert_p12"], @"the .p12 blob must never enter the profile dict");

    // round-trip back into a model
    NodeModel *r = [CheckConnectData getModalForDic:d];
    XCTAssertEqualObjects(r.authMethod, @"certificate");
    XCTAssertEqualObjects(r.certKey, m.certKey);
    XCTAssertEqualObjects(r.certName, m.certName);

    // password method must not set cert_auth even with a cert ref present
    m.authMethod = @"password";
    d = [CheckConnectData checkConnectParmer:m];
    XCTAssertEqualObjects(d[@"cert_auth"], @0);
}

- (void)testEapTlsCapability {
    XCTAssertTrue([SSAuthCapabilities sharedCapabilities].supportsEapTls);
}

- (void)testPeapCapabilityNowSupported {
    // PEAP (inner EAP-MSCHAPv2) is E2E-verified against Windows RRAS/NPS,
    // including the crypto-binding exchange and the client-side
    // "Require Crypto Binding" enforcement.
    SSAuthCapabilities *caps = [SSAuthCapabilities sharedCapabilities];
    XCTAssertTrue(caps.supportsPeap);
    XCTAssertTrue(caps.supportsPeapCryptoBinding);
    XCTAssertTrue(caps.supportsEapTls13);
    // EAP-TTLS with inner EAP-MSCHAPv2 is E2E-verified against FreeRADIUS
    XCTAssertTrue(caps.supportsEapTtls);
    // TEAP with inner EAP-MSCHAPv2 (swapped-IMSK crypto binding) verified vs FreeRADIUS
    XCTAssertTrue(caps.supportsTeap);
}

@end
