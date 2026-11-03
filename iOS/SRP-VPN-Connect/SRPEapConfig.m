//
//  SRPEapConfig.m
//  SRP-VPN-Connect
//

#import "SRPEapConfig.h"

@implementation SRPEapConfig

- (instancetype)initWithDefaults {
    self = [super init];
    if (self) {
        _eapMschapv2Enabled = NO;
        _peapEnabled = NO;
        _peapRequireCryptoBinding = NO;
        _ttlsInnerMethod = SRPTtlsInnerMethodDisabled;
        _teapEnabled = NO;
        _teapSecondaryMethod = SRPTeapSecondaryMethodNone;
        _identityPrivacyEnabled = NO;
        _anonymousIdentity = @"anonymous";
        _eapTls13Enabled = YES;
        _disableLegacyEapTls = YES;
    }
    return self;
}

+ (instancetype)initWithDefaults {
    return [[self alloc] initWithDefaults];
}

- (NSDictionary *)toDictionary {
    return @{
        @"eap_mschapv2_enabled": @(self.eapMschapv2Enabled),
        @"peap_enabled": @(self.peapEnabled),
        @"peap_require_crypto_binding": @(self.peapRequireCryptoBinding),
        @"ttls_inner_method": @(self.ttlsInnerMethod),
        @"teap_enabled": @(self.teapEnabled),
        @"teap_secondary_method": @(self.teapSecondaryMethod),
        @"identity_privacy_enabled": @(self.identityPrivacyEnabled),
        @"anonymous_identity": self.anonymousIdentity ?: @"anonymous",
        @"eap_tls13_enabled": @(self.eapTls13Enabled),
        @"disable_legacy_eap_tls": @(self.disableLegacyEapTls),
    };
}

+ (instancetype)fromDictionary:(NSDictionary *)dict {
    SRPEapConfig *c = [[SRPEapConfig alloc] initWithDefaults];
    if (![dict isKindOfClass:NSDictionary.class]) {
        return c;
    }
    if (dict[@"eap_mschapv2_enabled"]) c.eapMschapv2Enabled = [dict[@"eap_mschapv2_enabled"] boolValue];
    if (dict[@"peap_enabled"]) c.peapEnabled = [dict[@"peap_enabled"] boolValue];
    if (dict[@"peap_require_crypto_binding"]) c.peapRequireCryptoBinding = [dict[@"peap_require_crypto_binding"] boolValue];
    if (dict[@"ttls_inner_method"]) c.ttlsInnerMethod = [dict[@"ttls_inner_method"] integerValue];
    if (dict[@"teap_enabled"]) c.teapEnabled = [dict[@"teap_enabled"] boolValue];
    if (dict[@"teap_secondary_method"]) c.teapSecondaryMethod = [dict[@"teap_secondary_method"] integerValue];
    if (dict[@"identity_privacy_enabled"]) c.identityPrivacyEnabled = [dict[@"identity_privacy_enabled"] boolValue];
    if (dict[@"anonymous_identity"]) c.anonymousIdentity = dict[@"anonymous_identity"];
    if (dict[@"eap_tls13_enabled"]) c.eapTls13Enabled = [dict[@"eap_tls13_enabled"] boolValue];
    if (dict[@"disable_legacy_eap_tls"]) c.disableLegacyEapTls = [dict[@"disable_legacy_eap_tls"] boolValue];
    return c;
}

@end
