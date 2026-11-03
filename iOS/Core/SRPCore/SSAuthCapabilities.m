//
//  SSAuthCapabilities.m
//  SRPCore
//

#import "SSAuthCapabilities.h"

@implementation SSAuthCapabilities

+ (instancetype)sharedCapabilities {
    static SSAuthCapabilities *caps = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        caps = [[self alloc] init];
    });
    return caps;
}

- (instancetype)init {
    self = [super init];
    if (self) {
        // lwIP pppos backend: direct PPP auth only
        _supportsDirectPap = YES;
        _supportsDirectChap = YES;
        _supportsDirectMschap = YES;
        _supportsDirectMschapv2 = YES;

        // EAP-MSCHAPv2 (bare, no inner TLS tunnel) is supported since Phase 4
        _supportsEapMschapv2 = YES;
        _supportsPeap = YES;
        // PEAP crypto binding: fully implemented and verified against
        // Windows NPS 2019 (enforced) / 2022; with "Require Crypto Binding"
        // the client fails when the server does not negotiate it or its MAC
        // does not verify
        _supportsPeapCryptoBinding = YES;
        // EAP-TTLS (RFC 5281, TTLSv0) with inner EAP-MSCHAPv2 verified
        // against FreeRADIUS 3.2.5 (row 7 of the test matrix); inner
        // PAP/CHAP (AVP-based) verified the same way
        _supportsEapTtls = YES;
        _supportsTtlsPap = YES;
        _supportsTtlsChap = YES;
        _supportsTtlsMschapv2 = YES;
        // TEAP (RFC 7170 v1) with inner EAP-MSCHAPv2 and Crypto-Binding
        // (swapped IMSK) verified against FreeRADIUS 3.2.5 (rows 5-6)
        _supportsTeap = YES;
        _supportsTeapSecondaryAuthentication = NO;
        _supportsEapTls13 = YES;
        // EAP-TLS (RFC 5216) bare and as the inner method of PEAP/TTLS/TEAP,
        // verified against FreeRADIUS 3.2.5 (client certificate issued by a
        // test CA; NAK from the offered method to EAP-TLS when a certificate
        // is configured)
        _supportsEapTls = YES;
        // Proxy modes use per-connection nw_proxy_config (iOS 17/macOS 14+);
        // manual detection and PAC evaluation work everywhere, but the
        // tunnel itself needs the newer Network.framework API
        if (@available(iOS 17.0, macOS 14.0, *)) {
            _supportsProxy = YES;
        } else {
            _supportsProxy = NO;
        }

        _eapUnsupportedReason = @"TEAP secondary authentication is not supported";
    }
    return self;
}

@end
