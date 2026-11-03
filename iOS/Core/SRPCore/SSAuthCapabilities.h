//
//  SSAuthCapabilities.h
//  SRPCore
//
//  Immutable snapshot of what the lwIP PPP backend can actually do.
//  The backend (pppos) supports direct PAP/CHAP/MSCHAPv1/MSCHAPv2 and
//  EAP-MSCHAPv2.  PEAP/EAP-TTLS/TEAP require an inner TLS tunnel which
//  is not yet implemented.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface SSAuthCapabilities : NSObject

+ (instancetype)sharedCapabilities;

/// lwIP pppos direct auth methods (supported)
@property (nonatomic, readonly) BOOL supportsDirectPap;
@property (nonatomic, readonly) BOOL supportsDirectChap;
@property (nonatomic, readonly) BOOL supportsDirectMschap;
@property (nonatomic, readonly) BOOL supportsDirectMschapv2;

/// EAP methods — only bare EAP-MSCHAPv2 exists in the lwIP PPP backend
@property (nonatomic, readonly) BOOL supportsEapMschapv2;
@property (nonatomic, readonly) BOOL supportsPeap;
@property (nonatomic, readonly) BOOL supportsPeapCryptoBinding;
@property (nonatomic, readonly) BOOL supportsEapTtls;
@property (nonatomic, readonly) BOOL supportsTtlsPap;
@property (nonatomic, readonly) BOOL supportsTtlsChap;
@property (nonatomic, readonly) BOOL supportsTtlsMschapv2;
@property (nonatomic, readonly) BOOL supportsTeap;
@property (nonatomic, readonly) BOOL supportsTeapSecondaryAuthentication;
@property (nonatomic, readonly) BOOL supportsEapTls13;

/// EAP-TLS (certificate authentication, EAP type 13): bare, plus as the
/// inner method of PEAP / EAP-TTLS / TEAP
@property (nonatomic, readonly) BOOL supportsEapTls;

/// Proxy for the outer SSTP connection (None/Manual SOCKS5+HTTP CONNECT
/// auto-detection/Auto PAC). Uses Network.framework per-connection proxy
/// configs — iOS 17 / macOS 14 or later.
@property (nonatomic, readonly) BOOL supportsProxy;

/// Human-readable reason why EAP features are unsupported
@property (nonatomic, readonly, copy) NSString *eapUnsupportedReason;

@end

NS_ASSUME_NONNULL_END
