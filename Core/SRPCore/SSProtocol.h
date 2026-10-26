
#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

typedef enum : NSUInteger {
    SSClientType_DIRECT = 0,
    SSClientType_HTTP,
    SSClientType_SOCKS,
    SSClientType_VMESS,
    SSClientType_VLESS,
    SSClientType_TROJAN,
    SSClientType_SHADOWSOCKS,
    SSClientType_SSTP,
    SSClientType_SHADOWSOCKSR,
} SSClientType;

// Transport protocol used to carry the VPN data
typedef enum : NSUInteger {
    SSTransportTypeTCP = 0, // for direct connections: either TCP or UDP
    SSTransportTypeWebSocket,
    SSTransportTypeGRPC,
    SSTransportTypeQUIC,
    SSTransportTypeKCP
} SSTransportType;


typedef enum : UInt8 {
    // VLess security types
    SSSecurityType_UNKNOWN              = 0,
    SSSecurityType_LEGACY               = 1,
    SSSecurityType_AUTO                 = 2,
    SSSecurityType_AES_128_GCM           = 3,
    SSSecurityType_CHACHA20_POLY1305    = 4,
    SSSecurityType_NONE                 = 5,
    SSSecurityType_ZERO                 = 6,
    
    // Shadowsocks-only security types
    SSSecurityType_SS_NONE                 = 100,
    SSSecurityType_SS_AES_128_GCM          = 101,
    SSSecurityType_SS_AES_256_GCM          = 102,
    SSSecurityType_SS_CHACHA20_POLY1305    = 103,
    SSSecurityType_SS_XCHACHA20_POLY1305   = 104,
} SSSecurityType;


@interface SSProtocol : NSObject

@property (nonatomic)int port;

@property (nonatomic, strong)NSString *host;

@property (nonatomic, strong)NSString *query;

@property (nonatomic, strong, nullable)NSString *domain;

@property (nonatomic)BOOL tls;

@property (nonatomic)BOOL allowInsecure;

@property (nonatomic)SSTransportType transport;

@property (nonatomic, readonly)SSClientType protocol;

@property (nonatomic)SSSecurityType security;

@end

@interface SSSstp : SSProtocol

@property (nonatomic, strong, nullable)NSString *username;

@property (nonatomic, strong, nullable)NSString *password;

@property (nonatomic)BOOL PAP_ENABLE;

@property (nonatomic)BOOL CHAP_ENABLE;

@property (nonatomic)BOOL MS_CHAP_ENABLE;

@property (nonatomic)BOOL MS2_CHAP_ENABLE;

/// Request EAP (EAP-MSCHAPv2) instead of direct MS-CHAPv2 at LCP
@property (nonatomic)BOOL eapMschapv2Enabled;

/// Request PEAP (EAP type 25) with inner EAP-MSCHAPv2
@property (nonatomic)BOOL peapEnabled;

/// PEAP: fail unless a verified Crypto-Binding TLV was exchanged (MS-PEAP)
@property (nonatomic)BOOL peapRequireCryptoBinding;

/// Request EAP-TTLS (EAP type 21, RFC 5281) with inner EAP-MSCHAPv2
@property (nonatomic)BOOL ttlsEnabled;

/// TTLS phase-2 inner method: "eap" (inner EAP-MSCHAPv2 via EAP-Message
/// AVPs), "pap" or "chap" (AVP-based, RFC 5281 11.2). Only meaningful
/// when ttlsEnabled.
@property (nonatomic, strong, nullable)NSString *ttlsInnerMethod;

/// EAP-TLS client credentials (PEM blobs; the caller unwraps the .p12).
/// Presence enables certificate authentication (bare EAP-TLS, or inner
/// EAP-TLS inside PEAP/TTLS/TEAP).
@property (nonatomic, strong, nullable)NSData *eapTlsCertPem;
@property (nonatomic, strong, nullable)NSData *eapTlsKeyPem;

/// Unpack a passphrase-protected PKCS#12 (.p12/.pfx) into eapTlsCertPem /
/// eapTlsKeyPem (certificate chain first, then the private key).
/// Returns NO when the blob is not a PKCS#12 or the passphrase is wrong.
- (BOOL)setEapTlsP12:(NSData *)p12 passphrase:(NSString *)passphrase;

/// Inspect a .p12 without installing it: returns @{"name": subject CN,
/// @"expiry": notAfter as NSDate} or nil when the blob/passphrase is
/// invalid. Used by the app's certificate import UI.
+ (nullable NSDictionary *)eapTlsP12Info:(NSData *)p12 passphrase:(NSString *)passphrase;

/// Request TEAP (EAP type 55, RFC 7170) with inner EAP-MSCHAPv2
@property (nonatomic)BOOL teapEnabled;

/// Outer EAP identity privacy: answer the outer Identity request with
/// eapAnonymousIdentity; the real username is only used inside the tunnel
@property (nonatomic)BOOL eapIdentityPrivacy;

/// Outer identity when privacy is enabled (default "anonymous")
@property (nonatomic, strong, nullable)NSString *eapAnonymousIdentity;

/// Allow TLS 1.3 for the PEAP inner tunnel (default YES)
@property (nonatomic)BOOL eapTls13Enabled;

/// Require TLS >= 1.2 for the PEAP inner tunnel (default YES)
@property (nonatomic)BOOL eapDisableLegacyTls;

/// Proxy for the outer TCP path to the SSTP server (TLS SNI and the SSTP
/// destination stay independent of the proxy):
///   0 = none (default), 1 = manual (proxyHost/proxyPort, optional
///   credentials), 2 = auto (PAC URL evaluated for the SSTP host).
/// Manual mode auto-detects SOCKS5 vs HTTP CONNECT by negotiation.
@property (nonatomic)NSInteger proxyMode;
@property (nonatomic, strong, nullable)NSString *proxyHost;
@property (nonatomic)NSInteger proxyPort;
@property (nonatomic, strong, nullable)NSString *proxyUsername;
/// Runtime only — never persisted or put in the URI (the profile carries
/// a Keychain reference instead).
@property (nonatomic, strong, nullable)NSString *proxyPassword;
@property (nonatomic, strong, nullable)NSString *pacURL;

/// OPTIONS section:
/// Require TLS >= 1.2 on the OUTER SSTP TLS connection (default NO = system
/// default). The EAP inner tunnels have separate knobs (eapTls13Enabled /
/// eapDisableLegacyTls).
@property (nonatomic)BOOL disableLegacyOuterTls;

/// TLS fragmentation (TCP write splitting of the handshake output, OFF by
/// default): 0 = off, 1 = split. Sizes apply to the first write of a burst
/// and the following writes. Effective on NEW connections only.
@property (nonatomic)NSInteger tlsFragMode;
@property (nonatomic)NSInteger tlsFragFirst;       // bytes, default 32
@property (nonatomic)NSInteger tlsFragFollowing;   // bytes, default 256
@property (nonatomic)NSInteger tlsFragDelayMs;     // experiment only, default 0
/// Reconnect automatically 2s after a drop (default YES)
@property (nonatomic)BOOL autoReconnect;
/// Max consecutive failed reconnect attempts before giving up
/// (default 0 = unlimited)
@property (nonatomic)NSInteger retryTimes;
/// Reconnect on the new path when Wi-Fi becomes available (default YES)
@property (nonatomic)BOOL switchToWifi;
/// On device sleep: 0 = off (drop the connection), 1 = pause (reconnect on
/// wake), 2 = stay (do nothing, default)
@property (nonatomic)NSInteger onSleep;
/// Log level: 0 = normal, 1 = expert, 2 = debug (default 0)
@property (nonatomic)NSInteger logLevel;
@end

NS_ASSUME_NONNULL_END
