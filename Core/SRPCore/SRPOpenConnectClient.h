//
//  SRPOpenConnectClient.h
//  SRPCore
//
//  Objective-C wrapper over libopenconnect (vendored openconnect 9.21,
//  OpenSSL backend with srpse_ symbol prefixing). Mirrors the role of
//  lwIP (SSTP) and SRPSoftEtherClient: owns the session lifecycle, the
//  packet bridge to NEPacketTunnelFlow, and the OPTIONS behaviors.
//
//  v1 scope: AnyConnect (ocserv) with password auth, strict/relaxed TLS
//  trust via SecTrust, IPv4+IPv6 settings, DTLS, auto reconnect.
//

#import <Foundation/Foundation.h>

@class NEPacketTunnelNetworkSettings;

NS_ASSUME_NONNULL_BEGIN

typedef void(^SRPOCOutputCallback)(NSData *ipPacket, int family);
typedef void(^SRPOCNetworkSettingsCallback)(NEPacketTunnelNetworkSettings *setting);
typedef void(^SRPOCFailureCallback)(NSString *reason);
typedef void(^SRPOCConnectedCallback)(void);
typedef void(^SRPOCDisconnectedCallback)(void);

@interface SRPOpenConnectClient : NSObject

+ (void)initializeCore;   // one-time openconnect_init_ssl()

@property (nonatomic, strong) NSString *host;
@property (nonatomic) int port;
/// OpenConnect sub-protocol: "anyconnect" (v1). Others are enable-tested later.
@property (nonatomic, strong) NSString *ocProtocol;
@property (nonatomic, strong) NSString *username;
@property (nonatomic, strong, nullable) NSString *password;
/// Client certificate (PKCS#12 blob + passphrase), optional.
@property (nonatomic, strong, nullable) NSData *clientCertP12;
@property (nonatomic, strong, nullable) NSString *clientCertPassphrase;
/// ON = verify the server certificate against the system trust store.
@property (nonatomic) BOOL tlsServerVerification;

/// TLS write splitting of the initial flight (ClientHello): 0 = Off
/// (default), 1 = Manual (tlsFragFirst/tlsFragFollowing bytes), 2 = Auto
/// (computed from the access network; same policy as the SSTP channel)
@property (nonatomic) NSInteger tlsFragMode;
@property (nonatomic) NSInteger tlsFragFirst;
@property (nonatomic) NSInteger tlsFragFollowing;

// OPTIONS section
@property (nonatomic) BOOL autoReconnect;
@property (nonatomic) NSInteger retryTimes;       // 0 = unlimited
@property (nonatomic) BOOL switchToWifi;
@property (nonatomic) NSInteger onSleep;          // 0 off, 1 pause, 2 stay
@property (nonatomic) NSInteger logLevel;         // SSLogLevel

- (void)startWithOutputCallback:(SRPOCOutputCallback)output
         networkSettingsCallback:(SRPOCNetworkSettingsCallback)settings
               connectedCallback:(nullable SRPOCConnectedCallback)connected
            disconnectedCallback:(nullable SRPOCDisconnectedCallback)disconnected
                 failureCallback:(SRPOCFailureCallback)failure;

/// Inject an IP packet from the tunnel flow (TUN -> VPN). family: AF_INET/AF_INET6.
- (void)injectPacket:(NSData *)packet family:(int)family;

/// Manual close (user disconnect). No reconnect afterwards.
- (void)close;
/// Synchronous close for stopTunnelWithReason:.
- (void)closeAndWait;

- (void)pauseForSleep;
- (void)wakeFromSleep;

@end

NS_ASSUME_NONNULL_END
