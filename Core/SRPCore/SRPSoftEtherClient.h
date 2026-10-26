//
//  SRPSoftEtherClient.h
//  SRPCore
//
//  Objective-C wrapper over the SoftEther VPN Protocol core (libSECore).
//  Mirrors the lwIP class's role for SSTP: owns the session lifecycle,
//  Auto Reconnect / Retry Times / Switch to Wi-Fi / On Sleep behavior and
//  the packet/network-settings callbacks used by PacketTunnelProvider.
//

#import <Foundation/Foundation.h>

@class NEPacketTunnelNetworkSettings;

NS_ASSUME_NONNULL_BEGIN

typedef NS_ENUM(NSInteger, SRPSoftEtherAuthMethod) {
    SRPSoftEtherAuthAnonymous = 0,
    SRPSoftEtherAuthStandardPassword = 1,
    SRPSoftEtherAuthRadiusNTDomain = 2,
    SRPSoftEtherAuthCertificate = 3,
};

typedef void(^SRPSoftEtherOutputCallback)(NSData *ipPacket, int family);   // family: AF_INET | AF_INET6
typedef void(^SRPSoftEtherNetworkSettingsCallback)(NEPacketTunnelNetworkSettings *setting);
typedef void(^SRPSoftEtherFailureCallback)(NSString *reason);
/// Fired every time the tunnel is fully up (protocol established + DHCP bound).
typedef void(^SRPSoftEtherConnectedCallback)(void);
/// Fired when an established session dropped (before any auto-reconnect).
typedef void(^SRPSoftEtherDisconnectedCallback)(void);

@interface SRPSoftEtherClient : NSObject

/// One-time init of the SoftEther core. dir must be writable (app group).
+ (void)initializeCoreInDirectory:(NSString *)dir debugLog:(BOOL)debugLog;

@property (nonatomic, strong) NSString *host;
@property (nonatomic) int port;
@property (nonatomic, strong) NSString *hubName;
/// Optional TLS SNI / certificate-verification hostname override (UI "Hostname").
@property (nonatomic, strong, nullable) NSString *hostnameOverride;
@property (nonatomic, strong) NSString *username;
@property (nonatomic, strong, nullable) NSString *password;
@property (nonatomic) SRPSoftEtherAuthMethod authMethod;
/// Certificate auth: PKCS#12 blob + passphrase (unwrapped by the caller from Keychain).
@property (nonatomic, strong, nullable) NSData *clientCertP12;
@property (nonatomic, strong, nullable) NSString *clientCertPassphrase;
/// ON = verify the server certificate against the system trust store (SecTrust).
@property (nonatomic) BOOL tlsServerVerification;

/// TLS write splitting of the initial flight (ClientHello): 0 = Off
/// (default), 1 = Manual, 2 = Auto (same policy as SSTP/OpenConnect)
@property (nonatomic) NSInteger tlsFragMode;
@property (nonatomic) NSInteger tlsFragFirst;
@property (nonatomic) NSInteger tlsFragFollowing;
@property (nonatomic) NSInteger connections;      // 1...32
@property (nonatomic) BOOL udpAcceleration;
@property (nonatomic) BOOL natTraversal;
@property (nonatomic, strong, nullable) NSString *natTHint;
@property (nonatomic) BOOL useCompress;

// Proxy (manual HTTP/SOCKS5 only in v1; auto/PAC falls back to direct)
@property (nonatomic) NSInteger proxyMode;        // 0 none, 1 manual, 2 auto
@property (nonatomic, strong, nullable) NSString *proxyType;   // "http" | "socks5"
@property (nonatomic, strong, nullable) NSString *proxyHost;
@property (nonatomic) NSInteger proxyPort;
@property (nonatomic, strong, nullable) NSString *proxyUsername;
@property (nonatomic, strong, nullable) NSString *proxyPassword;

// OPTIONS section
@property (nonatomic) BOOL autoReconnect;
@property (nonatomic) NSInteger retryTimes;       // 0 = unlimited
@property (nonatomic) BOOL switchToWifi;
@property (nonatomic) NSInteger onSleep;          // 0 off, 1 pause, 2 stay
@property (nonatomic) NSInteger logLevel;         // SSLogLevel

- (void)startWithOutputCallback:(SRPSoftEtherOutputCallback)output
         networkSettingsCallback:(SRPSoftEtherNetworkSettingsCallback)settings
               connectedCallback:(nullable SRPSoftEtherConnectedCallback)connected
            disconnectedCallback:(nullable SRPSoftEtherDisconnectedCallback)disconnected
                 failureCallback:(SRPSoftEtherFailureCallback)failure;

/// Inject an IP packet from the tunnel flow (TUN -> VPN).
- (void)injectPacket:(NSData *)packet family:(int)family;

/// Manual close (user disconnect). No reconnect happens afterwards.
- (void)close;

/// Synchronous close for stopTunnelWithReason: — waits until the SoftEther
/// session thread has fully exited (iOS terminates the extension right after
/// the completion handler runs).
- (void)closeAndWait;

/// On Sleep option handling (same semantics as lwIP).
- (void)pauseForSleep;
- (void)wakeFromSleep;

@end

NS_ASSUME_NONNULL_END
