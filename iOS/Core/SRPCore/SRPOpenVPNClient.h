//
//  SRPOpenVPNClient.h
//  SRPCore
//
//  Objective-C++ façade over OpenVPN 3 Core (vendored release/3.11.7).
//  Mirrors the other engines: owns the session lifecycle, the packet
//  bridge to NEPacketTunnelFlow, and the OPTIONS behaviors.
//
//  v1 scope: native UDP/TCP OpenVPN with certificate auth from an .ovpn
//  profile; optional stunnel transport (OpenVPN TCP inside an outer TLS
//  connection to a server-side stunnel listener).
//

#import <Foundation/Foundation.h>

@class NEPacketTunnelNetworkSettings;

NS_ASSUME_NONNULL_BEGIN

typedef void(^SRPOVPNOutputCallback)(NSData *ipPacket, int family);
typedef void(^SRPOVPNNetworkSettingsCallback)(NEPacketTunnelNetworkSettings *setting);
typedef void(^SRPOVPNFailureCallback)(NSString *reason);
typedef void(^SRPOVPNConnectedCallback)(void);
typedef void(^SRPOVPNDisconnectedCallback)(void);

@interface SRPOpenVPNClient : NSObject

/// Full text of the .ovpn profile (inline <ca>/<cert>/<key>/<tls-crypt>).
@property (nonatomic, strong) NSString *profileText;

// Optional stunnel transport (OpenVPN TCP inside outer TLS). When enabled,
// the effective remote is taken from the profile but wrapped in TLS to
// stunnelHost:stunnelPort (must be the server's stunnel listener).
@property (nonatomic) BOOL stunnelEnabled;
@property (nonatomic, strong, nullable) NSString *stunnelHost;
@property (nonatomic) int stunnelPort;
/// SNI / verification hostname for the outer TLS (empty = stunnelHost).
@property (nonatomic, strong, nullable) NSString *stunnelSNI;
/// PEM of the CA that signs the stunnel server certificate (optional;
/// nil = system trust store).
@property (nonatomic, strong, nullable) NSString *outerCAPEM;

/// TLS write splitting of the outer (stunnel) TLS handshake: 0 = Off,
/// 1 = Manual, 2 = Auto (same policy as SSTP/OpenConnect). Only applies
/// when stunnel is enabled.
@property (nonatomic) NSInteger tlsFragMode;
@property (nonatomic) NSInteger tlsFragFirst;
@property (nonatomic) NSInteger tlsFragFollowing;

/// Username/password for profiles with `auth-user-pass` (ignored otherwise).
@property (nonatomic, strong, nullable) NSString *username;
@property (nonatomic, strong, nullable) NSString *password;

// OPTIONS section
@property (nonatomic) BOOL autoReconnect;
@property (nonatomic) NSInteger retryTimes;       // 0 = unlimited
@property (nonatomic) BOOL switchToWifi;
@property (nonatomic) NSInteger onSleep;          // 0 off, 1 pause, 2 stay
@property (nonatomic) NSInteger logLevel;         // SSLogLevel

- (void)startWithOutputCallback:(SRPOVPNOutputCallback)output
         networkSettingsCallback:(SRPOVPNNetworkSettingsCallback)settings
               connectedCallback:(nullable SRPOVPNConnectedCallback)connected
            disconnectedCallback:(nullable SRPOVPNDisconnectedCallback)disconnected
                 failureCallback:(SRPOVPNFailureCallback)failure;

/// Inject an IP packet from the tunnel flow (TUN -> VPN). family: AF_INET/AF_INET6.
- (void)injectPacket:(NSData *)packet family:(int)family;

/// Provider-managed mode: when enabled, the client waits for the provider's
/// tunApplied confirmation after the settings callback before declaring the
/// tunnel connected (used by SRPTunnel; the macOS harness leaves it off).
- (void)setProviderManaged:(BOOL)managed;
/// Called by the provider after setTunnelNetworkSettings completed
/// successfully — unblocks the core's tun_start and starts data flow.
- (void)tunApplied;

/// Manual close (user disconnect).
- (void)close;
/// Synchronous close for stopTunnelWithReason:.
- (void)closeAndWait;

- (void)pauseForSleep;
- (void)wakeFromSleep;

@end

NS_ASSUME_NONNULL_END
