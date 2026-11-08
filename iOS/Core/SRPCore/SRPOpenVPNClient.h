//
//  SRPOpenVPNClient.h
//  SRPCore
//
//  Objective-C++ façade over OpenVPN 3 Core (vendored release/3.11.7).
//  Mirrors the other engines: owns the session lifecycle, the packet
//  bridge to NEPacketTunnelFlow, and the OPTIONS behaviors.
//
//  Native UDP/TCP OpenVPN from an .ovpn profile (certificate and/or
//  auth-user-pass login), or OpenVPN TCP inside an outer TLS connection to a
//  server-side stunnel listener.
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

/// The profile's Server and Port fields. They start as the profile's first
/// remote line; when the user changed them, they replace it.
@property (nonatomic, strong, nullable) NSString *server;
@property (nonatomic, strong, nullable) NSString *port;

// Optional stunnel transport (OpenVPN TCP inside outer TLS). When enabled,
// the OpenVPN connection always uses TCP and goes to stunnelHost:stunnelPort
// (the server's stunnel listener) inside TLS.
@property (nonatomic) BOOL stunnelEnabled;
@property (nonatomic, strong, nullable) NSString *stunnelHost;
@property (nonatomic) int stunnelPort;
/// SNI / verification hostname for the outer TLS (empty = stunnelHost).
@property (nonatomic, strong, nullable) NSString *stunnelSNI;
/// PEM of the CA that signs the stunnel server certificate (optional;
/// nil = system trust store).
@property (nonatomic, strong, nullable) NSString *outerCAPEM;

/// TLS write splitting of the outer (stunnel) TLS handshake, as the profile
/// stores it: 0 = Off, 1 = Auto, 2 = Manual (SSFragModeFromProfileValue).
/// Only applies when stunnel is enabled.
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

/// Provider-managed mode: when enabled, the core's TUN waits for the
/// provider's tunApplied confirmation after the settings callback (every
/// connection, reconnects too). The macOS harness leaves it off.
- (void)setProviderManaged:(BOOL)managed;
/// Called by the provider after setTunnelNetworkSettings completed.
- (void)tunApplied;

/// Manual close (user disconnect).
- (void)close;
/// Synchronous close for stopTunnelWithReason:.
- (void)closeAndWait;

- (void)pauseForSleep;
- (void)wakeFromSleep;
/// What Switch to Wi-Fi does when Wi-Fi appears: the session moves to the
/// current network path (DEBUG builds expose it to the tests).
- (void)switchNetworkPath;

/// The tunnel settings for the options a server pushed (unit-testable).
/// serverAddress is the address the connection uses: it stays outside the tunnel.
+ (NEPacketTunnelNetworkSettings *)settingsForPushedOptions:(NSArray<NSArray<NSString *> *> *)options
                                              serverAddress:(nullable NSString *)serverAddress;
/// The first `remote` line of a profile as @[host, port, proto] (port and
/// proto from the profile's port/proto lines, or OpenVPN's defaults), and
/// how many remote lines it has.
+ (NSArray<NSString *> *)firstRemoteOfProfile:(NSString *)profile;
+ (NSInteger)remoteCountOfProfile:(NSString *)profile;
/// The profile turned to one transport protocol (stunnel carries TCP)
+ (NSString *)profileText:(NSString *)profile withProtocol:(NSString *)protocol;
/// The user's message for a core log line that explains a failed attempt, or nil
+ (nullable NSString *)messageForLogLine:(NSString *)line;

@end

NS_ASSUME_NONNULL_END
