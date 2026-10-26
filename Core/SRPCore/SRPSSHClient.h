//
//  SRPSSHClient.h
//  SRPCore
//
//  Objective-C façade over the SSH VPN engine (SRPSSHBridge: libssh2 +
//  vendored hev-socks5-tunnel packet stack). Mirrors SRPOpenConnectClient's
//  role: owns the session lifecycle and the packet bridge to
//  NEPacketTunnelFlow.
//
//  TCP flows: one SSH direct-tcpip channel each.
//  UDP flows: HEV FWD UDP over a channel to the server-side loopback relay.
//

#import <Foundation/Foundation.h>

@class NEPacketTunnelNetworkSettings;

NS_ASSUME_NONNULL_BEGIN

typedef void(^SRPSSHOutputCallback)(NSData *ipPacket, int family);
typedef void(^SRPSSHNetworkSettingsCallback)(NEPacketTunnelNetworkSettings *setting);
typedef void(^SRPSSHFailureCallback)(NSString *reason);
typedef void(^SRPSSHConnectedCallback)(void);
typedef void(^SRPSSHDisconnectedCallback)(void);

@interface SRPSSHClient : NSObject

@property (nonatomic, strong) NSString *host;
@property (nonatomic) int port;
@property (nonatomic, strong) NSString *username;
@property (nonatomic, strong, nullable) NSString *password;
/// Pinned server host key, OpenSSH format "SHA256:....". When set, a mismatch
/// fails closed; when nil, the key is accepted (TOFU is a policy decision of
/// the profile editor, not silently implicit here).
@property (nonatomic, strong, nullable) NSString *hostKeySHA256;

/// UDP relay (HEV) — the service runs on the SSH server, loopback only.
@property (nonatomic) BOOL udpEnabled;
@property (nonatomic, strong, nullable) NSString *relayHost;   // server-side, default 127.0.0.1
@property (nonatomic) int relayPort;                            // default 1080
@property (nonatomic, strong, nullable) NSString *relayUsername;
@property (nonatomic, strong, nullable) NSString *relayPassword;

/// TEST ONLY (macOS harness): run the engine on a real utun instead of the
/// socketpair bridge — for throughput measurement outside the app.
@property (nonatomic) BOOL useRealTun;

// OPTIONS section
@property (nonatomic) BOOL autoReconnect;
@property (nonatomic) NSInteger retryTimes;       // 0 = unlimited
@property (nonatomic) BOOL switchToWifi;
@property (nonatomic) NSInteger onSleep;          // 0 off, 1 pause, 2 stay
@property (nonatomic) NSInteger logLevel;         // SSLogLevel

- (void)startWithOutputCallback:(SRPSSHOutputCallback)output
         networkSettingsCallback:(SRPSSHNetworkSettingsCallback)settings
               connectedCallback:(nullable SRPSSHConnectedCallback)connected
            disconnectedCallback:(nullable SRPSSHDisconnectedCallback)disconnected
                 failureCallback:(SRPSSHFailureCallback)failure;

/// Inject an IP packet from the tunnel flow (TUN -> VPN). family: AF_INET/AF_INET6.
- (void)injectPacket:(NSData *)packet family:(int)family;

/// Manual close (user disconnect).
- (void)close;
/// Synchronous close for stopTunnelWithReason:.
- (void)closeAndWait;

- (void)pauseForSleep;
- (void)wakeFromSleep;

@end

NS_ASSUME_NONNULL_END
