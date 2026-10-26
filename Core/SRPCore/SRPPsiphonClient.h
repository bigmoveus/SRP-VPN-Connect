//
//  SRPPsiphonClient.h
//  SRPCore
//
//  Psiphon VPN — the official psiphon-tunnel-core clientlib, built into the
//  WireGuard bridge's Go archive (one Go runtime per process). The library
//  exposes a local SOCKS5 proxy; the hev-socks5-tunnel core bridges the
//  utun onto it. Psiphon carries TCP only, so the mapped-DNS layout answers
//  DNS locally and connections carry the hostname (same as SSH/Tor modes).
//

#import <Foundation/Foundation.h>

@class NEPacketTunnelNetworkSettings;

NS_ASSUME_NONNULL_BEGIN

typedef void(^SRPPsiphonOutputCallback)(NSData *ipPacket, int family);
typedef void(^SRPPsiphonNetworkSettingsCallback)(NEPacketTunnelNetworkSettings *setting);
typedef void(^SRPPsiphonConnectedCallback)(void);
typedef void(^SRPPsiphonFailureCallback)(NSString *reason);

@interface SRPPsiphonClient : NSObject

/// Hex-encoded psiphond server entry — one or more, separated by spaces or
/// newlines; the core rotates between them with its tactics
@property (nonatomic, strong, nullable) NSString *serverEntry;
/// Public IP of the server (for the route exclusion); empty = unknown
@property (nonatomic, strong, nullable) NSString *serverIP;
/// 0 = normal, 1 = expert, 2 = debug
@property (nonatomic) NSInteger logLevel;
/// Optional comma-separated tunnel-protocol allowlist (e.g. "OSSH,QUIC-OSSH")
@property (nonatomic, strong, nullable) NSString *limitProtocols;

- (void)startWithOutputCallback:(SRPPsiphonOutputCallback)output
         networkSettingsCallback:(SRPPsiphonNetworkSettingsCallback)settings
               connectedCallback:(nullable SRPPsiphonConnectedCallback)connected
                 failureCallback:(SRPPsiphonFailureCallback)failure;

- (void)injectPacket:(NSData *)packet family:(int)family;
- (void)close;
- (void)closeAndWait;

@end

NS_ASSUME_NONNULL_END
