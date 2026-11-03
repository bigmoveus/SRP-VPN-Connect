//
//  SRPWireGuardClient.h
//  SRPCore
//
//  Thin Objective-C wrapper over the official WireGuard bridge
//  (wireguard-apple's WireGuardKitGo, built with the latest wireguard-go
//  as a c-archive — see WireGuard/build_wg.sh). Like the official app, the
//  Go device attaches directly to the Network Extension's utun file
//  descriptor, so packets flow without a userspace pump.
//

#import <Foundation/Foundation.h>

@class NEPacketTunnelNetworkSettings;

NS_ASSUME_NONNULL_BEGIN

typedef void(^SRPWGNetworkSettingsCallback)(NEPacketTunnelNetworkSettings *setting);
typedef void(^SRPWGFailureCallback)(NSString *reason);

@interface SRPWireGuardClient : NSObject

/// Full text of the tunnel configuration in wg-quick format
/// ([Interface] PrivateKey/Address/DNS, [Peer] PublicKey/Endpoint/AllowedIPs).
@property (nonatomic, strong) NSString *configText;

/// 0 = normal (errors), 1 = expert, 2 = debug (verbose protocol log)
@property (nonatomic) NSInteger logLevel;

/// AmneziaWG mode: uses the amneziawg-go engine (awg* symbols) and honors the
/// obfuscation keys (Jc/Jmin/Jmax/S1/S2/H1-H4) in the config's [Interface].
@property (nonatomic) BOOL amnezia;

/// Parses the config, resolves the endpoint and hands the network settings
/// to the caller. Call activateWithError: once the tunnel settings are
/// applied (the utun interface must exist).
- (void)startWithNetworkSettingsCallback:(SRPWGNetworkSettingsCallback)settings
                          failureCallback:(SRPWGFailureCallback)failure;

/// Attaches wireguard-go to the tunnel's utun fd. Call after
/// setTunnelNetworkSettings completed. error holds a readable message.
- (BOOL)activateWithError:(NSError **)error;

/// Manual close (user disconnect).
- (void)close;
/// Synchronous close for stopTunnelWithReason:.
- (void)closeAndWait;

/// WireGuard is stateless over UDP; on wake the sockets are re-bound.
- (void)pauseForSleep;
- (void)wakeFromSleep;

/// Parses a wg-quick config into engine parameters for the netstack mode
/// (userspace WireGuard without a real utun — Aether "Private" mode).
/// Returns @{ @"uapi": UAPI string, @"endpointIP": resolved peer IPv4,
///             @"address": first interface IPv4 (no mask) } or nil with
/// errorOut set.
+ (nullable NSDictionary<NSString *, NSString *> *)netstackParametersFromConfig:(NSString *)configText
                                                                          error:(NSString * _Nullable * _Nullable)errorOut;

@end

NS_ASSUME_NONNULL_END
