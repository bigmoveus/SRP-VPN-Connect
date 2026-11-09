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

/// AmneziaWG mode: uses the amneziawg-go engine (awg* symbols) and honors the obfuscation keys in the config's [Interface]
/// (Jc, Jmin, Jmax, S1-S4, H1-H4, I1-I5, HeaderProtectionKey, ContentPaddingAddition, the timings, RandomTrailers,
/// DisableCookies). WireGuard refuses a config that has any of them.
@property (nonatomic) BOOL amnezia;

/// Parses the config, resolves the endpoint and hands the network settings
/// to the caller. Call activateWithError: once the tunnel settings are
/// applied (the utun interface must exist).
- (void)startWithNetworkSettingsCallback:(SRPWGNetworkSettingsCallback)settings
                          failureCallback:(SRPWGFailureCallback)failure;

/// Attaches wireguard-go to the tunnel's utun fd. Call after
/// setTunnelNetworkSettings completed. error holds a readable message.
- (BOOL)activateWithError:(NSError **)error;

/// The profile's options, for activateAndWaitForHandshake: (WireGuard and AmneziaWG; Aether keeps activateWithError:).
/// Retry Times 0 = no limit. On Sleep: 0 Off, 1 Pause, 2 Stay.
@property (nonatomic) BOOL autoReconnect;
@property (nonatomic) NSInteger retryTimes;
@property (nonatomic) NSInteger onSleep;
/// After the VPN is up: the connection broke for good (reconnects ran out, Auto Reconnect off, or On Sleep Off).
@property (nonatomic, copy, nullable) SRPWGFailureCallback lostCallback;

/// Attaches wireguard-go to the utun fd like activateWithError:, then waits for the first handshake: WireGuard
/// answers nothing to a wrong key, so only a handshake shows the server took the phone. completion(nil) once it
/// happened; completion(reason) when no attempt got one (one attempt of 10 s, or 1 + Retry Times with Auto
/// Reconnect). Afterwards the client watches the session: nothing coming back for 30 s while the phone sends means
/// the server stopped answering (Auto Reconnect tries again, else lostCallback); network changes re-bind the
/// sockets; On Sleep Pause and Off close the device at sleep.
- (void)activateAndWaitForHandshake:(void (^)(NSString * _Nullable failureReason))completion;

/// What a network change does (the debug build's path-switch test command): re-resolve the endpoint and re-bind
/// the sockets on the current network.
- (void)switchNetworkPath;

/// The peer's last_handshake_time_sec, rx_bytes and tx_bytes from a UAPI get (wgGetConfig).
+ (nullable NSDictionary<NSString *, NSNumber *> *)peerStateFromUAPI:(NSString *)uapi;

/// What the client derives from a config (for tests): @"uapi" (the engine's settings), @"mtu" (the tunnel's) and
/// @"silenceBytes" (the sent bytes that mean more than keepalives); nil with errorOut set as the connect would fail.
+ (nullable NSDictionary<NSString *, id> *)engineSettingsFromConfig:(NSString *)configText amnezia:(BOOL)amnezia
                                                              error:(NSString * _Nullable * _Nullable)errorOut;

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
