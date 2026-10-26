//
//  SRPAetherClient.h
//  SRPCore
//
//  Aether (CluvexStudio, AGPL-3.0) — the Rust WARP/MASQUE engine
//  (libaether.a) plus the hev-socks5-tunnel core from the SSH engine as the
//  TUN<->SOCKS5 bridge: the engine terminates WARP (MASQUE H3) and exposes a
//  local SOCKS5; hev maps tunnel traffic onto it.
//
//  Flow: identity_open (once per install, stored on disk) -> scan -> tunnel
//  (job runs until cancelled). All engine replies are JSON; see ffi.rs
//  upstream (pinned commit in Aether/build_aether.sh).
//

#import <Foundation/Foundation.h>
#import <SRPCore/SRPWireGuardClient.h>

@class NEPacketTunnelNetworkSettings;

NS_ASSUME_NONNULL_BEGIN

typedef void(^SRPAetherOutputCallback)(NSData *ipPacket, int family);
typedef void(^SRPAetherNetworkSettingsCallback)(NEPacketTunnelNetworkSettings *setting);
typedef void(^SRPAetherFailureCallback)(NSString *reason);
typedef void(^SRPAetherConnectedCallback)(void);

@interface SRPAetherClient : NSObject

/// Directory for the engine's identity/lastconn files (app-group container).
@property (nonatomic, strong) NSString *identityDir;
/// MASQUE HTTP/3 by default; "masque-h2" selects HTTP/2, "masque-both"
/// tries HTTP/3 then HTTP/2, and "wg" selects WARP WireGuard.
@property (nonatomic, strong) NSString *transport;
/// Endpoint scan mode ("balanced" default, or "turbo").
@property (nonatomic, strong) NSString *scanProfile;
/// 0 = normal, 1 = expert, 2 = debug
@property (nonatomic) NSInteger logLevel;
/// Optional WARP+ license key, bound to the device registration at connect
/// time (empty = free WARP). Best-effort: a failure never blocks the tunnel.
@property (nonatomic, strong, nullable) NSString *licenseKey;
/// Tor routing (engine feature): "off" (default), "reverse" (the MASQUE
/// tunnel is dialled through Tor, H2 carrier), or "only" (pure Tor exit —
/// no WARP, no identity, mapped-DNS layout)
@property (nonatomic, strong, nullable) NSString *torMode;
/// TLS ClientHello fragmentation for the MASQUE-H2 transport (the engine's
/// fragment layer): 0 = off, 1 = auto (engine defaults + SNI split),
/// 2 = manual (fragMin/fragMax byte range)
@property (nonatomic) NSInteger fragMode;
@property (nonatomic) NSInteger fragMin;
@property (nonatomic) NSInteger fragMax;
/// Private mode: wg-quick config of the user's own server. The engine is not
/// used; traffic goes utun -> hev -> SOCKS5 -> WireGuard (netstack relay) ->
/// the VPS-hosted Aether proxy -> Cloudflare WARP.
@property (nonatomic, strong, nullable) NSString *privateConfig;

- (void)startWithOutputCallback:(SRPAetherOutputCallback)output
         networkSettingsCallback:(SRPAetherNetworkSettingsCallback)settings
               connectedCallback:(nullable SRPAetherConnectedCallback)connected
                 failureCallback:(SRPAetherFailureCallback)failure;

- (void)injectPacket:(NSData *)packet family:(int)family;

/// YES when the WARP WireGuard transport drives the session — the WG engine
/// owns the utun fd then (the provider must not pump packetFlow).
@property (nonatomic, readonly) BOOL usingWireGuardEngine;
/// Forward the provider's setTunnelNetworkSettings confirmation (WG mode).
- (void)tunApplied;

- (void)close;
- (void)closeAndWait;

- (void)pauseForSleep;
- (void)wakeFromSleep;

@end

NS_ASSUME_NONNULL_END
