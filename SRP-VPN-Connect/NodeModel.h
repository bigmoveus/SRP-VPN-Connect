
#import <Foundation/Foundation.h>

@class SRPEapConfig;

NS_ASSUME_NONNULL_BEGIN

@interface NodeModel : NSObject

@property (nonatomic,copy) NSString * nodeName;
@property (nonatomic,copy) NSString * server;
@property (nonatomic,copy) NSString * port;
@property (nonatomic,copy) NSString * password;
@property (nonatomic,copy) NSString * desc;
@property (nonatomic,copy) NSString * username;
@property (nonatomic,copy) NSString * udpgw;
@property (nonatomic,copy) NSString * udpgw_port;
@property (nonatomic,assign) BOOL TLS;
@property (nonatomic,assign) BOOL PAP;
@property (nonatomic,assign) BOOL CHAP;
@property (nonatomic,assign) BOOL MSCHAP2;

/// New single switch semantics: legacy direct PAP/CHAP allowed
@property (nonatomic,assign) BOOL allowLegacyPapChap;

/// Authentication method: "password" (default) or "certificate" (future)
@property (nonatomic,copy) NSString * authMethod;

/// VPN protocol: "sstp" (default) or "softether"
@property (nonatomic,copy) NSString * protocolType;

/// SoftEther authentication method: "standardPassword" (default),
/// "radiusNT", "certificate" or "anonymous"
@property (nonatomic,copy) NSString * seAuthMethod;

/// SoftEther Virtual Hub (default "DEFAULT")
@property (nonatomic,copy,nullable) NSString * hubName;

/// OpenConnect sub-protocol: "anyconnect" (default), "f5" (BIG-IP) or "gp" (Palo Alto GlobalProtect)
@property (nonatomic,copy,nullable) NSString * ocProtocol;

/// SSH engine: pinned server host key, OpenSSH "SHA256:...." form (optional;
/// empty = accept any — TOFU is left to the administrator)
@property (nonatomic,copy,nullable) NSString * sshHostKey;
/// SSH engine: HEV UDP relay on the server (default OFF; no extra credentials)
@property (nonatomic,assign) BOOL sshUdpRelay;

/// OpenVPN: full text of the imported .ovpn profile (inline keys)
@property (nonatomic,copy,nullable) NSString * ovpnProfile;
/// OpenVPN stunnel (outer TLS) transport: OpenVPN TCP inside TLS to the
/// server's stunnel listener (default OFF)
@property (nonatomic,assign) BOOL ovpnStunnelEnabled;
/// stunnel listener host (empty = the Server field)
@property (nonatomic,copy,nullable) NSString * ovpnStunnelHost;
/// stunnel listener port (default 9443)
@property (nonatomic,copy,nullable) NSString * ovpnStunnelPort;
/// Outer-TLS SNI / verification hostname (empty = stunnel host)
@property (nonatomic,copy,nullable) NSString * ovpnStunnelSNI;
/// PEM of the CA that signs the stunnel server certificate (empty = system trust)
@property (nonatomic,copy,nullable) NSString * ovpnStunnelCA;

/// WireGuard: full text of the imported .conf (wg-quick format; holds the
/// private key — stored like a credential)
@property (nonatomic,copy,nullable) NSString * wgConfig;

/// WireGuard manual entry (used when no .conf is imported). The effective
/// config is generated from these + server/port — see wgEffectiveConfig.
@property (nonatomic,copy,nullable) NSString * wgPrivateKey;
@property (nonatomic,copy,nullable) NSString * wgPeerPublicKey;
@property (nonatomic,copy,nullable) NSString * wgPresharedKey;
@property (nonatomic,copy,nullable) NSString * wgAddress;      // CIDR, e.g. 10.88.0.2/24
@property (nonatomic,copy,nullable) NSString * wgDNS;          // comma-separated, optional
@property (nonatomic,copy,nullable) NSString * wgAllowedIPs;   // default 0.0.0.0/0
@property (nonatomic,assign) NSInteger wgKeepalive;            // seconds, 0 = off

/// AmneziaWG obfuscation ([Interface] extras; 0 = unset). Only meaningful
/// when protocolType is "amnezia"; must match the server.
@property (nonatomic,assign) NSInteger wgJc, wgJmin, wgJmax;
@property (nonatomic,assign) NSInteger wgS1, wgS2, wgS3, wgS4;
@property (nonatomic,assign) NSInteger wgH1, wgH2, wgH3, wgH4;
/// Junk-packet signature chains (verbatim strings, e.g. "<b 0x6d792e2e>")
@property (nonatomic,copy,nullable) NSString * wgI1, * wgI2, * wgI3, * wgI4, * wgI5;

/// The imported .conf if present, otherwise a wg-quick config generated
/// from the manual fields; nil when neither is complete.
-(nullable NSString*)wgEffectiveConfig;

/// Aether transport: "masque" (HTTP/3), "masque-h2" (HTTP/2),
/// "masque-both" (HTTP/3 with HTTP/2 fallback), or "wg" (WireGuard)
@property (nonatomic,copy,nullable) NSString * aetherTransport;
/// Endpoint scan mode: "balanced" (default) or "turbo"
@property (nonatomic,copy,nullable) NSString * aetherScan;

/// Aether server mode: "public" (default, Cloudflare WARP) or "private"
/// (own WireGuard server — the wg* manual fields carry the configuration)
@property (nonatomic,copy,nullable) NSString * aetherMode;

/// Aether public mode: optional WARP+ license key, bound to the device
/// registration at connect time (empty = free WARP)
@property (nonatomic,copy,nullable) NSString * aetherLicense;

/// Aether public mode Tor routing: "off" (default), "reverse" (the MASQUE
/// tunnel is dialled through the Tor network — hides WARP from the ISP), or
/// "only" (pure Tor exit, no WARP)
@property (nonatomic,copy,nullable) NSString * aetherTor;

/// Legacy WaterWall preset, read only to migrate existing profiles.
@property (nonatomic,copy,nullable) NSString * waterwallPreset;
/// Versioned general chain configuration. Credentials stay in the shared
/// Keychain and only their reference is stored in the profile.
@property (nonatomic,copy,nullable) NSString * waterwallConfigJSON;
@property (nonatomic,copy,nullable) NSString * waterwallSecretRef;
@property (nonatomic,copy,nullable) NSString * waterwallOuterSecret;
@property (nonatomic,copy,nullable) NSString * waterwallOuterSecretRef;
@property (nonatomic,copy,nullable) NSString * waterwallProbeIP;
@property (nonatomic,copy,nullable) NSString * waterwallDNSProbeIP;
@property (nonatomic,assign) BOOL waterwallFakeDNS;
@property (nonatomic,assign) BOOL waterwallSmartRouting;

/// Psiphon: "shared" (default, the bundled SRP server) or "private" (own
/// psiphond — psiphonServerEntry carries its hex-encoded server entry)
@property (nonatomic,copy,nullable) NSString * psiphonMode;
@property (nonatomic,copy,nullable) NSString * psiphonServerEntry;
/// Optional comma-separated tunnel-protocol allowlist (empty = all)
@property (nonatomic,copy,nullable) NSString * psiphonLimitProtocols;

/// SoftEther "Hostname" field: optional TLS SNI / certificate-verification
/// hostname override (empty = use the Server field)
@property (nonatomic,copy,nullable) NSString * hostnameOverride;

/// SoftEther parallel TCP connections (1...32, default 1)
@property (nonatomic,assign) NSInteger seConnections;
/// SoftEther UDP acceleration (default OFF)
@property (nonatomic,assign) BOOL seUdpAcceleration;
/// SoftEther NAT traversal / NAT-T (default OFF)
@property (nonatomic,assign) BOOL seNatTraversal;
/// NAT-T hint: private IP of the server when several share one public IP
@property (nonatomic,copy,nullable) NSString * seNatTHint;

/// Proxy protocol for SoftEther manual proxy: "http" (default) or "socks5"
/// (SSTP auto-detects the proxy protocol and ignores this)
@property (nonatomic,copy,nullable) NSString * proxyType;

/// EAP configuration (modeled only — unsupported by the lwIP backend).
/// Lazily created with defaults.
@property (nonatomic,strong) SRPEapConfig * eapConfig;

/// Keychain account (UUID) holding this node's password.
/// nil for legacy profiles until migration runs.
@property (nonatomic,copy,nullable) NSString * passwordKey;

/// Keychain reference (UUID) of the imported client certificate
/// (certificate authentication). The .p12 blob lives in the shared
/// Keychain; only the reference is persisted in the profile.
@property (nonatomic,copy,nullable) NSString * certKey;

/// Display name (subject CN) of the selected certificate, persisted for
/// display so the profile row does not need a Keychain read.
@property (nonatomic,copy,nullable) NSString * certName;

/// Proxy for the outer connection: 0 = none (default), 1 = manual,
/// 2 = auto (PAC). Details in proxyAddress/proxyPort/proxyUsername/
/// proxyPasswordRef/pacURL.
@property (nonatomic,assign) NSInteger proxyMode;
@property (nonatomic,copy,nullable) NSString * proxyAddress;
@property (nonatomic,copy,nullable) NSString * proxyPort;
@property (nonatomic,copy,nullable) NSString * proxyUsername;
/// In-memory proxy password (never persisted; the Keychain holds it under
/// proxyPasswordRef).
@property (nonatomic,copy,nullable) NSString * proxyPassword;
/// Keychain account (UUID) holding the proxy password.
@property (nonatomic,copy,nullable) NSString * proxyPasswordRef;
@property (nonatomic,copy,nullable) NSString * pacURL;

/// OPTIONS section
/// Require TLS >= 1.2 on the outer SSTP TLS connection (default OFF)
@property (nonatomic,assign) BOOL disableLegacyOuterTls;
/// SSTP TLS fragmentation: TCP write splitting of the handshake —
/// 0 = Off (default), 1 = Manual (custom chunk sizes), 2 = Auto (computed
/// from the access network and the ClientHello structure)
@property (nonatomic,assign) NSInteger tlsFragMode;
@property (nonatomic,assign) NSInteger tlsFragFirst;       // bytes, 0 = 32
@property (nonatomic,assign) NSInteger tlsFragFollowing;   // bytes, 0 = 256
/// Auto-reconnect 2s after a drop (default ON)
@property (nonatomic,assign) BOOL autoReconnect;
/// Max failed reconnect attempts before giving up (0/empty = unlimited)
@property (nonatomic,assign) NSInteger retryTimes;
/// Reconnect when Wi-Fi becomes available (default ON)
@property (nonatomic,assign) BOOL switchToWifi;
/// 0 = off, 1 = pause, 2 = stay (default)
@property (nonatomic,assign) NSInteger onSleep;
/// 0 = normal, 1 = expert, 2 = debug (default normal)
@property (nonatomic,assign) NSInteger logLevel;

/// Custom SNI (OPTIONS): when enabled, the TLS ClientHello carries
/// customSni in the server_name extension (and the certificate is verified
/// against it) while the TCP destination stays the Host field. Never
/// DNS-resolved for connecting.
@property (nonatomic,assign) BOOL customSniEnabled;
@property (nonatomic,copy,nullable) NSString * customSni;

@property (nonatomic,assign) BOOL isSelected;
@property (nonatomic,strong) NodeModel * selectNode;

/// Stable unique identity for selection/persistence (generated once,
/// persisted in the profile dict). Selection must never rely on
/// server:port — multiple profiles may share them.
@property (nonatomic,copy) NSString * nodeId;

+(instancetype)shareInstance;

/// Custom SNI validation: a bare DNS hostname — no scheme ("://"), no port
/// (":"), no path ("/"), no whitespace.
+(BOOL)isValidCustomSni:(NSString*)sni;

@end

NS_ASSUME_NONNULL_END
