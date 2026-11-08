//
//  SRPSSHBridge.h
//  SRPCore
//
//  C bridge between the vendored hev-socks5-tunnel packet engine and
//  libssh2: every engine TCP flow becomes an SSH direct-tcpip channel;
//  every engine UDP flow becomes a channel to the server-side HEV relay
//  (loopback SOCKS5 with FWD UDP), with the real relay authentication
//  performed here. No exec/session channels are ever opened.
//  Shared by the iOS tunnel and the Android app.
//

#ifndef SRPSSHBridge_h
#define SRPSSHBridge_h

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    const char *host;           // SSH server host
    int port;                   // SSH server port
    const char *username;
    const char *password;
    const char *hostkey_sha256; // optional pinned "SHA256:...." (base64) — fail closed when set; the line
                                // ssh-keygen -lf prints is accepted too
    int udp_enabled;            // 1 = verify and enable HEV UDP relay
    const char *relay_host;     // HEV relay as seen from the SERVER (e.g. "127.0.0.1")
    int relay_port;             // HEV relay port (e.g. 1080)
    const char *relay_user;     // HEV relay credentials (separate from SSH)
    const char *relay_pass;
    int mtu;                    // engine tun MTU (e.g. 1500)
    const char *tun_ipv4;       // engine-side tunnel IPv4 (e.g. "198.18.0.1")
    int log_level;              // 0=normal 1=expert 2=debug
    int keepalive_seconds;      // SSH keepalive interval (0 = 15); no answer for 3 intervals ends the session
    /// Android: called with the SSH socket before it connects (VpnService.protect), so it bypasses the VPN.
    int (*protect_socket)(void *ctx, int fd);
    void *protect_ctx;
} SRPSSHBridgeConfig;

typedef enum {
    SRPSSH_ERR_NONE = 0,
    SRPSSH_ERR_CONNECT,        // name lookup or TCP connect failed (detail: resolve, refused, timeout, unreachable)
    SRPSSH_ERR_HANDSHAKE,      // SSH handshake failed
    SRPSSH_ERR_HOSTKEY,        // host key mismatch / untrusted (detail: the key the server presented)
    SRPSSH_ERR_AUTH,           // SSH authentication failed (wrong user name or password)
    SRPSSH_ERR_AUTH_METHOD,    // the server takes no password for this user (detail: the methods it offers)
    SRPSSH_ERR_FORWARDING,     // the server does not let this user forward TCP (AllowTcpForwarding, PermitOpen)
    SRPSSH_ERR_RELAY,          // HEV relay missing / rejected (UDP unavailable)
    SRPSSH_ERR_LOST,           // session lost while running
} SRPSSHError;

/// Log sink — called from bridge threads; never receives secrets. level: 0 normal, 1 expert, 2 debug.
typedef void (*SRPSSHLogCallback)(void *ctx, int level, const char *line);
/// Called once when the SSH session is up, the relay (if required) verified,
/// and the packet engine is running.
typedef void (*SRPSSHReadyCallback)(void *ctx);
/// Called on unrecoverable failure before the session was up. Terminal for this session.
typedef void (*SRPSSHFailCallback)(void *ctx, SRPSSHError err, const char *detail);
/// Called when a session that was up ends (remote close, network loss, no keepalive answer); reason says which.
typedef void (*SRPSSHGoneCallback)(void *ctx, const char *reason);

/// Start everything. tun_fd is handed to the packet engine: on Apple platforms a
/// SOCK_DGRAM socketpair end (4-byte header + IP packet per datagram, like Darwin
/// utun), on Android the VpnService TUN descriptor.
/// Returns 0 on successful *launch* of the machinery; readiness/failure are
/// reported via the callbacks. No callback comes after srpssh_stop returns, and
/// none for a session srpssh_stop ended.
int srpssh_start(const SRPSSHBridgeConfig *cfg, int tun_fd,
                 SRPSSHLogCallback log, void *log_ctx,
                 SRPSSHReadyCallback ready, SRPSSHFailCallback fail,
                 SRPSSHGoneCallback gone, void *cb_ctx);

/// Stop engine, channels and session; safe to call from any thread except the callbacks'.
void srpssh_stop(void);

/// Pure helper (unit tests): the "SHA256:..." fingerprint in text such as "256 SHA256:abc root@h (ED25519)",
/// without "=" padding, into out; 0 when found, -1 when the text holds none.
int srpssh_pin_normalize(const char *text, char *out, unsigned long outlen);

#ifdef __cplusplus
}
#endif

#endif /* SRPSSHBridge_h */
