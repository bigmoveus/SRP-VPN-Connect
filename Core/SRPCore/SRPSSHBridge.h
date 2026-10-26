//
//  SRPSSHBridge.h
//  SRPCore
//
//  C bridge between the vendored hev-socks5-tunnel packet engine and
//  libssh2: every engine TCP flow becomes an SSH direct-tcpip channel;
//  every engine UDP flow becomes a channel to the server-side HEV relay
//  (loopback SOCKS5 with FWD UDP), with the real relay authentication
//  performed here. No exec/session channels are ever opened.
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
    const char *hostkey_sha256; // optional pinned "SHA256:...." (base64) — fail closed when set
    int udp_enabled;            // 1 = verify and enable HEV UDP relay
    const char *relay_host;     // HEV relay as seen from the SERVER (e.g. "127.0.0.1")
    int relay_port;             // HEV relay port (e.g. 1080)
    const char *relay_user;     // HEV relay credentials (separate from SSH)
    const char *relay_pass;
    int mtu;                    // engine tun MTU (e.g. 1500)
    const char *tun_ipv4;       // engine-side tunnel IPv4 (e.g. "198.18.0.1")
    int log_level;              // 0=error 1=info 2=debug
} SRPSSHBridgeConfig;

typedef enum {
    SRPSSH_ERR_NONE = 0,
    SRPSSH_ERR_CONNECT,        // TCP connect failed
    SRPSSH_ERR_HANDSHAKE,      // SSH handshake failed
    SRPSSH_ERR_HOSTKEY,        // host key mismatch / untrusted
    SRPSSH_ERR_AUTH,           // SSH authentication failed
    SRPSSH_ERR_RELAY,          // HEV relay missing / rejected (UDP unavailable)
    SRPSSH_ERR_LOST,           // session lost while running
} SRPSSHError;

/// Log sink — called from bridge threads; never receives secrets.
typedef void (*SRPSSHLogCallback)(void *ctx, const char *line);
/// Called once when the SSH session is up, the relay (if required) verified,
/// and the packet engine is running.
typedef void (*SRPSSHReadyCallback)(void *ctx);
/// Called on unrecoverable failure (before or after ready). Terminal.
typedef void (*SRPSSHFailCallback)(void *ctx, SRPSSHError err, const char *detail);
/// Called when the session ends while running (remote close / network loss).
typedef void (*SRPSSHGoneCallback)(void *ctx);

/// Start everything. tun_fd is a SOCK_DGRAM socketpair end handed to the
/// packet engine (4-byte header + IP packet per datagram, like Darwin utun).
/// Returns 0 on successful *launch* of the machinery; readiness/failure are
/// reported via the callbacks.
int srpssh_start(const SRPSSHBridgeConfig *cfg, int tun_fd,
                 SRPSSHLogCallback log, void *log_ctx,
                 SRPSSHReadyCallback ready, SRPSSHFailCallback fail,
                 SRPSSHGoneCallback gone, void *cb_ctx);

/// Stop engine, channels and session; safe to call from any thread.
void srpssh_stop(void);

#ifdef __cplusplus
}
#endif

#endif /* SRPSSHBridge_h */
