// SRPSEClient.h — C driver API for a native SoftEther VPN client session.
//
// Wraps Mayaqua/Cedar client core: global one-time init, session
// start/stop/status, IPv4 injection (via SRPSEAdapter), and a pluggable
// TLS server-certificate trust hook (SecTrust evaluation happens in the
// Objective-C layer).
#ifndef SRP_SE_CLIENT_H
#define SRP_SE_CLIENT_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct SRPSEClient SRPSEClient;

typedef enum {
    SRPSEAuthAnonymous = 0,
    SRPSEAuthPassword = 1,        // SoftEther standard password (challenge/response)
    SRPSEAuthPlainPassword = 2,   // RADIUS / NT domain (server-side backend)
    SRPSEAuthCertificate = 3,
} SRPSEAuthType;

typedef enum {
    SRPSEProxyNone = 0,
    SRPSEProxyHTTP = 1,
    SRPSEProxySOCKS4 = 2,
    SRPSEProxySOCKS5 = 3,
} SRPSEProxyType;

typedef struct {
    char     hostname[256];
    uint16_t port;
    char     hub[64];
    char     sniOverride[256];        // optional; empty = use hostname
    char     username[128];
    SRPSEAuthType authType;
    char     password[512];           // password / plain-password auth
    const uint8_t *p12;               // certificate auth: PKCS#12 blob
    size_t   p12Len;
    char     p12Passphrase[256];
    bool     tlsVerify;               // true = evaluate server cert via trust hook
    uint32_t maxConnections;          // 1..32
    bool     udpAcceleration;
    bool     natTraversal;            // false also disables UDP acceleration
    char     natTHint[256];
    bool     useCompress;
    SRPSEProxyType proxyType;
    char     proxyHost[256];
    uint16_t proxyPort;
    char     proxyUsername[128];
    char     proxyPassword[256];
    uint32_t retryIntervalSec;        // internal SoftEther retry interval (NumRetry = 0 always; outer loop owns reconnect)
    uint32_t tlsFragFirst;            // TLS write splitting (0 = off): first chunk bytes
    uint32_t tlsFragFollowing;        // following chunk bytes
    uint32_t tlsFragGapMs;            // pacing between chunks (0 = none)
} SRPSEClientConfig;

// Callbacks (all delivered on internal threads; the ObjC layer must hop to its own queue)
// family: 4 (IPv4) or 6 (IPv6)
typedef void (*SRPSEClientPacketFn)(void *ctx, const uint8_t *pkt, uint32_t len, int family);
typedef void (*SRPSEClientConfigFn)(void *ctx, const char *ip, const char *mask,
                                    const char *gw, const char *dnsCsv, uint32_t leaseSec);
// IPv6 config from RA/SLAAC (may never fire if the hub has no IPv6 router)
typedef void (*SRPSEClientConfig6Fn)(void *ctx, const char *addr6, int prefixLen,
                                     const char *gw6, const char *dns6Csv, uint32_t lifetimeSec);
// clientStatus: Cedar CLIENT_STATUS_* (0 connecting, 1 negotiation, 2 auth, 3 established, 4 retry, 5 idle)
typedef void (*SRPSEClientStateFn)(void *ctx, int clientStatus, uint32_t err);
typedef void (*SRPSEClientLogFn)(void *ctx, const char *line);

// TLS trust hook: chain = DER certs (leaf first), hostname = verification name.
// Return 0 to accept, or a SoftEther ERR_* code (e.g. 85 ERR_CERT_NOT_TRUSTED,
// 149 ERR_HOSTNAME_MISMATCH, 106 ERR_SERVER_CERT_EXPIRES) to reject.
typedef uint32_t (*SRPSETrustFn)(void *ctx, const uint8_t *const *chainDer,
                                 const size_t *chainLen, int chainCount,
                                 const char *hostname);

// One-time global init. writableDir must be a writable directory (a marker file
// is created there; it also becomes SoftEther's exe/db/log dir). Returns 0 on success.
int SRPSEGlobalInit(const char *writableDir, bool debugLog);

// Register the global trust hook before starting clients (NULL = accept any cert).
void SRPSESetTrustHook(void *ctx, SRPSETrustFn fn);

SRPSEClient *SRPSEClientCreate(const SRPSEClientConfig *cfg, void *ctx,
                               SRPSEClientPacketFn packetFn, SRPSEClientConfigFn configFn,
                               SRPSEClientConfig6Fn config6Fn,
                               SRPSEClientStateFn stateFn, SRPSEClientLogFn logFn);

// Start the session thread. Returns 0 on immediate setup success.
int  SRPSEClientStart(SRPSEClient *c);

// Inject an IP packet from the tunnel flow (TUN -> VPN). family: 4|6.
void SRPSEClientInjectPacket(SRPSEClient *c, const uint8_t *pkt, uint32_t len, int family);

// Stop the session (blocking until the session thread exits) and free resources.
void SRPSEClientStop(SRPSEClient *c);
void SRPSEClientFree(SRPSEClient *c);

// Current status snapshot (thread-safe).
void SRPSEClientGetStatus(SRPSEClient *c, int *clientStatus, uint32_t *err);

// Human-readable name for a SoftEther error code (static string).
const char *SRPSEErrorName(uint32_t err);

#ifdef __cplusplus
}
#endif

#endif
