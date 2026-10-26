//
//  SSFragTLSChannel.h
//  SRPCore
//
//  Optional TLS channel used by the SSTP outer connection when TLS
//  fragmentation is enabled (default OFF — the standard Network.framework
//  TLS path stays untouched).
//
//  The channel runs OpenSSL (client) over an already-connected plain TCP
//  nw_connection with memory BIOs. Outgoing TLS bytes are written to TCP in
//  ordered chunks (TCP write splitting, handshake phase only) — the byte
//  stream is identical to an unsplit stream, only the write sizes differ.
//
//  Trust is evaluated with SecTrust (system store + hostname) after the
//  handshake, mirroring the standard path; allowInsecure skips it. The
//  channel never weakens verification to make fragmentation work.
//

#import <Foundation/Foundation.h>
#import <Network/Network.h>

NS_ASSUME_NONNULL_BEGIN

typedef NS_ENUM(NSInteger, SSFragMode) {
    SSFragModeOff = 0,
    SSFragModeManual = 1,   // user-provided chunk sizes
    SSFragModeAuto = 2,     // computed from the network path (see .m)
};

@interface SSFragTLSConfig : NSObject
@property (nonatomic) SSFragMode mode;
@property (nonatomic) NSUInteger firstChunk;       // manual: bytes in the first write of a burst
@property (nonatomic) NSUInteger followingChunk;   // manual: bytes per following write
@property (nonatomic) NSUInteger maxExtraDelayMs;  // manual: pacing between chunks (0 = off)
/// nil when valid; otherwise a human-readable reason
- (nullable NSString *)validate;
@end

@interface SSFragTLSChannel : NSObject

/// conn must be a plain-TCP nw_connection that is already started by the
/// caller's state handler (this class takes over receive/send on ready).
/// pinnedCAPEM: PEM of a CA to anchor the trust evaluation on (nil =
/// system trust store).
- (instancetype)initWithConnection:(nw_connection_t)conn
                               sni:(NSString *)sni
                     allowInsecure:(BOOL)allowInsecure
              disableLegacyVersion:(BOOL)disableLegacy
                        pinnedCAPEM:(nullable NSString *)pinnedCAPEM
                            config:(SSFragTLSConfig *)config
                             queue:(dispatch_queue_t)queue;

/// Runs the TLS handshake (with optional write splitting). completion is
/// called once on `queue` with nil on success (verified, unless
/// allowInsecure) or an error.
- (void)startHandshake:(void(^)(NSError * _Nullable error))completion;

/// Encrypts and sends plaintext (post-handshake). Thread-affine to `queue`.
- (void)sendPlaintext:(NSData *)data;

/// Decrypted incoming bytes and connection teardown.
@property (nonatomic, copy, nullable) void (^onPlaintext)(NSData *);
@property (nonatomic, copy, nullable) void (^onClose)(NSError * _Nullable);

/// DER of the peer leaf certificate (for SSTP crypto binding); nil before
/// the handshake completes.
- (nullable NSData *)peerCertificateDER;

- (void)close;

@end

NS_ASSUME_NONNULL_END
