//
//  SSFragTLSChannel.m
//  SRPCore
//

#import "SSFragTLSChannel.h"
#import "SSLog.h"
#import <Security/Security.h>
#import <openssl/ssl.h>
#import <openssl/err.h>
#import <openssl/x509.h>

@implementation SSFragTLSConfig

- (instancetype)init {
    self = [super init];
    if (self) {
        _mode = SSFragModeOff;
        _firstChunk = 32;
        _followingChunk = 256;
        _maxExtraDelayMs = 0;
    }
    return self;
}

- (NSString *)validate {
    if (_mode == SSFragModeOff) return nil;
    if (_mode == SSFragModeAuto) return nil;   // sizes are computed at connect time
    if (_firstChunk == 0 || _followingChunk == 0) return @"chunk sizes must be > 0";
    if (_firstChunk > 4096 || _followingChunk > 16384) return @"chunk sizes out of bounds";
    if (_maxExtraDelayMs > 250) return @"extra delay out of bounds";
    return nil;
}

/// Auto mode, grounded in the ClientHello structure and the access network:
/// - firstChunk = 43 covers exactly the TLS record header (5) + handshake
///   header (4) + legacy_version (2) + client random (32): the SNI always
///   lands in a LATER write, no matter how the server/client negotiate.
/// - followingChunk scales with the access technology (cellular paths carry
///   more middleboxes): 128 on cellular, 256 otherwise.
/// - a small gap between writes keeps TCP from merging the chunks back into
///   one segment (observed in captures without pacing); the gap is dropped
///   on slow links to protect handshake timeouts.
- (void)computeAutoChunkingOverConnection:(nw_connection_t)conn {
    _firstChunk = 43;
    nw_path_t path = nw_connection_copy_current_path(conn);
    BOOL cellular = path && nw_path_uses_interface_type(path, nw_interface_type_cellular);
    _followingChunk = cellular ? 128 : 256;
    _maxExtraDelayMs = cellular ? 10 : 3;
}

@end

@implementation SSFragTLSChannel {
    nw_connection_t _conn;
    NSString *_sni;
    BOOL _allowInsecure;
    NSString *_pinnedCAPEM;
    dispatch_queue_t _queue;
    SSFragTLSConfig *_config;

    SSL_CTX *_ctx;
    SSL *_ssl;
    BIO *_rbio;   // network -> TLS
    BIO *_wbio;   // TLS -> network

    BOOL _handshakeDone;
    BOOL _splitActive;       // chunking on (handshake phase only in v1)
    BOOL _burstStart;        // next drained write starts a new burst (firstChunk applies)
    BOOL _closed;
    NSData *_peerLeaf;       // DER of the peer leaf certificate
    void (^_handshakeCompletion)(NSError *);
    NSUInteger _delayScheduled;  // throttle chain marker for maxExtraDelayMs
}

- (instancetype)initWithConnection:(nw_connection_t)conn
                               sni:(NSString *)sni
                     allowInsecure:(BOOL)allowInsecure
              disableLegacyVersion:(BOOL)disableLegacy
                        pinnedCAPEM:(NSString *)pinnedCAPEM
                            config:(SSFragTLSConfig *)config
                             queue:(dispatch_queue_t)queue {
    self = [super init];
    if (self) {
        _conn = conn;
        /* ARC manages OS_nw_connection */
        _sni = [sni copy];
        _allowInsecure = allowInsecure;
        _pinnedCAPEM = [pinnedCAPEM copy];
        _config = config;
        _queue = queue;
        _burstStart = YES;
        _splitActive = (config.mode != SSFragModeOff);
        if (config.mode == SSFragModeAuto) {
            [config computeAutoChunkingOverConnection:conn];
            SSLogM(@"TLS-frag: auto chunking -> first=%lu following=%lu gap=%lu ms",
                   (unsigned long)config.firstChunk, (unsigned long)config.followingChunk,
                   (unsigned long)config.maxExtraDelayMs);
        }

        _ctx = SSL_CTX_new(TLS_client_method());
        if (disableLegacy) {
            SSL_CTX_set_min_proto_version(_ctx, TLS1_2_VERSION);
        }
        // Trust is evaluated ourselves with SecTrust after the handshake —
        // OpenSSL never accepts/rejects on its own here.
        SSL_CTX_set_verify(_ctx, SSL_VERIFY_NONE, NULL);
        _ssl = SSL_new(_ctx);
        SSL_set_tlsext_host_name(_ssl, _sni.UTF8String);
        _rbio = BIO_new(BIO_s_mem());
        _wbio = BIO_new(BIO_s_mem());
        SSL_set_bio(_ssl, _rbio, _wbio);   // SSL owns both from here
        SSL_set_connect_state(_ssl);
    }
    return self;
}

- (void)dealloc {
    if (_ssl) SSL_free(_ssl);          // frees the BIOs
    if (_ctx) SSL_CTX_free(_ctx);
}

#pragma mark - handshake

- (void)startHandshake:(void (^)(NSError *))completion {
    _handshakeCompletion = [completion copy];
    dispatch_async(_queue, ^{
        [self startReceiveLoop];
        [self pumpHandshake];
    });
}

- (void)pumpHandshake {
    if (_closed || _handshakeDone) return;
    int r = SSL_do_handshake(_ssl);
    [self drainWriteBio];
    if (r == 1) {
        NSError *err = [self verifyPeer];
        if (err) {
            SSLogM(@"TLS-frag: peer verification failed: %@", err.localizedDescription);
            [self completeHandshake:err];
            return;
        }
        _handshakeDone = YES;
        _splitActive = NO;   // handshake-only in v1: plain pass-through from here
        SSLogM(@"TLS-frag: handshake complete (%s)", SSL_get_version(_ssl));
        [self completeHandshake:nil];
        return;
    }
    int code = SSL_get_error(_ssl, r);
    if (code == SSL_ERROR_WANT_READ || code == SSL_ERROR_WANT_WRITE) {
        return;   // receive loop re-pumps
    }
    char errbuf[256];
    ERR_error_string_n(ERR_get_error(), errbuf, sizeof(errbuf));
    [self completeHandshake:[NSError errorWithDomain:@"SRPFragTLS" code:-1
        userInfo:@{NSLocalizedDescriptionKey: [NSString stringWithFormat:@"TLS handshake failed: %s", errbuf]}]];
}

- (void)completeHandshake:(NSError *)error {
    void (^completion)(NSError *) = _handshakeCompletion;
    _handshakeCompletion = nil;
    if (completion) completion(error);
}

/// SecTrust evaluation with the system store + TLS hostname policy.
- (NSError *)verifyPeer {
    X509 *leaf = SSL_get_peer_certificate(_ssl);   // borrowed
    if (!leaf) {
        return [NSError errorWithDomain:@"SRPFragTLS" code:-2
            userInfo:@{NSLocalizedDescriptionKey: @"The server did not present a certificate."}];
    }
    unsigned char *der = NULL;
    int derLen = i2d_X509(leaf, &der);
    _peerLeaf = derLen > 0 ? [NSData dataWithBytes:der length:derLen] : nil;
    OPENSSL_free(der);

    if (_allowInsecure) {
        return nil;   // user accepted the risk
    }

    // Whole chain: leaf + SSL_get_peer_cert_chain
    NSMutableArray *certs = [NSMutableArray array];
    if (_peerLeaf) {
        SecCertificateRef c = SecCertificateCreateWithData(NULL, (__bridge CFDataRef)_peerLeaf);
        if (c) [certs addObject:(__bridge id)c];
    }
    STACK_OF(X509) *chain = SSL_get_peer_cert_chain(_ssl);
    for (int i = 0; chain && i < sk_X509_num(chain); i++) {
        X509 *x = sk_X509_value(chain, i);
        unsigned char *d = NULL;
        int dl = i2d_X509(x, &d);
        if (dl > 0) {
            NSData *dd = [NSData dataWithBytes:d length:dl];
            SecCertificateRef c = SecCertificateCreateWithData(NULL, (__bridge CFDataRef)dd);
            if (c) [certs addObject:(__bridge id)c];
        }
        OPENSSL_free(d);
    }
    SecPolicyRef policy = SecPolicyCreateSSL(YES, (__bridge CFStringRef)_sni);
    SecTrustRef trust = NULL;
    OSStatus st = SecTrustCreateWithCertificates((__bridge CFArrayRef)certs, policy, &trust);
    if (st != errSecSuccess || !trust) {
        if (policy) CFRelease(policy);
        return [NSError errorWithDomain:@"SRPFragTLS" code:-3
            userInfo:@{NSLocalizedDescriptionKey: @"Could not evaluate the server certificate."}];
    }
    if (_pinnedCAPEM.length > 0) {
        // The CA may be PEM-armored; SecCertificate wants DER
        NSString *pem = _pinnedCAPEM;
        NSData *caData = nil;
        NSRange b = [pem rangeOfString:@"-----BEGIN CERTIFICATE-----"];
        NSRange e = [pem rangeOfString:@"-----END CERTIFICATE-----"];
        if (b.location != NSNotFound && e.location != NSNotFound) {
            NSString *b64 = [pem substringWithRange:NSMakeRange(b.location + b.length,
                                                                e.location - b.location - b.length)];
            caData = [[NSData alloc] initWithBase64EncodedString:b64
                options:NSDataBase64DecodingIgnoreUnknownCharacters];
        } else {
            caData = [pem dataUsingEncoding:NSUTF8StringEncoding];   // assume DER bytes
        }
        SecCertificateRef ca = caData ? SecCertificateCreateWithData(NULL, (__bridge CFDataRef)caData) : NULL;
        if (ca) {
            SecTrustSetAnchorCertificates(trust, (__bridge CFArrayRef)@[(__bridge id)ca]);
            SecTrustSetAnchorCertificatesOnly(trust, true);
            CFRelease(ca);
        }
    }
    CFErrorRef cfErr = NULL;
    BOOL ok = SecTrustEvaluateWithError(trust, &cfErr);
    CFRelease(policy);
    CFRelease(trust);
    if (!ok) {
        NSString *msg = cfErr ? (NSString *)CFBridgingRelease(CFErrorCopyDescription(cfErr)) : @"certificate not trusted";
        NSError *err = [NSError errorWithDomain:@"SRPFragTLS" code:-4
            userInfo:@{NSLocalizedDescriptionKey: [NSString stringWithFormat:@"The server certificate is not trusted: %@", msg]}];
        if (cfErr) CFRelease(cfErr);
        return err;
    }
    return nil;
}

#pragma mark - write path (chunked)

/// Drain pending TLS bytes from the write BIO into ordered TCP writes.
/// During the handshake (split active) bursts are written as firstChunk +
/// followingChunk-sized writes; afterwards everything passes through.
- (void)drainWriteBio {
    while (YES) {
        size_t pending = BIO_ctrl_pending(_wbio);
        if (pending == 0) {
            _burstStart = YES;   // next burst starts with firstChunk again
            return;
        }
        NSUInteger chunk = pending;
        if (_splitActive) {
            chunk = _burstStart ? MIN(_config.firstChunk, pending)
                                : MIN(_config.followingChunk, pending);
        }
        uint8_t *buf = malloc(chunk);
        int n = BIO_read(_wbio, buf, (int)chunk);
        if (n <= 0) {
            free(buf);
            return;
        }
        dispatch_data_t dd = dispatch_data_create(buf, n, _queue, DISPATCH_DATA_DESTRUCTOR_DEFAULT);
        nw_connection_send(_conn, dd, NW_CONNECTION_DEFAULT_MESSAGE_CONTEXT, false,
                           ^(nw_error_t error) {
            if (error) SSLogI(@"TLS-frag: send error %@", error);
        });
        _burstStart = NO;
        if (_splitActive && _config.maxExtraDelayMs > 0 && BIO_ctrl_pending(_wbio) > 0) {
            // Paced mode: one chunk per gap so the TCP stack cannot merge the
            // burst back into a single segment (seen in captures without it)
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW,
                                         (int64_t)(_config.maxExtraDelayMs * NSEC_PER_MSEC)),
                           _queue, ^{
                [self drainWriteBio];
            });
            return;
        }
    }
}

- (void)sendPlaintext:(NSData *)data {
    dispatch_async(_queue, ^{
        if (self->_closed || !self->_handshakeDone) return;

        const uint8_t *bytes = data.bytes;
        NSUInteger left = data.length;
        while (left > 0) {
            int n = SSL_write(self->_ssl, bytes + (data.length - left), (int)left);
            if (n > 0) {
                left -= n;
                [self drainWriteBio];
                continue;
            }
            int code = SSL_get_error(self->_ssl, n);
            if (code == SSL_ERROR_WANT_WRITE) {
                [self drainWriteBio];
                continue;
            }
            if (code == SSL_ERROR_WANT_READ) continue;   // renegotiation-style; rbio fed by receive loop
            SSLogI(@"TLS-frag: SSL_write failed (%d)", code);
            return;
        }
    });
}

#pragma mark - read path

- (void)startReceiveLoop {
    if (_closed) return;
    __weak SSFragTLSChannel *weakSelf = self;
    nw_connection_receive(_conn, 1, UINT32_MAX, ^(dispatch_data_t content, nw_content_context_t context,
                                                  bool is_complete, nw_error_t receive_error) {
        SSFragTLSChannel *strongSelf = weakSelf;
        if (!strongSelf) return;
        if (content && dispatch_data_get_size(content) > 0) {
            NSData *data = (NSData *)content;
            BIO_write(strongSelf->_rbio, data.bytes, (int)data.length);
            if (!strongSelf->_handshakeDone) {
                [strongSelf pumpHandshake];
            } else {
                [strongSelf drainReadSide];
            }
        }
        if (receive_error || (is_complete && (context == nil || nw_content_context_get_is_final(context)))) {
            [strongSelf notifyClose:receive_error
                              ? [NSError errorWithDomain:@"SRPFragTLS" code:(NSInteger)nw_error_get_error_code(receive_error)
                                                  userInfo:@{NSLocalizedDescriptionKey: @"connection error"}]
                              : nil];
            return;
        }
        if (!strongSelf->_closed) [strongSelf startReceiveLoop];
    });
}

- (void)drainReadSide {
    while (YES) {
        uint8_t buf[16384];
        int n = SSL_read(_ssl, buf, sizeof(buf));
        if (n > 0) {

            if (_onPlaintext) _onPlaintext([NSData dataWithBytes:buf length:n]);
            continue;
        }
        int code = SSL_get_error(_ssl, n);
        if (code == SSL_ERROR_WANT_READ) return;
        if (code == SSL_ERROR_ZERO_RETURN) { [self notifyClose:nil]; return; }   // clean TLS close
        if (code == SSL_ERROR_SYSCALL && n == 0) { [self notifyClose:nil]; return; }
        return;   // other errors: wait for more input / close via send errors
    }
}

- (void)notifyClose:(NSError *)error {
    if (_closed) return;
    _closed = YES;
    if (!_handshakeDone) {
        [self completeHandshake:error ?: [NSError errorWithDomain:@"SRPFragTLS" code:-5
            userInfo:@{NSLocalizedDescriptionKey: @"The connection closed during the TLS handshake."}]];
    }
    if (_onClose) _onClose(error);
}

- (NSData *)peerCertificateDER {
    return _peerLeaf;
}

- (void)close {
    if (_closed) return;
    _closed = YES;
    dispatch_async(_queue, ^{
        if (self->_handshakeDone) SSL_shutdown(self->_ssl);   // best effort
        nw_connection_cancel(self->_conn);
    });
}

@end
