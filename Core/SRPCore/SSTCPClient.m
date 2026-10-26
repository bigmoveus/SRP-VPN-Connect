
#import "SSTCPClient.h"
#import "SSTCPClient+Private.h"
#import <Network/Network.h>
#import "sstp/utils.h"
#import <CommonCrypto/CommonCrypto.h>
#import <Security/Security.h>
#import <Security/SecureTransport.h>
#import "CCWebSocket.h"
#import "SSProtocol.h"
#import "NWRunLoop.h"
#import "SSProxyResolver.h"
#import "SSOuterTls.h"
#import "SSFragTLSChannel.h"
#import "SSLog.h"

@interface SSTCPClient ()<CCCodecDelegate>
@property (nonatomic)SSTCPState state;
@property (nonatomic, strong)nw_connection_t socket;
@property (nonatomic, strong)SSFragTLSChannel *fragChannel;
@property (nonatomic)SSTCPSocketState cancelling;
@property (nonatomic)NSInteger balance;
@property (nonatomic, copy, readwrite, nullable)NSString *connectionError;
@end


static long long __refCount__ = 0;

@implementation SSTCPClient {
    // Note: transport here is the actual underlying transport protocol
    SSTransportType _transportType;

    // Proxy protocol in use; nil for direct connections
    SSProtocol *_protocol;

    // websocket codec
    CCCodec *_codec;

    // Proxy hops resolved for this connection (nil = no proxy); each hop is
    // tried in order until one reaches the ready state
    NSArray<SSProxyHop *> *_proxyHops;
    NSInteger _proxyHopIndex;
    NSInteger _proxyHopGeneration;
    int _family;
}

-(instancetype)initWithTarget:(NSString *)target port:(int)port proto:(SSProtocolType)proto {
    return [self initWithTarget:target port:port proto:proto family:AF_INET];
}

-(instancetype)initWithTarget:(NSString *)target port:(int)port proto:(SSProtocolType)proto family:(int)family{
    self = [super init];
    if (self) {
        BOOL isProxy = ![self isKindOfClass:NSClassFromString(@"SSDirectClient")];
        if (!isProxy) {
            _socket = [self create_outbound_connection:target.UTF8String
                                                g_port:port
                                             g_use_udp:proto == SSProtocolTypeUDP
                                             g_use_tls:NO
                                           g_transport:(SSTransportTypeTCP)
                                      g_allow_insecure:NO
                                              g_family:family
                                                 g_sni:NULL
                                                  g_hop:nil];
            _transportType = SSTransportTypeTCP;
        }
        else {
            _protocol = NWRunLoop.currentRunLoop.protocol;
            _transportType = _protocol.transport;
            BOOL allowInsecure = _protocol.allowInsecure;
            SSSstp *sstpCfg = [_protocol isKindOfClass:SSSstp.class] ? (SSSstp *)_protocol : nil;
            if (sstpCfg.proxyMode != 0) {
                // Socket creation is deferred to -connect: the proxy path
                // (detection probe / PAC evaluation) must be resolved first.
            } else {
                _socket = [self create_outbound_connection:_protocol.host.UTF8String
                                                    g_port:_protocol.port
                                                 g_use_udp:NO
                                                 g_use_tls:[self useFragChannel] ? NO : NWRunLoop.currentRunLoop.protocol.tls
                                               g_transport:_transportType
                                          g_allow_insecure:allowInsecure
                                                  g_family:family
                                                     g_sni:_protocol.domain.UTF8String
                                                  g_hop:nil];
            }
        }
        _target = target;
        _port = port;
        _state = SSTCPStateIDLE;
        _cancelling = SSTCPSocketStateIDLE;
        _proto = proto;
        _family = family;
        __refCount__++;
    }
    return self;
}

-(void)dealloc {
    __refCount__--;
}

+ (long long)refCount {
    return __refCount__;
}

-(void)startReceiving {
    if (self.fragChannel) {
        return;   // the channel owns the receive loop (set up at handshake)
    }
    __weak SSTCPClient *weakSelf = self;
    nw_connection_receive(self.socket, 1, UINT16_MAX, ^(dispatch_data_t content, nw_content_context_t context, bool is_complete, nw_error_t receive_error) {
        SSTCPClient *strongSelf = weakSelf;
        if (!strongSelf) return;
        dispatch_block_t schedule_next_receive = ^{
            // If the context is marked as complete, and is the final context,
            // we're read-closed.
            if (is_complete && (context == nil || nw_content_context_get_is_final(context))) {
//                NSLog(@"%@ receive remote disconnected by eof", strongSelf.tag);
                strongSelf.state = SSTCPStateDisconnected;
                return;
            }
            // If there was no error in receiving, request more data
            if (receive_error == nil) {
                [strongSelf startReceiving];
            }
        };
        if (content != nil && dispatch_data_get_size(content) > 0) {
            NSData *ocContent = (NSData *)content;
            [strongSelf handleMessage:ocContent];
        }
        // Content was NULL, so directly schedule the next receive
        if (strongSelf.cancelling == SSTCPSocketStateIDLE) {
            schedule_next_receive();
        }
    });
}

/// TLS fragmentation (SSTP only, TLS over TCP): when enabled, the outer TLS
/// runs through our own OpenSSL channel over a plain TCP connection so the
/// handshake bytes can be written in ordered chunks.
-(BOOL)useFragChannel {
    SSSstp *sstpCfg = [_protocol isKindOfClass:SSSstp.class] ? (SSSstp *)_protocol : nil;
    return sstpCfg != nil && sstpCfg.tlsFragMode > 0 && _protocol.tls;
}

-(void)handleMessage:(NSData *)message {
    switch (_transportType) {
        case SSTransportTypeWebSocket: {
            [_codec decode:(uint8_t *)message.bytes length:(int)message.length];
        }
            break;
            
        default: {
            [self didReceiveMessage:(char *)message.bytes buflen:(int)message.length];
        }
            break;
    }
}

-(void)codec:(CCCodec *)codec statusDidChanged:(CCCodecStatus)status error:(nullable NSError *)error{
    if (status == CCCodecStatusConnected) {
        self.state = SSTCPStateConnected;
    }
    else if (status == CCCodecStatusDisconnected) {
        self.state = SSTCPStateDisconnected;
        if (error) {
            SSLogI(@"%@ disconnected caused by: %@", self.tag, error);
        }
    }
}

-(void)codec:(CCCodec *)codec read:(uint8_t *)message length:(int)length {
    [self didReceiveMessage:(char *)message buflen:length];
}

-(void)codec:(CCCodec *)codec write:(uint8_t *)message length:(int)length {
    [self sendMessageToNetwork:message length:length];
}

-(void)ready {
    [self startReceiving];
    switch (_transportType) {
        case SSTransportTypeWebSocket: {
            NSString *domain = self.protocol.domain.length > 0 ? self.protocol.domain : self.protocol.host;
            NSURL *url = [NSURL URLWithString:[NSString stringWithFormat:@"%@://%@:%@%@", (_protocol.tls ? @"wss":@"ws"), domain, @(_protocol.port), _protocol.query]];
            _codec = [[CCWebSocket alloc] initWithURL:url];
            _codec.delegate = self;
            [_codec open];
        }
            break;
            
        default: {
            self.state = SSTCPStateConnected;
        }
            break;
    }
}

-(void)didReceiveMessage:(char *)message buflen:(int)buflen {
    NSAssert(false, @"subclasses must implement the message receive method");
}

-(void)checkConnection {
    
}

-(void)sendMessageToNetwork:(uint8_t *)message length:(int)length {
    if (self.fragChannel) {
        [self.fragChannel sendPlaintext:[NSData dataWithBytes:message length:length]];
        return;
    }
    if (self.cancelling != SSTCPSocketStateIDLE) {
        SSLogI(@"%@ cancelling: %@", self.tag, @(self.cancelling));
        return;
    }
    self.balance++;
    __weak SSTCPClient *weakSelf = self;
    dispatch_data_t content = dispatch_data_create((void *)message, length, nil, DISPATCH_DATA_DESTRUCTOR_DEFAULT);
    NSString *tag = self.tag;
    nw_connection_send(self.socket, content, NW_CONNECTION_DEFAULT_MESSAGE_CONTEXT, true, ^(nw_error_t  _Nullable error) {
        __strong SSTCPClient *strongSelf = weakSelf;
        strongSelf.balance--;
        [strongSelf checkConnection];
        if (error) {
            SSLogI(@"%@ nw_connection_send failure:%@", tag, error);
        }
    });
}

-(BOOL)sendMessage:(uint8_t *)message length:(int)length {
    if (!_socket) {
        return NO;
    }
    
    switch (_transportType) {
        case SSTransportTypeWebSocket:{
            [_codec encode:message length:length];
        }
            break;
            
        default: {
            [self sendMessageToNetwork:message length:length];
        }
            break;
    }
    return YES;
}

-(void)close {
    [_fragChannel close];
    _fragChannel = nil;
    [_codec close];
    if (self.cancelling != SSTCPSocketStateIDLE) {
        return;
    }
    self.cancelling = SSTCPSocketStateCancelled;
    nw_connection_cancel(self.socket);
}

-(void)getCertificate:(uint8_t *)certificate length:(int *)length evp:(int)evp{
    if (self.fragChannel) {
        NSData *leaf = [self.fragChannel peerCertificateDER];
        if (leaf.length == 0) {
            *length = 0;
            return;
        }
        if (evp == 0) {
            crypto_sha1(leaf.bytes, leaf.length, certificate);
            *length = 20;
        }
        else {
            crypto_sha256(leaf.bytes, leaf.length, certificate);
            *length = 32;
        }
        return;
    }
    if (!self.socket) {
        return;
    }
    nw_protocol_metadata_t meta = nw_connection_copy_protocol_metadata(self.socket, nw_protocol_copy_tls_definition());
    sec_protocol_metadata_t sec_meta = nw_tls_copy_sec_protocol_metadata(meta);
    __block NSData *hash;
    __block BOOL isFirst = YES;
    bool accessible = sec_protocol_metadata_access_peer_certificate_chain(sec_meta, ^(sec_certificate_t  _Nonnull certificate) {
        // Only the leaf certificate (first in the chain) — the SSTP crypto binding needs the leaf hash
        if (!isFirst) {
            return;
        }
        isFirst = NO;
        SecCertificateRef cert = sec_certificate_copy_ref(certificate);
        if (cert == nil) {
            return;
        }
        CFDataRef cert_data_ref = SecCertificateCopyData(cert);
        hash = CFBridgingRelease(cert_data_ref);
        CFRelease(cert);
    });
    
    if (!accessible) {
        *length = 0;
        return;
    }
    if (evp == 0) {
        crypto_sha1(hash.bytes, hash.length, certificate);
        *length = 20;
    }
    else {
        crypto_sha256(hash.bytes, hash.length, certificate);
        *length = 32;
    }
}

-(void)connect {
    self.state = SSTCPStateConnecting;
    SSSstp *sstpCfg = [_protocol isKindOfClass:SSSstp.class] ? (SSSstp *)_protocol : nil;
    if (_socket == nil && sstpCfg.proxyMode != 0) {
        // Resolve the proxy path first (manual detection probe or PAC
        // download/evaluation); the SSTP flow only starts once a hop has
        // produced a ready TLS connection.
        __weak SSTCPClient *weakSelf = self;
        [SSProxyResolver resolveMode:sstpCfg.proxyMode
                           proxyHost:sstpCfg.proxyHost
                           proxyPort:sstpCfg.proxyPort
                       proxyUsername:sstpCfg.proxyUsername
                       proxyPassword:sstpCfg.proxyPassword
                              pacURL:sstpCfg.pacURL
                          targetHost:sstpCfg.host
                          targetPort:sstpCfg.port
                               queue:dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0)
                          completion:^(NSArray<SSProxyHop *> *hops, NSError *error) {
            SSTCPClient *strongSelf = weakSelf;
            if (!strongSelf) return;
            if (error != nil || hops.count == 0) {
                strongSelf.connectionError = error.localizedDescription ?: @"Proxy resolution failed";
                SSLogM(@"%@ proxy error: %@", strongSelf.tag, strongSelf.connectionError);
                strongSelf.state = SSTCPStateDisconnected;
                return;
            }
            strongSelf->_proxyHops = hops;
            strongSelf->_proxyHopIndex = 0;
            [strongSelf startCurrentProxyHop];
        }];
        return;
    }
    [self startSocket];
}

/// Try the current proxy hop: build the connection (with the hop's proxy
/// config attached when the hop is not DIRECT) and start it.
-(void)startCurrentProxyHop {
    SSProxyHop *hop = _proxyHops[_proxyHopIndex];
    if (hop.type != SSProxyHopTypeDirect) {
        SSLogI(@"%@ trying proxy hop %ld/%ld: %@ %@:%ld", self.tag,
              (long)(_proxyHopIndex + 1), (long)_proxyHops.count,
              hop.type == SSProxyHopTypeSOCKS5 ? @"SOCKS5" : @"HTTP CONNECT",
              hop.host, (long)hop.port);
    }
    _socket = [self create_outbound_connection:_protocol.host.UTF8String
                                        g_port:_protocol.port
                                     g_use_udp:NO
                                     g_use_tls:[self useFragChannel] ? NO : _protocol.tls
                                   g_transport:_transportType
                              g_allow_insecure:_protocol.allowInsecure
                                      g_family:_family
                                         g_sni:_protocol.domain.UTF8String
                                          g_hop:hop];
    if (_socket == nil) {
        // Proxy API unavailable on this OS version — no point retrying
        self.state = SSTCPStateDisconnected;
        return;
    }
    // Per-hop timeout: a silently black-holed proxy must not stall the
    // fallback list
    NSInteger generation = ++_proxyHopGeneration;
    __weak SSTCPClient *weakSelf = self;
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(15 * NSEC_PER_SEC)),
                   NWRunLoop.currentRunLoop.worker, ^{
        SSTCPClient *strongSelf = weakSelf;
        if (!strongSelf) return;
        if (strongSelf->_proxyHops != nil &&
            strongSelf->_proxyHopGeneration == generation &&
            strongSelf.state == SSTCPStateConnecting) {
            SSLogM(@"%@ proxy hop timed out", strongSelf.tag);
            [strongSelf advanceProxyHop];
        }
    });
    [self startSocket];
}

/// Move to the next PAC fallback hop, or fail the connection.
-(void)advanceProxyHop {
    if (self.cancelling != SSTCPSocketStateIDLE) {
        return;
    }
    if (_socket != nil) {
        // Detach the handler first: the cancelled state must not turn into
        // a client disconnect while the fallback list is still being tried
        nw_connection_set_state_changed_handler(_socket, NULL);
        nw_connection_cancel(_socket);
        _socket = nil;
    }
    _proxyHopIndex++;
    if (_proxyHopIndex < (NSInteger)_proxyHops.count) {
        [self startCurrentProxyHop];
        return;
    }
    if (self.connectionError == nil) {
        self.connectionError = @"Proxy connection failed (no usable proxy path)";
    }
    SSLogM(@"%@ %@", self.tag, self.connectionError);
    self.state = SSTCPStateDisconnected;
}

#pragma mark - TLS fragmentation channel

/// Runs the OpenSSL handshake over the (plain TCP) socket that just became
/// ready, then continues into the normal `ready` flow.
-(void)startFragHandshake {
    SSSstp *sstpCfg = (SSSstp *)_protocol;
    SSFragTLSConfig *cfg = [SSFragTLSConfig new];
    cfg.mode = sstpCfg.tlsFragMode == 2 ? SSFragModeAuto : SSFragModeManual;
    cfg.firstChunk = sstpCfg.tlsFragFirst > 0 ? sstpCfg.tlsFragFirst : 32;
    cfg.followingChunk = sstpCfg.tlsFragFollowing > 0 ? sstpCfg.tlsFragFollowing : 256;
    cfg.maxExtraDelayMs = sstpCfg.tlsFragDelayMs > 0 ? sstpCfg.tlsFragDelayMs : 0;
    NSString *cfgError = [cfg validate];
    if (cfgError) {
        // Fail closed: the socket here is plain TCP, continuing would send
        // the SSTP handshake in cleartext.
        SSLogM(@"%@ TLS-frag: invalid config: %@", self.tag, cfgError);
        self.connectionError = [NSString stringWithFormat:@"Invalid TLS fragmentation settings: %@", cfgError];
        self.state = SSTCPStateDisconnected;
        return;
    }
    NSString *sni = _protocol.domain.length > 0 ? _protocol.domain : _protocol.host;
    SSLogM(@"%@ TLS-frag: OpenSSL channel, mode=%@ (first=%lu following=%lu delay=%lu ms)",
           self.tag, cfg.mode == SSFragModeAuto ? @"auto" : @"manual",
           (unsigned long)cfg.firstChunk, (unsigned long)cfg.followingChunk,
           (unsigned long)cfg.maxExtraDelayMs);
    __weak SSTCPClient *weakSelf = self;
    self.fragChannel = [[SSFragTLSChannel alloc] initWithConnection:self.socket
                                                                sni:sni
                                                      allowInsecure:_protocol.allowInsecure
                                               disableLegacyVersion:sstpCfg.disableLegacyOuterTls
                                                         pinnedCAPEM:nil
                                                             config:cfg
                                                              queue:NWRunLoop.currentRunLoop.worker];
    self.fragChannel.onPlaintext = ^(NSData *data) {
        SSTCPClient *strongSelf = weakSelf;
        if (!strongSelf) return;
        [strongSelf handleMessage:data];
    };
    self.fragChannel.onClose = ^(NSError *error) {
        SSTCPClient *strongSelf = weakSelf;
        if (!strongSelf) return;
        if (strongSelf.cancelling == SSTCPSocketStateIDLE) {
            strongSelf.state = SSTCPStateDisconnected;
        }
    };
    [self.fragChannel startHandshake:^(NSError *error) {
        SSTCPClient *strongSelf = weakSelf;
        if (!strongSelf) return;
        if (error) {
            SSLogM(@"%@ TLS-frag handshake failed: %@", strongSelf.tag, error.localizedDescription);
            strongSelf.connectionError = error.localizedDescription;
            strongSelf.state = SSTCPStateDisconnected;
            return;
        }
        SSLogM(@"%@ TLS-frag: handshake OK, entering ready", strongSelf.tag);
        [strongSelf ready];
        SSLogM(@"%@ TLS-frag: ready returned", strongSelf.tag);
    }];
}

-(void)startSocket {
    // Spec-required diagnostics (Expert level): the TCP destination, the TLS
    // SNI and the certificate verification hostname are independent values.
    // With custom SNI set, NW both sends it in the ClientHello and verifies
    // the certificate against it; without it, both default to the host.
    NSString *sni = _protocol.domain.length > 0 ? _protocol.domain : nil;
    SSLogI(@"Connecting to: %@:%d", _protocol.host, _protocol.port);
    SSLogI(@"TLS SNI: %@", sni.length > 0 ? sni : _protocol.host);
    SSLogI(@"Certificate verification hostname: %@", sni.length > 0 ? sni : _protocol.host);
    nw_connection_set_queue(self.socket, NWRunLoop.currentRunLoop.worker);
    __weak SSTCPClient *weakSelf = self;
    nw_connection_set_state_changed_handler(self.socket, ^(nw_connection_state_t state, nw_error_t error) {
        __strong SSTCPClient *strongSelf = weakSelf;
        if (!strongSelf) return;
        nw_endpoint_t remote = nw_connection_copy_endpoint(strongSelf.socket);
        if (state == nw_connection_state_waiting) {
            SSLogM(@"%@ tcp failure: %@, is waiting", strongSelf.tag, error);
            if (strongSelf->_proxyHops != nil && strongSelf.state == SSTCPStateConnecting) {
                [strongSelf advanceProxyHop];
                return;
            }
            strongSelf.state = SSTCPStateDisconnected;
        } else if (state == nw_connection_state_failed) {
            if (strongSelf.cancelling == SSTCPSocketStateIDLE) {
                SSLogM(@"%@ connect to %s port %u failure: %@", strongSelf.tag, nw_endpoint_get_hostname(remote), nw_endpoint_get_port(remote), error);
            }
            if (strongSelf->_proxyHops != nil && strongSelf.state == SSTCPStateConnecting) {
                // Hop failed before the tunnel/TLS came up: next fallback
                [strongSelf advanceProxyHop];
                return;
            }
            if (strongSelf.cancelling == SSTCPSocketStateCancelling) {
                nw_connection_cancel(strongSelf.socket);
                strongSelf.cancelling = SSTCPSocketStateCancelled;
            }
            strongSelf.socket = nil;
            strongSelf.state = SSTCPStateDisconnected;
        } else if (state == nw_connection_state_ready) {
            strongSelf->_proxyHopGeneration++;   // disarm the hop timeout
            if (strongSelf->_proxyHops != nil) {
                SSProxyHop *hop = strongSelf->_proxyHops[strongSelf->_proxyHopIndex];
                if (hop.type != SSProxyHopTypeDirect) {
                    SSLogM(@"Proxy tunnel: established (%@ %@:%ld)",
                          hop.type == SSProxyHopTypeSOCKS5 ? @"SOCKS5" : @"HTTP CONNECT",
                          hop.host, (long)hop.port);
                }
                SSLogM(@"SSTP destination: %@:%d", strongSelf->_protocol.host, strongSelf->_protocol.port);
                NSString *sni = strongSelf->_protocol.domain.length > 0
                    ? strongSelf->_protocol.domain : strongSelf->_protocol.host;
                SSLogM(@"TLS SNI: %@", sni);
            }
            if ([strongSelf useFragChannel]) {
                [strongSelf startFragHandshake];
                return;
            }
            [strongSelf ready];
        } else if (state == nw_connection_state_cancelled) {
            // Release the primary reference on the connection
            // that was taken at creation time
            strongSelf.socket = nil;
            strongSelf.state = SSTCPStateDisconnected;
        }
    });
    nw_connection_start(self.socket);
}

-(nw_connection_t) create_outbound_connection:(const char *)name
                                       g_port:(int)g_port
                                    g_use_udp:(BOOL)g_use_udp
                                    g_use_tls:(BOOL)g_use_tls
                                  g_transport:(SSTransportType)g_transport
                             g_allow_insecure:(BOOL)g_allow_insecure
                                     g_family:(int)g_family
                                        g_sni:(const char *)g_sni
                                         g_hop:(SSProxyHop *)g_hop{

    char port[6] = {0};
    snprintf(port, 6, "%d", g_port);
    nw_endpoint_t endpoint = nw_endpoint_create_host(name, port);

    nw_parameters_t parameters = NULL;
    SSSstp *sstpCfg = [_protocol isKindOfClass:SSSstp.class] ? (SSSstp *)_protocol : nil;
    BOOL disableLegacyOuterTls = sstpCfg.disableLegacyOuterTls;
    nw_parameters_configure_protocol_block_t configure_tls = NW_PARAMETERS_DISABLE_PROTOCOL;
    if (g_use_tls) {

        const char *vv_sni = g_sni != NULL ? strdup(g_sni) : NULL;

        // The EAP inner TLS tunnels (PEAP/TTLS/TEAP) have their own version
        // knobs in EAP Configuration; disableLegacyOuterTls only applies to
        // this outer SSTP TLS session.
        configure_tls = ^(nw_protocol_options_t _Nonnull options) {
            SSConfigureOuterTLSOptions(options, vv_sni, g_allow_insecure,
                                       disableLegacyOuterTls,
                                       NWRunLoop.currentRunLoop.worker);
        };
    }
    if (g_use_udp) {
        // Create a UDP connection
        parameters = nw_parameters_create_secure_udp(configure_tls,
                                                     NW_PARAMETERS_DEFAULT_CONFIGURATION);
    } else {
        // Create a TCP connection
        parameters = nw_parameters_create_secure_tcp(configure_tls,
                                                     NW_PARAMETERS_DEFAULT_CONFIGURATION);
    }
    if (g_hop != nil && g_hop.type != SSProxyHopTypeDirect) {
        // Route this connection through the proxy hop. TLS options above are
        // untouched: SNI and certificate verification still target the SSTP
        // server, only the TCP path goes via the proxy.
        if (@available(iOS 17.0, macOS 14.0, *)) {
            char proxyPort[8] = {0};
            snprintf(proxyPort, sizeof(proxyPort), "%ld", (long)g_hop.port);
            nw_endpoint_t proxyEndpoint = nw_endpoint_create_host(g_hop.host.UTF8String, proxyPort);
            nw_proxy_config_t proxyConfig =
                g_hop.type == SSProxyHopTypeSOCKS5
                    ? nw_proxy_config_create_socksv5(proxyEndpoint)
                    : nw_proxy_config_create_http_connect(proxyEndpoint, nil);
            if (g_hop.username.length > 0) {
                nw_proxy_config_set_username_and_password(proxyConfig,
                    g_hop.username.UTF8String, g_hop.password.UTF8String ?: "");
            }
            nw_privacy_context_t privacyContext = nw_privacy_context_create("SRP proxy");
            nw_privacy_context_add_proxy(privacyContext, proxyConfig);
            nw_parameters_set_privacy_context(parameters, privacyContext);
        } else {
            SSLogM(@"proxy connections require iOS 17 / macOS 14");
            self.connectionError = @"Proxy connections require iOS 17 or later";
            return nil;
        }
    }
    nw_protocol_stack_t protocol_stack = nw_parameters_copy_default_protocol_stack(parameters);
    if (g_family == AF_INET || g_family == AF_INET6) {
        nw_protocol_options_t ip_options = nw_protocol_stack_copy_internet_protocol(protocol_stack);
        if (g_family == AF_INET) {
            // Force IPv4
            nw_ip_options_set_version(ip_options, nw_ip_version_4);
        } else if (g_family == AF_INET6) {
            // Force IPv6
            nw_ip_options_set_version(ip_options, nw_ip_version_6);
        }
    }
    nw_connection_t connection = nw_connection_create(endpoint, parameters);
    return connection;
}

-(void)checkTimeout {}

@end
