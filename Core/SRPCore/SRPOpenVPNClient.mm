//
//  SRPOpenVPNClient.mm
//  SRPCore
//
//  Objective-C++ session owner for OpenVPN 3 Core. The core's public
//  interfaces (ovpncli.hpp) are used with the external TUN and transport
//  factories: packets cross to NEPacketTunnelFlow via callbacks, native
//  UDP/TCP modes reuse the core's built-in transport configs, and the
//  optional stunnel mode uses an SRP TLS transport (NWConnection).
//

#import "SRPOpenVPNClient.h"

extern "C" {
#import "SSLog.h"
}

#import <NetworkExtension/NetworkExtension.h>
#import <Network/Network.h>
#import <Security/Security.h>
#import <arpa/inet.h>
#import <netdb.h>
#import <string>
#import <memory>

#include "ovpncli.hpp"
#include <openvpn/tun/client/tunbase.hpp>
#include <openvpn/transport/client/transbase.hpp>
#include <openvpn/transport/client/extern/config.hpp>
#import "SSFragTLSChannel.h"
#include <openvpn/transport/client/udpcli.hpp>
#include <openvpn/transport/client/tcpcli.hpp>
#include <openvpn/transport/protocol.hpp>

#pragma mark - C++ <-> ObjC bridge

namespace openvpn::logging {
/// Backend for the OPENVPN_LOG fallback defined in logger.hpp (SRP build).
static void (*srp_sink_fn)(void *, const char *);
static void *srp_sink_ctx;
void srp_set_sink(void *ctx, void (*fn)(void *, const char *)) {
    srp_sink_ctx = ctx;
    srp_sink_fn = fn;
}
void srp_log_sink(const std::string &s) {
    if (srp_sink_fn) srp_sink_fn(srp_sink_ctx, s.c_str());
}
}

@interface SRPOpenVPNClient (Cpp)
- (void)ovpnApplyOptionsAndWait:(NSArray<NSArray<NSString *> *> *)options;
- (void)ovpnOutputPacket:(NSData *)packet family:(int)family;
- (void)ovpnEventConnected;
- (void)ovpnEventDisconnectedWithError:(nullable NSString *)message;
- (void)ovpnLogLine:(NSString *)line;
- (void)ovpnRegisterTun:(void *)tun;
- (void)ovpnUnregisterTun:(void *)tun;
@end

#pragma mark - C++ TUN client

class SRPTun : public openvpn::TunClient {
  public:
    SRPTun(openvpn_io::io_context &io, openvpn::TunClientParent &parent,
           __weak SRPOpenVPNClient *owner)
        : io_(io), parent_(parent), owner_(owner) {
        [owner_ ovpnRegisterTun:this];
    }

    ~SRPTun() override {
        stop_ = true;
        [owner_ ovpnUnregisterTun:this];
    }

    void tun_start(const openvpn::OptionList &opt, openvpn::TransportClient &,
                   openvpn::CryptoDCSettings &) override {
        NSMutableArray<NSMutableArray<NSString *> *> *opts = [NSMutableArray array];
        for (const auto &o : opt) {
            NSMutableArray<NSString *> *parts = [NSMutableArray array];
            for (size_t i = 0; i < o.size(); i++)
                [parts addObject:@(o.get(i, 256).c_str())];
            if (parts.count)
                [opts addObject:parts];
        }
        // The core requires connected_ to be set when tun_start returns —
        // apply settings and wait for the provider (or harness) to confirm,
        // then notify synchronously.
        [owner_ ovpnApplyOptionsAndWait:opts];
        parent_.tun_connected();
        [owner_ ovpnEventConnected];
    }

    void stop() override {}

    void set_disconnect() override {}

    bool tun_send(openvpn::BufferAllocated &buf) override {
        const unsigned char *data = buf.data();
        size_t len = buf.size();
        if (!data || len < 1)
            return true;
        int family = (data[0] >> 4) == 6 ? AF_INET6 : AF_INET;
        NSData *pkt = [NSData dataWithBytes:data length:len];
        [owner_ ovpnOutputPacket:pkt family:family];
        return true;
    }

    std::string tun_name() const override { return "srp-tun"; }
    std::string vpn_ip4() const override { return ip4_; }
    std::string vpn_ip6() const override { return ip6_; }
    int vpn_mtu() const override { return mtu_; }

    void setAddr(std::string ip4, std::string ip6, int mtu) {
        ip4_ = std::move(ip4);
        ip6_ = std::move(ip6);
        mtu_ = mtu;
    }

    void injectFromPhone(NSData *packet) {
        if (!packet || packet.length == 0)
            return;
        openvpn_io::post(io_, [this, packet]() mutable {
            if (stop_)
                return;
            openvpn::BufferAllocated buf((const unsigned char *)packet.bytes,
                                         packet.length, 0);
            parent_.tun_recv(buf);
        });
    }

  private:
    openvpn_io::io_context &io_;
    openvpn::TunClientParent &parent_;
    __weak SRPOpenVPNClient *owner_;
    std::string ip4_, ip6_;
    int mtu_ = 1500;
    bool stop_ = false;
};

class SRPTunFactory : public openvpn::TunClientFactory {
  public:
    SRPTunFactory(__weak SRPOpenVPNClient *owner) : owner_(owner) {}

    openvpn::TunClient::Ptr new_tun_client_obj(openvpn_io::io_context &io_context,
                                               openvpn::TunClientParent &parent,
                                               openvpn::TransportClient *) override {
        return openvpn::TunClient::Ptr(new SRPTun(io_context, parent, owner_));
    }

    bool supports_epoch_data() override { return false; }

  private:
    __weak SRPOpenVPNClient *owner_;
};

#pragma mark - stunnel TLS transport (NWConnection)

struct SRPStunnelCfg {
    std::string host;
    int port = 443;
    std::string sni;
    std::string caPem;   // PEM of the outer CA (empty = system trust)
    int fragMode = 0;    // 0 off, 1 manual, 2 auto
    int fragFirst = 0;
    int fragFollowing = 0;
};

/// OpenVPN TCP stream inside an outer TLS connection to a server-side
/// stunnel listener. Preserves OpenVPN TCP framing: two-byte big-endian
/// packet length followed by that many OpenVPN packet bytes.
class SRPStunnelTransport : public openvpn::TransportClient {
  public:
    SRPStunnelTransport(openvpn_io::io_context &io,
                        openvpn::TransportClientParent *parent,
                        const SRPStunnelCfg &cfg)
        : io_(io), parent_(parent), cfg_(cfg) {}

    ~SRPStunnelTransport() override { cleanup(); }

    void transport_start() override {
        queue_ = dispatch_queue_create("srp.stunnel", DISPATCH_QUEUE_SERIAL);
        recvBuf_ = [NSMutableData new];

        if (cfg_.fragMode > 0) {
            startFragChannel();
            return;
        }

        nw_parameters_configure_protocol_block_t tls_conf = ^(nw_protocol_options_t options) {
            sec_protocol_options_t opts = nw_tls_copy_sec_protocol_options(options);
            sec_protocol_options_set_min_tls_protocol_version(opts, tls_protocol_version_TLSv12);
            sec_protocol_options_set_max_tls_protocol_version(opts, tls_protocol_version_TLSv13);
            if (!cfg_.sni.empty())
                sec_protocol_options_set_tls_server_name(opts, cfg_.sni.c_str());
            if (!cfg_.caPem.empty()) {
                NSData *caData = [NSData dataWithBytes:cfg_.caPem.data() length:cfg_.caPem.size()];
                SecCertificateRef ca = SecCertificateCreateWithData(NULL, (__bridge CFDataRef)caData);
                sec_protocol_options_set_verify_block(opts,
                    ^(sec_protocol_metadata_t, sec_trust_t trust_ref, sec_protocol_verify_complete_t complete) {
                        // Do NOT evaluate here (nested evaluation is forbidden);
                        // just pin the anchor and let the system evaluate with it.
                        if (ca) {
                            SecTrustRef trust = (__bridge SecTrustRef)trust_ref;
                            SecTrustSetAnchorCertificates(trust, (__bridge CFArrayRef)@[(__bridge id)ca]);
                            SecTrustSetAnchorCertificatesOnly(trust, true);
                        }
                        complete(true);
                    }, queue_);
                if (ca) CFRelease(ca);
            }
        };
        nw_parameters_t params = nw_parameters_create_secure_tcp(tls_conf,
                                                                 NW_PARAMETERS_DEFAULT_CONFIGURATION);

        char portStr[8];
        snprintf(portStr, sizeof(portStr), "%d", cfg_.port);
        nw_endpoint_t endpoint = nw_endpoint_create_host(cfg_.host.c_str(), portStr);
        conn_ = nw_connection_create(endpoint, params);
        nw_connection_set_queue(conn_, queue_);

        parent_->transport_wait();
        nw_connection_set_state_changed_handler(conn_, ^(nw_connection_state_t state, nw_error_t error) {
            onState(state, error);
        });
        nw_connection_start(conn_);
        openvpn::logging::srp_log_sink("stunnel: connecting " + cfg_.host + ":" + std::to_string(cfg_.port)
                                       + " sni=" + (cfg_.sni.empty() ? std::string("(default)") : cfg_.sni)
                                       + " ca=" + (cfg_.caPem.empty() ? std::string("system") : std::string("custom")));
        receive();
    }

    void stop() override { cleanup(); }

    bool transport_send_const(const openvpn::Buffer &buf) override {
        if (!conn_ || stopped_) return false;
        size_t len = buf.size();
        if (len > 0xFFFF) return false;
        if (!sentFirstTx_) {
            sentFirstTx_ = true;
            openvpn::logging::srp_log_sink("stunnel: first TX " + std::to_string(len) + " bytes");
        }
        size_t total = len + 2;
        uint8_t *raw = (uint8_t *)malloc(total);
        uint16_t plen = htons((uint16_t)len);
        memcpy(raw, &plen, 2);
        memcpy(raw + 2, buf.c_data(), len);
        if (channel_) {
            [channel_ sendPlaintext:[NSData dataWithBytesNoCopy:raw length:total freeWhenDone:YES]];
            return true;
        }
        dispatch_data_t dd = dispatch_data_create(raw, total, queue_,
                                                  DISPATCH_DATA_DESTRUCTOR_DEFAULT);
        pending_ += (NSInteger)total;
        nw_connection_send(conn_, dd, NW_CONNECTION_DEFAULT_MESSAGE_CONTEXT, false,
                           ^(nw_error_t error) {
            dispatch_async(queue_, ^{
                pending_ -= (NSInteger)total;
                if (pending_ <= 0 && parent_) {
                    pending_ = 0;
                    SRPStunnelTransport *self = this;
                    openvpn_io::post(io_, [self]() { self->parent_->transport_needs_send(); });
                }
            });
        });
        return true;
    }

    bool transport_send(openvpn::BufferAllocated &buf) override {
        return transport_send_const(buf);
    }

    bool transport_send_queue_empty() override { return pending_ <= 0; }
    bool transport_has_send_queue() override { return pending_ > 0; }
    void transport_stop_requeueing() override {}
    size_t transport_send_queue_size() override { return (size_t)pending_; }
    void reset_align_adjust(const size_t) override {}

    openvpn::IP::Addr server_endpoint_addr() const override {
        struct in_addr a4;
        if (inet_pton(AF_INET, endpointIp_.c_str(), &a4) == 1)
            return openvpn::IP::Addr::from_string(endpointIp_);
        return openvpn::IP::Addr();
    }

    unsigned short server_endpoint_port() const override { return (unsigned short)cfg_.port; }

    void server_endpoint_info(std::string &host, std::string &port,
                              std::string &proto, std::string &ip_addr) const override {
        host = cfg_.host;
        char p[8];
        snprintf(p, sizeof(p), "%d", cfg_.port);
        port = p;
        proto = "tcp";
        ip_addr = endpointIp_;
    }

    openvpn::Protocol transport_protocol() const override {
        return openvpn::Protocol(openvpn::Protocol::TCPv4);
    }

    void transport_reparent(openvpn::TransportClientParent *parent) override {
        parent_ = parent;
    }

  private:
    /// Fragmentation mode: outer TLS runs through SSFragTLSChannel (OpenSSL
    /// over a plain TCP connection) so the ClientHello can be split.
    void startFragChannel() {
        nw_parameters_t params = nw_parameters_create_secure_tcp(NW_PARAMETERS_DISABLE_PROTOCOL,
                                                                 NW_PARAMETERS_DEFAULT_CONFIGURATION);
        char portStr[8];
        snprintf(portStr, sizeof(portStr), "%d", cfg_.port);
        nw_endpoint_t endpoint = nw_endpoint_create_host(cfg_.host.c_str(), portStr);
        conn_ = nw_connection_create(endpoint, params);
        nw_connection_set_queue(conn_, queue_);

        SSFragTLSConfig *fc = [SSFragTLSConfig new];
        fc.mode = cfg_.fragMode == 2 ? SSFragModeAuto : SSFragModeManual;
        fc.firstChunk = cfg_.fragFirst > 0 ? (NSUInteger)cfg_.fragFirst : 32;
        fc.followingChunk = cfg_.fragFollowing > 0 ? (NSUInteger)cfg_.fragFollowing : 256;

        parent_->transport_wait();
        SRPStunnelTransport *self = this;
        nw_connection_set_state_changed_handler(conn_, ^(nw_connection_state_t state, nw_error_t error) {
            if (state == nw_connection_state_ready) {
                NSString *sni = cfg_.sni.empty() ? nil : @(cfg_.sni.c_str());
                NSString *ca = cfg_.caPem.empty() ? nil : @(cfg_.caPem.c_str());
                channel_ = [[SSFragTLSChannel alloc] initWithConnection:conn_
                                                                    sni:sni ?: @(cfg_.host.c_str())
                                                          allowInsecure:NO
                                                   disableLegacyVersion:YES
                                                            pinnedCAPEM:ca
                                                                 config:fc
                                                                  queue:queue_];
                channel_.onPlaintext = ^(NSData *data) {
                    [self->recvBuf_ appendData:data];
                    self->drainFrames();
                };
                channel_.onClose = ^(NSError *err) {
                    openvpn_io::post(self->io_, [self, err]() {
                        if (self->parent_ && !self->stopped_)
                            self->parent_->transport_error(openvpn::Error::TRANSPORT_ERROR,
                                                           err ? "stunnel TLS channel error" : "stunnel TLS channel closed");
                    });
                };
                [channel_ startHandshake:^(NSError *err) {
                    if (err) {
                        fail("TLS handshake with the stunnel endpoint failed: " + std::string(err.localizedDescription.UTF8String));
                        return;
                    }
                    connected_ = true;
                    resolveEndpoint();
                    openvpn::logging::srp_log_sink("stunnel: TLS ready (frag) to " + cfg_.host + ":" + std::to_string(cfg_.port));
                    parent_->transport_connecting();
                }];
            } else if (state == nw_connection_state_failed) {
                int err = error ? nw_error_get_error_code(error) : 0;
                fail("TCP connection to the stunnel endpoint failed (" + std::to_string(err) + ")");
            }
        });
        nw_connection_start(conn_);
        openvpn::logging::srp_log_sink("stunnel: connecting (frag) " + cfg_.host + ":" + std::to_string(cfg_.port));
    }

    void onState(nw_connection_state_t state, nw_error_t error) {
        openvpn::logging::srp_log_sink("stunnel: nw state=" + std::to_string((int)state)
                                       + " err=" + std::to_string(error ? nw_error_get_error_code(error) : 0));
        switch (state) {
        case nw_connection_state_ready:
            connected_ = true;
            resolveEndpoint();
            openvpn::logging::srp_log_sink("stunnel: TLS ready to " + cfg_.host + ":" + std::to_string(cfg_.port));
            parent_->transport_connecting();
            break;
        case nw_connection_state_failed: {
            int err = error ? nw_error_get_error_code(error) : 0;
            fail("TLS connection to the stunnel endpoint failed (" + std::to_string(err) + ")");
            break;
        }
        case nw_connection_state_cancelled:
            break;
        default:
            break;
        }
    }

    void receive() {
        if (!conn_ || stopped_) return;
        nw_connection_receive(conn_, 1, 256 * 1024, ^(dispatch_data_t content, nw_content_context_t,
                                                      bool is_complete, nw_error_t error) {
            if (content && dispatch_data_get_size(content) > 0) {
                if (!gotFirstRx_) {
                    gotFirstRx_ = true;
                    openvpn::logging::srp_log_sink("stunnel: first RX " + std::to_string(dispatch_data_get_size(content)) + " bytes");
                }
                [recvBuf_ appendData:(NSData *)content];
                drainFrames();
            }
            if (error) {
                int err = nw_error_get_error_code(error);
                fail("stunnel stream error (" + std::to_string(err) + ")");
                return;
            }
            if (is_complete) {
                SRPStunnelTransport *self = this;
                openvpn_io::post(io_, [self]() {
                    if (self->parent_) self->parent_->transport_error(openvpn::Error::UNDEF, "stunnel stream closed");
                });
                return;
            }
            receive();
        });
    }

    // OpenVPN TCP framing: 2-byte big-endian length + payload
    void drainFrames() {
        const uint8_t *bytes = (const uint8_t *)recvBuf_.bytes;
        size_t total = recvBuf_.length;
        size_t off = 0;
        while (total - off >= 2) {
            uint16_t plen = (bytes[off] << 8) | bytes[off + 1];
            if (plen == 0 || total - off < 2 + (size_t)plen) break;
            NSData *frame = [NSData dataWithBytes:bytes + off + 2 length:plen];
            off += 2 + plen;
            SRPStunnelTransport *self = this;
            openvpn_io::post(io_, [self, frame]() mutable {
                if (self->parent_ && !self->stopped_) {
                    openvpn::BufferAllocated buf((const unsigned char *)frame.bytes, frame.length, 0);
                    self->parent_->transport_recv(buf);
                }
            });
        }
        if (off > 0)
            [recvBuf_ replaceBytesInRange:NSMakeRange(0, off) withBytes:NULL length:0];
    }

    void resolveEndpoint() {
        if (!endpointIp_.empty()) return;
        struct addrinfo hints = {0}, *res = NULL;
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        char portStr[8];
        snprintf(portStr, sizeof(portStr), "%d", cfg_.port);
        if (getaddrinfo(cfg_.host.c_str(), portStr, &hints, &res) == 0 && res) {
            char buf[INET_ADDRSTRLEN];
            struct sockaddr_in *sa = (struct sockaddr_in *)res->ai_addr;
            if (inet_ntop(AF_INET, &sa->sin_addr, buf, sizeof(buf)))
                endpointIp_ = buf;
            freeaddrinfo(res);
        }
    }

    void fail(const std::string &msg) {
        if (stopped_) return;
        stopped_ = true;
        cleanup();
        SRPStunnelTransport *self = this;
        openvpn_io::post(io_, [self, msg]() {
            if (self->parent_) self->parent_->transport_error(openvpn::Error::TRANSPORT_ERROR, msg);
        });
    }

    void cleanup() {
        stopped_ = true;
        [channel_ close];
        channel_ = nil;
        if (conn_) {
            nw_connection_cancel(conn_);
            conn_ = nil;
        }
    }

    openvpn_io::io_context &io_;
    openvpn::TransportClientParent *parent_;
    SRPStunnelCfg cfg_;
    nw_connection_t conn_ = nil;
    SSFragTLSChannel *channel_ = nil;
    dispatch_queue_t queue_ = nil;
    NSMutableData *recvBuf_ = nil;
    NSInteger pending_ = 0;
    bool stopped_ = false;
    bool connected_ = false;
    bool gotFirstRx_ = false;
    bool sentFirstTx_ = false;
    std::string endpointIp_;
};

class SRPStunnelFactory : public openvpn::TransportClientFactory {
  public:
    SRPStunnelFactory(const SRPStunnelCfg &cfg) : cfg_(cfg) {}

    openvpn::TransportClient::Ptr new_transport_client_obj(openvpn_io::io_context &io_context,
                                                           openvpn::TransportClientParent *parent) override {
        return openvpn::TransportClient::Ptr(new SRPStunnelTransport(io_context, parent, cfg_));
    }

  private:
    SRPStunnelCfg cfg_;
};

#pragma mark - C++ client implementation

class SRPOvpnImpl : public openvpn::ClientAPI::OpenVPNClient {
  public:
    SRPOvpnImpl(__weak SRPOpenVPNClient *owner) : owner_(owner) {}

    // ExternalTun::Factory — fresh object each call; the core adopts it.
    openvpn::TunClientFactory *new_tun_factory(const openvpn::ExternalTun::Config &,
                                               const openvpn::OptionList &) override {
        NSLog(@"[ovpn-dbg] new_tun_factory called");
        return new SRPTunFactory(owner_);
    }

    // ExternalTransport::Factory — native UDP/TCP reuse the core's own
    // transport configs; stunnel mode uses the SRP TLS transport.
    openvpn::TransportClientFactory *new_transport_factory(const openvpn::ExternalTransport::Config &conf) override {
        NSLog(@"[ovpn-dbg] new_transport_factory proto udp=%d tcp=%d", conf.protocol.is_udp(), conf.protocol.is_tcp());
        if (conf.protocol.is_udp()) {
            openvpn::UDPTransport::ClientConfig::Ptr c = openvpn::UDPTransport::ClientConfig::new_obj();
            c->remote_list = conf.remote_list;
            c->frame = conf.frame;
            c->stats = conf.stats;
            c->socket_protect = conf.socket_protect;
            c->server_addr_float = conf.server_addr_float;
            tf_ = c;
            return tf_.get();
        }
        if (conf.protocol.is_tcp()) {
            SRPOpenVPNClient *o = owner_;
            if (o && o.stunnelEnabled) {
                SRPStunnelCfg sc;
                sc.host = o.stunnelHost ? o.stunnelHost.UTF8String : "";
                sc.fragMode = (int)o.tlsFragMode;
                sc.fragFirst = (int)o.tlsFragFirst;
                sc.fragFollowing = (int)o.tlsFragFollowing;
                sc.port = o.stunnelPort > 0 ? o.stunnelPort : 443;
                sc.sni = o.stunnelSNI.length > 0 ? o.stunnelSNI.UTF8String : sc.host;
                sc.caPem = o.outerCAPEM ? o.outerCAPEM.UTF8String : "";
                if (sc.host.empty()) {
                    [o ovpnEventDisconnectedWithError:@"stunnel is enabled but no stunnel Server is set"];
                    return nullptr;
                }
                tf_ = new SRPStunnelFactory(sc);
                return tf_.get();
            }
            openvpn::TCPTransport::ClientConfig::Ptr c = openvpn::TCPTransport::ClientConfig::new_obj();
            c->remote_list = conf.remote_list;
            c->frame = conf.frame;
            c->stats = conf.stats;
            c->socket_protect = conf.socket_protect;
            tf_ = c;
            return tf_.get();
        }
        [owner_ ovpnEventDisconnectedWithError:@"Unsupported transport protocol in the profile"];
        return nullptr;
    }

    // LogReceiver
    void log(const openvpn::ClientAPI::LogInfo &info) override {
        [owner_ ovpnLogLine:@(info.text.c_str())];
    }

    // EventReceiver
    void event(const openvpn::ClientAPI::Event &ev) override {
        NSString *name = @(ev.name.c_str());
        NSString *info = @(ev.info.c_str());
        NSLog(@"[ovpn-event] %@%@ (error=%d fatal=%d)", name,
              info.length ? [@": " stringByAppendingString:info] : @"", ev.error, ev.fatal);
        if (ev.error) {
            NSString *msg = [NSString stringWithFormat:@"%@%@", name, info.length ? [@": " stringByAppendingString:info] : @""];
            // Friendly messages for common fatal events
            if ([name isEqualToString:@"AUTH_FAILED"])
                msg = @"Authentication failed — check the username and password.";
            else if ([name isEqualToString:@"CONNECTION_TIMEOUT"])
                msg = @"Connection timed out. The server did not respond.";
            else if ([name isEqualToString:@"TLS_ERROR"])
                msg = [@"TLS negotiation with the server failed. " stringByAppendingString:info];
            [owner_ ovpnEventDisconnectedWithError:msg];
        }
    }

    void acc_event(const openvpn::ClientAPI::AppCustomControlMessageEvent &) override {}

    bool pause_on_connection_timeout() override { return false; }

    void external_pki_cert_request(openvpn::ClientAPI::ExternalPKICertRequest &) override {}
    void external_pki_sign_request(openvpn::ClientAPI::ExternalPKISignRequest &) override {}

    bool socket_protect(openvpn_io::detail::socket_type, std::string, bool) {
        return true;   // server endpoint is excluded from the tunnel routes
    }

  private:
    __weak SRPOpenVPNClient *owner_;
    openvpn::TransportClientFactory::Ptr tf_;
};

#pragma mark - ObjC implementation

@implementation SRPOpenVPNClient {
    dispatch_queue_t _worker;
    NSThread *_loopThread;
    SRPOvpnImpl *_impl;
    SRPTun *_tun;
    dispatch_semaphore_t _loopDone;

    SRPOVPNOutputCallback _outputCb;
    SRPOVPNNetworkSettingsCallback _settingsCb;
    SRPOVPNConnectedCallback _connectedCb;
    SRPOVPNDisconnectedCallback _disconnectedCb;
    SRPOVPNFailureCallback _failureCb;

    BOOL _closedManually;
    BOOL _sleepPaused;
    BOOL _up;
    BOOL _providerManaged;
    dispatch_semaphore_t _tunApplied;
    NEPacketTunnelNetworkSettings *_pendingSettings;
}

- (instancetype)init {
    self = [super init];
    if (self) {
        _worker = dispatch_queue_create("srp.openvpn", DISPATCH_QUEUE_SERIAL);
        _loopDone = dispatch_semaphore_create(0);
        _tunApplied = dispatch_semaphore_create(0);
        _autoReconnect = YES;
        _switchToWifi = YES;
        _onSleep = 2;
    }
    return self;
}

- (void)startWithOutputCallback:(SRPOVPNOutputCallback)output
         networkSettingsCallback:(SRPOVPNNetworkSettingsCallback)settings
               connectedCallback:(SRPOVPNConnectedCallback)connected
            disconnectedCallback:(SRPOVPNDisconnectedCallback)disconnected
                 failureCallback:(SRPOVPNFailureCallback)failure {
    _outputCb = output;
    _settingsCb = settings;
    _connectedCb = connected;
    _disconnectedCb = disconnected;
    _failureCb = failure;
    SSLogSetLevel((SSLogLevel)_logLevel);
    dispatch_async(_worker, ^{ [self startLocked]; });
}

- (void)startLocked {
    _closedManually = NO;
    _up = NO;

    if (_profileText.length == 0) {
        if (_failureCb) _failureCb(@"The OpenVPN profile is empty. Import an .ovpn file.");
        return;
    }

    _impl = new SRPOvpnImpl(self);
    openvpn::logging::srp_set_sink((__bridge void *)self, [](void *ctx, const char *s) {
        SRPOpenVPNClient *o = (__bridge SRPOpenVPNClient *)ctx;
        [o ovpnLogLine:@(s)];
    });

    openvpn::ClientAPI::Config conf;
    conf.content = _profileText.UTF8String;
    // User/password-only profiles carry no client certificate; without this
    // flag the core mistakes them for External PKI profiles and aborts with
    // "Missing External PKI alias".
    if ([_profileText rangeOfString:@"<cert>"].location == NSNotFound) {
        conf.disableClientCert = true;
    }
    openvpn::ClientAPI::EvalConfig eval = _impl->eval_config(conf);
    if (eval.error) {
        NSString *msg = @(eval.message.c_str());
        SSLogE(@"OpenVPN: eval_config failed: %@", msg);
        delete _impl;
        _impl = nullptr;
        if (_failureCb) _failureCb([NSString stringWithFormat:@"Invalid OpenVPN profile: %@", msg]);
        return;
    }

    // auth-user-pass profiles are not autologin: hand the credentials to the
    // core before connect (the profile itself carries no creds).
    if (!eval.autologin) {
        if (_username.length == 0) {
            SSLogE(@"OpenVPN: profile requires auth-user-pass but no username is set");
            delete _impl;
            _impl = nullptr;
            if (_failureCb) _failureCb(@"This profile requires a username and password (auth-user-pass). Enter them in the profile editor.");
            return;
        }
        openvpn::ClientAPI::ProvideCreds creds;
        creds.username = _username.UTF8String;
        creds.password = _password.length > 0 ? _password.UTF8String : "";
        openvpn::ClientAPI::Status pst = _impl->provide_creds(creds);
        if (pst.error) {
            NSString *msg = @(pst.message.c_str());
            SSLogE(@"OpenVPN: provide_creds failed: %@", msg);
            delete _impl;
            _impl = nullptr;
            if (_failureCb) _failureCb([NSString stringWithFormat:@"OpenVPN credentials rejected by the profile: %@", msg]);
            return;
        }
    }

    _loopThread = [[NSThread alloc] initWithBlock:^{
        openvpn::ClientAPI::Status st;
        try {
            st = self->_impl->connect();
        } catch (const std::exception &e) {
            st.error = true;
            st.message = std::string("exception: ") + e.what();
        } catch (...) {
            st.error = true;
            st.message = "unknown exception";
        }
        SSLogM(@"OpenVPN: connect() exited (error=%d %s)", st.error, st.message.c_str());
        dispatch_semaphore_signal(self->_loopDone);
        if (!self->_closedManually && !self->_sleepPaused) {
            NSString *reason = nil;
            if (st.error && st.message.length())
                reason = @(st.message.c_str());
            [self ovpnEventDisconnectedWithError:reason];
        }
    }];
    _loopThread.name = @"ovpn-main";
    [_loopThread start];
}

#pragma mark - C++ callbacks

/// Called by SRPTun on the core's io thread. Applies the pushed settings and
/// blocks until the provider confirms setTunnelNetworkSettings (or, without a
/// provider, immediately). The core requires this to finish before tun_start
/// returns.
- (void)ovpnApplyOptionsAndWait:(NSArray<NSArray<NSString *> *> *)options {
    NEPacketTunnelNetworkSettings *settings = [self buildSettingsFromOptions:options];
    _pendingSettings = settings;
    if (_settingsCb) _settingsCb(settings);
    if (_providerManaged) {
        dispatch_semaphore_wait(_tunApplied, dispatch_time(DISPATCH_TIME_NOW, 10 * NSEC_PER_SEC));
    }
}

/// Called by the packet-tunnel provider after setTunnelNetworkSettings has
/// completed successfully (also starts the provider's read loop).
- (void)tunApplied {
    dispatch_semaphore_signal(_tunApplied);
}

/// Set by the provider: when YES, ovpnApplyOptionsAndWait waits for
/// tunApplied; when NO (macOS harness), it proceeds immediately.
- (void)setProviderManaged:(BOOL)managed {
    _providerManaged = managed;
}

- (void)ovpnOutputPacket:(NSData *)packet family:(int)family {
    if (_outputCb) _outputCb(packet, family);
}

- (void)ovpnEventConnected {
    _up = YES;
    SSLogM(@"OpenVPN: session established");
    if (_connectedCb) _connectedCb();
}

- (void)ovpnEventDisconnectedWithError:(NSString *)message {
    dispatch_async(_worker, ^{
        if (self->_closedManually || self->_sleepPaused) return;
        self->_up = NO;
        if (message && self->_failureCb) {
            self->_failureCb(message);
        } else if (self->_disconnectedCb) {
            self->_disconnectedCb();
        }
    });
}

- (void)ovpnLogLine:(NSString *)line {
    NSLog(@"[ovpn-log] %@", line);
}

#pragma mark - settings

- (NEPacketTunnelNetworkSettings *)buildSettingsFromOptions:(NSArray<NSArray<NSString *> *> *)options {
    NSString *local4 = nil, *mask4 = @"255.255.255.0";
    NSString *local6 = nil;
    NSInteger prefix6 = 64;
    NSMutableArray<NSString *> *dns = [NSMutableArray array];
    NSMutableArray<NEIPv4Route *> *includes = [NSMutableArray array];
    BOOL fullTunnel = NO;
    NSInteger mtu = 1400;

    for (NSArray<NSString *> *parts in options) {
        NSString *name = parts.count > 0 ? parts[0] : @"";
        if ([name isEqualToString:@"ifconfig"] && parts.count >= 2) {
            local4 = parts[1];
            if (parts.count >= 3 && [parts[2] containsString:@"."])
                mask4 = parts[2];
        } else if ([name isEqualToString:@"ifconfig-ipv6"] && parts.count >= 2) {
            // "ifconfig-ipv6 addr/prefix gateway"
            NSArray *ap = [parts[1] componentsSeparatedByString:@"/"];
            local6 = ap.firstObject;
            if (ap.count > 1) prefix6 = [ap[1] integerValue];
        } else if ([name isEqualToString:@"dhcp-option"] && parts.count >= 3) {
            if ([parts[1] isEqualToString:@"DNS"]) [dns addObject:parts[2]];
        } else if ([name isEqualToString:@"redirect-gateway"]) {
            fullTunnel = YES;
        } else if ([name isEqualToString:@"route"] && parts.count >= 3) {
            NEIPv4Route *r = [[NEIPv4Route alloc] initWithDestinationAddress:parts[1]
                                                                subnetMask:parts[2]];
            if (r) [includes addObject:r];
        } else if ([name isEqualToString:@"tun-mtu"] && parts.count >= 2) {
            mtu = [parts[1] integerValue];
        }
    }
    if (dns.count == 0) [dns addObject:@"1.1.1.1"];

    // tunnelRemoteAddress: first remote in the profile, resolved
    NSString *remote = [self firstRemoteIP];
    NEPacketTunnelNetworkSettings *settings =
        [[NEPacketTunnelNetworkSettings alloc] initWithTunnelRemoteAddress:remote];
    settings.DNSSettings = [[NEDNSSettings alloc] initWithServers:dns];
    settings.MTU = @(mtu);

    if (local4) {
        NEIPv4Settings *v4 = [[NEIPv4Settings alloc] initWithAddresses:@[local4]
                                                           subnetMasks:@[mask4]];
        v4.includedRoutes = fullTunnel || includes.count == 0 ? @[[NEIPv4Route defaultRoute]] : includes;
        // The VPN server endpoint itself must stay on the physical path
        NSMutableArray<NEIPv4Route *> *excludes = [NSMutableArray array];
        struct in_addr sa;
        if (inet_pton(AF_INET, remote.UTF8String, &sa) == 1) {
            [excludes addObject:[[NEIPv4Route alloc] initWithDestinationAddress:remote
                                                                   subnetMask:@"255.255.255.255"]];
        }
        if (_stunnelEnabled && _stunnelHost.length > 0) {
            NSString *sip = [self resolveHost:_stunnelHost];
            if (sip && ![sip isEqualToString:remote]) {
                [excludes addObject:[[NEIPv4Route alloc] initWithDestinationAddress:sip
                                                                       subnetMask:@"255.255.255.255"]];
            }
        }
        if (excludes.count) v4.excludedRoutes = excludes;
        settings.IPv4Settings = v4;
    }
    if (local6) {
        NEIPv6Settings *v6 = [[NEIPv6Settings alloc] initWithAddresses:@[local6]
                                                  networkPrefixLengths:@[@(prefix6)]];
        v6.includedRoutes = @[[NEIPv6Route defaultRoute]];
        settings.IPv6Settings = v6;
    }
    return settings;
}

- (NSString *)firstRemoteIP {
    // find "remote host port" in the profile text; fall back to stunnel host
    for (NSString *line in [_profileText componentsSeparatedByCharactersInSet:[NSCharacterSet newlineCharacterSet]]) {
        NSString *t = [line stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
        if ([t hasPrefix:@"remote "]) {
            NSArray *parts = [t componentsSeparatedByCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
            if (parts.count >= 2) {
                NSString *host = parts[1];
                NSString *ip = [self resolveHost:host];
                if (ip) return ip;
            }
        }
    }
    if (_stunnelHost.length > 0) {
        NSString *ip = [self resolveHost:_stunnelHost];
        if (ip) return ip;
    }
    return @"1.0.0.1";
}

- (NSString *)resolveHost:(NSString *)host {
    struct in_addr a4;
    if (inet_pton(AF_INET, host.UTF8String, &a4) == 1) return host;
    struct hostent *he = gethostbyname(host.UTF8String);
    if (he && he->h_length == 4) {
        char buf[INET_ADDRSTRLEN];
        if (inet_ntop(AF_INET, he->h_addr_list[0], buf, sizeof(buf))) return @(buf);
    }
    return nil;
}

#pragma mark - packets / lifecycle

- (void)injectPacket:(NSData *)packet family:(int)family {
    if (packet.length < 20 || packet.length > 2048) return;
    if (_tun && _up) {
        _tun->injectFromPhone(packet);
    }
}

- (void)close {
    _closedManually = YES;
    [self teardownLocked];
}

- (void)closeAndWait {
    _closedManually = YES;
    [self teardownLocked];
}

- (void)teardownLocked {
    _up = NO;
    _tun = nullptr;
    if (_impl) {
        _impl->stop();
        dispatch_semaphore_wait(_loopDone, dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC));
        delete _impl;
        _impl = nullptr;
    }
    _loopThread = nil;
}

- (void)ovpnRegisterTun:(void *)tun {
    dispatch_async(_worker, ^{ self->_tun = (SRPTun *)tun; });
}

- (void)ovpnUnregisterTun:(void *)tun {
    dispatch_async(_worker, ^{
        if (self->_tun == (SRPTun *)tun) self->_tun = nullptr;
    });
}

- (void)pauseForSleep {
    if (_onSleep == 2) return;
    _sleepPaused = YES;
    [self teardownLocked];
}

- (void)wakeFromSleep {
    if (!_sleepPaused) return;
    _sleepPaused = NO;
    if (_onSleep == 1 || _autoReconnect) {
        SSLogM(@"OpenVPN: device wake — reconnecting");
        dispatch_async(_worker, ^{ [self startLocked]; });
    }
}

@end
