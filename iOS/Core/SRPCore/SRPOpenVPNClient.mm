//
//  SRPOpenVPNClient.mm
//  SRPCore
//
//  Objective-C++ session owner for OpenVPN 3 Core (ovpncli.hpp) with the external TUN and transport factories.
//  Packets cross to NEPacketTunnelFlow through callbacks; UDP and TCP use the core's own transports, stunnel mode an
//  SRP TLS transport (Network.framework, or SSFragTLSChannel when the handshake is split). The core reconnects by
//  itself after a dropped connection; this class decides from the OPTIONS section whether it may (Auto Reconnect,
//  Retry Times), moves the session to Wi-Fi (Switch to Wi-Fi When Available) and applies On Sleep.
//
//  Threads: the core runs on its own thread (connect() runs its io_context there); every decision is made on the
//  serial worker queue; packets from the phone are posted into the io_context. Every core callback that makes
//  Objective-C objects drains its own autorelease pool: the core thread lives as long as the session, so a pool
//  around connect() alone would keep every packet until the end (the extension's 50 MB limit came within seconds).
//

#import "SRPOpenVPNClient.h"

extern "C" {
#import "SSLog.h"
#import "SSNetOptions.h"
}

#import <NetworkExtension/NetworkExtension.h>
#import <Network/Network.h>
#import <Security/Security.h>
#import <arpa/inet.h>
#import <os/lock.h>
#import <atomic>
#import <memory>
#import <mutex>
#import <string>

#include "ovpncli.hpp"
#include <openvpn/tun/client/tunbase.hpp>
#include <openvpn/tun/extern/config.hpp>
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

class SRPTun;

@interface SRPOpenVPNClient (Cpp)
- (void)ovpnApplyOptionsAndWait:(NSArray<NSArray<NSString *> *> *)options serverAddress:(NSString *)serverAddress;
- (void)ovpnOutputPacket:(NSData *)packet family:(int)family;
- (void)ovpnEventNamed:(NSString *)name info:(NSString *)info error:(BOOL)error fatal:(BOOL)fatal generation:(NSUInteger)generation;
- (void)ovpnLogLine:(NSString *)line;
- (void)ovpnRegisterTun:(SRPTun *)tun io:(openvpn_io::io_context *)io;
- (void)ovpnUnregisterTun:(SRPTun *)tun;
- (void)ovpnDeliver:(NSData *)packet;
@end

#pragma mark - C++ TUN client

class SRPTun : public openvpn::TunClient {
  public:
    SRPTun(openvpn_io::io_context &io, openvpn::TunClientParent &parent, SRPOpenVPNClient *owner, openvpn::Frame::Ptr frame)
        : parent_(parent), owner_(owner), frame_(std::move(frame)) {
        [owner ovpnRegisterTun:this io:&io];
    }

    ~SRPTun() override {
        [owner_ ovpnUnregisterTun:this];
    }

    void tun_start(const openvpn::OptionList &opt, openvpn::TransportClient &transcli,
                   openvpn::CryptoDCSettings &) override {
        @autoreleasepool {
            NSMutableArray<NSArray<NSString *> *> *opts = [NSMutableArray array];
            for (const auto &o : opt) {
                NSMutableArray<NSString *> *parts = [NSMutableArray array];
                for (size_t i = 0; i < o.size(); i++)
                    [parts addObject:@(o.get(i, 256).c_str())];
                if (parts.count)
                    [opts addObject:parts];
            }
            openvpn::IP::Addr server = transcli.server_endpoint_addr();
            NSString *address = server.defined() ? @(server.to_string().c_str()) : nil;
            // The core requires the TUN to be up when tun_start returns: apply the settings and wait for the
            // provider to confirm them
            [owner_ ovpnApplyOptionsAndWait:opts serverAddress:address ?: @""];
        }
        parent_.tun_connected();
    }

    void stop() override { stopped_ = true; }
    void set_disconnect() override {}

    bool tun_send(openvpn::BufferAllocated &buf) override {
        const unsigned char *data = buf.data();
        size_t len = buf.size();
        if (stopped_ || !data || len < 1)
            return true;
        @autoreleasepool {
            int family = (data[0] >> 4) == 6 ? AF_INET6 : AF_INET;
            [owner_ ovpnOutputPacket:[NSData dataWithBytes:data length:len] family:family];
        }
        return true;
    }

    /// A packet from the phone, on the core thread. The buffer has the frame's room around the packet: encryption
    /// writes its header (and CBC's IV and HMAC) in front of it
    void deliver(NSData *packet) {
        if (stopped_)
            return;
        openvpn::BufferAllocated buf;
        frame_->prepare(openvpn::Frame::READ_TUN, buf);
        if (packet.length > buf.remaining(0))
            return;
        buf.write((const unsigned char *)packet.bytes, packet.length);
        parent_.tun_recv(buf);
    }

    std::string tun_name() const override { return "srp-tun"; }
    std::string vpn_ip4() const override { return ""; }
    std::string vpn_ip6() const override { return ""; }
    int vpn_mtu() const override { return 1500; }

  private:
    openvpn::TunClientParent &parent_;
    __weak SRPOpenVPNClient *owner_;
    openvpn::Frame::Ptr frame_;
    bool stopped_ = false;
};

class SRPTunFactory : public openvpn::TunClientFactory {
  public:
    SRPTunFactory(SRPOpenVPNClient *owner, openvpn::Frame::Ptr frame) : owner_(owner), frame_(std::move(frame)) {}

    openvpn::TunClient::Ptr new_tun_client_obj(openvpn_io::io_context &io_context,
                                               openvpn::TunClientParent &parent,
                                               openvpn::TransportClient *) override {
        SRPOpenVPNClient *owner = owner_;
        return openvpn::TunClient::Ptr(new SRPTun(io_context, parent, owner, frame_));
    }

    bool supports_epoch_data() override { return false; }

  private:
    __weak SRPOpenVPNClient *owner_;
    openvpn::Frame::Ptr frame_;
};

#pragma mark - stunnel TLS transport

struct SRPStunnelCfg {
    std::string host;
    int port = 443;
    std::string sni;
    std::string caPem;   // PEM of the outer CA (empty = system trust)
    int fragMode = 0;    // as the profile stores it: 0 off, 1 auto, 2 manual
    int fragFirst = 0;
    int fragFollowing = 0;
};

static NSArray *SRPCertificatesFromPEM(const std::string &pem) {
    NSMutableArray *certificates = [NSMutableArray array];
    NSString *text = @(pem.c_str());
    NSRegularExpression *re = [NSRegularExpression regularExpressionWithPattern:
        @"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----" options:NSRegularExpressionDotMatchesLineSeparators error:nil];
    for (NSTextCheckingResult *match in [re matchesInString:text options:0 range:NSMakeRange(0, text.length)]) {
        NSData *der = [[NSData alloc] initWithBase64EncodedString:[text substringWithRange:[match rangeAtIndex:1]]
                                                          options:NSDataBase64DecodingIgnoreUnknownCharacters];
        SecCertificateRef certificate = der ? SecCertificateCreateWithData(NULL, (__bridge CFDataRef)der) : NULL;
        if (certificate) [certificates addObject:(__bridge_transfer id)certificate];
    }
    return certificates;
}

/// What a Network.framework failure of the stunnel connection means for the user
static std::string SRPStunnelMessage(nw_error_t error, const SRPStunnelCfg &cfg) {
    std::string where = cfg.host + ":" + std::to_string(cfg.port);
    if (!error)
        return "The stunnel connection to " + where + " failed.";
    nw_error_domain_t domain = nw_error_get_error_domain(error);
    int code = nw_error_get_error_code(error);
    if (domain == nw_error_domain_posix) {
        switch (code) {
        case ECONNREFUSED: return "The stunnel server " + where + " refused the connection: nothing listens on that port.";
        case ETIMEDOUT: return "The stunnel server " + where + " did not answer.";
        case ENETUNREACH:
        case EHOSTUNREACH: return "The stunnel server " + where + " cannot be reached from this network.";
        case ECONNRESET: return "The stunnel server " + where + " reset the connection.";
        case ENETDOWN: return "There is no network connection.";
        default: return "The stunnel connection to " + where + " failed (" + std::string(strerror(code)) + ").";
        }
    }
    if (domain == nw_error_domain_dns)
        return "The stunnel server name " + cfg.host + " could not be resolved.";
    if (domain == nw_error_domain_tls) {
        switch (code) {
        case -9807: // errSSLXCertChainInvalid
        case -9808: // errSSLBadCert
        case -9812: // errSSLUnknownRootCert
        case -9813: // errSSLNoRootCert
        case -9814: // errSSLCertExpired
        case -9843: // errSSLHostNameMismatch
            return cfg.caPem.empty()
                ? "The stunnel server's certificate is not trusted for " + cfg.sni +
                      " (another name, expired, or not from a public certificate authority; import its CA Certificate if the server has its own CA)."
                : "The stunnel server's certificate is not signed by the imported CA Certificate, or not issued for " + cfg.sni + ".";
        default:
            return "The TLS handshake with the stunnel server " + where + " failed (" + std::to_string(code) +
                   "): it may require a TLS version or cipher this app does not offer.";
        }
    }
    return "The stunnel connection to " + where + " failed (" + std::to_string(code) + ").";
}

class SRPStunnelTransport;

/// What the stunnel transport shares with its Network.framework callbacks (transport queue). The core may destroy
/// the transport while callbacks are still queued: they hold this box, never the transport, and reach the transport
/// only on the core thread, after checking that it still exists.
struct SRPStunnelBox : std::enable_shared_from_this<SRPStunnelBox> {
    std::mutex lock;
    bool dead = false;                       // the transport is gone (set on the core thread)
    openvpn_io::io_context *io = nullptr;
    SRPStunnelTransport *owner = nullptr;    // read on the core thread only, while !dead
    std::atomic<long> pending{0};            // bytes handed to Network.framework and not yet sent
    NSMutableData *received = [NSMutableData new];   // transport queue only

    template <typename F>
    void post(F &&work) {
        std::lock_guard<std::mutex> guard(lock);
        if (dead || !io)
            return;
        std::shared_ptr<SRPStunnelBox> self = shared_from_this();
        openvpn_io::post(*io, [self, work = std::forward<F>(work)]() mutable {
            if (!self->dead && self->owner)
                work(self->owner);
        });
    }
};

/// OpenVPN TCP stream inside an outer TLS connection to a server-side stunnel listener. Keeps OpenVPN's TCP framing:
/// a two-byte big-endian packet length, then that many bytes.
class SRPStunnelTransport : public openvpn::TransportClient {
  public:
    SRPStunnelTransport(openvpn_io::io_context &io, openvpn::TransportClientParent *parent, const SRPStunnelCfg &cfg)
        : parent_(parent), cfg_(cfg), box_(std::make_shared<SRPStunnelBox>()) {
        box_->io = &io;
        box_->owner = this;
    }

    ~SRPStunnelTransport() override {
        {
            std::lock_guard<std::mutex> guard(box_->lock);
            box_->dead = true;
            box_->owner = nullptr;
        }
        cleanup();
    }

    void transport_start() override {
        queue_ = dispatch_queue_create("srp.stunnel", DISPATCH_QUEUE_SERIAL);
        std::string frag = cfg_.fragMode == 1 ? "auto" : cfg_.fragMode == 2
            ? "manual " + std::to_string(cfg_.fragFirst) + "/" + std::to_string(cfg_.fragFollowing) : "off";
        SSLogM(@"stunnel: connecting to %s:%d (SNI %s, CA %s, TLS fragmentation %s)", cfg_.host.c_str(), cfg_.port,
               cfg_.sni.c_str(), cfg_.caPem.empty() ? "system trust" : "imported", frag.c_str());
        parent_->transport_wait();
        if (SSFragModeFromProfileValue(cfg_.fragMode) != SSFragModeOff)
            startFragChannel();
        else
            startNetworkTLS();
    }

    void stop() override { cleanup(); }

    bool transport_send_const(const openvpn::Buffer &buf) override {
        if (stopped_ || !conn_)
            return false;
        size_t len = buf.size();
        if (len > 0xFFFF)
            return false;
        size_t total = len + 2;
        uint8_t *raw = (uint8_t *)malloc(total);
        raw[0] = (uint8_t)(len >> 8);
        raw[1] = (uint8_t)len;
        memcpy(raw + 2, buf.c_data(), len);
        if (channel_) {
            @autoreleasepool {
                [channel_ sendPlaintext:[NSData dataWithBytesNoCopy:raw length:total freeWhenDone:YES]];
            }
            return true;
        }
        dispatch_data_t data = dispatch_data_create(raw, total, queue_, DISPATCH_DATA_DESTRUCTOR_FREE);
        box_->pending += (long)total;
        std::shared_ptr<SRPStunnelBox> box = box_;
        nw_connection_send(conn_, data, NW_CONNECTION_DEFAULT_MESSAGE_CONTEXT, false, ^(nw_error_t) {
            if ((box->pending -= (long)total) <= 0)
                box->post([](SRPStunnelTransport *t) { t->parent_->transport_needs_send(); });
        });
        return true;
    }

    bool transport_send(openvpn::BufferAllocated &buf) override { return transport_send_const(buf); }
    bool transport_send_queue_empty() override { return box_->pending.load() <= 0; }
    bool transport_has_send_queue() override { return box_->pending.load() > 0; }
    void transport_stop_requeueing() override {}
    size_t transport_send_queue_size() override { return (size_t)std::max(0L, box_->pending.load()); }
    void reset_align_adjust(const size_t) override {}

    openvpn::IP::Addr server_endpoint_addr() const override {
        if (endpointIp_.empty())
            return openvpn::IP::Addr();
        try {
            return openvpn::IP::Addr::from_string(endpointIp_);
        } catch (...) {
            return openvpn::IP::Addr();
        }
    }

    unsigned short server_endpoint_port() const override { return (unsigned short)cfg_.port; }

    void server_endpoint_info(std::string &host, std::string &port, std::string &proto, std::string &ip_addr) const override {
        host = cfg_.host;
        port = std::to_string(cfg_.port);
        proto = "TCP-stunnel";
        ip_addr = endpointIp_;
    }

    openvpn::Protocol transport_protocol() const override { return openvpn::Protocol(openvpn::Protocol::TCPv4); }
    void transport_reparent(openvpn::TransportClientParent *parent) override { parent_ = parent; }

  private:
    nw_parameters_t tcpParameters(nw_parameters_configure_protocol_block_t tls) {
        return nw_parameters_create_secure_tcp(tls, ^(nw_protocol_options_t tcp) {
            nw_tcp_options_set_no_delay(tcp, true);   // OpenVPN's own TCP transport does the same
        });
    }

    nw_connection_t makeConnection(nw_parameters_t parameters) {
        nw_endpoint_t endpoint = nw_endpoint_create_host(cfg_.host.c_str(), std::to_string(cfg_.port).c_str());
        nw_connection_t conn = nw_connection_create(endpoint, parameters);
        nw_connection_set_queue(conn, queue_);
        return conn;
    }

    static std::string remoteAddress(nw_connection_t conn) {
        nw_path_t path = nw_connection_copy_current_path(conn);
        nw_endpoint_t remote = path ? nw_path_copy_effective_remote_endpoint(path) : nil;
        const struct sockaddr *sa = remote ? nw_endpoint_get_address(remote) : NULL;
        char text[INET6_ADDRSTRLEN] = "";
        if (sa && sa->sa_family == AF_INET)
            inet_ntop(AF_INET, &((const struct sockaddr_in *)sa)->sin_addr, text, sizeof(text));
        else if (sa && sa->sa_family == AF_INET6)
            inet_ntop(AF_INET6, &((const struct sockaddr_in6 *)sa)->sin6_addr, text, sizeof(text));
        return text;
    }

    /// Outer TLS by Network.framework: the system checks the certificate for the SNI name, against the system
    /// trust store or, when a CA Certificate is imported, against that CA alone
    void startNetworkTLS() {
        SRPStunnelCfg cfg = cfg_;
        dispatch_queue_t queue = queue_;
        NSArray *anchors = cfg.caPem.empty() ? nil : SRPCertificatesFromPEM(cfg.caPem);
        nw_parameters_t parameters = tcpParameters(^(nw_protocol_options_t options) {
            sec_protocol_options_t sec = nw_tls_copy_sec_protocol_options(options);
            sec_protocol_options_set_min_tls_protocol_version(sec, tls_protocol_version_TLSv12);
            sec_protocol_options_set_max_tls_protocol_version(sec, tls_protocol_version_TLSv13);
            sec_protocol_options_set_tls_server_name(sec, cfg.sni.c_str());
            if (anchors) {
                NSString *name = @(cfg.sni.c_str());
                sec_protocol_options_set_verify_block(sec, ^(sec_protocol_metadata_t, sec_trust_t trustRef,
                                                             sec_protocol_verify_complete_t complete) {
                    SecTrustRef trust = sec_trust_copy_ref(trustRef);
                    SecPolicyRef policy = SecPolicyCreateSSL(true, (__bridge CFStringRef)name);
                    SecTrustSetPolicies(trust, policy);
                    CFRelease(policy);
                    SecTrustSetAnchorCertificates(trust, (__bridge CFArrayRef)anchors);
                    SecTrustSetAnchorCertificatesOnly(trust, true);
                    if (SecTrustEvaluateAsyncWithError(trust, queue, ^(SecTrustRef evaluated, bool trusted, CFErrorRef error) {
                            if (!trusted)
                                SSLogE(@"stunnel: the server certificate is not trusted by the imported CA: %@",
                                       (__bridge NSError *)error);
                            CFRelease(evaluated);
                            complete(trusted);
                        }) != errSecSuccess) {
                        CFRelease(trust);
                        complete(false);
                    }
                }, queue);
            }
        });
        conn_ = makeConnection(parameters);
        nw_connection_t conn = conn_;
        std::shared_ptr<SRPStunnelBox> box = box_;
        nw_connection_set_state_changed_handler(conn, ^(nw_connection_state_t state, nw_error_t error) {
            if (state == nw_connection_state_ready) {
                std::string address = remoteAddress(conn);
                box->post([address](SRPStunnelTransport *t) { t->connected(address); });
                receive(box, conn);
            } else if (state == nw_connection_state_failed || state == nw_connection_state_waiting) {
                // waiting: Network.framework would retry on its own (refused, no route); the core decides instead
                std::string message = SRPStunnelMessage(error, cfg);
                box->post([message](SRPStunnelTransport *t) { t->fail(message); });
            }
        });
        nw_connection_start(conn);
    }

    /// Outer TLS by SSFragTLSChannel (OpenSSL over plain TCP) so that the ClientHello can be split
    void startFragChannel() {
        SSFragTLSConfig *config = [SSFragTLSConfig new];
        config.mode = SSFragModeFromProfileValue(cfg_.fragMode);
        if (config.mode == SSFragModeManual) {
            config.firstChunk = cfg_.fragFirst > 0 ? (NSUInteger)cfg_.fragFirst : 32;
            config.followingChunk = cfg_.fragFollowing > 0 ? (NSUInteger)cfg_.fragFollowing : 256;
        }
        NSString *invalid = [config validate];
        if (invalid) {
            fail("TLS Fragmentation: " + std::string(invalid.UTF8String));
            return;
        }
        SRPStunnelCfg cfg = cfg_;
        dispatch_queue_t queue = queue_;
        conn_ = makeConnection(tcpParameters(NW_PARAMETERS_DISABLE_PROTOCOL));
        nw_connection_t conn = conn_;
        std::shared_ptr<SRPStunnelBox> box = box_;
        nw_connection_set_state_changed_handler(conn, ^(nw_connection_state_t state, nw_error_t error) {
            if (state == nw_connection_state_ready) {
                std::string address = remoteAddress(conn);
                SSFragTLSChannel *channel = [[SSFragTLSChannel alloc] initWithConnection:conn
                                                                                    sni:@(cfg.sni.c_str())
                                                                          allowInsecure:NO
                                                                   disableLegacyVersion:YES
                                                                            pinnedCAPEM:cfg.caPem.empty() ? nil : @(cfg.caPem.c_str())
                                                                                 config:config
                                                                                  queue:queue];
                channel.onPlaintext = ^(NSData *data) {
                    [box->received appendData:data];
                    drainFrames(box);
                };
                channel.onClose = ^(NSError *err) {
                    std::string message = err ? "The stunnel TLS connection failed: " + std::string(err.localizedDescription.UTF8String)
                                              : "The stunnel server closed the connection.";
                    box->post([message](SRPStunnelTransport *t) { t->fail(message); });
                };
                box->post([channel](SRPStunnelTransport *t) { t->channel_ = channel; });
                [channel startHandshake:^(NSError *err) {
                    if (err) {
                        std::string message = "The TLS handshake with the stunnel server failed: " +
                                              std::string(err.localizedDescription.UTF8String);
                        box->post([message](SRPStunnelTransport *t) { t->fail(message); });
                        return;
                    }
                    box->post([address](SRPStunnelTransport *t) { t->connected(address); });
                }];
            } else if (state == nw_connection_state_failed || state == nw_connection_state_waiting) {
                std::string message = SRPStunnelMessage(error, cfg);
                box->post([message](SRPStunnelTransport *t) { t->fail(message); });
            }
        });
        nw_connection_start(conn);
    }

    static void receive(std::shared_ptr<SRPStunnelBox> box, nw_connection_t conn) {
        nw_connection_receive(conn, 1, 256 * 1024, ^(dispatch_data_t content, nw_content_context_t, bool complete, nw_error_t error) {
            if (content && dispatch_data_get_size(content) > 0) {
                [box->received appendData:(NSData *)content];
                drainFrames(box);
            }
            if (error) {
                box->post([](SRPStunnelTransport *t) { t->fail("The stunnel connection broke."); });
                return;
            }
            if (complete) {
                box->post([](SRPStunnelTransport *t) { t->fail("The stunnel server closed the connection."); });
                return;
            }
            receive(box, conn);
        });
    }

    // OpenVPN TCP framing: 2-byte big-endian length + payload; transport queue
    static void drainFrames(std::shared_ptr<SRPStunnelBox> box) {
        @autoreleasepool {
            NSMutableData *received = box->received;
            const uint8_t *bytes = (const uint8_t *)received.bytes;
            size_t total = received.length, offset = 0;
            NSMutableArray<NSData *> *frames = [NSMutableArray array];
            while (total - offset >= 2) {
                size_t length = ((size_t)bytes[offset] << 8) | bytes[offset + 1];
                if (total - offset < 2 + length)
                    break;
                [frames addObject:[NSData dataWithBytes:bytes + offset + 2 length:length]];
                offset += 2 + length;
            }
            if (offset > 0)
                [received replaceBytesInRange:NSMakeRange(0, offset) withBytes:NULL length:0];
            if (frames.count > 0) {
                box->post([frames](SRPStunnelTransport *t) {
                    @autoreleasepool {
                        for (NSData *frame in frames) {
                            if (t->stopped_ || !t->parent_)
                                return;
                            openvpn::BufferAllocated buf((const unsigned char *)frame.bytes, frame.length, 0);
                            t->parent_->transport_recv(buf);
                        }
                    }
                });
            }
        }
    }

    // core thread
    void connected(const std::string &address) {
        if (stopped_)
            return;
        endpointIp_ = address;
        SSLogM(@"stunnel: TLS ready to %s:%d (%s)", cfg_.host.c_str(), cfg_.port, address.c_str());
        parent_->transport_connecting();
    }

    // core thread
    void fail(const std::string &message) {
        if (stopped_)
            return;
        SSLogE(@"stunnel: %s", message.c_str());
        cleanup();
        if (parent_)
            parent_->transport_error(openvpn::Error::TRANSPORT_ERROR, "stunnel: " + message);
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

    openvpn::TransportClientParent *parent_;
    SRPStunnelCfg cfg_;
    std::shared_ptr<SRPStunnelBox> box_;
    nw_connection_t conn_ = nil;
    SSFragTLSChannel *channel_ = nil;
    dispatch_queue_t queue_ = nil;
    bool stopped_ = false;
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
    SRPOvpnImpl(SRPOpenVPNClient *owner, NSUInteger generation, bool stunnel, const SRPStunnelCfg &cfg)
        : owner_(owner), generation_(generation), stunnel_(stunnel), cfg_(cfg) {}

    // ExternalTun::Factory — fresh object each call; the core adopts it.
    openvpn::TunClientFactory *new_tun_factory(const openvpn::ExternalTun::Config &conf, const openvpn::OptionList &) override {
        SRPOpenVPNClient *owner = owner_;
        return new SRPTunFactory(owner, conf.frame);
    }

    // ExternalTransport::Factory — UDP/TCP reuse the core's own transport configs; stunnel mode (always TCP, the
    // start sets protoOverride) the SRP TLS transport.
    openvpn::TransportClientFactory *new_transport_factory(const openvpn::ExternalTransport::Config &conf) override {
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
        if (stunnel_) {
            tf_ = new SRPStunnelFactory(cfg_);
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

    void log(const openvpn::ClientAPI::LogInfo &info) override {
        @autoreleasepool {
            [owner_ ovpnLogLine:@(info.text.c_str())];
        }
    }

    void event(const openvpn::ClientAPI::Event &ev) override {
        @autoreleasepool {
            [owner_ ovpnEventNamed:@(ev.name.c_str()) info:@(ev.info.c_str()) error:ev.error fatal:ev.fatal generation:generation_];
        }
    }

    void acc_event(const openvpn::ClientAPI::AppCustomControlMessageEvent &) override {}
    bool pause_on_connection_timeout() override { return false; }
    void external_pki_cert_request(openvpn::ClientAPI::ExternalPKICertRequest &) override {}
    void external_pki_sign_request(openvpn::ClientAPI::ExternalPKISignRequest &) override {}

  private:
    __weak SRPOpenVPNClient *owner_;
    NSUInteger generation_;
    bool stunnel_;
    SRPStunnelCfg cfg_;
    openvpn::TransportClientFactory::Ptr tf_;
};

#pragma mark - ObjC implementation

@implementation SRPOpenVPNClient {
    dispatch_queue_t _worker;
    NSThread *_loopThread;
    SRPOvpnImpl *_impl;
    dispatch_semaphore_t _loopDone;    // the running core's: signalled when its connect() returns
    NSUInteger _generation;            // bumped by every core start; an older core's callbacks change nothing

    SRPOVPNOutputCallback _outputCb;
    SRPOVPNNetworkSettingsCallback _settingsCb;
    SRPOVPNConnectedCallback _connectedCb;
    SRPOVPNDisconnectedCallback _disconnectedCb;
    SRPOVPNFailureCallback _failureCb;

    // worker queue
    BOOL _closedManually;
    BOOL _sleepPaused;
    BOOL _failed;
    BOOL _up;
    BOOL _everEstablished;
    BOOL _pathSwitching;      // a reconnect this class asked for (Wi-Fi appeared), not a lost connection
    NSInteger _attempts;      // attempts since the last connection (or since the start)
    NSInteger _remoteCount;
    NSString *_lastReason;    // what the core last reported; it ends the session when no attempt is left
    nw_path_monitor_t _pathMonitor;
    BOOL _lastPathHadWifi;

    // shared with the core thread and the provider
    os_unfair_lock _ioLock;
    openvpn_io::io_context *_io;      // the running core's, once it made a TUN (guarded by _ioLock)
    dispatch_semaphore_t _tunApplied; // the current TUN's (guarded by _ioLock)
    SRPTun *_tun;                     // core thread only
    std::atomic<bool> _packetsFlow;   // a TUN is up and its settings are applied
    BOOL _providerManaged;
}

- (instancetype)init {
    self = [super init];
    if (self) {
        _worker = dispatch_queue_create("srp.openvpn", DISPATCH_QUEUE_SERIAL);
        _ioLock = OS_UNFAIR_LOCK_INIT;
        _packetsFlow = false;
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
    openvpn::logging::srp_set_sink((__bridge void *)self, [](void *ctx, const char *line) {
        @autoreleasepool {
            [(__bridge SRPOpenVPNClient *)ctx ovpnLogLine:@(line)];
        }
    });
    dispatch_async(_worker, ^{
        [self startLocked];
        [self startPathMonitor];
    });
}

#pragma mark - profile

static NSArray<NSArray<NSString *> *> *SRPProfileDirectives(NSString *profile, NSString *name) {
    NSMutableArray *found = [NSMutableArray array];
    for (NSString *line in [profile componentsSeparatedByCharactersInSet:NSCharacterSet.newlineCharacterSet]) {
        NSArray *words = [[line stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceCharacterSet]
                          componentsSeparatedByCharactersInSet:NSCharacterSet.whitespaceCharacterSet];
        words = [words filteredArrayUsingPredicate:[NSPredicate predicateWithFormat:@"length > 0"]];
        if (words.count > 0 && [words[0] isEqualToString:name]) [found addObject:words];
    }
    return found;
}

+ (NSArray<NSString *> *)firstRemoteOfProfile:(NSString *)profile {
    NSArray *remote = SRPProfileDirectives(profile, @"remote").firstObject;
    NSArray *portLine = SRPProfileDirectives(profile, @"port").firstObject;
    NSArray *protoLine = SRPProfileDirectives(profile, @"proto").firstObject;
    NSString *host = remote.count > 1 ? remote[1] : @"";
    NSString *port = remote.count > 2 ? remote[2] : (portLine.count > 1 ? portLine[1] : @"1194");
    NSString *proto = remote.count > 3 ? remote[3] : (protoLine.count > 1 ? protoLine[1] : @"udp");
    return @[host, port, proto];
}

+ (NSInteger)remoteCountOfProfile:(NSString *)profile {
    return MAX((NSInteger)1, (NSInteger)SRPProfileDirectives(profile, @"remote").count);
}

#pragma mark - session

/// Starts a core (the first connection, or after a wake); every decision about it is made on the worker queue
- (void)startLocked {
    if (_closedManually || _failed) return;
    [self stopCoreLocked];
    NSUInteger generation = ++_generation;
    if (_profileText.length == 0) {
        [self failWithReason:@"The OpenVPN profile is empty. Import an .ovpn file."];
        return;
    }
    if ([_profileText containsString:@"<secret>"] || SRPProfileDirectives(_profileText, @"secret").count > 0) {
        [self failWithReason:@"This profile uses an OpenVPN static key (secret), which OpenVPN 3 does not support. Ask for a profile with certificates (TLS mode)."];
        return;
    }
    if ([_profileText containsString:@"ENCRYPTED PRIVATE KEY"] || [_profileText containsString:@"Proc-Type: 4,ENCRYPTED"]) {
        [self failWithReason:@"The profile's private key is protected with a passphrase, which this app cannot enter. Export the key without a passphrase (for example: openssl pkey -in client.key -out client-plain.key) and import the profile again."];
        return;
    }

    openvpn::ClientAPI::Config conf;
    // stunnel carries TCP: the core's protocol override only picks TCP remotes, so a UDP profile is turned into TCP itself
    conf.content = (_stunnelEnabled ? [SRPOpenVPNClient profileText:_profileText withProtocol:@"tcp"] : _profileText).UTF8String;
    // AES-CBC with HMAC as well as the AEAD ciphers: older servers offer only CBC (the legacy BF-CBC and DES stay off)
    conf.enableNonPreferredDCAlgorithms = true;
    // A profile without a client certificate (auth-user-pass only) would otherwise read as External PKI and stop
    // with "Missing External PKI alias"
    if (![_profileText containsString:@"<cert>"] && SRPProfileDirectives(_profileText, @"cert").count == 0) {
        conf.disableClientCert = true;
    }
    NSArray<NSString *> *remote = [SRPOpenVPNClient firstRemoteOfProfile:_profileText];
    NSString *server = [_server stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceCharacterSet];
    NSString *port = [_port stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceCharacterSet];
    // The Server and Port fields start as the first remote line; changed, they replace the profile's remotes
    if (server.length > 0 && [server caseInsensitiveCompare:remote[0]] != NSOrderedSame) conf.serverOverride = server.UTF8String;
    if (port.integerValue > 0 && port.integerValue != remote[1].integerValue) conf.portOverride = port.UTF8String;
    _remoteCount = conf.serverOverride.empty() && conf.portOverride.empty() ? [SRPOpenVPNClient remoteCountOfProfile:_profileText] : 1;

    SRPStunnelCfg cfg;
    if (_stunnelEnabled) {
        NSString *host = _stunnelHost.length > 0 ? _stunnelHost : (server.length > 0 ? server : remote[0]);
        if (host.length == 0) {
            [self failWithReason:@"stunnel is on, but neither stunnel Host nor Server is set."];
            return;
        }
        cfg.host = host.UTF8String;
        cfg.port = _stunnelPort > 0 ? _stunnelPort : 443;
        cfg.sni = _stunnelSNI.length > 0 ? _stunnelSNI.UTF8String : cfg.host;
        cfg.caPem = _outerCAPEM.length > 0 ? _outerCAPEM.UTF8String : "";
        cfg.fragMode = (int)_tlsFragMode;
        cfg.fragFirst = (int)_tlsFragFirst;
        cfg.fragFollowing = (int)_tlsFragFollowing;
        conf.protoOverride = "tcp";
        _remoteCount = 1;
    }

    SRPOvpnImpl *impl = new SRPOvpnImpl(self, generation, _stunnelEnabled, cfg);
    openvpn::ClientAPI::EvalConfig eval = impl->eval_config(conf);
    if (eval.error) {
        delete impl;
        [self failWithReason:[SRPOpenVPNClient messageForInvalidProfile:@(eval.message.c_str()) profile:_profileText]];
        return;
    }
    if (!eval.autologin) {
        if (_username.length == 0) {
            delete impl;
            [self failWithReason:@"This profile requires a username and password (auth-user-pass). Enter them in the profile editor."];
            return;
        }
        openvpn::ClientAPI::ProvideCreds creds;
        creds.username = _username.UTF8String;
        creds.password = _password.length > 0 ? _password.UTF8String : "";
        openvpn::ClientAPI::Status status = impl->provide_creds(creds);
        if (status.error) {
            delete impl;
            [self failWithReason:[NSString stringWithFormat:@"OpenVPN credentials rejected by the profile: %s", status.message.c_str()]];
            return;
        }
    }

    NSString *via = _stunnelEnabled
        ? [NSString stringWithFormat:@"TCP inside stunnel TLS to %s:%d", cfg.host.c_str(), cfg.port]
        : (eval.remoteProto.length() ? @(eval.remoteProto.c_str()) : @"UDP");
    SSLogM(@"OpenVPN: connecting to %s:%s over %@ (%ld remote%@, auto reconnect %@, retry times %ld)",
           conf.serverOverride.empty() ? eval.remoteHost.c_str() : conf.serverOverride.c_str(),
           conf.portOverride.empty() ? eval.remotePort.c_str() : conf.portOverride.c_str(), via,
           (long)_remoteCount, _remoteCount == 1 ? @"" : @"s", _autoReconnect ? @"on" : @"off", (long)_retryTimes);

    _impl = impl;
    dispatch_semaphore_t done = dispatch_semaphore_create(0);
    _loopDone = done;
    __weak SRPOpenVPNClient *weakSelf = self;
    _loopThread = [[NSThread alloc] initWithBlock:^{
        openvpn::ClientAPI::Status st;
        try {
            st = impl->connect();
        } catch (const std::exception &e) {
            st.error = true;
            st.message = std::string("exception: ") + e.what();
        } catch (...) {
            st.error = true;
            st.message = "unknown exception";
        }
        NSString *message = st.error && st.message.length() ? @(st.message.c_str()) : nil;
        dispatch_semaphore_signal(done);
        [weakSelf coreExited:generation message:message];
    }];
    _loopThread.name = @"ovpn-core";
    _loopThread.stackSize = 1 << 20;
    [_loopThread start];
}

/// Stops the running core and waits for its thread; worker queue
- (void)stopCoreLocked {
    os_unfair_lock_lock(&_ioLock);
    _io = nullptr;
    dispatch_semaphore_t applied = _tunApplied;
    _tunApplied = nil;
    os_unfair_lock_unlock(&_ioLock);
    _packetsFlow = false;
    _up = NO;
    if (!_impl) return;
    if (applied) dispatch_semaphore_signal(applied);   // a tun_start waiting for the settings lets go
    BOOL exited = NO;
    for (int i = 0; i < 150 && !exited; i++) {
        _impl->stop();   // repeated: a stop before connect() is ready does nothing
        exited = dispatch_semaphore_wait(_loopDone, dispatch_time(DISPATCH_TIME_NOW, 100 * NSEC_PER_MSEC)) == 0;
    }
    if (exited) {
        delete _impl;
    } else {
        SSLogE(@"OpenVPN: the core thread did not stop within 15 seconds; leaving it");
    }
    _impl = nullptr;
    _loopThread = nil;
    _loopDone = nil;
}

/// connect() returned: the core stopped by itself (a fatal error) or because it was asked to; core thread
- (void)coreExited:(NSUInteger)generation message:(NSString *)message {
    dispatch_async(_worker, ^{
        if (generation != self->_generation) return;
        os_unfair_lock_lock(&self->_ioLock);
        self->_io = nullptr;
        os_unfair_lock_unlock(&self->_ioLock);
        self->_packetsFlow = false;
        self->_up = NO;
        if (self->_closedManually || self->_sleepPaused || self->_failed) return;
        [self failWithReason:self->_lastReason ?: message ?: @"The OpenVPN session ended."];
    });
}

- (void)failWithReason:(NSString *)reason {
    if (_failed || _closedManually) return;
    _failed = YES;
    SSLogM(@"OpenVPN: closing with reason: %@", reason);
    [self stopPathMonitor];
    // The core thread may be the caller's: stop it asynchronously, closeAndWait waits for it
    if (_impl) _impl->stop();
    os_unfair_lock_lock(&_ioLock);
    _io = nullptr;
    os_unfair_lock_unlock(&_ioLock);
    _packetsFlow = false;
    if (_failureCb) _failureCb(reason);
}

#pragma mark - events

- (void)ovpnEventNamed:(NSString *)name info:(NSString *)info error:(BOOL)error fatal:(BOOL)fatal generation:(NSUInteger)generation {
    if (error) {
        SSLogE(@"OpenVPN event %@%@%@", name, info.length ? @": " : @"", info);
    } else {
        SSLogI(@"OpenVPN event %@%@%@", name, info.length ? @": " : @"", info);
    }
    dispatch_async(_worker, ^{
        [self handleEventNamed:name info:info error:error fatal:fatal generation:generation];
    });
}

- (void)handleEventNamed:(NSString *)name info:(NSString *)info error:(BOOL)error fatal:(BOOL)fatal generation:(NSUInteger)generation {
    if (generation != _generation || _closedManually || _failed || _sleepPaused) return;
    if ([name isEqualToString:@"CONNECTED"]) {
        _up = YES;
        _everEstablished = YES;
        _attempts = 0;
        _pathSwitching = NO;
        _lastReason = nil;
        SSLogM(@"OpenVPN: session established%@%@", info.length ? @": " : @"", info);
        if (_connectedCb) _connectedCb();
        return;
    }
    if ([name isEqualToString:@"RECONNECTING"]) {
        [self coreReconnecting];
        return;
    }
    if (fatal) {
        [self failWithReason:[SRPOpenVPNClient messageForEvent:name info:info]];
        return;
    }
    if (error) {
        // TRANSPORT_ERROR, TUN_ERROR, CLIENT_RESTART: the core tries again in 5 seconds unless no attempt is left
        _lastReason = [SRPOpenVPNClient messageForEvent:name info:info];
        [self connectionLost];
        if (!_pathSwitching && ![self mayTryAgain]) [self failWithReason:[self finalMessage]];
    }
}

- (void)coreReconnecting {
    if (_pathSwitching) {
        _pathSwitching = NO;
        SSLogM(@"OpenVPN: moving the connection to the current network path");
        return;
    }
    [self connectionLost];
    if (_lastReason == nil) {
        _lastReason = _everEstablished ? @"The server stopped answering." : @"The server did not answer.";
    }
    if (![self mayTryAgain]) {
        [self failWithReason:[self finalMessage]];
        return;
    }
    _attempts++;
    SSLogM(@"OpenVPN: %@ Reconnecting (attempt %ld%@).", _lastReason, (long)_attempts,
           _retryTimes > 0 ? [NSString stringWithFormat:@" of %ld", (long)_retryTimes] : @"");
}

- (void)connectionLost {
    if (!_up) return;
    _up = NO;
    if (_disconnectedCb) _disconnectedCb();
}

/// Whether the core may make another attempt now that one failed. Before the tunnel was ever up, an attempt goes to
/// every remote line of the profile once, again only for an explicit Retry Times budget (as SSTP, SoftEther, SSL
/// VPN and SSH); after it was up, Auto Reconnect and Retry Times decide.
- (BOOL)mayTryAgain {
    if (_everEstablished) {
        return _autoReconnect && SSReconnectAttemptAllowed(_attempts, _retryTimes);
    }
    NSInteger budget = _remoteCount * (_autoReconnect ? 1 + MAX((NSInteger)0, _retryTimes) : 1);
    return _attempts + 1 < budget;
}

- (NSString *)finalMessage {
    NSString *reason = _lastReason ?: @"The connection to the server was lost.";
    NSString *bare = [reason hasSuffix:@"."] ? [reason substringToIndex:reason.length - 1] : reason;
    if (_everEstablished && !_autoReconnect) return [NSString stringWithFormat:@"%@ (auto reconnect is off).", bare];
    if (_retryTimes > 0 && _autoReconnect) {
        return [NSString stringWithFormat:@"Could not %@ after %ld attempts. (%@)", _everEstablished ? @"reconnect" : @"connect",
                (long)_retryTimes, bare];
    }
    return reason;
}

/// A log line that explains a failed attempt, as the user's message; nil for any other line
+ (NSString *)messageForLogLine:(NSString *)line {
    if ([line containsString:@"KEEPALIVE_TIMEOUT"]) return @"The server stopped answering (keepalive timeout).";
    if ([line containsString:@"Server poll timeout"]) return @"The server did not answer.";
    NSRange transport = [line rangeOfString:@"Transport Error: "];
    if (transport.location != NSNotFound) {
        return [SRPOpenVPNClient messageForTransportError:[line substringFromIndex:NSMaxRange(transport)]];
    }
    NSRange exception = [line rangeOfString:@"Client exception in "];
    if (exception.location != NSNotFound) {
        NSString *detail = [line substringFromIndex:NSMaxRange(exception)];
        NSRange colon = [detail rangeOfString:@": "];
        if (colon.location != NSNotFound) detail = [detail substringFromIndex:NSMaxRange(colon)];
        NSRegularExpression *compressor = [NSRegularExpression regularExpressionWithPattern:@"pushed compressor '([^']*)'" options:0 error:nil];
        NSTextCheckingResult *match = [compressor firstMatchInString:detail options:0 range:NSMakeRange(0, detail.length)];
        if (match) {
            return [NSString stringWithFormat:@"The server pushes compression (%@), which this app does not take: compression inside a VPN can leak data (VORACLE). Turn it off on the server (remove compress/comp-lzo from its configuration).",
                    [detail substringWithRange:[match rangeAtIndex:1]]];
        }
        if ([detail containsString:@"option_error"] || [detail containsString:@"ERR_PROFILE_OPTION"]) {
            return [NSString stringWithFormat:@"The server pushed a setting this app cannot use (%@).", detail];
        }
        return [NSString stringWithFormat:@"The OpenVPN session failed (%@).", detail];
    }
    return nil;
}

/// The core's transport errors: DNS, refused or unreachable connections, closed streams, the stunnel layer's own words
+ (NSString *)messageForTransportError:(NSString *)text {
    if ([text hasPrefix:@"stunnel: "]) return [text substringFromIndex:9];
    if ([text containsString:@"DNS resolve error"] || [text containsString:@"Host not found"] || [text containsString:@"HOST_NOT_FOUND"] ||
        [text containsString:@"nodename nor servname"]) {
        NSRegularExpression *host = [NSRegularExpression regularExpressionWithPattern:@"on '([^']*)'" options:0 error:nil];
        NSTextCheckingResult *match = [host firstMatchInString:text options:0 range:NSMakeRange(0, text.length)];
        return match ? [NSString stringWithFormat:@"The server name %@ could not be resolved.", [text substringWithRange:[match rangeAtIndex:1]]]
                     : @"The server name could not be resolved.";
    }
    if ([text containsString:@"refused"] || [text containsString:@"ECONNREFUSED"] || [text containsString:@"NETWORK_RECV_ERROR"]) {
        return @"The server refused the connection: no OpenVPN server answers on that port.";
    }
    if ([text containsString:@"timed out"]) return @"The server did not answer.";
    if ([text containsString:@"unreachable"] || [text containsString:@"No route"]) return @"The server cannot be reached from this network.";
    if ([text containsString:@"NETWORK_EOF_ERROR"] || [text containsString:@"End of file"] || [text containsString:@"reset by peer"]) {
        return @"The server closed the connection.";
    }
    return [NSString stringWithFormat:@"The connection to the server failed (%@).", text];
}

/// A profile turned to one transport protocol: its proto lines and the protocol word of its remote lines
+ (NSString *)profileText:(NSString *)profile withProtocol:(NSString *)protocol {
    NSMutableArray<NSString *> *lines = [NSMutableArray array];
    BOOL sawProto = NO;
    for (NSString *line in [profile componentsSeparatedByString:@"\n"]) {
        NSString *trimmed = [line stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
        NSArray *words = [[trimmed componentsSeparatedByCharactersInSet:NSCharacterSet.whitespaceCharacterSet]
                          filteredArrayUsingPredicate:[NSPredicate predicateWithFormat:@"length > 0"]];
        if (words.count >= 1 && [words[0] isEqualToString:@"proto"]) {
            sawProto = YES;
            [lines addObject:[@"proto " stringByAppendingString:protocol]];
        } else if (words.count >= 4 && [words[0] isEqualToString:@"remote"]) {
            [lines addObject:[NSString stringWithFormat:@"remote %@ %@ %@", words[1], words[2], protocol]];
        } else {
            [lines addObject:line];
        }
    }
    NSString *text = [lines componentsJoinedByString:@"\n"];
    return sawProto ? text : [NSString stringWithFormat:@"proto %@\n%@", protocol, text];
}

+ (NSString *)messageForInvalidProfile:(NSString *)message profile:(NSString *)profile {
    NSString *lower = message.lowercaseString;
    if (SRPProfileDirectives(profile, @"secret").count > 0 || [profile containsString:@"<secret>"] || [lower containsString:@"static key"]) {
        return @"This profile uses an OpenVPN static key (secret), which OpenVPN 3 does not support. Ask for a profile with certificates (TLS mode).";
    }
    return [NSString stringWithFormat:@"Invalid OpenVPN profile: %@", message];
}

+ (NSString *)messageForEvent:(NSString *)name info:(NSString *)info {
    NSString *detail = info.length > 0 ? [NSString stringWithFormat:@" (%@)", info] : @"";
    if ([name isEqualToString:@"AUTH_FAILED"]) {
        if ([info.lowercaseString containsString:@"cipher"]) {
            return [NSString stringWithFormat:@"The server and this app have no data-channel cipher in common (%@).", info];
        }
        return [NSString stringWithFormat:@"The server refused the login%@. Check the username and password.", detail];
    }
    if ([name isEqualToString:@"CERT_VERIFY_FAIL"]) {
        return [NSString stringWithFormat:@"The server's certificate could not be verified with the profile's CA%@.", detail];
    }
    if ([name hasPrefix:@"TLS_ALERT_"] || [name isEqualToString:@"TLS_SIGALG_DISALLOWED_OR_UNSUPPORTED"]) {
        NSString *what = [[name substringFromIndex:[name hasPrefix:@"TLS_ALERT_"] ? 10 : 0].lowercaseString
                          stringByReplacingOccurrencesOfString:@"_" withString:@" "];
        return [NSString stringWithFormat:@"The server refused the TLS handshake (%@). Check the profile's client certificate and key.", what];
    }
    if ([name isEqualToString:@"TLS_VERSION_MIN"]) {
        return @"The server does not offer the TLS version the profile asks for (tls-version-min).";
    }
    if ([name isEqualToString:@"CLIENT_HALT"]) {
        return [NSString stringWithFormat:@"The server ended the session%@.", detail];
    }
    if ([name isEqualToString:@"CLIENT_RESTART"]) {
        return @"The server restarted the session.";
    }
    if ([name isEqualToString:@"CONNECTION_TIMEOUT"]) {
        return @"Connection timed out. The server did not respond.";
    }
    if ([name isEqualToString:@"INACTIVE_TIMEOUT"]) {
        return @"The session ended after the profile's inactivity timeout.";
    }
    if ([name isEqualToString:@"COMPRESS_ERROR"]) {
        return [NSString stringWithFormat:@"The server uses compression that this app does not support%@.", detail];
    }
    if ([name isEqualToString:@"DYNAMIC_CHALLENGE"] || [name isEqualToString:@"NEED_CREDS"]) {
        return @"The server asked for another login step (a challenge or one-time code), which this app does not support.";
    }
    if ([name isEqualToString:@"SESSION_EXPIRED"]) {
        return @"The server ended the session: the login expired.";
    }
    if ([name isEqualToString:@"EPKI_ERROR"] || [name isEqualToString:@"EPKI_INVALID_ALIAS"]) {
        return [NSString stringWithFormat:@"The profile's client certificate or key could not be used%@.", detail];
    }
    if ([name isEqualToString:@"TRANSPORT_ERROR"]) {
        return [SRPOpenVPNClient messageForTransportError:info];
    }
    if ([name isEqualToString:@"TUN_ERROR"]) {
        return [NSString stringWithFormat:@"The VPN interface failed%@.", detail];
    }
    return [NSString stringWithFormat:@"%@%@", name, detail];
}

#pragma mark - core callbacks

- (void)ovpnLogLine:(NSString *)line {
    NSString *trimmed = [line stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
    SSLogI(@"OpenVPN core: %@", trimmed);
    // What the core reports only in its log: lost connections, failed connects, refused pushed settings
    NSString *reason = [SRPOpenVPNClient messageForLogLine:trimmed];
    if (reason) {
        dispatch_async(_worker, ^{
            if (self->_pathSwitching) return;
            // Before the tunnel was up, a silence after the TLS handshake usually means the server refused this client
            if (!self->_everEstablished && [trimmed containsString:@"KEEPALIVE_TIMEOUT"]) {
                self->_lastReason = @"The server stopped answering after the TLS handshake. It may have refused the client certificate (revoked, from another CA or expired); the server's log names the reason.";
                return;
            }
            self->_lastReason = reason;
        });
    }
}

- (void)ovpnRegisterTun:(SRPTun *)tun io:(openvpn_io::io_context *)io {
    _tun = tun;
    os_unfair_lock_lock(&_ioLock);
    _io = io;
    os_unfair_lock_unlock(&_ioLock);
}

- (void)ovpnUnregisterTun:(SRPTun *)tun {
    if (_tun == tun) {
        _tun = nullptr;
        _packetsFlow = false;
    }
}

- (void)ovpnDeliver:(NSData *)packet {
    SRPTun *tun = _tun;
    if (tun) tun->deliver(packet);
}

/// Called by SRPTun on the core thread. Applies the pushed settings and waits until the provider confirms them
/// (or, without a provider, goes on at once); the core requires this before tun_start returns.
- (void)ovpnApplyOptionsAndWait:(NSArray<NSArray<NSString *> *> *)options serverAddress:(NSString *)serverAddress {
    NEPacketTunnelNetworkSettings *settings = [SRPOpenVPNClient settingsForPushedOptions:options serverAddress:serverAddress];
    SSLogM(@"OpenVPN: applying settings addr=%@ routes=%@ dns=%@ mtu=%@", settings.IPv4Settings.addresses,
           settings.IPv4Settings.includedRoutes.count == 1 && [settings.IPv4Settings.includedRoutes.firstObject.destinationAddress isEqualToString:@"0.0.0.0"]
               ? @"default" : @(settings.IPv4Settings.includedRoutes.count), settings.DNSSettings.servers, settings.MTU);
    dispatch_semaphore_t applied = dispatch_semaphore_create(0);
    os_unfair_lock_lock(&_ioLock);
    _tunApplied = applied;
    os_unfair_lock_unlock(&_ioLock);
    if (_settingsCb) _settingsCb(settings);
    if (_providerManaged &&
        dispatch_semaphore_wait(applied, dispatch_time(DISPATCH_TIME_NOW, 10 * NSEC_PER_SEC)) != 0) {
        SSLogE(@"OpenVPN: the tunnel settings were not confirmed within 10 seconds");
    }
    _packetsFlow = true;
}

- (void)tunApplied {
    os_unfair_lock_lock(&_ioLock);
    dispatch_semaphore_t applied = _tunApplied;
    os_unfair_lock_unlock(&_ioLock);
    if (applied) dispatch_semaphore_signal(applied);
}

- (void)setProviderManaged:(BOOL)managed {
    _providerManaged = managed;
}

- (void)ovpnOutputPacket:(NSData *)packet family:(int)family {
    if (_outputCb) _outputCb(packet, family);
}

#pragma mark - settings

/// "1.1.1.1", "1.1.1.1:53", "[2620:fe::fe]:53" or "2620:fe::fe" as the bare address
static NSString *SRPDNSAddress(NSString *value) {
    if ([value hasPrefix:@"["]) {
        NSRange end = [value rangeOfString:@"]"];
        return end.location != NSNotFound ? [value substringWithRange:NSMakeRange(1, end.location - 1)] : value;
    }
    NSArray *parts = [value componentsSeparatedByString:@":"];
    return parts.count == 2 ? parts[0] : value;
}

+ (NEPacketTunnelNetworkSettings *)settingsForPushedOptions:(NSArray<NSArray<NSString *> *> *)options
                                              serverAddress:(NSString *)serverAddress {
    NSString *local4 = nil, *peer4 = nil, *mask4 = nil, *topology = nil;
    NSString *local6 = nil;
    NSInteger prefix6 = 64;
    NSMutableArray<NSString *> *dns = [NSMutableArray array];
    NSMutableArray<NSString *> *domains = [NSMutableArray array];
    NSMutableArray<NEIPv4Route *> *includes = [NSMutableArray array];
    NSMutableArray<NEIPv4Route *> *excludes = [NSMutableArray array];
    BOOL fullTunnel = NO;
    NSInteger mtu = 1400;

    for (NSArray<NSString *> *parts in options) {
        NSString *name = parts.count > 0 ? parts[0] : @"";
        if ([name isEqualToString:@"ifconfig"] && parts.count >= 2) {
            local4 = parts[1];
            if (parts.count >= 3) peer4 = parts[2];
        } else if ([name isEqualToString:@"topology"] && parts.count >= 2) {
            topology = parts[1];
        } else if ([name isEqualToString:@"ifconfig-ipv6"] && parts.count >= 2) {
            // "ifconfig-ipv6 addr/prefix gateway"
            NSArray *ap = [parts[1] componentsSeparatedByString:@"/"];
            local6 = ap.firstObject;
            if (ap.count > 1) prefix6 = [ap[1] integerValue];
        } else if ([name isEqualToString:@"dhcp-option"] && parts.count >= 3) {
            if ([parts[1] isEqualToString:@"DNS"] || [parts[1] isEqualToString:@"DNS6"]) [dns addObject:parts[2]];
            if ([parts[1] isEqualToString:@"DOMAIN"] || [parts[1] isEqualToString:@"DOMAIN-SEARCH"] ||
                [parts[1] isEqualToString:@"ADAPTER_DOMAIN_SUFFIX"]) [domains addObject:parts[2]];
        } else if ([name isEqualToString:@"dns"] && parts.count >= 5 && [parts[1] isEqualToString:@"server"] &&
                   [parts[3] isEqualToString:@"address"]) {
            // OpenVPN 2.6's "dns server N address ADDR [ADDR...]"
            for (NSUInteger i = 4; i < parts.count; i++) [dns addObject:SRPDNSAddress(parts[i])];
        } else if ([name isEqualToString:@"redirect-gateway"]) {
            fullTunnel = YES;
        } else if ([name isEqualToString:@"route"] && parts.count >= 2) {
            // route NETWORK [MASK] [GATEWAY]; net_gateway sends the network around the tunnel
            NSString *mask = parts.count >= 3 && ![parts[2] isEqualToString:@"default"] ? parts[2] : @"255.255.255.255";
            struct in_addr a, m;
            if (inet_pton(AF_INET, parts[1].UTF8String, &a) != 1 || inet_pton(AF_INET, mask.UTF8String, &m) != 1) continue;
            NEIPv4Route *r = [[NEIPv4Route alloc] initWithDestinationAddress:parts[1] subnetMask:mask];
            if (parts.count >= 4 && [parts[3] isEqualToString:@"net_gateway"]) [excludes addObject:r];
            else [includes addObject:r];
        } else if ([name isEqualToString:@"tun-mtu"] && parts.count >= 2) {
            mtu = [parts[1] integerValue];
        }
    }
    if (local4 && peer4) {
        // topology subnet: "ifconfig LOCAL NETMASK"; net30 and p2p (OpenVPN 2.6's default): "ifconfig LOCAL PEER"
        if ([topology isEqualToString:@"subnet"]) {
            mask4 = peer4;
        } else {
            mask4 = @"255.255.255.255";
            [includes addObject:[[NEIPv4Route alloc] initWithDestinationAddress:peer4 subnetMask:@"255.255.255.255"]];
        }
    }
    if (dns.count == 0) [dns addObject:@"1.1.1.1"];
    if (mtu < 576 || mtu > 9000) mtu = 1400;

    NSString *remote = serverAddress.length > 0 ? serverAddress : @"1.0.0.1";
    NEPacketTunnelNetworkSettings *settings = [[NEPacketTunnelNetworkSettings alloc] initWithTunnelRemoteAddress:remote];
    settings.DNSSettings = [[NEDNSSettings alloc] initWithServers:dns];
    if (domains.count) settings.DNSSettings.searchDomains = domains;
    settings.MTU = @(mtu);

    if (local4) {
        NEIPv4Settings *v4 = [[NEIPv4Settings alloc] initWithAddresses:@[local4] subnetMasks:@[mask4 ?: @"255.255.255.0"]];
        v4.includedRoutes = fullTunnel || includes.count == 0 ? @[[NEIPv4Route defaultRoute]] : includes;
        // The server itself stays on the physical path
        struct in_addr sa;
        if (inet_pton(AF_INET, remote.UTF8String, &sa) == 1) {
            [excludes addObject:[[NEIPv4Route alloc] initWithDestinationAddress:remote subnetMask:@"255.255.255.255"]];
        }
        if (excludes.count) v4.excludedRoutes = excludes;
        settings.IPv4Settings = v4;
    }
    if (local6) {
        NEIPv6Settings *v6 = [[NEIPv6Settings alloc] initWithAddresses:@[local6] networkPrefixLengths:@[@(prefix6)]];
        v6.includedRoutes = @[[NEIPv6Route defaultRoute]];
        settings.IPv6Settings = v6;
    }
    return settings;
}

#pragma mark - packets / lifecycle

- (void)injectPacket:(NSData *)packet family:(int)family {
    if (packet.length < 20 || packet.length > 65535 || !_packetsFlow) return;
    os_unfair_lock_lock(&_ioLock);
    openvpn_io::io_context *io = _io;
    if (io) {
        SRPOpenVPNClient *owner = self;
        // The TUN is looked up when the packet runs on the core thread: it may have been replaced by a reconnect
        openvpn_io::post(*io, [owner, packet]() {
            @autoreleasepool {
                [owner ovpnDeliver:packet];
            }
        });
    }
    os_unfair_lock_unlock(&_ioLock);
}

- (void)close {
    dispatch_async(_worker, ^{
        self->_closedManually = YES;
        [self stopPathMonitor];
        [self stopCoreLocked];
    });
}

- (void)closeAndWait {
    dispatch_sync(_worker, ^{
        self->_closedManually = YES;
        [self stopPathMonitor];
        [self stopCoreLocked];
    });
}

#pragma mark - Switch to Wi-Fi

- (void)startPathMonitor {
    [self stopPathMonitor];
    if (!_switchToWifi) return;
    _lastPathHadWifi = NO;
    _pathMonitor = nw_path_monitor_create();
    __weak SRPOpenVPNClient *weakSelf = self;
    nw_path_monitor_set_queue(_pathMonitor, _worker);
    nw_path_monitor_set_update_handler(_pathMonitor, ^(nw_path_t path) {
        SRPOpenVPNClient *strongSelf = weakSelf;
        if (!strongSelf) return;
        BOOL satisfied = nw_path_get_status(path) == nw_path_status_satisfied;
        BOOL hasWifi = satisfied && nw_path_uses_interface_type(path, nw_interface_type_wifi);
        BOOL hadWifi = strongSelf->_lastPathHadWifi;
        strongSelf->_lastPathHadWifi = hasWifi;
        if (SSShouldReconnectForPathChange(hadWifi, hasWifi, satisfied, strongSelf->_up)) {
            SSLogM(@"Wi-Fi became available; moving the OpenVPN connection to it");
            [strongSelf moveToNewPathLocked];
        }
    });
    nw_path_monitor_start(_pathMonitor);
}

/// The core reconnects on the current path; it is not a lost connection, so Auto Reconnect off does not end it
- (void)moveToNewPathLocked {
    if (!_up || !_impl || _failed || _closedManually) return;
    _pathSwitching = YES;
    _attempts = 0;
    _impl->reconnect(0);
}

- (void)switchNetworkPath {
    dispatch_async(_worker, ^{
        SSLogM(@"OpenVPN: network path switch requested");
        [self moveToNewPathLocked];
    });
}

- (void)stopPathMonitor {
    if (_pathMonitor != nil) {
        nw_path_monitor_cancel(_pathMonitor);
        _pathMonitor = nil;
    }
}

#pragma mark - On Sleep

- (void)pauseForSleep {
    dispatch_async(_worker, ^{
        if (self->_onSleep == 2 || self->_closedManually || self->_failed) return;
        SSLogM(@"device sleep: %@ the OpenVPN connection", self->_onSleep == 1 ? @"pausing" : @"closing");
        self->_sleepPaused = YES;
        [self stopCoreLocked];
    });
}

- (void)wakeFromSleep {
    dispatch_async(_worker, ^{
        if (!self->_sleepPaused || self->_closedManually || self->_failed) return;
        self->_sleepPaused = NO;
        if (self->_onSleep == 1 || self->_autoReconnect) {
            self->_attempts = 0;
            SSLogM(@"device wake: reconnecting the OpenVPN connection");
            [self startLocked];
        } else {
            // Off without Auto Reconnect leaves no connection; end the tunnel instead of keeping a VPN that drops every
            // packet (as SoftEther, SSTP, SSL VPN and SSH do)
            [self failWithReason:@"The connection was closed while the device slept."];
        }
    });
}

@end
