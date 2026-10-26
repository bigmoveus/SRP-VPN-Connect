
#import "SSSSTPClient.h"
#import "SSTCPClient+Private.h"
#import "SSFragTLSChannel.h"
#import "SSLog.h"
#include "sstp/sstp-buff.h"
#include "sstp/sstp-common.h"
#include "sstp/sstp-packet.h"
#include "sstp/sstp-state.h"
#include "sstp/sstp-private.h"
#include "sstp/sstp-pppd.h"
#include "sstp/sstp-stream.h"
#include "sstp/sstp-http.h"
#include "sstp/utils.h"
#include <arpa/inet.h>
#include <netinet/ip.h>
#import <SRPCore/SSProtocol.h>
#import <SRPCore/NWRunLoop.h>

@interface SSSSTPClient ()
@property (nonatomic)sstp_state_st *state_machine;
@property (nonatomic)sstp_pppd_st *pppd;
@property (nonatomic)sstp_stream_st *stream;
@end

status_t x_sstp_send_fn(sstp_stream_st *stream, sstp_buff_st *tx,
                        sstp_complete_fn complete, void *ctx, int timeout) {
    SSSSTPClient *client = (__bridge SSSSTPClient *)(stream->ctx);
    if (client.socket == nil || client.cancelling != SSTCPSocketStateIDLE) {
        return SSTP_FAIL;
    }
    if (client.cancelling == SSTCPSocketStateIDLE) {
        void *message = tx->data + tx->off;
        int length = tx->len - tx->off;
        /* TLS fragmentation mode: the outer TLS runs in the channel — the
         * engine's bytes are plaintext that the channel encrypts. */
        if (client.fragChannel) {
            [client.fragChannel sendPlaintext:[NSData dataWithBytes:message length:length]];
            complete(stream, tx, ctx, SSTP_OKAY);
            return SSTP_OKAY;
        }
        /* nw_connection_send is asynchronous and dispatch_data_create with
         * DESTRUCTOR_DEFAULT does not copy; the pppd tx buffer is reused by
         * the next frame, so take an owned copy (freed on send completion). */
        void *copy = malloc(length);
        memcpy(copy, message, length);
        dispatch_data_t content = dispatch_data_create(copy, length, nil, DISPATCH_DATA_DESTRUCTOR_FREE);
        NSString *tag = client.tag;
        nw_connection_send(client.socket, content, NW_CONNECTION_DEFAULT_MESSAGE_CONTEXT, true, ^(nw_error_t  _Nullable error) {
            if (error) {
                SSLogI(@"%@ nw_connection_send failure:%@", tag, error);
                complete(stream, tx, ctx, SSTP_FAIL);
            }
            else {
                complete(stream, tx, ctx, SSTP_OKAY);
            }
        });
    }
    return SSTP_OKAY;
}

status_t x_sstp_get_cert_hash_fn(sstp_stream_st *ctx, int proto,
                                 unsigned char *hash, int hlen) {
    SSSSTPClient *client = (__bridge SSSSTPClient *)(ctx->ctx);
    int evp = (proto & SSTP_PROTO_HASH_SHA256) ? 1 : 0;
    [client getCertificate:hash length:&hlen evp:evp];
    return SSTP_OKAY;
}

status_t x_sstp_state_forward_fn(void *arg, uint8_t *buf, int len) {
    uint8_t *frame = NULL;
    int flen = 0;
    int ret  = 0;

#if SSTP_PPPD_DEBUG
    {
        char hex[160]; int o = 0;
        for (int i = 0; i < len && i < 48; i++) o += snprintf(hex + o, sizeof(hex) - o, "%02x", buf[i]);
        SSLogI(@"forward_fn: %d bytes: %s", len, hex);
    }
#endif

    /* Get the maximum size of the frame */
    flen = (len << 1) + 4;
    
    /* Allocate some stack space (do not free!) */
    frame = alloca(flen);
    if (!frame) {
        SSLogI(@"Could not alloca frame: %d", flen);
        return SSTP_FAIL;;
    }
    /* Perform the HDLC encoding of the frame */
    ret = sstp_frame_encode((const unsigned char*) buf, len, frame, &flen);
    if (SSTP_OKAY != ret) {
        SSLogI(@"Could not encode frame");
        return SSTP_FAIL;
    }
    SSSSTPClient *client = (__bridge SSSSTPClient *)(arg);
    id<SSSSTPClientDelegate> delegate = (id<SSSSTPClientDelegate>)client.delegate;
    uint16_t protocol = ntohs(*(uint16_t *)(buf + 2));
    if (protocol == 0x21) {
        struct ip *x = (struct ip *)(buf + 4);
        ushort total_len = ntohs(x->ip_len);
#if SSTP_LOG_PROTOCOL
        char ip_dst[32] = {0};
        char ip_src[32] = {0};
        char *dst = inet_ntoa(x->ip_dst);
        memcpy(ip_dst, dst, strlen(dst));
        
        char *src = inet_ntoa(x->ip_src);
        memcpy(ip_src, src, strlen(src));
        SSLogI(@"recv protocol:%x ip_dst: %s, ip_src:%s, total_len: %d", protocol, ip_dst, ip_src, total_len);
#endif
        [delegate tcpClient:client didReceiveIPPacket:(uint8_t *)x length:total_len];
    }
    else {
#if SSTP_LOG_PROTOCOL
        SSLogI(@"recv protocol: %x", protocol);
#endif
        [delegate tcpClient:client didReceiveMessage:frame length:flen];
    }
    return SSTP_OKAY;
}

status_t x_sstp_state_change_fn(void *arg, sstp_state_t state) {
    SSSSTPClient *client = (__bridge SSSSTPClient *)(arg);
    id<SSSSTPClientDelegate> delegate = (id<SSSSTPClientDelegate>)client.delegate;
    switch (state) {
        case SSTP_CALL_CONNECT: {
            SSLogI(@"Started PPP Link Negotiation");
            [delegate tcpClient:client didChangeSSTPState:SSTPPPPState_OPEN];
            /* Set the forwarder function */
            sstp_state_set_forward(client.state_machine, x_sstp_state_forward_fn, (__bridge void *)(client));
        }
            break;
        case SSTP_CALL_ESTABLISHED:
            SSLogM(@"PPP Link Negotiation ESTABLISHED");
            [client startEchoTimer];
            [delegate tcpClient:client didChangeSSTPState:SSTPPPPState_ESTABLISHED];
            break;
        default: {
            SSLogM(@"Connection was aborted, state:%d, reason:%s", state, sstp_state_reason(client.state_machine));
            [client stopEchoTimer];
            [delegate tcpClient:client didChangeSSTPState:SSTPPPPState_CLOSE];
        }
            break;
    }
    return SSTP_OKAY;
}

void x_sstp_pppd_fn(void *arg, sstp_pppd_event_t ev){
    SSSSTPClient *client = (__bridge SSSSTPClient *)(arg);
    switch (ev) {
        case SSTP_PPP_UP: {
            /* Tell the state machine to connect */
            int ret = sstp_state_accept(client.state_machine);
            if (SSTP_FAIL == ret) {
                SSLogM(@"Negotiation with server failure: %d", ret);
            }
        }
            break;
        case SSTP_PPP_AUTH: {
            uint8_t skey[16];
            uint8_t rkey[16];
            SSSstp *sstp = (SSSstp *)NWRunLoop.currentRunLoop.protocol;
            /* Get the MPPE keys */
            int ret = sstp_chap_mppe_get(sstp_pppd_getchap(client.pppd), sstp.password.UTF8String, skey, rkey, 0);
            if (SSTP_FAIL == ret){
                SSLogM(@"Negotiation auth chap mppe get failure: %d", ret);
                return;
            }
            /* Set the keys */
            sstp_state_mppe_keys(client.state_machine, skey, rkey, 16);
        }
            break;
        case SSTP_PPP_START: {
            sstp_state_resume_recv(client.state_machine);
        }
            break;
        default: {
            SSLogI(@"Receive pppd event: %d", ev);
        }
            break;
    }
    
}

typedef enum {
    SSTPStateIDLE,
    SSTPStateHttpSend,
    SSTPStateStateSend,
} SSTPState;

@implementation SSSSTPClient {
    NSString *_uuid;
    SSTPState _sstp_state;

    int _recv_len;
    char *_recv_buf;

    dispatch_source_t _echoTimer;
}

#define kEchoIntervalSeconds 15

-(void)startEchoTimer {
    if (_echoTimer) {
        return;
    }
    dispatch_queue_t queue = NWRunLoop.currentRunLoop.worker;
    _echoTimer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, queue);
    dispatch_source_set_timer(_echoTimer,
                              dispatch_time(DISPATCH_TIME_NOW, kEchoIntervalSeconds * NSEC_PER_SEC),
                              kEchoIntervalSeconds * NSEC_PER_SEC, 0);
    __weak SSSSTPClient *weakSelf = self;
    dispatch_source_set_event_handler(_echoTimer, ^{
        SSSSTPClient *strongSelf = weakSelf;
        if (strongSelf && strongSelf.state_machine) {
            sstp_state_keepalive_tick(strongSelf.state_machine);
        }
    });
    dispatch_resume(_echoTimer);
    SSLogI(@"SSTP keepalive echo timer started (%ds)", kEchoIntervalSeconds);
}

-(void)stopEchoTimer {
    if (_echoTimer) {
        dispatch_source_cancel(_echoTimer);
        _echoTimer = nil;
    }
}

-(void)setMppeKeys:(NSData *)send recv:(NSData *)recv {
    if (send.length == 0 || recv.length == 0 || send.length > 32 || recv.length > 32) {
        SSLogI(@"setMppeKeys: refusing bad key lengths (%lu/%lu)",
              (unsigned long)send.length, (unsigned long)recv.length);
        return;
    }
    /* Same entry point the cleartext MSCHAPv2 snoop path uses */
    sstp_state_mppe_keys(self.state_machine, (unsigned char *)send.bytes,
        (unsigned char *)recv.bytes, send.length);
    /* The cleartext snoop never fires for tunneled EAP; mark auth done so
     * the first outbound IPCP frame triggers the Connected message. */
    sstp_pppd_auth_done(self.pppd);
    SSLogM(@"MPPE keys for the SSTP crypto binding set from the tunneled EAP session");
}

- (instancetype)initWithTarget:(NSString *)target port:(int)port proto:(SSProtocolType)proto family:(int)family{
    self = [super initWithTarget:target port:port proto:proto family:family];
    if (self) {
        _uuid = [NSUUID UUID].UUIDString;
        _sstp_state = SSTPStateIDLE;
        sstp_stream_create(&_stream, x_sstp_send_fn, x_sstp_get_cert_hash_fn, (__bridge void *)(self));
        sstp_state_create(&_state_machine, _stream, x_sstp_state_change_fn, (__bridge void *)(self), SSTP_MODE_CLIENT);
        sstp_pppd_create(&_pppd, _stream, x_sstp_pppd_fn, (__bridge void *)(self));
        SSLogI(@"Client Unique ID: %@", _uuid);
    }
    return self;
}

-(void)dealloc {
    SSLogI(@"%s", __func__);
    [self stopEchoTimer];
    sstp_pppd_free(_pppd);
    _pppd = NULL;
    
    sstp_stream_destroy(_stream);
    _stream = NULL;
    
    sstp_state_free(_state_machine);
    _state_machine = NULL;
}

-(void)setState:(SSTCPState)state {
    [super setState:state];
    switch (state) {
        case SSTCPStateConnecting: {
            self.sstate = SSClientStateConnecting;
            [self.delegate tcpClient:self didChangeState:SSClientStateConnecting];
        }
            break;
        case SSTCPStateConnected: {
            SSSstp *sstp = (SSSstp *)NWRunLoop.currentRunLoop.protocol;
            const int capaticy = 512;
            char buf[512];
            int offset = 0;
            offset += snprintf(buf + offset, capaticy - offset, "SSTP_DUPLEX_POST %s HTTP/1.1\r\n", SSTP_HTTP_DFLT_PATH);
            offset += snprintf(buf + offset, capaticy - offset, "Host: %s\r\n", sstp.host.UTF8String);
            offset += snprintf(buf + offset, capaticy - offset, "Content-Length: %llu\r\n", -1ULL);
            offset += snprintf(buf + offset, capaticy - offset, "SSTPCORRELATIONID: %s\r\n\r\n", _uuid.UTF8String);
            [super sendMessage:(byte_t *)buf length:offset];
            _sstp_state = SSTPStateHttpSend;
        }
            break;
        case SSTCPStateDisconnected: {
            self.sstate = SSClientStateDisconnected;
            [self.delegate tcpClient:self didChangeState:SSClientStateDisconnected];
        }
            break;
        default:
            break;
    }
}

#define k_sstp_max_lenth 16384

/// Called with raw TCP data from the peer; reassembles it into whole SSTP packets (the layer below cannot). The TCP read buffer is 65536, this buffer is capped at 32768
/// - Parameters:
///   - message: TCP data
///   - buflen: data length
-(void)didReceiveMessage:(char *)message buflen:(int)buflen {
    int offset = 0;
    while (buflen > k_sstp_max_lenth) {
        [self didReceiveMessage32768:(message + offset) buflen:k_sstp_max_lenth];
        buflen -= k_sstp_max_lenth;
        offset += k_sstp_max_lenth;
    }
    if (buflen > 0) {
        [self didReceiveMessage32768:message + offset buflen:buflen];
    }
}

-(void)didReceiveMessage32768:(char *)message buflen:(int)buflen {
    if (_recv_buf == NULL) {
        _recv_len = 0;
        _recv_buf = malloc(32768);
    }
    memcpy(_recv_buf + _recv_len, message, buflen);
    _recv_len += buflen;
    
    // Once the HTTP request was sent, the HTTP response must be handled first to complete the handshake
    if (SSTPStateHttpSend == _sstp_state) {
        status_t rc = sstp_recv_http_hello_complete(self.stream, _recv_buf, SSTP_OKAY);
        if (rc != SSTP_OKAY) {
            return;
        }
        _sstp_state = SSTPStateStateSend;
        _recv_len = 0;
        sstp_state_start(self.state_machine);
        return;
    }

    // Everything below is SSTP protocol handling; each sstp_state_read_msg call must get exactly one complete SSTP packet
    while (true) {
        if (_recv_len <= 4) {
            return;
        }
        sstp_pkt_st *pkt = (sstp_pkt_st *) _recv_buf;
        uint16_t pkt_len = ntohs(pkt->length);
        if (_recv_len < pkt_len) {
            return;
        }
        sstp_state_read_msg(self.state_machine, self.stream, _recv_buf, pkt_len);
        if (_recv_len - pkt_len > 0) {
            memmove(_recv_buf, _recv_buf + pkt_len, _recv_len - pkt_len);
        }
        _recv_len = _recv_len - pkt_len;
    }
}

-(BOOL)sendMessage:(uint8_t *)message length:(int)buflen {
    sstp_pppd_recv(_pppd, (char *)message, buflen);
    return YES;
}

-(void)echo {
    sstp_state_send_echo(self.state_machine);
}

-(void)close {
    [self stopEchoTimer];
    sstp_state_disconnect(self.state_machine);
}

@end
