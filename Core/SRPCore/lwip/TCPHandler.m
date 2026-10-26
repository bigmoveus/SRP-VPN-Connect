
#import "TCPHandler.h"
#import "SSTCPClient.h"
#import "LPHelper.h"
#import "SSBuffer.h"
#import "SSData.h"
#import "NWRunLoop.h"
#import "SSDirectClient.h"

#define AF_INET         2
#define AF_INET6        30

static long long __refCount__ = 0;
static int8_t __shared_mem__[2048];

@interface lwIP (TCP)
-(TCPHandler *)GetTCPHander:(void *)argument newpcb:(struct tcp_pcb *)newpcb;
@end

err_t netif_tcp_accept_callback(void *argument, struct tcp_pcb *newpcb, err_t err) {
    if (err != ERR_OK) return err;
    [[lwIP shared] GetTCPHander:argument newpcb:newpcb];
    return ERR_OK;
}


@interface TCPHandler ()<SSClientDelegate>
@property (nonatomic, readonly)BOOL isClose;
@property (nonatomic, readonly)BOOL isAppleTunnelWritable;
@property (nonatomic, readonly, strong)SSBuffer *snd_buf;
@property (nonatomic, readonly, strong)SSBuffer *rsv_buf;
@property (nonatomic, readonly, strong)SSTCPClient *transport;
@property (nonatomic)int64_t FIN_SENT;
@end


@implementation TCPHandler {
    ip_addr_t _local_addr;
    ip_addr_t _remote_addr;
    u16_t _local_port;
    u16_t _remote_port;
}


static err_t x_netif_tcp_recv_fn(void *arg, struct tcp_pcb *tpcb, struct pbuf *p, err_t err) {
    
    // The client has already disconnected
    if (err != ERR_OK && err != ERR_ABRT) {
        if (p) pbuf_free(p);
        return err;
    }
    TCPHandler *SELF;
    
    {
        // On bad arguments abort the connection, releasing buffers if needed
        if (!arg) {
            if (p) pbuf_free(p);
            tcp_abort(tpcb);
            return ERR_ABRT;
        }
        SELF = (__bridge TCPHandler *)(arg);
        if (!SELF) {
            if (p) pbuf_free(p);
            tcp_abort(tpcb);
            return ERR_ABRT;
        }
    }
    
    if (!p) {
        if (SELF.state == TCPStateAborting) {
            return ERR_ABRT;
        }
        // A FIN event: the peer closed the connection, no more data can arrive from the TUN side
        SELF.state = TCPStateReceiveClosed;
        return ERR_OK;
    }
    
    //    Handle the connecting state
    //    Tell lwip we can't receive data at the moment,
    //    lwip will store it and try again later.
    //    Cannot receive yet (remote not connected); reply so lwIP resends later, keep the pbuf
    if (SELF.state == TCPStateConnecting) {
        return ERR_CONN;
    }
    
    //    Handle errors by cleaning up resources
    if (SELF.state == TCPStateError) {
        pbuf_free(p);
        return ERR_ABRT;
    }
    
    //     Handle the tun-not-readable cases: read-closed, closing, closed
    //    _state == TCPStateReceiveClosed || _state == TCPStateClosing || _state == TCPStateClosed || _state == TCPStateAborting
    if (SELF.isClose) {
        pbuf_free(p);
        tcp_recved(tpcb, p->tot_len);
        tcp_shutdown(tpcb, 1, 0);
        return ERR_OK;
    }
    
    if (p->tot_len == p->len) {
        [SELF SendBufferList:(int8_t *)p->payload length:p->tot_len];
    }
    else {
        if (p->tot_len > 2048) {
            NSMutableData *packet = [NSMutableData dataWithLength:p->tot_len];
            pbuf_copy_partial(p, packet.mutableBytes, p->tot_len, 0);
            [SELF SendBufferList:(int8_t *)packet.bytes length:p->tot_len];
        }
        else{
            pbuf_copy_partial(p, __shared_mem__, p->tot_len, 0);
            [SELF SendBufferList:__shared_mem__ length:p->tot_len];
        }
    }
    tcp_recved(tpcb, p->tot_len);
    pbuf_free(p);
    return ERR_OK;
}

static err_t x_netif_tcp_sent_fn(void *arg, struct tcp_pcb *tpcb, u16_t len) {
    if (!arg) {
        tcp_abort(tpcb);
        return ERR_ABRT;
    }
    TCPHandler *SELF = (__bridge TCPHandler *)(arg);
    if (SELF.state == TCPStateAborting) {
        return ERR_ABRT;
    }
    [SELF WriteToTunnelAgain];
    return ERR_OK;
}

static void x_netif_tcp_error_fn(void *arg, err_t err) {
    if (!arg) {
        return;
    }
    TCPHandler *SELF = (__bridge TCPHandler *)(arg);
    NSString *identifier = SELF ? SELF.identifier : @"";
    switch (err) {
        case ERR_ABRT:
            NSLog(@"[Y] %@ tunnel device connection aborted.", identifier);
            break;
        case ERR_RST:
            NSLog(@"[Y] %@ tunnel device connection reset.",identifier);
            break;
        case ERR_CLSD:
            NSLog(@"[Y] %@ tunnel device connection closed.",identifier);
            break;
        case ERR_ARG:
            NSLog(@"[Y] %@ tunnel device Illegal argument.",identifier);
            break;
        default: {
            NSLog(@"[Y] %@ tunnel device exception: %d.", identifier, err);
        }
            break;
    }
    SELF.state = TCPStateError;
}

static err_t x_netif_tcp_poll_fn(void *arg, struct tcp_pcb *tpcb) {
    if (!arg) {
        tcp_abort(tpcb);
        return ERR_ABRT;
    }
    TCPHandler *SELF = (__bridge TCPHandler *)(arg);
    if (SELF.state == TCPStateAborting) {
        return ERR_ABRT;
    }
    [SELF WriteToTunnelAgain];
    return ERR_OK;
}


-(instancetype)initWithPCB:(struct tcp_pcb *)pcb identifier:(NSString *)identifier {
    self = [super init];
    if (self) {
        assert([lwIP InQueue]);
        _pcb = pcb;
        tcp_arg(pcb, (__bridge void *)(self));
        tcp_recv(pcb, x_netif_tcp_recv_fn);
        tcp_sent(pcb, x_netif_tcp_sent_fn);
        tcp_err(pcb, x_netif_tcp_error_fn);
        tcp_poll(pcb, x_netif_tcp_poll_fn, 8);
        
        _local_addr = pcb->remote_ip;
        _remote_addr = pcb->local_ip;
        
        _local_port = pcb->remote_port;
        _remote_port = pcb->local_port;
        
        _state = TCPStateConnecting;
        _identifier = identifier;
        _snd_buf = [[SSBuffer alloc] init];
        _rsv_buf = [[SSBuffer alloc] init];
        
        int family = _local_addr.type == IPADDR_TYPE_V4 ? AF_INET : AF_INET6;
        char remote[32] = {0};
        ipaddr_ntoa_r(&_remote_addr, remote, 32);
        int port = _remote_port;
        SSClientType type = NWRunLoop.currentRunLoop.protocol.protocol;
        if ([[NWRunLoop currentRunLoop] lookup:remote]) {
            _transport = [[SSDirectClient alloc] initWithTarget:[NSString stringWithUTF8String:remote] port:port proto:(SSProtocolTypeTCP) family:family];
        }
        else {
            switch (type) {
                case SSClientType_DIRECT: {
                    _transport = [[SSDirectClient alloc] initWithTarget:[NSString stringWithUTF8String:remote] port:port proto:(SSProtocolTypeTCP) family:family];
                }
                    break;

                default:
                    break;
            }
        }
        _transport.delegate = self;
        _transport.tag = identifier;
        [_transport connect];
        ++__refCount__;
        //        NSLog(@"[Y] TCP:%@ alloc, refCount:%lld, irefCount:%lld", _identifier, __refCount__, SSTCPClient.refCount);
    }
    return self;
}

-(void)close {
    [_transport close];
    if (!_pcb) return;
    tcp_recv(_pcb, NULL);
    tcp_sent(_pcb, NULL);
    tcp_err(_pcb, NULL);
    tcp_poll(_pcb, NULL, 0);
    tcp_arg(_pcb, NULL);
    tcp_close(_pcb);
    _pcb = NULL;
    _transport = nil;
}

+(int64_t)refCount {
    return __refCount__;
}

-(void)dealloc {
    --__refCount__;
    //    NSLog(@"[Y] TCP:%@ dealloc, refCount:%lld, irefCount:%lld", _identifier, __refCount__, SSTCPClient.refCount);
}

-(void)tcpClient:(SSTCPClient *)client didReceiveMessage:(nonnull uint8_t *)message length:(int)length{
    assert([lwIP InQueue]);
    [_rsv_buf SendBufferList:(int8_t *)message length:length];
    [self WriteToTunnelAgain];
}

-(void)SendBufferList:(int8_t *)buf length:(int)length {
    assert([lwIP InQueue]);
    if (_transport.sstate == SSClientStateConnected) {
        [_transport sendMessage:(uint8_t *)buf length:length];
        return;
    }
    [_snd_buf SendBufferList:buf length:length];
    while (true) {
        SSData *bb = [_snd_buf read];
        if (bb.length == 0 || _transport.sstate != SSClientStateConnected) {
            break;
        }
        [_transport sendMessage:(uint8_t *)bb.bytes length:(int)bb.length];
    }
}

-(void)tcpClient:(SSTCPClient *)client didChangeState:(SSClientState)state {
    assert([lwIP InQueue]);
    switch (state) {
        case SSClientStateConnecting:
            self.state = TCPStateConnecting;
            break;
            
        case SSClientStateConnected: {
            self.state = TCPStateConnected;
            if (self.pcb->refused_data) {
                tcp_process_refused_data(self.pcb);
            }
        }
            break;
            
        case SSClientStateDisconnected: {
            if (_rsv_buf.length > 0) {
                //                NSLog(@"[Y] TCP:%@ rsv buf is not empty: %@, so write again", self.identifier, @(_rsv_buf.length));
                [self WriteToTunnelAgain];
            }
            if (_rsv_buf.length == 0) {
                self.state = TCPStateWriteClosed;
            }
        }
            break;
        default:
            break;
    }
}

-(void)WriteToTunnelAgain {
    assert([lwIP InQueue]);
    
    while (true) {
        SSData *bb = [_rsv_buf read];
        if (bb.length == 0) break;
        int writen = [self WriteToTunnel:bb];
        if (writen < bb.length) {
            break;
        }
    }
    // If the receive buffer is empty and the transport is closed, this handler can close
    if (_rsv_buf.length == 0) {
        if (self.state == TCPStateReceiveClosed && self.transport.sstate == SSClientStateDisconnected) {
            //            NSLog(@"[Y] TCP:%@:rsv buf is empty, closed by receive closed and transport closed", self.identifier);
            self.state = TCPStateClosing;
        }
    }
    
}

-(int)WriteToTunnel:(SSData *)message {
    assert([lwIP InQueue]);
    if (!self.isAppleTunnelWritable) {
        //        NSLog(@"[Y] TCP:%@ is not writable", _identifier);
        return 0;
    }
    int buflen = (int)message.length;
    int totalWritten = 0;
    
    int toWrite = (int)buflen;
    if (_pcb == NULL) {
        NSLog(@"[Y] TCP:%@ is not writable caused by pcb == NULL", _identifier);
        return -1;
    }
    
    if (toWrite > _pcb->snd_buf) {
        // Write at most the size of the LWIP buffer.
        toWrite = _pcb->snd_buf;
    }
    
    if (toWrite > 0) {
        err_t err = ERR_OK;
        uint8_t *buf = (uint8_t *)message.bytes;
        buf = buf + totalWritten;
        int written = [self WriteToTunInternal:buf length:toWrite err:&err];
        if (err != ERR_OK) {
            NSLog(@"[Y] TCP:%@ write to tunnel exception:%d", _identifier, err);
            return -3;
        }
        totalWritten += written;
        buflen -= written;
    }
    if (totalWritten >= (int)message.length) {
        // Buffer fully written, nothing left to do
        return totalWritten;
    }
    // Partial write: push the remainder back to the buffer head for the next attempt
    int8_t *buf = (int8_t *)message.bytes;
    buf = buf + totalWritten;
    
    // Partial write: queue the remainder for the next attempt
    [_rsv_buf insert:[SSData dataWithBytes:buf length:message.length - totalWritten]];
    return totalWritten;
}


-(int)WriteToTunInternal:(uint8_t *)bytes length:(u16_t)length err:(err_t *)err{
    if (_pcb == NULL) {
        *err = ERR_CLSD;
        return 0;
    }
    *err = tcp_write(_pcb, bytes, (u16_t)length, TCP_WRITE_FLAG_COPY);
    if (*err == ERR_OK) {
        err_t o_err = tcp_output(_pcb);
        if (o_err != ERR_OK) {
            NSLog(@"[Y] TCP:%@ send available tcp buf to tunnel failure: %d", self.identifier, o_err);
        }
        return (int)length;
    }
    else if (*err == ERR_MEM) {
        *err = ERR_OK;
        return 0;
    }
    *err = ERR_VAL;
    return 0;
}

-(BOOL)checkTimeout {
    [_transport checkTimeout];
    if (self.FIN_SENT == 0) {
        return NO;
    }
    BOOL timeout = x_system_time_mills() - self.FIN_SENT >= 5000;
    NSLog(@"[Y] TCP:%@ timeout: %d", self.identifier, timeout);
    return timeout;
}

-(void)setState:(TCPState)state {
    if (_state == TCPStateReceiveClosed && state == TCPStateWriteClosed) {
        state = TCPStateClosing;
    }
    else if (_state == TCPStateWriteClosed && state == TCPStateReceiveClosed) {
        state = TCPStateClosing;
    }
    
    // On error lwIP already freed the memory; just nil the pcb so a late callback cannot double-free
    if (_state == TCPStateError) {
        _pcb = NULL;
    }
    
    if (_state != TCPStateReceiveClosed && state == TCPStateReceiveClosed) {
        // Send FIN to the peer but keep the connection half-open so pending data still drains
        self.FIN_SENT = x_system_time_mills();
        [_transport close];
    }
    if (state > _state) {
        _state = state;
        //        NSLog(@"[Y] TCP:%@ setState: %@, rstate: %@", self.identifier, [LPHelper GetTCPStateDesc:state], [LPHelper GetTCPStateDesc:_state]);
        [self.delegate handler:self onTcpStateDidChanged:state];
    }
}

-(BOOL)isAppleTunnelWritable {
    return _state == TCPStateConnecting || _state == TCPStateConnected || _state == TCPStateReceiveClosed || _state == TCPStateWriteClosed;
}

-(BOOL)isClose {
    return _state == TCPStateReceiveClosed || _state == TCPStateClosing || _state == TCPStateClosed || _state == TCPStateAborting;
}
@end
