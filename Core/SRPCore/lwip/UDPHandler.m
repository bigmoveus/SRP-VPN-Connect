
#import "UDPHandler.h"
#include "lwIP.h"
#import "x_utils.h"
#import "LPHelper.h"
#import "SSTCPClient.h"
#import "SSBuffer.h"
#import "SSDirectClient.h"

#define CLOSE_AND_CLEAN close

#ifdef _WIN32
#include "win_getopt.h"
#else
#include <getopt.h>
#endif

#define AF_INET         2
#define AF_INET6        30

static long long __refCount__ = 0;

@interface UDPHandler ()<SSClientDelegate>
-(void)write:(int8_t *)buffer length:(int)length;
@property (nonatomic, strong, readonly)SSTCPClient *transport;
@end

static int8_t __shared_mem__[2048];

@interface lwIP (UDP)
-(UDPHandler *)GetUDPHandler:(void *)argument pcb:(struct udp_pcb *)pcb addr:(const ip_addr_t *)addr port:(u16_t)port dest_addr:(const ip_addr_t *)dest_addr dest_port:(u16_t)dest_port;
@end


void netif_udp_receive_callback(void *argument, struct udp_pcb *pcb, struct pbuf *p,
                                const ip_addr_t *addr, u16_t port,
                                const ip_addr_t *dest_addr, u16_t dest_port) {
    UDPHandler *handler = [[lwIP shared] GetUDPHandler:argument pcb:pcb addr:addr port:port dest_addr:dest_addr dest_port:dest_port];
    if (p->tot_len == p->len) {
        [handler write:(int8_t *)p->payload length:p->tot_len];
    }
    else {
        if (p->tot_len > 2048) {
            pbuf_copy_partial(p, __shared_mem__, p->tot_len, 0);
            [handler write:__shared_mem__ length:p->tot_len];
        }
        else {
            NSMutableData *packet = [NSMutableData dataWithLength:p->tot_len];
            pbuf_copy_partial(p, packet.mutableBytes, p->tot_len, 0);
            [handler write:(int8_t *)packet.bytes length:p->tot_len];
        }
    }
    if (p != NULL) {
        pbuf_free(p);
    }
}

@implementation UDPHandler {
    void *_argument;
    SSBuffer *_buf;
}

-(instancetype)initWithArgument:(void *)argument pcb:(struct udp_pcb *)pcb addr:(const ip_addr_t *)addr port:(u16_t)port dest_addr:(const ip_addr_t *)dest_addr dest_port:(u16_t)dest_port identifier:(nonnull NSString *)identifier{
    self = [super init];
    if (self) {
        assert([lwIP InQueue]);
        _argument = argument;
        _pcb = pcb;
        _local_addr = (*addr);
        _local_port = port;
        _dest_addr = (*dest_addr);
        _dest_port = dest_port;
        _identifier = identifier;
        
        char dst_ip[32] = {0};
        ip4addr_ntoa_r((const ip4_addr_t *)dest_addr, dst_ip, 32);
        NSString *host = [NSString stringWithUTF8String:dst_ip];
        
        _activeTime = x_system_time_mills();
        
        _buf = [[SSBuffer alloc] initWithCapaticy:4];
        int family = addr->type == IPADDR_TYPE_V4 ? AF_INET : AF_INET6;
        _transport = [[SSDirectClient alloc] initWithTarget:host port:dest_port proto:(SSProtocolTypeUDP) family:family];
        _transport.delegate = self;
        _transport.tag = identifier;
        [_transport connect];
        __refCount__++;
    }
    return self;
}

-(void)tcpClient:(SSTCPClient *)client didReceiveMessage:(nonnull uint8_t *)message length:(int)length {
    assert([lwIP InQueue]);
    _activeTime = x_system_time_mills();
    void *payload = (void *)message;
    struct pbuf *buf = pbuf_alloc_reference(payload, length, PBUF_ROM);
    ip_addr_t local_addr = self.local_addr;
    ip_addr_t dest_addr = self.dest_addr;
    udp_sendto(self.pcb, buf, &local_addr, self.local_port, &dest_addr, self.dest_port);
    pbuf_free(buf);
}

-(void)tcpClient:(SSTCPClient *)client didChangeState:(SSClientState)state {
    assert([lwIP InQueue]);
    //    NSLog(@"[Y] UDP:%@ setState: %@", self.identifier, [LPHelper GetStateDesc:state]);
    switch (state) {
        case SSClientStateConnected: {
            _activeTime = x_system_time_mills();
            while (true) {
                SSData *buf = [_buf read];
                if (buf.length == 0) {
                    break;
                }
                [self write:(int8_t *)buf.bytes length:(int)buf.length];
            }
        }
            break;
        case SSClientStateDisconnected: {
            [self.delegate handler:self onUdpStateDidChanged:(UDPStateDisconnected)];
        }
            break;
        default:
            break;
    }
}

-(void)close:(BOOL)timeout {
    //    NSLog(@"[Y] UDP:%@ close, timeout:%d", _identifier, timeout);
    [_transport close];
}

+(int64_t)refCount {
    return __refCount__;
}

-(void)dealloc {
    --__refCount__;
    //    NSLog(@"[Y] UDP:%@ dealloc, refCount:%lld", _identifier, __refCount__);
}

-(void)write:(int8_t *)buffer length:(int)length {
    _activeTime = x_system_time_mills();
    if (_transport.sstate == SSClientStateConnecting) {
        [_buf SendBufferList:buffer length:length];
    }
    else if (_transport.sstate == SSClientStateConnected ){
        [_transport sendMessage:(uint8_t *)buffer length:length];
    }
}


@end
