
#import <Foundation/Foundation.h>
#include "x_lwip.h"

NS_ASSUME_NONNULL_BEGIN


@class UDPHandler;


void netif_udp_receive_callback(void *argument, struct udp_pcb *pcb, struct pbuf *p,
                                const ip_addr_t *addr, u16_t port,
                                const ip_addr_t *dest_addr, u16_t dest_port);

typedef enum : NSUInteger {
    UDPStateIDLE,
    UDPStateConnected,
    UDPStateDisconnected,
} UDPState;

@protocol UDPHandlerDelegate <NSObject>

-(void)handler:(UDPHandler *)handler onUdpStateDidChanged:(UDPState)state;

@end

@interface UDPHandler : NSObject

@property (nonatomic, readonly, class)int64_t refCount;

@property (nonatomic, weak)id <UDPHandlerDelegate> delegate;

@property (nonatomic, readonly)ip_addr_t local_addr;

@property (nonatomic, readonly)u16_t local_port;

@property (nonatomic, readonly)ip_addr_t dest_addr;

@property (nonatomic, readonly)u16_t dest_port;

@property (nonatomic, readonly)struct udp_pcb *pcb;

@property (nonatomic, readonly)long long activeTime;

@property (nonatomic, strong, readonly)NSString *identifier;

/// Initialize the handler
/// - Parameters:
///   - argument: init argument
///   - pcb: UDP PCB
///   - addr: local address
///   - port: local port
///   - dest_addr: remote address
///   - dest_port: remote port
-(instancetype)initWithArgument:(void *)argument pcb:(struct udp_pcb *)pcb addr:(const ip_addr_t *)addr port:(u16_t)port dest_addr:(const ip_addr_t *)dest_addr dest_port:(u16_t)dest_port identifier:(NSString *)identifier;

/// Close the socket
-(void)close:(BOOL)timeout;

@end

NS_ASSUME_NONNULL_END
