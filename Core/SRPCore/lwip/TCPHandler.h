
#import <Foundation/Foundation.h>
#include "x_lwip.h"
#include "lwIP.h"
#import "x_utils.h"
#import "LPHelper.h"

#define CLOSE_AND_CLEAN close

#ifdef _WIN32
#include "win_getopt.h"
#else
#include <getopt.h>
#endif

NS_ASSUME_NONNULL_BEGIN

err_t netif_tcp_accept_callback(void *argument, struct tcp_pcb *newpcb, err_t err);

@class TCPHandler;
@class SSBuffer;

@protocol TCPHandlerDelegate <NSObject>

-(void)handler:(TCPHandler *)handler onTcpStateDidChanged:(TCPState)state;

@end

@interface TCPHandler : NSObject

/// Initialize a TCP handler shuttling data to/from the transport
/// - Parameter pcb: lwIP PCB handle
-(instancetype)initWithPCB:(struct tcp_pcb *)pcb identifier:(NSString *)identifier;

@property (nonatomic, readonly)struct tcp_pcb *pcb;

@property (nonatomic, readonly, class)int64_t refCount;

@property (nonatomic)TCPState state;

@property (nonatomic, weak)id<TCPHandlerDelegate> delegate;

@property (nonatomic, strong, readonly)NSString *identifier;

-(void)close;

-(BOOL)checkTimeout;
@end

NS_ASSUME_NONNULL_END
