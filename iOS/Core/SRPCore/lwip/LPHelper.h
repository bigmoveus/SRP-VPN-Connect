
#import <Foundation/Foundation.h>

typedef enum : NSUInteger {
    
    // tcpConnecting indicates the handler is still connecting remote host.
    TCPStateConnecting = 0,
    
    // tcpConnected indicates the connection has been established, handler
    // may write data to TUN, and read data from TUN.
    TCPStateConnected,
    
    // tcpWriteClosed indicates the handler has closed the writing side
    // of the connection, no more data will send to TUN, but handler can still
    // read data from TUN.
    // Can no longer write to the TUN device, but can still read from it
    TCPStateWriteClosed,
    
    // tcpReceiveClosed indicates lwIP has received a FIN segment from
    // local peer, the reading side is closed, no more data can be read
    // from TUN, but handler can still write data to TUN.
    // Can no longer read from the TUN device, but can still write to it
    TCPStateReceiveClosed,
    
    // tcpClosing indicates both reading side and writing side are closed,
    // resources deallocation will be triggered at any time in lwIP callbacks.
    TCPStateClosing,
    
    // tcpAborting indicates the connection is aborting, resources deallocation
    // will be triggered at any time in lwIP callbacks.
    TCPStateAborting,
    
    // tcpClosed indicates the connection has been closed, resources were freed.
    TCPStateClosed,
    
    // tcpErrord indicates an fatal error occured on the connection, resources
    // were freed.
    TCPStateError,
} TCPState;

NS_ASSUME_NONNULL_BEGIN

@interface LPHelper : NSObject
+(NSString *)GetStateDesc:(int)state;
+(NSString *)GetTCPStateDesc:(TCPState)state;
@end

NS_ASSUME_NONNULL_END
