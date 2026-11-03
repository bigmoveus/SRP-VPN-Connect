
#import <SRPCore/SRPCore.h>
#import <Network/Network.h>

typedef enum : NSUInteger {
    SSTCPStateIDLE = 0,
    SSTCPStateConnecting,
    SSTCPStateConnected,
    SSTCPStateDisconnected
} SSTCPState;


typedef enum : NSUInteger {
    SSTCPSocketStateIDLE = 0,
    SSTCPSocketStateCancelling,
    SSTCPSocketStateCancelled,
} SSTCPSocketState;


NS_ASSUME_NONNULL_BEGIN

@class SSFragTLSChannel;

@interface SSTCPClient (Private)

@property (nonatomic)SSTCPState state;
@property (nonatomic)SSTCPSocketState cancelling;

/// Underlying send socket
@property (nonatomic, strong, readwrite)nw_connection_t socket;

/// Non-nil while the TLS-fragmentation channel carries the outer TLS
@property (nonatomic, strong, nullable)SSFragTLSChannel *fragChannel;

/// Called when binary data arrives
/// - Parameters:
///   - message: data
///   - buflen: data length
-(void)didReceiveMessage:(char *)message buflen:(int)buflen;

@end

NS_ASSUME_NONNULL_END
