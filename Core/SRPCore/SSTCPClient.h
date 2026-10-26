
#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

typedef enum : NSUInteger {
    SSClientStateIDLE = 0,
    SSClientStateConnecting,
    SSClientStateConnected,
    SSClientStateDisconnected,
} SSClientState;

// Protocol used for app-originated packets
typedef enum : NSUInteger {
    SSProtocolTypeTCP,
    SSProtocolTypeUDP,
    SSProtocolTypeICMP,
} SSProtocolType;

@class SSTCPClient;
@class SSProtocol;

@protocol SSClientDelegate <NSObject>

/// A message was received
/// - Parameters:
///   - client: TCP client
///   - message: message bytes
///   - length: message length
-(void)tcpClient:(SSTCPClient *)client didReceiveMessage:(uint8_t *)message length:(int)length;

/// The client state changed
/// - Parameters:
///   - client: TCP client
///   - state: connection state
-(void)tcpClient:(SSTCPClient *)client didChangeState:(SSClientState)state;
@end


@interface SSTCPClient : NSObject

/// Current client instance count
@property (nonatomic, class, readonly)long long refCount;

/// The real server address being connected to
@property (nonatomic, strong, readonly)NSString *target;

/// The real server port being connected to
@property (nonatomic, readonly)int port;

@property (nonatomic, readonly)SSProtocolType proto;

/// Proxy protocol in use; nil for direct connections
@property (nonatomic, strong, readonly, nullable)SSProtocol *protocol;

/// Client tag
@property (nonatomic, strong)NSString *tag;

/// Current connection state
@property (nonatomic)SSClientState sstate;

/// Client delegate
@property (nonatomic, weak)id<SSClientDelegate> delegate;

/// Initialize a client
/// - Parameters:
///   - target: target server
///   - port: target server port
///   - proto: transport, TCP or UDP; IPv4 by default
-(instancetype)initWithTarget:(NSString *)target port:(int)port proto:(SSProtocolType)proto;

/// Initialize a client
/// - Parameters:
///   - target: target server
///   - port: target server port
///   - proto: transport, TCP or UDP
///   - family: AF_INET or AF_INET6
-(instancetype)initWithTarget:(NSString *)target port:(int)port proto:(SSProtocolType)proto family:(int)family;

/// Send binary data
/// - Parameters:
///   - message: data bytes
///   - length: data length
-(BOOL)sendMessage:(uint8_t *)message length:(int)length;

/// Get the current connection's peer certificate hash
/// - Parameters:
///   - certificate: output buffer for the hash
///   - length: output hash length
///   - evp: 0 = sha1, 1 = sha256
-(void)getCertificate:(uint8_t *)certificate length:(int *)length evp:(int)evp;

/// When the connection failed because of the proxy layer (detection,
/// negotiation, PAC, or the proxy tunnel itself), this carries a distinct
/// human-readable reason. nil for direct/TLS/SSTP failures.
@property (nonatomic, copy, readonly, nullable)NSString *connectionError;

/// Close the connection. This is a hard close: in-flight data may be lost
-(void)close;

/// Open the connection
-(void)connect;

/// Timeout check driven by an external timer
-(void)checkTimeout;
@end

NS_ASSUME_NONNULL_END
