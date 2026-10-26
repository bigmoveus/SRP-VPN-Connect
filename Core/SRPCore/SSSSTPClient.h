
#import <Foundation/Foundation.h>
#import <SRPCore/SRPCore.h>
#import <SRPCore/SSTCPClient.h>

NS_ASSUME_NONNULL_BEGIN


@class SSSSTPClient;

typedef enum : NSUInteger {
    SSTPPPPState_OPEN,
    SSTPPPPState_ESTABLISHED,
    SSTPPPPState_CLOSE,
} SSTPPPPState;

@protocol SSSSTPClientDelegate <SSClientDelegate>

-(void)tcpClient:(SSTCPClient *)client didChangeSSTPState:(SSTPPPPState)state;

-(void)tcpClient:(SSTCPClient *)client didReceiveIPPacket:(uint8_t *)ipPacket length:(int)length;

@end


@interface SSSSTPClient : SSTCPClient

-(void)echo;

/// Start/stop the periodic SSTP keepalive echo timer (called from the
/// state-change callback on ESTABLISHED / abort-disconnect).
-(void)startEchoTimer;
-(void)stopEchoTimer;

/// Feed the MPPE session keys (client send/recv, 32 octets each) derived by
/// a tunneled-EAP method into the SSTP Call Connected crypto binding, and
/// mark PPP authentication complete so the Connected message can be sent.
-(void)setMppeKeys:(NSData *)send recv:(NSData *)recv;

@end

NS_ASSUME_NONNULL_END
