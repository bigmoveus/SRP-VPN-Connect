
#import "SSDirectClient.h"
#import "SSTCPClient+Private.h"

@implementation SSDirectClient
-(void)setState:(SSTCPState)state {
    [super setState:state];
    self.sstate = (SSClientState)state;
    [self.delegate tcpClient:self didChangeState:self.sstate];
}

-(void)didReceiveMessage:(char *)message buflen:(int)buflen {
    [self.delegate tcpClient:self didReceiveMessage:(uint8_t *)message length:buflen];
}

@end
