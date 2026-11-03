
#import "CCCodec.h"

@implementation CCCodec
-(void)decode:(uint8_t *)message length:(int)length {
    [self.delegate codec:self read:message length:length];
}

-(void)encode:(uint8_t *)message length:(int)length {
    [self.delegate codec:self write:message length:length];
}

-(void)open {
    [self.delegate codec:self statusDidChanged:(CCCodecStatusConnected) error:nil];
}

-(void)close {
    [self.delegate codec:self statusDidChanged:(CCCodecStatusDisconnected) error:nil];
}

@end
