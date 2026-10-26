
#import "LPHelper.h"

@implementation LPHelper
+(NSString *)GetStateDesc:(int)state {
    switch (state) {
        case 0:
            return @"IDLE";

        case 1:
            return @"Connecting";
            
        case 2:
            return @"Connected";
            
        case 3:
            return @"Disconnected";

        default:
            break;
    }
    return @"Unknown";
}

+(NSString *)GetTCPStateDesc:(TCPState)state {
    switch (state) {
        case TCPStateConnecting:
            return @"Connecting";
        case TCPStateConnected:
            return @"Connected";
        case TCPStateWriteClosed:
            return @"WriteClosed";
        case TCPStateReceiveClosed:
            return @"ReceiveClosed";
        case TCPStateClosing:
            return @"Closing";
        case TCPStateAborting:
            return @"Aborting";
        case TCPStateClosed:
            return @"Closed";
        case TCPStateError:
            return @"Errored";
        default:
            break;
    }
    return @"Unknown";
}

@end
