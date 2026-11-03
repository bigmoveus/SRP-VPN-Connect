
#import "PDBase64.h"

@implementation PDBase64
+(NSString *)decode:(NSString *)base64EncodedString {
    NSInteger pp = base64EncodedString.length % 4;
    if (pp == 3) {
        base64EncodedString = [base64EncodedString stringByAppendingString:@"="];
    }
    else if (pp == 2) {
        base64EncodedString = [base64EncodedString stringByAppendingString:@"=="];
    }
    else if (pp == 1) {
        base64EncodedString = [base64EncodedString stringByAppendingString:@"==="];
    }
    NSData *payload = [[NSData alloc] initWithBase64EncodedString:base64EncodedString options:0];
    NSString *prefix = [[NSString alloc] initWithData:payload encoding:NSUTF8StringEncoding];
    return prefix;
}


+ (NSString *)base64EncodedStringWithWrapWidth:(NSUInteger)wrapWidth raw:(NSData *)raw
{
    if (![raw length]) return nil;
    
    NSString *encoded = nil;
    {
        switch (wrapWidth)
        {
            case 64:
            {
                return [raw base64EncodedStringWithOptions:NSDataBase64Encoding64CharacterLineLength];
            }
            case 76:
            {
                return [raw base64EncodedStringWithOptions:NSDataBase64Encoding76CharacterLineLength];
            }
            default:
            {
                encoded = [raw base64EncodedStringWithOptions:(NSDataBase64EncodingOptions)0];
            }
        }
    }
    
    if (!wrapWidth || wrapWidth >= [encoded length])
    {
        return encoded;
    }
    
    wrapWidth = (wrapWidth / 4) * 4;
    NSMutableString *result = [NSMutableString string];
    for (NSUInteger i = 0; i < [encoded length]; i+= wrapWidth)
    {
        if (i + wrapWidth >= [encoded length])
        {
            [result appendString:[encoded substringFromIndex:i]];
            break;
        }
        [result appendString:[encoded substringWithRange:NSMakeRange(i, wrapWidth)]];
        [result appendString:@"\r\n"];
    }
    
    return result;
}

+(NSString *)encode:(NSString *)raw {
    
    NSData *data = [raw dataUsingEncoding:NSUTF8StringEncoding allowLossyConversion:YES];
    return [self base64EncodedStringWithWrapWidth:0 raw:data];
    
}
@end
