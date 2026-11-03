
#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@class CCCodec;

typedef enum : NSUInteger {
    CCCodecStatusIDLE,
    CCCodecStatusConnecting,
    CCCodecStatusConnected,
    CCCodecStatusDisconnected
} CCCodecStatus;


@protocol CCCodecDelegate <NSObject>

-(void)codec:(CCCodec *)codec statusDidChanged:(CCCodecStatus)status error:(nullable NSError *)error;

-(void)codec:(CCCodec *)codec read:(uint8_t *)message length:(int)length;

-(void)codec:(CCCodec *)codec write:(uint8_t *)message length:(int)length;

@end

@interface CCCodec : NSObject

@property (nonatomic, weak)id<CCCodecDelegate> delegate;

-(void)decode:(uint8_t *)message length:(int)length;

-(void)encode:(uint8_t *)message length:(int)length;

-(void)open;

-(void)close;

@end

NS_ASSUME_NONNULL_END
