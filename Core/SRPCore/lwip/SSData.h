
#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface SSData : NSObject
@property (nonatomic, readonly, class)int64_t refCount;
@property (nonatomic, readonly, class)int64_t flow;
@property (nonatomic, readonly)const void *bytes;
@property (nonatomic, readonly)NSUInteger length;

+ (instancetype)dataWithBytes:(nullable const void *)bytes length:(NSUInteger)length;
+ (instancetype)dataWithBytesNoCopy:(void *)bytes length:(NSUInteger)length;
+ (instancetype)dataWithBytesNoCopy:(void *)bytes length:(NSUInteger)length freeWhenDone:(BOOL)b;
+ (instancetype)dataWithLength:(NSUInteger)length;
- (void)appendBytes:(const void *)bytes length:(NSUInteger)length;
- (void)appendData:(SSData *)data;
- (SSData *)subdataWithRange:(NSRange)range;
@end

NS_ASSUME_NONNULL_END
