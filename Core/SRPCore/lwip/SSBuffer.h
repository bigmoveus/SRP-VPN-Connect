
#import <Foundation/Foundation.h>
#import "SSData.h"

NS_ASSUME_NONNULL_BEGIN

@interface SSBuffer : NSObject

/// Buffer length
@property (nonatomic, readonly)NSInteger length;

@property (nonatomic, class, readonly)int64_t flow;

-(instancetype)initWithCapaticy:(NSInteger)capaticy;


/// Read binary data from the buffer
/// - Parameter length: data length
-(SSData *)read;

/// Insert data at the head
/// - Parameter buf: data
-(void)insert:(SSData *)buf;

/// Append data at the tail
/// - Parameter buf: data buffer
-(void)append:(SSData *)buf;

/// Send raw binary data
/// - Parameters:
///   - list: list of data blobs
///   - length: data length
-(void)SendBufferList:(int8_t *)list length:(int)length;

@end

NS_ASSUME_NONNULL_END
