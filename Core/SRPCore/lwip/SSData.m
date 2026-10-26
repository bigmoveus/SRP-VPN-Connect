
#import "SSData.h"


static int64_t __flow__ = 0;
static int64_t __refCount__ = 0;

@implementation SSData {
    uint8_t *_mbytes;
    NSUInteger _capaticy;
    BOOL _mutable;
    BOOL _freeWhenDone;
}

- (instancetype)initWithBytesNoCopy:(nullable const void *)bytes length:(NSUInteger)length freeWhenDone:(BOOL)freeWhenDone {
    self = [super init];
    if (self) {
        _mbytes = (uint8_t *)bytes;
        _length = length;
        _mutable = NO;
        _freeWhenDone = freeWhenDone;
        __refCount__++;
        _capaticy = 0;
    }
    return self;
}

- (instancetype)initWithBytes:(nullable const void *)bytes length:(NSUInteger)length {
    self = [super init];
    if (self) {
        // Keep the allocation a multiple of 16
        _capaticy = length / 16 * 16 + 16;
        _mbytes = malloc(_capaticy);
        __flow__ += _capaticy;
        _length = length;
        if (bytes != NULL) {
            memcpy(_mbytes, bytes, length);
        }
        _freeWhenDone = YES;
        __refCount__++;
        _mutable = YES;
    }
    return self;
}

- (SSData *)subdataWithRange:(NSRange)range {
    return [SSData dataWithBytes:_mbytes + range.location length:range.length];
}

-(const void *)bytes {
    return _mbytes;
}

-(void)ensure:(NSUInteger)size {
    size_t final = _capaticy;
    size = size / 16 * 16 + 16;
    if (self.length + size > final) {
        final += size;
    }
    if (final != _capaticy) {
        _mbytes = realloc(_mbytes, final);
        _capaticy = final;
        __flow__ += size;
    }
}

-(void)appendBytes:(const void *)bytes length:(NSUInteger)length {
    NSAssert(_mutable == YES, @"immutable instance cannot grow");
    [self ensure:length];
    memcpy(_mbytes + _length, bytes, length);
    _length += length;
}

- (void)appendData:(SSData *)data {
    [self appendBytes:data.bytes length:data.length];
}

+(int64_t)flow {
    return __flow__;
}

+(int64_t)refCount {
    return __refCount__;
}

-(void)dealloc {
    if (_freeWhenDone) {
        free(_mbytes);
        _mbytes = NULL;
    }
    __flow__ -= _capaticy;
    __refCount__--;
}

+ (instancetype)dataWithBytes:(nullable const void *)bytes length:(NSUInteger)length {
    SSData *x = [[SSData alloc] initWithBytes:bytes length:length];
    return x;
}

+ (instancetype)dataWithLength:(NSUInteger)length {
    SSData *x = [[SSData alloc] initWithBytes:NULL length:length];
    return x;
}

+ (instancetype)dataWithBytesNoCopy:(void *)bytes length:(NSUInteger)length {
    SSData *x = [[SSData alloc] initWithBytesNoCopy:bytes length:length freeWhenDone:YES];
    return x;
}
+ (instancetype)dataWithBytesNoCopy:(void *)bytes length:(NSUInteger)length freeWhenDone:(BOOL)b {
    SSData *x = [[SSData alloc] initWithBytesNoCopy:bytes length:length freeWhenDone:b];
    return x;
}
@end
