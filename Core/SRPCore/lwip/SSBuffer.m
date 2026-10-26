
#import "SSBuffer.h"

static int64_t __flow__ = 0;

@implementation SSBuffer {
    
    NSMutableArray *_source;
    NSInteger _capaticy;
}

-(instancetype)initWithCapaticy:(NSInteger)capaticy {
    self = [super init];
    if (self) {
        _source = [NSMutableArray new];
        _capaticy = capaticy;
    }
    return self;
}

- (instancetype)init {
    return [self initWithCapaticy:-1];
}

-(NSInteger)length {
    return _source.count;
}

-(void)SendBufferList:(int8_t *)list length:(int)length {
    SSData *buf = [SSData dataWithBytes:list length:length];
    if (_capaticy != -1 && _source.count >= _capaticy) {
        SSData *x = _source[0];
        __flow__ -= x.length;
        [_source removeObjectAtIndex:0];
        [_source addObject:buf];
        __flow__ += buf.length;
        return;
    }
    [_source addObject:buf];
    __flow__ += buf.length;
}

-(void)append:(SSData *)buf {
    if (_capaticy != -1 && _source.count >= _capaticy) {
        SSData *x = _source[0];
        __flow__ -= x.length;
        [_source removeObjectAtIndex:0];
        [_source addObject:buf];
        __flow__ += buf.length;
        return;
    }
    __flow__ += buf.length;
    [_source addObject:buf];
}

-(SSData *)read {
    SSData *pop;
    if (_source.count > 0) {
        pop = _source.firstObject;
        [_source removeObjectAtIndex:0];
        __flow__ -= pop.length;
    }
    return pop;
}

-(void)insert:(SSData *)buf {
    [_source insertObject:buf atIndex:0];
    __flow__ += buf.length;
}

+(int64_t)flow {
    return __flow__;
}
@end
