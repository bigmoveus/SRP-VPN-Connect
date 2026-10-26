#import "SRPProfileLatencyTester.h"
#import "NodeModel.h"
#import <SRPParser/SRPParser.h>
#import <QuartzCore/QuartzCore.h>

@interface SRPProfileLatencyTester () {
    NSUInteger _runID;
    NSString *_activeNodeID;
    NSURLSession *_session;
    SRPProfileLatencyUpdate _update;
    dispatch_block_t _finished;
}
@end

@implementation SRPProfileLatencyTester

+ (NSArray<NSURL *> *)endpointURLs {
    return @[[NSURL URLWithString:@"https://gstatic.com/generate_204"],
             [NSURL URLWithString:@"https://connectivitycheck.gstatic.com/generate_204"]];
}

+ (NSString *)textForMilliseconds:(NSTimeInterval)milliseconds {
    return [NSString stringWithFormat:@"Ping: %.0f ms", milliseconds];
}

+ (NSString *)textForFailure:(NSError *)error {
    return error.domain == NSURLErrorDomain && error.code == NSURLErrorTimedOut ? @"Timeout" : @"Failed";
}

+ (BOOL)isSuccessfulResponse:(NSURLResponse *)response error:(NSError *)error {
    return error == nil && [response isKindOfClass:NSHTTPURLResponse.class] &&
           ((NSHTTPURLResponse *)response).statusCode == 204;
}

- (void)measureProfile:(NodeModel *)profile
                update:(SRPProfileLatencyUpdate)update
              finished:(dispatch_block_t)finished {
    if (!NSThread.isMainThread) {
        dispatch_async(dispatch_get_main_queue(), ^{
            [self measureProfile:profile update:update finished:finished];
        });
        return;
    }
    if (profile.nodeId.length == 0) {
        if (finished) finished();
        return;
    }
    [self cancel];
    NSUInteger runID = ++_runID;
    _activeNodeID = [profile.nodeId copy];
    _update = [update copy];
    _finished = [finished copy];
    _update(_activeNodeID, @"Testing…");
    [self probeEndpointAtIndex:0 runID:runID];
}

- (void)probeEndpointAtIndex:(NSUInteger)endpointIndex runID:(NSUInteger)runID {
    if (runID != _runID) return;
    if (endpointIndex >= self.class.endpointURLs.count) {
        [self finishWithText:[self.class textForFailure:nil] runID:runID];
        return;
    }
    NSURLSessionConfiguration *configuration = NSURLSessionConfiguration.ephemeralSessionConfiguration;
    configuration.timeoutIntervalForRequest = 10;
    configuration.timeoutIntervalForResource = 15;
    configuration.requestCachePolicy = NSURLRequestReloadIgnoringLocalCacheData;
    _session = [NSURLSession sessionWithConfiguration:configuration];
    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:self.class.endpointURLs[endpointIndex]];
    request.cachePolicy = NSURLRequestReloadIgnoringLocalCacheData;
    request.HTTPMethod = @"GET";
    [request setValue:@"no-cache" forHTTPHeaderField:@"Cache-Control"];
    NSTimeInterval started = CACurrentMediaTime();
    __weak typeof(self) weakSelf = self;
    NSURLSessionDataTask *task = [_session dataTaskWithRequest:request
                                            completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
        dispatch_async(dispatch_get_main_queue(), ^{
            SRPProfileLatencyTester *strongSelf = weakSelf;
            if (!strongSelf || runID != strongSelf->_runID) return;
            [strongSelf->_session finishTasksAndInvalidate];
            strongSelf->_session = nil;
            if (PDVPNManager.sharedManager.status != YDVPNStatusConnected) {
                [strongSelf cancel];
            } else if ([strongSelf.class isSuccessfulResponse:response error:error]) {
                NSTimeInterval milliseconds = (CACurrentMediaTime() - started) * 1000;
                [strongSelf finishWithText:[strongSelf.class textForMilliseconds:milliseconds] runID:runID];
            } else if (endpointIndex + 1 < strongSelf.class.endpointURLs.count) {
                [strongSelf probeEndpointAtIndex:endpointIndex + 1 runID:runID];
            } else {
                [strongSelf finishWithText:[strongSelf.class textForFailure:error] runID:runID];
            }
        });
    }];
    [task resume];
}

- (void)finishWithText:(NSString *)text runID:(NSUInteger)runID {
    if (runID != _runID) return;
    _update(_activeNodeID, text);
    [self cancel];
}

- (void)cancel {
    if (!NSThread.isMainThread) {
        dispatch_async(dispatch_get_main_queue(), ^{ [self cancel]; });
        return;
    }
    _runID += 1;
    [_session invalidateAndCancel];
    _session = nil;
    _activeNodeID = nil;
    _update = nil;
    dispatch_block_t finished = _finished;
    _finished = nil;
    if (finished) finished();
}

@end
