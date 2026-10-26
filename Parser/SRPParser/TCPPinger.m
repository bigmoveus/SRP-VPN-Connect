
#import "TCPPinger.h"
#import <arpa/inet.h>
#import <netdb.h>
#import <netinet/in.h>
#import <sys/socket.h>
#import <unistd.h>

#include <netinet/in.h>
#include <netinet/tcp.h>


@implementation TCPPinger
{
    BOOL mTimeout;
    BOOL mDone;
}
/**
 * Check whether a string is an IP address
 **/
+ (BOOL)isValidIP:(NSString *)ipStr {
    if (nil == ipStr) {
        return NO;
    }
    NSArray *ipArray = [ipStr componentsSeparatedByString:@"."];
    if (ipArray.count == 4) {
        for (NSString *ipnumberStr in ipArray) {
            int ipnumber = [ipnumberStr intValue];
            if (!(ipnumber>=0 && ipnumber <= 255)) {
                return NO;
            }
        }
        return YES;
    }
    return NO;
}

+ (NSString *)LookupIP:(NSString *)domain {
    struct hostent *host = gethostbyname([domain UTF8String]);
    if (!host) {
        return domain;
    }
    struct in_addr sin_addr = *(struct in_addr *)host->h_addr;
    char *pp = inet_ntoa(sin_addr);
    return [NSString stringWithUTF8String:pp];
}

-(int)ping:(NSString *)node port:(int)port count:(int)count{
    int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == -1) {
        return -2;
    }
    int on = 1;
    setsockopt(sock, SOL_SOCKET, SO_NOSIGPIPE, &on, sizeof(on));
    setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (char *)&on, sizeof(on));
    
    struct timeval timeout;
    timeout.tv_sec = 5;
    timeout.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, sizeof(timeout));
    
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_len = sizeof(addr);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    
    if ([TCPPinger isValidIP:node]) {
        const char *hostaddr = [node UTF8String];
        addr.sin_addr.s_addr = inet_addr(hostaddr);
    }
    else {
        struct hostent *remoteHost = gethostbyname([node UTF8String]);
        if (!remoteHost) {
            return -3;
        }
        addr.sin_addr = *(struct in_addr *)remoteHost->h_addr;
    }
    long long begin = (long long)(NSDate.date.timeIntervalSince1970 * 1000);
    __weak TCPPinger *weakSelf = self;
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(5 * NSEC_PER_SEC)), dispatch_get_global_queue(0, 0), ^{
        __strong TCPPinger *strongSelf = weakSelf;
        if (strongSelf && !strongSelf->mDone) {
            strongSelf->mTimeout = YES;
            close(sock);
        }
    });
    int ack = connect(sock, (struct sockaddr *)&addr, sizeof(struct sockaddr));
    long long end = (long long)(NSDate.date.timeIntervalSince1970 * 1000);
    int diff = (int)(end - begin);
    if (ack < 0) {
        diff = mTimeout ? -1 : -3;
    }
    if (!mTimeout) {
        close(sock);
    }
    NSLog(@"host: %@, duraion: %@", node, @(diff));
    mDone = YES;
    return diff;
}


@end
