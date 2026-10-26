//
//  SSProxyResolver.h
//  SRPCore
//
//  Resolves the proxy path to the SSTP server:
//    Manual — auto-detect SOCKS5 vs HTTP CONNECT by protocol negotiation
//             (SOCKS5 probe first; on failure a fresh TCP connection and an
//             HTTP CONNECT probe — never both on the same socket, never
//             decided by port number)
//    Auto   — download the PAC file and evaluate FindProxyForURL for
//             url=https://<sstp-host>/ host=<sstp-host>
//  The result is an ordered list of hops (PAC fallbacks in order).
//

#import <Foundation/Foundation.h>
#import <SRPCore/SSProxySupport.h>

NS_ASSUME_NONNULL_BEGIN

/// Error domain for proxy resolution/negotiation failures (kept distinct
/// from TLS and SSTP errors).
extern NSString * const SSProxyErrorDomain;

@interface SSProxyResolver : NSObject

/// Asynchronously resolve the proxy path. `queue` receives the completion.
/// mode: 0 = none (returns a single DIRECT hop), 1 = manual, 2 = auto (PAC).
+ (void)resolveMode:(NSInteger)mode
          proxyHost:(nullable NSString *)proxyHost
          proxyPort:(NSInteger)proxyPort
       proxyUsername:(nullable NSString *)proxyUsername
       proxyPassword:(nullable NSString *)proxyPassword
             pacURL:(nullable NSString *)pacURL
         targetHost:(NSString *)targetHost
         targetPort:(NSInteger)targetPort
              queue:(dispatch_queue_t)queue
         completion:(void (^)(NSArray<SSProxyHop *> * _Nullable hops,
                              NSError * _Nullable error))completion;

@end

NS_ASSUME_NONNULL_END
