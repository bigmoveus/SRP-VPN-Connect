//
//  SSProxySupport.h
//  SRPCore
//
//  Proxy support for the SSTP outer connection: hop model, CFNetwork PAC
//  result mapping, and the SOCKS5 / HTTP CONNECT wire-format builders and
//  parsers. Everything here is pure and network-free so it can be unit
//  tested; SSProxyResolver does the actual probing.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

typedef NS_ENUM(NSInteger, SSProxyHopType) {
    SSProxyHopTypeDirect = 0,
    SSProxyHopTypeSOCKS5,
    SSProxyHopTypeHTTPConnect,
};

/// One connection attempt: direct, or via a proxy hop. PAC fallback lists
/// map to an ordered array of hops.
@interface SSProxyHop : NSObject
@property (nonatomic) SSProxyHopType type;
@property (nonatomic, copy, nullable) NSString *host;   // nil for DIRECT
@property (nonatomic) NSInteger port;
@property (nonatomic, copy, nullable) NSString *username;  // credentials are
@property (nonatomic, copy, nullable) NSString *password;  // never logged
@end

@interface SSProxySupport : NSObject

/// Map a PAC result string ("SOCKS5 h:1080; PROXY h:8088; DIRECT") to
/// ordered hops. DIRECT, PROXY (HTTP CONNECT), SOCKS and SOCKS5 are
/// recognized (both SOCKS keywords mean a SOCKS5 tunnel); unknown entries
/// are skipped. CFNetwork's own PAC evaluation silently drops the SOCKS5
/// keyword, which is why the string is parsed here.
+ (NSArray<SSProxyHop *> *)hopsFromPACResultString:(NSString *)result;

/// SOCKS5 greeting: 05 01 00 without credentials, 05 02 00 02 with.
+ (NSData *)socks5GreetingWithCredentials:(BOOL)hasCredentials;
/// RFC 1929 username/password authentication packet.
+ (NSData *)socks5AuthWithUsername:(NSString *)username password:(NSString *)password;
/// SOCKS5 CONNECT request (domain form) for host:port.
+ (NSData *)socks5ConnectRequestToHost:(NSString *)host port:(NSInteger)port;
/// Parse the 2-byte method selection reply. Returns the chosen method
/// (0x00/0x02/0xFF...) or -1 when the reply is not SOCKS5.
+ (int)socks5MethodFromReply:(NSData *)reply;
/// Parse the RFC 1929 auth status reply; returns YES on success (00).
+ (BOOL)socks5AuthSucceeded:(NSData *)reply;
/// Parse a CONNECT reply; returns the REP field (0 = granted) or -1 when
/// the reply is not a SOCKS5 reply.
+ (int)socks5ConnectResult:(NSData *)reply;

/// HTTP CONNECT request for host:port; adds Proxy-Authorization (Basic)
/// when credentials are given. The credential bytes are only ever written
/// to the returned packet, never to logs.
+ (NSData *)httpConnectRequestToHost:(NSString *)host port:(NSInteger)port
                            username:(nullable NSString *)username
                            password:(nullable NSString *)password;
/// Parse an HTTP response (at least the status line); returns the status
/// code (200, 407, ...) or -1 when the data is not an HTTP response.
+ (int)httpConnectStatusFromResponse:(NSData *)response;

@end

NS_ASSUME_NONNULL_END
