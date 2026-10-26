//
//  SRProxySupportTests.m
//  SRP-VPN-ConnectTests / SRP-VPN-ConnectTestsMac
//
//  Proxy support: PAC result parsing, SOCKS5 / HTTP CONNECT wire formats,
//  profile serialization (proxy password only via Keychain reference).
//

#import <XCTest/XCTest.h>
#import "SSProxySupport.h"
#import "NodeModel.h"
#import "CheckConnectData.h"
#import "SRPKeychain.h"
#import "SSAuthCapabilities.h"

@interface SRProxySupportTests : XCTestCase
@end

@implementation SRProxySupportTests

#pragma mark - PAC result parsing

- (void)testPacDirect {
    NSArray<SSProxyHop *> *hops = [SSProxySupport hopsFromPACResultString:@"DIRECT"];
    XCTAssertEqual(hops.count, 1);
    XCTAssertEqual(hops.firstObject.type, SSProxyHopTypeDirect);
}

- (void)testPacProxyHttp {
    NSArray<SSProxyHop *> *hops = [SSProxySupport hopsFromPACResultString:@"PROXY proxy.example.com:8080"];
    XCTAssertEqual(hops.count, 1);
    XCTAssertEqual(hops.firstObject.type, SSProxyHopTypeHTTPConnect);
    XCTAssertEqualObjects(hops.firstObject.host, @"proxy.example.com");
    XCTAssertEqual(hops.firstObject.port, 8080);
}

- (void)testPacSocks5AndSocks {
    NSArray<SSProxyHop *> *hops = [SSProxySupport hopsFromPACResultString:@"SOCKS5 192.0.2.30:1080"];
    XCTAssertEqual(hops.count, 1);
    XCTAssertEqual(hops.firstObject.type, SSProxyHopTypeSOCKS5);
    XCTAssertEqualObjects(hops.firstObject.host, @"192.0.2.30");
    XCTAssertEqual(hops.firstObject.port, 1080);

    // the SOCKS keyword is also a SOCKS5 tunnel for us
    hops = [SSProxySupport hopsFromPACResultString:@"SOCKS 192.0.2.30:1080"];
    XCTAssertEqual(hops.count, 1);
    XCTAssertEqual(hops.firstObject.type, SSProxyHopTypeSOCKS5);
}

- (void)testPacFallbackOrder {
    NSArray<SSProxyHop *> *hops = [SSProxySupport hopsFromPACResultString:
        @"PROXY proxy1.example.com:8080; SOCKS5 proxy2.example.com:1080; DIRECT"];
    XCTAssertEqual(hops.count, 3);
    XCTAssertEqual(hops[0].type, SSProxyHopTypeHTTPConnect);
    XCTAssertEqualObjects(hops[0].host, @"proxy1.example.com");
    XCTAssertEqual(hops[1].type, SSProxyHopTypeSOCKS5);
    XCTAssertEqualObjects(hops[1].host, @"proxy2.example.com");
    XCTAssertEqual(hops[2].type, SSProxyHopTypeDirect);
}

- (void)testPacJunkSkipped {
    XCTAssertEqual([SSProxySupport hopsFromPACResultString:@""].count, 0);
    XCTAssertEqual([SSProxySupport hopsFromPACResultString:@"BOGUS x:1"].count, 0);
    XCTAssertEqual([SSProxySupport hopsFromPACResultString:@"PROXY noporthere"].count, 0);
    // unknown entries are skipped, known ones survive
    NSArray<SSProxyHop *> *hops = [SSProxySupport hopsFromPACResultString:@"QUIC x:1; DIRECT"];
    XCTAssertEqual(hops.count, 1);
    XCTAssertEqual(hops.firstObject.type, SSProxyHopTypeDirect);
}

#pragma mark - SOCKS5 wire format

- (void)testSocks5Greeting {
    const uint8_t noauth[] = {0x05, 0x01, 0x00};
    const uint8_t auth[] = {0x05, 0x02, 0x00, 0x02};
    XCTAssertEqualObjects([SSProxySupport socks5GreetingWithCredentials:NO],
                          [NSData dataWithBytes:noauth length:sizeof(noauth)]);
    XCTAssertEqualObjects([SSProxySupport socks5GreetingWithCredentials:YES],
                          [NSData dataWithBytes:auth length:sizeof(auth)]);
}

- (void)testSocks5AuthPacket {
    NSData *pkt = [SSProxySupport socks5AuthWithUsername:@"u" password:@"p"];
    const uint8_t expect[] = {0x01, 0x01, 'u', 0x01, 'p'};
    XCTAssertEqualObjects(pkt, [NSData dataWithBytes:expect length:sizeof(expect)]);
}

- (void)testSocks5ConnectRequest {
    NSData *pkt = [SSProxySupport socks5ConnectRequestToHost:@"vpn.example.com" port:443];
    const uint8_t *b = pkt.bytes;
    XCTAssertEqual(b[0], 0x05);
    XCTAssertEqual(b[1], 0x01);  // CONNECT
    XCTAssertEqual(b[3], 0x03);  // domain
    XCTAssertEqual(b[4], 15);    // host length
    XCTAssertEqual(b[pkt.length - 2], 443 >> 8);
    XCTAssertEqual(b[pkt.length - 1], 443 & 0xff);
}

- (void)testSocks5Replies {
    const uint8_t m0[] = {5, 0}, m2[] = {5, 2}, ht[] = {'H', 'T'};
    const uint8_t a0[] = {1, 0}, a1[] = {1, 1};
    const uint8_t c0[] = {5, 0, 0, 1}, c5[] = {5, 5, 0, 1};
    XCTAssertEqual([SSProxySupport socks5MethodFromReply:[NSData dataWithBytes:m0 length:2]], 0);
    XCTAssertEqual([SSProxySupport socks5MethodFromReply:[NSData dataWithBytes:m2 length:2]], 2);
    XCTAssertEqual([SSProxySupport socks5MethodFromReply:[NSData dataWithBytes:ht length:2]], -1);
    XCTAssertTrue([SSProxySupport socks5AuthSucceeded:[NSData dataWithBytes:a0 length:2]]);
    XCTAssertFalse([SSProxySupport socks5AuthSucceeded:[NSData dataWithBytes:a1 length:2]]);
    XCTAssertEqual([SSProxySupport socks5ConnectResult:[NSData dataWithBytes:c0 length:4]], 0);
    XCTAssertEqual([SSProxySupport socks5ConnectResult:[NSData dataWithBytes:c5 length:4]], 5);
    XCTAssertEqual([SSProxySupport socks5ConnectResult:[NSData dataWithBytes:ht length:2]], -1);
}

#pragma mark - HTTP CONNECT wire format

- (void)testHttpConnectRequestNoAuth {
    NSData *pkt = [SSProxySupport httpConnectRequestToHost:@"vpn.example.com" port:443
                                                  username:nil password:nil];
    NSString *req = [[NSString alloc] initWithData:pkt encoding:NSUTF8StringEncoding];
    XCTAssertTrue([req containsString:@"CONNECT vpn.example.com:443 HTTP/1.1\r\n"]);
    XCTAssertTrue([req containsString:@"Host: vpn.example.com:443\r\n"]);
    XCTAssertFalse([req containsString:@"Proxy-Authorization"]);
}

- (void)testHttpConnectRequestWithAuth {
    NSData *pkt = [SSProxySupport httpConnectRequestToHost:@"vpn.example.com" port:443
                                                  username:@"user" password:@"pass"];
    NSString *req = [[NSString alloc] initWithData:pkt encoding:NSUTF8StringEncoding];
    // dXNlcjpwYXNz = base64("user:pass")
    XCTAssertTrue([req containsString:@"Proxy-Authorization: Basic dXNlcjpwYXNz\r\n"]);
}

- (void)testHttpStatusParse {
    XCTAssertEqual([SSProxySupport httpConnectStatusFromResponse:
        [@"HTTP/1.1 200 Connection Established\r\n\r\n" dataUsingEncoding:NSUTF8StringEncoding]], 200);
    XCTAssertEqual([SSProxySupport httpConnectStatusFromResponse:
        [@"HTTP/1.0 407 Proxy Authentication Required\r\n\r\n" dataUsingEncoding:NSUTF8StringEncoding]], 407);
    XCTAssertEqual([SSProxySupport httpConnectStatusFromResponse:
        [@"HTTP/1.0 401 Unauthorized\r\n\r\n" dataUsingEncoding:NSUTF8StringEncoding]], 401);
    const uint8_t junk[] = {5, 0};
    XCTAssertEqual([SSProxySupport httpConnectStatusFromResponse:
        [NSData dataWithBytes:junk length:2]], -1);
}

#pragma mark - Profile model / persistence

- (void)testProxyModeDefaultIsNone {
    NodeModel *m = [NodeModel new];
    XCTAssertEqual(m.proxyMode, 0);
    NSDictionary *d = [CheckConnectData checkConnectParmer:m];
    XCTAssertEqualObjects(d[@"proxy_mode"], @"none");
    XCTAssertNil(d[@"proxy_host"]);
    XCTAssertNil(d[@"proxy_pass_ref"]);
}

- (void)testProxyLegacyDictMigration {
    // A stored profile without proxy keys must come back as mode None
    NSDictionary *legacy = @{
        @"type": @"sstp",
        @"username": @"u",
        @"address": @"vpn.example.com",
        @"port": @"443",
    };
    NodeModel *m = [CheckConnectData getModalForDic:legacy];
    XCTAssertEqual(m.proxyMode, 0);
    XCTAssertNil(m.proxyAddress);
    XCTAssertNil(m.pacURL);
}

- (void)testProxyManualRoundTrip {
    NodeModel *m = [NodeModel new];
    m.server = @"vpn.example.com";
    m.username = @"u";
    m.proxyMode = 1;
    m.proxyAddress = @"proxy.example.com";
    m.proxyPort = @"8080";
    m.proxyUsername = @"proxyuser";
    m.proxyPassword = @"proxy-secret";

    NSDictionary *d = [CheckConnectData checkConnectParmer:m];
    XCTAssertEqualObjects(d[@"proxy_mode"], @"manual");
    XCTAssertEqualObjects(d[@"proxy_host"], @"proxy.example.com");
    XCTAssertEqualObjects(d[@"proxy_port"], @"8080");
    XCTAssertEqualObjects(d[@"proxy_user"], @"proxyuser");
    XCTAssertNotNil(d[@"proxy_pass_ref"]);
    XCTAssertNil(d[@"proxy_password"], @"proxy password must never enter the profile dict");
    // the password is in the Keychain under the ref
    XCTAssertEqualObjects([SRPKeychain passwordForKey:d[@"proxy_pass_ref"]], @"proxy-secret");

    NodeModel *r = [CheckConnectData getModalForDic:d];
    XCTAssertEqual(r.proxyMode, 1);
    XCTAssertEqualObjects(r.proxyAddress, @"proxy.example.com");
    XCTAssertEqualObjects(r.proxyPort, @"8080");
    XCTAssertEqualObjects(r.proxyUsername, @"proxyuser");
    XCTAssertEqualObjects(r.proxyPassword, @"proxy-secret");

    [SRPKeychain deletePasswordForKey:m.proxyPasswordRef];
}

- (void)testProxyAutoRoundTrip {
    NodeModel *m = [NodeModel new];
    m.proxyMode = 2;
    m.pacURL = @"https://example.com/proxy.pac";
    NSDictionary *d = [CheckConnectData checkConnectParmer:m];
    XCTAssertEqualObjects(d[@"proxy_mode"], @"auto");
    XCTAssertEqualObjects(d[@"pac_url"], @"https://example.com/proxy.pac");

    NodeModel *r = [CheckConnectData getModalForDic:d];
    XCTAssertEqual(r.proxyMode, 2);
    XCTAssertEqualObjects(r.pacURL, @"https://example.com/proxy.pac");
}

- (void)testProxyCapability {
    // Per-connection proxies need Network.framework iOS 17 / macOS 14;
    // the test host is much newer
    XCTAssertTrue([SSAuthCapabilities sharedCapabilities].supportsProxy);
}

@end
