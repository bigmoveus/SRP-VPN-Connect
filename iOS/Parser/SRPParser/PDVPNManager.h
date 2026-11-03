
#import <Foundation/Foundation.h>
#import <NetworkExtension/NetworkExtension.h>
#import <SRPParser/SRPParser.h>

NS_ASSUME_NONNULL_BEGIN

typedef void(^YDProviderManagerCompletion)(NETunnelProviderManager *_Nullable manager);
typedef void(^YDPingResponse)(NSString *url, long long rtt);
typedef void(^YDGetStatisticsResponse)(int64_t downloadlink, int64_t uploadlink, int64_t mdownloadlink, int64_t muploadlink);
typedef void(^YDDownloadProgress)(int64_t downloadSpeed, BOOL isDone);
typedef void(^YDUploadProgress)(int64_t uploadSpeed, BOOL isDone);


typedef void(^YDUnsafeAuthResponse)(BOOL go);

typedef void(^YDUnsafeAuthRequest)(YDUnsafeAuthResponse response);

@class YDItemInfo;

typedef enum : NSUInteger {
    YDVPNStatusIDLE = 0,
    YDVPNStatusConnecting,
    YDVPNStatusConnected,
    YDVPNStatusDisconnecting,
    YDVPNStatusDisconnected
} YDVPNStatus;


@protocol YDStorage <NSObject>

- (BOOL)setObject:(nullable NSObject<NSCoding> *)object forKey:(NSString *)key;

- (BOOL)setString:(NSString *)value forKey:(NSString *)key;

- (nullable id)getObjectOfClass:(Class)cls forKey:(NSString *)key;

- (nullable NSString *)getStringForKey:(NSString *)key;

- (void)removeValueForKey:(NSString *)key;

@end



@interface PDVPNManager : NSObject

+(void)setVPNServerAddress:(NSString *)address;

+(void)setVPNLocalizedDescription:(NSString *)description;

/// Set the app group ID used for app<->extension communication. Both processes must call this; the app should call it at launch
/// - Parameter groupId: group ID
+(void)setGroupID:(NSString *)groupId;

/// Manager
+(instancetype)sharedManager;

// App-process only; do not call from the extension
-(void)setupVPNManager;


@property (nonatomic, strong, readonly, class, nullable)NSString *mmdb;

/// UDP Socks
@property (nonatomic)BOOL udpSocks;

/// Shared manager
@property (nonatomic)BOOL shareable;

/// TCP Pings
@property (nonatomic)BOOL pingUseTcp;

/// Storage
@property (nonatomic, strong)id<YDStorage> storage;

/// Current connection status
@property (nonatomic, readonly)YDVPNStatus status;

/// Currently connected node
@property (nonatomic, strong, readonly)NSString *connectedURL;
@property (nonatomic, strong, readonly, nullable)NSString *connectedNodeID;

/// When the VPN connected
@property (nonatomic, strong, readonly)NSDate *connectedDate;

/// Engine type
@property (nonatomic)int engine;

/// Global mode; must be set before starting the VPN or switching nodes
@property (nonatomic)BOOL isGlobalMode;

/// Start a connection
/// - Parameter url: node URL
-(void)connect:(NSString *)url;

/// Connect using a server dictionary
/// - Parameter server: server info
-(BOOL)connectUsing:(NSDictionary *)server auth:(YDUnsafeAuthRequest)auth;

/// Last TLS error from the server certificate check (for the warning dialog)
@property (nonatomic, strong, readonly, nullable)NSString *lastTLSIssue;

/// Disconnect
-(void)disconnect;

/// Switch node
/// - Parameter url: node URL
-(void)changeURL:(NSString *)url;

/// Get the current custom DNS servers
-(NSArray <NSString *> *)GetDNS;

/// Remove a DNS server
/// - Parameter dns: DNS server
-(void)deleteDnsServer:(NSString *)dns;

/// Add a DNS server
/// - Parameter dns: DNS server
-(void)addDnsServer:(NSString *)dns;

/// App-process only; do not call from the extension
/// - Parameters:
///   - ips: hosts to ping
///   - response: ping response
-(void)ping:(NSArray <NSString *> *)ips response:(YDPingResponse)response;

/// TCP Ping
/// - Parameters:
///   - ips: hosts to ping
///   - response: ping results, url/RTT pairs
-(void)tcpping:(NSArray <NSString *> *)ips response:(YDPingResponse)response;

/// Add a node
/// - Parameter protocol: node URL
-(void)addProtocol:(NSString *)protocol;

/// Add subscription nodes
/// - Parameters:
///   - protocol: node URL
///   - name: subscription name
-(void)addProtocol:(NSString *)protocol name:(NSString *)name;

/// Delete a node by name
/// - Parameters:
///   - protoccol: node
///   - name: node name
-(void)deleteProtocol:(NSString *)protoccol name:(NSString *)name;

/// Delete all nodes with a given name
/// - Parameter name: node name
-(void)deleteName:(NSString *)name;

/// Get all nodes
-(NSArray <NSString *> *)allProtocols;

/// Get all nodes of a subscription
/// - Parameter name: subscription name
-(NSArray <NSString *> *)allProtocols:(NSString *)name;

/// Get all subscription names
-(NSArray <NSString *> *)allSubscriptions;

/// Send a liveness check to the extension; for debugging
-(void)echo;


-(void)getStatistics:(YDGetStatisticsResponse) response;

/// Set the routing configuration
//    [
//        {
//          "method": "direct",
//          "type": "ip",
//          "content": "192.168.9.3"
//        },
//        {
//          "method": "proxy",
//          "type": "domain",
//          "content": "www.baidu.com"
//        },
//        {
//          "method": "block",
//          "type": "ip",
//          "content": "192.168.9.3"
//        }
//    ]
/// - Parameter router: routing configuration
-(void)setRouterConfiguration:(nullable NSArray <NSDictionary *> *)router;

/// Download speed test
/// - Parameter progress: download speed stats
-(void)download:(YDDownloadProgress)progress;


/// Upload speed test
/// - Parameter progress: upload speed stats
-(void)upload:(YDUploadProgress)progress;

@end

// The interfaces below are called from the extension process
@interface PDVPNManager (Extension)

/// Extension-process only; do not call from the app
/// - Parameter ips: url list
/// - Parameter type: 0 ICMP, 1 TCP
-(void)ping:(NSArray *)ips type:(int)type;

/// Extension-process only; do not call from the app
-(void)setupExtenstionApplication;

/// Get the router configuration
-(NSArray <NSDictionary *> *)getRouterConfiguration;
@end


NS_ASSUME_NONNULL_END
