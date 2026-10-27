
#import "PDVPNManager.h"
#import <SRPParser/SRPParser.h>
#import <CommonCrypto/CommonCrypto.h>
#import "SimplePing.h"
#import "TCPPinger.h"
#import <resolv.h>
#import <sys/sysctl.h>
#import <sys/time.h>
#import <sys/utsname.h>
#import <arpa/inet.h>
#import "PDBase64.h"
#import "YDURLRequestSerialization.h"

static NSString * kApplicationVPNServerAddress = @"com.md.vpn.x.work";
static NSString * kApplicationVPNLocalizedDescription = @"MDConnect";
static NSString *const kYDApplicationDNSListKey = @"kYDApplicationDNSListKey";
static NSString *__groundID__ = @"Cw21d48KFNss2DY4D.com.jf.net.extension";

typedef void(^YDFetchCompletion)(NETunnelProviderManager *manager);

@interface PDProgressSummer : NSObject
@property (nonatomic, copy)YDUploadProgress progress;
@property (nonatomic)int64_t begin;
@end

@implementation PDProgressSummer


@end

@interface PDVPNManager ()<SimplePingDelegate, NSURLSessionDelegate>

@end

@interface PDVPNManager ()
@property (nonatomic, strong)NSUserDefaults *userDefaults;
@property (nonatomic)BOOL isExtension;
@property (nonatomic)NSInteger notifier;
@property (nonatomic, strong)NSMutableDictionary *info;
@end


@implementation PDVPNManager
{
    NETunnelProviderManager *_providerManager;
    NSTimer *_durationTimer;
    NSTimer *_pingTimer;
    YDPingResponse _rsp;
    NSMutableArray *_dns;
    dispatch_queue_t _worker;
    NSLock *_lock;
    NSMutableDictionary *_cache;

    YDUnsafeAuthRequest _authHandler;
    NSString *_requestedNodeID;
    NSURLSession *_certSession;
    NSUInteger _connectionGeneration;
    BOOL _certChecked;
    BOOL _certTrusted;
}
+(instancetype)sharedManager{
    static PDVPNManager *__manager__;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        __manager__ = [[self alloc] init];
        [__manager__ configure];
    });
    return __manager__;
}

-(void)downloadMMDB{
    NSURL *url = [[NSFileManager defaultManager] containerURLForSecurityApplicationGroupIdentifier:__groundID__];
    url = [url URLByAppendingPathComponent:@"Library/mmdb"];
    NSString *dest = [NSString stringWithFormat:@"%@/country.mmdb", url.path];
    if (![[NSFileManager defaultManager] fileExistsAtPath:dest]) {
        [[NSURLSession sharedSession] downloadTaskWithURL:[NSURL URLWithString:@"https://imaodou.oss-cn-hangzhou.aliyuncs.com/GeoLite2-Country.mmdb"] completionHandler:^(NSURL * _Nullable location, NSURLResponse * _Nullable response, NSError * _Nullable error) {
            if (location) {
                NSLog(@"download success");
                [[NSFileManager defaultManager] createDirectoryAtPath:url.path withIntermediateDirectories:YES attributes:nil error:&error];
                [[NSFileManager defaultManager] moveItemAtURL:location toURL:[NSURL fileURLWithPath:dest] error:nil];
            }
            else {
                NSLog(@"download failure: %@", error);
            }
        }];
    }
}

+(NSString *)mmdb {
    NSURL *url = [[NSFileManager defaultManager] containerURLForSecurityApplicationGroupIdentifier:__groundID__];
    url = [url URLByAppendingPathComponent:@"Library/mmdb"];
    NSString *dest = [NSString stringWithFormat:@"%@/country.mmdb", url.path];
    if ([[NSFileManager defaultManager] fileExistsAtPath:dest]) {
        return dest;
    }
    return nil;
}

+ (NSString *)md5:(NSString *)content{
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    CC_MD5_CTX md5;
    CC_MD5_Init(&md5);
    NSData *fileData = [content dataUsingEncoding:NSUTF8StringEncoding];
    CC_MD5_Update(&md5, [fileData bytes], (CC_LONG)[fileData length]);
    unsigned char digest[CC_MD5_DIGEST_LENGTH];
    CC_MD5_Final(digest, &md5);
    NSString *result = [NSString stringWithFormat:@"%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
                        digest[0], digest[1],
                        digest[2], digest[3],
                        digest[4], digest[5],
                        digest[6], digest[7],
                        digest[8], digest[9],
                        digest[10], digest[11],
                        digest[12], digest[13],
                        digest[14], digest[15]];
#pragma clang diagnostic pop
    return result;
}

+(void)setVPNServerAddress:(NSString *)address {
    kApplicationVPNServerAddress = address;
}

+(void)setVPNLocalizedDescription:(NSString *)description {
    kApplicationVPNLocalizedDescription = description;
}

+(void)setGroupID:(NSString *)groupId {
    __groundID__ = groupId;
}

-(void)deleteDnsServer:(NSString *)dns {
    [_dns removeObject:dns];
    [_userDefaults setObject:_dns forKey:@"dns"];
    [_userDefaults synchronize];
}


-(void)addDnsServer:(NSString *)dns {
    [_dns addObject:dns];
    [_userDefaults setObject:_dns forKey:@"dns"];
    [_userDefaults synchronize];
}

-(NSArray <NSString *> *)GetDNS {
    return [_dns copy];
}

-(void)configure {
    _dns = [@[@"1.1.1.1", @"1.0.0.1", @"8.8.4.4", @"8.8.8.8"] mutableCopy];
    _userDefaults = [[NSUserDefaults alloc] initWithSuiteName:__groundID__];
    NSArray *dns = [_userDefaults objectForKey:@"dns"];
    if (dns) {
        _dns = [dns mutableCopy];
    }
    [_userDefaults setObject:_dns forKey:@"dns"];
    [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(connectionStatusDidChangeNotification:) name:NEVPNStatusDidChangeNotification object:nil];
    _engine = (int)[_userDefaults integerForKey:@"engine"];
    [_userDefaults addObserver:self forKeyPath:@"notifier" options:(NSKeyValueObservingOptionNew) context:nil];
    _worker = dispatch_queue_create("com.jfdream.pinger.queue", DISPATCH_QUEUE_SERIAL);
    _cache = [NSMutableDictionary new];
    _lock = [[NSLock alloc] init];
}

-(void)setEngine:(int)engine {
    _engine = engine;
    [_userDefaults setInteger:engine forKey:@"engine"];
}

-(void)setupVPNManager:(YDFetchCompletion)completion {
    [NETunnelProviderManager loadAllFromPreferencesWithCompletionHandler:^(NSArray<NETunnelProviderManager *> * _Nullable managers, NSError * _Nullable error) {
        if (managers.count == 0) {
            [self createVPNConfiguration:completion];
            if (error) {
                NSLog(@"loadAllFromPreferencesWithCompletionHandler: %@", error);
            }
            return;
        }
        [self handlePreferences:managers completion:completion];
    }];
    
}

-(void)setupVPNManager {
    [self setupVPNManager:^(NETunnelProviderManager *manager) { [self setupConnection:manager]; }];
}

-(void)setupConnection:(NETunnelProviderManager *)manager {
    _providerManager = manager;
    NEVPNConnection *connection = manager.connection;
    if (connection.status == NEVPNStatusConnected) {
        _status = YDVPNStatusConnected;
        NETunnelProviderProtocol *protocolConfiguration = (NETunnelProviderProtocol *)_providerManager.protocolConfiguration;
        NSDictionary *copy = protocolConfiguration.providerConfiguration;
        NSDictionary *configuration = copy[@"configuration"];
        _connectedURL = configuration[@"uri"];
        _connectedNodeID = configuration[@"node_id"];
        _requestedNodeID = _connectedNodeID;
        _connectedDate = [_userDefaults objectForKey:@"connectedDate"];
        [[NSNotificationCenter defaultCenter] postNotificationName:@"kApplicationVPNStatusDidChangeNotification" object:nil];
    }
}

-(void)setupExtenstionApplication {
    _isExtension = YES;
    _info = [NSMutableDictionary new];
    _userDefaults = [[NSUserDefaults alloc] initWithSuiteName:__groundID__];
    [_userDefaults setObject:NSDate.date forKey:@"connectedDate"];
}

-(void)setRouterConfiguration:(nullable NSArray <NSDictionary *> *)router {
    if (!router) {
        [_userDefaults removeObjectForKey:@"kApplicationVPNRouter"];
    }
    else {
        [_userDefaults setObject:router forKey:@"kApplicationVPNRouter"];
    }
}

-(NSArray <NSDictionary *> *)getRouterConfiguration {
    return [_userDefaults objectForKey:@"kApplicationVPNRouter"];
}

-(void)observeValueForKeyPath:(NSString *)keyPath ofObject:(id)object change:(NSDictionary<NSKeyValueChangeKey,id> *)change context:(void *)context {
    
    if ([keyPath isEqualToString:@"countOfBytesSent"]) {
        NSURLSessionTask *task = (NSURLSessionTask *)object;
        PDProgressSummer *summer = [self getSummer:task.taskIdentifier];
        if (summer) {
            int64_t now = NSDate.date.timeIntervalSince1970 * 1000;
            int64_t x = task.countOfBytesSent * 8 * 1000 / (now - summer.begin);
            BOOL isDone = task.countOfBytesExpectedToSend == task.countOfBytesSent || (now - summer.begin) >= 5000;
            if (isDone) {
                [self removeSummer:task.taskIdentifier];
            }
            if (now - summer.begin >= 5000) {
                [task cancel];
            }
            if (x > 0) {
                summer.progress(x, isDone);
            }
        }
        return;
    }
    else if ([keyPath isEqualToString:@"countOfBytesReceived"]) {
        NSURLSessionTask *task = (NSURLSessionTask *)object;
        PDProgressSummer *summer = [self getSummer:task.taskIdentifier];
        if (summer) {
            int64_t now = NSDate.date.timeIntervalSince1970 * 1000;
            int64_t x = task.countOfBytesReceived * 8 * 1000 / (now - summer.begin);
            BOOL isDone = task.countOfBytesExpectedToReceive == task.countOfBytesReceived || (now - summer.begin) >= 5000;
            if (isDone) {
                [self removeSummer:task.taskIdentifier];
            }
            if (now - summer.begin >= 5000) {
                [task cancel];
            }
            if (x > 0) {
                summer.progress(x, isDone);
            }
        }
        return;
    }
    
    NSDictionary <NSString *, NSNumber *>*vinfo = [_userDefaults objectForKey:@"vinfo"];
    if (_rsp) {
        [vinfo enumerateKeysAndObjectsUsingBlock:^(NSString * _Nonnull key, NSNumber * _Nonnull obj, BOOL * _Nonnull stop) {
            _rsp(key, obj.intValue);
        }];
    }
    NSLog(@"observeValueForKeyPath keyPath:%@ info:%@", keyPath, vinfo);
}

-(void)reenableManager:(YDFetchCompletion)complection {
    if (_providerManager) {
        if(_providerManager.enabled == NO) {
            NSLog(@"providerManager is disabled, so reenable");
            _providerManager.enabled = YES;
            [_providerManager saveToPreferencesWithCompletionHandler:^(NSError * _Nullable error) {
                if (error) {
                    NSLog(@"saveToPreferencesWithCompletionHandler:%@", error);
                    complection(nil);
                    return;
                }
                complection(_providerManager);
            }];
        } else {
            complection(_providerManager);
        }
    }
    else {
        [self setupVPNManager:^(NETunnelProviderManager *manager) {
            [self setupConnection:manager];
            complection(manager);
        }];
    }
}

// Mask URI userinfo (may contain base64 credentials) before logging
static NSString *SRPMaskedURI(NSString *uri) {
    if (uri == nil) return nil;
    NSRange schemeEnd = [uri rangeOfString:@"//"];
    NSRange atSign = [uri rangeOfString:@"@"];
    if (schemeEnd.location != NSNotFound && atSign.location != NSNotFound && atSign.location > schemeEnd.location + 1) {
        return [uri stringByReplacingCharactersInRange:NSMakeRange(schemeEnd.location + 2, atSign.location - schemeEnd.location - 2) withString:@"***"];
    }
    return uri;
}

-(void)connect:(NSString *)url {
    NSLog(@"[SRP] connect: entered, manager=%@", _providerManager ? @"exists" : @"nil");
    _connectedURL = url;
    [self reenableManager:^(NETunnelProviderManager *manager) {
        NSLog(@"[SRP] reenableManager completion: manager=%@", manager ? @"ok" : @"NIL");
        if (!manager){
            return;
        }
        NETunnelProviderSession *session = (NETunnelProviderSession *)_providerManager.connection;
        NSString *uri = url;
        NSDictionary *providerConfiguration = @{@"type":@(0), @"uri":uri, @"global":@(self.isGlobalMode), @"udp_socks":@(self.udpSocks),
                                                @"node_id":_requestedNodeID ?: @""};
        NETunnelProviderProtocol *protocolConfiguration = (NETunnelProviderProtocol *)_providerManager.protocolConfiguration;
        NSMutableDictionary *copy = protocolConfiguration.providerConfiguration.mutableCopy;
        copy[@"configuration"] = providerConfiguration;
        // Never log credentials: mask the URI userinfo before logging
        NSMutableDictionary *safeConfig = providerConfiguration.mutableCopy;
        safeConfig[@"uri"] = SRPMaskedURI(uri);
        NSLog(@"connect using: %@", safeConfig);
        protocolConfiguration.providerConfiguration = copy;
        [_providerManager saveToPreferencesWithCompletionHandler:^(NSError * _Nullable error) {
            if (error) {
                NSLog(@"saveToPreferencesWithCompletionHandler:%@", error);
                NSUserDefaults *shared = [[NSUserDefaults alloc] initWithSuiteName:__groundID__];
                [shared setObject:@{@"message": error.localizedDescription, @"date": NSDate.date} forKey:@"SRPLastError"];
                return;
            }
            NSError *startError = nil;
            [session startVPNTunnelWithOptions:providerConfiguration andReturnError:&startError];
            if (startError) {
                NSLog(@"startVPNTunnelWithOptions:%@", startError);
                NSUserDefaults *shared = [[NSUserDefaults alloc] initWithSuiteName:__groundID__];
                [shared setObject:@{@"message": startError.localizedDescription, @"date": NSDate.date} forKey:@"SRPLastError"];
            }
        }];
    }];

}

-(BOOL)connectUsing:(NSDictionary *)server auth:(YDUnsafeAuthRequest)auth {
    _requestedNodeID = server[@"node_id"];
    [_certSession invalidateAndCancel];
    _certSession = nil;
    NSUInteger generation = ++_connectionGeneration;
    // Never log credentials: redact the password before logging
    NSMutableDictionary *safeServer = server.mutableCopy;
    if (safeServer[@"password"]) safeServer[@"password"] = @"***";
    if (safeServer[@"ww_outer_secret"]) safeServer[@"ww_outer_secret"] = @"***";
    if (safeServer[@"wg_conf"]) safeServer[@"wg_conf"] = @"***";
    if (safeServer[@"wg_private_key"]) safeServer[@"wg_private_key"] = @"***";
    if (safeServer[@"wg_preshared_key"]) safeServer[@"wg_preshared_key"] = @"***";
    if (safeServer[@"ww_config"]) safeServer[@"ww_config"] = @"***";
    NSLog(@"connect>>%@", safeServer);
    // TLS pre-check with a user dialog on untrusted certificates applies to
    // all protocols: SSTP, SoftEther and OpenConnect (AnyConnect/F5/...).
    if ([server[@"type"] isEqualToString:@"sstp"] ||
        [server[@"type"] isEqualToString:@"softether"] ||
        [server[@"type"] isEqualToString:@"openconnect"]) {

        _authHandler = auth;

        NSString *address = server[@"address"];
        NSString *port = [NSString stringWithFormat:@"%@", server[@"port"]];

        // SoftEther "Hostname" override: TLS verification at connect time checks
        // this name, so probe it (if the name does not resolve, the probe errors
        // before TLS and the flow proceeds — the extension re-checks anyway).
        if ([server[@"type"] isEqualToString:@"softether"] && [server[@"hostname_override"] length] > 0) {
            address = server[@"hostname_override"];
        }

        // Allow Untrusted is on — connect without certificate verification
        BOOL allowInsecure = [server[@"allowInsecure"] boolValue];
        if (allowInsecure) {
            return [self connectDirectly:server];
        }

        _certChecked = NO;
        _certTrusted = NO;
        _lastTLSIssue = nil;

        NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:[NSString stringWithFormat:@"https://%@:%@", address, port]]];
        request.HTTPMethod = @"HEAD"; // headers only, no body download
        request.timeoutInterval = 15;

        NSURLSessionConfiguration *config = [NSURLSessionConfiguration defaultSessionConfiguration];
        NSURLSession *session = [NSURLSession sessionWithConfiguration:config delegate:self delegateQueue:nil];
        _certSession = session;

        NSURLSessionDataTask *task = [session dataTaskWithRequest:request
                                                completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
            [session finishTasksAndInvalidate];
            if (generation != self->_connectionGeneration) return;
            if (self->_certSession == session) self->_certSession = nil;
            if (error) {
                if (self->_certChecked && !self->_certTrusted && self->_lastTLSIssue) {
                    // Invalid certificate — ask the user
                    NSLog(@"❌ TLS verification failed: %@", self->_lastTLSIssue);
                    _authHandler(^(BOOL go){
                        if (go && generation == self->_connectionGeneration) {
                            // User accepted the risk — the real connection also skips verification
                            NSMutableDictionary *insecure = server.mutableCopy;
                            insecure[@"allowInsecure"] = @1;
                            [self connectDirectly:insecure];
                        }
                    });
                } else {
                    // Certificate is valid (or a network error before TLS) — continue connecting
                    [self connectDirectly:server];
                }
            } else {
                NSLog(@"HTTPS verification passed");
                [self connectDirectly:server];
            }
        }];
        [task resume];

    }
    else {
        NSLog(@"[SRP] connectUsing: non-sstp type %@ -> connectDirectly", server[@"type"]);
        BOOL r = [self connectDirectly:server];
        NSLog(@"[SRP] connectDirectly returned %d", r);
        return r;
    }
    return YES;
}

-(void)connectWaterWall:(NSDictionary *)server {
    NSArray *keys = @[@"ww_config", @"address", @"port", @"username", @"password", @"ww_probe_ip", @"ww_dns_probe_ip", @"sni",
                      @"allowInsecure", @"ww_secret_ref", @"ww_outer_secret_ref", @"wg_conf",
                      @"wg_private_key", @"wg_peer_public_key", @"wg_address",
                      @"wg_keepalive", @"log_level", @"tls_frag", @"tls_frag_first",
                      @"tls_frag_following", @"ww_fake_dns", @"ww_smart_routing", @"ww_geoip_db_path", @"ww_test_id"];
    NSMutableDictionary *configuration = [NSMutableDictionary new];
    for (NSString *key in keys) {
        if (server[key] != nil) configuration[key] = server[key];
    }
    NSDictionary *providerConfiguration = @{@"type": @(0),
                                            @"node_id": server[@"node_id"] ?: @"",
                                            @"waterwall": configuration,
                                            @"global": @(self.isGlobalMode),
                                            @"udp_socks": @(self.udpSocks)};
    [self reenableManager:^(NETunnelProviderManager *manager) {
        if (!manager) return;
        NETunnelProviderProtocol *protocolConfiguration = (NETunnelProviderProtocol *)manager.protocolConfiguration;
        NSMutableDictionary *copy = protocolConfiguration.providerConfiguration.mutableCopy;
        copy[@"configuration"] = providerConfiguration;
        protocolConfiguration.providerConfiguration = copy;
        [manager saveToPreferencesWithCompletionHandler:^(NSError *error) {
            if (error) {
                NSLog(@"saveToPreferencesWithCompletionHandler:%@", error);
                return;
            }
            NSError *startError;
            [(NETunnelProviderSession *)manager.connection startVPNTunnelWithOptions:providerConfiguration andReturnError:&startError];
            if (startError) NSLog(@"startVPNTunnelWithOptions:%@", startError);
        }];
    }];
}

-(BOOL)connectDirectly:(NSDictionary *)server {
    NSMutableString *uri = NSMutableString.new;
    if (!server[@"type"] || !server[@"username"] || !server[@"password"] || !server[@"address"] || !server[@"port"]) {
        return NO;
    }
    if ([server[@"type"] isEqualToString:@"waterwall"]) {
        [self connectWaterWall:server];
        return YES;
    }
    if ([server[@"type"] isEqualToString:@"sstp"]) {
        [uri appendString:@"sstp://"];
    }
    else if ([server[@"type"] isEqualToString:@"softether"]) {
        [uri appendString:@"softether://"];
    }
    else if ([server[@"type"] isEqualToString:@"openconnect"]) {
        [uri appendString:@"openconnect://"];
    }
    else if ([server[@"type"] isEqualToString:@"ssh"]) {
        [uri appendString:@"ssh://"];
    }
    else if ([server[@"type"] isEqualToString:@"openvpn"]) {
        [uri appendString:@"openvpn://"];
    }
    else if ([server[@"type"] isEqualToString:@"wireguard"]) {
        [uri appendString:@"wireguard://"];
    }
    else if ([server[@"type"] isEqualToString:@"amnezia"]) {
        [uri appendString:@"amnezia://"];
    }
    else if ([server[@"type"] isEqualToString:@"aether"]) {
        [uri appendString:@"aether://"];
    }
    else if ([server[@"type"] isEqualToString:@"psiphon"]) {
        [uri appendString:@"psiphon://"];
    }
    else {
        return NO;
    }
    
    NSString *up = [NSString stringWithFormat:@"%@:%@", server[@"username"], server[@"password"]];
    up = [PDBase64 encode:up];
    [uri appendFormat:@"%@", up];
    // Psiphon entries carry their own server addresses; the profile's
    // address field may be empty — keep the URI parseable regardless
    NSString *host = [server[@"address"] length] > 0 ? server[@"address"] : @"127.0.0.1";
    [uri appendFormat:@"@%@:%@?t=1", host, server[@"port"]];
    if (server[@"allowInsecure"]) {
        [uri appendFormat:@"&allowInsecure=%@", server[@"allowInsecure"]];
    }
    if (server[@"udpgw"]) {
        [uri appendFormat:@"&udpgw=%@", server[@"udpgw"]];
    }
    if (server[@"udpgw_port"]) {
        [uri appendFormat:@"&udpgw_port=%@", server[@"udpgw_port"]];
    }
    if (server[@"pap_enable"]) {
        [uri appendFormat:@"&pap_enable=%@", server[@"pap_enable"]];
    }
    if (server[@"chap_enable"]) {
        [uri appendFormat:@"&chap_enable=%@", server[@"chap_enable"]];
    }
    if (server[@"mschap_enable"]) {
        [uri appendFormat:@"&mschap_enable=%@", server[@"mschap_enable"]];
    }
    if (server[@"mschap2_enable"]) {
        [uri appendFormat:@"&mschap2_enable=%@", server[@"mschap2_enable"]];
    }
    if (server[@"eapmschapv2_enable"]) {
        [uri appendFormat:@"&eapmschapv2_enable=%@", server[@"eapmschapv2_enable"]];
    }
    if (server[@"peap_enable"]) {
        [uri appendFormat:@"&peap_enable=%@", server[@"peap_enable"]];
    }
    if (server[@"peap_require_cb"]) {
        [uri appendFormat:@"&peap_require_cb=%@", server[@"peap_require_cb"]];
    }
    if (server[@"eapttls_enable"]) {
        [uri appendFormat:@"&eapttls_enable=%@", server[@"eapttls_enable"]];
    }
    if ([server[@"eapttls_inner"] length] > 0) {
        [uri appendFormat:@"&eapttls_inner=%@", server[@"eapttls_inner"]];
    }
    if (server[@"eapteap_enable"]) {
        [uri appendFormat:@"&eapteap_enable=%@", server[@"eapteap_enable"]];
    }
    if (server[@"eap_identity_privacy"]) {
        [uri appendFormat:@"&eap_identity_privacy=%@", server[@"eap_identity_privacy"]];
    }
    if ([server[@"eap_anonymous_identity"] length] > 0) {
        NSString *anon = [server[@"eap_anonymous_identity"] stringByAddingPercentEncodingWithAllowedCharacters:NSCharacterSet.alphanumericCharacterSet];
        [uri appendFormat:@"&eap_anonymous_identity=%@", anon];
    }
    if (server[@"eap_tls13"]) {
        [uri appendFormat:@"&eap_tls13=%@", server[@"eap_tls13"]];
    }
    if (server[@"eap_disable_legacy_tls"]) {
        [uri appendFormat:@"&eap_disable_legacy_tls=%@", server[@"eap_disable_legacy_tls"]];
    }
    if (server[@"cert_auth"]) {
        [uri appendFormat:@"&cert_auth=%@", server[@"cert_auth"]];
    }
    if ([server[@"cert_key"] length] > 0) {
        // The .p12 blob itself stays in the shared Keychain; the URI carries
        // only the reference (UUID, alphanumeric+dash — no encoding needed).
        [uri appendFormat:@"&cert_ref=%@", server[@"cert_key"]];
    }
    if ([server[@"proxy_mode"] length] > 0) {
        [uri appendFormat:@"&proxy_mode=%@", server[@"proxy_mode"]];
    }
    // Only the query delimiters are encoded; hostnames keep dots/colons,
    // PAC URLs keep their structure
    NSCharacterSet *querySafe = [[NSCharacterSet characterSetWithCharactersInString:@"&=%#"] invertedSet];
    if ([server[@"proxy_host"] length] > 0) {
        [uri appendFormat:@"&proxy_host=%@", [server[@"proxy_host"] stringByAddingPercentEncodingWithAllowedCharacters:querySafe]];
    }
    if ([server[@"proxy_port"] length] > 0) {
        [uri appendFormat:@"&proxy_port=%@", server[@"proxy_port"]];
    }
    if ([server[@"proxy_user"] length] > 0) {
        [uri appendFormat:@"&proxy_user=%@", [server[@"proxy_user"] stringByAddingPercentEncodingWithAllowedCharacters:querySafe]];
    }
    if ([server[@"proxy_pass_ref"] length] > 0) {
        // The proxy password itself stays in the Keychain; only the
        // reference crosses into the URI
        [uri appendFormat:@"&proxy_pass_ref=%@", server[@"proxy_pass_ref"]];
    }
    if ([server[@"pac_url"] length] > 0) {
        [uri appendFormat:@"&pac_url=%@", [server[@"pac_url"] stringByAddingPercentEncodingWithAllowedCharacters:querySafe]];
    }
    // OPTIONS section
    if (server[@"disable_legacy_outer_tls"]) {
        [uri appendFormat:@"&disable_legacy_outer_tls=%@", server[@"disable_legacy_outer_tls"]];
    }
    if (server[@"auto_reconnect"]) {
        [uri appendFormat:@"&auto_reconnect=%@", server[@"auto_reconnect"]];
    }
    if (server[@"retry_times"]) {
        [uri appendFormat:@"&retry_times=%@", server[@"retry_times"]];
    }
    if (server[@"switch_to_wifi"]) {
        [uri appendFormat:@"&switch_to_wifi=%@", server[@"switch_to_wifi"]];
    }
    if ([server[@"on_sleep"] length] > 0) {
        [uri appendFormat:@"&on_sleep=%@", server[@"on_sleep"]];
    }
    if ([server[@"log_level"] length] > 0) {
        [uri appendFormat:@"&log_level=%@", server[@"log_level"]];
    }
    if (server[@"custom_sni_enabled"]) {
        [uri appendFormat:@"&custom_sni=%@", server[@"custom_sni_enabled"]];
    }
    if (server[@"sni"]) {
        [uri appendFormat:@"&sni=%@", server[@"sni"]];
    }
    // SoftEther-specific parameters
    if ([server[@"type"] isEqualToString:@"softether"]) {
        NSString *seAuth = server[@"se_auth_method"];
        NSString *authParam = [seAuth isEqualToString:@"radiusNT"] ? @"plain"
                            : [seAuth isEqualToString:@"certificate"] ? @"cert"
                            : [seAuth isEqualToString:@"anonymous"] ? @"anonymous"
                            : @"password";
        [uri appendFormat:@"&auth=%@", authParam];
        if ([server[@"hub"] length] > 0) {
            [uri appendFormat:@"&hub=%@", [server[@"hub"] stringByAddingPercentEncodingWithAllowedCharacters:querySafe]];
        }
        if (server[@"se_connections"]) {
            [uri appendFormat:@"&conns=%@", server[@"se_connections"]];
        }
        if (server[@"se_udp_accel"]) {
            [uri appendFormat:@"&udp_accel=%@", server[@"se_udp_accel"]];
        }
        if (server[@"se_natt"]) {
            [uri appendFormat:@"&natt=%@", server[@"se_natt"]];
        }
        if ([server[@"se_natt_hint"] length] > 0) {
            [uri appendFormat:@"&natt_hint=%@", [server[@"se_natt_hint"] stringByAddingPercentEncodingWithAllowedCharacters:querySafe]];
        }
        if ([server[@"hostname_override"] length] > 0) {
            [uri appendFormat:@"&sni=%@", [server[@"hostname_override"] stringByAddingPercentEncodingWithAllowedCharacters:querySafe]];
        }
        if ([server[@"proxy_type"] length] > 0) {
            [uri appendFormat:@"&proxy_type=%@", server[@"proxy_type"]];
        }
    }
    if ([server[@"type"] isEqualToString:@"openconnect"] && [server[@"oc_protocol"] length] > 0) {
        [uri appendFormat:@"&ocproto=%@", server[@"oc_protocol"]];
    }
    // SSH engine parameters
    if ([server[@"type"] isEqualToString:@"ssh"]) {
        if (server[@"ssh_udp"]) {
            [uri appendFormat:@"&ssh_udp=%@", server[@"ssh_udp"]];
        }
        if ([server[@"hostkey"] length] > 0) {
            [uri appendFormat:@"&hostkey=%@", [server[@"hostkey"] stringByAddingPercentEncodingWithAllowedCharacters:querySafe]];
        }
    }
    // OpenVPN engine parameters
    if ([server[@"type"] isEqualToString:@"openvpn"]) {
        if ([server[@"ovpn_profile"] length] > 0) {
            [uri appendFormat:@"&profile=%@", [server[@"ovpn_profile"] stringByAddingPercentEncodingWithAllowedCharacters:querySafe]];
        }
        if (server[@"stunnel"]) {
            [uri appendFormat:@"&stunnel=%@", server[@"stunnel"]];
        }
        if ([server[@"stunnel_host"] length] > 0) {
            [uri appendFormat:@"&stunnel_host=%@", [server[@"stunnel_host"] stringByAddingPercentEncodingWithAllowedCharacters:querySafe]];
        }
        if ([server[@"stunnel_port"] length] > 0) {
            [uri appendFormat:@"&stunnel_port=%@", server[@"stunnel_port"]];
        }
        if ([server[@"stunnel_sni"] length] > 0) {
            [uri appendFormat:@"&stunnel_sni=%@", [server[@"stunnel_sni"] stringByAddingPercentEncodingWithAllowedCharacters:querySafe]];
        }
        if ([server[@"stunnel_ca"] length] > 0) {
            [uri appendFormat:@"&stunnel_ca=%@", [server[@"stunnel_ca"] stringByAddingPercentEncodingWithAllowedCharacters:querySafe]];
        }
    }
    // TLS fragmentation (handshake splitting; for Aether only the MASQUE-H2
    // transport consumes it)
    if (([server[@"type"] isEqualToString:@"sstp"] || [server[@"type"] isEqualToString:@"openconnect"] ||
         [server[@"type"] isEqualToString:@"softether"] || [server[@"type"] isEqualToString:@"openvpn"] ||
         [server[@"type"] isEqualToString:@"aether"]) && [server[@"tls_frag"] integerValue] > 0) {
        [uri appendFormat:@"&tls_frag=%@", server[@"tls_frag"]];
        if (server[@"tls_frag_first"]) {
            [uri appendFormat:@"&tls_frag_first=%@", server[@"tls_frag_first"]];
        }
        if (server[@"tls_frag_following"]) {
            [uri appendFormat:@"&tls_frag_following=%@", server[@"tls_frag_following"]];
        }
    }
    // WireGuard engine parameters
    if ([server[@"type"] isEqualToString:@"aether"] && [server[@"ae_transport"] length] > 0) {
        [uri appendFormat:@"&ae_transport=%@", server[@"ae_transport"]];
    }
    if ([server[@"type"] isEqualToString:@"aether"] && [server[@"ae_scan"] length] > 0) {
        [uri appendFormat:@"&ae_scan=%@", server[@"ae_scan"]];
    }
    if ([server[@"type"] isEqualToString:@"aether"] && [server[@"ae_mode"] isEqualToString:@"private"] && [server[@"wg_conf"] length] > 0) {
        [uri appendFormat:@"&ae_mode=private&wg_conf=%@", [server[@"wg_conf"] stringByAddingPercentEncodingWithAllowedCharacters:querySafe]];
    }
    if ([server[@"type"] isEqualToString:@"aether"] && [server[@"ae_license"] length] > 0) {
        [uri appendFormat:@"&ae_license=%@", [server[@"ae_license"] stringByAddingPercentEncodingWithAllowedCharacters:querySafe]];
    }
    if ([server[@"type"] isEqualToString:@"aether"] && [server[@"ae_tor"] length] > 0 && ![server[@"ae_tor"] isEqualToString:@"off"]) {
        [uri appendFormat:@"&ae_tor=%@", server[@"ae_tor"]];
    }
    if ([server[@"type"] isEqualToString:@"psiphon"] && [server[@"psi_entry"] length] > 0) {
        [uri appendFormat:@"&psi_entry=%@", [server[@"psi_entry"] stringByAddingPercentEncodingWithAllowedCharacters:querySafe]];
    }
    if ([server[@"type"] isEqualToString:@"psiphon"] && [server[@"psi_protos"] length] > 0) {
        [uri appendFormat:@"&psi_protos=%@", [server[@"psi_protos"] stringByAddingPercentEncodingWithAllowedCharacters:querySafe]];
    }
    if (([server[@"type"] isEqualToString:@"wireguard"] || [server[@"type"] isEqualToString:@"amnezia"]) && [server[@"wg_conf"] length] > 0) {
        [uri appendFormat:@"&wg_conf=%@", [server[@"wg_conf"] stringByAddingPercentEncodingWithAllowedCharacters:querySafe]];
    }
    NSLog(@"[SRP] connectDirectly: uri built (%@...), calling connect:", SRPMaskedURI([uri substringToIndex:MIN(uri.length, 60)]));
    [self connect:uri];
    return YES;
}

-(void)setIsGlobalMode:(BOOL)isGlobalMode {
    if (_isGlobalMode == isGlobalMode) return;
    _isGlobalMode = isGlobalMode;
    if (self.status != YDVPNStatusConnected) {
        return;
    }
    [self reenableManager:^(NETunnelProviderManager *manager) {
        if (!manager){
            return;
        }
        NSString *uri = _connectedURL;
        NETunnelProviderSession *connection = (NETunnelProviderSession *)_providerManager.connection;
        NSDictionary *providerConfiguration = @{@"type":@(5), @"uri":uri, @"global":@(self.isGlobalMode), @"udp_socks":@(self.udpSocks)};
        NETunnelProviderProtocol *protocolConfiguration = (NETunnelProviderProtocol *)_providerManager.protocolConfiguration;
        NSMutableDictionary *copy = protocolConfiguration.providerConfiguration.mutableCopy;
        copy[@"configuration"] = providerConfiguration;
        NSMutableDictionary *safeChange = providerConfiguration.mutableCopy;
        safeChange[@"uri"] = SRPMaskedURI(providerConfiguration[@"uri"]);
        NSLog(@"changeURL using: %@", safeChange);
        protocolConfiguration.providerConfiguration = copy;
        [_providerManager saveToPreferencesWithCompletionHandler:^(NSError * _Nullable error) {
            if (error) {
                NSLog(@"saveToPreferencesWithCompletionHandler:%@", error);
            }
        }];
        [connection sendProviderMessage:[NSJSONSerialization dataWithJSONObject:providerConfiguration options:(NSJSONWritingPrettyPrinted) error:nil] returnError:nil responseHandler:^(NSData * _Nullable responseData) {
            NSString *x = [[NSString alloc] initWithData:responseData encoding:NSUTF8StringEncoding];
            NSLog(@"sendProviderMessage=>%@", x);
        }];
    }];
}
-(void)changeURL:(NSString *)uri {
    [self changeURL:uri force:NO];
}
-(void)changeURL:(NSString *)uri force:(BOOL)force{
    if ([uri isEqualToString:_connectedURL] && force == NO) {
        return;
    }
    if (self.status != YDVPNStatusConnected) {
        return;
    }
    [self reenableManager:^(NETunnelProviderManager *manager) {
        if (!manager){
            return;
        }
        _connectedURL = uri;
        NETunnelProviderSession *connection = (NETunnelProviderSession *)_providerManager.connection;
        NSDictionary *providerConfiguration = @{@"type":@(2), @"uri":uri, @"global":@(self.isGlobalMode), @"udp_socks":@(self.udpSocks)};
        NETunnelProviderProtocol *protocolConfiguration = (NETunnelProviderProtocol *)_providerManager.protocolConfiguration;
        NSMutableDictionary *copy = protocolConfiguration.providerConfiguration.mutableCopy;
        copy[@"configuration"] = providerConfiguration;
        NSMutableDictionary *safeChange = providerConfiguration.mutableCopy;
        safeChange[@"uri"] = SRPMaskedURI(providerConfiguration[@"uri"]);
        NSLog(@"changeURL using: %@", safeChange);
        protocolConfiguration.providerConfiguration = copy;
        [_providerManager saveToPreferencesWithCompletionHandler:^(NSError * _Nullable error) {
            if (error) {
                NSLog(@"saveToPreferencesWithCompletionHandler:%@", error);
            }
        }];
        [connection sendProviderMessage:[NSJSONSerialization dataWithJSONObject:providerConfiguration options:(NSJSONWritingPrettyPrinted) error:nil] returnError:nil responseHandler:^(NSData * _Nullable responseData) {
            NSString *x = [[NSString alloc] initWithData:responseData encoding:NSUTF8StringEncoding];
            NSLog(@"sendProviderMessage=>%@", x);
        }];
    }];
}

-(void)disconnect {
    _connectionGeneration += 1;
    [_certSession invalidateAndCancel];
    _certSession = nil;
    _authHandler = nil;
    _status = YDVPNStatusDisconnecting;
    NETunnelProviderSession *session = (NETunnelProviderSession *)_providerManager.connection;
    [session stopVPNTunnel];
    NSLog(@"disconnect");
}

-(void)connectionStatusDidChangeNotification:(NSNotification *)notification {
    NEVPNConnection *connection = _providerManager.connection;
    switch (connection.status) {
        case NEVPNStatusInvalid:
            _status = YDVPNStatusDisconnected;
            break;
            
        case NEVPNStatusConnected:{
            NSDictionary *configuration = ((NETunnelProviderProtocol *)_providerManager.protocolConfiguration).providerConfiguration[@"configuration"];
            NSString *nodeID = configuration[@"node_id"];
            _connectedNodeID = nodeID.length > 0 ? nodeID : _requestedNodeID;
            _status = YDVPNStatusConnected;
            _connectedDate = NSDate.date;
        }
            break;
            
        case NEVPNStatusConnecting: {
            _status = YDVPNStatusConnecting;
        }
            break;
            
        case NEVPNStatusDisconnected:{
            _status = YDVPNStatusDisconnected;
        }
            break;
            
        case NEVPNStatusReasserting:{
            _status = YDVPNStatusDisconnected;
        }
            break;
        case NEVPNStatusDisconnecting: {
            _status = YDVPNStatusDisconnecting;
        }
            break;
            
        default:
            break;
    }
    [[NSNotificationCenter defaultCenter] postNotificationName:@"kApplicationVPNStatusDidChangeNotification" object:nil];
}

- (void)handlePreferences:(NSArray<NETunnelProviderManager *> * _Nullable)managers completion:(YDProviderManagerCompletion)completion{
    NETunnelProviderManager *manager;
    for (NETunnelProviderManager *item in managers) {
        if ([item.localizedDescription isEqualToString:kApplicationVPNLocalizedDescription]) {
            manager = item;
            break;
        }
    }
    if (manager.enabled == NO) {
        manager.enabled = YES;
        [manager saveToPreferencesWithCompletionHandler:^(NSError * _Nullable error) {
            completion(manager);
        }];
    }
    else {
        completion(manager);
    }
}

- (void)createVPNConfiguration:(YDProviderManagerCompletion)completion {
        
    NETunnelProviderManager *manager = [NETunnelProviderManager new];
    NETunnelProviderProtocol *protocolConfiguration = [NETunnelProviderProtocol new];
    
    protocolConfiguration.serverAddress = kApplicationVPNServerAddress;
    
    // providerConfiguration may carry custom data
    protocolConfiguration.providerConfiguration = @{};
    manager.protocolConfiguration = protocolConfiguration;

    manager.localizedDescription = kApplicationVPNLocalizedDescription;
    manager.enabled = YES;
    [manager saveToPreferencesWithCompletionHandler:^(NSError * _Nullable error) {
        if (error) {
            NSLog(@"saveToPreferencesWithCompletionHandler:%@", error);
            completion(nil);
            return;
        }
        [manager loadFromPreferencesWithCompletionHandler:^(NSError * _Nullable error) {
            
            if (error) {
                NSLog(@"loadFromPreferencesWithCompletionHandler:%@", error);
                completion(nil);
            }
            else {
                completion(manager);
            }
        }];
    }];
}

-(void)pingInHost:(NSArray<NSString *> *)ips response:(YDPingResponse)response {
    NSMutableArray *pings = NSMutableArray.new;
    [ips enumerateObjectsUsingBlock:^(NSString * _Nonnull obj, NSUInteger idx, BOOL * _Nonnull stop) {
        NSDictionary *protocol = [PDParser parseURI:obj];
        NSString *address = protocol[@"address"];
        SimplePing *ping = [[SimplePing alloc] initWithHostName:address];
        ping.delegate = self;
        ping.tag = obj;
        ping.response = response;
        [pings addObject:ping];
    }];
    NSLog(@"schedule host: %ld", pings.count);
    [self schedule:pings];
}

-(void)tcpping:(NSArray <NSString *> *)ips response:(YDPingResponse)response {
    if (self.status == YDVPNStatusConnected) {
        [self pingInTunnel:ips type:1 response:response];
    }
    else {
        dispatch_async(_worker, ^{
            [ips enumerateObjectsUsingBlock:^(NSString * _Nonnull obj, NSUInteger idx, BOOL * _Nonnull stop) {
                NSDictionary *info = [PDParser parseURI:obj];
                if (info) {
                    TCPPinger *pinger = [[TCPPinger alloc] init];
                    int rtt = [pinger ping:info[@"address"] port:(int)[info[@"port"] integerValue] count:1];
                    dispatch_async(dispatch_get_main_queue(), ^{
                        response(obj, rtt);
                    });
                }
                else {
                    dispatch_async(dispatch_get_main_queue(), ^{
                        response(obj, -3);
                    });
                }
            }];
        });
    }
}

-(void)schedule:(NSMutableArray <SimplePing *>*)pings{
    [pings enumerateObjectsUsingBlock:^(SimplePing * _Nonnull obj, NSUInteger idx, BOOL * _Nonnull stop) {
        [obj start];
    }];
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(5 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        [pings enumerateObjectsUsingBlock:^(SimplePing * _Nonnull obj, NSUInteger idx, BOOL * _Nonnull stop) {
            [obj stop];
            if (self.isExtension) {
                if (obj.rtt == 0) {
                    [self.info setObject:@(-1) forKey:obj.tag];
                    [self.userDefaults setObject:self.info forKey:@"vinfo"];
                    [self.userDefaults setObject:@(++self.notifier) forKey:@"notifier"];
                }
                NSLog(@"ping timeout: %@", obj.hostName);
                return;
            }
            if (obj.rtt == 0) {
                obj.response(obj.tag, -1);
                NSLog(@"ping timeout: %@", obj.hostName);
            }
        }];
    });
}

#pragma mark SimplePingDelegate - begin
- (void)simplePing:(SimplePing *)pinger didStartWithAddress:(NSData *)address {
    long long now = (NSDate.date.timeIntervalSince1970 * 1000);
    NSData *echo = [NSData dataWithBytes:&now length:8];
    pinger.begin = now;
    [pinger sendPingWithData:echo];
}

- (void)simplePing:(SimplePing *)pinger didReceivePingResponsePacket:(NSData *)packet sequenceNumber:(uint16_t)sequenceNumber {
    long long now = (NSDate.date.timeIntervalSince1970 * 1000);
    pinger.rtt = now - pinger.begin;
    if (self.isExtension) {
        [self.info setObject:@(pinger.rtt) forKey:pinger.tag];
        [self.userDefaults setObject:self.info forKey:@"vinfo"];
        [self.userDefaults setObject:@(++self.notifier) forKey:@"notifier"];
    }
    else {
        dispatch_async(dispatch_get_main_queue(), ^{
            pinger.response(pinger.tag, pinger.rtt);
        });
    }
}

-(void)simplePing:(SimplePing *)pinger didFailWithError:(nonnull NSError *)error {
    NSLog(@"didFailWithError: %@", error);
}

-(void)simplePing:(SimplePing *)pinger didFailToSendPacket:(NSData *)packet sequenceNumber:(uint16_t)sequenceNumber error:(NSError *)error {
    if (error.code == 65) {
        pinger.rtt = -3;
        if (self.isExtension) {
            [self.info setObject:@(pinger.rtt) forKey:pinger.tag];
            [self.userDefaults setObject:self.info forKey:@"vinfo"];
            [self.userDefaults setObject:@(++self.notifier) forKey:@"notifier"];
        }
        else {
            dispatch_async(dispatch_get_main_queue(), ^{
                pinger.response(pinger.tag, pinger.rtt);
            });
        }
    }
    NSLog(@"didFailToSendPacket: %@", error);
}

#pragma mark SimplePingDelegate - end

-(void)pingInTunnel:(NSArray <NSString *> *)ips type:(int)type response:(YDPingResponse)response {
    _rsp = response;
    if (!_providerManager) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.5 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            [self pingInTunnel:ips type:type response:response];
        });
    }
    else {
        NETunnelProviderSession *connection = (NETunnelProviderSession *)_providerManager.connection;
        [_providerManager saveToPreferencesWithCompletionHandler:^(NSError * _Nullable error) {
            if (error) {
                NSLog(@"saveToPreferencesWithCompletionHandler:%@", error);
            }
        }];
        NSLog(@"schedule pinger: %ld", ips.count);
        NSDictionary *echo = @{@"type":@3, @"urls":ips, @"action":@(type)};
        [connection sendProviderMessage:[NSJSONSerialization dataWithJSONObject:echo options:(NSJSONWritingPrettyPrinted) error:nil] returnError:nil responseHandler:^(NSData * _Nullable responseData) {
            NSString *x = [[NSString alloc] initWithData:responseData encoding:NSUTF8StringEncoding];
            NSLog(@"schedule pinger: %@", x);
        }];
    }
}

-(void)ping:(NSArray *)ips type:(int)type{
    if (type == 0) {
        NSMutableArray *pings = NSMutableArray.new;
        [ips enumerateObjectsUsingBlock:^(NSString * _Nonnull obj, NSUInteger idx, BOOL * _Nonnull stop) {
            NSDictionary *protocol = [PDParser parseURI:obj];
            NSString *address = protocol[@"address"];
            SimplePing *ping = [[SimplePing alloc] initWithHostName:address];
            ping.delegate = self;
            ping.tag = obj;
            [pings addObject:ping];
        }];
        [self schedule:pings];
    }
    else {
        dispatch_async(_worker, ^{
            [ips enumerateObjectsUsingBlock:^(NSString * _Nonnull obj, NSUInteger idx, BOOL * _Nonnull stop) {
                NSDictionary *info = [PDParser parseURI:obj];
                int rtt = -1;
                if (info) {
                    TCPPinger *pinger = [[TCPPinger alloc] init];
                    rtt = [pinger ping:info[@"address"] port:(int)[info[@"port"] integerValue] count:1];
                }
                [self.info setObject:@(rtt) forKey:obj];
                [self.userDefaults setObject:self.info forKey:@"vinfo"];
                [self.userDefaults setObject:@(++self.notifier) forKey:@"notifier"];
            }];
        });
    }
}


-(void)ping:(NSArray <NSString *> *)ips response:(YDPingResponse)response {
    if (self.status == YDVPNStatusConnected) {
        [self pingInTunnel:ips type:0 response:response];
    }
    else {
        [self pingInHost:ips response:response];
    }
}

-(void)addProtocol:(NSString *)protocol {
    [self addProtocol:protocol name:@"com.jfdream.vpn.default"];
}

-(void)addProtocol:(NSString *)protocol name:(NSString *)name {
    NSMutableArray *locals = [self.storage getObjectOfClass:NSMutableArray.class forKey:name];
    if (!locals) {
        locals = [NSMutableArray new];
    }
    if ([locals containsObject:protocol]) {
        return;
    }
    [locals addObject:protocol];
    [self.storage setObject:locals forKey:name];
    
    
    NSMutableArray *subscriptions = [self.storage getObjectOfClass:NSMutableArray.class forKey:@"com.jfdream.vpn.subscriptions"];
    if (!subscriptions) {
        subscriptions = [NSMutableArray new];
    }
    if (![subscriptions containsObject:name]) {
        [subscriptions addObject:name];
        [self.storage setObject:subscriptions forKey:@"com.jfdream.vpn.subscriptions"];
    }
}

-(void)deleteProtocol:(NSString *)protoccol name:(NSString *)name {
    NSMutableArray *protocols = [self.storage getObjectOfClass:NSMutableArray.class forKey:name];
    if (!protocols) {
        protocols = [NSMutableArray new];
    }
    [protocols removeObject:protoccol];
    if (protocols.count == 0) {
        [self.storage removeValueForKey:name];
        NSMutableArray *subscriptions = [self.storage getObjectOfClass:NSMutableArray.class forKey:@"com.jfdream.vpn.subscriptions"];
        if (!subscriptions) {
            subscriptions = [NSMutableArray new];
        }
        [subscriptions removeObject:name];
        [self.storage setObject:subscriptions forKey:@"com.jfdream.vpn.subscriptions"];
    }
    else {
        [self.storage setObject:protocols forKey:name];
    }
}

-(void)deleteName:(NSString *)name {
    [self.storage removeValueForKey:name];
    NSMutableArray *subscriptions = [self.storage getObjectOfClass:NSMutableArray.class forKey:@"com.jfdream.vpn.subscriptions"];
    if (!subscriptions) {
        subscriptions = [NSMutableArray new];
    }
    [subscriptions removeObject:name];
    [self.storage setObject:subscriptions forKey:@"com.jfdream.vpn.subscriptions"];
}


-(NSArray<NSString *> *)allProtocols {
    NSMutableArray <NSString *>*subscriptions = [self.storage getObjectOfClass:NSMutableArray.class forKey:@"com.jfdream.vpn.subscriptions"];
    NSMutableArray *pro = NSMutableArray.new;
    [subscriptions enumerateObjectsUsingBlock:^(NSString * _Nonnull obj, NSUInteger idx, BOOL * _Nonnull stop) {
        NSArray *protocols = [self.storage getObjectOfClass:NSArray.class forKey:obj];
        if (protocols) {
            [pro addObjectsFromArray:protocols];
        }
    }];
    return pro;
}

-(NSArray<NSString *> *)allProtocols:(NSString *)name {
    NSArray *protocols = [self.storage getObjectOfClass:NSArray.class forKey:name];
    return protocols;
}

-(NSArray <NSString *> *)allSubscriptions {
    NSMutableArray <NSString *>*subscriptions = [self.storage getObjectOfClass:NSMutableArray.class forKey:@"com.jfdream.vpn.subscriptions"];
    return subscriptions;
}


-(void)echo {
    NETunnelProviderSession *connection = (NETunnelProviderSession *)_providerManager.connection;
    if (!connection) return;
    NSDictionary *echo = @{@"type":@1};
    NSError *error;
    [connection sendProviderMessage:[NSJSONSerialization dataWithJSONObject:echo options:(NSJSONWritingPrettyPrinted) error:nil] returnError:&error responseHandler:^(NSData * _Nullable responseData) {
        NSString *x = [[NSString alloc] initWithData:responseData encoding:NSUTF8StringEncoding];
        NSLog(@"%@", x);
    }];
    if (error) {
        NSLog(@"echo sendProviderMessage: %@", error);
    }
}

-(void)getStatistics:(YDGetStatisticsResponse) response {
    NETunnelProviderSession *connection = (NETunnelProviderSession *)_providerManager.connection;
    if (!connection || _status != YDVPNStatusConnected) return response(-1, -1, -1, -1);
    NSDictionary *echo = @{@"type":@4};
    [connection sendProviderMessage:[NSJSONSerialization dataWithJSONObject:echo options:(NSJSONWritingPrettyPrinted) error:nil] returnError:nil responseHandler:^(NSData * _Nullable responseData) {
        if (responseData) {
            NSDictionary *rsp = [NSJSONSerialization JSONObjectWithData:responseData options:NSJSONReadingMutableContainers error:nil];
            int64_t downloadlink = [rsp[@"downloadlink"] longLongValue];
            int64_t uploadlink = [rsp[@"uploadlink"] longLongValue];
            int64_t mdownloadlink = [rsp[@"mdownloadlink"] longLongValue];
            int64_t muploadlink = [rsp[@"muploadlink"] longLongValue];
            return response(downloadlink, uploadlink, mdownloadlink, muploadlink);
        }
        response(-1, -1, -1, -1);
    }];
}


-(void)setSummber:(NSUInteger)identifier summer:(PDProgressSummer *)summer {
    [_lock lock];
    _cache[@(identifier)] = summer;
    [_lock unlock];
}

-(PDProgressSummer *)getSummer:(NSUInteger)identifier {
    [_lock lock];
    PDProgressSummer *summer = _cache[@(identifier)];
    [_lock unlock];
    return summer;
}

-(void)removeSummer:(NSUInteger)identifier {
    [_lock lock];
    [_cache removeObjectForKey:@(identifier)];
    [_lock unlock];
}


-(void)download:(YDDownloadProgress)progress {
    
    NSString *__download_url__ = @"http://lax-ca-us-ping.vultr.com/vultr.com.1000MB.bin";
    PDProgressSummer *summber = [[PDProgressSummer alloc] init];
    summber.progress = progress;
    summber.begin = [NSDate date].timeIntervalSince1970 * 1000;
    NSURLSessionTask *downloadTask = [[NSURLSession sharedSession] dataTaskWithURL:[NSURL URLWithString:__download_url__] completionHandler:^(NSData * _Nullable data, NSURLResponse * _Nullable response, NSError * _Nullable error) {
        if (error) {
            NSLog(@"download error:%@", error);
        }
    }];
    [self setSummber:downloadTask.taskIdentifier summer:summber];
    [downloadTask addObserver:self forKeyPath:@"countOfBytesReceived" options:(NSKeyValueObservingOptionNew) context:nil];
    [downloadTask resume];
}

-(void)upload:(YDUploadProgress)progress {
    NSError *error;
    NSString *r = [NSString stringWithFormat:@"%@/Library/upload.bin", NSHomeDirectory()];
    if (![[NSFileManager defaultManager] fileExistsAtPath:r]){
        [[NSFileManager defaultManager] createFileAtPath:r contents:nil attributes:nil];
        NSFileHandle *handle = [NSFileHandle fileHandleForWritingToURL:[NSURL fileURLWithPath:r] error:&error];
        long long t = 0;
        while (true) {
            t += 1024;
            [handle writeData:[NSMutableData dataWithLength:1024]];
            if (t >= 1024 * 1024 * 20) {
                break;
            }
        }
        [handle closeFile];
        error = nil;
    }
    
    PDProgressSummer *summber = [[PDProgressSummer alloc] init];
    summber.progress = progress;
    summber.begin = [NSDate date].timeIntervalSince1970 * 1000;
    
    CMHTTPRequestSerializer *serializer = [CMHTTPRequestSerializer serializer];
    NSMutableURLRequest *request = [serializer multipartFormRequestWithMethod:@"POST" URLString:@"https://kkcloud.co/upload.php" parameters:nil constructingBodyWithBlock:^(id<CMMultipartFormData>  _Nonnull formData) {
        [formData appendPartWithFileURL:[NSURL fileURLWithPath:r] name:@"file" error:nil];
    } error:&error];
    if (error) {
        NSLog(@"multipartFormRequestWithMethod: %@", error);
        return;
    }
    NSURLSessionDataTask *dataTask = [[NSURLSession sharedSession] dataTaskWithRequest:request completionHandler:^(NSData * _Nullable data, NSURLResponse * _Nullable response, NSError * _Nullable error) {
        if (error) {
            NSLog(@"Upload Upload Request Error: %@", error);
            return;
        }
        error = nil;
        NSString *str = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
        NSLog(@"%@", str);
        if (error) {
            NSLog(@"Upload Upload Data Error: %@", error);
            return;
        }
    }];
    [self setSummber:dataTask.taskIdentifier summer:summber];
    [dataTask addObserver:self forKeyPath:@"countOfBytesSent" options:NSKeyValueObservingOptionNew context:nil];
    [dataTask resume];
}


// Handle HTTPS authentication in the NSURLSession delegate
- (void)URLSession:(NSURLSession *)session
              didReceiveChallenge:(NSURLAuthenticationChallenge *)challenge
              completionHandler:(void (^)(NSURLSessionAuthChallengeDisposition disposition, NSURLCredential *credential))completionHandler {

    // Check for server-trust authentication
    if ([challenge.protectionSpace.authenticationMethod isEqualToString:NSURLAuthenticationMethodServerTrust]) {
        SecTrustRef serverTrust = challenge.protectionSpace.serverTrust;
        _certChecked = YES;

        CFErrorRef cfError = NULL;
        BOOL trusted = SecTrustEvaluateWithError(serverTrust, &cfError);

        if (trusted) {
            // Certificate valid — handshake verified, no need to wait for the HTTP response
            _certTrusted = YES;
            completionHandler(NSURLSessionAuthChallengeCancelAuthenticationChallenge, nil);
        } else {
            // Certificate invalid — collect error details for display
            _certTrusted = NO;
            _lastTLSIssue = [self describeTrustFailure:serverTrust
                                                 error:(__bridge NSError *)cfError
                                                  host:challenge.protectionSpace.host];
            if (cfError) {
                CFRelease(cfError);
            }
            completionHandler(NSURLSessionAuthChallengeCancelAuthenticationChallenge, nil);
        }
    } else {
        // Default handling for other authentication methods
        completionHandler(NSURLSessionAuthChallengePerformDefaultHandling, nil);
    }
}

- (NSString *)describeTrustFailure:(SecTrustRef)trust error:(NSError *)error host:(NSString *)host {
    NSMutableString *detail = [NSMutableString stringWithFormat:
        @"TLS verification on the server certificate (%@) has failed due to the following error. As such, the identity of the server can't be verified at the moment.\n\n", host];

    NSDictionary *result = CFBridgingRelease(SecTrustCopyResult(trust));
    NSArray *chain = CFBridgingRelease(SecTrustCopyCertificateChain(trust));
    NSArray *details = result[@"TrustResultDetails"];

    for (NSUInteger i = 0; i < chain.count; i++) {
        SecCertificateRef cert = (__bridge SecCertificateRef)chain[i];
        NSString *subject = CFBridgingRelease(SecCertificateCopySubjectSummary(cert)) ?: @"Unknown";
        [detail appendFormat:@"Certificate %lu \"%@\"", (unsigned long)i, subject];

        NSDictionary *certErrors = i < details.count ? details[i] : nil;
        if (certErrors.count > 0) {
            NSMutableArray *reasons = [NSMutableArray new];
            for (NSString *code in certErrors) {
                [reasons addObject:[PDVPNManager humanizeTrustError:code]];
            }
            [detail appendFormat:@" has errors: %@;", [reasons componentsJoinedByString:@"; "]];
        }
        [detail appendString:@"\n"];
    }
    if (chain.count == 0 && error) {
        [detail appendFormat:@"%@\n", error.localizedDescription];
    }

    [detail appendString:@"\nThis may indicate a server misconfiguration or an ongoing MITM attack. Do you want to trust the server certificate and continue? Choose Cancel if you are unsure."];
    return detail;
}

+ (NSString *)humanizeTrustError:(NSString *)code {
    static NSDictionary *map = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        map = @{
            @"CSSMERR_TP_NOT_TRUSTED": @"Root is not trusted",
            @"CSSMERR_TP_INVALID_ANCHOR": @"Root is not trusted",
            @"CSSMERR_TP_CERT_EXPIRED": @"Certificate has expired",
            @"CSSMERR_TP_CERT_NOT_VALID_YET": @"Certificate is not valid yet",
            @"CSSMERR_TP_HOSTNAME_MISMATCH": @"Hostname does not match the certificate",
            @"CSSMERR_TP_CERT_REVOKED": @"Certificate has been revoked",
            @"CSSMERR_TP_CERT_POLICY_INVALID": @"Certificate policy is invalid",
            @"CSSMERR_APPLETP_HOSTNAME_MISMATCH": @"Hostname does not match the certificate",
            @"CSSMERR_APPLETP_CERT_EXPIRED": @"Certificate has expired",
        };
    });
    return map[code] ?: code;
}

@end
