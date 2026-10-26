//
//  SSProxyResolver.m
//  SRPCore
//

#import "SSProxyResolver.h"
#import <Network/Network.h>
#import <JavaScriptCore/JavaScriptCore.h>
#import <netdb.h>
#import <arpa/inet.h>
#import <sys/socket.h>
#import <unistd.h>

NSString * const SSProxyErrorDomain = @"SSProxyErrorDomain";

/* A single probe connection (plain TCP to the proxy) with accumulate-until
 * receive and a watchdog timeout. */
@interface SSProxyProbe : NSObject
@property (nonatomic, strong) nw_connection_t conn;
@property (nonatomic, strong) NSMutableData *buffer;
@property (nonatomic) BOOL done;
@end

@implementation SSProxyProbe
@end

@implementation SSProxyResolver

#pragma mark - errors

+ (NSError *)proxyError:(NSString *)message {
    return [NSError errorWithDomain:SSProxyErrorDomain code:-1
                           userInfo:@{NSLocalizedDescriptionKey: message}];
}

#pragma mark - entry point

+ (void)resolveMode:(NSInteger)mode
          proxyHost:(NSString *)proxyHost
          proxyPort:(NSInteger)proxyPort
       proxyUsername:(NSString *)proxyUsername
       proxyPassword:(NSString *)proxyPassword
             pacURL:(NSString *)pacURL
         targetHost:(NSString *)targetHost
         targetPort:(NSInteger)targetPort
              queue:(dispatch_queue_t)queue
         completion:(void (^)(NSArray<SSProxyHop *> *, NSError *))completion {
    void (^done)(NSArray<SSProxyHop *> *, NSError *) = ^(NSArray<SSProxyHop *> *hops, NSError *error) {
        dispatch_async(queue, ^{
            completion(hops, error);
        });
    };

    if (mode == 0) {
        done(@[[SSProxyHop new]], nil);   // DIRECT
        return;
    }

    if (mode == 1) {
        NSLog(@"[Y] Proxy mode: Manual");
        NSLog(@"[Y] Proxy server: %@:%ld", proxyHost, (long)proxyPort);
        if (proxyHost.length == 0 || proxyPort <= 0) {
            done(nil, [self proxyError:@"Proxy configuration incomplete (address and port are required)"]);
            return;
        }
        [self detectProxyProtocol:proxyHost port:proxyPort
                         username:proxyUsername password:proxyPassword
                       targetHost:targetHost targetPort:targetPort
                       completion:done];
        return;
    }

    // Auto (PAC)
    NSLog(@"[Y] Proxy mode: Auto");
    NSLog(@"[Y] PAC URL: %@", pacURL);
    NSURL *url = [NSURL URLWithString:pacURL ?: @""];
    if (url == nil || !([url.scheme isEqualToString:@"http"] || [url.scheme isEqualToString:@"https"])) {
        done(nil, [self proxyError:@"Invalid PAC configuration (the PAC URL must be a http(s) URL)"]);
        return;
    }
    NSURLSessionConfiguration *cfg = [NSURLSessionConfiguration ephemeralSessionConfiguration];
    cfg.timeoutIntervalForRequest = 15;
    NSURLSession *session = [NSURLSession sessionWithConfiguration:cfg];
    NSURLSessionDataTask *task = [session dataTaskWithURL:url
        completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
        [session invalidateAndCancel];
        if (error != nil || data.length == 0 ||
            ([response isKindOfClass:NSHTTPURLResponse.class] &&
             ((NSHTTPURLResponse *)response).statusCode != 200)) {
            done(nil, [self proxyError:@"Unable to download PAC configuration"]);
            return;
        }
        NSString *script = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
        if (script.length == 0) {
            done(nil, [self proxyError:@"Invalid PAC configuration (not a text script)"]);
            return;
        }
        NSString *result = [self evaluatePAC:script targetHost:targetHost error:&error];
        if (result == nil) {
            done(nil, error);
            return;
        }
        NSArray<SSProxyHop *> *hops = [SSProxySupport hopsFromPACResultString:result];
        if (hops.count == 0) {
            done(nil, [self proxyError:@"No usable proxy returned by PAC"]);
            return;
        }
        NSLog(@"[Y] PAC result: %@", result);
        done(hops, nil);
    }];
    [task resume];
}

#pragma mark - PAC evaluation

/* Standard PAC helper functions FindProxyForURL may call. Only the common
 * pure ones plus DNS resolution are provided. */
+ (void)installPACHelpers:(JSContext *)ctx {
    ctx[@"isPlainHostName"] = ^BOOL(NSString *host) {
        return [host rangeOfString:@"."].location == NSNotFound;
    };
    ctx[@"dnsDomainIs"] = ^BOOL(NSString *host, NSString *domain) {
        return [host hasSuffix:domain];
    };
    ctx[@"localHostOrDomainIs"] = ^BOOL(NSString *host, NSString *hostdom) {
        // exact match, or unqualified host naming the same machine
        return [host isEqualToString:hostdom] ||
               [hostdom hasPrefix:[host stringByAppendingString:@"."]];
    };
    ctx[@"shExpMatch"] = ^BOOL(NSString *str, NSString *pattern) {
        NSString *escaped = [NSRegularExpression escapedPatternForString:pattern];
        // shell glob: * and ?
        escaped = [escaped stringByReplacingOccurrencesOfString:@"\\*" withString:@".*"];
        escaped = [escaped stringByReplacingOccurrencesOfString:@"\\?" withString:@"."];
        NSRegularExpression *re = [NSRegularExpression regularExpressionWithPattern:
            [NSString stringWithFormat:@"^%@$", escaped] options:0 error:nil];
        return [re firstMatchInString:str options:0
                                range:NSMakeRange(0, str.length)] != nil;
    };
    ctx[@"dnsResolve"] = ^id(NSString *host) {
        struct addrinfo hints = {0}, *res = NULL;
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        if (getaddrinfo(host.UTF8String, NULL, &hints, &res) != 0 || res == NULL) {
            return (id)nil;
        }
        char buf[INET_ADDRSTRLEN];
        struct sockaddr_in *sin = (struct sockaddr_in *)res->ai_addr;
        const char *s = inet_ntop(AF_INET, &sin->sin_addr, buf, sizeof(buf));
        freeaddrinfo(res);
        return s ? (id)@(s) : nil;
    };
    ctx[@"isResolvable"] = ^BOOL(NSString *host) {
        struct addrinfo hints = {0}, *res = NULL;
        hints.ai_family = AF_INET;
        int rc = getaddrinfo(host.UTF8String, NULL, &hints, &res);
        if (res) freeaddrinfo(res);
        return rc == 0;
    };
    ctx[@"isInNet"] = ^BOOL(NSString *ip, NSString *network, NSString *mask) {
        struct in_addr a, n, m;
        if (inet_pton(AF_INET, ip.UTF8String, &a) != 1 ||
            inet_pton(AF_INET, network.UTF8String, &n) != 1 ||
            inet_pton(AF_INET, mask.UTF8String, &m) != 1) {
            return NO;
        }
        return (a.s_addr & m.s_addr) == (n.s_addr & m.s_addr);
    };
    ctx[@"myIpAddress"] = ^id {
        // Best effort: the local address of a UDP "connection" to a public
        // address (no traffic is sent)
        int s = socket(AF_INET, SOCK_DGRAM, 0);
        if (s < 0) return (id)nil;
        struct sockaddr_in dst = {0};
        dst.sin_family = AF_INET;
        dst.sin_port = htons(53);
        inet_pton(AF_INET, "8.8.8.8", &dst.sin_addr);
        if (connect(s, (struct sockaddr *)&dst, sizeof(dst)) != 0) {
            close(s);
            return (id)nil;
        }
        struct sockaddr_in local = {0};
        socklen_t len = sizeof(local);
        getsockname(s, (struct sockaddr *)&local, &len);
        close(s);
        char buf[INET_ADDRSTRLEN];
        const char *r = inet_ntop(AF_INET, &local.sin_addr, buf, sizeof(buf));
        return r ? (id)@(r) : nil;
    };
}

/// Run FindProxyForURL(url=https://<host>/, host) in a JavaScriptCore
/// sandbox; returns the raw result string (DIRECT / PROXY ... / SOCKS5 ...)
/// or nil with `error` set.
+ (NSString *)evaluatePAC:(NSString *)script targetHost:(NSString *)host
                    error:(NSError **)error {
    JSContext *ctx = [JSContext new];
    [self installPACHelpers:ctx];
    __block JSValue *jsError = nil;
    ctx.exceptionHandler = ^(JSContext *c, JSValue *exception) {
        jsError = exception;
    };
    [ctx evaluateScript:script];
    if (jsError != nil) {
        if (error) *error = [self proxyError:@"Invalid PAC configuration (script error)"];
        return nil;
    }
    JSValue *fn = ctx[@"FindProxyForURL"];
    if (fn == nil || fn.isUndefined) {
        if (error) *error = [self proxyError:@"Invalid PAC configuration (no FindProxyForURL function)"];
        return nil;
    }
    NSString *url = [NSString stringWithFormat:@"https://%@/", host];
    JSValue *result = [fn callWithArguments:@[url, host]];
    if (jsError != nil || result == nil || result.isUndefined || result.isNull) {
        if (error) *error = [self proxyError:@"PAC evaluation failed"];
        return nil;
    }
    NSString *str = [result toString];
    if (str.length == 0) {
        if (error) *error = [self proxyError:@"PAC evaluation failed"];
        return nil;
    }
    return str;
}

#pragma mark - manual protocol detection

/* Detection: SOCKS5 negotiation on one connection; on any failure a FRESH
 * connection retries with HTTP CONNECT. */
+ (void)detectProxyProtocol:(NSString *)host port:(NSInteger)port
                   username:(NSString *)username password:(NSString *)password
                 targetHost:(NSString *)targetHost targetPort:(NSInteger)targetPort
                 completion:(void (^)(NSArray<SSProxyHop *> *, NSError *))completion {
    [self trySOCKS5:host port:port username:username password:password
         targetHost:targetHost targetPort:targetPort
         completion:^(NSError *error) {
        if (error == nil) {
            NSLog(@"[Y] Detected proxy protocol: SOCKS5");
            SSProxyHop *hop = [SSProxyHop new];
            hop.type = SSProxyHopTypeSOCKS5;
            hop.host = host;
            hop.port = port;
            hop.username = username;
            hop.password = password;
            completion(@[hop], nil);
            return;
        }
        // SOCKS5 auth/negotiation verdicts are final — the proxy IS socks
        if ([error.domain isEqualToString:SSProxyErrorDomain] &&
            (error.code == -10 || error.code == -11 || error.code == -12)) {
            completion(nil, error);
            return;
        }
        NSLog(@"[Y] SOCKS5 negotiation did not complete (%@); retrying as HTTP CONNECT on a fresh connection",
              error.localizedDescription);
        [self tryHTTPConnect:host port:port username:username password:password
                  targetHost:targetHost targetPort:targetPort
                  completion:^(NSError *httpError) {
            if (httpError == nil) {
                NSLog(@"[Y] Detected proxy protocol: HTTP CONNECT");
                SSProxyHop *hop = [SSProxyHop new];
                hop.type = SSProxyHopTypeHTTPConnect;
                hop.host = host;
                hop.port = port;
                hop.username = username;
                hop.password = password;
                completion(@[hop], nil);
                return;
            }
            // An HTTP status (e.g. 407) proves an HTTP proxy — never
            // "unknown protocol"
            if ([httpError.domain isEqualToString:SSProxyErrorDomain] &&
                (httpError.code == -10 || httpError.code == -11 || httpError.code == -13)) {
                completion(nil, httpError);
                return;
            }
            completion(nil, [self proxyError:@"Unsupported proxy protocol (neither SOCKS5 nor HTTP CONNECT answered)"]);
        }];
    }];
}

#pragma mark - probe plumbing

+ (SSProxyProbe *)probeToHost:(NSString *)host port:(NSInteger)port
                        error:(void (^)(NSError *))onError {
    SSProxyProbe *probe = [SSProxyProbe new];
    char portStr[8];
    snprintf(portStr, sizeof(portStr), "%ld", (long)port);
    nw_endpoint_t endpoint = nw_endpoint_create_host(host.UTF8String, portStr);
    nw_parameters_t params = nw_parameters_create_secure_tcp(NW_PARAMETERS_DISABLE_PROTOCOL,
                                                             NW_PARAMETERS_DEFAULT_CONFIGURATION);
    probe.conn = nw_connection_create(endpoint, params);
    probe.buffer = [NSMutableData new];
    nw_connection_set_queue(probe.conn, dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0));
    nw_connection_set_state_changed_handler(probe.conn, ^(nw_connection_state_t state, nw_error_t error) {
        if (probe.done) return;
        if (state == nw_connection_state_failed || state == nw_connection_state_cancelled) {
            probe.done = YES;
            onError([self proxyError:@"Proxy connection failed"]);
        }
    });
    nw_connection_start(probe.conn);
    return probe;
}

/// Receive until `needed` bytes are buffered, consume them, or fail.
+ (void)probeReceive:(SSProxyProbe *)probe needed:(NSUInteger)needed
               error:(void (^)(NSError *))onError
                  ok:(void (^)(NSData *))onData {
    if (probe.buffer.length >= needed) {
        NSData *data = [probe.buffer subdataWithRange:NSMakeRange(0, needed)];
        [probe.buffer replaceBytesInRange:NSMakeRange(0, needed) withBytes:NULL length:0];
        onData(data);
        return;
    }
    nw_connection_receive(probe.conn, 1, UINT16_MAX,
        ^(dispatch_data_t content, nw_content_context_t context, bool is_complete, nw_error_t receive_error) {
        if (probe.done) return;
        if (content != nil && dispatch_data_get_size(content) > 0) {
            [probe.buffer appendData:(NSData *)content];
        }
        if (receive_error != nil) {
            probe.done = YES;
            onError([self proxyError:@"Proxy connection failed"]);
            return;
        }
        if (probe.buffer.length >= needed) {
            // Enough data — deliver even when the peer half-closed (proxies
            // like tinyproxy answer auth failures with Connection: close)
            [self probeReceive:probe needed:needed error:onError ok:onData];
            return;
        }
        if (is_complete) {
            probe.done = YES;
            onError([self proxyError:@"Proxy connection failed"]);
            return;
        }
        [self probeReceive:probe needed:needed error:onError ok:onData];
    });
}

+ (void)probeSend:(SSProxyProbe *)probe data:(NSData *)data
            error:(void (^)(NSError *))onError
               ok:(void (^)(void))onSent {
    nw_connection_send(probe.conn,
        dispatch_data_create(data.bytes, data.length, nil, DISPATCH_DATA_DESTRUCTOR_DEFAULT),
        NW_CONNECTION_DEFAULT_MESSAGE_CONTEXT, true, ^(nw_error_t error) {
        if (probe.done) return;
        if (error != nil) {
            probe.done = YES;
            onError([self proxyError:@"Proxy connection failed"]);
            return;
        }
        onSent();
    });
}

+ (void)probeClose:(SSProxyProbe *)probe {
    probe.done = YES;
    if (probe.conn != nil) {
        nw_connection_cancel(probe.conn);
    }
}

#pragma mark - SOCKS5 probe (full negotiation, then close)

/* Error codes used for verdicts that must not fall through to HTTP:
 *   -10 proxy authentication required (no credentials given)
 *   -11 proxy authentication failed (credentials rejected)
 *   -12 SOCKS5 negotiation failed (proxy understood but refused)
 *   -13 HTTP CONNECT failed with an HTTP status */
+ (void)trySOCKS5:(NSString *)host port:(NSInteger)port
         username:(NSString *)username password:(NSString *)password
       targetHost:(NSString *)targetHost targetPort:(NSInteger)targetPort
       completion:(void (^)(NSError *))completion {
    __block BOOL finished = NO;
    void (^finish)(NSError *) = ^(NSError *error) {
        if (finished) return;
        finished = YES;
        dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
            completion(error);
        });
    };
    BOOL hasCreds = username.length > 0;
    SSProxyProbe *probe = [self probeToHost:host port:port error:finish];

    // Watchdog: a silent proxy must not stall detection
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(10 * NSEC_PER_SEC)),
                   dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        if (!finished) {
            [self probeClose:probe];
            finish([self proxyError:@"SOCKS5 negotiation timed out"]);
        }
    });

    [self probeSend:probe data:[SSProxySupport socks5GreetingWithCredentials:hasCreds]
              error:finish ok:^{
        [self probeReceive:probe needed:2 error:finish ok:^(NSData *reply) {
            int method = [SSProxySupport socks5MethodFromReply:reply];
            if (method < 0) {
                finish([NSError errorWithDomain:SSProxyErrorDomain code:-2 userInfo:nil]);  // not SOCKS5
                return;
            }
            void (^connectStep)(void) = ^{
                [self probeSend:probe data:[SSProxySupport socks5ConnectRequestToHost:targetHost port:targetPort]
                          error:finish ok:^{
                    [self probeReceive:probe needed:4 error:finish ok:^(NSData *reply) {
                        int rep = [SSProxySupport socks5ConnectResult:reply];
                        [self probeClose:probe];
                        if (rep == 0) {
                            finish(nil);   // tunnel granted — SOCKS5 works
                        } else if (rep < 0) {
                            finish([NSError errorWithDomain:SSProxyErrorDomain code:-2 userInfo:nil]);
                        } else {
                            finish([NSError errorWithDomain:SSProxyErrorDomain code:-12
                                                   userInfo:@{NSLocalizedDescriptionKey:
                                [NSString stringWithFormat:@"SOCKS5 negotiation failed (reply code %d)", rep]}]);
                        }
                    }];
                }];
            };
            if (method == 0x00) {
                connectStep();
            } else if (method == 0x02) {
                if (!hasCreds) {
                    [self probeClose:probe];
                    finish([NSError errorWithDomain:SSProxyErrorDomain code:-10
                                           userInfo:@{NSLocalizedDescriptionKey: @"Proxy authentication required (SOCKS5)"}]);
                    return;
                }
                [self probeSend:probe data:[SSProxySupport socks5AuthWithUsername:username password:password ?: @""]
                          error:finish ok:^{
                    [self probeReceive:probe needed:2 error:finish ok:^(NSData *reply) {
                        if (![SSProxySupport socks5AuthSucceeded:reply]) {
                            [self probeClose:probe];
                            finish([NSError errorWithDomain:SSProxyErrorDomain code:-11
                                                   userInfo:@{NSLocalizedDescriptionKey: @"Proxy authentication failed (SOCKS5)"}]);
                            return;
                        }
                        connectStep();
                    }];
                }];
            } else {
                [self probeClose:probe];
                finish([NSError errorWithDomain:SSProxyErrorDomain code:-12
                                       userInfo:@{NSLocalizedDescriptionKey: @"SOCKS5 negotiation failed (no acceptable authentication method)"}]);
            }
        }];
    }];
}

#pragma mark - HTTP CONNECT probe (full CONNECT, then close)

+ (void)tryHTTPConnect:(NSString *)host port:(NSInteger)port
              username:(NSString *)username password:(NSString *)password
            targetHost:(NSString *)targetHost targetPort:(NSInteger)targetPort
            completion:(void (^)(NSError *))completion {
    __block BOOL finished = NO;
    void (^finish)(NSError *) = ^(NSError *error) {
        if (finished) return;
        finished = YES;
        dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
            completion(error);
        });
    };
    SSProxyProbe *probe = [self probeToHost:host port:port error:finish];

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(10 * NSEC_PER_SEC)),
                   dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        if (!finished) {
            [self probeClose:probe];
            finish([self proxyError:@"HTTP CONNECT timed out"]);
        }
    });

    NSData *request = [SSProxySupport httpConnectRequestToHost:targetHost port:targetPort
                                                      username:username password:password];
    [self probeSend:probe data:request error:finish ok:^{
        [self probeReceive:probe needed:12 error:finish ok:^(NSData *reply) {
            int status = [SSProxySupport httpConnectStatusFromResponse:reply];
            [self probeClose:probe];
            if (status == 200) {
                finish(nil);
            } else if (status == 407 || status == 401) {
                // 407 (RFC) — and 401 + WWW-Authenticate (tinyproxy's
                // dialect) — prove an HTTP proxy; only the credentials are
                // missing/wrong. Never an "unknown protocol".
                finish([NSError errorWithDomain:SSProxyErrorDomain
                                           code:(username.length > 0 ? -11 : -10)
                                       userInfo:@{NSLocalizedDescriptionKey:
                            username.length > 0 ? [NSString stringWithFormat:@"Proxy authentication failed (HTTP %d)", status]
                                                : [NSString stringWithFormat:@"Proxy authentication required (HTTP %d)", status]}]);
            } else if (status > 0) {
                finish([NSError errorWithDomain:SSProxyErrorDomain code:-13
                                       userInfo:@{NSLocalizedDescriptionKey:
                            [NSString stringWithFormat:@"HTTP CONNECT failed (status %d)", status]}]);
            } else {
                finish([NSError errorWithDomain:SSProxyErrorDomain code:-2 userInfo:nil]);  // not HTTP
            }
        }];
    }];
}

@end
