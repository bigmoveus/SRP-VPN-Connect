#import "SRPWaterWallChainConfig.h"

static BOOL SRPWWInteger(id value) {
    return [value isKindOfClass:NSNumber.class] && CFGetTypeID((__bridge CFTypeRef)value) != CFBooleanGetTypeID() &&
           [value doubleValue] == floor([value doubleValue]);
}

static BOOL SRPWWRange(NSDictionary *settings, NSString *key, long long minimum, long long maximum) {
    id value = settings[key];
    return SRPWWInteger(value) && [value longLongValue] >= minimum && [value longLongValue] <= maximum;
}

static BOOL SRPWWBooleans(NSDictionary *settings, NSSet *keys) {
    for (NSString *key in keys) {
        id value = settings[key];
        if (value != nil && (![value isKindOfClass:NSNumber.class] || CFGetTypeID((__bridge CFTypeRef)value) != CFBooleanGetTypeID())) return NO;
    }
    return YES;
}

static BOOL SRPWWBoolean(id value) {
    return [value isKindOfClass:NSNumber.class] && CFGetTypeID((__bridge CFTypeRef)value) == CFBooleanGetTypeID();
}

static NSString *SRPWWALPNError(id value) {
    if (![value isKindOfClass:NSArray.class]) return @"alpns must be an array of unique nonempty strings.";
    NSMutableSet *seen = [NSMutableSet new];
    NSUInteger totalBytes = 0;
    for (id item in (NSArray *)value) {
        if (![item isKindOfClass:NSString.class] || [item lengthOfBytesUsingEncoding:NSUTF8StringEncoding] == 0 ||
            [item lengthOfBytesUsingEncoding:NSUTF8StringEncoding] > 255 || [seen containsObject:item]) {
            return @"Each alpns entry must be a unique nonempty string of at most 255 UTF-8 bytes.";
        }
        [seen addObject:item];
        totalBytes += [item lengthOfBytesUsingEncoding:NSUTF8StringEncoding] + 1;
        if (totalBytes > 65533) return @"alpns exceeds the encoded 65533-byte limit.";
    }
    return nil;
}

static NSString *SRPWWFakeDNSError(NSString *key, id value) {
    if (SRPWWBoolean(value)) return nil;
    if (![value isKindOfClass:NSDictionary.class]) return [NSString stringWithFormat:@"%@ must be a boolean or an object.", key];
    NSSet *allowed = [NSSet setWithArray:@[@"enabled", @"address", @"network", @"netmask", @"port", @"cache-size", @"ttl"]];
    for (NSString *nestedKey in (NSDictionary *)value) {
        if (![allowed containsObject:nestedKey]) return [NSString stringWithFormat:@"Unsupported %@ setting: %@", key, nestedKey];
    }
    if (value[@"enabled"] != nil && !SRPWWBoolean(value[@"enabled"])) return [NSString stringWithFormat:@"%@.enabled must be a boolean.", key];
    for (NSString *nestedKey in @[@"address", @"network", @"netmask"]) {
        if (value[nestedKey] != nil && ![value[nestedKey] isKindOfClass:NSString.class]) {
            return [NSString stringWithFormat:@"%@.%@ must be a string.", key, nestedKey];
        }
    }
    NSArray *ranges = @[@[@"port", @1, @65535], @[@"cache-size", @1, @262144], @[@"ttl", @0, @2147483647]];
    for (NSArray *rule in ranges) {
        if (value[rule[0]] != nil && !SRPWWRange(value, rule[0], [rule[1] longLongValue], [rule[2] longLongValue])) {
            return [NSString stringWithFormat:@"%@.%@ has an invalid value or range.", key, rule[0]];
        }
    }
    return nil;
}

static NSString *SRPWWFragmentError(id value) {
    if (![value isKindOfClass:NSDictionary.class] || [value count] == 0) return @"fragment must be a nonempty object.";
    NSSet *allowed = [NSSet setWithArray:@[@"mode", @"count", @"duration-ms", @"bypass_chance", @"wait-for-est",
                                           @"tls-hello-fragment", @"tls-hello-timeout-ms", @"cuts"]];
    for (NSString *key in (NSDictionary *)value) {
        if (![allowed containsObject:key]) return [NSString stringWithFormat:@"Unsupported fragment setting: %@", key];
    }
    id mode = value[@"mode"];
    if (![mode isKindOfClass:NSString.class] || ![@[@"counter", @"timed"] containsObject:mode]) return @"fragment.mode must be counter or timed.";
    BOOL counter = [mode isEqualToString:@"counter"];
    NSString *counterKey = counter ? @"count" : @"duration-ms";
    NSString *forbiddenKey = counter ? @"duration-ms" : @"count";
    if (value[counterKey] == nil || !SRPWWRange(value, counterKey, 0, 4294967295LL)) {
        return [NSString stringWithFormat:@"fragment.%@ has an invalid value or range.", counterKey];
    }
    if (value[forbiddenKey] != nil) return [NSString stringWithFormat:@"fragment.%@ is not valid in %@ mode.", forbiddenKey, mode];
    if (value[@"bypass_chance"] != nil && !SRPWWRange(value, @"bypass_chance", 0, 100)) return @"fragment.bypass_chance has an invalid value or range.";
    for (NSString *key in @[@"wait-for-est", @"tls-hello-fragment"]) {
        if (value[key] != nil && !SRPWWBoolean(value[key])) return [NSString stringWithFormat:@"fragment.%@ must be a boolean.", key];
    }
    if (value[@"tls-hello-timeout-ms"] != nil &&
        (![value[@"tls-hello-fragment"] boolValue] || !SRPWWRange(value, @"tls-hello-timeout-ms", 1, 4294967295LL))) {
        return @"fragment.tls-hello-timeout-ms requires TLS fragmentation and an integer from 1 to 4294967295.";
    }
    id cuts = value[@"cuts"];
    if (![cuts isKindOfClass:NSArray.class] || [cuts count] > 64) return @"fragment.cuts must be an array of at most 64 entries.";
    long long previousOffset = 0;
    for (id cut in (NSArray *)cuts) {
        if (![cut isKindOfClass:NSArray.class] || [cut count] != 3 || !SRPWWInteger(cut[0]) || !SRPWWInteger(cut[1]) || !SRPWWInteger(cut[2])) {
            return @"Each fragment cut must be [offset, delay_ms, chance_percent] with integer values.";
        }
        long long offset = [cut[0] longLongValue];
        long long delay = [cut[1] longLongValue];
        long long chance = [cut[2] longLongValue];
        if (offset <= previousOffset || offset < 1 || offset > 4294967295LL) return @"fragment cut offsets must be strictly increasing integers from 1 to 4294967295.";
        if (delay < 0 || delay > 4294967295LL) return @"fragment cut delays must be integers from 0 to 4294967295.";
        if (chance < 0 || chance > 100) return @"fragment cut chances must be integers from 0 to 100.";
        previousOffset = offset;
    }
    return nil;
}

static BOOL SRPWWUUID(NSString *value) {
    if (![value isKindOfClass:NSString.class]) return NO;
    NSString *hex = value;
    if (value.length == 36) {
        for (NSNumber *position in @[@8, @13, @18, @23]) {
            if ([value characterAtIndex:position.unsignedIntegerValue] != '-') return NO;
        }
        hex = [value stringByReplacingOccurrencesOfString:@"-" withString:@""];
    }
    if (hex.length != 32) return NO;
    NSCharacterSet *nonHex = [NSCharacterSet characterSetWithCharactersInString:@"0123456789abcdefABCDEF"].invertedSet;
    return [hex rangeOfCharacterFromSet:nonHex].location == NSNotFound;
}

static BOOL SRPWWIntegerOrRange(id value, long long minimum, long long maximum) {
    if (SRPWWInteger(value)) return [value longLongValue] >= minimum && [value longLongValue] <= maximum;
    if (![value isKindOfClass:NSArray.class] || [value count] != 2) return NO;
    if (!SRPWWInteger(value[0]) || !SRPWWInteger(value[1])) return NO;
    long long lower = [value[0] longLongValue];
    long long upper = [value[1] longLongValue];
    return lower >= minimum && upper <= maximum && lower <= upper;
}

static NSString *SRPWWStringMapError(id value, NSString *field) {
    if (![value isKindOfClass:NSDictionary.class]) return [NSString stringWithFormat:@"%@ must be an object with string values.", field];
    for (id key in (NSDictionary *)value) {
        if (![value[key] isKindOfClass:NSString.class]) return [NSString stringWithFormat:@"%@ values must be strings.", field];
    }
    return nil;
}

static BOOL SRPWWHTTPVersion(id value, NSInteger *version) {
    if (SRPWWInteger(value) && ([value integerValue] == 1 || [value integerValue] == 2)) {
        *version = [value integerValue];
        return YES;
    }
    if (![value isKindOfClass:NSString.class]) return NO;
    if ([@[@"1", @"1.1", @"http1", @"http1.1"] containsObject:value]) {
        *version = 1;
        return YES;
    }
    if ([@[@"2", @"2.0", @"http2", @"h2"] containsObject:value]) {
        *version = 2;
        return YES;
    }
    if ([@[@"both", @"any", @"auto", @"1.1+2"] containsObject:value]) {
        *version = 0;
        return YES;
    }
    return NO;
}

static NSString *SRPWWHTTPError(NSDictionary *settings, BOOL usesTLS, NSString *httpMode, id configuredVersion) {
    for (NSString *key in @[@"path", @"scheme", @"method", @"user-agent", @"upgrade-protocol", @"content-type",
                            @"websocket-origin", @"websocket-subprotocol", @"websocket-extensions", @"http1-mode"]) {
        if (settings[key] != nil && ![settings[key] isKindOfClass:NSString.class]) return [NSString stringWithFormat:@"http.%@ must be a string.", key];
    }
    if (settings[@"scheme"] != nil && ![@[@"http", @"https"] containsObject:settings[@"scheme"]]) return @"http.scheme must be http or https.";
    if (settings[@"http1-mode"] != nil && ![@[@"single", @"split"] containsObject:settings[@"http1-mode"]]) return @"http.http1-mode must be single or split.";
    if (!SRPWWBooleans(settings, [NSSet setWithArray:@[@"upgrade", @"verbose"]])) return @"An HTTP boolean setting has the wrong type.";
    NSInteger effectiveVersion = 0;
    SRPWWHTTPVersion(configuredVersion, &effectiveVersion);
    if (settings[@"http-version"] != nil) {
        if (!SRPWWHTTPVersion(settings[@"http-version"], &effectiveVersion)) return @"http.http-version is invalid.";
        if (usesTLS && effectiveVersion == 0) return @"Automatic HTTP upgrade cannot be used with TLS ALPN.";
    }
    if ([settings[@"http1-mode"] isEqualToString:@"split"] &&
        (effectiveVersion != 1 || [httpMode isEqualToString:@"websocket"])) return @"HTTP split mode requires HTTP version 1 and cannot be used with WebSocket.";
    for (NSString *key in @[@"upgrade-request-headers", @"upgrade-response-headers", @"headers"]) {
        if (settings[key] != nil) {
            NSString *error = SRPWWStringMapError(settings[key], [@"http." stringByAppendingString:key]);
            if (error != nil) return error;
        }
    }
    if (settings[@"split"] != nil && ![settings[@"split"] isKindOfClass:NSDictionary.class]) return @"http.split must be an object.";
    if ([settings[@"websocket-extensions"] length] > 0) return @"http.websocket-extensions is unsupported because negotiated extensions are not implemented.";
    return nil;
}

static NSString *SRPWWObfuscatorError(NSDictionary *settings) {
    if (settings[@"method"] != nil && (![settings[@"method"] isKindOfClass:NSString.class] || ![settings[@"method"] isEqualToString:@"xor"])) return @"obfuscator.method must be xor.";
    if (settings[@"xor_key"] != nil && !SRPWWRange(settings, @"xor_key", 0, 255)) return @"obfuscator.xor_key must be an integer from 0 to 255.";
    if (settings[@"skip"] != nil && (![settings[@"skip"] isKindOfClass:NSString.class] || ![@[@"none", @"ipv4", @"transport"] containsObject:settings[@"skip"]])) return @"obfuscator.skip must be none, ipv4 or transport.";
    if (!SRPWWBooleans(settings, [NSSet setWithArray:@[@"tls_record_header", @"tls_header"]])) return @"Obfuscator TLS header flags must be booleans.";
    return nil;
}

static NSString *SRPWWKCPError(NSDictionary *settings) {
    if (!SRPWWBooleans(settings, [NSSet setWithArray:@[@"fec", @"kcp-nodelay", @"kcp-no-congestion-control"]])) return @"A KCP boolean setting has the wrong type.";
    long long minimumMTU = [settings[@"fec"] boolValue] ? 86 : 78;
    if (settings[@"mtu"] != nil && !SRPWWRange(settings, @"mtu", minimumMTU, 65535)) return @"kcp.mtu has an invalid value or range.";
    NSArray *ranges = @[
        @[@"fec-data-shards", @1, @255], @[@"fec-parity-shards", @1, @255], @[@"kcp-interval-ms", @10, @5000],
        @[@"kcp-resend", @0, @2147483647], @[@"kcp-send-window", @1, @4294967295LL], @[@"kcp-recv-window", @1, @4294967295LL],
        @[@"kcp-rx-minrto-ms", @1, @2147483647], @[@"kcp-send-buffer-limit", @0, @2147483647],
        @[@"ping-interval-ms", @1, @2147483647], @[@"no-recv-timeout-ms", @1, @2147483647]
    ];
    for (NSArray *rule in ranges) {
        if (settings[rule[0]] != nil && !SRPWWRange(settings, rule[0], [rule[1] longLongValue], [rule[2] longLongValue])) return [NSString stringWithFormat:@"kcp.%@ has an invalid value or range.", rule[0]];
    }
    long long dataShards = settings[@"fec-data-shards"] != nil ? [settings[@"fec-data-shards"] longLongValue] : 10;
    long long parityShards = settings[@"fec-parity-shards"] != nil ? [settings[@"fec-parity-shards"] longLongValue] : 3;
    if (dataShards + parityShards > 255) return @"KCP FEC data and parity shards cannot exceed 255 in total.";
    long long sendWindow = settings[@"kcp-send-window"] != nil ? [settings[@"kcp-send-window"] longLongValue] : 8192;
    if (settings[@"kcp-initial-cwnd"] != nil && (!SRPWWRange(settings, @"kcp-initial-cwnd", 1, sendWindow))) return @"kcp.kcp-initial-cwnd must be positive and no greater than kcp-send-window.";
    long long ping = settings[@"ping-interval-ms"] != nil ? [settings[@"ping-interval-ms"] longLongValue] : 10000;
    long long timeout = settings[@"no-recv-timeout-ms"] != nil ? [settings[@"no-recv-timeout-ms"] longLongValue] : 30000;
    if (timeout <= ping) return @"kcp.no-recv-timeout-ms must be greater than kcp.ping-interval-ms.";
    return nil;
}

static NSString *SRPWWTLS13Error(id value, BOOL reality) {
    if (![value isKindOfClass:NSDictionary.class] || [value count] == 0) return @"tls13-record-shaping must be a nonempty object.";
    NSSet *allowed = [NSSet setWithArray:@[@"scope", @"outcomes"]];
    for (NSString *key in (NSDictionary *)value) if (![allowed containsObject:key]) return [NSString stringWithFormat:@"Unsupported tls13-record-shaping setting: %@", key];
    id scope = value[@"scope"];
    if (![scope isKindOfClass:NSDictionary.class] || scope[@"first-application-records"] == nil || [scope count] != 1 ||
        !SRPWWRange(scope, @"first-application-records", 1, 1024)) return @"tls13-record-shaping.scope requires first-application-records from 1 to 1024.";
    id outcomes = value[@"outcomes"];
    if (![outcomes isKindOfClass:NSArray.class] || [outcomes count] < 1 || [outcomes count] > 16) return @"tls13-record-shaping.outcomes must contain 1 to 16 entries.";
    NSInteger cumulativeProbability = 0;
    for (id outcome in (NSArray *)outcomes) {
        if (![outcome isKindOfClass:NSDictionary.class]) return @"Each TLS 1.3 shaping outcome must be an object.";
        NSSet *outcomeKeys = [NSSet setWithArray:@[@"probability", @"padding-bytes", @"delay"]];
        for (NSString *key in (NSDictionary *)outcome) if (![outcomeKeys containsObject:key]) return [NSString stringWithFormat:@"Unsupported TLS shaping outcome setting: %@", key];
        if (!SRPWWRange(outcome, @"probability", 1, 100)) return @"TLS shaping outcome probability must be an integer from 1 to 100.";
        cumulativeProbability += [outcome[@"probability"] integerValue];
        if (cumulativeProbability > 100) return @"TLS shaping cumulative probability cannot exceed 100.";
        if (outcome[@"padding-bytes"] != nil && !SRPWWIntegerOrRange(outcome[@"padding-bytes"], 1, 4096)) return @"TLS shaping padding-bytes must be in the range 1 to 4096.";
        BOOL meaningfulDelay = NO;
        if (outcome[@"delay"] != nil) {
            if (reality) return @"Reality TLS shaping cannot contain delay settings.";
            id delay = outcome[@"delay"];
            if (![delay isKindOfClass:NSDictionary.class]) return @"TLS shaping delay must be an object.";
            NSSet *delayKeys = [NSSet setWithArray:@[@"probability", @"ms"]];
            for (NSString *key in (NSDictionary *)delay) if (![delayKeys containsObject:key]) return [NSString stringWithFormat:@"Unsupported TLS shaping delay setting: %@", key];
            if (!SRPWWRange(delay, @"probability", 0, 100)) return @"TLS shaping delay probability must be an integer from 0 to 100.";
            if (!SRPWWIntegerOrRange(delay[@"ms"], 0, 1000)) return @"TLS shaping delay ms must be in the range 0 to 1000.";
            long long maximumDelay = SRPWWInteger(delay[@"ms"]) ? [delay[@"ms"] longLongValue] : [delay[@"ms"][1] longLongValue];
            meaningfulDelay = [delay[@"probability"] integerValue] > 0 && maximumDelay > 0;
        }
        if (outcome[@"padding-bytes"] == nil && !meaningfulDelay) return @"Each TLS shaping outcome requires padding or a nonzero-probability, nonzero delay.";
    }
    return nil;
}

static BOOL SRPWWEndpoint(id value, NSString **server, NSInteger *port) {
    if (![value isKindOfClass:NSString.class]) return NO;
    NSRange colon = [value rangeOfString:@":" options:NSBackwardsSearch];
    if (colon.location == NSNotFound || colon.location == 0 || colon.location + 1 >= [value length]) return NO;
    NSString *portString = [value substringFromIndex:colon.location + 1];
    NSScanner *scanner = [NSScanner scannerWithString:portString];
    long long parsedPort = 0;
    if (![scanner scanLongLong:&parsedPort] || !scanner.isAtEnd || parsedPort < 1 || parsedPort > 65535) return NO;
    NSString *parsedServer = [value substringToIndex:colon.location];
    if ([parsedServer hasPrefix:@"["] && [parsedServer hasSuffix:@"]"] && parsedServer.length > 2) {
        parsedServer = [parsedServer substringWithRange:NSMakeRange(1, parsedServer.length - 2)];
    }
    if (parsedServer.length == 0) return NO;
    *server = parsedServer;
    *port = (NSInteger)parsedPort;
    return YES;
}

static BOOL SRPWWNonnegativeIntegerString(id value, NSInteger *result) {
    if (![value isKindOfClass:NSString.class] || [value length] == 0) return NO;
    NSScanner *scanner = [NSScanner scannerWithString:value];
    long long parsed = 0;
    if (![scanner scanLongLong:&parsed] || !scanner.isAtEnd || parsed < 0 || parsed > 65535) return NO;
    *result = (NSInteger)parsed;
    return YES;
}

static NSArray<NSString *> *SRPWWGeoIPCountries(id value) {
    if (value == nil) return @[];
    if (![value isKindOfClass:NSArray.class]) return nil;
    NSMutableSet<NSString *> *countries = [NSMutableSet new];
    for (id item in (NSArray *)value) {
        if (![item isKindOfClass:NSString.class]) return nil;
        NSString *code = [item uppercaseString];
        if (code.length != 2) return nil;
        unichar first = [code characterAtIndex:0];
        unichar second = [code characterAtIndex:1];
        if (first < 'A' || first > 'Z' || second < 'A' || second > 'Z') return nil;
        [countries addObject:code];
    }
    return [countries.allObjects sortedArrayUsingSelector:@selector(compare:)];
}

static NSDictionary *SRPWWMigrateConfiguration(NSDictionary *configuration) {
    if (![configuration isKindOfClass:NSDictionary.class]) return configuration;
    NSDictionary *migrated = configuration;
    if ([migrated[@"version"] isEqual:@2]) {
        NSMutableDictionary *versioned = [migrated mutableCopy];
        versioned[@"version"] = @3;
        if ([versioned[@"mode"] isEqualToString:@"chain"]) {
            NSDictionary *defaults = @{@"http": @"off", @"http-version": @1, @"obfuscator": @NO,
                                       @"carrier": @"tcp", @"quic-carrier": @"datagram"};
            for (NSString *key in defaults) {
                if (versioned[key] == nil) versioned[key] = defaults[key];
            }
        }
        migrated = versioned;
    }
    if (![migrated[@"geoip"] isKindOfClass:NSDictionary.class]) return migrated;
    NSMutableDictionary *result = [migrated mutableCopy];
    NSMutableDictionary *geoIP = [migrated[@"geoip"] mutableCopy];
    id legacy = geoIP[@"iran-direct"];
    if (legacy != nil && SRPWWBoolean(legacy)) {
        if (geoIP[@"countries"] == nil && [legacy boolValue]) geoIP[@"countries"] = @[@"IR"];
        [geoIP removeObjectForKey:@"iran-direct"];
    }
    NSArray<NSString *> *countries = SRPWWGeoIPCountries(geoIP[@"countries"]);
    if (countries != nil && geoIP[@"countries"] != nil) geoIP[@"countries"] = countries;
    if (geoIP.count == 0) [result removeObjectForKey:@"geoip"];
    else result[@"geoip"] = geoIP;
    return result;
}

@implementation SRPWaterWallChainConfig

+ (NSDictionary *)defaultConfiguration {
    return @{@"version": @3, @"mode": @"chain", @"input": @"connections", @"application": @"vless",
             @"mux": @NO, @"outer": @"tls", @"http": @"off", @"http-version": @1, @"obfuscator": @NO,
             @"carrier": @"tcp", @"quic-carrier": @"datagram", @"node-options": @{}};
}

+ (NSDictionary *)configurationFromLegacyPreset:(NSString *)preset {
    if ([preset isEqualToString:@"direct"] || [preset isEqualToString:@"wireguard"]) {
        return @{@"version": @3, @"mode": preset, @"node-options": @{}};
    }
    BOOL raw = [preset hasPrefix:@"rawip"];
    NSString *application = [preset hasPrefix:@"vless"] ? @"vless" : [preset hasPrefix:@"trojan"] ? @"trojan" : @"";
    NSString *outer = [preset containsString:@"reality"] ? @"reality" : [preset containsString:@"aead"] ? @"aead" :
                      [preset containsString:@"quic"] ? @"quic" : [preset containsString:@"tls"] ? @"tls" : @"";
    if (application.length == 0 && !raw) return nil;
    NSDictionary *configuration = @{@"version": @2, @"mode": @"chain", @"input": raw ? @"raw-ipv4" : @"connections",
                                    @"application": application, @"mux": @([preset containsString:@"mux"]),
                                    @"outer": outer, @"node-options": @{}};
    NSDictionary *migrated = SRPWWMigrateConfiguration(configuration);
    return [self validationErrorForConfiguration:migrated] == nil ? migrated : nil;
}

+ (NSDictionary *)configurationWithJSON:(NSString *)json {
    if (json.length == 0) return [self defaultConfiguration];
    id value = [NSJSONSerialization JSONObjectWithData:[json dataUsingEncoding:NSUTF8StringEncoding] options:0 error:nil];
    NSDictionary *configuration = SRPWWMigrateConfiguration(value);
    return [configuration isKindOfClass:NSDictionary.class] && [self validationErrorForConfiguration:configuration] == nil ? configuration : nil;
}

+ (NSString *)JSONWithConfiguration:(NSDictionary *)configuration {
    NSDictionary *migrated = SRPWWMigrateConfiguration(configuration);
    if ([self validationErrorForConfiguration:migrated] != nil) return nil;
    NSData *data = [NSJSONSerialization dataWithJSONObject:migrated options:NSJSONWritingSortedKeys error:nil];
    return [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
}

+ (BOOL)isWireGuardConfiguration:(NSDictionary *)configuration {
    return [configuration[@"mode"] isEqualToString:@"wireguard"];
}

+ (BOOL)isDirectConfiguration:(NSDictionary *)configuration {
    return [configuration[@"mode"] isEqualToString:@"direct"];
}

+ (BOOL)configurationNeedsApplicationSecret:(NSDictionary *)configuration {
    return [configuration[@"mode"] isEqualToString:@"chain"] && [configuration[@"input"] isEqualToString:@"connections"];
}

+ (BOOL)configurationNeedsOuterSecret:(NSDictionary *)configuration {
    NSString *outer = configuration[@"outer"];
    return [configuration[@"mode"] isEqualToString:@"chain"] && ([outer isEqualToString:@"reality"] || [outer isEqualToString:@"aead"]);
}

+ (BOOL)configurationUsesTLS:(NSDictionary *)configuration {
    NSString *outer = configuration[@"outer"];
    return [configuration[@"mode"] isEqualToString:@"chain"] &&
           ([outer isEqualToString:@"tls"] || [outer isEqualToString:@"reality"] || [outer isEqualToString:@"quic"]);
}

+ (BOOL)configurationAllowsFragmentation:(NSDictionary *)configuration {
    NSString *outer = configuration[@"outer"];
    return [configuration[@"mode"] isEqualToString:@"chain"] && ([outer isEqualToString:@"tls"] || [outer isEqualToString:@"reality"]);
}

+ (BOOL)configurationAllowsRouting:(NSDictionary *)configuration {
    return [configuration[@"mode"] isEqualToString:@"chain"] && [configuration[@"input"] isEqualToString:@"connections"];
}

+ (NSString *)summaryForConfiguration:(NSDictionary *)configuration {
    if ([self isWireGuardConfiguration:configuration]) return @"WireGuard";
    if ([self isDirectConfiguration:configuration]) return @"Direct (diagnostics)";
    NSMutableArray *parts = [NSMutableArray new];
    if ([configuration[@"input"] isEqualToString:@"raw-ipv4"]) [parts addObject:@"Raw IPv4"];
    else {
        NSDictionary *names = @{@"vless": @"VLESS", @"vmess": @"VMess", @"trojan": @"Trojan",
                                @"socks5": @"SOCKS5", @"http-proxy": @"HTTP CONNECT"};
        [parts addObject:names[configuration[@"application"]] ?: @"VLESS"];
    }
    if ([configuration[@"mux"] boolValue]) [parts addObject:@"MUX"];
    if ([configuration[@"obfuscator"] boolValue]) [parts addObject:@"XOR"];
    if ([configuration[@"http"] isEqualToString:@"websocket"]) [parts addObject:@"WebSocket"];
    else if ([configuration[@"http"] isEqualToString:@"http"]) [parts addObject:@"HTTP"];
    if ([configuration[@"bgp4"] boolValue] && ![configuration[@"outer"] isEqualToString:@"bgp4"]) [parts addObject:@"BGP4"];
    NSString *outer = configuration[@"outer"];
    if ([outer isEqualToString:@"quic"] && [configuration[@"quic-carrier"] isEqualToString:@"stream"]) [parts addObject:@"QUIC Stream"];
    else [parts addObject:[outer isEqualToString:@"aead"] ? @"AEAD" : [outer isEqualToString:@"none"] ? @"none" : outer.uppercaseString];
    if ([configuration[@"carrier"] isEqualToString:@"kcp"]) [parts addObject:@"KCP"];
    return [parts componentsJoinedByString:@" + "];
}

+ (NSString *)validationErrorForConfiguration:(NSDictionary *)configuration {
    if (![configuration isKindOfClass:NSDictionary.class]) return @"WaterWall configuration must be a JSON object.";
    configuration = SRPWWMigrateConfiguration(configuration);
    NSSet *topKeys = [NSSet setWithArray:@[@"version", @"mode", @"input", @"application", @"mux", @"outer", @"http",
                                           @"http-version", @"obfuscator", @"carrier", @"quic-carrier", @"node-options", @"geoip", @"bgp4"]];
    for (NSString *key in configuration) if (![topKeys containsObject:key]) return [NSString stringWithFormat:@"Unknown configuration key: %@", key];
    if (![configuration[@"version"] isEqual:@3]) return @"Unsupported WaterWall configuration version.";
    for (NSString *key in @[@"mode", @"input", @"application", @"outer", @"http", @"carrier", @"quic-carrier"]) {
        if (configuration[key] != nil && ![configuration[key] isKindOfClass:NSString.class]) return [NSString stringWithFormat:@"WaterWall %@ must be a string.", key];
    }
    NSString *mode = configuration[@"mode"];
    if (![mode isKindOfClass:NSString.class]) return @"WaterWall mode must be a string.";
    if (![@[@"chain", @"direct", @"wireguard"] containsObject:mode]) return @"WaterWall mode is invalid.";
    BOOL direct = [mode isEqualToString:@"direct"];
    BOOL wireGuard = [mode isEqualToString:@"wireguard"];
    BOOL raw = NO;
    NSString *application = nil;
    NSString *outer = nil;
    NSString *http = nil;
    NSString *carrier = nil;
    NSString *quicCarrier = nil;
    id geoIP = configuration[@"geoip"];
    if (geoIP != nil) {
        if (![geoIP isKindOfClass:NSDictionary.class]) return @"geoip must be an object.";
        NSSet *allowed = [NSSet setWithArray:@[@"iran-direct", @"countries", @"update-url"]];
        for (NSString *key in (NSDictionary *)geoIP) {
            if (![allowed containsObject:key]) return [NSString stringWithFormat:@"Unsupported geoip setting: %@", key];
        }
        if (![mode isEqualToString:@"chain"] || ![configuration[@"input"] isEqualToString:@"connections"]) {
            return @"GeoIP routing requires Chain mode with Connections input.";
        }
        if (geoIP[@"iran-direct"] != nil && !SRPWWBoolean(geoIP[@"iran-direct"])) return @"geoip.iran-direct must be a boolean.";
        if (geoIP[@"countries"] != nil && SRPWWGeoIPCountries(geoIP[@"countries"]) == nil) {
            return @"geoip.countries must be an array of two-letter country codes.";
        }
        id updateURL = geoIP[@"update-url"];
        if (updateURL != nil) {
            if (![updateURL isKindOfClass:NSString.class] || [updateURL length] == 0 || [updateURL length] > 2048 ||
                ![updateURL isEqualToString:[updateURL stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet]]) {
                return @"geoip.update-url must be a nonempty HTTPS link of at most 2048 characters.";
            }
            NSURLComponents *components = [NSURLComponents componentsWithString:updateURL];
            if (![components.scheme.lowercaseString isEqualToString:@"https"] || components.host.length == 0 ||
                components.user != nil || components.password != nil || components.fragment != nil) {
                return @"geoip.update-url must use HTTPS and cannot contain embedded credentials or a fragment.";
            }
        }
    }
    if (configuration[@"bgp4"] != nil && !SRPWWBoolean(configuration[@"bgp4"])) return @"BGP4 must be a boolean.";
    if ((direct || wireGuard) && [configuration[@"bgp4"] boolValue]) return @"BGP4 framing requires Chain mode.";
    if (!direct && !wireGuard) {
        NSString *input = configuration[@"input"];
        if (![input isKindOfClass:NSString.class]) return @"WaterWall input must be a string.";
        raw = [input isEqualToString:@"raw-ipv4"];
        if (!raw && ![input isEqualToString:@"connections"]) return @"WaterWall input is invalid.";
        application = configuration[@"application"];
        if (![application isKindOfClass:NSString.class]) return @"WaterWall application must be a string.";
        NSArray *applications = @[@"vless", @"vmess", @"trojan", @"socks5", @"http-proxy"];
        if (!raw && ![applications containsObject:application]) return @"Select VLESS, VMess, Trojan, SOCKS5 or HTTP CONNECT.";
        if (raw && application.length > 0) return @"Raw IPv4 cannot be combined with an application protocol.";
        outer = configuration[@"outer"];
        if (![outer isKindOfClass:NSString.class]) return @"WaterWall outer must be a string.";
        if (![@[@"none", @"tls", @"reality", @"aead", @"quic", @"bgp4"] containsObject:outer]) return @"Select none, TLS, Reality, AEAD, QUIC or BGP4.";
        http = configuration[@"http"];
        carrier = configuration[@"carrier"];
        quicCarrier = configuration[@"quic-carrier"];
        if (![http isKindOfClass:NSString.class] || ![@[@"off", @"http", @"websocket"] containsObject:http]) return @"WaterWall http must be off, http or websocket.";
        if (![carrier isKindOfClass:NSString.class] || ![@[@"tcp", @"kcp"] containsObject:carrier]) return @"WaterWall carrier must be tcp or kcp.";
        if (![quicCarrier isKindOfClass:NSString.class] || ![@[@"datagram", @"stream"] containsObject:quicCarrier]) return @"WaterWall quic-carrier must be datagram or stream.";
        if (!SRPWWBoolean(configuration[@"mux"])) return @"MUX must be a boolean.";
        if (!SRPWWBoolean(configuration[@"obfuscator"])) return @"Obfuscator must be a boolean.";
        if (!SRPWWInteger(configuration[@"http-version"]) ||
            !([configuration[@"http-version"] integerValue] == 1 || [configuration[@"http-version"] integerValue] == 2)) return @"http-version must be integer 1 or 2.";
        if (raw && [configuration[@"mux"] boolValue]) return @"MUX requires an application protocol, not Raw IPv4.";
        if ([outer isEqualToString:@"quic"] && [carrier isEqualToString:@"kcp"]) return @"QUIC cannot be combined with the KCP carrier.";
        if ([outer isEqualToString:@"quic"] && ![http isEqualToString:@"off"]) return @"HTTP cannot run over QUIC.";
        if ([outer isEqualToString:@"quic"] && [configuration[@"mux"] boolValue] && ![quicCarrier isEqualToString:@"stream"]) return @"MUX over QUIC requires the stream carrier.";
        if ([outer isEqualToString:@"quic"] && [configuration[@"bgp4"] boolValue] && ![quicCarrier isEqualToString:@"stream"]) return @"BGP4 over QUIC requires the stream carrier.";
        if ([application isEqualToString:@"socks5"] && (![outer isEqualToString:@"none"] || ![http isEqualToString:@"off"] ||
            [configuration[@"mux"] boolValue] || [configuration[@"obfuscator"] boolValue] || [configuration[@"bgp4"] boolValue] || [carrier isEqualToString:@"kcp"])) {
            return @"SOCKS5 TCP and UDP require the TCP carrier with no MUX, outer transport, HTTP or obfuscation.";
        }
        if ([application isEqualToString:@"http-proxy"] && ([configuration[@"mux"] boolValue] || ![http isEqualToString:@"off"] || [carrier isEqualToString:@"kcp"])) {
            return @"HTTP CONNECT cannot be combined with MUX, another HTTP layer or KCP.";
        }
        if ([application isEqualToString:@"http-proxy"] && [outer isEqualToString:@"quic"] && ![quicCarrier isEqualToString:@"stream"]) {
            return @"HTTP CONNECT over QUIC requires the stream carrier.";
        }
    }

    NSDictionary *nodeOptions = configuration[@"node-options"];
    if (![nodeOptions isKindOfClass:NSDictionary.class]) return @"Advanced Node Settings must be a JSON object.";
    if (wireGuard) {
        if (nodeOptions.count > 0) return @"WireGuard mode does not consume node-options; leave it empty.";
        return nil;
    }
    NSMutableSet *layers = [NSMutableSet setWithObject:@"packet"];
    if (!direct) {
        if (!raw) [layers addObject:@"application"];
        if ([configuration[@"mux"] boolValue]) [layers addObject:@"mux"];
        if (![outer isEqualToString:@"none"]) [layers addObject:@"outer"];
        if (![http isEqualToString:@"off"]) [layers addObject:@"http"];
        if ([configuration[@"obfuscator"] boolValue]) [layers addObject:@"obfuscator"];
        if ([carrier isEqualToString:@"kcp"]) [layers addObject:@"kcp"];
    }
    for (NSString *layer in nodeOptions) {
        if (![layers containsObject:layer] || ![nodeOptions[layer] isKindOfClass:NSDictionary.class]) {
            return direct ? @"Direct mode permits only packet node-options objects." :
                            [NSString stringWithFormat:@"Advanced node setting %@ is unavailable or is not an object.", layer];
        }
    }
    NSArray *connectionPacketKeys = @[@"mtu", @"udp-idle-timeout-ms", @"max-pending-bytes", @"max-total-pending-bytes",
                                      @"fake-dns", @"mapdns", @"fake_dns"];
    NSArray *applicationKeys = @[@"protocol", @"proto", @"first-payload-timeout-ms", @"verbose", @"domain-strategy"];
    if ([application isEqualToString:@"vmess"]) {
        applicationKeys = @[@"protocol", @"proto", @"first-payload-timeout-ms", @"verbose", @"domain-strategy", @"security",
                            @"chunk-masking", @"global-padding", @"authenticated-length", @"encrypted-counter-policy",
                            @"send-termination", @"packet-encoding"];
    } else if ([application isEqualToString:@"socks5"]) {
        applicationKeys = @[@"protocol", @"proto", @"verbose", @"domain-strategy"];
    } else if ([application isEqualToString:@"http-proxy"]) {
        applicationKeys = @[@"verbose", @"domain-strategy", @"headers", @"max-header-bytes", @"header-timeout-ms",
                            @"connect-response-timeout-ms", @"idle-timeout-ms"];
    }
    NSDictionary *schemas = @{
        @"packet": raw ? @[@"sensitive-mode", @"interval-ms", @"tolerance-ms", @"packet-validation-level"] : connectionPacketKeys,
        @"application": applicationKeys,
        @"mux": @[@"mode", @"connection-duration-ms", @"connection-capacity", @"per-worker-connections-count", @"keepalive", @"ping-interval", @"tolerance-ms",
                  @"parent-write-buffer-pause-threshold", @"parent-write-buffer-resume-threshold", @"parent-write-buffer-limit",
                  @"max-children", @"child-buffer-limit", @"child-buffer-resume-threshold", @"parent-buffer-limit",
                  @"detached-buffer-limit", @"detached-child-limit", @"log-main-line-stats"],
        @"http": @[@"path", @"scheme", @"method", @"user-agent", @"http-version", @"upgrade", @"upgrade-protocol",
                   @"upgrade-request-headers", @"upgrade-response-headers", @"headers", @"content-type",
                   @"websocket-origin", @"websocket-subprotocol", @"websocket-extensions", @"http1-mode", @"split", @"verbose"],
        @"obfuscator": @[@"method", @"xor_key", @"skip", @"tls_record_header", @"tls_header"],
        @"kcp": @[@"mtu", @"fec", @"fec-data-shards", @"fec-parity-shards", @"kcp-nodelay", @"kcp-interval-ms", @"kcp-resend",
                  @"kcp-no-congestion-control", @"kcp-send-window", @"kcp-recv-window", @"kcp-initial-cwnd", @"kcp-rx-minrto-ms",
                  @"kcp-send-buffer-limit", @"ping-interval-ms", @"no-recv-timeout-ms"],
        @"outer": [outer isEqualToString:@"tls"] ? @[@"alpns", @"x25519mlkem768", @"fragment", @"tls13-record-shaping", @"ech-config-list", @"ech-sni-trick", @"verbose"] :
                  [outer isEqualToString:@"reality"] ? @[@"alpns", @"x25519mlkem768", @"fragment", @"tls13-record-shaping", @"ech-config-list", @"ech-sni-trick", @"verbose", @"algorithm", @"method", @"salt", @"kdf-iterations"] :
                  [outer isEqualToString:@"aead"] ? @[@"algorithm", @"method", @"salt", @"kdf-iterations", @"max-frame-size"] :
                  [outer isEqualToString:@"quic"] ? @[@"ca-file", @"protocol", @"handshake-timeout-ms", @"idle-timeout-ms", @"max-packet-size", @"max-buffered-bytes", @"max-buffered-buffers", @"receive-window-bytes", @"verbose"] : @[]
    };
    for (NSString *layer in nodeOptions) {
        NSDictionary *settings = nodeOptions[layer];
        NSSet *allowed = [NSSet setWithArray:schemas[layer]];
        for (NSString *key in settings) if (![allowed containsObject:key]) return [NSString stringWithFormat:@"Unsupported %@ setting: %@", layer, key];
    }
    NSDictionary *packet = nodeOptions[@"packet"] ?: @{};
    NSDictionary *app = nodeOptions[@"application"] ?: @{};
    NSDictionary *mux = nodeOptions[@"mux"] ?: @{};
    NSDictionary *outerOptions = nodeOptions[@"outer"] ?: @{};
    if (!SRPWWBooleans(packet, [NSSet setWithArray:@[@"sensitive-mode", @"enabled"]]) ||
        !SRPWWBooleans(app, [NSSet setWithArray:@[@"verbose", @"chunk-masking", @"global-padding",
                                                   @"authenticated-length", @"send-termination"]]) ||
        !SRPWWBooleans(mux, [NSSet setWithArray:@[@"log-main-line-stats", @"keepalive"]]) ||
        !SRPWWBooleans(outerOptions, [NSSet setWithArray:@[@"x25519mlkem768", @"verbose"]])) return @"A boolean node setting has the wrong type.";
    NSArray *ranges = @[
        @[packet, @"mtu", @68, @65535], @[packet, @"udp-idle-timeout-ms", @1, @4294967295LL],
        @[packet, @"max-pending-bytes", @1024, @67108864], @[packet, @"max-total-pending-bytes", @65536, @67108864],
        @[packet, @"interval-ms", @1, @4294967295LL], @[packet, @"tolerance-ms", @1, @4294967295LL],
        @[app, @"first-payload-timeout-ms", @0, @4294967295LL],
        @[app, @"max-header-bytes", @1024, @65536], @[app, @"header-timeout-ms", @1, @2147483647],
        @[app, @"connect-response-timeout-ms", @1, @2147483647], @[app, @"idle-timeout-ms", @1, @2147483647],
        @[mux, @"connection-duration-ms", @61, @4294967295LL], @[mux, @"connection-capacity", @1, @4294967295LL],
        @[mux, @"per-worker-connections-count", @1, @4294967295LL], @[mux, @"max-children", @1, @4294967295LL],
        @[mux, @"ping-interval", @1, @2147483647], @[mux, @"tolerance-ms", @1, @2147483647],
        @[mux, @"parent-write-buffer-pause-threshold", @1, @2147483647], @[mux, @"parent-write-buffer-resume-threshold", @0, @2147483647],
        @[mux, @"parent-write-buffer-limit", @1, @2147483647], @[mux, @"child-buffer-limit", @1, @2147483647],
        @[mux, @"child-buffer-resume-threshold", @1, @2147483647], @[mux, @"parent-buffer-limit", @0, @2147483647],
        @[mux, @"detached-buffer-limit", @0, @2147483647], @[mux, @"detached-child-limit", @0, @2147483647],
        @[outerOptions, @"kdf-iterations", @1, @1000000], @[outerOptions, @"max-frame-size", @1, @16356],
        @[outerOptions, @"handshake-timeout-ms", @1, @86400000], @[outerOptions, @"idle-timeout-ms", @1, @86400000],
        @[outerOptions, @"max-packet-size", @1200, @1452], @[outerOptions, @"max-buffered-bytes", @65536, @67108864],
        @[outerOptions, @"max-buffered-buffers", @1, @65536], @[outerOptions, @"receive-window-bytes", @16384, @16777216]
    ];
    for (NSArray *rule in ranges) {
        NSDictionary *settings = rule[0]; NSString *key = rule[1];
        if (settings[key] != nil && !SRPWWRange(settings, key, [rule[2] longLongValue], [rule[3] longLongValue])) return [NSString stringWithFormat:@"%@ has an invalid value or range.", key];
    }
    if (mux[@"mode"] != nil && ![mux[@"mode"] isKindOfClass:NSString.class]) return @"MUX mode must be a string.";
    if ([mux[@"mode"] length] > 0 && ![@[@"timer", @"counter", @"fixed-connections-count"] containsObject:mux[@"mode"]]) return @"MUX mode is invalid.";
    NSString *muxMode = [mux[@"mode"] length] > 0 ? mux[@"mode"] : @"counter";
    if ([muxMode isEqualToString:@"timer"]) {
        if (mux[@"connection-duration-ms"] == nil) return @"MUX timer mode requires connection-duration-ms.";
        if (mux[@"connection-capacity"] != nil || mux[@"per-worker-connections-count"] != nil) return @"MUX timer mode accepts duration only, not capacity or fixed-count settings.";
    } else if ([muxMode isEqualToString:@"fixed-connections-count"]) {
        if (mux[@"per-worker-connections-count"] == nil) return @"MUX fixed-connections-count mode requires per-worker-connections-count.";
        if (mux[@"connection-duration-ms"] != nil || mux[@"connection-capacity"] != nil) return @"MUX fixed mode accepts fixed-count settings only.";
    } else if (mux[@"connection-duration-ms"] != nil || mux[@"per-worker-connections-count"] != nil) {
        return @"MUX counter mode accepts capacity only, not duration or fixed-count settings.";
    }
    NSInteger resume = [mux[@"parent-write-buffer-resume-threshold"] integerValue] ?: 1048576;
    NSInteger pause = [mux[@"parent-write-buffer-pause-threshold"] integerValue] ?: 8388608;
    NSInteger limit = [mux[@"parent-write-buffer-limit"] integerValue] ?: 16777216;
    if (!(resume < pause && pause < limit)) return @"MUX buffer thresholds must satisfy resume < pause < limit.";

    if (packet[@"packet-validation-level"] != nil) {
        id level = packet[@"packet-validation-level"];
        if (![level isKindOfClass:NSString.class]) return @"packet-validation-level must be a string.";
        if (![@[@"none", @"loose", @"hard"] containsObject:level]) return @"packet-validation-level must be none, loose or hard.";
    }
    NSArray *fakeDNSKeys = @[@"fake-dns", @"mapdns", @"fake_dns"];
    NSUInteger fakeDNSCount = 0;
    for (NSString *key in fakeDNSKeys) {
        if (packet[key] == nil) continue;
        fakeDNSCount += 1;
        NSString *error = SRPWWFakeDNSError(key, packet[key]);
        if (error != nil) return error;
    }
    if (fakeDNSCount > 1) return @"fake-dns, mapdns and fake_dns are mutually exclusive aliases.";
    NSArray *applicationProtocols = @[@"tcp", @"connect", @"udp", @"udp-associate", @"dest_context->protocol", @"line->dest_ctx->protocol"];
    for (NSString *key in @[@"protocol", @"proto"]) {
        if (app[key] == nil) continue;
        if (![app[key] isKindOfClass:NSString.class]) return [NSString stringWithFormat:@"application.%@ must be a string.", key];
        if (![applicationProtocols containsObject:app[key]]) return [NSString stringWithFormat:@"application.%@ has an unsupported protocol.", key];
    }
    if (app[@"domain-strategy"] != nil) {
        id strategy = app[@"domain-strategy"];
        if (![strategy isKindOfClass:NSString.class]) return @"application.domain-strategy must be a string.";
        NSArray *strategies = @[@"do-not-resolve-domains", @"resolve-domains-and-prefer-ipv4", @"resolve-domains-and-prefer-ipv6",
                                @"resolve-domains-with-core-settings", @"resolve-domains-and-accept-dns-returned-order",
                                @"resolve-domains-and-use-only-ipv4", @"resolve-domains-and-use-only-ipv6"];
        if (![strategies containsObject:strategy]) return @"application.domain-strategy is invalid.";
    }
    if (app[@"headers"] != nil) {
        NSString *error = SRPWWStringMapError(app[@"headers"], @"application.headers");
        if (error != nil) return error;
        NSSet *forbidden = [NSSet setWithArray:@[@"host", @"proxy-authorization", @"content-length", @"transfer-encoding",
                                                 @"connection", @"proxy-connection", @"keep-alive", @"te", @"trailer", @"upgrade", @"expect"]];
        NSCharacterSet *token = [NSCharacterSet characterSetWithCharactersInString:@"!#$%&'*+-.^_`|~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"];
        for (NSString *name in (NSDictionary *)app[@"headers"]) {
            if (name.length == 0 || [forbidden containsObject:name.lowercaseString] ||
                [name rangeOfCharacterFromSet:token.invertedSet].location != NSNotFound) return @"HTTP proxy contains an invalid or reserved header name.";
            NSString *value = app[@"headers"][name];
            for (NSUInteger index = 0; index < value.length; index++) {
                unichar character = [value characterAtIndex:index];
                if ((character < 32 && character != 9) || character == 127) return @"HTTP proxy header values cannot contain control characters.";
            }
        }
    }
    if ([application isEqualToString:@"vmess"]) {
        NSString *security = app[@"security"] ?: @"aes-128-gcm";
        if (![security isKindOfClass:NSString.class] ||
            ![@[@"aes-128-gcm", @"chacha20-poly1305", @"auto", @"none", @"zero"] containsObject:security]) {
            return @"VMess security must be aes-128-gcm, chacha20-poly1305, auto, none or zero.";
        }
        if (app[@"encrypted-counter-policy"] != nil &&
            ![@[@"wrap", @"strict"] containsObject:app[@"encrypted-counter-policy"]]) {
            return @"VMess encrypted-counter-policy must be wrap or strict.";
        }
        if (app[@"packet-encoding"] != nil && ![@[@"none", @"packetaddr"] containsObject:app[@"packet-encoding"]]) {
            return @"VMess packet-encoding must be none or packetaddr.";
        }
        NSString *protocol = app[@"protocol"] ?: app[@"proto"] ?: @"dest_context->protocol";
        if ([security isEqualToString:@"zero"] && ![@[@"tcp", @"connect"] containsObject:protocol]) {
            return @"VMess zero supports TCP only; select a fixed TCP protocol or an encrypted security mode.";
        }
        if ([app[@"global-padding"] boolValue] && app[@"chunk-masking"] != nil && ![app[@"chunk-masking"] boolValue]) {
            return @"VMess global-padding requires chunk-masking.";
        }
        if ([app[@"authenticated-length"] boolValue] && [@[@"none", @"zero"] containsObject:security]) {
            return @"VMess authenticated-length requires an encrypted security mode.";
        }
        if ([security isEqualToString:@"zero"] &&
            ([app[@"chunk-masking"] boolValue] || [app[@"global-padding"] boolValue] || [app[@"authenticated-length"] boolValue])) {
            return @"VMess zero cannot enable masking, padding or authenticated lengths.";
        }
        if ([app[@"packet-encoding"] isEqualToString:@"packetaddr"] &&
            (!app[@"domain-strategy"] || [app[@"domain-strategy"] isEqualToString:@"do-not-resolve-domains"])) {
            return @"VMess packetaddr requires local DNS resolution so the target is an IP address.";
        }
    }
    for (NSString *key in @[@"algorithm", @"method", @"salt", @"ech-config-list", @"ech-sni-trick", @"ca-file"]) {
        if (outerOptions[key] != nil && (![outerOptions[key] isKindOfClass:NSString.class] || [outerOptions[key] length] == 0)) return [NSString stringWithFormat:@"%@ must be a nonempty string.", key];
    }
    if (outerOptions[@"salt"] != nil && [outerOptions[@"salt"] lengthOfBytesUsingEncoding:NSUTF8StringEncoding] > 32) return @"salt must contain 1 to 32 UTF-8 bytes.";
    if ([outer isEqualToString:@"reality"] || [outer isEqualToString:@"aead"]) {
        NSArray *algorithms = [outer isEqualToString:@"reality"] ?
            @[@"chacha20-poly1305", @"chacha20poly1305", @"aes-gcm", @"aes-256-gcm", @"aes256gcm"] :
            @[@"chacha20-poly1305", @"chacha20poly1305", @"chacha20", @"chacha", @"aes-gcm", @"aes256gcm", @"aes-256-gcm", @"aes256-gcm"];
        for (NSString *key in @[@"algorithm", @"method"]) {
            if (outerOptions[key] != nil && ![algorithms containsObject:outerOptions[key]]) return [NSString stringWithFormat:@"%@.%@ is unsupported.", outer, key];
        }
    }
    if (outerOptions[@"ech-config-list"] != nil && outerOptions[@"ech-sni-trick"] != nil) return @"ech-config-list and ech-sni-trick cannot be used together.";
    if (![http isEqualToString:@"off"] && ([outer isEqualToString:@"tls"] || [outer isEqualToString:@"reality"]) && outerOptions[@"alpns"] != nil) {
        return @"outer.alpns is builder-owned when HTTP is enabled with TLS or Reality.";
    }
    if (outerOptions[@"alpns"] != nil) {
        NSString *error = SRPWWALPNError(outerOptions[@"alpns"]);
        if (error != nil) return error;
    }
    if (outerOptions[@"fragment"] != nil) {
        NSString *error = SRPWWFragmentError(outerOptions[@"fragment"]);
        if (error != nil) return error;
    }
    if (outerOptions[@"tls13-record-shaping"] != nil) {
        NSString *error = SRPWWTLS13Error(outerOptions[@"tls13-record-shaping"], [outer isEqualToString:@"reality"]);
        if (error != nil) return error;
    }
    if (outerOptions[@"protocol"] != nil && ![outerOptions[@"protocol"] isKindOfClass:NSString.class]) return @"QUIC protocol must be a string.";
    if ([outerOptions[@"protocol"] length] == 0 && outerOptions[@"protocol"] != nil) return @"QUIC protocol cannot be empty.";
    if ([outer isEqualToString:@"quic"]) {
        long long quicByteBudget = outerOptions[@"max-buffered-bytes"] != nil ? [outerOptions[@"max-buffered-bytes"] longLongValue] : 2097152;
        long long quicBufferCount = outerOptions[@"max-buffered-buffers"] != nil ? [outerOptions[@"max-buffered-buffers"] longLongValue] : 1024;
        long long receiveWindow = outerOptions[@"receive-window-bytes"] != nil ? [outerOptions[@"receive-window-bytes"] longLongValue] : 1048576;
        if (receiveWindow > quicByteBudget) return @"QUIC receive-window-bytes cannot exceed max-buffered-bytes.";
        if ((quicBufferCount + 1) * 24 > quicByteBudget) return @"QUIC buffer entry count does not fit its byte budget.";
    }
    if (nodeOptions[@"http"] != nil) {
        NSString *error = SRPWWHTTPError(nodeOptions[@"http"], [outer isEqualToString:@"tls"] || [outer isEqualToString:@"reality"],
                                         http, configuration[@"http-version"]);
        if (error != nil) return error;
    }
    if (nodeOptions[@"obfuscator"] != nil) {
        NSString *error = SRPWWObfuscatorError(nodeOptions[@"obfuscator"]);
        if (error != nil) return error;
        // The server re-derives each skip from its own buffer boundaries, which a connection stream does not keep.
        NSString *skip = nodeOptions[@"obfuscator"][@"skip"];
        if (!raw && skip != nil && ![skip isEqualToString:@"none"]) return @"obfuscator.skip must be none for connection input.";
    }
    if (nodeOptions[@"kcp"] != nil) {
        NSString *error = SRPWWKCPError(nodeOptions[@"kcp"]);
        if (error != nil) return error;
    }
    return nil;
}

+ (NSString *)validationErrorForApplicationSecret:(NSString *)secret forConfiguration:(NSDictionary *)configuration {
    if (![self configurationNeedsApplicationSecret:configuration]) return nil;
    if ([configuration[@"application"] isEqualToString:@"socks5"] || [configuration[@"application"] isEqualToString:@"http-proxy"]) return nil;
    BOOL vless = [configuration[@"application"] isEqualToString:@"vless"];
    BOOL vmess = [configuration[@"application"] isEqualToString:@"vmess"];
    NSString *name = vless ? @"VLESS UUID" : vmess ? @"VMess UUID or ID" : @"Trojan password";
    if (![secret isKindOfClass:NSString.class]) return [NSString stringWithFormat:@"%@ must be a string.", name];
    if (vless && !SRPWWUUID(secret)) return @"Enter a valid VLESS UUID as dashed RFC4122 or 32 hexadecimal characters.";
    if (vmess && !SRPWWUUID(secret)) {
        NSUInteger bytes = [secret lengthOfBytesUsingEncoding:NSUTF8StringEncoding];
        if (bytes < 1 || bytes > 30) return @"Enter a VMess UUID or a short string ID of 1 to 30 UTF-8 bytes.";
    }
    if (!vless && !vmess && secret.length == 0) return @"Enter the Trojan password.";
    return nil;
}

+ (NSString *)validationErrorForApplicationUsername:(NSString *)username
                                             secret:(NSString *)secret
                                    forConfiguration:(NSDictionary *)configuration {
    NSString *application = configuration[@"application"];
    BOOL socks = [application isEqualToString:@"socks5"];
    BOOL httpProxy = [application isEqualToString:@"http-proxy"];
    if (!socks && !httpProxy) return nil;
    if (username.length == 0 && secret.length == 0) return nil;
    if (![username isKindOfClass:NSString.class] || ![secret isKindOfClass:NSString.class] || username.length == 0 || secret.length == 0) {
        return @"Proxy username and password must be supplied together, or both left empty.";
    }
    if ([username lengthOfBytesUsingEncoding:NSUTF8StringEncoding] > 255 || [secret lengthOfBytesUsingEncoding:NSUTF8StringEncoding] > 255) {
        return @"Proxy username and password must each contain at most 255 UTF-8 bytes.";
    }
    if (httpProxy) {
        if ([username containsString:@":"]) return @"HTTP proxy username cannot contain a colon.";
        for (NSString *value in @[username, secret]) {
            for (NSUInteger index = 0; index < value.length; index++) {
                unichar character = [value characterAtIndex:index];
                if (character < 32 || character == 127) return @"HTTP proxy credentials cannot contain control characters.";
            }
        }
    }
    return nil;
}

+ (NSString *)validationErrorForOuterSecret:(NSString *)secret forConfiguration:(NSDictionary *)configuration {
    if (![self configurationNeedsOuterSecret:configuration]) return nil;
    BOOL reality = [configuration[@"outer"] isEqualToString:@"reality"];
    NSString *name = reality ? @"Reality password" : @"AEAD password";
    if (![secret isKindOfClass:NSString.class]) return [NSString stringWithFormat:@"%@ must be a string.", name];
    NSUInteger bytes = [secret lengthOfBytesUsingEncoding:NSUTF8StringEncoding];
    if (reality && (bytes < 1 || bytes > 32)) return @"Reality password must contain 1 to 32 UTF-8 bytes.";
    if (!reality && secret.length == 0) return @"Enter the AEAD password.";
    return nil;
}

+ (NSString *)coreJSON {
    return [self coreJSONWithLogLevel:0];
}

+ (NSString *)coreJSONWithLogLevel:(NSInteger)level {
    NSString *name = level >= 2 ? @"DEBUG" : level == 1 ? @"INFO" : @"WARN";
    NSDictionary *core = @{
        @"log": @{@"path": @"/tmp/", @"core": @{@"loglevel": name, @"file": @"ww-core.log", @"console": @YES},
                  @"network": @{@"loglevel": name, @"file": @"ww-network.log", @"console": @YES},
                  @"dns": @{@"loglevel": name, @"file": @"ww-dns.log", @"console": @YES},
                  @"internal": @{@"loglevel": name, @"file": @"ww-internal.log", @"console": @YES}},
        @"misc": @{@"workers": @1, @"ram-profile": @"minimal", @"mtu": @1420, @"splice": @NO, @"try-enabling-bbr": @NO, @"tcp-tune": @NO},
        @"dns": @{@"domain-strategy": @"prefer-ipv4"}, @"configs": @[@"hosted-nodes.json"]};
    NSData *data = [NSJSONSerialization dataWithJSONObject:core options:0 error:nil];
    return [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
}

+ (NSMutableDictionary *)settings:(NSDictionary *)defaults overrides:(NSDictionary *)overrides required:(NSDictionary *)required {
    NSMutableDictionary *settings = [defaults mutableCopy];
    [settings addEntriesFromDictionary:overrides ?: @{}];
    [settings addEntriesFromDictionary:required];
    return settings;
}

+ (NSString *)nodesJSONForConfiguration:(NSDictionary *)configuration
                                 server:(NSString *)server
                                   port:(NSInteger)port
                                    sni:(NSString *)sni
                              verifyTLS:(BOOL)verifyTLS
                                 secret:(NSString *)secret
                            outerSecret:(NSString *)outerSecret
                                options:(NSDictionary *)options {
    configuration = SRPWWMigrateConfiguration(configuration);
    if ([self validationErrorForConfiguration:configuration] != nil || [self isWireGuardConfiguration:configuration] || port < 1 || port > 65535) return nil;
    if (![self isDirectConfiguration:configuration] && server.length == 0) return nil;
    if ([self validationErrorForApplicationSecret:secret forConfiguration:configuration] != nil) return nil;
    if ([self validationErrorForApplicationUsername:options[@"username"] secret:secret forConfiguration:configuration] != nil) return nil;
    if ([self validationErrorForOuterSecret:outerSecret forConfiguration:configuration] != nil) return nil;
    BOOL direct = [self isDirectConfiguration:configuration];
    BOOL raw = [configuration[@"input"] isEqualToString:@"raw-ipv4"];
    BOOL mux = [configuration[@"mux"] boolValue];
    BOOL quic = [configuration[@"outer"] isEqualToString:@"quic"];
    BOOL hasOuter = ![configuration[@"outer"] isEqualToString:@"none"];
    BOOL hasHTTP = ![configuration[@"http"] isEqualToString:@"off"];
    BOOL obfuscator = [configuration[@"obfuscator"] boolValue];
    BOOL kcp = [configuration[@"carrier"] isEqualToString:@"kcp"];
    NSString *application = configuration[@"application"];
    NSString *outer = configuration[@"outer"];
    NSDictionary *advanced = configuration[@"node-options"] ?: @{};
    BOOL bgp4 = [configuration[@"bgp4"] boolValue] && ![outer isEqualToString:@"bgp4"];
    NSString *afterBGP4 = hasOuter ? outer : kcp ? @"kcp" : @"connector";
    NSString *afterObfuscator = bgp4 ? @"bgp4" : hasHTTP ? @"http" : afterBGP4;
    NSString *afterApplication = obfuscator ? @"obfuscator" : afterObfuscator;
    NSString *afterInput = raw ? afterApplication : application;
    NSMutableArray *nodes = [NSMutableArray arrayWithObject:@{@"name": @"ne", @"type": @"NEPacketDevice", @"settings": @{}, @"next": direct || !raw ? @"ptc" : @"pts"}];
    if (direct || !raw) {
        NSMutableDictionary *required = [NSMutableDictionary new];
        if ((options[@"ww_fake_dns"] == nil || [options[@"ww_fake_dns"] boolValue]) && !direct) {
            required[@"fake-dns"] = @{@"enabled": @YES, @"address": @"198.18.0.2", @"port": @53, @"network": @"100.64.0.0",
                                      @"netmask": @"255.192.0.0", @"cache-size": @10000, @"ttl": @60};
        }
        NSMutableDictionary *settings = [[self settings:@{@"mtu": @1420, @"max-pending-bytes": @65536,
                                                           @"max-total-pending-bytes": @16777216}
                                              overrides:advanced[@"packet"] required:required] mutableCopy];
        if (required[@"fake-dns"] != nil) [settings removeObjectsForKeys:@[@"mapdns", @"fake_dns"]];
        NSString *first = direct ? @"connector" : raw ? afterInput : @"router";
        [nodes addObject:@{@"name": @"ptc", @"type": @"PacketsToConnection", @"settings": settings, @"next": first}];
    }
    if (direct) {
        [nodes addObject:@{@"name": @"connector", @"type": @"TcpUdpConnector", @"settings": @{@"address": @"dest_context->address", @"port": @"dest_context->port", @"nodelay": @YES}}];
    } else {
        if (!raw) {
            BOOL vmess = [application isEqualToString:@"vmess"];
            BOOL socks = [application isEqualToString:@"socks5"];
            BOOL httpProxy = [application isEqualToString:@"http-proxy"];
            NSMutableDictionary *applicationDefaults = [@{@"domain-strategy": @"do-not-resolve-domains"} mutableCopy];
            if (!httpProxy) applicationDefaults[@"protocol"] = @"dest_context->protocol";
            if (vmess) applicationDefaults[@"security"] = @"aes-128-gcm";
            if (httpProxy) applicationDefaults[@"mode"] = @"connect";
            NSMutableDictionary *required = [@{httpProxy ? @"target-address" : @"address": @"dest_context->address",
                                               @"port": @"dest_context->port"} mutableCopy];
            if (!socks && !httpProxy) required[[application isEqualToString:@"trojan"] ? @"password" : @"uuid"] = secret;
            NSMutableDictionary *applicationSettings = [[self settings:applicationDefaults
                                                             overrides:advanced[@"application"]
                                                              required:required] mutableCopy];
            if ((socks || httpProxy) && [options[@"username"] length] > 0) {
                applicationSettings[socks ? @"user" : @"username"] = options[@"username"];
                applicationSettings[socks ? @"pass" : @"password"] = secret;
            }
            if (advanced[@"application"][@"protocol"] == nil && advanced[@"application"][@"proto"] != nil) {
                applicationSettings[@"protocol"] = advanced[@"application"][@"proto"];
            }
            NSString *applicationType = [application isEqualToString:@"vless"] ? @"VlessClient" : vmess ? @"VmessClient" :
                                        [application isEqualToString:@"trojan"] ? @"TrojanClient" : socks ? @"Socks5Client" : @"HttpProxyClient";
            [nodes addObject:@{@"name": application, @"type": applicationType,
                               @"settings": applicationSettings, @"next": mux ? @"mux" : afterApplication}];
            NSArray<NSString *> *directCountries = SRPWWGeoIPCountries(configuration[@"geoip"][@"countries"]);
            if (directCountries.count > 0 && [options[@"ww_geoip_db_path"] length] == 0) return nil;
            NSMutableDictionary *routerSettings = [@{@"resolve-domains": directCountries.count > 0 ? @YES : @NO} mutableCopy];
            NSMutableArray *rules = [NSMutableArray new];
            if ([options[@"ww_smart_routing"] boolValue]) {
                [rules addObject:@{@"destination-ip": @[@"10.0.0.0/8", @"172.16.0.0/12", @"192.168.0.0/16"], @"target": @"direct-local"}];
            }
            if (directCountries.count > 0) {
                routerSettings[@"geoip-db-path"] = options[@"ww_geoip_db_path"];
                for (NSString *country in directCountries) {
                    [rules addObject:@{@"destination-ip": @[[@"geoip:" stringByAppendingString:country.lowercaseString]], @"target": @"direct-local"}];
                }
            }
            if (rules.count > 0) routerSettings[@"rules"] = rules;
            [nodes addObject:@{@"name": @"router", @"type": @"Router", @"settings": routerSettings, @"next": application}];
            if (rules.count > 0) {
                [nodes addObject:@{@"name": @"direct-local", @"type": @"TcpUdpConnector", @"settings": @{@"address": @"dest_context->address", @"port": @"dest_context->port", @"domain-strategy": @"prefer-ipv4", @"nodelay": @YES}}];
            }
        } else {
            [nodes addObject:@{@"name": @"pts", @"type": @"PacketsToStream",
                               @"settings": [self settings:@{@"packet-validation-level": @"hard"} overrides:advanced[@"packet"] required:@{}], @"next": afterApplication}];
        }
        if (mux) {
            NSString *muxMode = [advanced[@"mux"][@"mode"] length] > 0 ? advanced[@"mux"][@"mode"] : @"counter";
            NSMutableDictionary *muxDefaults = [@{@"mode": muxMode, @"max-children": @256,
                @"parent-write-buffer-pause-threshold": @8388608, @"parent-write-buffer-resume-threshold": @1048576,
                @"parent-write-buffer-limit": @16777216, @"child-buffer-limit": @4194304, @"parent-buffer-limit": @16777216,
                @"detached-buffer-limit": @4194304, @"detached-child-limit": @128} mutableCopy];
            if ([muxMode isEqualToString:@"counter"]) muxDefaults[@"connection-capacity"] = @128;
            [nodes addObject:@{@"name": @"mux", @"type": @"MuxClient",
                               @"settings": [self settings:muxDefaults overrides:advanced[@"mux"] required:@{}], @"next": afterApplication}];
        }
        if (obfuscator) {
            NSDictionary *settings = [self settings:@{@"method": @"xor", @"xor_key": @90, @"skip": @"none"}
                                          overrides:advanced[@"obfuscator"] required:@{}];
            [nodes addObject:@{@"name": @"obfuscator", @"type": @"ObfuscatorClient", @"settings": settings, @"next": afterObfuscator}];
        }
        NSInteger httpVersion = 0;
        id httpVersionValue = advanced[@"http"][@"http-version"] ?: configuration[@"http-version"];
        if (hasHTTP) {
            SRPWWHTTPVersion(httpVersionValue, &httpVersion);
            NSString *scheme = [outer isEqualToString:@"tls"] || [outer isEqualToString:@"reality"] ? @"https" : @"http";
            NSDictionary *settings = [self settings:@{@"host": sni.length > 0 ? sni : server, @"path": @"/", @"scheme": scheme,
                                                      @"port": @(port), @"http-version": httpVersionValue,
                                                      @"websocket": @([configuration[@"http"] isEqualToString:@"websocket"])}
                                          overrides:advanced[@"http"]
                                           required:@{@"host": sni.length > 0 ? sni : server, @"port": @(port),
                                                      @"http-version": httpVersionValue,
                                                      @"websocket": @([configuration[@"http"] isEqualToString:@"websocket"])}];
            [nodes addObject:@{@"name": @"http", @"type": @"HttpClient", @"settings": settings, @"next": hasOuter ? outer : kcp ? @"kcp" : @"connector"}];
        }
        if (bgp4) {
            [nodes addObject:@{@"name": @"bgp4", @"type": @"Bgp4Client", @"settings": @{}, @"next": afterBGP4}];
        }
        if (hasOuter) {
            NSMutableDictionary *outerSettings = [NSMutableDictionary new];
            if ([outer isEqualToString:@"tls"] || [outer isEqualToString:@"reality"] || quic) {
                outerSettings[@"sni"] = sni.length > 0 ? sni : [outer isEqualToString:@"reality"] ? @"www.cloudflare.com" : server;
                outerSettings[@"verify"] = @(verifyTLS);
            }
            if ([outer isEqualToString:@"tls"]) outerSettings[@"alpns"] = @[@"http/1.1"];
            if ([outer isEqualToString:@"reality"]) {
                outerSettings[@"password"] = outerSecret; outerSettings[@"algorithm"] = @"chacha20-poly1305";
                outerSettings[@"salt"] = @"waterwall-reality"; outerSettings[@"kdf-iterations"] = @12000;
                outerSettings[@"verbose"] = @([options[@"log_level"] isEqualToString:@"debug"]);
            } else if ([outer isEqualToString:@"aead"]) {
                outerSettings[@"password"] = outerSecret; outerSettings[@"algorithm"] = @"chacha20-poly1305";
                outerSettings[@"salt"] = @"waterwall-aead"; outerSettings[@"kdf-iterations"] = @12000; outerSettings[@"max-frame-size"] = @16356;
            } else if (quic) {
                outerSettings[@"protocol"] = @"h3"; outerSettings[@"carrier-mode"] = configuration[@"quic-carrier"];
            }
            if ([options[@"tls_frag"] integerValue] > 0 && [self configurationAllowsFragmentation:configuration]) {
                NSInteger firstCut = MAX(1, [options[@"tls_frag_first"] integerValue] ?: 32);
                NSInteger following = MAX(1, [options[@"tls_frag_following"] integerValue] ?: 256);
                NSMutableArray *cuts = [NSMutableArray new];
                for (NSInteger offset = firstCut; offset < 16384 && cuts.count < 64; offset += following) [cuts addObject:@[@(offset), @0, @100]];
                outerSettings[@"fragment"] = @{@"mode": @"counter", @"count": @1, @"tls-hello-fragment": @YES, @"tls-hello-timeout-ms": @1000, @"cuts": cuts};
            }
            outerSettings = [self settings:outerSettings overrides:advanced[@"outer"] required:@{}].mutableCopy;
            if (advanced[@"outer"][@"algorithm"] == nil && advanced[@"outer"][@"method"] != nil) {
                outerSettings[@"algorithm"] = advanced[@"outer"][@"method"];
            }
            if ([outer isEqualToString:@"tls"] || [outer isEqualToString:@"reality"] || quic) {
                outerSettings[@"sni"] = sni.length > 0 ? sni : [outer isEqualToString:@"reality"] ? @"www.cloudflare.com" : server;
                outerSettings[@"verify"] = @(verifyTLS);
            }
            if (hasHTTP && httpVersion > 0 && ([outer isEqualToString:@"tls"] || [outer isEqualToString:@"reality"])) {
                outerSettings[@"alpns"] = httpVersion == 1 ? @[@"http/1.1"] : @[@"h2"];
            }
            if ([outer isEqualToString:@"reality"] || [outer isEqualToString:@"aead"]) outerSettings[@"password"] = outerSecret;
            if (quic) outerSettings[@"carrier-mode"] = configuration[@"quic-carrier"];
            NSString *outerType = [outer isEqualToString:@"tls"] ? @"TlsClient" : [outer isEqualToString:@"reality"] ? @"RealityClient" :
                                  [outer isEqualToString:@"aead"] ? @"EncryptionClient" :
                                  [outer isEqualToString:@"bgp4"] ? @"Bgp4Client" : @"QuicClient";
            [nodes addObject:@{@"name": outer, @"type": outerType, @"settings": outerSettings, @"next": kcp ? @"kcp" : @"connector"}];
        }
        if (kcp) {
            [nodes addObject:@{@"name": @"kcp", @"type": @"TcpOverUdpClient",
                               @"settings": [self settings:@{@"kcp-send-window": @128, @"kcp-recv-window": @128,
                                                             @"kcp-initial-cwnd": @16, @"kcp-send-buffer-limit": @512}
                                              overrides:advanced[@"kcp"]
                                              required:@{}], @"next": @"connector"}];
        }
        NSSet *fixedProtocols = [NSSet setWithArray:@[@"tcp", @"connect", @"udp", @"udp-associate"]];
        NSString *applicationProtocol = advanced[@"application"][@"protocol"] ?: advanced[@"application"][@"proto"];
        BOOL fixedApplicationProtocol = [fixedProtocols containsObject:applicationProtocol];
        BOOL dynamicTCPUDP = !raw && !mux && !hasHTTP && [outer isEqualToString:@"tls"] &&
            ![application isEqualToString:@"http-proxy"] && !fixedApplicationProtocol;
        NSString *connectorType = [application isEqualToString:@"socks5"] ? @"TcpUdpConnector" :
            kcp ? @"UdpConnector" : quic ?
            ([configuration[@"quic-carrier"] isEqualToString:@"stream"] ? @"TcpConnector" : @"UdpConnector") :
            dynamicTCPUDP ? @"TcpUdpConnector" : @"TcpConnector";
        NSDictionary *connector = @{@"address": server, @"port": @(port), @"nodelay": @YES};
        [nodes addObject:@{@"name": @"connector", @"type": connectorType, @"settings": connector}];
    }
    NSData *data = [NSJSONSerialization dataWithJSONObject:@{@"name": [self summaryForConfiguration:configuration], @"nodes": nodes} options:0 error:nil];
    return [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
}

+ (NSDictionary *)wireGuardConfigurationWithPrivateKey:(NSString *)privateKey
                                         serverPublicKey:(NSString *)serverPublicKey
                                                  server:(NSString *)server
                                                    port:(NSInteger)port
                                            clientAddress:(NSString *)clientAddress
                                                keepalive:(NSInteger)keepalive {
    if (privateKey.length == 0 || serverPublicKey.length == 0 || server.length == 0 ||
        clientAddress.length == 0 || port < 1 || port > 65535 || keepalive < 0 || keepalive > 65535) return nil;
    NSString *endpoint = [NSString stringWithFormat:@"%@:%ld", server, (long)port];
    NSArray *nodes = @[
        @{@"name": @"udp", @"type": @"UdpStatelessSocket", @"settings": @{
            @"listen-address": @"0.0.0.0", @"listen-port": @0, @"verbose": @YES}, @"next": @"wg"},
        @{@"name": @"wg", @"type": @"WireGuardDevice", @"settings": @{
            @"privatekey": privateKey,
            @"peers": @[@{
                @"publickey": serverPublicKey,
                @"allowedips": @"0.0.0.0/0",
                @"endpoint": endpoint,
                @"persistentkeepalive": @(MAX(0, keepalive))}]}, @"next": @"ne"},
        @{@"name": @"ne", @"type": @"NEPacketDevice", @"settings": @{}},
    ];
    NSData *data = [NSJSONSerialization dataWithJSONObject:@{@"name": @"wireguard", @"nodes": nodes} options:0 error:nil];
    NSString *json = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    NSString *address = [clientAddress componentsSeparatedByString:@"/"].firstObject;
    return @{@"nodesJSON": json, @"tunnelAddress": address, @"allowedIPs": @"0.0.0.0/0",
             @"dnsServers": @[@"1.1.1.1", @"1.0.0.1"], @"endpointIP": server};
}

+ (NSDictionary *)wireGuardConfigurationWithConfig:(NSString *)config {
    if (![config isKindOfClass:NSString.class] || config.length == 0) return nil;
    NSMutableDictionary *interface = nil;
    NSMutableArray<NSMutableDictionary *> *peerValues = [NSMutableArray new];
    NSMutableDictionary *current = nil;
    for (NSString *line in [config componentsSeparatedByCharactersInSet:NSCharacterSet.newlineCharacterSet]) {
        NSString *trimmed = [line stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
        if (trimmed.length == 0 || [trimmed hasPrefix:@"#"] || [trimmed hasPrefix:@";"]) continue;
        if ([trimmed hasPrefix:@"["]) {
            if (![trimmed hasSuffix:@"]"]) return nil;
            NSString *section = [[trimmed substringWithRange:NSMakeRange(1, trimmed.length - 2)] lowercaseString];
            if ([section isEqualToString:@"interface"]) {
                if (interface != nil) return nil;
                interface = [NSMutableDictionary new];
                current = interface;
            } else if ([section isEqualToString:@"peer"]) {
                if (peerValues.count >= 32) return nil;
                current = [NSMutableDictionary new];
                [peerValues addObject:current];
            } else {
                return nil;
            }
            continue;
        }
        NSRange separator = [trimmed rangeOfString:@"="];
        if (current == nil || separator.location == NSNotFound) return nil;
        NSString *key = [[trimmed substringToIndex:separator.location] stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceCharacterSet].lowercaseString;
        NSString *value = [[trimmed substringFromIndex:separator.location + 1] stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceCharacterSet];
        if (key.length == 0) return nil;
        current[key] = value;
    }
    if ([interface[@"privatekey"] length] == 0 || [interface[@"address"] length] == 0 || peerValues.count == 0 || peerValues.count > 32) return nil;
    NSMutableArray *peers = [NSMutableArray new];
    NSMutableArray *allowedIPParts = [NSMutableArray new];
    NSMutableArray *endpointIPs = [NSMutableArray new];
    NSString *endpointIP = nil;
    for (NSDictionary *values in peerValues) {
        NSString *server = nil;
        NSInteger port = 0;
        if ([values[@"publickey"] length] == 0 || !SRPWWEndpoint(values[@"endpoint"], &server, &port)) return nil;
        NSInteger keepalive = 0;
        if (values[@"persistentkeepalive"] != nil && !SRPWWNonnegativeIntegerString(values[@"persistentkeepalive"], &keepalive)) return nil;
        NSString *allowedIPs = [values[@"allowedips"] length] > 0 ? values[@"allowedips"] : @"0.0.0.0/0";
        NSMutableDictionary *peer = [@{@"publickey": values[@"publickey"], @"allowedips": allowedIPs,
                                      @"endpoint": values[@"endpoint"], @"persistentkeepalive": @(keepalive)} mutableCopy];
        if ([values[@"presharedkey"] length] > 0) peer[@"presharedkey"] = values[@"presharedkey"];
        [peers addObject:peer];
        [allowedIPParts addObject:allowedIPs];
        [endpointIPs addObject:server];
        if (endpointIP == nil) endpointIP = server;
    }
    NSArray *nodes = @[
        @{@"name": @"udp", @"type": @"UdpStatelessSocket", @"settings": @{@"listen-address": @"0.0.0.0", @"listen-port": @0, @"verbose": @YES}, @"next": @"wg"},
        @{@"name": @"wg", @"type": @"WireGuardDevice", @"settings": @{@"privatekey": interface[@"privatekey"], @"peers": peers}, @"next": @"ne"},
        @{@"name": @"ne", @"type": @"NEPacketDevice", @"settings": @{}}
    ];
    NSData *data = [NSJSONSerialization dataWithJSONObject:@{@"name": @"wireguard", @"nodes": nodes} options:0 error:nil];
    if (data == nil) return nil;
    NSString *json = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    NSMutableArray *dnsServers = [NSMutableArray new];
    for (NSString *item in [interface[@"dns"] componentsSeparatedByString:@","]) {
        NSString *address = [item stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceCharacterSet];
        if (address.length > 0) [dnsServers addObject:address];
    }
    if (dnsServers.count == 0) [dnsServers addObjectsFromArray:@[@"1.1.1.1", @"1.0.0.1"]];
    NSString *address = [interface[@"address"] componentsSeparatedByString:@"/"].firstObject;
    return @{@"nodesJSON": json, @"tunnelAddress": address, @"allowedIPs": [allowedIPParts componentsJoinedByString:@", "],
             @"dnsServers": dnsServers, @"endpointIP": endpointIP, @"endpointIPs": endpointIPs};
}

@end
