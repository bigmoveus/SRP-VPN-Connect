#import "SRPWaterWallChainConfig.h"

// PacketsToConnection's fake DNS: lookups get placeholder addresses, so the connection carries the name to the server
static NSDictionary *SRPWWFakeDNSSettings(void) {
    return @{@"enabled": @YES, @"address": @"198.18.0.2", @"port": @53, @"network": @"100.64.0.0",
             @"netmask": @"255.192.0.0", @"cache-size": @10000, @"ttl": @60};
}

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
    long long minimumMTU = [settings[@"fec"] boolValue] ? 126 : 118;
    if (settings[@"send-mtu"] != nil && !SRPWWRange(settings, @"send-mtu", minimumMTU, 65535)) return @"kcp.send-mtu has an invalid value or range.";
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
    long long sendWindow = settings[@"kcp-send-window"] != nil ? [settings[@"kcp-send-window"] longLongValue] : 128;  // the builder's default
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

static NSArray<NSString *> *SRPWWDNSStrategies(void) {
    return @[@"core-settings", @"accept-dns-returned-order", @"prefer-ipv4", @"prefer-ipv6", @"only-ipv4", @"only-ipv6"];
}

// BIND's inet_pton, as Android and Linux have it. Apple's also takes leading zeros and interface scopes, which
// WaterWall on Android rejects, so a profile checked here works on both.
static BOOL SRPWWNumericIPv4(const char *text) {
    int octets = 0, value = 0;
    BOOL sawDigit = NO;
    for (; *text != '\0'; text++) {
        char character = *text;
        if (character >= '0' && character <= '9') {
            if (sawDigit && value == 0) return NO;
            value = value * 10 + (character - '0');
            if (value > 255) return NO;
            if (!sawDigit) {
                if (++octets > 4) return NO;
                sawDigit = YES;
            }
        } else if (character == '.' && sawDigit) {
            if (octets == 4) return NO;
            value = 0;
            sawDigit = NO;
        } else {
            return NO;
        }
    }
    return octets >= 4;
}

static BOOL SRPWWNumericIPv6(const char *text) {
    if (*text == ':' && *++text != ':') return NO;
    int bytes = 0, colon = -1, digits = 0;
    const char *token = text;
    char character;
    while ((character = *text++) != '\0') {
        if ((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f') || (character >= 'A' && character <= 'F')) {
            if (++digits > 4) return NO;
            continue;
        }
        if (character == ':') {
            token = text;
            if (digits == 0) {
                if (colon >= 0) return NO;
                colon = bytes;
                continue;
            }
            if (*text == '\0' || bytes + 2 > 16) return NO;
            bytes += 2;
            digits = 0;
            continue;
        }
        if (character == '.' && bytes + 4 <= 16 && SRPWWNumericIPv4(token)) {
            bytes += 4;
            digits = 0;
            break;
        }
        return NO;
    }
    if (digits > 0) {
        if (bytes + 2 > 16) return NO;
        bytes += 2;
    }
    if (colon >= 0) {
        if (bytes == 16) return NO;
        bytes = 16;
    }
    return bytes == 16;
}

// WaterWall's DNS server grammar (dns_policy.c): a numeric IP, IPv4:port or [IPv6]:port, at most 64 bytes.
static BOOL SRPWWDNSServer(id value) {
    if (![value isKindOfClass:NSString.class] || [value length] == 0 || [value lengthOfBytesUsingEncoding:NSUTF8StringEncoding] > 64) return NO;
    const char *endpoint = [value UTF8String];
    if (strlen(endpoint) != [value lengthOfBytesUsingEncoding:NSUTF8StringEncoding]) return NO;
    char host[64];
    const char *port = NULL;
    size_t length;
    BOOL bracketed = endpoint[0] == '[';
    if (bracketed) {
        const char *end = strchr(endpoint, ']');
        if (end == NULL || (end[1] != '\0' && end[1] != ':')) return NO;
        length = (size_t)(end - endpoint - 1);
        if (length == 0 || length >= sizeof(host)) return NO;
        memcpy(host, endpoint + 1, length);
        if (end[1] == ':') port = end + 2;
    } else {
        const char *colon = strchr(endpoint, ':');
        if (colon != NULL && strchr(colon + 1, ':') == NULL) {
            length = (size_t)(colon - endpoint);
            port = colon + 1;
        } else {
            length = strlen(endpoint);
        }
        if (length == 0 || length >= sizeof(host)) return NO;
        memcpy(host, endpoint, length);
    }
    host[length] = '\0';
    if (bracketed ? !SRPWWNumericIPv6(host) : !(SRPWWNumericIPv4(host) || SRPWWNumericIPv6(host))) return NO;
    if (port == NULL) return YES;
    if (*port == '\0') return NO;
    unsigned long number = 0;
    for (; *port != '\0'; port++) {
        if (*port < '0' || *port > '9') return NO;
        number = number * 10 + (unsigned long)(*port - '0');
        if (number > 65535) return NO;
    }
    return number > 0;
}

// The DNS resolver option: a flat DomainResolver setting without verbose and dns-next.
static NSString *SRPWWDomainResolverError(id resolver) {
    if (![resolver isKindOfClass:NSDictionary.class]) return @"domain-resolver must be an object.";
    for (NSString *key in (NSDictionary *)resolver) {
        if (![@[@"mode", @"strategy", @"servers"] containsObject:key]) return @"The DNS resolver supports only mode, strategy and servers.";
    }
    id mode = resolver[@"mode"] ?: @"native";
    if (![@[@"native", @"direct", @"chain"] containsObject:mode]) return @"The DNS resolver mode must be native, direct or chain.";
    if (resolver[@"strategy"] != nil && ![SRPWWDNSStrategies() containsObject:resolver[@"strategy"]]) return @"The DNS resolver strategy is invalid.";
    id servers = resolver[@"servers"];
    if ([mode isEqual:@"native"]) return servers == nil ? nil : @"Native DNS uses the system's DNS servers; remove the server list.";
    if (![servers isKindOfClass:NSArray.class] || [servers count] < 1 || [servers count] > 32) return @"Direct and chain DNS need 1 to 32 DNS servers.";
    for (id server in (NSArray *)servers) {
        if (![server isKindOfClass:NSString.class]) return @"DNS servers must be strings.";
        if (!SRPWWDNSServer(server)) return [NSString stringWithFormat:@"%@ is not a DNS server address: use an IP address, IPv4:port or [IPv6]:port.", server];
    }
    return nil;
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
    id nodeOptions = migrated[@"node-options"];
    id kcpOptions = [nodeOptions isKindOfClass:NSDictionary.class] ? nodeOptions[@"kcp"] : nil;
    if ([kcpOptions isKindOfClass:NSDictionary.class] && kcpOptions[@"mtu"] != nil) {
        // WaterWall 1.5.3 renamed this setting.
        NSMutableDictionary *renamed = [kcpOptions mutableCopy];
        if (renamed[@"send-mtu"] == nil) renamed[@"send-mtu"] = renamed[@"mtu"];
        [renamed removeObjectForKey:@"mtu"];
        NSMutableDictionary *options = [nodeOptions mutableCopy];
        options[@"kcp"] = renamed;
        NSMutableDictionary *result = [migrated mutableCopy];
        result[@"node-options"] = options;
        migrated = result;
    }
    id applicationOptions = [nodeOptions isKindOfClass:NSDictionary.class] ? migrated[@"node-options"][@"application"] : nil;
    id legacyStrategy = [applicationOptions isKindOfClass:NSDictionary.class] ? applicationOptions[@"domain-strategy"] : nil;
    NSDictionary *strategies = @{@"do-not-resolve-domains": @"", @"resolve-domains-with-core-settings": @"core-settings",
                                 @"resolve-domains-and-accept-dns-returned-order": @"accept-dns-returned-order",
                                 @"resolve-domains-and-prefer-ipv4": @"prefer-ipv4", @"resolve-domains-and-prefer-ipv6": @"prefer-ipv6",
                                 @"resolve-domains-and-use-only-ipv4": @"only-ipv4", @"resolve-domains-and-use-only-ipv6": @"only-ipv6"};
    if ([legacyStrategy isKindOfClass:NSString.class] && strategies[legacyStrategy] != nil) {
        // WaterWall 1.5.4 rejects domain-strategy; dns-behaviour replaces it, and not resolving is the default.
        NSMutableDictionary *renamed = [applicationOptions mutableCopy];
        [renamed removeObjectForKey:@"domain-strategy"];
        NSString *strategy = strategies[legacyStrategy];
        if (strategy.length > 0 && renamed[@"dns-behaviour"] == nil) renamed[@"dns-behaviour"] = @{@"resolve": @YES, @"strategy": strategy};
        NSMutableDictionary *options = [migrated[@"node-options"] mutableCopy];
        if (renamed.count > 0) options[@"application"] = renamed;
        else [options removeObjectForKey:@"application"];
        NSMutableDictionary *result = [migrated mutableCopy];
        result[@"node-options"] = options;
        migrated = result;
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
    return [configuration[@"mode"] isEqualToString:@"chain"] &&
           ([outer isEqualToString:@"reality"] || [outer isEqualToString:@"aead"] || [configuration[@"packet-encryption"] boolValue]);
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

+ (BOOL)configurationUsesUDPCarrier:(NSDictionary *)configuration {
    if ([self isWireGuardConfiguration:configuration]) return YES;
    if (![configuration[@"mode"] isEqualToString:@"chain"]) return NO;
    // QUIC's stream carrier runs over a TCP connection, like the chain's default carrier.
    return [configuration[@"carrier"] isEqualToString:@"kcp"] ||
           ([configuration[@"outer"] isEqualToString:@"quic"] && ![configuration[@"quic-carrier"] isEqualToString:@"stream"]);
}

+ (NSString *)summaryForConfiguration:(NSDictionary *)configuration {
    if ([self isWireGuardConfiguration:configuration]) return @"WireGuard";
    if ([self isDirectConfiguration:configuration]) return @"Direct (diagnostics)";
    NSMutableArray *parts = [NSMutableArray new];
    if ([configuration[@"input"] isEqualToString:@"raw-ipv4"]) {
        [parts addObject:@"Raw IPv4"];
        if ([configuration[@"packet-encryption"] boolValue]) [parts addObject:@"Packet encryption"];
    } else {
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
                                           @"http-version", @"obfuscator", @"carrier", @"quic-carrier", @"node-options", @"geoip", @"bgp4", @"packet-encryption",
                                           @"domain-resolver"]];
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
    id resolver = configuration[@"domain-resolver"];
    if (resolver != nil) {
        NSString *error = SRPWWDomainResolverError(resolver);
        if (error != nil) return error;
        if (![mode isEqualToString:@"chain"] || ![configuration[@"input"] isEqualToString:@"connections"]) {
            return @"The DNS resolver requires Chain mode with Connections input.";
        }
    }
    if (configuration[@"bgp4"] != nil && !SRPWWBoolean(configuration[@"bgp4"])) return @"BGP4 must be a boolean.";
    if ((direct || wireGuard) && [configuration[@"bgp4"] boolValue]) return @"BGP4 framing requires Chain mode.";
    if (configuration[@"packet-encryption"] != nil && !SRPWWBoolean(configuration[@"packet-encryption"])) return @"Packet encryption must be a boolean.";
    if ([configuration[@"packet-encryption"] boolValue]) {
        if (direct || wireGuard || ![configuration[@"input"] isEqualToString:@"raw-ipv4"]) return @"Packet encryption requires Raw IPv4.";
        if ([configuration[@"outer"] isEqualToString:@"reality"] || [configuration[@"outer"] isEqualToString:@"aead"]) {
            return @"Packet encryption cannot be combined with Reality or AEAD.";
        }
    }
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
    NSArray *applicationKeys = @[@"protocol", @"proto", @"first-payload-timeout-ms", @"verbose", @"dns-behaviour"];
    if ([application isEqualToString:@"vmess"]) {
        applicationKeys = @[@"protocol", @"proto", @"first-payload-timeout-ms", @"verbose", @"dns-behaviour", @"security",
                            @"chunk-masking", @"global-padding", @"authenticated-length", @"encrypted-counter-policy",
                            @"send-termination", @"packet-encoding"];
    } else if ([application isEqualToString:@"socks5"]) {
        applicationKeys = @[@"protocol", @"proto", @"verbose", @"dns-behaviour"];
    } else if ([application isEqualToString:@"http-proxy"]) {
        applicationKeys = @[@"verbose", @"dns-behaviour", @"headers", @"max-header-bytes", @"header-timeout-ms",
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
        @"kcp": @[@"send-mtu", @"fec", @"fec-data-shards", @"fec-parity-shards", @"kcp-nodelay", @"kcp-interval-ms", @"kcp-resend",
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
    if (app[@"dns-behaviour"] != nil) {
        // Resolving on the phone, as domain-strategy did before WaterWall 1.5.4; the DNS resolver option covers the rest.
        NSDictionary *policy = app[@"dns-behaviour"];
        if (![policy isKindOfClass:NSDictionary.class] || !SRPWWBoolean(policy[@"resolve"])) return @"application.dns-behaviour needs a boolean resolve.";
        for (NSString *key in policy) {
            if (![@[@"resolve", @"strategy"] containsObject:key]) return @"application.dns-behaviour supports only resolve and strategy.";
        }
        if (policy[@"strategy"] != nil && (![policy[@"resolve"] boolValue] || ![SRPWWDNSStrategies() containsObject:policy[@"strategy"]])) {
            return @"application.dns-behaviour.strategy is invalid or needs resolve true.";
        }
    }
    if ([resolver[@"mode"] isEqual:@"chain"] && ([application isEqualToString:@"http-proxy"] ||
        [@[@"tcp", @"connect"] containsObject:app[@"protocol"] ?: app[@"proto"] ?: @""])) {
        return @"Chain DNS sends UDP queries through the VPN, which HTTP CONNECT and a fixed TCP protocol cannot carry.";
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
            ![app[@"dns-behaviour"][@"resolve"] boolValue] && resolver == nil) {
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
    BOOL packet = [configuration[@"packet-encryption"] boolValue];
    NSString *name = reality ? @"Reality password" : packet ? @"Packet encryption password" : @"AEAD password";
    if (![secret isKindOfClass:NSString.class]) return [NSString stringWithFormat:@"%@ must be a string.", name];
    NSUInteger bytes = [secret lengthOfBytesUsingEncoding:NSUTF8StringEncoding];
    if (reality && (bytes < 1 || bytes > 32)) return @"Reality password must contain 1 to 32 UTF-8 bytes.";
    if (!reality && secret.length == 0) return packet ? @"Enter the packet encryption password." : @"Enter the AEAD password.";
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
        @"misc": @{@"workers": @1, @"ram-profile": @"minimal", @"mtu": @1420, @"splice": @NO, @"try-enabling-bbr": @NO, @"tcp-tune": @NO,
                   // lwIP's receive windows may hold this much in total; the extension's memory limit is 50 MB.
                   @"tcp-stack-receive-budget": @16777216},
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
    // An empty SNI means the server, except for Reality, whose default cover is www.cloudflare.com
    NSString *effectiveSNI = sni.length > 0 ? sni : [outer isEqualToString:@"reality"] ? @"www.cloudflare.com" : server;
    NSDictionary *advanced = configuration[@"node-options"] ?: @{};
    BOOL bgp4 = [configuration[@"bgp4"] boolValue] && ![outer isEqualToString:@"bgp4"];
    NSString *afterBGP4 = hasOuter ? outer : kcp ? @"kcp" : @"connector";
    NSString *afterHTTP = bgp4 ? @"bgp4" : afterBGP4;
    NSString *afterObfuscator = hasHTTP ? @"http" : afterHTTP;
    NSString *afterApplication = obfuscator ? @"obfuscator" : afterObfuscator;
    NSString *afterInput = raw ? afterApplication : application;
    BOOL packetEncryption = [configuration[@"packet-encryption"] boolValue];
    NSMutableArray *nodes = [NSMutableArray arrayWithObject:@{@"name": @"ne", @"type": @"NEPacketDevice", @"settings": @{},
                                                              @"next": direct || !raw ? @"ptc" : packetEncryption ? @"packet-encryption" : @"pts"}];
    if (direct || !raw) {
        NSMutableDictionary *required = [NSMutableDictionary new];
        if ((options[@"ww_fake_dns"] == nil || [options[@"ww_fake_dns"] boolValue]) && !direct) {
            required[@"fake-dns"] = SRPWWFakeDNSSettings();
        }
        NSMutableDictionary *settings = [[self settings:@{@"mtu": @1420, @"max-pending-bytes": @65536,
                                                           @"max-total-pending-bytes": @16777216}
                                              overrides:advanced[@"packet"] required:required] mutableCopy];
        if (required[@"fake-dns"] != nil) [settings removeObjectsForKeys:@[@"mapdns", @"fake_dns"]];
        NSString *first = direct ? @"connector" : raw ? afterInput : configuration[@"domain-resolver"] != nil ? @"resolver" : @"router";
        [nodes addObject:@{@"name": @"ptc", @"type": @"PacketsToConnection", @"settings": settings, @"next": first}];
    }
    if (direct) {
        [nodes addObject:@{@"name": @"connector", @"type": @"TcpUdpConnector", @"settings": @{@"address": @"dest_context->address", @"port": @"dest_context->port", @"nodelay": @YES}}];
    } else {
        if (!raw) {
            BOOL vmess = [application isEqualToString:@"vmess"];
            BOOL socks = [application isEqualToString:@"socks5"];
            BOOL httpProxy = [application isEqualToString:@"http-proxy"];
            NSMutableDictionary *applicationDefaults = [NSMutableDictionary new];
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
            NSDictionary *resolver = configuration[@"domain-resolver"];
            NSMutableDictionary *routerSettings = [NSMutableDictionary new];
            // The DNS resolver in front leaves the Router only IP addresses.
            if (directCountries.count > 0 && resolver == nil) routerSettings[@"dns-behaviour"] = @{@"resolve": @YES};
            NSMutableArray *rules = [NSMutableArray new];
            // First, so that a DNS server in a direct country or the local network is still asked through the VPN
            if ([resolver[@"mode"] isEqual:@"chain"]) [rules addObject:@{@"resolver-dns": @YES, @"target": application}];
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
            if (resolver != nil) [nodes addObject:@{@"name": @"resolver", @"type": @"DomainResolver", @"settings": resolver, @"next": @"router"}];
            if ([[rules valueForKey:@"target"] containsObject:@"direct-local"]) {
                [nodes addObject:@{@"name": @"direct-local", @"type": @"TcpUdpConnector", @"settings": @{@"address": @"dest_context->address", @"port": @"dest_context->port",
                                                                                                   @"dns-behaviour": @{@"resolve": @YES, @"strategy": @"prefer-ipv4"}, @"nodelay": @YES}}];
            }
        } else {
            if (packetEncryption) {
                [nodes addObject:@{@"name": @"packet-encryption", @"type": @"EncryptionClient",
                                   @"settings": @{@"packet-mode": @YES, @"algorithm": @"xchacha20-poly1305", @"password": outerSecret,
                                                  @"salt": @"waterwall-packet", @"kdf-iterations": @12000}, @"next": @"pts"}];
            }
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
            NSDictionary *settings = [self settings:@{@"host": effectiveSNI, @"path": @"/", @"scheme": scheme,
                                                      @"port": @(port), @"http-version": httpVersionValue,
                                                      @"websocket": @([configuration[@"http"] isEqualToString:@"websocket"])}
                                          overrides:advanced[@"http"]
                                           required:@{@"host": effectiveSNI, @"port": @(port),
                                                      @"http-version": httpVersionValue,
                                                      @"websocket": @([configuration[@"http"] isEqualToString:@"websocket"])}];
            [nodes addObject:@{@"name": @"http", @"type": @"HttpClient", @"settings": settings, @"next": afterHTTP}];
        }
        if (bgp4) {
            [nodes addObject:@{@"name": @"bgp4", @"type": @"Bgp4Client", @"settings": @{}, @"next": afterBGP4}];
        }
        if (hasOuter) {
            NSMutableDictionary *outerSettings = [NSMutableDictionary new];
            if ([outer isEqualToString:@"tls"] || [outer isEqualToString:@"reality"] || quic) {
                outerSettings[@"sni"] = effectiveSNI;
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
                outerSettings[@"protocol"] = @"h3";
            }
            if ([options[@"tls_frag"] integerValue] > 0 && [self configurationAllowsFragmentation:configuration]) {
                // Auto uses the default sizes; only Manual takes the profile's
                BOOL manual = [options[@"tls_frag"] integerValue] == 2;
                NSInteger firstCut = manual ? MAX(1, [options[@"tls_frag_first"] integerValue] ?: 32) : 32;
                NSInteger following = manual ? MAX(1, [options[@"tls_frag_following"] integerValue] ?: 256) : 256;
                NSMutableArray *cuts = [NSMutableArray new];
                for (NSInteger offset = firstCut; offset < 16384 && cuts.count < 64; offset += following) [cuts addObject:@[@(offset), @0, @100]];
                outerSettings[@"fragment"] = @{@"mode": @"counter", @"count": @1, @"tls-hello-fragment": @YES, @"tls-hello-timeout-ms": @1000, @"cuts": cuts};
            }
            outerSettings = [self settings:outerSettings overrides:advanced[@"outer"] required:@{}].mutableCopy;
            if (advanced[@"outer"][@"algorithm"] == nil && advanced[@"outer"][@"method"] != nil) {
                outerSettings[@"algorithm"] = advanced[@"outer"][@"method"];
            }
            if ([outer isEqualToString:@"tls"] || [outer isEqualToString:@"reality"] || quic) {
                outerSettings[@"sni"] = effectiveSNI;
                outerSettings[@"verify"] = @(verifyTLS);
            }
            if (hasHTTP && httpVersion > 0 && ([outer isEqualToString:@"tls"] || [outer isEqualToString:@"reality"])) {
                outerSettings[@"alpns"] = httpVersion == 1 ? @[@"http/1.1"] : @[@"h2"];
            }
            if ([outer isEqualToString:@"reality"] || [outer isEqualToString:@"aead"]) outerSettings[@"password"] = outerSecret;
            NSString *outerType = [outer isEqualToString:@"tls"] ? @"TlsClient" : [outer isEqualToString:@"reality"] ? @"RealityClient" :
                                  [outer isEqualToString:@"aead"] ? @"EncryptionClient" :
                                  [outer isEqualToString:@"bgp4"] ? @"Bgp4Client" : @"QuicClient";
            NSString *carrier = kcp ? @"kcp" : @"connector";
            // WaterWall 1.6 QUIC sends datagrams only; over TCP they travel in UdpOverTcp frames
            BOOL quicOverTCP = quic && [configuration[@"quic-carrier"] isEqualToString:@"stream"];
            [nodes addObject:@{@"name": outer, @"type": outerType, @"settings": outerSettings, @"next": quicOverTCP ? @"udp-over-tcp" : carrier}];
            if (quicOverTCP) [nodes addObject:@{@"name": @"udp-over-tcp", @"type": @"UdpOverTcpClient", @"settings": @{}, @"next": carrier}];
        }
        if (kcp) {
            [nodes addObject:@{@"name": @"kcp", @"type": @"KcpClient",
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

// WaterWall 1.6: the phone's packets enter WireGuardClient, and its datagrams leave by a connector to the peer's endpoint.
static NSArray<NSDictionary *> *SRPWWWireGuardNodes(NSString *privateKey, NSArray<NSDictionary *> *peers) {
    return @[
        @{@"name": @"ne", @"type": @"NEPacketDevice", @"settings": @{}, @"next": @"wg"},
        @{@"name": @"wg", @"type": @"WireGuardClient", @"settings": @{@"privatekey": privateKey, @"peers": peers}, @"next": @"udp"},
        @{@"name": @"udp", @"type": @"UdpConnector", @"settings": @{@"address": @"dest_context->address", @"port": @"dest_context->port"}},
    ];
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
    NSArray *nodes = SRPWWWireGuardNodes(privateKey, @[@{
        @"publickey": serverPublicKey,
        @"allowedips": @"0.0.0.0/0",
        @"endpoint": endpoint,
        @"persistentkeepalive": @(MAX(0, keepalive))}]);
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
    // WaterWall 1.6's WireGuardClient talks to one server; a file with more peers runs as a WireGuard profile instead
    if (peers.count != 1) return nil;
    NSArray *nodes = SRPWWWireGuardNodes(interface[@"privatekey"], peers);
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

NSString *const SRPWaterWallInputTUN = @"tun";
NSString *const SRPWaterWallInputSOCKS5 = @"socks5";
NSString *const SRPWaterWallInputHTTP = @"http";
NSString *const SRPWaterWallHintConnection = @"HintConnectionIN";
NSString *const SRPWaterWallHintPacket = @"HintPacketIN";

static BOOL SRPWWIsHint(id type) {
    return [type isEqual:SRPWaterWallHintConnection] || [type isEqual:SRPWaterWallHintPacket];
}

static NSArray<NSDictionary *> *SRPWWNodes(NSDictionary *document) {
    id nodes = [document isKindOfClass:NSDictionary.class] ? document[@"nodes"] : nil;
    if (![nodes isKindOfClass:NSArray.class]) return @[];
    return [nodes filteredArrayUsingPredicate:[NSPredicate predicateWithBlock:^BOOL(id node, NSDictionary *bindings) {
        return [node isKindOfClass:NSDictionary.class];
    }]];
}

static NSDictionary *SRPWWDocumentWithNodes(NSDictionary *document, NSArray *nodes) {
    NSMutableDictionary *result = [document mutableCopy];
    result[@"nodes"] = nodes;
    return result;
}

// The nodes a node names in its settings: a Router's targets, the two paths of a HalfDuplexClient and the DNS chain of
// dns-behaviour. rename gets each name with the setting that holds it; the node comes back with the names
// rename returned.
static NSDictionary *SRPWWNodeWithReferences(NSDictionary *node, NSString *(^rename)(NSString *name, NSString *setting)) {
    NSDictionary *settings = [node[@"settings"] isKindOfClass:NSDictionary.class] ? node[@"settings"] : nil;
    NSMutableDictionary *changed = [settings mutableCopy];
    id (^renamed)(id, NSString *) = ^id(id value, NSString *setting) {
        return [value isKindOfClass:NSString.class] ? rename(value, setting) : value;
    };
    if ([node[@"type"] isEqual:@"HalfDuplexClient"]) {
        for (NSString *path in @[@"upload", @"download"]) changed[path] = renamed(settings[path], path);
    }
    if ([node[@"type"] isEqual:@"Router"] && [settings[@"rules"] isKindOfClass:NSArray.class]) {
        NSMutableArray *rules = [NSMutableArray new];
        for (id rule in settings[@"rules"]) {
            // A rule that is not an object names no node: it stays for WaterWall to refuse
            NSMutableDictionary *copy = [rule isKindOfClass:NSDictionary.class] ? [rule mutableCopy] : nil;
            copy[@"target"] = renamed(copy[@"target"], @"rules target");
            [rules addObject:copy ?: rule];
        }
        changed[@"rules"] = rules;
    }
    if ([settings[@"dns-behaviour"] isKindOfClass:NSDictionary.class]) {
        NSMutableDictionary *behaviour = [settings[@"dns-behaviour"] mutableCopy];
        behaviour[@"dns-next"] = renamed(behaviour[@"dns-next"], @"dns-next");
        changed[@"dns-behaviour"] = behaviour;
    }
    if (settings == nil || [changed isEqualToDictionary:settings]) return node;
    NSMutableDictionary *result = [node mutableCopy];
    result[@"settings"] = changed;
    return result;
}

// A WaterWall client config written for a computer starts at its own listener and SOCKS5 or HTTP proxy server. SRP supplies
// that input itself, so in a file without a hint the pair becomes the connection hint.
static NSDictionary *SRPWWDocumentWithHintForLocalProxy(NSDictionary *document) {
    NSArray<NSDictionary *> *nodes = SRPWWNodes(document);
    NSMutableSet *names = [NSMutableSet new], *followers = [NSMutableSet new];
    for (NSDictionary *node in nodes) {
        if (SRPWWIsHint(node[@"type"])) return document;
        if ([node[@"name"] isKindOfClass:NSString.class]) [names addObject:node[@"name"]];
        if ([node[@"next"] isKindOfClass:NSString.class]) [followers addObject:node[@"next"]];
    }
    NSDictionary *listener = nil, *server = nil;
    for (NSDictionary *node in nodes) {
        if (![@[@"TcpListener", @"TcpUdpListener"] containsObject:node[@"type"] ?: @""] || [followers containsObject:node[@"name"] ?: @""]) continue;
        for (NSDictionary *next in nodes) {
            if (![node[@"next"] isKindOfClass:NSString.class] || ![next[@"name"] isEqual:node[@"next"]] ||
                ![@[@"Socks5Server", @"HttpProxyServer"] containsObject:next[@"type"] ?: @""]) continue;
            if (listener != nil) return document;   // two local proxies: which one is the input is not the app's guess
            listener = node;
            server = next;
        }
    }
    if (listener == nil || ![server[@"next"] isKindOfClass:NSString.class]) return document;
    NSString *name = @"input";
    for (NSInteger suffix = 2; [names containsObject:name]; suffix++) name = [NSString stringWithFormat:@"input-%ld", (long)suffix];
    NSMutableArray *result = [NSMutableArray arrayWithObject:@{@"name": name, @"type": SRPWaterWallHintConnection, @"settings": @{},
                                                               @"next": server[@"next"]}];
    for (NSDictionary *node in nodes) {
        if (node != listener && node != server) [result addObject:node];
    }
    return SRPWWDocumentWithNodes(document, result);
}

// WaterWall's own loader takes // comments and $name$ placeholders, each standing for a value of the top-level
// "variables" object. JSON has neither: a comment goes, and a placeholder becomes a marked string that SRPWWParsedProfile
// replaces once the text is parsed.
static NSString *const SRPWWVariableMarker = @"$srp-variable$:";

static NSString *SRPWWPlainJSON(NSString *text) {
    NSMutableString *plain = [NSMutableString stringWithCapacity:text.length];
    NSUInteger length = text.length, copied = 0;
    BOOL inString = NO;
    for (NSUInteger index = 0; index < length; index++) {
        unichar character = [text characterAtIndex:index];
        if (inString) {
            if (character == '\\') index++;
            else if (character == '"') inString = NO;
            continue;
        }
        if (character == '"') {
            inString = YES;
            continue;
        }
        BOOL comment = character == '/' && index + 1 < length && [text characterAtIndex:index + 1] == '/';
        if (!comment && character != '$') continue;
        NSUInteger end = index + 1;
        while (end < length && [text characterAtIndex:end] != '\n' && [text characterAtIndex:end] != '\r' &&
               (comment || [text characterAtIndex:end] != '$')) end++;
        NSString *name = comment ? nil : [text substringWithRange:NSMakeRange(index + 1, end - index - 1)];
        // An unfinished or empty placeholder stays as it is, and the text then fails as JSON
        if (!comment && (end >= length || [text characterAtIndex:end] != '$' || name.length == 0 ||
                         [name rangeOfCharacterFromSet:[NSCharacterSet characterSetWithCharactersInString:@"\"\\"]].location != NSNotFound)) continue;
        [plain appendString:[text substringWithRange:NSMakeRange(copied, index - copied)]];
        if (!comment) [plain appendFormat:@"\"%@%@\"", SRPWWVariableMarker, name];
        copied = comment ? end : end + 1;
        index = comment ? end - 1 : end;
    }
    [plain appendString:[text substringFromIndex:copied]];
    return plain;
}

// How much of a profile a value is: the characters of its strings and keys, and one for each value
static long long SRPWWWeight(id value) {
    if ([value isKindOfClass:NSString.class]) return (long long)[value length];
    long long weight = 1;
    if ([value isKindOfClass:NSArray.class]) {
        for (id item in value) weight += SRPWWWeight(item);
    } else if ([value isKindOfClass:NSDictionary.class]) {
        for (NSString *key in value) weight += (long long)key.length + SRPWWWeight(value[key]);
    }
    return weight;
}

// room is what the values may still add: a value named many times must not grow the profile past what a file may hold
static id SRPWWWithVariables(id value, NSDictionary *variables, NSMutableSet<NSString *> *missing, long long *room) {
    if ([value isKindOfClass:NSString.class] && [value hasPrefix:SRPWWVariableMarker]) {
        NSString *name = [value substringFromIndex:SRPWWVariableMarker.length];
        id filled = variables[name];
        if (filled == nil) [missing addObject:name];
        else if (*room >= 0) *room -= SRPWWWeight(filled);
        return filled == nil || *room < 0 ? value : filled;
    }
    if ([value isKindOfClass:NSArray.class]) {
        NSMutableArray *items = [NSMutableArray new];
        for (id item in value) [items addObject:SRPWWWithVariables(item, variables, missing, room)];
        return items;
    }
    if ([value isKindOfClass:NSDictionary.class]) {
        NSMutableDictionary *items = [NSMutableDictionary new];
        for (id key in value) items[key] = SRPWWWithVariables(value[key], variables, missing, room);
        return items;
    }
    return value;
}

// The profile of a file: plain JSON, or WaterWall's config syntax with its comments removed and its variables filled in.
static id SRPWWParsedProfile(NSString *text, NSString **problem) {
    id document = [NSJSONSerialization JSONObjectWithData:[text dataUsingEncoding:NSUTF8StringEncoding] options:0 error:nil];
    if (document != nil) return document;
    NSString *plain = SRPWWPlainJSON(text);
    document = [plain isEqualToString:text] ? nil :
        [NSJSONSerialization JSONObjectWithData:[plain dataUsingEncoding:NSUTF8StringEncoding] options:0 error:nil];
    if (![document isKindOfClass:NSDictionary.class]) return document;
    NSDictionary *variables = [document[@"variables"] isKindOfClass:NSDictionary.class] ? document[@"variables"] : @{};
    NSMutableDictionary *profile = [document mutableCopy];
    [profile removeObjectForKey:@"variables"];
    NSMutableSet<NSString *> *missing = [NSMutableSet new];
    long long room = 1048576;
    id filled = SRPWWWithVariables(profile, variables, missing, &room);
    if (missing.count == 0 && room < 0) {
        *problem = @"The file is larger than 1 MB with its variables filled in.";
        return nil;
    }
    if (missing.count > 0) {
        // Of several, the first by name: a dictionary has no order, and the message must not change from run to run
        NSString *first = [missing.allObjects sortedArrayUsingComparator:^NSComparisonResult(NSString *one, NSString *other) {
            return [one compare:other options:NSLiteralSearch];
        }].firstObject;
        *problem = [NSString stringWithFormat:@"The file uses the variable $%@$, but its \"variables\" block does not define it.", first];
        return nil;
    }
    return filled;
}

@implementation SRPWaterWallNodeChain

+ (NSUserDefaults *)sharedDefaults {
    return [[NSUserDefaults alloc] initWithSuiteName:@"group.tr.com.srp.vpn"] ?: NSUserDefaults.standardUserDefaults;
}

+ (NSString *)currentInput {
    NSString *input = [[self sharedDefaults] stringForKey:@"SRPWaterWallInput"];
    return [@[SRPWaterWallInputSOCKS5, SRPWaterWallInputHTTP] containsObject:input] ? input : SRPWaterWallInputTUN;
}

+ (void)setCurrentInput:(NSString *)input {
    [[self sharedDefaults] setObject:input forKey:@"SRPWaterWallInput"];
}

+ (NSInteger)portForInput:(NSString *)input {
    return [input isEqualToString:SRPWaterWallInputSOCKS5] ? 1080 : [input isEqualToString:SRPWaterWallInputHTTP] ? 8080 : 0;
}

+ (NSDictionary *)documentWithJSON:(NSString *)json error:(NSString **)error {
    NSString *problem = nil;
    id document = [json isKindOfClass:NSString.class] ? SRPWWParsedProfile(json, &problem) : nil;
    // A number no double can hold (-1e999 is read as an infinity) could not be written back
    if (document != nil && ![NSJSONSerialization isValidJSONObject:document]) document = nil;
    if ([document isKindOfClass:NSDictionary.class]) document = SRPWWDocumentWithHintForLocalProxy(document);
    if (problem == nil) problem = document == nil ? @"The file is not valid JSON." : [self validationErrorForDocument:document];
    if (problem != nil) {
        if (error) *error = problem;
        return nil;
    }
    return [self currentDocumentForDocument:document];
}

+ (NSDictionary *)currentDocumentForDocument:(NSDictionary *)document {
    NSArray<NSDictionary *> *nodes = SRPWWNodes(document);
    NSMutableSet *names = [NSMutableSet setWithArray:[nodes valueForKey:@"name"]];
    NSMutableArray *current = [NSMutableArray new];
    BOOL changed = NO;
    for (NSDictionary *node in nodes) {
        id mode = [node[@"settings"] isKindOfClass:NSDictionary.class] ? node[@"settings"][@"carrier-mode"] : nil;
        if (![node[@"type"] isEqual:@"QuicClient"] || mode == nil) {
            [current addObject:node];
            continue;
        }
        changed = YES;
        NSMutableDictionary *quic = [node mutableCopy];
        NSMutableDictionary *settings = [node[@"settings"] mutableCopy];
        [settings removeObjectForKey:@"carrier-mode"];
        quic[@"settings"] = settings;
        [current addObject:quic];
        if (![mode isEqual:@"stream"]) continue;
        NSString *name = @"udp-over-tcp";
        for (NSInteger suffix = 2; [names containsObject:name]; suffix++) name = [NSString stringWithFormat:@"udp-over-tcp-%ld", (long)suffix];
        [names addObject:name];
        NSMutableDictionary *framing = [@{@"name": name, @"type": @"UdpOverTcpClient", @"settings": @{}} mutableCopy];
        framing[@"next"] = node[@"next"];
        quic[@"next"] = name;
        [current addObject:framing];
    }
    return changed ? SRPWWDocumentWithNodes(document, current) : document;
}

+ (NSString *)validationErrorForDocument:(NSDictionary *)document {
    if (![document isKindOfClass:NSDictionary.class] || ![document[@"nodes"] isKindOfClass:NSArray.class]) {
        return @"The file is not a WaterWall profile: it has no \"nodes\" list.";
    }
    NSArray *nodes = document[@"nodes"];
    // A node SRP does not run blocks the file whatever else is in it, wherever it is
    for (NSUInteger index = 0; index < nodes.count; index++) {
        id node = nodes[index];
        if (![node isKindOfClass:NSDictionary.class] || ![node[@"type"] isKindOfClass:NSString.class]) continue;
        NSString *label = [node[@"name"] isKindOfClass:NSString.class] && [node[@"name"] length] > 0 ?
            [NSString stringWithFormat:@"Node \"%@\"", node[@"name"]] : [NSString stringWithFormat:@"Node %lu", (unsigned long)index + 1];
        if ([node[@"type"] isEqualToString:@"RawSocket"]) {
            return [label stringByAppendingString:@" is a RawSocket node: raw socket nodes cannot be imported."];
        }
        if ([@[@"TunDevice", @"PacketsToConnection", @"NEPacketDevice"] containsObject:node[@"type"]]) {
            return [label stringByAppendingFormat:@" is a %@ node: SRP supplies TunDevice and PacketsToConnection itself when it connects, so leave them out of the profile.", node[@"type"]];
        }
    }
    NSMutableDictionary<NSString *, NSDictionary *> *byName = [NSMutableDictionary new];
    NSMutableArray<NSDictionary *> *hints = [NSMutableArray new];
    for (NSUInteger index = 0; index < nodes.count; index++) {
        id node = nodes[index];
        if (![node isKindOfClass:NSDictionary.class]) return [NSString stringWithFormat:@"Node %lu is not a JSON object.", (unsigned long)index + 1];
        id name = node[@"name"];
        if (![name isKindOfClass:NSString.class] || [name length] == 0) return [NSString stringWithFormat:@"Node %lu has no name.", (unsigned long)index + 1];
        if (![node[@"type"] isKindOfClass:NSString.class] || [node[@"type"] length] == 0) return [NSString stringWithFormat:@"Node \"%@\" has no type.", name];
        if (node[@"settings"] != nil && ![node[@"settings"] isKindOfClass:NSDictionary.class]) {
            return [NSString stringWithFormat:@"The settings of node \"%@\" are not a JSON object.", name];
        }
        id next = node[@"next"];
        if (next != nil && (![next isKindOfClass:NSString.class] || [next length] == 0)) {
            return [NSString stringWithFormat:@"The next of node \"%@\" is not a node name.", name];
        }
        if (byName[name] != nil) return [NSString stringWithFormat:@"Two nodes are named \"%@\": every node needs a name of its own.", name];
        byName[name] = node;
        if (SRPWWIsHint(node[@"type"])) [hints addObject:node];
    }
    if (hints.count == 0) return @"The chain must start with an input hint: HintConnectionIN or HintPacketIN.";
    if (hints.count > 1) {
        return [NSString stringWithFormat:@"The profile has more than one input hint (\"%@\" and \"%@\"); it needs exactly one.",
                hints[0][@"name"], hints[1][@"name"]];
    }
    NSDictionary *hint = hints.firstObject;
    NSString *hintName = hint[@"name"];
    if ([hint[@"settings"] count] > 0) return [NSString stringWithFormat:@"The input hint \"%@\" has settings, but a hint takes none.", hintName];
    for (NSDictionary *node in nodes) {
        if ([node[@"next"] isEqual:hintName]) {
            return [NSString stringWithFormat:@"Node \"%@\" points to the input hint \"%@\", which must start the chain.", node[@"name"], hintName];
        }
    }
    if (hint[@"next"] == nil) {
        return [NSString stringWithFormat:@"The input hint \"%@\" has no next node: import a WaterWall profile or insert a node after it.", hintName];
    }
    NSMutableSet<NSString *> *seen = [NSMutableSet setWithObject:hintName];
    for (NSDictionary *node = hint; node[@"next"] != nil;) {
        NSString *next = node[@"next"];
        NSDictionary *successor = byName[next];
        if (successor == nil) return [NSString stringWithFormat:@"Node \"%@\" names \"%@\" as next, but no node has that name.", node[@"name"], next];
        if ([seen containsObject:next]) {
            return [NSString stringWithFormat:@"Following next from \"%@\" comes back to \"%@\": the chain has a cycle.", node[@"name"], next];
        }
        [seen addObject:next];
        node = successor;
    }
    __block NSString *problem = nil;
    for (NSDictionary *node in nodes) {
        SRPWWNodeWithReferences(node, ^NSString *(NSString *name, NSString *setting) {
            if (problem != nil) return name;
            if ([name isEqual:hintName]) {
                problem = [NSString stringWithFormat:@"Node \"%@\" names the input hint \"%@\" as its %@, but the hint must start the chain.",
                           node[@"name"], name, setting];
            } else if (byName[name] == nil) {
                problem = [NSString stringWithFormat:@"Node \"%@\" names \"%@\" as its %@, but no node has that name.", node[@"name"], name, setting];
            }
            return name;
        });
    }
    return problem;
}

+ (NSString *)JSONWithDocument:(NSDictionary *)document {
    NSData *data = [NSJSONSerialization dataWithJSONObject:document options:NSJSONWritingSortedKeys | NSJSONWritingWithoutEscapingSlashes error:nil];
    return data ? [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding] : @"{}";
}

+ (NSDictionary *)emptyDocument {
    return @{@"nodes": @[@{@"name": @"input", @"type": SRPWaterWallHintConnection, @"settings": @{}}]};
}

+ (NSDictionary *)hintOfDocument:(NSDictionary *)document {
    for (NSDictionary *node in SRPWWNodes(document)) {
        if (SRPWWIsHint(node[@"type"])) return node;
    }
    return nil;
}

+ (NSArray<NSDictionary *> *)chainOfDocument:(NSDictionary *)document {
    NSArray<NSDictionary *> *nodes = SRPWWNodes(document);
    NSDictionary *hint = [self hintOfDocument:document];
    if (hint == nil) return nodes;   // nothing to follow: the file's order
    NSMutableDictionary<NSString *, NSDictionary *> *byName = [NSMutableDictionary new];
    for (NSDictionary *node in nodes) {
        if ([node[@"name"] isKindOfClass:NSString.class] && byName[node[@"name"]] == nil) byName[node[@"name"]] = node;
    }
    NSMutableArray *chain = [NSMutableArray arrayWithObject:hint];
    NSMutableSet *seen = [NSMutableSet setWithObject:hint[@"name"] ?: @""];
    for (NSDictionary *node = hint; [node[@"next"] isKindOfClass:NSString.class];) {
        NSDictionary *successor = byName[node[@"next"]];
        if (successor == nil || [seen containsObject:node[@"next"]]) break;
        [seen addObject:node[@"next"]];
        [chain addObject:successor];
        node = successor;
    }
    return chain;
}

+ (NSArray<NSDictionary *> *)branchNodesOfDocument:(NSDictionary *)document {
    NSArray<NSDictionary *> *chain = [self chainOfDocument:document];
    NSMutableArray<NSDictionary *> *others = [NSMutableArray new];
    NSMutableDictionary<NSString *, NSDictionary *> *byName = [NSMutableDictionary new];
    for (NSDictionary *node in SRPWWNodes(document)) {
        if ([chain containsObject:node] || ![node[@"name"] isKindOfClass:NSString.class]) continue;
        [others addObject:node];
        if (byName[node[@"name"]] == nil) byName[node[@"name"]] = node;
    }
    NSMutableSet *followers = [NSMutableSet new];
    for (NSDictionary *node in others) {
        if ([node[@"next"] isKindOfClass:NSString.class]) [followers addObject:node[@"next"]];
    }
    // Each branch from its first node along next; what a cycle leaves over keeps the file's order
    NSMutableArray<NSDictionary *> *ordered = [NSMutableArray new];
    for (NSInteger pass = 0; pass < 2; pass++) {
        for (NSDictionary *start in others) {
            if (pass == 0 && [followers containsObject:start[@"name"]]) continue;
            for (NSDictionary *node = start; node != nil && ![ordered containsObject:node];
                 node = [node[@"next"] isKindOfClass:NSString.class] ? byName[node[@"next"]] : nil) {
                [ordered addObject:node];
            }
        }
    }
    return ordered;
}

+ (NSString *)summaryOfDocument:(NSDictionary *)document {
    if ([document[@"name"] isKindOfClass:NSString.class] && [document[@"name"] length] > 0) return document[@"name"];
    NSMutableArray *types = [NSMutableArray new];
    for (NSDictionary *node in [self chainOfDocument:document]) {
        if (!SRPWWIsHint(node[@"type"]) && [node[@"type"] isKindOfClass:NSString.class]) [types addObject:node[@"type"]];
    }
    return types.count > 0 ? [types componentsJoinedByString:@" → "] : @"No nodes";
}

+ (NSDictionary *)document:(NSDictionary *)document replacingNodeNamed:(NSString *)name withNode:(NSDictionary *)node {
    NSString *newName = node[@"name"];
    NSMutableArray *nodes = [NSMutableArray new];
    for (NSDictionary *item in SRPWWNodes(document)) {
        if ([item[@"name"] isEqual:name]) {
            [nodes addObject:node];
        } else if ([newName isEqual:name]) {
            [nodes addObject:item];
        } else {
            // A rename keeps the links that pointed to the old name: next, and the settings that name a node
            NSMutableDictionary *linked = [SRPWWNodeWithReferences(item, ^NSString *(NSString *reference, NSString *setting) {
                return [reference isEqual:name] ? newName : reference;
            }) mutableCopy];
            if ([item[@"next"] isEqual:name]) linked[@"next"] = newName;
            [nodes addObject:linked];
        }
    }
    return SRPWWDocumentWithNodes(document, nodes);
}

+ (NSDictionary *)document:(NSDictionary *)document insertingNode:(NSDictionary *)node afterNodeNamed:(NSString *)name {
    NSMutableArray *nodes = [NSMutableArray new];
    for (NSDictionary *item in SRPWWNodes(document)) {
        if (![item[@"name"] isEqual:name]) {
            [nodes addObject:item];
            continue;
        }
        // The new node takes over the former successor; after the last node it becomes the last one
        NSMutableDictionary *inserted = [node mutableCopy];
        inserted[@"next"] = item[@"next"];
        NSMutableDictionary *previous = [item mutableCopy];
        previous[@"next"] = inserted[@"name"];
        [nodes addObject:previous];
        [nodes addObject:inserted];
    }
    return SRPWWDocumentWithNodes(document, nodes);
}

+ (NSDictionary *)document:(NSDictionary *)document deletingNodeNamed:(NSString *)name {
    NSDictionary *deleted = nil;
    for (NSDictionary *item in SRPWWNodes(document)) {
        if ([item[@"name"] isEqual:name]) deleted = item;
    }
    NSMutableArray *nodes = [NSMutableArray new];
    for (NSDictionary *item in SRPWWNodes(document)) {
        if ([item[@"name"] isEqual:name]) continue;
        if ([item[@"next"] isEqual:name]) {
            // The predecessor links to the successor, or becomes the last node
            NSMutableDictionary *linked = [item mutableCopy];
            linked[@"next"] = deleted[@"next"];
            [nodes addObject:linked];
        } else {
            [nodes addObject:item];
        }
    }
    return SRPWWDocumentWithNodes(document, nodes);
}

static BOOL SRPWWIsConnector(id type) {
    return [@[@"TcpConnector", @"UdpConnector", @"TcpUdpConnector"] containsObject:type ?: @""];
}

// A connector's own server, not the destination of the connection it carries
static NSString *SRPWWFixedAddress(NSDictionary *node) {
    id address = [node[@"settings"] isKindOfClass:NSDictionary.class] ? node[@"settings"][@"address"] : nil;
    // A value taken from the connection (dest_context->address, src_context->address), an IPv6 literal and a CIDR range are
    // WaterWall's to handle: there is no IPv4 server of the profile to look up
    if (!SRPWWIsConnector(node[@"type"]) || ![address isKindOfClass:NSString.class] || [address length] == 0 ||
        [address containsString:@"_context->"] || [address containsString:@":"] || [address containsString:@"/"]) return nil;
    return address;
}

+ (NSArray<NSDictionary *> *)endpointsOfDocument:(NSDictionary *)document {
    NSMutableArray<NSDictionary *> *ordered = [[[[self chainOfDocument:document] reverseObjectEnumerator] allObjects] mutableCopy];
    for (NSDictionary *node in SRPWWNodes(document)) {
        if (![ordered containsObject:node]) [ordered addObject:node];
    }
    NSMutableArray *endpoints = [NSMutableArray new];
    for (NSDictionary *node in ordered) {
        NSString *host = SRPWWFixedAddress(node);
        id port = node[@"settings"][@"port"];
        NSInteger number = [port isKindOfClass:NSNumber.class] || [port isKindOfClass:NSString.class] ? [port integerValue] : 0;
        if (host == nil || number < 1 || number > 65535) continue;
        [endpoints addObject:@{@"host": host, @"port": @(number)}];
    }
    return endpoints;
}

static BOOL SRPWWRouterUsesGeoIP(NSDictionary *node) {
    if (![node[@"type"] isEqual:@"Router"] || ![node[@"settings"] isKindOfClass:NSDictionary.class]) return NO;
    id rules = node[@"settings"][@"rules"];
    if (![rules isKindOfClass:NSArray.class]) return NO;
    for (id rule in rules) {
        for (NSString *key in @[@"destination-ip", @"source-ips"]) {
            id addresses = [rule isKindOfClass:NSDictionary.class] ? rule[key] : nil;
            for (id address in [addresses isKindOfClass:NSArray.class] ? addresses : addresses ? @[addresses] : @[]) {
                NSString *token = [address isKindOfClass:NSString.class] ? [address lowercaseString] : @"";
                if ([token hasPrefix:@"geoip:"] || [token hasPrefix:@"!geoip:"]) return YES;
            }
        }
    }
    return NO;
}

+ (BOOL)documentUsesGeoIP:(NSDictionary *)document {
    for (NSDictionary *node in SRPWWNodes(document)) {
        if (SRPWWRouterUsesGeoIP(node)) return YES;
    }
    return NO;
}

+ (BOOL)documentUsesUDPCarrier:(NSDictionary *)document {
    return [[self chainOfDocument:document].lastObject[@"type"] isEqual:@"UdpConnector"];
}

+ (NSSet<NSString *> *)includedNodeTypes {
    static NSSet<NSString *> *included;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        included = [NSSet setWithArray:@[
            @"AuthenticationClient", @"Bgp4Client", @"BlackHole", @"ConnectionFisherClient", @"ConnectionStripeClient",
            @"ConnectionToPackets", @"Disturber", @"DomainResolver", @"EncryptionClient", @"EnetClient", @"GnsClient",
            @"HalfDuplexClient", @"HeaderClient", @"HttpClient", @"HttpProxyClient", @"HttpProxyServer", @"JunkDatagramSender",
            @"KcpClient", @"KeepAliveClient", @"LoggerTunnel", @"MuxClient", @"ObfuscatorClient", @"PacketsToStream", @"QuicClient",
            @"RealityClient", @"Router", @"RtmpClient", @"Socks5Client", @"Socks5Server", @"SpeedLimit",
            @"StreamFragmenter", @"TcpConnector", @"TcpListener", @"TcpUdpConnector", @"TcpUdpListener", @"TlsClient",
            @"TrojanClient", @"UdpConnector", @"UdpListener", @"UdpOverTcpClient", @"UserController", @"VlessClient",
            @"VmessClient", @"WireGuardClient"]];
    });
    return included;
}

+ (NSDictionary *)runtimeDocumentForDocument:(NSDictionary *)document
                                       input:(NSString *)input
                                     fakeDNS:(BOOL)fakeDNS
                           geoIPDatabasePath:(NSString *)geoIPDatabasePath
                                   addresses:(NSDictionary<NSString *, NSString *> *)addresses
                                       error:(NSString **)error {
    document = [self currentDocumentForDocument:document];
    NSString *problem = [self validationErrorForDocument:document];
    NSDictionary *hint = [self hintOfDocument:document];
    BOOL packets = [hint[@"type"] isEqual:SRPWaterWallHintPacket];
    if (problem == nil && packets && ![input isEqualToString:SRPWaterWallInputTUN]) {
        problem = @"This profile starts with HintPacketIN, which takes IP packets, but the local SOCKS5 and HTTP proxies supply connections. Choose System VPN (TUN) in Settings → WaterWall Input to use it.";
    }
    for (NSDictionary *node in problem == nil ? SRPWWNodes(document) : @[]) {
        if (node == hint || [[self includedNodeTypes] containsObject:node[@"type"]]) continue;
        problem = [NSString stringWithFormat:@"Node \"%@\" is a %@ node, which the app's WaterWall does not include.", node[@"name"], node[@"type"]];
        break;
    }
    if (problem == nil && [self documentUsesGeoIP:document] && geoIPDatabasePath.length == 0) {
        problem = @"The profile routes by country, but the GeoIP database is not available.";
    }
    if (problem != nil) {
        if (error) *error = problem;
        return nil;
    }
    NSMutableSet<NSString *> *names = [NSMutableSet setWithArray:[SRPWWNodes(document) valueForKey:@"name"]];
    NSString *(^unique)(NSString *) = ^NSString *(NSString *base) {
        NSString *name = base;
        for (NSInteger suffix = 2; [names containsObject:name]; suffix++) name = [NSString stringWithFormat:@"%@-%ld", base, (long)suffix];
        [names addObject:name];
        return name;
    };
    NSMutableArray *nodes = [NSMutableArray new];
    NSString *successor = hint[@"next"];
    if ([input isEqualToString:SRPWaterWallInputSOCKS5]) {
        NSString *server = unique(@"srp-socks5");
        [nodes addObject:@{@"name": unique(@"srp-socks5-listener"), @"type": @"TcpUdpListener",
                           @"settings": @{@"address": @"127.0.0.1", @"port": @1080, @"nodelay": @YES}, @"next": server}];
        [nodes addObject:@{@"name": server, @"type": @"Socks5Server",
                           @"settings": @{@"no-auth": @YES, @"connect": @YES, @"udp": @YES, @"ipv4": @"127.0.0.1"},
                           @"next": successor}];
    } else if ([input isEqualToString:SRPWaterWallInputHTTP]) {
        NSString *server = unique(@"srp-http-proxy");
        [nodes addObject:@{@"name": unique(@"srp-http-listener"), @"type": @"TcpListener",
                           @"settings": @{@"address": @"127.0.0.1", @"port": @8080, @"nodelay": @YES}, @"next": server}];
        [nodes addObject:@{@"name": server, @"type": @"HttpProxyServer", @"settings": @{@"no-auth": @YES}, @"next": successor}];
    } else if (packets) {
        [nodes addObject:@{@"name": unique(@"srp-device"), @"type": @"NEPacketDevice", @"settings": @{}, @"next": successor}];
    } else {
        NSString *connections = unique(@"srp-connections");
        [nodes addObject:@{@"name": unique(@"srp-device"), @"type": @"NEPacketDevice", @"settings": @{}, @"next": connections}];
        NSMutableDictionary *settings = [@{@"mtu": @1420, @"max-pending-bytes": @65536, @"max-total-pending-bytes": @16777216} mutableCopy];
        if (fakeDNS) settings[@"fake-dns"] = SRPWWFakeDNSSettings();
        [nodes addObject:@{@"name": connections, @"type": @"PacketsToConnection", @"settings": settings, @"next": successor}];
    }
    for (NSDictionary *node in SRPWWNodes(document)) {
        if (node == hint) continue;
        NSString *host = SRPWWFixedAddress(node);
        BOOL geoIP = SRPWWRouterUsesGeoIP(node);
        if ((host == nil || addresses[host] == nil) && !geoIP) {
            [nodes addObject:node];
            continue;
        }
        NSMutableDictionary *runtime = [node mutableCopy];
        NSMutableDictionary *settings = [node[@"settings"] mutableCopy];
        // The tunnel's routes leave out the address it resolved, so the connector must use that one
        if (host != nil && addresses[host] != nil) settings[@"address"] = addresses[host];
        // A path in the file belongs to another machine; on the phone the app's database is the one there is
        if (geoIP) settings[@"geoip-db-path"] = geoIPDatabasePath;
        runtime[@"settings"] = settings;
        [nodes addObject:runtime];
    }
    NSString *name = [document[@"name"] isKindOfClass:NSString.class] && [document[@"name"] length] > 0 ? document[@"name"] : @"WaterWall";
    return @{@"name": name, @"nodes": nodes};
}

+ (NSDictionary *)documentForConfiguration:(NSDictionary *)configuration
                                    server:(NSString *)server
                                      port:(NSInteger)port
                                       sni:(NSString *)sni
                                 verifyTLS:(BOOL)verifyTLS
                                    secret:(NSString *)secret
                               outerSecret:(NSString *)outerSecret
                                   options:(NSDictionary *)options {
    if ([SRPWaterWallChainConfig isWireGuardConfiguration:configuration]) return nil;
    // The builder wants the database to route by country; the runtime sets the phone's own path again
    NSMutableDictionary *builderOptions = [options mutableCopy] ?: [NSMutableDictionary new];
    builderOptions[@"ww_geoip_db_path"] = @"geoip.mmdb";
    NSString *json = [SRPWaterWallChainConfig nodesJSONForConfiguration:configuration server:server port:port sni:sni
                                                              verifyTLS:verifyTLS secret:secret outerSecret:outerSecret
                                                                options:builderOptions];
    NSDictionary *built = json ? [NSJSONSerialization JSONObjectWithData:[json dataUsingEncoding:NSUTF8StringEncoding] options:0 error:nil] : nil;
    NSArray<NSDictionary *> *nodes = SRPWWNodes(built);
    NSDictionary *device = nil;
    for (NSDictionary *node in nodes) {
        if ([node[@"type"] isEqual:@"NEPacketDevice"]) device = node;
    }
    if (device == nil) return nil;
    NSDictionary *connections = nil;
    for (NSDictionary *node in nodes) {
        if ([node[@"name"] isEqual:device[@"next"]] && [node[@"type"] isEqual:@"PacketsToConnection"]) connections = node;
    }
    NSMutableArray *result = [NSMutableArray arrayWithObject:@{@"name": @"input",
        @"type": connections ? SRPWaterWallHintConnection : SRPWaterWallHintPacket, @"settings": @{},
        @"next": connections ? connections[@"next"] : device[@"next"]}];
    for (NSDictionary *node in nodes) {
        if (node == device || node == connections) continue;
        if ([node[@"type"] isEqual:@"Router"] && node[@"settings"][@"geoip-db-path"] != nil) {
            NSMutableDictionary *router = [node mutableCopy];
            NSMutableDictionary *settings = [node[@"settings"] mutableCopy];
            [settings removeObjectForKey:@"geoip-db-path"];
            router[@"settings"] = settings;
            [result addObject:router];
        } else {
            [result addObject:node];
        }
    }
    NSDictionary *document = @{@"name": built[@"name"] ?: @"WaterWall", @"nodes": result};
    return [self validationErrorForDocument:document] == nil ? document : nil;
}

@end

