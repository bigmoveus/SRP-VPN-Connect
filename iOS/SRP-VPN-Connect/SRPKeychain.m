//
//  SRPKeychain.m
//  SRP-VPN-Connect
//

#import "SRPKeychain.h"
#import <Security/Security.h>

static NSString * const kSRPKeychainService = @"tr.com.srp.vpn";

@implementation SRPKeychain

+ (NSMutableDictionary *)baseQueryForKey:(NSString *)key {
    return [@{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: kSRPKeychainService,
        (__bridge id)kSecAttrAccount: key,
    } mutableCopy];
}

+ (BOOL)setPassword:(NSString *)password forKey:(NSString *)key {
    if (password == nil || key == nil) return NO;
    NSMutableDictionary *query = [self baseQueryForKey:key];
    // delete any existing item first (simplest update strategy)
    SecItemDelete((__bridge CFDictionaryRef)query);
    query[(__bridge id)kSecValueData] = [password dataUsingEncoding:NSUTF8StringEncoding];
#if !TARGET_OS_OSX
    query[(__bridge id)kSecAttrAccessible] = (__bridge id)kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly;
#endif
    OSStatus status = SecItemAdd((__bridge CFDictionaryRef)query, NULL);
    return status == errSecSuccess;
}

+ (nullable NSString *)passwordForKey:(NSString *)key {
    if (key == nil) return nil;
    NSMutableDictionary *query = [self baseQueryForKey:key];
    query[(__bridge id)kSecReturnData] = @YES;
    query[(__bridge id)kSecMatchLimit] = (__bridge id)kSecMatchLimitOne;
    CFTypeRef result = NULL;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &result);
    if (status != errSecSuccess || result == NULL) {
        return nil;
    }
    NSData *data = (__bridge_transfer NSData *)result;
    return [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
}

+ (BOOL)deletePasswordForKey:(NSString *)key {
    if (key == nil) return NO;
    NSMutableDictionary *query = [self baseQueryForKey:key];
    OSStatus status = SecItemDelete((__bridge CFDictionaryRef)query);
    return status == errSecSuccess || status == errSecItemNotFound;
}

#pragma mark - Client certificates

/* The access group shared between the app and the packet-tunnel extension.
 * The app's own app-identifier group already IS <team>.tr.com.srp.vpn (the
 * app bundle id is tr.com.srp.vpn); the extension reaches it through its
 * keychain-access-groups entitlement.  The value is probed once from the
 * process's own default keychain group instead of hardcoding the team id.
 * Returns nil on macOS (single-process tests; no group needed). */
+ (nullable NSString *)sharedAccessGroup {
#if TARGET_OS_OSX
    return nil;
#else
    static NSString *group = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        NSDictionary *probe = @{
            (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
            (__bridge id)kSecAttrService: @"tr.com.srp.vpn.probe",
            (__bridge id)kSecAttrAccount: @"probe",
            (__bridge id)kSecReturnAttributes: @YES,
        };
        CFDictionaryRef result = NULL;
        OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)probe, (CFTypeRef *)&result);
        if (status == errSecItemNotFound) {
            NSMutableDictionary *add = [probe mutableCopy];
            add[(__bridge id)kSecValueData] = [@"probe" dataUsingEncoding:NSUTF8StringEncoding];
            status = SecItemAdd((__bridge CFDictionaryRef)add, (CFTypeRef *)&result);
            SecItemDelete((__bridge CFDictionaryRef)probe);
        }
        if (status == errSecSuccess && result != NULL) {
            group = [(__bridge NSDictionary *)result objectForKey:(__bridge id)kSecAttrAccessGroup];
            CFRelease(result);
        }
    });
    return group;
#endif
}

+ (NSString *)certAccountForKey:(NSString *)key {
    return [@"cert:" stringByAppendingString:key];
}

+ (NSMutableDictionary *)certQueryForKey:(NSString *)key {
    NSMutableDictionary *query = [@{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: kSRPKeychainService,
        (__bridge id)kSecAttrAccount: [self certAccountForKey:key],
    } mutableCopy];
    NSString *group = [self sharedAccessGroup];
    if (group != nil) {
        query[(__bridge id)kSecAttrAccessGroup] = group;
    }
    return query;
}

+ (BOOL)setCertificate:(NSData *)p12 passphrase:(NSString *)passphrase forKey:(NSString *)key {
    if (p12.length == 0 || passphrase == nil || key == nil) return NO;
    NSDictionary *payload = @{@"p12": p12, @"passphrase": passphrase};
    NSData *data = [NSKeyedArchiver archivedDataWithRootObject:payload
                                         requiringSecureCoding:YES
                                                         error:NULL];
    if (data == nil) return NO;
    NSMutableDictionary *query = [self certQueryForKey:key];
    SecItemDelete((__bridge CFDictionaryRef)query);
    query[(__bridge id)kSecValueData] = data;
#if !TARGET_OS_OSX
    query[(__bridge id)kSecAttrAccessible] = (__bridge id)kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly;
#endif
    OSStatus status = SecItemAdd((__bridge CFDictionaryRef)query, NULL);
    return status == errSecSuccess;
}

+ (nullable NSData *)certificateForKey:(NSString *)key passphrase:(NSString * _Nullable * _Nullable)passphrase {
    if (key == nil) return nil;
    NSMutableDictionary *query = [self certQueryForKey:key];
    query[(__bridge id)kSecReturnData] = @YES;
    query[(__bridge id)kSecMatchLimit] = (__bridge id)kSecMatchLimitOne;
    CFTypeRef result = NULL;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &result);
    if (status != errSecSuccess || result == NULL) {
        return nil;
    }
    NSData *data = (__bridge_transfer NSData *)result;
    NSDictionary *payload = [NSKeyedUnarchiver unarchivedObjectOfClasses:
        [NSSet setWithObjects:NSDictionary.class, NSData.class, NSString.class, nil]
        fromData:data error:NULL];
    NSData *p12 = payload[@"p12"];
    if (![p12 isKindOfClass:NSData.class] || p12.length == 0) {
        return nil;
    }
    if (passphrase != NULL) {
        *passphrase = [payload[@"passphrase"] isKindOfClass:NSString.class] ? payload[@"passphrase"] : nil;
    }
    return p12;
}

+ (BOOL)deleteCertificateForKey:(NSString *)key {
    if (key == nil) return NO;
    NSMutableDictionary *query = [self certQueryForKey:key];
    OSStatus status = SecItemDelete((__bridge CFDictionaryRef)query);
    return status == errSecSuccess || status == errSecItemNotFound;
}

@end
