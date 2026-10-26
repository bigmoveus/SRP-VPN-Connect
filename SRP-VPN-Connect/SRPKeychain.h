//
//  SRPKeychain.h
//  SRP-VPN-Connect
//
//  Minimal Keychain wrapper for node passwords.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface SRPKeychain : NSObject

+ (BOOL)setPassword:(NSString *)password forKey:(NSString *)key;
+ (nullable NSString *)passwordForKey:(NSString *)key;
+ (BOOL)deletePasswordForKey:(NSString *)key;

/// Client certificates (certificate authentication). The .p12 blob and its
/// passphrase are stored together in the Keychain access group shared with
/// the tunnel extension, so the extension can unwrap the certificate when
/// bringing the tunnel up. Only the `key` reference ever leaves the Keychain.
+ (BOOL)setCertificate:(NSData *)p12 passphrase:(NSString *)passphrase forKey:(NSString *)key;
+ (nullable NSData *)certificateForKey:(NSString *)key passphrase:(NSString * _Nullable * _Nullable)passphrase;
+ (BOOL)deleteCertificateForKey:(NSString *)key;

@end

NS_ASSUME_NONNULL_END
