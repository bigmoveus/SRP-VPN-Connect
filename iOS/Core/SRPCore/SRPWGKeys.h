//
//  SRPWGKeys.h
//  SRPCore
//
//  Curve25519 key generation for WireGuard manual profiles (official
//  wireguard-apple WireGuardKitC code: x25519.c / key.c). Kept separate
//  from SRPWireGuardClient so the UI can use it without linking
//  wireguard-go into the app target.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface SRPWGKeys : NSObject

/// Generates a fresh Curve25519 private key (base64, wg-quick form).
+ (NSString *)generatePrivateKeyBase64;
/// Derives the public key (base64) from a base64 private key; nil if invalid.
+ (nullable NSString *)publicKeyBase64ForPrivateKeyBase64:(NSString *)privateKey;

@end

NS_ASSUME_NONNULL_END
