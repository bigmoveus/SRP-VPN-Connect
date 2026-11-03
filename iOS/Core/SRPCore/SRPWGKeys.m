//
//  SRPWGKeys.m
//  SRPCore
//

#import "SRPWGKeys.h"
#import "x25519.h"
#import "key.h"
#import <string.h>

@implementation SRPWGKeys

+ (NSString *)generatePrivateKeyBase64 {
    uint8_t priv[WG_KEY_LEN];
    curve25519_generate_private_key(priv);
    char b64[WG_KEY_LEN_BASE64];
    key_to_base64(b64, priv);
    memset(priv, 0, sizeof(priv));
    return @(b64);
}

+ (NSString *)publicKeyBase64ForPrivateKeyBase64:(NSString *)privateKey {
    uint8_t priv[WG_KEY_LEN];
    if (!key_from_base64(priv, privateKey.UTF8String)) {
        return nil;
    }
    uint8_t pub[WG_KEY_LEN];
    curve25519_derive_public_key(pub, priv);
    char b64[WG_KEY_LEN_BASE64];
    key_to_base64(b64, pub);
    memset(priv, 0, sizeof(priv));
    memset(pub, 0, sizeof(pub));
    return @(b64);
}

@end
