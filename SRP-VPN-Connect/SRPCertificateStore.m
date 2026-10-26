//
//  SRPCertificateStore.m
//  SRP-VPN-Connect
//

#import "SRPCertificateStore.h"
#import "SRPKeychain.h"
#import <SRPCore/SSProtocol.h>

@implementation SRPCertificateInfo
@end

static NSString * const kRegistryKey = @"SRPCertificateList";

@implementation SRPCertificateStore

+ (NSArray<SRPCertificateInfo *> *)certificates {
    NSArray *raw = [[NSUserDefaults standardUserDefaults] arrayForKey:kRegistryKey];
    NSMutableArray<SRPCertificateInfo *> *out = [NSMutableArray new];
    for (NSDictionary *d in raw) {
        SRPCertificateInfo *info = [SRPCertificateInfo new];
        info.ref = [d[@"ref"] isKindOfClass:NSString.class] ? d[@"ref"] : @"";
        info.name = [d[@"name"] isKindOfClass:NSString.class] ? d[@"name"] : @"";
        info.expiry = [d[@"expiry"] isKindOfClass:NSDate.class] ? d[@"expiry"] : [NSDate distantPast];
        if (info.ref.length > 0) {
            [out addObject:info];
        }
    }
    return out;
}

+ (void)saveRegistry:(NSArray<SRPCertificateInfo *> *)list {
    NSMutableArray *raw = [NSMutableArray new];
    for (SRPCertificateInfo *info in list) {
        [raw addObject:@{@"ref": info.ref, @"name": info.name, @"expiry": info.expiry}];
    }
    [[NSUserDefaults standardUserDefaults] setObject:raw forKey:kRegistryKey];
    [[NSUserDefaults standardUserDefaults] synchronize];
}

+ (SRPCertificateInfo *)certificateWithRef:(NSString *)ref {
    for (SRPCertificateInfo *info in [self certificates]) {
        if ([info.ref isEqualToString:ref]) {
            return info;
        }
    }
    return nil;
}

/* Validate the .p12 and pull the subject CN + expiry out of the leaf
 * certificate (via SRPCore's BoringSSL-based parser — the same code path
 * the tunnel extension uses). Returns NO with `error` set when the blob is
 * not a PKCS#12 or the passphrase does not unlock it. */
+ (BOOL)inspectP12:(NSData *)data
        passphrase:(NSString *)passphrase
              name:(NSString **)name
            expiry:(NSDate **)expiry
             error:(NSError **)error {
    NSDictionary *info = [SSSstp eapTlsP12Info:data passphrase:passphrase];
    if (info == nil) {
        if (error) {
            *error = [NSError errorWithDomain:@"SRPCertificateStore" code:-1
                                     userInfo:@{NSLocalizedDescriptionKey:
                @"Could not read the file. Check that it is a valid .p12/.pfx and that the passphrase is correct."}];
        }
        return NO;
    }
    if (name) *name = info[@"name"];
    if (expiry) *expiry = info[@"expiry"];
    return YES;
}

+ (SRPCertificateInfo *)importP12:(NSData *)data
                       passphrase:(NSString *)passphrase
                            error:(NSError **)error {
    NSString *name = nil;
    NSDate *expiry = nil;
    if (![self inspectP12:data passphrase:passphrase name:&name expiry:&expiry error:error]) {
        return nil;
    }
    SRPCertificateInfo *info = [SRPCertificateInfo new];
    info.ref = NSUUID.UUID.UUIDString;
    info.name = name;
    info.expiry = expiry;
    if (![SRPKeychain setCertificate:data passphrase:passphrase forKey:info.ref]) {
        if (error) {
            *error = [NSError errorWithDomain:@"SRPCertificateStore" code:-2
                                     userInfo:@{NSLocalizedDescriptionKey: @"Could not store the certificate in the Keychain."}];
        }
        return nil;
    }
    NSMutableArray *list = [[self certificates] mutableCopy];
    [list addObject:info];
    [self saveRegistry:list];
    return info;
}

+ (void)removeCertificateWithRef:(NSString *)ref {
    [SRPKeychain deleteCertificateForKey:ref];
    NSMutableArray *list = [[self certificates] mutableCopy];
    NSIndexSet *dead = [list indexesOfObjectsPassingTest:^BOOL(SRPCertificateInfo *info, NSUInteger idx, BOOL *stop) {
        return [info.ref isEqualToString:ref];
    }];
    [list removeObjectsAtIndexes:dead];
    [self saveRegistry:list];
}

@end
