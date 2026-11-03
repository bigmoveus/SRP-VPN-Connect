//
//  SRPCertificateStore.h
//  SRP-VPN-Connect
//
//  Registry of imported client certificates (certificate authentication).
//  The .p12 blobs live in the Keychain (shared with the tunnel extension);
//  this store only keeps the display metadata (subject CN + expiry) in
//  NSUserDefaults, keyed by the Keychain reference (UUID).
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface SRPCertificateInfo : NSObject
@property (nonatomic, copy) NSString *ref;      // Keychain reference (UUID)
@property (nonatomic, copy) NSString *name;     // subject CN
@property (nonatomic, strong) NSDate *expiry;   // notAfter
@end

@interface SRPCertificateStore : NSObject

/// All imported certificates, oldest import first.
+ (NSArray<SRPCertificateInfo *> *)certificates;

/// Validate and import a .p12/.pfx blob. The passphrase is verified and the
/// blob + passphrase are stored in the Keychain; returns the registry entry.
+ (nullable SRPCertificateInfo *)importP12:(NSData *)data
                                passphrase:(NSString *)passphrase
                                     error:(NSError **)error;

/// Remove the Keychain blob and the registry entry.
+ (void)removeCertificateWithRef:(NSString *)ref;

/// Look up a registry entry.
+ (nullable SRPCertificateInfo *)certificateWithRef:(NSString *)ref;

@end

NS_ASSUME_NONNULL_END
