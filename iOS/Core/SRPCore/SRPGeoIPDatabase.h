#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

FOUNDATION_EXPORT NSString *const SRPGeoIPDatabaseErrorDomain;

typedef NS_ERROR_ENUM(SRPGeoIPDatabaseErrorDomain, SRPGeoIPDatabaseError) {
    SRPGeoIPDatabaseErrorUnavailable = 1,
    SRPGeoIPDatabaseErrorInvalidFile,
    SRPGeoIPDatabaseErrorInvalidURL,
    SRPGeoIPDatabaseErrorTooLarge,
    SRPGeoIPDatabaseErrorDownload,
};

@interface SRPGeoIPDatabase : NSObject

@property (nonatomic, strong, readonly) NSURL *databaseURL;
@property (nonatomic, strong, readonly, nullable) NSURL *bundledDatabaseURL;
@property (nonatomic, strong, readonly, nullable) NSURL *currentDatabaseURL;

+ (instancetype)sharedDatabase;
- (instancetype)initWithDirectory:(NSURL *)directory NS_DESIGNATED_INITIALIZER;
- (instancetype)init NS_UNAVAILABLE;

- (nullable NSDictionary *)databaseInfo;
- (BOOL)installBundledDatabaseIfNeeded:(NSError **)error;
- (BOOL)validateDatabaseAtURL:(NSURL *)url error:(NSError **)error;
- (BOOL)installDatabaseAtURL:(NSURL *)url error:(NSError **)error;
- (void)downloadDatabaseFromURLString:(NSString *)urlString
                           completion:(void (^)(NSError *_Nullable error))completion;
- (void)cancelDownload;

@end

NS_ASSUME_NONNULL_END
