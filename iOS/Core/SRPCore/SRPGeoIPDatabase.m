#import "SRPGeoIPDatabase.h"

#import <maxminddb.h>
#import <sys/stat.h>

NSString *const SRPGeoIPDatabaseErrorDomain = @"SRPGeoIPDatabaseErrorDomain";
static const unsigned long long SRPGeoIPMaximumBytes = 128ULL * 1024ULL * 1024ULL;

static NSError *SRPGeoIPError(SRPGeoIPDatabaseError code, NSString *message) {
    return [NSError errorWithDomain:SRPGeoIPDatabaseErrorDomain code:code
                            userInfo:@{NSLocalizedDescriptionKey: message}];
}

static BOOL SRPGeoIPHTTPSURL(NSString *value, NSURL **result) {
    if (![value isKindOfClass:NSString.class] || value.length == 0 || value.length > 2048) return NO;
    NSString *trimmed = [value stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
    if (![trimmed isEqualToString:value]) return NO;
    NSURLComponents *components = [NSURLComponents componentsWithString:value];
    if (![components.scheme.lowercaseString isEqualToString:@"https"] || components.host.length == 0 ||
        components.user != nil || components.password != nil || components.fragment != nil) return NO;
    if (result != NULL) *result = components.URL;
    return YES;
}

static BOOL SRPGeoIPCountryEntryIsValid(MMDB_entry_s *entry) {
    for (NSString *name in @[@"country", @"registered_country"]) {
        MMDB_entry_data_s data = {0};
        int status = MMDB_get_value(entry, &data, name.UTF8String, "iso_code", NULL);
        if (status == MMDB_LOOKUP_PATH_DOES_NOT_MATCH_DATA_ERROR) continue;
        if (status != MMDB_SUCCESS || !data.has_data || data.type != MMDB_DATA_TYPE_UTF8_STRING || data.data_size != 2) return NO;
        return YES;
    }
    return NO;
}

@interface SRPGeoIPDatabase () <NSURLSessionDataDelegate, NSURLSessionDownloadDelegate>
@property (nonatomic, strong) NSURLSession *downloadSession;
@property (nonatomic, strong) NSURLSessionDownloadTask *downloadTask;
@property (nonatomic, copy) void (^downloadCompletion)(NSError *error);
@property (nonatomic, strong) NSError *downloadError;
@end

@implementation SRPGeoIPDatabase

+ (instancetype)sharedDatabase {
    static SRPGeoIPDatabase *database;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        NSURL *container = [NSFileManager.defaultManager
            containerURLForSecurityApplicationGroupIdentifier:@"group.tr.com.srp.vpn"];
        NSURL *directory = [container URLByAppendingPathComponent:@"Library/GeoIP" isDirectory:YES];
        database = [[self alloc] initWithDirectory:directory];
    });
    return database;
}

- (instancetype)initWithDirectory:(NSURL *)directory {
    NSParameterAssert(directory != nil);
    self = [super init];
    if (self) {
        _databaseURL = [directory URLByAppendingPathComponent:@"GeoLite2-Country.mmdb"];
        _bundledDatabaseURL = [NSBundle.mainBundle URLForResource:@"GeoLite2-Country"
                                                   withExtension:@"mmdb"
                                                    subdirectory:@"GeoIP"];
    }
    return self;
}

- (NSURL *)currentDatabaseURL {
    return [NSFileManager.defaultManager fileExistsAtPath:self.databaseURL.path] ? self.databaseURL : self.bundledDatabaseURL;
}

- (BOOL)validateDatabaseAtURL:(NSURL *)url error:(NSError **)error {
    if (!url.isFileURL) {
        if (error) *error = SRPGeoIPError(SRPGeoIPDatabaseErrorUnavailable, @"The GeoIP database is not a local file.");
        return NO;
    }
    struct stat info;
    if (lstat(url.fileSystemRepresentation, &info) != 0 || !S_ISREG(info.st_mode) || S_ISLNK(info.st_mode) ||
        info.st_size <= 0 || (unsigned long long)info.st_size > SRPGeoIPMaximumBytes) {
        if (error) *error = SRPGeoIPError(SRPGeoIPDatabaseErrorInvalidFile,
                                         @"Choose a nonempty MaxMind Country MMDB file no larger than 128 MB.");
        return NO;
    }
    MMDB_s database;
    int status = MMDB_open(url.fileSystemRepresentation, MMDB_MODE_MMAP, &database);
    if (status != MMDB_SUCCESS) {
        if (error) *error = SRPGeoIPError(SRPGeoIPDatabaseErrorInvalidFile,
                                         [NSString stringWithFormat:@"The file is not a valid MaxMind database: %s", MMDB_strerror(status)]);
        return NO;
    }
    NSString *failure = nil;
    const char *type = database.metadata.database_type;
    BOOL supportedType = type != NULL && strcasestr(type, "Country") != NULL;
    if (!supportedType || (database.metadata.ip_version != 4 && database.metadata.ip_version != 6)) {
        NSString *detectedType = type != NULL ? [NSString stringWithUTF8String:type] : nil;
        failure = [NSString stringWithFormat:@"The database type '%@' is unsupported. Use a GeoIP2 or GeoLite2 Country MMDB.",
                   detectedType ?: @"unknown"];
    } else {
        int addressError = 0;
        int lookupError = MMDB_SUCCESS;
        MMDB_lookup_result_s result = MMDB_lookup_string(&database, "1.1.1.1", &addressError, &lookupError);
        if (addressError != 0 || lookupError != MMDB_SUCCESS) {
            failure = @"The database lookup tree could not be read.";
        } else if (result.found_entry && !SRPGeoIPCountryEntryIsValid(&result.entry)) {
            failure = @"The database does not contain valid two-letter country entries.";
        }
    }
    MMDB_close(&database);
    if (failure != nil) {
        if (error) *error = SRPGeoIPError(SRPGeoIPDatabaseErrorInvalidFile, failure);
        return NO;
    }
    return YES;
}

- (BOOL)installBundledDatabaseIfNeeded:(NSError **)error {
    @synchronized (self) {
        if ([NSFileManager.defaultManager fileExistsAtPath:self.databaseURL.path]) {
            return [self validateDatabaseAtURL:self.databaseURL error:error];
        }
        if (self.bundledDatabaseURL == nil) {
            if (error) *error = SRPGeoIPError(SRPGeoIPDatabaseErrorUnavailable, @"The bundled GeoIP country database is unavailable. Upload or download a Country MMDB.");
            return NO;
        }
        return [self installDatabaseAtURL:self.bundledDatabaseURL error:error];
    }
}

- (BOOL)installDatabaseAtURL:(NSURL *)url error:(NSError **)error {
    @synchronized (self) {
        if (![self validateDatabaseAtURL:url error:error]) return NO;
        NSFileManager *files = NSFileManager.defaultManager;
        NSURL *directory = [self.databaseURL URLByDeletingLastPathComponent];
        NSError *fileError = nil;
        if (![files createDirectoryAtURL:directory withIntermediateDirectories:YES attributes:nil error:&fileError]) {
            if (error) *error = fileError;
            return NO;
        }
        NSURL *temporary = [directory URLByAppendingPathComponent:[NSString stringWithFormat:@".%@.tmp", NSUUID.UUID.UUIDString]];
        if (![files copyItemAtURL:url toURL:temporary error:&fileError] ||
            ![self validateDatabaseAtURL:temporary error:error] ||
            ![files setAttributes:@{NSFileProtectionKey: NSFileProtectionNone} ofItemAtPath:temporary.path error:&fileError]) {
            [files removeItemAtURL:temporary error:nil];
            if (error && *error == nil) *error = fileError;
            return NO;
        }
        if (rename(temporary.fileSystemRepresentation, self.databaseURL.fileSystemRepresentation) != 0) {
            [files removeItemAtURL:temporary error:nil];
            if (error) *error = SRPGeoIPError(SRPGeoIPDatabaseErrorUnavailable, @"The validated GeoIP database could not be installed. The previous file was kept.");
            return NO;
        }
        return YES;
    }
}

- (NSDictionary *)databaseInfo {
    NSURL *url = self.currentDatabaseURL;
    if (url == nil || ![self validateDatabaseAtURL:url error:nil]) return nil;
    MMDB_s database;
    if (MMDB_open(url.fileSystemRepresentation, MMDB_MODE_MMAP, &database) != MMDB_SUCCESS) return nil;
    NSDictionary *info = @{
        @"bytes": @((unsigned long long)database.file_size),
        @"buildDate": [NSDate dateWithTimeIntervalSince1970:(NSTimeInterval)database.metadata.build_epoch],
        @"type": [NSString stringWithUTF8String:database.metadata.database_type] ?: @"MaxMind Country",
        @"source": [url isEqual:self.bundledDatabaseURL] ? @"Bundled" : @"Updated",
    };
    MMDB_close(&database);
    return info;
}

- (void)downloadDatabaseFromURLString:(NSString *)urlString completion:(void (^)(NSError *))completion {
    NSParameterAssert(completion != nil);
    NSURL *url = nil;
    if (!SRPGeoIPHTTPSURL(urlString, &url)) {
        NSError *error = SRPGeoIPError(SRPGeoIPDatabaseErrorInvalidURL,
                                      @"Enter a valid HTTPS link without embedded credentials. The file must be a MaxMind Country MMDB.");
        dispatch_async(dispatch_get_main_queue(), ^{ completion(error); });
        return;
    }
    [self cancelDownload];
    @synchronized (self) {
        NSURLSessionConfiguration *configuration = NSURLSessionConfiguration.ephemeralSessionConfiguration;
        configuration.timeoutIntervalForRequest = 30;
        configuration.timeoutIntervalForResource = 120;
        NSOperationQueue *queue = [NSOperationQueue new];
        queue.maxConcurrentOperationCount = 1;
        self.downloadSession = [NSURLSession sessionWithConfiguration:configuration delegate:self delegateQueue:queue];
        self.downloadCompletion = completion;
        self.downloadError = nil;
        NSURLSession *session = self.downloadSession;
        __weak SRPGeoIPDatabase *weakSelf = self;
        self.downloadTask = [session downloadTaskWithURL:url
                                       completionHandler:^(NSURL *location, NSURLResponse *response, NSError *error) {
            SRPGeoIPDatabase *strongSelf = weakSelf;
            if (strongSelf == nil || session != strongSelf.downloadSession) return;
            [strongSelf handleDownloadLocation:location response:response error:error];
        }];
        [self.downloadTask resume];
    }
}

- (void)cancelDownload {
    void (^completion)(NSError *) = nil;
    NSURLSession *session = nil;
    @synchronized (self) {
        if (self.downloadCompletion == nil) return;
        completion = self.downloadCompletion;
        self.downloadCompletion = nil;
        session = self.downloadSession;
        self.downloadSession = nil;
        self.downloadTask = nil;
    }
    [session invalidateAndCancel];
    if (completion != nil) {
        NSError *error = SRPGeoIPError(SRPGeoIPDatabaseErrorDownload, @"The GeoIP update was cancelled.");
        dispatch_async(dispatch_get_main_queue(), ^{ completion(error); });
    }
}

- (void)finishDownload:(NSError *)error {
    void (^completion)(NSError *) = nil;
    NSURLSession *session = nil;
    @synchronized (self) {
        if (self.downloadCompletion == nil) return;
        completion = self.downloadCompletion;
        self.downloadCompletion = nil;
        session = self.downloadSession;
        self.downloadSession = nil;
        self.downloadTask = nil;
    }
    [session finishTasksAndInvalidate];
    dispatch_async(dispatch_get_main_queue(), ^{ completion(error); });
}

- (void)handleDownloadLocation:(NSURL *)location response:(NSURLResponse *)response error:(NSError *)error {
    if (error != nil) {
        [self finishDownload:self.downloadError ?: SRPGeoIPError(SRPGeoIPDatabaseErrorDownload,
            @"The GeoIP download failed. Check the HTTPS link and network connection.")];
        return;
    }
    if (![response isKindOfClass:NSHTTPURLResponse.class] ||
        ((NSHTTPURLResponse *)response).statusCode < 200 || ((NSHTTPURLResponse *)response).statusCode >= 300) {
        [self finishDownload:SRPGeoIPError(SRPGeoIPDatabaseErrorDownload,
                                           @"The GeoIP download link did not return a successful HTTPS response.")];
        return;
    }
    NSError *installError = nil;
    BOOL installed = [self installDatabaseAtURL:location error:&installError];
    [self finishDownload:installed ? nil : installError];
}

- (void)URLSession:(NSURLSession *)session task:(NSURLSessionTask *)task
    willPerformHTTPRedirection:(NSHTTPURLResponse *)response
                    newRequest:(NSURLRequest *)request
             completionHandler:(void (^)(NSURLRequest *))completionHandler {
    if (session != self.downloadSession) return;
    if (!SRPGeoIPHTTPSURL(request.URL.absoluteString, NULL)) {
        self.downloadError = SRPGeoIPError(SRPGeoIPDatabaseErrorInvalidURL, @"GeoIP redirects must remain on HTTPS without embedded credentials.");
        completionHandler(nil);
        [self finishDownload:self.downloadError];
        return;
    }
    completionHandler(request);
}

- (void)URLSession:(NSURLSession *)session dataTask:(NSURLSessionDataTask *)dataTask
    didReceiveResponse:(NSURLResponse *)response
     completionHandler:(void (^)(NSURLSessionResponseDisposition))completionHandler {
    if (session != self.downloadSession) return;
    if (![response isKindOfClass:NSHTTPURLResponse.class] ||
        ((NSHTTPURLResponse *)response).statusCode < 200 || ((NSHTTPURLResponse *)response).statusCode >= 300) {
        self.downloadError = SRPGeoIPError(SRPGeoIPDatabaseErrorDownload, @"The GeoIP download link did not return a successful HTTPS response.");
    } else if (response.expectedContentLength != NSURLSessionTransferSizeUnknown &&
               (unsigned long long)response.expectedContentLength > SRPGeoIPMaximumBytes) {
        self.downloadError = SRPGeoIPError(SRPGeoIPDatabaseErrorTooLarge, @"The GeoIP database exceeds the 128 MB limit.");
    }
    if (self.downloadError != nil) {
        completionHandler(NSURLSessionResponseCancel);
        [self finishDownload:self.downloadError];
    } else {
        completionHandler(NSURLSessionResponseAllow);
    }
}

- (void)URLSession:(NSURLSession *)session downloadTask:(NSURLSessionDownloadTask *)downloadTask
    didWriteData:(int64_t)bytesWritten
    totalBytesWritten:(int64_t)totalBytesWritten
    totalBytesExpectedToWrite:(int64_t)totalBytesExpectedToWrite {
    if (session != self.downloadSession) return;
    if ((unsigned long long)totalBytesWritten > SRPGeoIPMaximumBytes) {
        self.downloadError = SRPGeoIPError(SRPGeoIPDatabaseErrorTooLarge, @"The GeoIP database exceeds the 128 MB limit.");
        [downloadTask cancel];
        [self finishDownload:self.downloadError];
    }
}

- (void)URLSession:(NSURLSession *)session downloadTask:(NSURLSessionDownloadTask *)downloadTask
    didFinishDownloadingToURL:(NSURL *)location {
    if (session != self.downloadSession) return;
    [self handleDownloadLocation:location response:downloadTask.response error:nil];
}

- (void)URLSession:(NSURLSession *)session task:(NSURLSessionTask *)task
    didCompleteWithError:(NSError *)error {
    if (session != self.downloadSession) return;
    if (error != nil) {
        [self finishDownload:self.downloadError ?: SRPGeoIPError(SRPGeoIPDatabaseErrorDownload,
            @"The GeoIP download failed. Check the HTTPS link and network connection.")];
    }
}

- (void)dealloc {
    [_downloadSession invalidateAndCancel];
}

@end
