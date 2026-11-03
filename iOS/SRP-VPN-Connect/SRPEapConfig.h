//
//  SRPEapConfig.h
//  SRP-VPN-Connect
//
//  Typed EAP configuration model for a node profile.
//  NOTE: the lwIP PPP backend does NOT support any EAP method.
//  These flags are modeled for future backends / UI completeness;
//  SSAuthCapabilities reports them all as unsupported.
//  Contains NO secrets — safe to persist in NSUserDefaults.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

typedef NS_ENUM(NSInteger, SRPTtlsInnerMethod) {
    SRPTtlsInnerMethodDisabled = 0,
    SRPTtlsInnerMethodEAP,
    SRPTtlsInnerMethodPAP,
    SRPTtlsInnerMethodCHAP,
    SRPTtlsInnerMethodMSCHAPv2,
};

typedef NS_ENUM(NSInteger, SRPTeapSecondaryMethod) {
    SRPTeapSecondaryMethodNone = 0, // extensible
};

@interface SRPEapConfig : NSObject

@property (nonatomic) BOOL eapMschapv2Enabled;

@property (nonatomic) BOOL peapEnabled;
@property (nonatomic) BOOL peapRequireCryptoBinding;

@property (nonatomic) SRPTtlsInnerMethod ttlsInnerMethod;

@property (nonatomic) BOOL teapEnabled;
@property (nonatomic) SRPTeapSecondaryMethod teapSecondaryMethod;

@property (nonatomic) BOOL identityPrivacyEnabled;
@property (nonatomic, copy) NSString *anonymousIdentity;

@property (nonatomic) BOOL eapTls13Enabled;
@property (nonatomic) BOOL disableLegacyEapTls;

+ (instancetype)initWithDefaults;
- (instancetype)initWithDefaults;

- (NSDictionary *)toDictionary;
+ (instancetype)fromDictionary:(NSDictionary *)dict;

@end

NS_ASSUME_NONNULL_END
