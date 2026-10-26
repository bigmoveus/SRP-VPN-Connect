#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface SRPWaterWallChainConfig : NSObject

+ (NSDictionary *)defaultConfiguration;
+ (nullable NSDictionary *)configurationWithJSON:(nullable NSString *)json;
+ (nullable NSString *)JSONWithConfiguration:(NSDictionary *)configuration;
+ (nullable NSDictionary *)configurationFromLegacyPreset:(NSString *)preset;
+ (NSString *)summaryForConfiguration:(NSDictionary *)configuration;
+ (nullable NSString *)validationErrorForConfiguration:(NSDictionary *)configuration;
+ (nullable NSString *)validationErrorForApplicationSecret:(nullable NSString *)secret
                                           forConfiguration:(NSDictionary *)configuration;
+ (nullable NSString *)validationErrorForApplicationUsername:(nullable NSString *)username
                                                      secret:(nullable NSString *)secret
                                             forConfiguration:(NSDictionary *)configuration;
+ (nullable NSString *)validationErrorForOuterSecret:(nullable NSString *)secret
                                    forConfiguration:(NSDictionary *)configuration;
+ (BOOL)isWireGuardConfiguration:(NSDictionary *)configuration;
+ (BOOL)isDirectConfiguration:(NSDictionary *)configuration;
+ (BOOL)configurationNeedsApplicationSecret:(NSDictionary *)configuration;
+ (BOOL)configurationNeedsOuterSecret:(NSDictionary *)configuration;
+ (BOOL)configurationUsesTLS:(NSDictionary *)configuration;
+ (BOOL)configurationAllowsFragmentation:(NSDictionary *)configuration;
+ (BOOL)configurationAllowsRouting:(NSDictionary *)configuration;
+ (NSString *)coreJSON;
+ (NSString *)coreJSONWithLogLevel:(NSInteger)level;
+ (nullable NSString *)nodesJSONForConfiguration:(NSDictionary *)configuration
                                          server:(NSString *)server
                                            port:(NSInteger)port
                                             sni:(nullable NSString *)sni
                                       verifyTLS:(BOOL)verifyTLS
                                          secret:(nullable NSString *)secret
                                     outerSecret:(nullable NSString *)outerSecret
                                         options:(nullable NSDictionary *)options;
+ (nullable NSDictionary *)wireGuardConfigurationWithPrivateKey:(NSString *)privateKey
                                                  serverPublicKey:(NSString *)serverPublicKey
                                                           server:(NSString *)server
                                                             port:(NSInteger)port
                                                     clientAddress:(NSString *)clientAddress
                                                         keepalive:(NSInteger)keepalive;
+ (nullable NSDictionary *)wireGuardConfigurationWithConfig:(NSString *)config;

@end

NS_ASSUME_NONNULL_END
