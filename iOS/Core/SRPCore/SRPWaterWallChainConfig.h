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
// Reaches the server over UDP (WireGuard, KCP or QUIC datagrams) rather than over TCP.
+ (BOOL)configurationUsesUDPCarrier:(NSDictionary *)configuration;
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

/// The input a WaterWall profile's leading hint asks for, as Settings → WaterWall Input supplies it to every profile
FOUNDATION_EXPORT NSString *const SRPWaterWallInputTUN;      // System VPN (TUN)
FOUNDATION_EXPORT NSString *const SRPWaterWallInputSOCKS5;   // Local SOCKS5 proxy
FOUNDATION_EXPORT NSString *const SRPWaterWallInputHTTP;     // Local HTTP proxy
FOUNDATION_EXPORT NSString *const SRPWaterWallHintConnection;
FOUNDATION_EXPORT NSString *const SRPWaterWallHintPacket;

/// A WaterWall profile as the node editor keeps it: a WaterWall JSON document ({"name", "nodes"}) whose chain starts
/// with an input hint, HintConnectionIN or HintPacketIN, in place of the input SRP supplies when it connects.
@interface SRPWaterWallNodeChain : NSObject

/// Settings → WaterWall Input, one choice for every profile (System VPN unless chosen otherwise), shared with the tunnel
@property (class, nonatomic, copy) NSString *currentInput;
/// The 127.0.0.1 port of a local proxy input, 0 for System VPN
+ (NSInteger)portForInput:(NSString *)input;

/// A file or saved profile, checked as an import is: nil with *error naming the node or reference at fault
+ (nullable NSDictionary *)documentWithJSON:(nullable NSString *)json error:(NSString * _Nullable * _Nullable)error;
/// The checks of an import, on a document an edit made; nil when it may be kept
+ (nullable NSString *)validationErrorForDocument:(NSDictionary *)document;
+ (NSString *)JSONWithDocument:(NSDictionary *)document;
/// A new profile's document: the connection hint alone, until a file is imported or nodes are inserted
+ (NSDictionary *)emptyDocument;

/// The nodes from the hint along each next, in the order the chain runs (a missing node or a cycle ends the list)
+ (NSArray<NSDictionary *> *)chainOfDocument:(NSDictionary *)document;
+ (nullable NSDictionary *)hintOfDocument:(NSDictionary *)document;
/// The document's name, or the node types along the chain
+ (NSString *)summaryOfDocument:(NSDictionary *)document;

/// The editor's changes; each returns the new document, which the caller checks before keeping it
+ (NSDictionary *)document:(NSDictionary *)document replacingNodeNamed:(NSString *)name withNode:(NSDictionary *)node;
+ (NSDictionary *)document:(NSDictionary *)document insertingNode:(NSDictionary *)node afterNodeNamed:(NSString *)name;
+ (NSDictionary *)document:(NSDictionary *)document deletingNodeNamed:(NSString *)name;

/// The fixed server endpoints of the profile's connectors ({"host", "port"}), the chain's last node first
+ (NSArray<NSDictionary *> *)endpointsOfDocument:(NSDictionary *)document;
+ (BOOL)documentUsesGeoIP:(NSDictionary *)document;
/// The chain reaches its server over UDP (it ends in a UDP connector)
+ (BOOL)documentUsesUDPCarrier:(NSDictionary *)document;

/// What WaterWall runs: the hint replaced by the input SRP supplies, linked to the hint's successor; the GeoIP database
/// set on the Routers that need it; each fixed server name of a connector replaced by its address from addresses
+ (nullable NSDictionary *)runtimeDocumentForDocument:(NSDictionary *)document
                                                input:(NSString *)input
                                              fakeDNS:(BOOL)fakeDNS
                                    geoIPDatabasePath:(nullable NSString *)geoIPDatabasePath
                                            addresses:(nullable NSDictionary<NSString *, NSString *> *)addresses
                                                error:(NSString * _Nullable * _Nullable)error;

/// The document of a profile made with the former WaterWall form: the nodes the app built for it when it connected,
/// with the input hint in place of NEPacketDevice and PacketsToConnection. nil for WireGuard mode and incomplete profiles.
+ (nullable NSDictionary *)documentForConfiguration:(NSDictionary *)configuration
                                             server:(NSString *)server
                                               port:(NSInteger)port
                                                sni:(nullable NSString *)sni
                                          verifyTLS:(BOOL)verifyTLS
                                             secret:(nullable NSString *)secret
                                        outerSecret:(nullable NSString *)outerSecret
                                            options:(nullable NSDictionary *)options;

@end

NS_ASSUME_NONNULL_END
