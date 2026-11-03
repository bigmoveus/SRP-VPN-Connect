
#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@class NodeModel;

@interface CheckConnectData : NSObject

+(NSDictionary*)checkConnectParmer:(NodeModel*)modal;
+(NodeModel*)getModalForDic:(NSDictionary*)selectDic;
/// The profile as saved on disk: passwords and WireGuard keys go to the Keychain and only their references stay.
+(NSDictionary*)storedParametersForProfile:(NodeModel*)modal;
/// Removes the profile's passwords and WireGuard keys from the Keychain, for a deleted profile.
+(void)deleteStoredSecretsOfProfile:(NodeModel*)modal;
/// The other WaterWall profiles of the same server that Auto Switch may use, those with the
/// other carrier (TCP or UDP) first, each as connect parameters. Empty when Auto Switch is off.
+(NSArray<NSDictionary*>*)waterWallFallbacksForProfile:(NodeModel*)profile amongProfiles:(NSArray<NodeModel*>*)profiles;
/// checkConnectParmer: plus the Auto Switch fallbacks of a WaterWall profile.
+(NSDictionary*)connectParametersForProfile:(NodeModel*)profile amongProfiles:(NSArray<NodeModel*>*)profiles;
@end

NS_ASSUME_NONNULL_END
