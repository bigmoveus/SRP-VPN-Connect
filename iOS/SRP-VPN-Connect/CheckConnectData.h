
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
/// A WaterWall profile made with the former form becomes the chain the app built for it when it connected (WireGuard
/// mode becomes a WireGuard profile). YES when it changed and must be saved; NO for a profile with a chain already, or
/// one that could not be converted, which keeps its former settings until a chain is saved for it.
+(BOOL)convertLegacyWaterWallProfile:(NodeModel*)modal;
/// The former form's settings and the secrets it kept apart, which the chain now holds
+(void)clearLegacyWaterWallSettingsOfProfile:(NodeModel*)modal;
/// The other WaterWall profiles of the same server that Auto Switch may use, those with the
/// other carrier (TCP or UDP) first, each as connect parameters. Empty when Auto Switch is off.
+(NSArray<NSDictionary*>*)waterWallFallbacksForProfile:(NodeModel*)profile amongProfiles:(NSArray<NodeModel*>*)profiles;
/// checkConnectParmer: plus the Auto Switch fallbacks of a WaterWall profile.
+(NSDictionary*)connectParametersForProfile:(NodeModel*)profile amongProfiles:(NSArray<NodeModel*>*)profiles;
/// An SSL VPN address pasted whole into Server, such as https://vpn.example.com:8443/?secret, as "server" plus "port"
/// and "path" when the text has them. Mirrors splitSslVpnAddress of the Android app.
+(NSDictionary<NSString*, NSString*>*)splitSslVpnAddress:(NSString*)text;
@end

NS_ASSUME_NONNULL_END
