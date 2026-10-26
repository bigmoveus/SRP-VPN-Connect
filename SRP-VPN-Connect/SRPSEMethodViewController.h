//
//  SRPSEMethodViewController.h
//  SRP-VPN-Connect
//
//  SoftEther authentication method picker (native SoftEther auth types).
//

#import <UIKit/UIKit.h>

@class NodeModel;

NS_ASSUME_NONNULL_BEGIN

@interface SRPSEMethodViewController : UITableViewController
- (instancetype)initWithNodeModel:(NodeModel *)model;
/// Display title for a SoftEther auth method id (e.g. "radiusNT").
+ (NSString *)titleForMethod:(NSString *)method;
@end

NS_ASSUME_NONNULL_END
