#import <UIKit/UIKit.h>

@class NodeModel;

NS_ASSUME_NONNULL_BEGIN

/// The profile's WaterWall screen: the chain of nodes from the input hint along each next, one expandable row per node
/// with Edit node, Insert node after and Delete node, and Import JSON. Changes go to the profile being edited; its Save
/// keeps them.
@interface SRPWaterWallConfigViewController : UITableViewController

- (instancetype)initWithNodeModel:(NodeModel *)model;

@end

/// The app's settings: WaterWall Input, one choice for every WaterWall profile, and the GeoIP database that WaterWall
/// Routers use to route by country.
@interface SRPSettingsViewController : UITableViewController
@end

NS_ASSUME_NONNULL_END
