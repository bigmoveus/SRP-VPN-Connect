//
//  SRPEapConfigViewController.h
//  SRP-VPN-Connect
//

#import <UIKit/UIKit.h>

@class NodeModel;

NS_ASSUME_NONNULL_BEGIN

/// Screen B: EAP configuration for a node profile.
/// The lwIP PPP backend supports NO EAP method — every switch here is
/// capability-gated and disabled in the UI. Values still persist if set
/// programmatically.
@interface SRPEapConfigViewController : UITableViewController

- (instancetype)initWithNodeModel:(NodeModel *)model;

@end

NS_ASSUME_NONNULL_END
