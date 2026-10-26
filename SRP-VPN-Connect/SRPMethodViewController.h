//
//  SRPMethodViewController.h
//  SRP-VPN-Connect
//

#import <UIKit/UIKit.h>

@class NodeModel;

NS_ASSUME_NONNULL_BEGIN

/// Screen D: authentication method selection (Password / Certificate).
@interface SRPMethodViewController : UITableViewController

- (instancetype)initWithNodeModel:(NodeModel *)model;

@end

NS_ASSUME_NONNULL_END
