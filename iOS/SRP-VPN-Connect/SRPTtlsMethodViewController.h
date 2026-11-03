//
//  SRPTtlsMethodViewController.h
//  SRP-VPN-Connect
//

#import <UIKit/UIKit.h>

@class NodeModel;

NS_ASSUME_NONNULL_BEGIN

/// Screen C: EAP-TTLS inner method selection.
@interface SRPTtlsMethodViewController : UITableViewController

- (instancetype)initWithNodeModel:(NodeModel *)model;

@end

NS_ASSUME_NONNULL_END
