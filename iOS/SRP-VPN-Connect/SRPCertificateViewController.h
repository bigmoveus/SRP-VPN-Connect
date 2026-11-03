//
//  SRPCertificateViewController.h
//  SRP-VPN-Connect
//

#import <UIKit/UIKit.h>

@class NodeModel;

NS_ASSUME_NONNULL_BEGIN

@interface SRPCertificateViewController : UITableViewController
- (instancetype)initWithNodeModel:(NodeModel *)model;
@end

NS_ASSUME_NONNULL_END
