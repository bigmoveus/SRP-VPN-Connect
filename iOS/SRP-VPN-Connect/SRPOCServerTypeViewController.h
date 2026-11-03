//
//  SRPOCServerTypeViewController.h
//  SRP-VPN-Connect
//

#import <UIKit/UIKit.h>

@class NodeModel;

@interface SRPOCServerTypeViewController : UITableViewController
- (instancetype)initWithNodeModel:(NodeModel *)model;
+ (NSString *)titleForType:(NSString *)type;
@end
