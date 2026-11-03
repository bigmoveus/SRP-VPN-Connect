
#import <UIKit/UIKit.h>

NS_ASSUME_NONNULL_BEGIN

@class NodeModel;

typedef void (^backNodeModal)(NodeModel*modal);

@interface CreateVC : UIViewController

@property (nonatomic,strong) NodeModel * t_modal;
@property (nonatomic,copy) backNodeModal backModal;

-(void)createNodeBackResult:(backNodeModal)modal;

@end

NS_ASSUME_NONNULL_END
