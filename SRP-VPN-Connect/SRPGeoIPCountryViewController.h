#import <UIKit/UIKit.h>

NS_ASSUME_NONNULL_BEGIN

@interface SRPGeoIPCountryViewController : UITableViewController

- (instancetype)initWithSelectedCodes:(NSSet<NSString *> *)selectedCodes
                           completion:(void (^)(NSSet<NSString *> *selectedCodes))completion;

@end

NS_ASSUME_NONNULL_END
