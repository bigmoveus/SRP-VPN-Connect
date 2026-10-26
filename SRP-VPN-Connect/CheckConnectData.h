
#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@class NodeModel;

@interface CheckConnectData : NSObject

+(NSDictionary*)checkConnectParmer:(NodeModel*)modal;
+(NodeModel*)getModalForDic:(NSDictionary*)selectDic;
@end

NS_ASSUME_NONNULL_END
