
#import "userNodeData.h"
#import "NodeModel.h"
#import "CheckConnectData.h"

@implementation userNodeData
static userNodeData * user = nil;
+(instancetype)shareInstance{
    @synchronized (self) {
        if(!user) {
            user = [[self alloc] init];
        }
        return user;
    }
}

-(void)setNodeArray:(NSMutableArray *)nodeArray{
    NSMutableArray *t = [NSMutableArray new];
    for(NodeModel * modal in nodeArray) {
        NSMutableDictionary *d = [[CheckConnectData checkConnectParmer:modal] mutableCopy];
        // Never persist plaintext credentials — they live in the Keychain.
        [d removeObjectForKey:@"password"];
        [d removeObjectForKey:@"ww_outer_secret"];
        [t addObject:d];
    }
    [[NSUserDefaults standardUserDefaults] setObject:t forKey:@"nodeArray"];
    [[NSUserDefaults standardUserDefaults] synchronize];
}

-(NSMutableArray*)nodeArray {
    NSMutableArray *t = [NSMutableArray new];
    BOOL migrated = NO;

    if([[NSUserDefaults standardUserDefaults] objectForKey:@"nodeArray"]) {
        for(NSDictionary *dic in [[NSUserDefaults standardUserDefaults] objectForKey:@"nodeArray"]) {
            NodeModel *modal = [CheckConnectData getModalForDic:dic];
            if (modal) {
                [t addObject:modal];
            }
            // Re-save profiles that still contain either plaintext credential.
            if (dic[@"password"] != nil || dic[@"ww_outer_secret"] != nil) {
                migrated = YES;
            }
        }
        if (migrated) {
            self.nodeArray = t;
        }
        return t;
    }
    return t;
}

@end
