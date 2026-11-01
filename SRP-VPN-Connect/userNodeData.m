
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
        [t addObject:[CheckConnectData storedParametersForProfile:modal]];
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
            // Re-save profiles that still contain a plaintext credential or WireGuard key.
            if (dic[@"password"] != nil || dic[@"ww_outer_secret"] != nil || dic[@"wg_conf"] != nil ||
                dic[@"wg_private_key"] != nil || dic[@"wg_preshared_key"] != nil) {
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
