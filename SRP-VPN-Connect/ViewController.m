#import "ViewController.h"
#import <SRPParser/SRPParser.h>
#import "HomeHeaderView.h"
#import "HomeProtocolView.h"
#import "CreateVC.h"
#import "NodeModel.h"
#import "Toast.h"
#import "CheckConnectData.h"
#import "userNodeData.h"
#import "SRPLogViewController.h"
#import <SRPCore/SRPWaterWallChainConfig.h>
#import "SRPProfileLatencyTester.h"

@interface ViewController ()<UITableViewDelegate,UITableViewDataSource>

@property (nonatomic,strong) SRPProfileLatencyTester *latencyTester;
@property (nonatomic,strong) NSMutableDictionary<NSString *, NSString *> *latencyResults;
@property (nonatomic,strong) UITableView * homeTableview;
@property (nonatomic,strong) NSMutableArray * nodaArray;
@property (nonatomic,strong) HomeHeaderView * header;
@property (nonatomic,strong) NSLayoutConstraint * headerHeightConstraint;
@property (nonatomic,strong) UILabel * versionLabel;
@property (nonatomic,assign) NSInteger selectIndex;
@property (nonatomic,assign) BOOL wasConnecting;
@property (nonatomic,strong) UILabel * emptyLabel;

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];

    [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(vpnConnectionStatusDidChange) name:@"kApplicationVPNStatusDidChangeNotification" object:nil];

    self.view.backgroundColor = UIColor.systemGroupedBackgroundColor;

    self.header = [[HomeHeaderView alloc] initWithStyle:UITableViewCellStyleDefault reuseIdentifier:nil];
    self.header.translatesAutoresizingMaskIntoConstraints = NO;
    [self.view addSubview:self.header];
    self.headerHeightConstraint = [self.header.heightAnchor constraintEqualToConstant:280];
    [NSLayoutConstraint activateConstraints:@[
        [self.header.topAnchor constraintEqualToAnchor:self.view.safeAreaLayoutGuide.topAnchor],
        [self.header.leadingAnchor constraintEqualToAnchor:self.view.leadingAnchor],
        [self.header.trailingAnchor constraintEqualToAnchor:self.view.trailingAnchor],
        self.headerHeightConstraint,
    ]];
    [self.header.addButton addTarget:self action:@selector(showCreateView) forControlEvents:UIControlEventTouchUpInside];
    [self.header.editButton addTarget:self action:@selector(editNode) forControlEvents:UIControlEventTouchUpInside];
    [self.header.helpButton addTarget:self action:@selector(onHelp) forControlEvents:UIControlEventTouchUpInside];
    [self.header.connectButton addTarget:self action:@selector(connectVPN) forControlEvents:UIControlEventTouchUpInside];
    __weak typeof(self) weakSelfHeader = self;
    self.header.onStatusTap = ^{
        SRPLogViewController *log = [SRPLogViewController new];
        UINavigationController *nav = [[UINavigationController alloc] initWithRootViewController:log];
        if (weakSelfHeader.traitCollection.userInterfaceIdiom == UIUserInterfaceIdiomPad) {
            nav.modalPresentationStyle = UIModalPresentationFormSheet;
        }
        [weakSelfHeader presentViewController:nav animated:YES completion:nil];
    };

    NSString *version = [[NSBundle mainBundle] objectForInfoDictionaryKey:@"CFBundleShortVersionString"];
    self.versionLabel = [UILabel new];
    self.versionLabel.text = [NSString stringWithFormat:@"version %@", version];
    self.versionLabel.font = [UIFont preferredFontForTextStyle:UIFontTextStyleCaption1];
    self.versionLabel.textColor = UIColor.tertiaryLabelColor;
    self.versionLabel.translatesAutoresizingMaskIntoConstraints = NO;
    [self.view addSubview:self.versionLabel];
    [NSLayoutConstraint activateConstraints:@[
        [self.versionLabel.centerXAnchor constraintEqualToAnchor:self.view.centerXAnchor],
        [self.versionLabel.bottomAnchor constraintEqualToAnchor:self.view.safeAreaLayoutGuide.bottomAnchor constant:-8],
    ]];

    self.homeTableview = [[UITableView alloc] initWithFrame:CGRectZero style:UITableViewStylePlain];
    self.homeTableview.delegate = self;
    self.homeTableview.dataSource = self;
    self.homeTableview.backgroundColor = UIColor.clearColor;
    self.homeTableview.separatorStyle = UITableViewCellSeparatorStyleNone;
    self.homeTableview.rowHeight = UITableViewAutomaticDimension;
    self.homeTableview.estimatedRowHeight = 80;
    self.homeTableview.translatesAutoresizingMaskIntoConstraints = NO;
    [self.view addSubview:self.homeTableview];
    [NSLayoutConstraint activateConstraints:@[
        [self.homeTableview.topAnchor constraintEqualToAnchor:self.header.bottomAnchor],
        [self.homeTableview.bottomAnchor constraintEqualToAnchor:self.versionLabel.topAnchor constant:-4],
        [self.homeTableview.leadingAnchor constraintEqualToAnchor:self.view.leadingAnchor],
        [self.homeTableview.trailingAnchor constraintEqualToAnchor:self.view.trailingAnchor],
    ]];

    self.emptyLabel = [UILabel new];
    self.emptyLabel.text = @"No profiles yet — tap + to add";
    self.emptyLabel.font = [UIFont preferredFontForTextStyle:UIFontTextStyleCallout];
    self.emptyLabel.textColor = UIColor.secondaryLabelColor;
    self.emptyLabel.textAlignment = NSTextAlignmentCenter;
    self.emptyLabel.numberOfLines = 0;
    self.emptyLabel.hidden = YES;

    self.nodaArray = [userNodeData shareInstance].nodeArray;
    self.latencyTester = [SRPProfileLatencyTester new];
    self.latencyResults = [NSMutableDictionary new];
    self.selectIndex = -1;

    [[PDVPNManager sharedManager] setupVPNManager];
}

- (void)viewDidLayoutSubviews {
    [super viewDidLayoutSubviews];
    CGFloat w = self.view.bounds.size.width;
    if (w > 0) {
        CGSize fit = [self.header systemLayoutSizeFittingSize:UILayoutFittingCompressedSize];
        if (fit.height > 0 && fabs(fit.height - self.headerHeightConstraint.constant) > 0.5) {
            self.headerHeightConstraint.constant = fit.height;
        }
    }
}

-(void)tapClick{
    [[PDVPNManager sharedManager] echo];
}

-(SRPHomeStatus)homeStatusFromVPN:(YDVPNStatus)status {
    switch (status) {
        case YDVPNStatusConnected: return SRPHomeStatusConnected;
        case YDVPNStatusConnecting: return SRPHomeStatusConnecting;
        default: return SRPHomeStatusDisconnected;
    }
}

-(void)vpnConnectionStatusDidChange{
    YDVPNStatus status = PDVPNManager.sharedManager.status;
    if (status != YDVPNStatusConnected) [self.latencyTester cancel];
    if (status == YDVPNStatusConnected) {
        _wasConnecting = NO;
        [self.header showStatus:SRPHomeStatusConnected animated:YES];
        [self measureConnectedProfileLatency];
    } else if (status == YDVPNStatusConnecting) {
        _wasConnecting = YES;
        [self.header showStatus:SRPHomeStatusConnecting animated:YES];
    }
    else if (status == YDVPNStatusDisconnected){
        BOOL wasConnecting = _wasConnecting;
        _wasConnecting = NO;
        [self.header showStatus:SRPHomeStatusDisconnected animated:YES];
        if (wasConnecting) {
            [self showLastTunnelErrorIfRecent];
        }
    }
}

-(void)showLastTunnelErrorIfRecent {
    dispatch_async(dispatch_get_main_queue(), ^{
        NSUserDefaults *shared = [[NSUserDefaults alloc] initWithSuiteName:@"group.tr.com.srp.vpn"];
        NSDictionary *lastError = [shared objectForKey:@"SRPLastError"];
        if (![lastError isKindOfClass:NSDictionary.class]) {
            return;
        }
        NSDate *date = lastError[@"date"];
        NSString *message = lastError[@"message"];
        if (![date isKindOfClass:NSDate.class] || -[date timeIntervalSinceNow] > 30 || message.length == 0) {
            return;
        }
        [shared removeObjectForKey:@"SRPLastError"];
        [shared synchronize];
        UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"Connection Failed"
                                                                       message:message
                                                                preferredStyle:UIAlertControllerStyleAlert];
        [alert addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];
        [self presentViewController:alert animated:YES completion:nil];
    });
}

-(NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section {
    self.emptyLabel.hidden = self.nodaArray.count > 0;
    self.homeTableview.backgroundView = self.nodaArray.count > 0 ? nil : self.emptyLabel;
    return self.nodaArray.count;
}

-(UITableViewCell*)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath {
    static NSString * strID = @"HomeProtocolView";
    HomeProtocolView * node = [tableView dequeueReusableCellWithIdentifier:strID];
    if(!node) {
        node = [[HomeProtocolView alloc] initWithStyle:UITableViewCellStyleDefault reuseIdentifier:strID];
    }
    NodeModel * modal = [self.nodaArray objectAtIndex:indexPath.row];
    NSString *title = modal.desc.length > 0 ? modal.desc
                    : (modal.server.length > 0 ? modal.server : modal.nodeName);
    NSString *subtitle;
    if ([modal.protocolType isEqualToString:@"aether"] && ![modal.aetherMode isEqualToString:@"private"]) {
        subtitle = @"Cloudflare WARP";
    } else if ([modal.protocolType isEqualToString:@"waterwall"]) {
        NSDictionary *configuration = [SRPWaterWallChainConfig configurationWithJSON:modal.waterwallConfigJSON];
        subtitle = [SRPWaterWallChainConfig summaryForConfiguration:configuration ?: [SRPWaterWallChainConfig defaultConfiguration]];
    } else if ([modal.protocolType isEqualToString:@"psiphon"] && modal.server.length == 0) {
        subtitle = @"Psiphon (own server)";
    } else {
        subtitle = [NSString stringWithFormat:@"%@:%@", modal.server, modal.port];
    }
    NodeModel *sel = [NodeModel shareInstance].selectNode;
    BOOL selected = (sel.nodeId.length > 0 && [sel.nodeId isEqualToString:modal.nodeId]);
    [node configureWithTitle:title
                    subtitle:subtitle
                       badge:modal.nodeName
                     latency:self.latencyResults[modal.nodeId]
                    selected:selected];
    return node;
}

- (NodeModel *)connectedProfileForLatency {
    NSString *nodeID = PDVPNManager.sharedManager.connectedNodeID;
    for (NodeModel *profile in self.nodaArray) {
        if ([profile.nodeId isEqualToString:nodeID]) return profile;
    }
    if (nodeID.length > 0) return nil;
    NodeModel *selected = [NodeModel shareInstance].selectNode;
    for (NodeModel *profile in self.nodaArray) {
        if ([profile.nodeId isEqualToString:selected.nodeId]) return profile;
    }
    return nil;
}

- (void)measureConnectedProfileLatency {
    if (PDVPNManager.sharedManager.status != YDVPNStatusConnected) return;
    NodeModel *profile = [self connectedProfileForLatency];
    if (profile == nil) return;
    __weak typeof(self) weakSelf = self;
    [self.latencyTester measureProfile:profile update:^(NSString *nodeID, NSString *text) {
        dispatch_async(dispatch_get_main_queue(), ^{
            weakSelf.latencyResults[nodeID] = text;
            [weakSelf.homeTableview reloadData];
        });
    } finished:^{
        dispatch_async(dispatch_get_main_queue(), ^{
            ViewController *strongSelf = weakSelf;
            if ([strongSelf.latencyResults[profile.nodeId] isEqualToString:@"Testing…"]) {
                [strongSelf.latencyResults removeObjectForKey:profile.nodeId];
            }
            [strongSelf.homeTableview reloadData];
        });
    }];
}

-(void)onHelp {
    [[UIApplication sharedApplication] openURL:[NSURL URLWithString:@"https://srpconnect.app"] options:@{} completionHandler:nil];
}

-(void)editNode {
    if([PDVPNManager sharedManager].status == YDVPNStatusConnected) {
        [self.view makeToast:@"Disconnect the VPN before editing this profile" duration:2 position:CSToastPositionCenter];
        return;
    }
    if(self.selectIndex == -1) {
        [self.view makeToast:@"Select a profile first (or add one with +)" duration:2 position:CSToastPositionCenter];
        return;
    }

    __weak typeof(self)weakSelf = self;
    CreateVC * create = [CreateVC new];
    create.t_modal = [self.nodaArray objectAtIndex:self.selectIndex];
    create.modalPresentationStyle = self.traitCollection.userInterfaceIdiom == UIUserInterfaceIdiomPad
        ? UIModalPresentationFormSheet : UIModalPresentationFullScreen;
    [create createNodeBackResult:^(NodeModel * _Nonnull modal) {
        dispatch_async(dispatch_get_main_queue(), ^{
            [weakSelf.nodaArray replaceObjectAtIndex:self.selectIndex withObject:modal];
            [userNodeData shareInstance].nodeArray = weakSelf.nodaArray;
            [weakSelf.homeTableview reloadData];
        });
    }];
    [self presentViewController:create animated:YES completion:nil];
}

-(void)connectVPN {
    if([PDVPNManager sharedManager].status == YDVPNStatusConnected) {
        [[PDVPNManager sharedManager] disconnect];
        return;
    }else if([PDVPNManager sharedManager].status == YDVPNStatusConnecting) {
        [[PDVPNManager sharedManager] disconnect];
        return;
    }
    NodeModel *selNode = [NodeModel shareInstance].selectNode;
    BOOL needsServerField = ![selNode.protocolType isEqualToString:@"psiphon"] &&
                            !([selNode.protocolType isEqualToString:@"aether"] &&
                              ![selNode.aetherMode isEqualToString:@"private"]) &&
                            !([selNode.protocolType isEqualToString:@"waterwall"] &&
                              [SRPWaterWallChainConfig isDirectConfiguration:[SRPWaterWallChainConfig configurationWithJSON:selNode.waterwallConfigJSON]]);
    if(needsServerField && selNode.server.length==0) {
        [self.view makeToast:@"Add a profile first (tap +)" duration:2 position:CSToastPositionCenter];
        [self.header showStatus:SRPHomeStatusDisconnected animated:NO];
        return;
    }

    __weak typeof(self)weakSelf = self;
    [[PDVPNManager sharedManager] connectUsing:[CheckConnectData checkConnectParmer:[NodeModel shareInstance].selectNode] auth:^(YDUnsafeAuthResponse  _Nonnull response) {
        dispatch_async(dispatch_get_main_queue(), ^{
            NSString *issue = [PDVPNManager sharedManager].lastTLSIssue ?: @"The identity of the server can't be verified.";
            UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"DANGEROUS!"
                                                                           message:issue
                                                                    preferredStyle:UIAlertControllerStyleAlert];
            [alert addAction:[UIAlertAction actionWithTitle:@"Continue"
                                                      style:UIAlertActionStyleDestructive
                                                    handler:^(UIAlertAction * _Nonnull action) {
                response(YES);
            }]];
            [alert addAction:[UIAlertAction actionWithTitle:@"Save and Continue"
                                                      style:UIAlertActionStyleDestructive
                                                    handler:^(UIAlertAction * _Nonnull action) {
                NodeModel *node = [NodeModel shareInstance].selectNode;
                node.TLS = YES;
                [userNodeData shareInstance].nodeArray = weakSelf.nodaArray;
                response(YES);
            }]];
            [alert addAction:[UIAlertAction actionWithTitle:@"Cancel"
                                                      style:UIAlertActionStyleCancel
                                                    handler:^(UIAlertAction * _Nonnull action) {
                response(NO);
                [weakSelf.header showStatus:SRPHomeStatusDisconnected animated:NO];
            }]];
            [weakSelf presentViewController:alert animated:YES completion:nil];
        });
    }];
}

-(void)showCreateView {
    __weak typeof(self)weakSelf = self;
    CreateVC * create = [CreateVC new];
    create.modalPresentationStyle = self.traitCollection.userInterfaceIdiom == UIUserInterfaceIdiomPad
        ? UIModalPresentationFormSheet : UIModalPresentationFullScreen;
    [create createNodeBackResult:^(NodeModel * _Nonnull modal) {
        dispatch_async(dispatch_get_main_queue(), ^{
            [weakSelf.nodaArray addObject:modal];
            [userNodeData shareInstance].nodeArray = weakSelf.nodaArray;
            [weakSelf.homeTableview reloadData];
        });
    }];
    [self presentViewController:create animated:YES completion:nil];
}

-(void)tableView:(UITableView *)tableView didSelectRowAtIndexPath:(NSIndexPath *)indexPath {
    [NodeModel shareInstance].selectNode = self.nodaArray[indexPath.row];
    self.selectIndex = indexPath.row;
    [self.homeTableview reloadData];
}

-(UISwipeActionsConfiguration *)tableView:(UITableView *)tableView trailingSwipeActionsConfigurationForRowAtIndexPath:(NSIndexPath *)indexPath {
    __weak typeof(self)weakSelf = self;
    UIContextualAction *delete = [UIContextualAction contextualActionWithStyle:UIContextualActionStyleDestructive
                                                                         title:@"Delete"
                                                                       handler:^(UIContextualAction *action, UIView *view, void (^completion)(BOOL)) {
        __strong typeof(weakSelf) self2 = weakSelf;
        if ([PDVPNManager sharedManager].status == YDVPNStatusConnected ||
            [PDVPNManager sharedManager].status == YDVPNStatusConnecting) {
            [self2.view makeToast:@"Disconnect the VPN before deleting this profile" duration:2 position:CSToastPositionCenter];
            completion(NO);
            return;
        }
        [self2.nodaArray removeObjectAtIndex:indexPath.row];
        [userNodeData shareInstance].nodeArray = self2.nodaArray;
        if (self2.selectIndex == indexPath.row) {
            self2.selectIndex = -1;
            [NodeModel shareInstance].selectNode = [NodeModel new];
        } else if (self2.selectIndex > indexPath.row) {
            self2.selectIndex--;
        }
        [self2.homeTableview reloadData];
        completion(YES);
    }];
    return [UISwipeActionsConfiguration configurationWithActions:@[delete]];
}

- (IBAction)connect:(id)sender {
    [[PDVPNManager sharedManager] connect:@""];
}

- (IBAction)echo:(id)sender {
    [[PDVPNManager sharedManager] echo];
}

@end
