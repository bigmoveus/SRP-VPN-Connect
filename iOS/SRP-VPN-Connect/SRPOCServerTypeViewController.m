//
//  SRPOCServerTypeViewController.m
//  SRP-VPN-Connect
//

#import "SRPOCServerTypeViewController.h"
#import "NodeModel.h"

@interface SRPOCServerTypeViewController ()
@property (nonatomic, strong) NodeModel *model;
@end

@implementation SRPOCServerTypeViewController

- (instancetype)initWithNodeModel:(NodeModel *)model {
    self = [super initWithStyle:UITableViewStyleGrouped];
    if (self) {
        _model = model;
    }
    return self;
}

- (void)viewDidLoad {
    [super viewDidLoad];
    self.title = @"Server Type";
}

- (NSArray<NSString *> *)types {
    return @[@"anyconnect", @"f5", @"gp"];
}

+ (NSString *)titleForType:(NSString *)type {
    if ([type isEqualToString:@"f5"]) return @"F5 BIG-IP";
    if ([type isEqualToString:@"gp"]) return @"Palo Alto GP";
    return @"AnyConnect";
}

#pragma mark - Table view

- (NSInteger)numberOfSectionsInTableView:(UITableView *)tableView {
    return 1;
}

- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section {
    return self.types.count;
}

- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath {
    static NSString *cellID = @"ocServerType";
    UITableViewCell *cell = [tableView dequeueReusableCellWithIdentifier:cellID];
    if (!cell) {
        cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleDefault reuseIdentifier:cellID];
    }
    NSString *type = self.types[indexPath.row];
    cell.textLabel.text = [SRPOCServerTypeViewController titleForType:type];
    NSString *current = self.model.ocProtocol.length > 0 ? self.model.ocProtocol : @"anyconnect";
    cell.accessoryType = [current isEqualToString:type] ? UITableViewCellAccessoryCheckmark : UITableViewCellAccessoryNone;
    return cell;
}

- (void)tableView:(UITableView *)tableView didSelectRowAtIndexPath:(NSIndexPath *)indexPath {
    self.model.ocProtocol = self.types[indexPath.row];
    [self.navigationController popViewControllerAnimated:YES];
}

@end
