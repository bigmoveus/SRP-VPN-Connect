//
//  SRPSEMethodViewController.m
//  SRP-VPN-Connect
//

#import "SRPSEMethodViewController.h"
#import "NodeModel.h"

@interface SRPSEMethodViewController ()
@property (nonatomic, strong) NodeModel *model;
@end

@implementation SRPSEMethodViewController

- (instancetype)initWithNodeModel:(NodeModel *)model {
    self = [super initWithStyle:UITableViewStyleGrouped];
    if (self) {
        _model = model;
    }
    return self;
}

- (void)viewDidLoad {
    [super viewDidLoad];
    self.title = @"Authentication";
}

- (NSArray<NSString *> *)methods {
    return @[@"standardPassword", @"radiusNT", @"certificate", @"anonymous"];
}

+ (NSString *)titleForMethod:(NSString *)method {
    if ([method isEqualToString:@"radiusNT"])    return @"RADIUS / NT Domain";
    if ([method isEqualToString:@"certificate"]) return @"Certificate";
    if ([method isEqualToString:@"anonymous"])   return @"Anonymous";
    return @"Standard Password";
}

#pragma mark - Table view

- (NSInteger)numberOfSectionsInTableView:(UITableView *)tableView {
    return 1;
}

- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section {
    return self.methods.count;
}

- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath {
    static NSString *cellID = @"seAuthMethod";
    UITableViewCell *cell = [tableView dequeueReusableCellWithIdentifier:cellID];
    if (!cell) {
        cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleDefault reuseIdentifier:cellID];
    }
    NSString *method = self.methods[indexPath.row];
    cell.textLabel.text = [SRPSEMethodViewController titleForMethod:method];
    cell.accessoryType = [self.model.seAuthMethod isEqualToString:method] ? UITableViewCellAccessoryCheckmark : UITableViewCellAccessoryNone;
    return cell;
}

- (void)tableView:(UITableView *)tableView didSelectRowAtIndexPath:(NSIndexPath *)indexPath {
    self.model.seAuthMethod = self.methods[indexPath.row];
    [self.navigationController popViewControllerAnimated:YES];
}

@end
