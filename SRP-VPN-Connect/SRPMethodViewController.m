//
//  SRPMethodViewController.m
//  SRP-VPN-Connect
//

#import "SRPMethodViewController.h"
#import "NodeModel.h"

@interface SRPMethodViewController ()
@property (nonatomic, strong) NodeModel *model;
@end

@implementation SRPMethodViewController

- (instancetype)initWithNodeModel:(NodeModel *)model {
    self = [super initWithStyle:UITableViewStyleGrouped];
    if (self) {
        _model = model;
    }
    return self;
}

- (void)viewDidLoad {
    [super viewDidLoad];
    self.title = @"Method";
}

- (NSArray<NSString *> *)methods {
    return @[@"password", @"certificate"];
}

- (NSString *)titleForMethod:(NSString *)method {
    return [method isEqualToString:@"certificate"] ? @"Certificate" : @"Password";
}

#pragma mark - Table view

- (NSInteger)numberOfSectionsInTableView:(UITableView *)tableView {
    return 1;
}

- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section {
    return self.methods.count;
}

- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath {
    static NSString *cellID = @"authMethod";
    UITableViewCell *cell = [tableView dequeueReusableCellWithIdentifier:cellID];
    if (!cell) {
        cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleDefault reuseIdentifier:cellID];
    }
    NSString *method = self.methods[indexPath.row];
    cell.textLabel.text = [self titleForMethod:method];
    cell.accessoryType = [self.model.authMethod isEqualToString:method] ? UITableViewCellAccessoryCheckmark : UITableViewCellAccessoryNone;
    return cell;
}

- (void)tableView:(UITableView *)tableView didSelectRowAtIndexPath:(NSIndexPath *)indexPath {
    self.model.authMethod = self.methods[indexPath.row];
    [self.navigationController popViewControllerAnimated:YES];
}

@end
