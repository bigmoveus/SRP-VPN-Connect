//
//  SRPCertificateViewController.m
//  SRP-VPN-Connect
//
//  "Select Certificate" screen for certificate (EAP-TLS) authentication:
//  lists the imported client certificates, imports .p12/.pfx files through
//  the document picker (passphrase prompt), and swipe-to-delete.
//

#import "SRPCertificateViewController.h"
#import "SRPCertificateStore.h"
#import "NodeModel.h"
#import <UniformTypeIdentifiers/UniformTypeIdentifiers.h>

@interface SRPCertificateViewController () <UIDocumentPickerDelegate>
@property (nonatomic, strong) NodeModel *model;
@property (nonatomic, strong) NSArray<SRPCertificateInfo *> *certs;
@property (nonatomic, strong) NSData *pendingP12;
@property (nonatomic, copy) NSString *pendingFileName;
@end

@implementation SRPCertificateViewController

- (instancetype)initWithNodeModel:(NodeModel *)model {
    self = [super initWithStyle:UITableViewStyleGrouped];
    if (self) {
        _model = model;
    }
    return self;
}

- (void)viewDidLoad {
    [super viewDidLoad];
    self.title = @"Select Certificate";

    UIBarButtonItem *importItem = [[UIBarButtonItem alloc] initWithTitle:@"Import"
                                                                   style:UIBarButtonItemStylePlain
                                                                  target:self
                                                                  action:@selector(onImport)];
    UIBarButtonItem *helpItem = [[UIBarButtonItem alloc] initWithTitle:@"?"
                                                                 style:UIBarButtonItemStylePlain
                                                                target:self
                                                                action:@selector(onHelp)];
    self.navigationItem.rightBarButtonItems = @[importItem, helpItem];
    [self reload];
}

- (void)viewWillAppear:(BOOL)animated {
    [super viewWillAppear:animated];
    [self reload];
}

- (void)reload {
    self.certs = [SRPCertificateStore certificates];
    [self.tableView reloadData];
}

#pragma mark - Import

- (void)onHelp {
    UIAlertController *alert = [UIAlertController
        alertControllerWithTitle:@"Client Certificate"
                         message:@"Import a client certificate as a .p12 or .pfx file (PKCS#12). "
                                 @"The file must contain the certificate and its private key. "
                                 @"You will be asked for the export passphrase."
                  preferredStyle:UIAlertControllerStyleAlert];
    [alert addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];
    [self presentViewController:alert animated:YES completion:nil];
}

- (void)onImport {
    UTType *p12 = [UTType typeWithIdentifier:@"com.rsa.pkcs-12"];
    UIDocumentPickerViewController *picker =
        [[UIDocumentPickerViewController alloc] initForOpeningContentTypes:@[p12 ?: UTTypeData]];
    picker.delegate = self;
    [self presentViewController:picker animated:YES completion:nil];
}

- (void)documentPicker:(UIDocumentPickerViewController *)controller didPickDocumentsAtURLs:(NSArray<NSURL *> *)urls {
    NSURL *url = urls.firstObject;
    if (url == nil) {
        return;
    }
    BOOL scoped = [url startAccessingSecurityScopedResource];
    NSData *data = [NSData dataWithContentsOfURL:url];
    if (scoped) {
        [url stopAccessingSecurityScopedResource];
    }
    if (data.length == 0) {
        [self showError:@"Could not read the selected file."];
        return;
    }
    self.pendingP12 = data;
    self.pendingFileName = url.lastPathComponent;
    [self askPassphrase];
}

- (void)askPassphrase {
    UIAlertController *alert = [UIAlertController
        alertControllerWithTitle:@"Certificate Passphrase"
                         message:[NSString stringWithFormat:@"Enter the passphrase for %@",
                                  self.pendingFileName ?: @"the certificate"]
                  preferredStyle:UIAlertControllerStyleAlert];
    [alert addTextFieldWithConfigurationHandler:^(UITextField *field) {
        field.secureTextEntry = YES;
        field.placeholder = @"Passphrase";
    }];
    __weak SRPCertificateViewController *weakSelf = self;
    [alert addAction:[UIAlertAction actionWithTitle:@"Cancel" style:UIAlertActionStyleCancel handler:nil]];
    [alert addAction:[UIAlertAction actionWithTitle:@"Import" style:UIAlertActionStyleDefault
                                            handler:^(UIAlertAction *action) {
        [weakSelf finishImport:alert.textFields.firstObject.text ?: @""];
    }]];
    [self presentViewController:alert animated:YES completion:nil];
}

- (void)finishImport:(NSString *)passphrase {
    NSError *error = nil;
    SRPCertificateInfo *info = [SRPCertificateStore importP12:self.pendingP12
                                                   passphrase:passphrase
                                                        error:&error];
    self.pendingP12 = nil;
    self.pendingFileName = nil;
    if (info == nil) {
        [self showError:error.localizedDescription ?: @"Import failed."];
        return;
    }
    // Select the freshly imported certificate right away
    self.model.certKey = info.ref;
    self.model.certName = info.name;
    [self reload];
}

- (void)showError:(NSString *)message {
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"Import Failed"
                                                                   message:message
                                                            preferredStyle:UIAlertControllerStyleAlert];
    [alert addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];
    [self presentViewController:alert animated:YES completion:nil];
}

#pragma mark - Table view

- (NSInteger)numberOfSectionsInTableView:(UITableView *)tableView {
    return 1;
}

- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section {
    return self.certs.count;
}

- (NSString *)tableView:(UITableView *)tableView titleForFooterInSection:(NSInteger)section {
    if (self.certs.count == 0) {
        return @"No certificates imported yet. Tap Import to add a .p12/.pfx client certificate.";
    }
    return nil;
}

- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath {
    static NSString *cellID = @"cert";
    UITableViewCell *cell = [tableView dequeueReusableCellWithIdentifier:cellID];
    if (!cell) {
        cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleSubtitle reuseIdentifier:cellID];
    }
    SRPCertificateInfo *info = self.certs[indexPath.row];
    cell.textLabel.text = info.name;
    static NSDateFormatter *fmt = nil;
    if (!fmt) {
        fmt = [NSDateFormatter new];
        fmt.dateStyle = NSDateFormatterMediumStyle;
        fmt.timeStyle = NSDateFormatterNoStyle;
    }
    cell.detailTextLabel.text = [NSString stringWithFormat:@"Expires %@",
                                 [fmt stringFromDate:info.expiry]];
    cell.accessoryType = [self.model.certKey isEqualToString:info.ref]
        ? UITableViewCellAccessoryCheckmark : UITableViewCellAccessoryNone;
    return cell;
}

- (void)tableView:(UITableView *)tableView didSelectRowAtIndexPath:(NSIndexPath *)indexPath {
    SRPCertificateInfo *info = self.certs[indexPath.row];
    self.model.certKey = info.ref;
    self.model.certName = info.name;
    [self.navigationController popViewControllerAnimated:YES];
}

- (BOOL)tableView:(UITableView *)tableView canEditRowAtIndexPath:(NSIndexPath *)indexPath {
    return YES;
}

- (void)tableView:(UITableView *)tableView
    commitEditingStyle:(UITableViewCellEditingStyle)editingStyle
     forRowAtIndexPath:(NSIndexPath *)indexPath {
    if (editingStyle != UITableViewCellEditingStyleDelete) {
        return;
    }
    SRPCertificateInfo *info = self.certs[indexPath.row];
    [SRPCertificateStore removeCertificateWithRef:info.ref];
    if ([self.model.certKey isEqualToString:info.ref]) {
        self.model.certKey = nil;
        self.model.certName = nil;
    }
    [self reload];
}

@end
