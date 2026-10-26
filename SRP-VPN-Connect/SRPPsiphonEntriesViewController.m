//
//  SRPPsiphonEntriesViewController.m
//  SRP-VPN-Connect
//

#import "SRPPsiphonEntriesViewController.h"
#import "NodeModel.h"
#import <UniformTypeIdentifiers/UniformTypeIdentifiers.h>

@interface SRPPsiphonEntriesViewController () <UITextViewDelegate, UIDocumentPickerDelegate>
@property (nonatomic, strong) NodeModel *model;
@property (nonatomic, strong) UITextView *textView;
@property (nonatomic, strong) UILabel *countLabel;
@end

@implementation SRPPsiphonEntriesViewController

- (instancetype)initWithNodeModel:(NodeModel *)model {
    self = [super initWithNibName:nil bundle:nil];
    if (self) {
        _model = model;
    }
    return self;
}

- (void)viewDidLoad {
    [super viewDidLoad];
    self.title = @"Server Entries";
    self.view.backgroundColor = UIColor.systemBackgroundColor;

    self.navigationItem.rightBarButtonItem = [[UIBarButtonItem alloc] initWithBarButtonSystemItem:UIBarButtonSystemItemDone
                                                                                           target:self
                                                                                           action:@selector(onDone)];

    UIToolbar *tools = [[UIToolbar alloc] init];
    tools.translatesAutoresizingMaskIntoConstraints = NO;
    UIBarButtonItem *paste = [[UIBarButtonItem alloc] initWithTitle:@"Paste"
                                                              style:UIBarButtonItemStylePlain
                                                             target:self
                                                             action:@selector(onPaste)];
    UIBarButtonItem *import = [[UIBarButtonItem alloc] initWithTitle:@"Import from File"
                                                               style:UIBarButtonItemStylePlain
                                                              target:self
                                                              action:@selector(onImport)];
    UIBarButtonItem *flex = [[UIBarButtonItem alloc] initWithBarButtonSystemItem:UIBarButtonSystemItemFlexibleSpace target:nil action:nil];
    UIBarButtonItem *clear = [[UIBarButtonItem alloc] initWithTitle:@"Clear"
                                                              style:UIBarButtonItemStylePlain
                                                             target:self
                                                             action:@selector(onClear)];
    tools.items = @[paste, import, flex, clear];
    [self.view addSubview:tools];

    self.countLabel = [[UILabel alloc] init];
    self.countLabel.translatesAutoresizingMaskIntoConstraints = NO;
    self.countLabel.font = [UIFont preferredFontForTextStyle:UIFontTextStyleCaption1];
    self.countLabel.textColor = UIColor.secondaryLabelColor;
    self.countLabel.numberOfLines = 0;
    [self.view addSubview:self.countLabel];

    self.textView = [[UITextView alloc] init];
    self.textView.translatesAutoresizingMaskIntoConstraints = NO;
    self.textView.font = [UIFont monospacedSystemFontOfSize:13 weight:UIFontWeightRegular];
    self.textView.autocorrectionType = UITextAutocorrectionTypeNo;
    self.textView.autocapitalizationType = UITextAutocapitalizationTypeNone;
    self.textView.smartQuotesType = UITextSmartQuotesTypeNo;
    self.textView.smartDashesType = UITextSmartDashesTypeNo;
    self.textView.keyboardDismissMode = UIScrollViewKeyboardDismissModeInteractive;
    self.textView.delegate = self;
    self.textView.text = self.model.psiphonServerEntry;
    self.textView.layer.borderWidth = 0.5;
    self.textView.layer.borderColor = UIColor.separatorColor.CGColor;
    self.textView.layer.cornerRadius = 8;
    [self.view addSubview:self.textView];

    [NSLayoutConstraint activateConstraints:@[
        [tools.topAnchor constraintEqualToAnchor:self.view.safeAreaLayoutGuide.topAnchor],
        [tools.leadingAnchor constraintEqualToAnchor:self.view.leadingAnchor],
        [tools.trailingAnchor constraintEqualToAnchor:self.view.trailingAnchor],
        [self.countLabel.topAnchor constraintEqualToAnchor:tools.bottomAnchor constant:8],
        [self.countLabel.leadingAnchor constraintEqualToAnchor:self.view.leadingAnchor constant:16],
        [self.countLabel.trailingAnchor constraintEqualToAnchor:self.view.trailingAnchor constant:-16],
        [self.textView.topAnchor constraintEqualToAnchor:self.countLabel.bottomAnchor constant:8],
        [self.textView.leadingAnchor constraintEqualToAnchor:self.view.leadingAnchor constant:12],
        [self.textView.trailingAnchor constraintEqualToAnchor:self.view.trailingAnchor constant:-12],
        [self.textView.bottomAnchor constraintEqualToAnchor:self.view.keyboardLayoutGuide.topAnchor constant:-8],
    ]];

    [self updateCount];
}

#pragma mark - helpers

- (NSArray<NSString *> *)entriesIn:(NSString *)text {
    NSString *raw = [text stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
    NSMutableArray *out = [NSMutableArray new];
    for (NSString *p in [raw componentsSeparatedByCharactersInSet:
                         [NSCharacterSet characterSetWithCharactersInString:@" \t\r\n,"]]) {
        if (p.length > 0) [out addObject:p];
    }
    return out;
}

- (void)updateCount {
    NSArray *entries = [self entriesIn:self.textView.text];
    BOOL hexOK = entries.count > 0;
    for (NSString *e in entries) {
        NSCharacterSet *hexSet = [NSCharacterSet characterSetWithCharactersInString:@"0123456789abcdefABCDEF"];
        if (e.length % 2 != 0 || [[e stringByTrimmingCharactersInSet:hexSet] length] > 0) hexOK = NO;
    }
    self.countLabel.text = [NSString stringWithFormat:@"%lu server %@ — each produced by 'psiphond generate' on a server; separate with spaces or new lines. The core rotates between them.",
                            (unsigned long)entries.count,
                            entries.count == 1 ? @"entry" : @"entries"];
    if (!hexOK && entries.count > 0) {
        self.countLabel.text = [self.countLabel.text stringByAppendingString:@"\n⚠️ Some entries contain non-hex characters — the paste may be corrupted."];
    }
}

- (void)commitText {
    self.model.psiphonServerEntry = [self.textView.text stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
}

#pragma mark - actions

- (void)textViewDidChange:(UITextView *)textView {
    [self commitText];
    [self updateCount];
}

- (void)onDone {
    [self commitText];
    [self.navigationController popViewControllerAnimated:YES];
}

- (void)onPaste {
    NSString *clip = UIPasteboard.generalPasteboard.string;
    if (clip.length == 0) return;
    NSString *current = self.textView.text;
    self.textView.text = current.length > 0 ? [NSString stringWithFormat:@"%@\n%@", current, clip] : clip;
    [self textViewDidChange:self.textView];
}

- (void)onClear {
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"Clear all entries?"
                                                                   message:nil
                                                            preferredStyle:UIAlertControllerStyleAlert];
    [alert addAction:[UIAlertAction actionWithTitle:@"Clear" style:UIAlertActionStyleDestructive handler:^(UIAlertAction *a) {
        self.textView.text = @"";
        [self textViewDidChange:self.textView];
    }]];
    [alert addAction:[UIAlertAction actionWithTitle:@"Cancel" style:UIAlertActionStyleCancel handler:nil]];
    [self presentViewController:alert animated:YES completion:nil];
}

- (void)onImport {
    UIDocumentPickerViewController *picker =
        [[UIDocumentPickerViewController alloc] initForOpeningContentTypes:@[UTTypeText, UTTypeData] asCopy:YES];
    picker.delegate = self;
    picker.allowsMultipleSelection = NO;
    [self presentViewController:picker animated:YES completion:nil];
}

- (void)documentPicker:(UIDocumentPickerViewController *)controller didPickDocumentsAtURLs:(NSArray<NSURL *> *)urls {
    NSURL *url = urls.firstObject;
    if (!url) return;
    NSString *text = [NSString stringWithContentsOfURL:url encoding:NSUTF8StringEncoding error:nil];
    if (text.length == 0) return;
    NSString *current = self.textView.text;
    self.textView.text = current.length > 0
        ? [NSString stringWithFormat:@"%@\n%@", current, [text stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet]]
        : [text stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
    [self textViewDidChange:self.textView];
}

@end
