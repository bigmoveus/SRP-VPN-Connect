//
//  SRPLogViewController.m
//  SRP-VPN-Connect
//

#import "SRPLogViewController.h"
#import "NodeModel.h"

@implementation SRPLogViewController {
    UITextView *_textView;
}

/// The extension writes srptunnel.log into the shared app-group container
+ (NSString *)logFilePath {
    NSURL *container = [[NSFileManager defaultManager]
        containerURLForSecurityApplicationGroupIdentifier:@"group.tr.com.srp.vpn"];
    // Keep the log under Library/ so it stays within the app-group's
    // readable directories (devicectl allows Library/Documents/tmp only).
    NSString *base = container ? container.path : NSHomeDirectory();
    NSString *dir = [base stringByAppendingPathComponent:@"Library"];
    [[NSFileManager defaultManager] createDirectoryAtPath:dir withIntermediateDirectories:YES attributes:nil error:nil];
    return [dir stringByAppendingPathComponent:@"srptunnel.log"];
}

+ (NSString *)logLevelName {
    switch ([NodeModel shareInstance].selectNode.logLevel) {
        case 2: return @"Debug";
        case 1: return @"Expert";
        default: return @"Normal";
    }
}

- (void)viewDidLoad {
    [super viewDidLoad];
    self.title = @"Connection Log";
    self.view.backgroundColor = UIColor.systemBackgroundColor;

    self.navigationItem.rightBarButtonItems = @[
        [[UIBarButtonItem alloc] initWithImage:[UIImage systemImageNamed:@"arrow.clockwise"]
                                         style:UIBarButtonItemStylePlain
                                        target:self action:@selector(onRefresh)],
        [[UIBarButtonItem alloc] initWithImage:[UIImage systemImageNamed:@"square.and.arrow.up"]
                                         style:UIBarButtonItemStylePlain
                                        target:self action:@selector(onShare)],
        [[UIBarButtonItem alloc] initWithImage:[UIImage systemImageNamed:@"trash"]
                                         style:UIBarButtonItemStylePlain
                                        target:self action:@selector(onClear)],
    ];

    _textView = [UITextView new];
    _textView.editable = NO;
    _textView.selectable = YES;
    _textView.font = [UIFont monospacedSystemFontOfSize:11 weight:UIFontWeightRegular];
    _textView.textColor = UIColor.labelColor;
    _textView.backgroundColor = UIColor.systemBackgroundColor;
    _textView.translatesAutoresizingMaskIntoConstraints = NO;
    [self.view addSubview:_textView];
    [NSLayoutConstraint activateConstraints:@[
        [_textView.topAnchor constraintEqualToAnchor:self.view.safeAreaLayoutGuide.topAnchor],
        [_textView.bottomAnchor constraintEqualToAnchor:self.view.bottomAnchor],
        [_textView.leadingAnchor constraintEqualToAnchor:self.view.leadingAnchor],
        [_textView.trailingAnchor constraintEqualToAnchor:self.view.trailingAnchor],
    ]];
    [self onRefresh];
}

- (void)onRefresh {
    NSString *path = [SRPLogViewController logFilePath];
    NSString *log = [NSString stringWithContentsOfFile:path encoding:NSUTF8StringEncoding error:nil];
    NSString *header = [NSString stringWithFormat:@"# srptunnel.log — log level: %@\n\n",
                        [SRPLogViewController logLevelName]];
    _textView.text = [header stringByAppendingString:log.length > 0 ? log : @"(no log yet — connect once to produce one)"];
    // auto-scroll to the end
    dispatch_async(dispatch_get_main_queue(), ^{
        NSRange end = NSMakeRange(self->_textView.text.length, 0);
        [self->_textView scrollRangeToVisible:end];
    });
}

- (void)onClear {
    NSString *path = [SRPLogViewController logFilePath];
    [[NSFileManager defaultManager] removeItemAtPath:path error:nil];
    [[NSFileManager defaultManager] createFileAtPath:path contents:nil attributes:nil];
    [self onRefresh];
}

- (void)onShare {
    NSString *path = [SRPLogViewController logFilePath];
    NSURL *url = [NSURL fileURLWithPath:path];
    UIActivityViewController *share = [[UIActivityViewController alloc]
        initWithActivityItems:@[url] applicationActivities:nil];
    [self presentViewController:share animated:YES completion:nil];
}

@end
