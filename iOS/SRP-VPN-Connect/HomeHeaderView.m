//
//  HomeHeaderView.m
//  SRP-VPN-Connect
//

#import "HomeHeaderView.h"

@implementation HomeHeaderView

- (instancetype)initWithStyle:(UITableViewCellStyle)style reuseIdentifier:(NSString *)reuseIdentifier {
    self = [super initWithStyle:style reuseIdentifier:reuseIdentifier];
    if (self) {
        self.selectionStyle = UITableViewCellSelectionStyleNone;
        self.backgroundColor = UIColor.clearColor;
        self.contentView.backgroundColor = UIColor.clearColor;
        [self buildSubviews];
        [self showStatus:SRPHomeStatusDisconnected animated:NO];
    }
    return self;
}

- (UIButton *)toolbarButtonWithSymbol:(NSString *)symbol {
    UIButton *button = [UIButton buttonWithType:UIButtonTypeSystem];
    UIImage *image = [UIImage systemImageNamed:symbol];
    [button setImage:image forState:UIControlStateNormal];
    button.tintColor = UIColor.secondaryLabelColor;
    button.translatesAutoresizingMaskIntoConstraints = NO;
    NSLayoutConstraint *w = [button.widthAnchor constraintEqualToConstant:44];
    NSLayoutConstraint *h = [button.heightAnchor constraintEqualToConstant:44];
    w.priority = UILayoutPriorityRequired;
    h.priority = UILayoutPriorityRequired;
    [NSLayoutConstraint activateConstraints:@[w, h]];
    return button;
}

- (void)buildSubviews {
    UILabel *titleLabel = [UILabel new];
    titleLabel.text = @"SRP VPN Connect";
    titleLabel.font = [UIFont preferredFontForTextStyle:UIFontTextStyleTitle2];
    titleLabel.textColor = UIColor.labelColor;
    titleLabel.textAlignment = NSTextAlignmentCenter;
    titleLabel.translatesAutoresizingMaskIntoConstraints = NO;

    _connectButton = [UIButton buttonWithType:UIButtonTypeSystem];
    UIImage *power = [UIImage systemImageNamed:@"power"
                             withConfiguration:[UIImageSymbolConfiguration configurationWithPointSize:38 weight:UIImageSymbolWeightMedium]];
    [_connectButton setImage:power forState:UIControlStateNormal];
    _connectButton.translatesAutoresizingMaskIntoConstraints = NO;
    _connectButton.layer.cornerRadius = 48;
    _connectButton.layer.masksToBounds = YES;

    _statusLabel = [UILabel new];
    _statusLabel.font = [UIFont preferredFontForTextStyle:UIFontTextStyleHeadline];
    _statusLabel.textAlignment = NSTextAlignmentCenter;
    _statusLabel.translatesAutoresizingMaskIntoConstraints = NO;
    // The status text is tappable (opens the connection log); the power
    // button/icon is untouched
    _statusLabel.userInteractionEnabled = YES;
    [_statusLabel addGestureRecognizer:[[UITapGestureRecognizer alloc]
        initWithTarget:self action:@selector(statusTapped)]];

    _editButton = [self toolbarButtonWithSymbol:@"square.and.pencil"];
    _helpButton = [self toolbarButtonWithSymbol:@"questionmark.circle"];
    _addButton = [self toolbarButtonWithSymbol:@"plus"];

    UIStackView *toolbar = [[UIStackView alloc] initWithArrangedSubviews:@[_editButton, _helpButton, _addButton]];
    toolbar.axis = UILayoutConstraintAxisHorizontal;
    toolbar.spacing = 24;
    toolbar.alignment = UIStackViewAlignmentCenter;
    toolbar.translatesAutoresizingMaskIntoConstraints = NO;

    UIStackView *stack = [[UIStackView alloc] initWithArrangedSubviews:@[titleLabel, _connectButton, _statusLabel, toolbar]];
    stack.axis = UILayoutConstraintAxisVertical;
    stack.alignment = UIStackViewAlignmentCenter;
    stack.spacing = 12;
    stack.translatesAutoresizingMaskIntoConstraints = NO;
    [self.contentView addSubview:stack];

    [NSLayoutConstraint activateConstraints:@[
        [stack.topAnchor constraintEqualToAnchor:self.contentView.topAnchor constant:24],
        [stack.bottomAnchor constraintEqualToAnchor:self.contentView.bottomAnchor constant:-20],
        [stack.leadingAnchor constraintEqualToAnchor:self.contentView.leadingAnchor],
        [stack.trailingAnchor constraintEqualToAnchor:self.contentView.trailingAnchor],
        [_connectButton.widthAnchor constraintEqualToConstant:96],
        [_connectButton.heightAnchor constraintEqualToConstant:96],
    ]];
}

- (void)statusTapped {
    if (self.onStatusTap) {
        self.onStatusTap();
    }
}

- (void)showStatus:(SRPHomeStatus)status animated:(BOOL)animated {
    UIColor *tint;
    NSString *text;
    switch (status) {
        case SRPHomeStatusConnected:
            tint = UIColor.systemGreenColor;
            text = @"Connected";
            break;
        case SRPHomeStatusConnecting:
            tint = UIColor.systemBlueColor;
            text = @"Connecting…";
            break;
        case SRPHomeStatusDisconnected:
        default:
            tint = UIColor.systemGrayColor;
            text = @"Disconnected";
            break;
    }
    void (^apply)(void) = ^{
        self.connectButton.tintColor = tint;
        self.connectButton.backgroundColor = [tint colorWithAlphaComponent:0.12];
        self.statusLabel.textColor = tint;
        self.statusLabel.text = text;
    };
    if (animated) {
        [UIView animateWithDuration:0.25 animations:apply];
    } else {
        apply();
    }

    if (status == SRPHomeStatusConnecting) {
        // Light pulse while connecting (UIView animation only)
        [UIView animateWithDuration:0.7
                              delay:0
                            options:UIViewAnimationOptionAutoreverse | UIViewAnimationOptionRepeat | UIViewAnimationOptionAllowUserInteraction
                         animations:^{
            self.connectButton.transform = CGAffineTransformMakeScale(1.06, 1.06);
        } completion:nil];
    } else {
        [self.connectButton.layer removeAllAnimations];
        [UIView animateWithDuration:0.2 animations:^{
            self.connectButton.transform = CGAffineTransformIdentity;
        }];
    }
}

@end
