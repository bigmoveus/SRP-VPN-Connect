//
//  HomeProtocolView.m
//  SRP-VPN-Connect
//

#import "HomeProtocolView.h"

@implementation HomeProtocolView {
    UILabel *_titleLabel;
    UILabel *_subtitleLabel;
    UILabel *_badgeLabel;
    UIView *_badgePill;
    UILabel *_latencyLabel;
    UIImageView *_checkView;
}

- (instancetype)initWithStyle:(UITableViewCellStyle)style reuseIdentifier:(NSString *)reuseIdentifier {
    self = [super initWithStyle:style reuseIdentifier:reuseIdentifier];
    if (self) {
        self.selectionStyle = UITableViewCellSelectionStyleNone;
        self.backgroundColor = UIColor.clearColor;
        self.contentView.backgroundColor = UIColor.clearColor;
        [self buildSubviews];
    }
    return self;
}

- (void)buildSubviews {
    UIView *card = [UIView new];
    card.backgroundColor = UIColor.secondarySystemGroupedBackgroundColor;
    card.layer.cornerRadius = 12;
    card.layer.masksToBounds = YES;
    card.translatesAutoresizingMaskIntoConstraints = NO;
    [self.contentView addSubview:card];

    _titleLabel = [UILabel new];
    _titleLabel.font = [UIFont preferredFontForTextStyle:UIFontTextStyleHeadline];
    _titleLabel.textColor = UIColor.labelColor;
    _titleLabel.translatesAutoresizingMaskIntoConstraints = NO;

    _subtitleLabel = [UILabel new];
    _subtitleLabel.font = [UIFont preferredFontForTextStyle:UIFontTextStyleSubheadline];
    _subtitleLabel.textColor = UIColor.secondaryLabelColor;
    _subtitleLabel.translatesAutoresizingMaskIntoConstraints = NO;

    // Protocol badge: a pill that hugs its content (no fixed width —
    // "AmneziaWG VPN" must never truncate)
    _badgePill = [UIView new];
    _badgePill.backgroundColor = [UIColor.systemBlueColor colorWithAlphaComponent:0.12];
    _badgePill.layer.cornerRadius = 9;
    _badgePill.layer.masksToBounds = YES;
    _badgePill.translatesAutoresizingMaskIntoConstraints = NO;

    _badgeLabel = [UILabel new];
    _badgeLabel.text = @"SSTP VPN";
    _badgeLabel.font = [UIFont monospacedSystemFontOfSize:11 weight:UIFontWeightSemibold];
    _badgeLabel.textColor = UIColor.systemBlueColor;
    _badgeLabel.textAlignment = NSTextAlignmentCenter;
    _badgeLabel.translatesAutoresizingMaskIntoConstraints = NO;
    [_badgePill addSubview:_badgeLabel];

    UIStackView *titles = [[UIStackView alloc] initWithArrangedSubviews:@[_titleLabel, _subtitleLabel]];
    titles.axis = UILayoutConstraintAxisVertical;
    titles.spacing = 2;
    titles.translatesAutoresizingMaskIntoConstraints = NO;

    _checkView = [[UIImageView alloc] initWithImage:[UIImage systemImageNamed:@"circle"]];
    _checkView.contentMode = UIViewContentModeScaleAspectFit;
    _checkView.translatesAutoresizingMaskIntoConstraints = NO;

    _latencyLabel = [UILabel new];
    _latencyLabel.font = [UIFont preferredFontForTextStyle:UIFontTextStyleCaption1];
    _latencyLabel.textColor = UIColor.secondaryLabelColor;
    _latencyLabel.textAlignment = NSTextAlignmentCenter;
    _latencyLabel.translatesAutoresizingMaskIntoConstraints = NO;

    UIStackView *right = [[UIStackView alloc] initWithArrangedSubviews:@[_badgePill, _latencyLabel]];
    right.axis = UILayoutConstraintAxisVertical;
    right.alignment = UIStackViewAlignmentCenter;
    right.spacing = 2;
    right.translatesAutoresizingMaskIntoConstraints = NO;

    [card addSubview:titles];
    [card addSubview:right];
    [card addSubview:_checkView];

    // Readable width on iPad: cards fill the width on iPhone (16pt margins)
    // but cap at 640pt centered on wide screens
    NSLayoutConstraint *fillWidth = [card.widthAnchor constraintEqualToAnchor:self.contentView.widthAnchor constant:-32];
    fillWidth.priority = UILayoutPriorityDefaultHigh;   // yields to the cap
    [NSLayoutConstraint activateConstraints:@[
        [card.topAnchor constraintEqualToAnchor:self.contentView.topAnchor constant:5],
        [card.bottomAnchor constraintEqualToAnchor:self.contentView.bottomAnchor constant:-5],
        [card.centerXAnchor constraintEqualToAnchor:self.contentView.centerXAnchor],
        [card.widthAnchor constraintLessThanOrEqualToConstant:640],
        [card.leadingAnchor constraintGreaterThanOrEqualToAnchor:self.contentView.leadingAnchor constant:16],
        [card.trailingAnchor constraintLessThanOrEqualToAnchor:self.contentView.trailingAnchor constant:-16],
        fillWidth,

        [titles.leadingAnchor constraintEqualToAnchor:card.leadingAnchor constant:14],
        [titles.centerYAnchor constraintEqualToAnchor:card.centerYAnchor],
        [titles.topAnchor constraintEqualToAnchor:card.topAnchor constant:10],
        [titles.bottomAnchor constraintEqualToAnchor:card.bottomAnchor constant:-10],

        [_badgeLabel.topAnchor constraintEqualToAnchor:_badgePill.topAnchor constant:3],
        [_badgeLabel.bottomAnchor constraintEqualToAnchor:_badgePill.bottomAnchor constant:-3],
        [_badgeLabel.leadingAnchor constraintEqualToAnchor:_badgePill.leadingAnchor constant:8],
        [_badgeLabel.trailingAnchor constraintEqualToAnchor:_badgePill.trailingAnchor constant:-8],

        [right.leadingAnchor constraintGreaterThanOrEqualToAnchor:titles.trailingAnchor constant:8],
        [right.centerYAnchor constraintEqualToAnchor:card.centerYAnchor],

        [_checkView.leadingAnchor constraintEqualToAnchor:right.trailingAnchor constant:10],
        [_checkView.trailingAnchor constraintEqualToAnchor:card.trailingAnchor constant:-14],
        [_checkView.centerYAnchor constraintEqualToAnchor:card.centerYAnchor],
        [_checkView.widthAnchor constraintEqualToConstant:24],
        [_checkView.heightAnchor constraintEqualToConstant:24],
    ]];
}

- (void)configureWithTitle:(NSString *)title subtitle:(NSString *)subtitle selected:(BOOL)selected {
    [self configureWithTitle:title subtitle:subtitle badge:nil selected:selected];
}

- (void)configureWithTitle:(NSString *)title subtitle:(NSString *)subtitle badge:(NSString *)badge selected:(BOOL)selected {
    _titleLabel.text = title;
    _subtitleLabel.text = subtitle;
    if (badge.length > 0) {
        _badgeLabel.text = badge;
    }
    _checkView.image = [UIImage systemImageNamed:selected ? @"checkmark.circle.fill" : @"circle"];
    _checkView.tintColor = selected ? UIColor.systemBlueColor : UIColor.tertiaryLabelColor;
}

- (void)configureWithTitle:(NSString *)title
                  subtitle:(NSString *)subtitle
                     badge:(NSString *)badge
                   latency:(NSString *)latency
                  selected:(BOOL)selected {
    [self configureWithTitle:title subtitle:subtitle badge:badge selected:selected];
    _latencyLabel.text = latency.length > 0 ? latency : @"Ping: —";
}

@end
