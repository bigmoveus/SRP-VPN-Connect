#import "SRPWaterWallConfigViewController.h"
#import "NodeModel.h"
#import <IQKeyboardManager.h>
#import <SRPCore/SRPGeoIPDatabase.h>
#import <SRPCore/SRPWaterWallChainConfig.h>
#import <UniformTypeIdentifiers/UniformTypeIdentifiers.h>

#pragma mark - Shared pieces

// The large title the WaterWall screens show under the navigation bar
static UIView *SRPWWTitleView(NSString *title, UILabel **labelOut) {
    UILabel *label = [UILabel new];
    label.translatesAutoresizingMaskIntoConstraints = NO;
    label.text = title;
    UIFontDescriptor *descriptor = [[UIFontDescriptor preferredFontDescriptorWithTextStyle:UIFontTextStyleLargeTitle]
                                    fontDescriptorWithSymbolicTraits:UIFontDescriptorTraitBold];
    label.font = [UIFont fontWithDescriptor:descriptor size:0];
    label.adjustsFontForContentSizeCategory = YES;
    label.numberOfLines = 0;
    label.accessibilityTraits = UIAccessibilityTraitHeader;
    UIView *header = [[UIView alloc] initWithFrame:CGRectMake(0, 0, 320, 56)];
    [header addSubview:label];
    [NSLayoutConstraint activateConstraints:@[
        [label.leadingAnchor constraintEqualToAnchor:header.layoutMarginsGuide.leadingAnchor],
        [label.trailingAnchor constraintEqualToAnchor:header.layoutMarginsGuide.trailingAnchor],
        [label.topAnchor constraintEqualToAnchor:header.topAnchor constant:4],
        [label.bottomAnchor constraintEqualToAnchor:header.bottomAnchor constant:-4],
    ]];
    if (labelOut) *labelOut = label;
    return header;
}

// A table view sizes its sections, not its header view: the title header takes the height its text needs
static void SRPWWFitHeader(UITableView *table) {
    UIView *header = table.tableHeaderView;
    CGFloat width = table.bounds.size.width;
    if (header == nil || width == 0) return;
    CGFloat height = [header systemLayoutSizeFittingSize:CGSizeMake(width, UILayoutFittingCompressedSize.height)
                           withHorizontalFittingPriority:UILayoutPriorityRequired
                                 verticalFittingPriority:UILayoutPriorityFittingSizeLevel].height;
    if (fabs(header.frame.size.height - height) < 0.5 && fabs(header.frame.size.width - width) < 0.5) return;
    header.frame = CGRectMake(0, 0, width, height);
    table.tableHeaderView = header;
}

static void SRPWWAlert(UIViewController *controller, NSString *title, NSString *message) {
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:title message:message preferredStyle:UIAlertControllerStyleAlert];
    [alert addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];
    [controller presentViewController:alert animated:YES completion:nil];
}

// The profile's document as the editor has it: a new profile's lacks nodes yet, so it is read, not checked
static NSDictionary *SRPWWDocument(NodeModel *model) {
    NSData *data = [model.waterwallChainJSON dataUsingEncoding:NSUTF8StringEncoding];
    id document = data ? [NSJSONSerialization JSONObjectWithData:data options:0 error:nil] : nil;
    return [document isKindOfClass:NSDictionary.class] ? document : [SRPWaterWallNodeChain emptyDocument];
}

static BOOL SRPWWIsHintNode(NSDictionary *node) {
    return [node[@"type"] isEqual:SRPWaterWallHintConnection] || [node[@"type"] isEqual:SRPWaterWallHintPacket];
}

// Keeps a checked document in the profile being edited; the profile's Save puts it in the Keychain
static void SRPWWKeep(NodeModel *model, NSDictionary *document) {
    model.waterwallChainJSON = [SRPWaterWallNodeChain JSONWithDocument:document];
    // A chain saved over a profile that could not be converted replaces its former settings
    model.waterwallConfigJSON = nil;
    model.waterwallPreset = nil;
    [model syncWaterWallServer];
    // A Router that routes by country needs the database before the tunnel starts
    if ([SRPWaterWallNodeChain documentUsesGeoIP:document]) [SRPGeoIPDatabase.sharedDatabase installBundledDatabaseIfNeeded:nil];
}

// Empty text means no settings. Otherwise *message says why the text is not a JSON object, with the line and column of
// a syntax error.
static NSDictionary *SRPWWSettingsWithText(NSString *text, NSString **message) {
    if ([text stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet].length == 0) return @{};
    NSData *data = [text dataUsingEncoding:NSUTF8StringEncoding];
    NSError *error = nil;
    id settings = [NSJSONSerialization JSONObjectWithData:data options:0 error:&error];
    if ([settings isKindOfClass:NSDictionary.class]) return settings;
    if (settings != nil) {
        *message = @"The settings must be a JSON object.";
        return nil;
    }
    NSString *reason = error.userInfo[NSDebugDescriptionErrorKey] ?: @"Invalid JSON.";
    NSNumber *index = error.userInfo[@"NSJSONSerializationErrorIndex"];
    if (index == nil) {
        *message = reason;
        return nil;
    }
    NSRange around = [reason rangeOfString:@" around "];
    if (around.location != NSNotFound) reason = [reason substringToIndex:around.location];
    // The index counts UTF-8 bytes; the line and column count characters as the editor shows them.
    NSData *head = [data subdataWithRange:NSMakeRange(0, MIN(index.unsignedIntegerValue, data.length))];
    NSArray<NSString *> *lines = [([[NSString alloc] initWithData:head encoding:NSUTF8StringEncoding] ?: @"")
                                  componentsSeparatedByString:@"\n"];
    *message = [NSString stringWithFormat:@"Line %lu, column %lu: %@", (unsigned long)lines.count,
                (unsigned long)lines.lastObject.length + 1, reason];
    return nil;
}

static NSString *SRPWWTextWithSettings(NSDictionary *settings) {
    NSData *data = [NSJSONSerialization dataWithJSONObject:settings
                                                   options:NSJSONWritingPrettyPrinted | NSJSONWritingSortedKeys |
                                                           NSJSONWritingWithoutEscapingSlashes
                                                     error:nil];
    return [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding] ?: @"{}";
}

// A new line keeps the indentation of the line it breaks, one level deeper after { or [.
static NSString *SRPWWNewline(NSString *text, NSUInteger location) {
    NSRange line = [text lineRangeForRange:NSMakeRange(location, 0)];
    NSString *head = [text substringWithRange:NSMakeRange(line.location, location - line.location)];
    NSString *indent = [head substringToIndex:[head rangeOfString:@"^[ \t]*" options:NSRegularExpressionSearch].length];
    NSString *trimmed = [head stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceCharacterSet];
    if ([trimmed hasSuffix:@"{"] || [trimmed hasSuffix:@"["]) indent = [indent stringByAppendingString:@"  "];
    return [@"\n" stringByAppendingString:indent];
}

static UIColor *SRPWWColor(CGFloat r, CGFloat g, CGFloat b, CGFloat darkR, CGFloat darkG, CGFloat darkB) {
    return [UIColor colorWithDynamicProvider:^UIColor *(UITraitCollection *traits) {
        BOOL dark = traits.userInterfaceStyle == UIUserInterfaceStyleDark;
        return [UIColor colorWithRed:dark ? darkR : r green:dark ? darkG : g blue:dark ? darkB : b alpha:1];
    }];
}

// Keys in red, values in blue, as the editor's mockup shows them
static void SRPWWHighlight(UITextView *textView) {
    static NSRegularExpression *strings, *literals;
    static UIColor *keyColor, *valueColor;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        strings = [NSRegularExpression regularExpressionWithPattern:@"\"(?:[^\"\\\\\\n]|\\\\.)*\"(\\s*:)?" options:0 error:nil];
        literals = [NSRegularExpression regularExpressionWithPattern:@"\\b(?:true|false|null)\\b|-?\\b\\d+(?:\\.\\d+)?(?:[eE][+-]?\\d+)?\\b"
                                                             options:0 error:nil];
        keyColor = SRPWWColor(0.77, 0.10, 0.09, 1.0, 0.45, 0.40);
        valueColor = SRPWWColor(0.11, 0.0, 0.81, 0.45, 0.75, 1.0);
    });
    NSTextStorage *storage = textView.textStorage;
    NSString *text = storage.string;
    NSRange all = NSMakeRange(0, text.length);
    [storage beginEditing];
    [storage setAttributes:@{NSFontAttributeName: textView.font, NSForegroundColorAttributeName: UIColor.labelColor} range:all];
    [literals enumerateMatchesInString:text options:0 range:all usingBlock:^(NSTextCheckingResult *match, NSMatchingFlags flags, BOOL *stop) {
        [storage addAttribute:NSForegroundColorAttributeName value:valueColor range:match.range];
    }];
    [strings enumerateMatchesInString:text options:0 range:all usingBlock:^(NSTextCheckingResult *match, NSMatchingFlags flags, BOOL *stop) {
        NSRange colon = [match rangeAtIndex:1];
        NSRange range = colon.location == NSNotFound ? match.range : NSMakeRange(match.range.location, colon.location - match.range.location);
        [storage addAttribute:NSForegroundColorAttributeName value:colon.location == NSNotFound ? valueColor : keyColor range:range];
    }];
    [storage endEditing];
}

#pragma mark - Edit Node

@interface SRPWaterWallNodeViewController : UITableViewController <UITextViewDelegate>

- (instancetype)initWithModel:(NodeModel *)model nodeName:(nullable NSString *)name insertingAfter:(nullable NSString *)previous;

@end

@implementation SRPWaterWallNodeViewController {
    NodeModel *_model;
    NSString *_name;        // the node edited; nil when a new one is inserted
    NSString *_previous;    // the node a new one follows
    NSDictionary *_node;    // the node as the chain has it, or the new one
    UITextField *_nameField;
    UITextField *_typeField;
    UITextView *_settingsView;
    UILabel *_titleLabel;
    UILabel *_statusLabel;
}

- (instancetype)initWithModel:(NodeModel *)model nodeName:(NSString *)name insertingAfter:(NSString *)previous {
    self = [super initWithStyle:UITableViewStyleInsetGrouped];
    if (self) {
        _model = model;
        _name = [name copy];
        _previous = [previous copy];
        NSDictionary *found = nil;
        for (id node in SRPWWDocument(model)[@"nodes"]) {
            if ([node isKindOfClass:NSDictionary.class] && [node[@"name"] isEqual:name ?: previous]) found = node;
        }
        if (name != nil) {
            _node = found ?: @{@"name": name, @"type": @""};
        } else {
            // The new node takes over the successor of the one it follows
            NSMutableDictionary *node = [@{@"name": @"", @"type": @""} mutableCopy];
            node[@"next"] = found[@"next"];
            _node = node;
        }
    }
    return self;
}

- (UITextField *)fieldWithText:(NSString *)text placeholder:(NSString *)placeholder {
    UITextField *field = [UITextField new];
    field.text = [text isKindOfClass:NSString.class] ? text : @"";
    field.placeholder = placeholder;
    field.font = [UIFont preferredFontForTextStyle:UIFontTextStyleBody];
    field.adjustsFontForContentSizeCategory = YES;
    field.autocorrectionType = UITextAutocorrectionTypeNo;
    field.autocapitalizationType = UITextAutocapitalizationTypeNone;
    field.spellCheckingType = UITextSpellCheckingTypeNo;
    field.clearButtonMode = UITextFieldViewModeWhileEditing;
    field.returnKeyType = UIReturnKeyDone;
    [field addTarget:field action:@selector(resignFirstResponder) forControlEvents:UIControlEventEditingDidEndOnExit];
    return field;
}

- (void)viewDidLoad {
    [super viewDidLoad];
    // The table view moves the editor above the keyboard. IQKeyboardManager would also lift CreateVC, which holds the
    // whole navigation stack, and push the bar buttons under the status bar.
    [[IQKeyboardManager sharedManager].disabledDistanceHandlingClasses addObject:self.class];
    self.title = _name != nil ? @"Edit Node" : @"Insert Node";
    self.navigationItem.rightBarButtonItem = [[UIBarButtonItem alloc] initWithTitle:@"Save" style:UIBarButtonItemStyleDone
                                                                             target:self action:@selector(save)];
    UILabel *title = nil;
    self.tableView.tableHeaderView = SRPWWTitleView([_node[@"type"] length] > 0 ? _node[@"type"] : @"New Node", &title);
    _titleLabel = title;
    _nameField = [self fieldWithText:_node[@"name"] placeholder:@"Required"];
    _nameField.accessibilityLabel = @"Name";
    _typeField = [self fieldWithText:_node[@"type"] placeholder:@"Required, such as TlsClient"];
    _typeField.accessibilityLabel = @"Type";
    [_typeField addTarget:self action:@selector(typeChanged) forControlEvents:UIControlEventEditingChanged];
    if (!SRPWWIsHintNode(_node)) {
        _settingsView = [UITextView new];
        _settingsView.translatesAutoresizingMaskIntoConstraints = NO;
        _settingsView.font = [[UIFontMetrics metricsForTextStyle:UIFontTextStyleBody]
                              scaledFontForFont:[UIFont monospacedSystemFontOfSize:15 weight:UIFontWeightRegular]];
        _settingsView.adjustsFontForContentSizeCategory = YES;
        _settingsView.backgroundColor = UIColor.clearColor;
        _settingsView.text = SRPWWTextWithSettings([_node[@"settings"] isKindOfClass:NSDictionary.class] ? _node[@"settings"] : @{});
        _settingsView.autocorrectionType = UITextAutocorrectionTypeNo;
        _settingsView.autocapitalizationType = UITextAutocapitalizationTypeNone;
        _settingsView.smartQuotesType = UITextSmartQuotesTypeNo;
        _settingsView.smartDashesType = UITextSmartDashesTypeNo;
        _settingsView.smartInsertDeleteType = UITextSmartInsertDeleteTypeNo;
        _settingsView.spellCheckingType = UITextSpellCheckingTypeNo;
        _settingsView.keyboardType = UIKeyboardTypeASCIICapable;
        _settingsView.accessibilityLabel = @"Settings";
        _settingsView.delegate = self;
        _statusLabel = [UILabel new];
        _statusLabel.translatesAutoresizingMaskIntoConstraints = NO;
        _statusLabel.font = [UIFont preferredFontForTextStyle:UIFontTextStyleFootnote];
        _statusLabel.adjustsFontForContentSizeCategory = YES;
        _statusLabel.numberOfLines = 0;
        [self textViewDidChange:_settingsView];
    }
}

- (void)viewDidLayoutSubviews {
    [super viewDidLayoutSubviews];
    SRPWWFitHeader(self.tableView);
}

- (void)typeChanged {
    _titleLabel.text = _typeField.text.length > 0 ? _typeField.text : @"New Node";
    SRPWWFitHeader(self.tableView);
}

- (BOOL)showsNext {
    return [_node[@"next"] isKindOfClass:NSString.class];
}

- (NSInteger)numberOfSectionsInTableView:(UITableView *)tableView {
    return _settingsView != nil ? 2 : 1;
}

- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section {
    return section == 0 ? ([self showsNext] ? 3 : 2) : 1;
}

- (NSString *)tableView:(UITableView *)tableView titleForHeaderInSection:(NSInteger)section {
    return section == 0 ? @"NODE" : @"SETTINGS";
}

- (NSString *)tableView:(UITableView *)tableView titleForFooterInSection:(NSInteger)section {
    if (section != 0) return nil;
    if (SRPWWIsHintNode(_node)) {
        return @"An input hint has no settings: SRP puts the input chosen in Settings → WaterWall Input in its place when it connects. Its type says what the chain takes: HintConnectionIN connections, HintPacketIN IP packets.";
    }
    if (_name == nil) {
        return [_node[@"next"] isKindOfClass:NSString.class] ?
            [NSString stringWithFormat:@"The new node goes between \"%@\" and \"%@\".", _previous, _node[@"next"]] :
            [NSString stringWithFormat:@"The new node goes after \"%@\" and ends the chain.", _previous];
    }
    return nil;
}

- (UIView *)tableView:(UITableView *)tableView viewForFooterInSection:(NSInteger)section {
    if (section != 1) return nil;
    UIView *footer = [UIView new];
    [footer addSubview:_statusLabel];
    [NSLayoutConstraint activateConstraints:@[
        [_statusLabel.leadingAnchor constraintEqualToAnchor:footer.layoutMarginsGuide.leadingAnchor],
        [_statusLabel.trailingAnchor constraintEqualToAnchor:footer.layoutMarginsGuide.trailingAnchor],
        [_statusLabel.topAnchor constraintEqualToAnchor:footer.topAnchor constant:6],
        [_statusLabel.bottomAnchor constraintEqualToAnchor:footer.bottomAnchor constant:-6],
    ]];
    return footer;
}

- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath {
    UITableViewCell *cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleValue1 reuseIdentifier:nil];
    cell.selectionStyle = UITableViewCellSelectionStyleNone;
    if (indexPath.section == 1) {
        [cell.contentView addSubview:_settingsView];
        [NSLayoutConstraint activateConstraints:@[
            [_settingsView.leadingAnchor constraintEqualToAnchor:cell.contentView.leadingAnchor constant:12],
            [_settingsView.trailingAnchor constraintEqualToAnchor:cell.contentView.trailingAnchor constant:-12],
            [_settingsView.topAnchor constraintEqualToAnchor:cell.contentView.topAnchor constant:4],
            [_settingsView.bottomAnchor constraintEqualToAnchor:cell.contentView.bottomAnchor constant:-4],
            [_settingsView.heightAnchor constraintGreaterThanOrEqualToConstant:220],
        ]];
        return cell;
    }
    if (indexPath.row == 2) {
        cell.textLabel.text = @"Next";
        cell.detailTextLabel.text = _node[@"next"];
        cell.detailTextLabel.font = [[UIFontMetrics metricsForTextStyle:UIFontTextStyleBody]
                                     scaledFontForFont:[UIFont monospacedSystemFontOfSize:17 weight:UIFontWeightRegular]];
        cell.detailTextLabel.textColor = UIColor.labelColor;
        return cell;
    }
    UILabel *label = [UILabel new];
    label.text = indexPath.row == 0 ? @"Name" : @"Type";
    label.font = [UIFont preferredFontForTextStyle:UIFontTextStyleBody];
    label.adjustsFontForContentSizeCategory = YES;
    [label setContentHuggingPriority:UILayoutPriorityRequired forAxis:UILayoutConstraintAxisHorizontal];
    UITextField *field = indexPath.row == 0 ? _nameField : _typeField;
    UIStackView *row = [[UIStackView alloc] initWithArrangedSubviews:@[label, field]];
    row.translatesAutoresizingMaskIntoConstraints = NO;
    row.spacing = 16;
    [label.widthAnchor constraintEqualToConstant:72].active = YES;
    [cell.contentView addSubview:row];
    [NSLayoutConstraint activateConstraints:@[
        [row.leadingAnchor constraintEqualToAnchor:cell.contentView.layoutMarginsGuide.leadingAnchor],
        [row.trailingAnchor constraintEqualToAnchor:cell.contentView.layoutMarginsGuide.trailingAnchor],
        [row.topAnchor constraintEqualToAnchor:cell.contentView.layoutMarginsGuide.topAnchor],
        [row.bottomAnchor constraintEqualToAnchor:cell.contentView.layoutMarginsGuide.bottomAnchor],
        [row.heightAnchor constraintGreaterThanOrEqualToConstant:30],
    ]];
    return cell;
}

- (void)textViewDidChange:(UITextView *)textView {
    NSString *message = nil;
    NSDictionary *settings = SRPWWSettingsWithText(textView.text, &message);
    _statusLabel.text = settings != nil ? @"Valid JSON" : message;
    _statusLabel.textColor = settings != nil ? UIColor.secondaryLabelColor : UIColor.systemRedColor;
    SRPWWHighlight(textView);
}

- (BOOL)textView:(UITextView *)textView shouldChangeTextInRange:(NSRange)range replacementText:(NSString *)text {
    if (![text isEqualToString:@"\n"]) return YES;
    NSString *newline = SRPWWNewline(textView.text, range.location);
    if (newline.length == 1) return YES;
    [textView insertText:newline];
    return NO;
}

- (void)save {
    [self.view endEditing:YES];
    NSMutableDictionary *node = [_node mutableCopy];
    node[@"name"] = [_nameField.text stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
    node[@"type"] = [_typeField.text stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
    if (_settingsView != nil) {
        NSString *message = nil;
        NSDictionary *settings = SRPWWSettingsWithText(_settingsView.text, &message);
        if (settings == nil) {
            SRPWWAlert(self, @"Invalid Node Settings", message);
            return;
        }
        // A node the file wrote without settings keeps it so when none were added
        if (settings.count == 0 && _node[@"settings"] == nil) [node removeObjectForKey:@"settings"];
        else node[@"settings"] = settings;
    }
    NSDictionary *document = SRPWWDocument(_model);
    document = _name != nil ? [SRPWaterWallNodeChain document:document replacingNodeNamed:_name withNode:node] :
                              [SRPWaterWallNodeChain document:document insertingNode:node afterNodeNamed:_previous];
    NSString *problem = [SRPWaterWallNodeChain validationErrorForDocument:document];
    if (problem != nil) {
        SRPWWAlert(self, @"Invalid Node", problem);
        return;
    }
    SRPWWKeep(_model, document);
    [self.navigationController popViewControllerAnimated:YES];
}

@end

#pragma mark - Import JSON

@interface SRPWaterWallImportViewController : UITableViewController <UIDocumentPickerDelegate>

- (instancetype)initWithModel:(NodeModel *)model;
/// Reads and checks a chosen file (the document picker's copy)
- (void)loadFileAtURL:(NSURL *)url;

@end

@implementation SRPWaterWallImportViewController {
    NodeModel *_model;
    NSString *_fileName;
    NSDictionary *_document;
    NSString *_problem;
    UIButton *_importButton;
}

- (instancetype)initWithModel:(NodeModel *)model {
    self = [super initWithStyle:UITableViewStyleInsetGrouped];
    if (self) _model = model;
    return self;
}

- (void)viewDidLoad {
    [super viewDidLoad];
    self.tableView.tableHeaderView = SRPWWTitleView(@"Import JSON", nil);
    UIButtonConfiguration *configuration = [UIButtonConfiguration filledButtonConfiguration];
    configuration.title = @"Import";
    configuration.buttonSize = UIButtonConfigurationSizeLarge;
    configuration.cornerStyle = UIButtonConfigurationCornerStyleLarge;
    _importButton = [UIButton buttonWithConfiguration:configuration primaryAction:nil];
    _importButton.translatesAutoresizingMaskIntoConstraints = NO;
    _importButton.enabled = NO;
    [_importButton addTarget:self action:@selector(import) forControlEvents:UIControlEventTouchUpInside];
    UIView *footer = [[UIView alloc] initWithFrame:CGRectMake(0, 0, 320, 96)];
    [footer addSubview:_importButton];
    [NSLayoutConstraint activateConstraints:@[
        [_importButton.leadingAnchor constraintEqualToAnchor:footer.layoutMarginsGuide.leadingAnchor],
        [_importButton.trailingAnchor constraintEqualToAnchor:footer.layoutMarginsGuide.trailingAnchor],
        [_importButton.topAnchor constraintEqualToAnchor:footer.topAnchor constant:24],
        [_importButton.heightAnchor constraintGreaterThanOrEqualToConstant:50],
    ]];
    self.tableView.tableFooterView = footer;
}

- (void)viewDidLayoutSubviews {
    [super viewDidLayoutSubviews];
    SRPWWFitHeader(self.tableView);
}

- (NSInteger)numberOfSectionsInTableView:(UITableView *)tableView {
    return _problem != nil ? 3 : 2;
}

- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section {
    return section == 1 ? 3 : 1;
}

- (NSString *)tableView:(UITableView *)tableView titleForHeaderInSection:(NSInteger)section {
    return section == 1 ? @"IMPORT RULES" : nil;
}

- (NSString *)tableView:(UITableView *)tableView titleForFooterInSection:(NSInteger)section {
    if (section == 0 && _document != nil) {
        return [NSString stringWithFormat:@"%@: %lu nodes on the chain. Import replaces the profile's chain.",
                [SRPWaterWallNodeChain summaryOfDocument:_document], (unsigned long)[SRPWaterWallNodeChain chainOfDocument:_document].count];
    }
    return nil;
}

- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath {
    UITableViewCell *cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleSubtitle reuseIdentifier:nil];
    cell.selectionStyle = UITableViewCellSelectionStyleNone;
    cell.textLabel.numberOfLines = 0;
    cell.detailTextLabel.numberOfLines = 0;
    if (indexPath.section == 0) {
        cell.imageView.image = [UIImage systemImageNamed:@"doc"];
        cell.textLabel.text = _fileName ?: @"No file chosen";
        cell.textLabel.textColor = _fileName ? UIColor.labelColor : UIColor.secondaryLabelColor;
        UIButton *choose = [UIButton buttonWithType:UIButtonTypeSystem];
        [choose setTitle:@"Choose File" forState:UIControlStateNormal];
        choose.titleLabel.font = [UIFont preferredFontForTextStyle:UIFontTextStyleBody];
        [choose addTarget:self action:@selector(choose) forControlEvents:UIControlEventTouchUpInside];
        [choose sizeToFit];
        cell.accessoryView = choose;
        return cell;
    }
    if (indexPath.section == 2) {
        cell.backgroundColor = [UIColor.systemRedColor colorWithAlphaComponent:0.12];
        cell.imageView.image = [UIImage systemImageNamed:@"exclamationmark.circle"
                                       withConfiguration:[UIImageSymbolConfiguration configurationWithTextStyle:UIFontTextStyleTitle2]];
        cell.imageView.tintColor = UIColor.systemRedColor;
        cell.textLabel.text = @"Import blocked";
        cell.textLabel.font = [UIFont preferredFontForTextStyle:UIFontTextStyleHeadline];
        cell.textLabel.textColor = UIColor.systemRedColor;
        cell.detailTextLabel.text = _problem;
        cell.detailTextLabel.textColor = UIColor.systemRedColor;
        return cell;
    }
    NSArray<NSArray<NSString *> *> *rules = @[
        @[@"Input hint", @"Start with HintConnectionIN or HintPacketIN."],
        @[@"App-managed input", @"Leave TunDevice and PacketsToConnection out of the file."],
        @[@"Raw sockets", @"Raw socket nodes cannot be imported."],
    ];
    cell.textLabel.text = rules[indexPath.row][0];
    cell.textLabel.font = [UIFont preferredFontForTextStyle:UIFontTextStyleHeadline];
    cell.detailTextLabel.text = rules[indexPath.row][1];
    cell.detailTextLabel.textColor = UIColor.secondaryLabelColor;
    return cell;
}

- (void)choose {
    UIDocumentPickerViewController *picker = [[UIDocumentPickerViewController alloc] initForOpeningContentTypes:@[UTTypeJSON, UTTypePlainText]
                                                                                                         asCopy:YES];
    picker.delegate = self;
    picker.allowsMultipleSelection = NO;
    [self presentViewController:picker animated:YES completion:nil];
}

- (void)documentPicker:(UIDocumentPickerViewController *)controller didPickDocumentsAtURLs:(NSArray<NSURL *> *)urls {
    if (urls.firstObject != nil) [self loadFileAtURL:urls.firstObject];
}

- (void)loadFileAtURL:(NSURL *)url {
    _fileName = url.lastPathComponent;
    _document = nil;
    _problem = nil;
    NSNumber *size = nil;
    [url getResourceValue:&size forKey:NSURLFileSizeKey error:nil];
    NSData *data = size.longLongValue <= 1048576 ? [NSData dataWithContentsOfURL:url] : nil;
    NSString *json = data ? [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding] : nil;
    NSString *problem = size.longLongValue > 1048576 ? @"The file is larger than 1 MB." :
                        data == nil ? @"The file could not be read." : json == nil ? @"The file is not UTF-8 text." : nil;
    // An invalid file leaves the profile as it is: nothing of it is imported
    if (problem == nil) _document = [SRPWaterWallNodeChain documentWithJSON:json error:&problem];
    _problem = _document == nil ? problem : nil;
    _importButton.enabled = _document != nil;
    [self.tableView reloadData];
    if (_problem != nil) UIAccessibilityPostNotification(UIAccessibilityAnnouncementNotification, [@"Import blocked. " stringByAppendingString:_problem]);
}

- (void)import {
    if (_document == nil) return;
    SRPWWKeep(_model, _document);
    [self.navigationController popViewControllerAnimated:YES];
}

@end

#pragma mark - The chain

@implementation SRPWaterWallConfigViewController {
    NodeModel *_model;
    NSString *_expanded;   // the node whose next and actions show
}

- (instancetype)initWithNodeModel:(NodeModel *)model {
    self = [super initWithStyle:UITableViewStyleInsetGrouped];
    if (self) _model = model;
    return self;
}

- (void)viewDidLoad {
    [super viewDidLoad];
    self.navigationItem.backButtonTitle = @"WaterWall";
    UIBarButtonItem *import = [[UIBarButtonItem alloc] initWithImage:[UIImage systemImageNamed:@"arrow.down.doc"]
                                                               style:UIBarButtonItemStylePlain target:self action:@selector(showImport)];
    import.accessibilityLabel = @"Import JSON";
    self.navigationItem.rightBarButtonItem = import;
    self.tableView.tableHeaderView = SRPWWTitleView(@"WaterWall", nil);
}

- (void)viewWillAppear:(BOOL)animated {
    [super viewWillAppear:animated];
    [self.tableView reloadData];
}

- (void)viewDidLayoutSubviews {
    [super viewDidLayoutSubviews];
    SRPWWFitHeader(self.tableView);
}

- (void)showImport {
    [self.navigationController pushViewController:[[SRPWaterWallImportViewController alloc] initWithModel:_model] animated:YES];
}

// One row per node from the hint along next; the expanded node adds its next and its actions
- (NSArray<NSDictionary *> *)rows {
    NSDictionary *document = SRPWWDocument(_model);
    NSArray<NSDictionary *> *chain = [SRPWaterWallNodeChain chainOfDocument:document];
    NSMutableArray *rows = [NSMutableArray new];
    [chain enumerateObjectsUsingBlock:^(NSDictionary *node, NSUInteger index, BOOL *stop) {
        [rows addObject:@{@"kind": @"node", @"node": node, @"number": @(index + 1), @"end": @(index + 1 == chain.count)}];
        if (![node[@"name"] isEqual:self->_expanded]) return;
        if ([node[@"next"] isKindOfClass:NSString.class]) [rows addObject:@{@"kind": @"next", @"node": node}];
        [rows addObject:@{@"kind": @"edit", @"node": node}];
        [rows addObject:@{@"kind": @"insert", @"node": node}];
        if (!SRPWWIsHintNode(node)) [rows addObject:@{@"kind": @"delete", @"node": node}];
    }];
    return rows;
}

- (NSInteger)numberOfSectionsInTableView:(UITableView *)tableView {
    return 2;
}

- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section {
    return section == 0 ? [self rows].count : 1;
}

- (NSString *)tableView:(UITableView *)tableView titleForHeaderInSection:(NSInteger)section {
    return section == 0 ? @"NODE CHAIN" : nil;
}

- (NSString *)tableView:(UITableView *)tableView titleForFooterInSection:(NSInteger)section {
    if (section != 0) return nil;
    NSDictionary *document = SRPWWDocument(_model);
    NSUInteger all = [document[@"nodes"] isKindOfClass:NSArray.class] ? [document[@"nodes"] count] : 0;
    NSUInteger chain = [SRPWaterWallNodeChain chainOfDocument:document].count;
    if (all <= chain) return @"Order follows each node's next field.";
    NSUInteger others = all - chain;
    return [NSString stringWithFormat:@"Order follows each node's next field. The profile has %lu more %@ off the chain, such as a Router's targets, which %@ kept as %@.",
            (unsigned long)others, others == 1 ? @"node" : @"nodes", others == 1 ? @"is" : @"are", others == 1 ? @"it is" : @"they are"];
}

- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath {
    if (indexPath.section == 1) {
        UITableViewCell *cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleDefault reuseIdentifier:nil];
        cell.imageView.image = [UIImage systemImageNamed:@"doc"];
        cell.textLabel.text = @"Import JSON…";
        cell.textLabel.textColor = self.view.tintColor;
        cell.accessibilityTraits |= UIAccessibilityTraitButton;
        return cell;
    }
    NSDictionary *row = [self rows][indexPath.row];
    NSDictionary *node = row[@"node"];
    NSString *kind = row[@"kind"];
    if ([kind isEqualToString:@"node"]) {
        UITableViewCell *cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleSubtitle reuseIdentifier:nil];
        NSInteger number = [row[@"number"] integerValue];
        UIImageSymbolConfiguration *symbol = [UIImageSymbolConfiguration configurationWithTextStyle:UIFontTextStyleTitle2];
        cell.imageView.image = [UIImage systemImageNamed:number <= 50 ? [NSString stringWithFormat:@"%ld.circle", (long)number] : @"circle"
                                       withConfiguration:symbol];
        cell.imageView.tintColor = UIColor.secondaryLabelColor;
        cell.textLabel.text = [node[@"type"] isKindOfClass:NSString.class] ? node[@"type"] : @"";
        cell.textLabel.font = [UIFont preferredFontForTextStyle:UIFontTextStyleHeadline];
        cell.detailTextLabel.text = node[@"name"];
        cell.detailTextLabel.textColor = UIColor.secondaryLabelColor;
        BOOL expanded = [node[@"name"] isEqual:_expanded];
        BOOL end = [row[@"end"] boolValue];
        UIImageView *chevron = [[UIImageView alloc] initWithImage:[UIImage systemImageNamed:expanded ? @"chevron.down" : @"chevron.right"]];
        chevron.tintColor = UIColor.tertiaryLabelColor;
        UIStackView *accessory = [[UIStackView alloc] initWithArrangedSubviews:@[chevron]];
        accessory.alignment = UIStackViewAlignmentCenter;
        accessory.spacing = 12;
        if (end) {
            UILabel *label = [UILabel new];
            label.text = @"End";
            label.font = [UIFont preferredFontForTextStyle:UIFontTextStyleBody];
            label.textColor = UIColor.secondaryLabelColor;
            [accessory insertArrangedSubview:label atIndex:0];
        }
        CGSize size = [accessory systemLayoutSizeFittingSize:UILayoutFittingCompressedSize];
        accessory.frame = CGRectMake(0, 0, size.width, MAX(size.height, 30));
        cell.accessoryView = accessory;
        cell.accessibilityLabel = [NSString stringWithFormat:@"%ld, %@, %@%@", (long)number, cell.textLabel.text, node[@"name"], end ? @", End" : @""];
        cell.accessibilityHint = expanded ? @"Hides the node's actions" : @"Shows the node's next and actions";
        return cell;
    }
    if ([kind isEqualToString:@"next"]) {
        UITableViewCell *cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleValue1 reuseIdentifier:nil];
        cell.textLabel.text = @"next";
        cell.detailTextLabel.text = node[@"next"];
        cell.detailTextLabel.font = [[UIFontMetrics metricsForTextStyle:UIFontTextStyleBody]
                                     scaledFontForFont:[UIFont monospacedSystemFontOfSize:17 weight:UIFontWeightRegular]];
        cell.detailTextLabel.textColor = UIColor.labelColor;
        cell.selectionStyle = UITableViewCellSelectionStyleNone;
        return cell;
    }
    UITableViewCell *cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleDefault reuseIdentifier:nil];
    BOOL delete = [kind isEqualToString:@"delete"];
    BOOL edit = [kind isEqualToString:@"edit"];
    cell.imageView.image = [UIImage systemImageNamed:delete ? @"trash" : edit ? @"pencil" : @"plus"];
    cell.textLabel.text = delete ? @"Delete node" : edit ? @"Edit node" : @"Insert node after";
    UIColor *color = delete ? UIColor.systemRedColor : self.view.tintColor;
    cell.imageView.tintColor = color;
    cell.textLabel.textColor = color;
    cell.accessibilityTraits |= UIAccessibilityTraitButton;
    return cell;
}

- (void)tableView:(UITableView *)tableView didSelectRowAtIndexPath:(NSIndexPath *)indexPath {
    [tableView deselectRowAtIndexPath:indexPath animated:YES];
    if (indexPath.section == 1) {
        [self showImport];
        return;
    }
    NSDictionary *row = [self rows][indexPath.row];
    NSString *kind = row[@"kind"];
    NSString *name = row[@"node"][@"name"];
    if ([kind isEqualToString:@"node"]) {
        _expanded = [name isEqual:_expanded] ? nil : name;
        [tableView reloadSections:[NSIndexSet indexSetWithIndex:0] withRowAnimation:UITableViewRowAnimationAutomatic];
    } else if ([kind isEqualToString:@"edit"] || [kind isEqualToString:@"insert"]) {
        BOOL edit = [kind isEqualToString:@"edit"];
        SRPWaterWallNodeViewController *controller = [[SRPWaterWallNodeViewController alloc] initWithModel:_model
                                                                                                  nodeName:edit ? name : nil
                                                                                            insertingAfter:edit ? nil : name];
        [self.navigationController pushViewController:controller animated:YES];
    } else if ([kind isEqualToString:@"delete"]) {
        NSDictionary *document = [SRPWaterWallNodeChain document:SRPWWDocument(_model) deletingNodeNamed:name];
        NSString *problem = [SRPWaterWallNodeChain validationErrorForDocument:document];
        if (problem != nil) {
            SRPWWAlert(self, @"Node Not Deleted", problem);
            return;
        }
        SRPWWKeep(_model, document);
        _expanded = nil;
        [tableView reloadSections:[NSIndexSet indexSetWithIndex:0] withRowAnimation:UITableViewRowAnimationAutomatic];
    }
}

@end

#pragma mark - Settings → WaterWall Input

@interface SRPWaterWallInputViewController : UITableViewController
@end

static NSArray<NSArray<NSString *> *> *SRPWWInputs(void) {
    return @[@[SRPWaterWallInputTUN, @"System VPN (TUN)"], @[SRPWaterWallInputSOCKS5, @"Local SOCKS5 proxy"],
             @[SRPWaterWallInputHTTP, @"Local HTTP proxy"]];
}

static NSString *SRPWWInputTitle(NSString *input) {
    for (NSArray<NSString *> *choice in SRPWWInputs()) {
        if ([choice[0] isEqualToString:input]) return choice[1];
    }
    return SRPWWInputs()[0][1];
}

@implementation SRPWaterWallInputViewController

- (instancetype)init {
    return [super initWithStyle:UITableViewStyleInsetGrouped];
}

- (void)viewDidLoad {
    [super viewDidLoad];
    self.tableView.tableHeaderView = SRPWWTitleView(@"WaterWall Input", nil);
}

- (void)viewDidLayoutSubviews {
    [super viewDidLayoutSubviews];
    SRPWWFitHeader(self.tableView);
}

- (NSInteger)numberOfSectionsInTableView:(UITableView *)tableView {
    return 2;
}

- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section {
    return section == 0 ? SRPWWInputs().count : 2;
}

- (NSString *)tableView:(UITableView *)tableView titleForHeaderInSection:(NSInteger)section {
    if (section == 0) return @"INPUT FOR ALL PROFILES";
    NSString *input = SRPWaterWallNodeChain.currentInput;
    return [input isEqualToString:SRPWaterWallInputSOCKS5] ? @"LOCAL SOCKS5 INPUT" :
           [input isEqualToString:SRPWaterWallInputHTTP] ? @"LOCAL HTTP INPUT" : @"SYSTEM VPN INPUT";
}

- (NSString *)tableView:(UITableView *)tableView titleForFooterInSection:(NSInteger)section {
    if (section == 0) return @"Every WaterWall profile uses this input. A change applies the next time a profile connects.";
    NSString *input = SRPWaterWallNodeChain.currentInput;
    if ([input isEqualToString:SRPWaterWallInputTUN]) return @"SRP adds these nodes when it builds the runtime configuration.";
    return [NSString stringWithFormat:@"SRP adds these nodes when it builds the runtime configuration. Apps on this device that you set to use the proxy at 127.0.0.1:%ld go through WaterWall; the VPN carries no other traffic.",
            (long)[SRPWaterWallNodeChain portForInput:input]];
}

- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath {
    NSString *input = SRPWaterWallNodeChain.currentInput;
    if (indexPath.section == 0) {
        UITableViewCell *cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleDefault reuseIdentifier:nil];
        NSArray<NSString *> *choice = SRPWWInputs()[indexPath.row];
        cell.textLabel.text = choice[1];
        cell.accessoryType = [choice[0] isEqualToString:input] ? UITableViewCellAccessoryCheckmark : UITableViewCellAccessoryNone;
        return cell;
    }
    UITableViewCell *cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleSubtitle reuseIdentifier:nil];
    cell.selectionStyle = UITableViewCellSelectionStyleNone;
    cell.textLabel.font = [UIFont preferredFontForTextStyle:UIFontTextStyleHeadline];
    cell.detailTextLabel.textColor = UIColor.secondaryLabelColor;
    cell.detailTextLabel.numberOfLines = 0;
    BOOL packets = indexPath.row == 0;
    cell.textLabel.text = packets ? SRPWaterWallHintPacket : SRPWaterWallHintConnection;
    if ([input isEqualToString:SRPWaterWallInputTUN]) {
        cell.detailTextLabel.text = packets ? @"TunDevice" : @"TunDevice → PacketsToConnection";
    } else if (packets) {
        cell.detailTextLabel.text = @"Not available: a profile that takes IP packets needs System VPN (TUN).";
    } else {
        BOOL socks = [input isEqualToString:SRPWaterWallInputSOCKS5];
        cell.detailTextLabel.text = [NSString stringWithFormat:@"%@ 127.0.0.1:%ld → %@", socks ? @"TcpUdpListener" : @"TcpListener",
                                     (long)[SRPWaterWallNodeChain portForInput:input], socks ? @"Socks5Server" : @"HttpProxyServer"];
    }
    return cell;
}

- (void)tableView:(UITableView *)tableView didSelectRowAtIndexPath:(NSIndexPath *)indexPath {
    [tableView deselectRowAtIndexPath:indexPath animated:YES];
    if (indexPath.section != 0) return;
    SRPWaterWallNodeChain.currentInput = SRPWWInputs()[indexPath.row][0];
    [tableView reloadData];
}

@end

#pragma mark - Settings

static NSString *const SRPGeoIPUpdateURLKey = @"SRPGeoIPUpdateURL";

@interface SRPSettingsViewController () <UIDocumentPickerDelegate, UITextFieldDelegate>
@end

@implementation SRPSettingsViewController {
    UITextField *_geoIPURLField;
    BOOL _geoIPBusy;
}

- (instancetype)init {
    return [super initWithStyle:UITableViewStyleInsetGrouped];
}

- (void)viewDidLoad {
    [super viewDidLoad];
    self.title = @"Settings";
    if (self.navigationController.viewControllers.firstObject == self) {
        self.navigationItem.leftBarButtonItem = [[UIBarButtonItem alloc] initWithBarButtonSystemItem:UIBarButtonSystemItemDone
                                                                                              target:self action:@selector(done)];
    }
}

- (void)viewWillAppear:(BOOL)animated {
    [super viewWillAppear:animated];
    [self.tableView reloadData];
}

- (void)done {
    [self.view endEditing:YES];
    [self dismissViewControllerAnimated:YES completion:nil];
}

- (NSInteger)numberOfSectionsInTableView:(UITableView *)tableView {
    return 2;
}

- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section {
    return section == 0 ? 1 : 4;
}

- (NSString *)tableView:(UITableView *)tableView titleForHeaderInSection:(NSInteger)section {
    return section == 0 ? @"WATERWALL" : @"GEOIP DATABASE";
}

- (NSString *)tableView:(UITableView *)tableView titleForFooterInSection:(NSInteger)section {
    if (section == 0) return @"What SRP puts in place of a WaterWall profile's input hint when it connects, for every profile.";
    return @"WaterWall Routers that route by country (rules with geoip: destinations) use this country database. Download & Replace fetches a GeoIP2 or GeoLite2 Country MMDB file from the HTTPS link; Upload takes one from your files.";
}

- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath {
    UITableViewCell *cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleValue1 reuseIdentifier:nil];
    if (indexPath.section == 0) {
        cell.textLabel.text = @"WaterWall Input";
        cell.detailTextLabel.text = SRPWWInputTitle(SRPWaterWallNodeChain.currentInput);
        cell.accessoryType = UITableViewCellAccessoryDisclosureIndicator;
        return cell;
    }
    if (indexPath.row == 0) {
        cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleSubtitle reuseIdentifier:nil];
        NSDictionary *info = [SRPGeoIPDatabase.sharedDatabase databaseInfo];
        cell.textLabel.text = @"Country Database";
        if (info != nil) {
            NSString *bytes = [NSByteCountFormatter stringFromByteCount:[info[@"bytes"] longLongValue] countStyle:NSByteCountFormatterCountStyleFile];
            cell.detailTextLabel.text = [NSString stringWithFormat:@"%@ · %@ · %@", info[@"type"], info[@"source"], bytes];
        } else {
            cell.detailTextLabel.text = @"No valid database";
        }
        cell.detailTextLabel.numberOfLines = 2;
        cell.detailTextLabel.textColor = UIColor.secondaryLabelColor;
        cell.selectionStyle = UITableViewCellSelectionStyleNone;
        return cell;
    }
    if (indexPath.row == 1) {
        cell.textLabel.text = @"Update URL";
        UITextField *field = [[UITextField alloc] initWithFrame:CGRectMake(0, 0, 210, 36)];
        field.placeholder = @"https://…/GeoLite2-Country.mmdb";
        field.text = [NSUserDefaults.standardUserDefaults stringForKey:SRPGeoIPUpdateURLKey];
        field.keyboardType = UIKeyboardTypeURL;
        field.textContentType = UITextContentTypeURL;
        field.autocorrectionType = UITextAutocorrectionTypeNo;
        field.autocapitalizationType = UITextAutocapitalizationTypeNone;
        field.clearButtonMode = UITextFieldViewModeAlways;
        field.returnKeyType = UIReturnKeyDone;
        field.delegate = self;
        field.enabled = !_geoIPBusy;
        field.accessibilityLabel = @"Update URL";
        cell.accessoryView = field;
        cell.selectionStyle = UITableViewCellSelectionStyleNone;
        _geoIPURLField = field;
        return cell;
    }
    BOOL download = indexPath.row == 2;
    cell.textLabel.text = download ? @"Download & Replace" : @"Upload MMDB…";
    cell.detailTextLabel.text = _geoIPBusy ? @"Validating…" : nil;
    cell.textLabel.textColor = _geoIPBusy ? UIColor.secondaryLabelColor : self.view.tintColor;
    cell.userInteractionEnabled = !_geoIPBusy;
    return cell;
}

- (void)textFieldDidEndEditing:(UITextField *)textField {
    NSString *url = [textField.text stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
    textField.text = url;
    if (url.length > 0) [NSUserDefaults.standardUserDefaults setObject:url forKey:SRPGeoIPUpdateURLKey];
    else [NSUserDefaults.standardUserDefaults removeObjectForKey:SRPGeoIPUpdateURLKey];
}

- (BOOL)textFieldShouldReturn:(UITextField *)textField {
    [textField resignFirstResponder];
    return YES;
}

- (void)finishGeoIPUpdate:(NSError *)error {
    _geoIPBusy = NO;
    [self.tableView reloadData];
    SRPWWAlert(self, @"GeoIP", error != nil ? error.localizedDescription :
               @"The country database was validated and installed. Reconnect WaterWall to use the new file.");
}

- (void)tableView:(UITableView *)tableView didSelectRowAtIndexPath:(NSIndexPath *)indexPath {
    [tableView deselectRowAtIndexPath:indexPath animated:YES];
    if (indexPath.section == 0) {
        [self.navigationController pushViewController:[SRPWaterWallInputViewController new] animated:YES];
        return;
    }
    if (indexPath.row == 2) {
        [self.view endEditing:YES];
        NSString *url = [NSUserDefaults.standardUserDefaults stringForKey:SRPGeoIPUpdateURLKey];
        if (url.length == 0) {
            SRPWWAlert(self, @"GeoIP", @"Enter the HTTPS link to a GeoIP2 or GeoLite2 Country MMDB file first.");
            return;
        }
        _geoIPBusy = YES;
        [tableView reloadData];
        [SRPGeoIPDatabase.sharedDatabase downloadDatabaseFromURLString:url completion:^(NSError *error) {
            dispatch_async(dispatch_get_main_queue(), ^{ [self finishGeoIPUpdate:error]; });
        }];
    } else if (indexPath.row == 3) {
        UIDocumentPickerViewController *picker = [[UIDocumentPickerViewController alloc] initForOpeningContentTypes:@[UTTypeData] asCopy:YES];
        picker.delegate = self;
        picker.allowsMultipleSelection = NO;
        [self presentViewController:picker animated:YES completion:nil];
    }
}

- (void)documentPicker:(UIDocumentPickerViewController *)controller didPickDocumentsAtURLs:(NSArray<NSURL *> *)urls {
    NSURL *url = urls.firstObject;
    if (url == nil) return;
    _geoIPBusy = YES;
    [self.tableView reloadData];
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        NSError *error = nil;
        [SRPGeoIPDatabase.sharedDatabase installDatabaseAtURL:url error:&error];
        dispatch_async(dispatch_get_main_queue(), ^{ [self finishGeoIPUpdate:error]; });
    });
}

@end
