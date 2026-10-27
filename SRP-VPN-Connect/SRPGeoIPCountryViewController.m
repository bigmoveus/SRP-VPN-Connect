#import "SRPGeoIPCountryViewController.h"

@interface SRPGeoIPCountryViewController () <UISearchResultsUpdating>
@end

@implementation SRPGeoIPCountryViewController {
    NSArray<NSDictionary<NSString *, NSString *> *> *_countries;
    NSArray<NSDictionary<NSString *, NSString *> *> *_visibleCountries;
    NSMutableSet<NSString *> *_selectedCodes;
    void (^_completion)(NSSet<NSString *> *selectedCodes);
    UISearchController *_searchController;
}

- (instancetype)initWithSelectedCodes:(NSSet<NSString *> *)selectedCodes
                           completion:(void (^)(NSSet<NSString *> *selectedCodes))completion {
    self = [super initWithStyle:UITableViewStyleGrouped];
    if (self) {
        self.title = @"GeoIP Countries";
        _selectedCodes = [selectedCodes mutableCopy] ?: [NSMutableSet new];
        _completion = [completion copy];
        NSLocale *locale = [NSLocale localeWithLocaleIdentifier:@"en_US"];
        NSMutableArray<NSDictionary<NSString *, NSString *> *> *countries = [NSMutableArray new];
        for (NSString *code in NSLocale.ISOCountryCodes) {
            NSString *name = [locale displayNameForKey:NSLocaleCountryCode value:code];
            if (name.length == 0) continue;
            [countries addObject:@{@"code": code, @"name": name}];
        }
        _countries = [countries sortedArrayUsingComparator:^NSComparisonResult(NSDictionary *left, NSDictionary *right) {
            return [left[@"name"] localizedCaseInsensitiveCompare:right[@"name"]];
        }];
        _visibleCountries = _countries;
    }
    return self;
}

- (void)viewDidLoad {
    [super viewDidLoad];
    self.view.backgroundColor = UIColor.systemBackgroundColor;
    self.navigationItem.rightBarButtonItem = [[UIBarButtonItem alloc] initWithBarButtonSystemItem:UIBarButtonSystemItemDone
                                                                                          target:self
                                                                                          action:@selector(done)];
    _searchController = [[UISearchController alloc] initWithSearchResultsController:nil];
    _searchController.searchResultsUpdater = self;
    _searchController.obscuresBackgroundDuringPresentation = NO;
    _searchController.searchBar.placeholder = @"Country or ISO code";
    self.navigationItem.searchController = _searchController;
    self.navigationItem.hidesSearchBarWhenScrolling = NO;
    self.definesPresentationContext = YES;
}

- (void)done {
    [self.navigationController popViewControllerAnimated:YES];
}

- (void)updateSearchResultsForSearchController:(UISearchController *)searchController {
    NSString *query = [searchController.searchBar.text stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
    if (query.length == 0) {
        _visibleCountries = _countries;
    } else {
        NSMutableArray<NSDictionary<NSString *, NSString *> *> *filtered = [NSMutableArray new];
        for (NSDictionary<NSString *, NSString *> *country in _countries) {
            if ([country[@"name"] rangeOfString:query options:NSCaseInsensitiveSearch].location != NSNotFound ||
                [country[@"code"] rangeOfString:query options:NSCaseInsensitiveSearch].location != NSNotFound) {
                [filtered addObject:country];
            }
        }
        _visibleCountries = filtered;
    }
    [self.tableView reloadData];
}

- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section {
    return _visibleCountries.count;
}

- (NSString *)tableView:(UITableView *)tableView titleForFooterInSection:(NSInteger)section {
    return [NSString stringWithFormat:@"%lu selected. Selected countries use direct routing.",
            (unsigned long)_selectedCodes.count];
}

- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath {
    UITableViewCell *cell = [tableView dequeueReusableCellWithIdentifier:@"CountryCell"];
    if (cell == nil) cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleDefault reuseIdentifier:@"CountryCell"];
    NSDictionary<NSString *, NSString *> *country = _visibleCountries[indexPath.row];
    cell.textLabel.text = [NSString stringWithFormat:@"%@ (%@)", country[@"name"], country[@"code"]];
    cell.textLabel.adjustsFontSizeToFitWidth = YES;
    cell.textLabel.minimumScaleFactor = 0.8;
    cell.accessoryType = [_selectedCodes containsObject:country[@"code"]] ? UITableViewCellAccessoryCheckmark : UITableViewCellAccessoryNone;
    cell.accessibilityIdentifier = [@"WWGeoIPCountry." stringByAppendingString:country[@"code"]];
    return cell;
}

- (void)tableView:(UITableView *)tableView didSelectRowAtIndexPath:(NSIndexPath *)indexPath {
    [tableView deselectRowAtIndexPath:indexPath animated:YES];
    NSString *code = _visibleCountries[indexPath.row][@"code"];
    if ([_selectedCodes containsObject:code]) [_selectedCodes removeObject:code];
    else [_selectedCodes addObject:code];
    _completion([_selectedCodes copy]);
    [self.tableView reloadData];
}

@end
