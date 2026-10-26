
#import "HelpVC.h"
#import "HelpMenu.h"
#import "HelpView.h"

@interface HelpVC ()<UITableViewDelegate,UITableViewDataSource>
@property (nonatomic,strong) UITableView * helpTableview;
@property (nonatomic,strong) HelpMenu * menu;
@property (nonatomic,copy) NSString * contentStr;

@end

@implementation HelpVC

- (void)viewDidLoad {
    [super viewDidLoad];
    
    self.helpTableview = [[UITableView alloc] initWithFrame:CGRectMake(0, 49, self.view.frame.size.width, self.view.frame.size.height-49-100)];
    self.helpTableview.delegate = self;
    self.helpTableview.dataSource = self;
    self.helpTableview.separatorStyle = UITableViewCellSeparatorStyleNone;
    self.helpTableview.backgroundColor = UIColor.clearColor;
    self.helpTableview.keyboardDismissMode =UIScrollViewKeyboardDismissModeOnDrag;
    [self.view addSubview:self.helpTableview];
    
    HelpMenu * menu = [[[NSBundle mainBundle] loadNibNamed:@"HelpMenu" owner:self options:nil] lastObject];
    menu.frame = CGRectMake(0, 0, self.view.frame.size.width, 49);
    self.menu = menu;
    menu.sshBtn.hidden = YES;
    menu.openConnectBtn.hidden = YES;
    [self.view addSubview:menu];

    self.view.backgroundColor = [UIColor colorWithRed:242.0/255.0 green:242.0/255.0 blue:247.0/255.0 alpha:1];

    [self onSstpBtn];
    // Do any additional setup after loading the view.
}

-(void)onSstpBtn {
    self.contentStr = @"Any VPN connection requires a client and a server. Both the client and server must “agree” on the protocol and support the connection. Traditional Point-to-Point Tunneling Protocol (PPTP) connections do not use SSL/TLS, so SSTP was introduced to improve the security of data transfers and to avoid limitations set up by firewalls that block specific ports. Unlike PPTP, SSTP uses SSL/TLS, secure key negotiations, and encrypted transfers.\n\
    \n\
    SSTP is used for secure connections, and the technology behind it leverages SSL/TLS handshakes. It uses the same port as SSL/TLS (port 443), and it bases the connection on user authentication instead of a device. It’s popular with internet connections that must have improved security over basic SSL/TLS connections. It’s often compared to the OpenVPN standard, which is considered the gold standard in encryption libraries.;\n\
    Windows Vista introduced the SSTP standard, and it persists as a trusted secure protocol in Windows 7, 8, and 10. If you use the Windows operating system, its native libraries make it convenient to use and secure against eavesdropping and other side-attacks. It’s a chosen resource by many organizations that rely on encrypted communication between two locations.\n\
\n\
    While SSL/TLS is a part of the SSTP protocol suite, you still must consider the cryptographic library and version used to encrypt data. SSTP uses the AES (Advanced Encryption Standard) encryption cipher, making it a safe option. It uses 256-bit encryption with the AES encryption cipher, which is currently considered cryptographically secure. Even though AES-256 encryption can be slow, SSTP is still considered a fast protocol for tunneled and encrypted communications.";
    [self.helpTableview reloadData];

}

-(NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section {
    return 1;
}

-(UITableViewCell*)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath {
    static NSString * strID = @"HelpView";
    HelpView * help = [tableView dequeueReusableCellWithIdentifier:strID];
    if(!help) {
        help = [[[NSBundle mainBundle] loadNibNamed:@"HelpView" owner:self options:nil] lastObject];
    }
    help.contentString.text = self.contentStr;
    help.selectionStyle = UITableViewCellSelectionStyleNone;
    return help;
}

/*
#pragma mark - Navigation

// In a storyboard-based application, you will often want to do a little preparation before navigation
- (void)prepareForSegue:(UIStoryboardSegue *)segue sender:(id)sender {
    // Get the new view controller using [segue destinationViewController].
    // Pass the selected object to the new view controller.
}
*/

@end
