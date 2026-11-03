//
//  main.m — SSH tunnel full-stack throughput test (macOS, needs sudo)
//
//  Runs the engine on a REAL utun (no socketpair bridge), routes a test
//  prefix through it, and lets you curl/ping through the SSH tunnel.
//
//  Usage: sudo ./sshspeed <user> <pass> <host> [port]
//  Then in another shell: route add -net 5.5.5.5/32 -interface utunX
//  or set the route for the target you test.
//

#import <Foundation/Foundation.h>
#import <NetworkExtension/NetworkExtension.h>
#import <arpa/inet.h>

#import "SRPSSHClient.h"

int main(int argc, const char *argv[]) {
    @autoreleasepool {
        if (argc < 4) {
            NSLog(@"usage: sudo sshspeed <user> <pass> <host> [port]");
            return 2;
        }
        SRPSSHClient *c = [SRPSSHClient new];
        c.host = @(argv[3]);
        c.port = argc > 4 ? atoi(argv[4]) : 22;
        c.username = @(argv[1]);
        c.password = @(argv[2]);
        c.udpEnabled = YES;
        c.useRealTun = YES;
        c.logLevel = 1;

        [c startWithOutputCallback:^(NSData *pkt, int family) {}
             networkSettingsCallback:^(NEPacketTunnelNetworkSettings *s) {}
               connectedCallback:^{ NSLog(@"[speed] READY"); }
            disconnectedCallback:^{ NSLog(@"[speed] disconnected"); }
                 failureCallback:^(NSString *r) { NSLog(@"[speed] FAILED: %@", r); }];

        [[NSRunLoop currentRunLoop] run];
        return 0;
    }
}
