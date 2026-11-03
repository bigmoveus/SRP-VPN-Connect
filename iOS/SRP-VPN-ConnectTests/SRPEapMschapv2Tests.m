//
//  SRPEapMschapv2Tests.m
//  SRP-VPN-ConnectTests / SRP-VPN-ConnectTestsMac
//
//  Phase 4: EAP-MSCHAPv2 crypto verified against RFC 2759 section 9.2
//  test vectors, exercised through the real lwIP chap_ms.c helpers used
//  by the EAP-MSCHAPv2 client in eap.c.
//

#import <XCTest/XCTest.h>
#import "SSAuthCapabilities.h"

/* lwIP ppp helper prototypes (chap_ms.c) */
void chapms2_eap_nt_response(const unsigned char *auth_challenge,
	const unsigned char peer_challenge[16], const char *username,
	const char *secret, int secret_len, unsigned char nt_response[24]);
void chapms2_eap_auth_response(const unsigned char *auth_challenge,
	const unsigned char peer_challenge[16], const unsigned char nt_response[24],
	const char *username, const char *secret, int secret_len,
	unsigned char auth_response[41]);

/* Stubs for ppp-side symbols referenced by chap_ms.o/pppcrypt.o/magic.o
   that are irrelevant to the crypto under test */
void mppe_set_key(void *pcb, unsigned char *key, int keylen) { (void)pcb; (void)key; (void)keylen; }
void ppp_error(const char *fmt, ...) { (void)fmt; }
void ppp_dbglog(const char *fmt, ...) { (void)fmt; }
void ppp_info(const char *fmt, ...) { (void)fmt; }
void ppp_warn(const char *fmt, ...) { (void)fmt; }
unsigned int sys_jiffies(void) { return 0; }

@interface SRPEapMschapv2Tests : XCTestCase
@end

@implementation SRPEapMschapv2Tests

static int hex2bin(const char *hex, unsigned char *out) {
	int n = 0;
	while (hex[0] && hex[1]) {
		unsigned v;
		sscanf(hex, "%2x", &v);
		out[n++] = (unsigned char)v;
		hex += 2;
	}
	return n;
}

/* RFC 2759 section 9.2:
   username "User", password "clientPass",
   authenticator challenge 5B5D7C7D7B3F2F3E3C2C602132262628,
   peer challenge 21402324255E262A28295F2B3A337C7E,
   NT response 82309ECD8D708B5EA08FAA3981CD83544233114A3D85D6DF,
   authenticator response S=407A5589115FD0D6209F510FE9C04566932CDA56 */
- (void)testRfc2759Vectors {
	unsigned char auth[16], peer[16], nt[24], expnt[24], authresp[41];
	const char *user = "User";
	const char *pass = "clientPass";

	hex2bin("5B5D7C7D7B3F2F3E3C2C602132262628", auth);
	hex2bin("21402324255E262A28295F2B3A337C7E", peer);
	hex2bin("82309ECD8D708B5EA08FAA3981CD83544233114A3D85D6DF", expnt);

	chapms2_eap_nt_response(auth, peer, user, pass, (int)strlen(pass), nt);
	NSData *got = [NSData dataWithBytes:nt length:24];
	NSData *want = [NSData dataWithBytes:expnt length:24];
	XCTAssertEqualObjects(got, want, @"NT-Response must match RFC 2759 9.2");

	chapms2_eap_auth_response(auth, peer, nt, user, pass, (int)strlen(pass), authresp);
	XCTAssertEqualObjects([NSString stringWithUTF8String:(const char *)authresp],
	                      @"407A5589115FD0D6209F510FE9C04566932CDA56",
	                      @"Authenticator response must match RFC 2759 9.2");
}

- (void)testEapMschapv2CapabilityNowSupported {
	SSAuthCapabilities *caps = [SSAuthCapabilities sharedCapabilities];
	XCTAssertTrue(caps.supportsEapMschapv2);
	XCTAssertTrue(caps.supportsPeap);
	XCTAssertTrue(caps.supportsEapTtls);
	XCTAssertTrue(caps.supportsTeap);
	XCTAssertTrue(caps.supportsEapTls13);
	XCTAssertTrue(caps.eapUnsupportedReason.length > 0);
}

@end
