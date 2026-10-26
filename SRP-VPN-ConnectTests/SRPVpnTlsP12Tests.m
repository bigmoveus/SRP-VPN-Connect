//
//  SRPVpnTlsP12Tests.m
//  SRP-VPN-ConnectTestsMac
//
//  EAP-TLS credential handling: SSSctp's PKCS#12 unpacking (the code path
//  the packet-tunnel extension uses after reading the shared Keychain).
//  Mac-only: links BoringSSL from SRPCore's xcframework slices.
//

#import <XCTest/XCTest.h>
#import "SSProtocol.h"
#import <openssl/evp.h>
#import <openssl/rsa.h>
#import <openssl/x509.h>
#import <openssl/pkcs8.h>
#import <openssl/crypto.h>

@interface SRPVpnTlsP12Tests : XCTestCase
@end

@implementation SRPVpnTlsP12Tests

+ (NSData *)fixtureP12 {
    NSData *result = nil;
    EVP_PKEY_CTX *context = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    EVP_PKEY *key = NULL;
    X509 *certificate = NULL;
    PKCS12 *bundle = NULL;
    uint8_t *der = NULL;

    if (context == NULL || EVP_PKEY_keygen_init(context) <= 0 ||
        EVP_PKEY_CTX_set_rsa_keygen_bits(context, 2048) <= 0 ||
        EVP_PKEY_keygen(context, &key) <= 0) {
        XCTFail(@"Unable to generate an in-memory test key");
        goto cleanup;
    }
    certificate = X509_new();
    if (certificate == NULL || !X509_set_version(certificate, X509_VERSION_3) ||
        !ASN1_INTEGER_set(X509_get_serialNumber(certificate), 1) ||
        X509_gmtime_adj(X509_get_notBefore(certificate), 0) == NULL ||
        X509_gmtime_adj(X509_get_notAfter(certificate), 3600) == NULL ||
        !X509_NAME_add_entry_by_txt(X509_get_subject_name(certificate), "CN", MBSTRING_ASC,
                                    (const unsigned char *)"Unit Test", -1, -1, 0) ||
        !X509_set_issuer_name(certificate, X509_get_subject_name(certificate)) ||
        !X509_set_pubkey(certificate, key) || !X509_sign(certificate, key, EVP_sha256())) {
        XCTFail(@"Unable to generate an in-memory test certificate");
        goto cleanup;
    }
    bundle = PKCS12_create("srtp123", "Unit Test", key, certificate, NULL, 0, 0, 0, 0, 0);
    int length = bundle == NULL ? 0 : i2d_PKCS12(bundle, &der);
    if (length <= 0 || der == NULL) {
        XCTFail(@"Unable to encode the in-memory PKCS#12 fixture");
        goto cleanup;
    }
    result = [NSData dataWithBytes:der length:(NSUInteger)length];

cleanup:
    OPENSSL_free(der);
    PKCS12_free(bundle);
    X509_free(certificate);
    EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(context);
    return result;
}

- (void)testValidP12UnpacksToPem {
    NSData *p12 = [SRPVpnTlsP12Tests fixtureP12];
    XCTAssertNotNil(p12, @"The in-memory PKCS#12 fixture must not be nil");

    SSSstp *p = [SSSstp new];
    XCTAssertTrue([p setEapTlsP12:p12 passphrase:@"srtp123"]);
    XCTAssertNotNil(p.eapTlsCertPem);
    XCTAssertNotNil(p.eapTlsKeyPem);
    NSString *cert = [[NSString alloc] initWithData:p.eapTlsCertPem encoding:NSUTF8StringEncoding];
    NSString *key = [[NSString alloc] initWithData:p.eapTlsKeyPem encoding:NSUTF8StringEncoding];
    XCTAssertTrue([cert containsString:@"-----BEGIN CERTIFICATE-----"]);
    XCTAssertTrue([key containsString:@"-----BEGIN PRIVATE KEY-----"] ||
                  [key containsString:@"-----BEGIN RSA PRIVATE KEY-----"]);
}

- (void)testWrongPassphraseRejected {
    NSData *p12 = [SRPVpnTlsP12Tests fixtureP12];
    XCTAssertNotNil(p12);
    SSSstp *p = [SSSstp new];
    XCTAssertFalse([p setEapTlsP12:p12 passphrase:@"wrong-passphrase"]);
    XCTAssertNil(p.eapTlsCertPem);
    XCTAssertNil(p.eapTlsKeyPem);
}

- (void)testGarbageRejected {
    SSSstp *p = [SSSstp new];
    XCTAssertFalse([p setEapTlsP12:[@"not a p12" dataUsingEncoding:NSUTF8StringEncoding]
                        passphrase:@"srtp123"]);
    XCTAssertNil(p.eapTlsCertPem);
    XCTAssertNil(p.eapTlsKeyPem);
}

@end
