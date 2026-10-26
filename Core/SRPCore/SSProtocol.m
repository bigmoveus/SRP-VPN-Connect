
#import "SSProtocol.h"
#include <openssl/pkcs12.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/asn1.h>
#include <openssl/obj_mac.h>

@implementation SSProtocol

- (instancetype)init
{
    self = [super init];
    if (self) {
        _transport = SSTransportTypeTCP;
        _protocol = SSClientType_DIRECT;
        _security = SSSecurityType_NONE;
        _allowInsecure = NO;
    }
    return self;
}

@end


@implementation SSSstp

-(SSClientType)protocol {
    return SSClientType_SSTP;
}

- (instancetype)init
{
    self = [super init];
    if (self) {
        _MS2_CHAP_ENABLE = YES;
        _PAP_ENABLE = NO;
        _MS_CHAP_ENABLE = NO;
        _CHAP_ENABLE = NO;
        _eapMschapv2Enabled = NO;
        _peapEnabled = NO;
        _peapRequireCryptoBinding = NO;
        _ttlsEnabled = NO;
        _ttlsInnerMethod = @"eap";
        _teapEnabled = NO;
        _eapIdentityPrivacy = NO;
        _eapAnonymousIdentity = @"anonymous";
        _eapTls13Enabled = YES;
        _eapDisableLegacyTls = YES;
        _proxyMode = 0;
        _disableLegacyOuterTls = NO;
        _autoReconnect = YES;
        _retryTimes = 0;
        _switchToWifi = YES;
        _onSleep = 2;   // stay
        _logLevel = 0;  // normal
    }
    return self;
}

- (BOOL)setEapTlsP12:(NSData *)p12 passphrase:(NSString *)passphrase {
    if (p12.length == 0 || passphrase == nil) {
        return NO;
    }
    const uint8_t *bytes = p12.bytes;
    PKCS12 *pkcs12 = d2i_PKCS12(NULL, &bytes, p12.length);
    if (pkcs12 == NULL) {
        return NO;
    }
    EVP_PKEY *key = NULL;
    X509 *cert = NULL;
    STACK_OF(X509) *ca = NULL;
    int ok = PKCS12_parse(pkcs12, passphrase.UTF8String, &key, &cert, &ca);
    PKCS12_free(pkcs12);
    if (ok != 1 || key == NULL || cert == NULL) {
        if (key) EVP_PKEY_free(key);
        if (cert) X509_free(cert);
        if (ca) sk_X509_pop_free(ca, X509_free);
        return NO;
    }
    BIO *b = BIO_new(BIO_s_mem());
    PEM_write_bio_X509(b, cert);
    for (int i = 0; ca != NULL && i < sk_X509_num(ca); i++) {
        PEM_write_bio_X509(b, sk_X509_value(ca, i));
    }
    int n = (int)BIO_number_written(b);
    NSMutableData *certPem = [NSMutableData dataWithLength:n];
    BIO_read(b, certPem.mutableBytes, n);
    BIO_free_all(b);
    b = BIO_new(BIO_s_mem());
    PEM_write_bio_PrivateKey(b, key, NULL, NULL, 0, NULL, NULL);
    n = (int)BIO_number_written(b);
    NSMutableData *keyPem = [NSMutableData dataWithLength:n];
    BIO_read(b, keyPem.mutableBytes, n);
    BIO_free_all(b);
    EVP_PKEY_free(key);
    X509_free(cert);
    if (ca) sk_X509_pop_free(ca, X509_free);
    self.eapTlsCertPem = certPem;
    self.eapTlsKeyPem = keyPem;
    return YES;
}

/* Parse a .p12 and return the leaf certificate (or NULL). Caller frees. */
static X509 *ss_eap_tls_p12_leaf(NSData *p12, NSString *passphrase) {
    if (p12.length == 0 || passphrase == nil) {
        return NULL;
    }
    const uint8_t *bytes = p12.bytes;
    PKCS12 *pkcs12 = d2i_PKCS12(NULL, &bytes, p12.length);
    if (pkcs12 == NULL) {
        return NULL;
    }
    EVP_PKEY *key = NULL;
    X509 *cert = NULL;
    STACK_OF(X509) *ca = NULL;
    int ok = PKCS12_parse(pkcs12, passphrase.UTF8String, &key, &cert, &ca);
    PKCS12_free(pkcs12);
    if (key) EVP_PKEY_free(key);
    if (ca) sk_X509_pop_free(ca, X509_free);
    if (ok != 1 || cert == NULL) {
        if (cert) X509_free(cert);
        return NULL;
    }
    return cert;
}

+ (NSDictionary *)eapTlsP12Info:(NSData *)p12 passphrase:(NSString *)passphrase {
    X509 *cert = ss_eap_tls_p12_leaf(p12, passphrase);
    if (cert == NULL) {
        return nil;
    }
    NSString *name = nil;
    char cn[256];
    X509_NAME *subject = X509_get_subject_name(cert);
    if (subject != NULL &&
        X509_NAME_get_text_by_NID(subject, NID_commonName, cn, (int)sizeof(cn)) > 0) {
        name = [NSString stringWithUTF8String:cn];
    }
    if (name.length == 0) {
        name = @"Client Certificate";
    }
    NSDate *expiry = [NSDate distantPast];
    const ASN1_TIME *notAfter = X509_get0_notAfter(cert);
    if (notAfter != NULL) {
        int days = 0, secs = 0;
        if (ASN1_TIME_diff(&days, &secs, NULL, notAfter) == 1) {
            expiry = [NSDate dateWithTimeIntervalSinceNow:days * 86400.0 + secs];
        }
    }
    X509_free(cert);
    return @{@"name": name, @"expiry": expiry};
}

@end

