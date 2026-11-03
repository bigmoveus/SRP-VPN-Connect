// Stub for libsodium — SoftEther 5.x calls sodium_init() from InitCedar(),
// but all actual sodium usage is confined to Proto_WireGuard (not compiled).
// The constants below are only referenced by struct declarations in
// Proto_WireGuard.h / Server.h; the WireGuard code itself is excluded.
#ifndef SRPSE_SODIUM_STUB_H
#define SRPSE_SODIUM_STUB_H
#include <stddef.h>
static inline int sodium_init(void) { return 0; }

#define crypto_aead_chacha20poly1305_ietf_KEYBYTES 32u
#define crypto_aead_chacha20poly1305_ietf_ABYTES   16u
#define crypto_aead_chacha20poly1305_ietf_NPUBBYTES 12u
#define crypto_aead_xchacha20poly1305_ietf_KEYBYTES  32u
#define crypto_aead_xchacha20poly1305_ietf_ABYTES    16u
#define crypto_aead_xchacha20poly1305_ietf_NPUBBYTES 24u
#define crypto_scalarmult_curve25519_BYTES      32u
#define crypto_scalarmult_curve25519_SCALARBYTES 32u
#define crypto_box_PUBLICKEYBYTES 32u
#define crypto_box_SECRETKEYBYTES 32u
#define crypto_generichash_BYTES 32u
#define crypto_hash_sha256_BYTES 32u
#define crypto_hash_sha512_BYTES 64u
#define crypto_auth_hmacsha256_BYTES 32u
#define crypto_auth_hmacsha256_KEYBYTES 32u
#define crypto_kx_PUBLICKEYBYTES 32u
#define crypto_kx_SECRETKEYBYTES 32u
#define crypto_kx_SESSIONKEYBYTES 32u
#define crypto_sign_PUBLICKEYBYTES 32u
#define crypto_sign_SECRETKEYBYTES 64u
#define crypto_sign_BYTES 64u
#define crypto_secretbox_KEYBYTES 32u
#define crypto_secretbox_NONCEBYTES 24u
#define crypto_secretbox_MACBYTES 16u
#define crypto_stream_chacha20_KEYBYTES 32u
#define crypto_stream_chacha20_NONCEBYTES 8u
#define sodium_base64_VARIANT_ORIGINAL 1
#define sodium_base64_VARIANT_URLSAFE 2
#define sodium_base64_VARIANT_URLSAFE_NO_PADDING 3
#define sodium_base64_ENCODED_LEN(bin_len, variant) ((((bin_len) + 2) / 3) * 4 + 1)
static inline void sodium_memzero(void *p, size_t n) { volatile unsigned char *v = (volatile unsigned char *)p; while (n--) *v++ = 0; }
static inline int sodium_memcmp(const void *a, const void *b, size_t n) {
    const unsigned char *x = (const unsigned char *)a, *y = (const unsigned char *)b;
    int r = 0; while (n--) r |= *x++ ^ *y++; return r ? -1 : 0;
}
static inline void randombytes_buf(void *buf, size_t size) {
    unsigned char *p = (unsigned char *)buf; for (size_t i = 0; i < size; i++) p[i] = 0;
}
#endif
