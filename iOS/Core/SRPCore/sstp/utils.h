
#ifndef time_utils_h
#define time_utils_h

#include <stdio.h>
#include <netinet/in.h>
#include <openssl/sha.h>

#if defined(__cplusplus)
extern "C" {
#endif

typedef uint8_t byte_t;
typedef signed long ssize_t;
typedef byte_t data64_t[8];
typedef byte_t data128_t[16];
typedef byte_t data256_t[32];

typedef void (*x_log_print_fn)(const char *str);
void x_set_print_func(x_log_print_fn);

int64_t x_socks_system_time_mills(void);

int uv_ip4_addr(const char* ip, int port, struct sockaddr_in* addr);

void x_print_bytes(uint8_t *buf, int len);

void x_debug(const char *fmt, ...);

int crypto_sha256(const byte_t *data, size_t size, data256_t hash);

int crypto_sha1(const byte_t *data, size_t size, uint8_t hash[SHA_DIGEST_LENGTH]);

#if defined(__cplusplus)
}  // extern C
#endif

#endif /* time_utils_h */
