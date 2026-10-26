
#ifndef time_utils_h
#define time_utils_h

#include <stdio.h>
#include <netinet/in.h>

#if defined(__cplusplus)
extern "C" {
#endif

typedef void (*x_log_print_fn)(const char *str);
void x_set_print_func(x_log_print_fn);

int64_t x_socks_system_time_mills(void);

int uv_ip4_addr(const char* ip, int port, struct sockaddr_in* addr);

void x_print_bytes(uint8_t *buf, int len);

void x_debug(const char *fmt, ...);

#if defined(__cplusplus)
}  // extern C
#endif

#endif /* time_utils_h */
