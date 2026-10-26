
#ifndef x_utils_h
#define x_utils_h

#include <stdio.h>
#import <Foundation/Foundation.h>

typedef enum x_ipver {
    x_ipv4 = 4,
    x_ipv6 = 6,
} x_ipver;

typedef enum x_proto {
    x_proto_unknown = 0,
    x_proto_icmp = 1,
    x_proto_tcp  = 6,
    x_proto_udp  = 17
} x_proto;

x_ipver x_ip_version(uint8_t *p);

x_proto x_tcp_stack_version(x_ipver ipv, uint8_t *p, int len);

bool x_more_fragments(x_ipver v, uint8_t *p);

uint16_t x_fragment_offset(x_ipver ipv, uint8_t *p);

void x_print_ip_packet(uint8_t *p, const char *tag);

int64_t x_system_time_nanos(void);

int64_t x_system_time_micro(void);

int64_t x_system_time_mills(void);
#endif /* x_utils_h */
