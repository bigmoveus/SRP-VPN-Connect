
#include "x_utils.h"
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <mach/mach_time.h>
#include "x_lwip.h"

x_ipver x_ip_version(uint8_t *p) {
    return (p[0] & 0xf0) >> 4;
}


bool x_more_fragments(x_ipver ipv, uint8_t *p) {
    switch (ipv) {
        case x_ipv4: {
            if ((p[6] & 0x20) > 0 /* has MF (More Fragments) bit set */) {
                return true;
            }
        }
        case x_ipv6: {
            // FIXME Just too lazy to implement this for IPv6, for now
            // returning true simply indicate do the copy anyway.
            return true;
        }
        default:{
            return false;
        }
    }
    return false;
}

x_proto x_tcp_stack_version(x_ipver ipv, uint8_t *p, int len) {
    switch (ipv) {
        case x_ipv4: {
            if (len < 10) {
                return x_proto_unknown;
            }
            return p[9];
        }
        case x_ipv6: {
            if (len < 7) {
                return x_proto_unknown;
            }
            return p[6];
        }
        default:
            return x_proto_unknown;
    }
}

uint16_t x_fragment_offset(x_ipver ipv, uint8_t *p){
    switch (ipv) {
        case x_ipv4: {
            p = p + 6;
            uint16_t pp = *((uint16_t *)p);
            pp = htons(pp);
            return (pp & 0x1fff);
        }
        case x_ipv6:
            // FIXME Just too lazy to implement this for IPv6, for now
            // returning a value greater than 0 simply indicate do the
            // copy anyway.
            return 1;
    }
    return 0;
}

void x_print_ip_packet(uint8_t *mem, const char *tag) {
    struct ip *ip_hdr = (struct ip *)mem;
    int hdr_len = ip_hdr->ip_hl * 4;
    
    char ip_src[32] = {0};
    char ip_dst[32] = {0};

    ip4addr_ntoa_r((const ip4_addr_t *)&ip_hdr->ip_src, ip_src, 32);
    ip4addr_ntoa_r((const ip4_addr_t *)&ip_hdr->ip_dst, ip_dst, 32);
    
    uint16_t sport = ntohs(*(uint16_t *)(mem + hdr_len));
    uint16_t dport = ntohs(*(uint16_t *)(mem + hdr_len + 2));
    
    NSString *identifier_dest = [NSString stringWithFormat:@"udp:%s:%d", ip_dst, dport];
    NSString *identifier_source = [NSString stringWithFormat:@"udp:%s:%d", ip_src, sport];
    NSString *key = [NSString stringWithFormat:@"%@->%@", identifier_source, identifier_dest];
    NSLog(@"[Y] TAG:%s, %@", tag, key);
}

int64_t x_system_time_nanos(void) {
    static mach_timebase_info_data_t timebase;
    if (timebase.denom == 0) {
      // Get the timebase if this is the first time we run.
      // Recommended by Apple's QA1398.
      if (mach_timebase_info(&timebase) != KERN_SUCCESS) {
          return -1;
      }
    }
    int64_t ticks = mach_absolute_time() * timebase.numer / timebase.denom;
    return ticks;
}

int64_t x_system_time_micro(void) {
    return x_system_time_nanos() / 1000;
}

int64_t x_system_time_mills(void) {
    return x_system_time_micro() / 1000;
}
