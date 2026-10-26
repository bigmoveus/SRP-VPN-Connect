
#ifndef xlwip_h
#define xlwip_h

#include "lwip/icmp.h"
#include "lwip/ip4.h"
#include "lwip/init.h"
#include "netif/etharp.h"
#include "lwip/stats.h"
#include "lwip/prot/ip.h"
#include "lwip/prot/ip4.h"
#include "lwip/tcpip.h"
#include "lwip/tcp.h"
#include "lwip/udp.h"
#include "lwip/err.h"

void sys_check_timeouts(void);
void sys_restart_timeouts(void);

#endif /* xlwip_h */
