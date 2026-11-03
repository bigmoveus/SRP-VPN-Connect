/*
 * SRP patch for hev-socks5-core: upstream-stream hook.
 *
 * The stock client opens a TCP connection to a SOCKS5 server. The SRP SSH
 * engine instead hands each client a socketpair endpoint whose peer is
 * pumped through an SSH direct-tcpip channel (TCP flows) or a channel to
 * the server-side HEV relay (UDP flows).
 *
 * The hook runs on an engine task thread and must return a nonblocking,
 * pollable stream fd (socketpair) or -1.
 */

#ifndef __SRP_SSH_HOOK_H__
#define __SRP_SSH_HOOK_H__

typedef int (*srp_ssh_stream_open_hook_t) (void);

extern srp_ssh_stream_open_hook_t srp_ssh_stream_open_hook;

#endif /* __SRP_SSH_HOOK_H__ */
