/*
 * eap-teap.h - TEAP (EAP type 55) client, RFC 7170 (version 1),
 *              with an inner EAP method inside the TLS tunnel.
 *
 * The TLS tunnel runs over the EAP frame stream using BoringSSL with a
 * memory BIO pair (same transport pattern as the PEAP/TTLS engines).
 * Only the client (authenticatee) side is implemented.
 */

#include "netif/ppp/ppp_opts.h"
#if PPP_SUPPORT && EAP_SUPPORT && MSCHAP_SUPPORT  /* don't build if not configured for use in lwipopts.h */

#ifndef PPP_EAP_TEAP_H
#define PPP_EAP_TEAP_H

#include "ppp.h"

#ifdef __cplusplus
extern "C" {
#endif

/* TEAP frame flags (first octet of the Type-Data), EAP-TLS style;
 * the low 3 bits carry the TEAP version (1 for RFC 7170) */
#define TEAP_FLAGS_LENGTH_INCLUDED	0x80	/* L: 4-octet TLS length follows */
#define TEAP_FLAGS_MORE_FRAGMENTS	0x40	/* M: more fragments follow */
#define TEAP_FLAGS_START		0x20	/* S: TEAP start (TLS handshake begins) */
#define TEAP_FLAGS_OUTER_TLV		0x10	/* O: 4-octet length + Outer TLVs follow */

/* Handle an EAP-Request/TEAP payload (everything after the Type octet). */
void eap_teap_input(ppp_pcb *pcb, u_char id, const u_char *payload, int len);

/* Release all TEAP state (called on link down / auth end). */
void eap_teap_free(ppp_pcb *pcb);

/* A TEAP exchange is in progress on this link. */
int eap_teap_active(ppp_pcb *pcb);

/* The inner authentication completed and was verified; a cleartext
 * EAP Success is now legitimate. */
int eap_teap_done(ppp_pcb *pcb);

#ifdef __cplusplus
}
#endif

#endif /* PPP_EAP_TEAP_H */

#endif /* PPP_SUPPORT && EAP_SUPPORT && MSCHAP_SUPPORT */
