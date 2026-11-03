/*
 * eap-peap.h - PEAP (EAP type 25) client with an inner EAP method,
 *              Microsoft PEAPv1 style (draft-josefsson-pppext-eap-tunnel).
 *
 * The TLS tunnel runs over the EAP frame stream using BoringSSL with a
 * memory BIO pair.  Only the client (authenticatee) side is implemented.
 */

#include "netif/ppp/ppp_opts.h"
#if PPP_SUPPORT && EAP_SUPPORT && MSCHAP_SUPPORT  /* don't build if not configured for use in lwipopts.h */

#ifndef PPP_EAP_PEAP_H
#define PPP_EAP_PEAP_H

#include "ppp.h"

#ifdef __cplusplus
extern "C" {
#endif

/* PEAP frame flags (first octet of the Type-Data), EAP-TLS style */
#define PEAP_FLAGS_LENGTH_INCLUDED	0x80	/* L: 4-octet TLS length follows */
#define PEAP_FLAGS_MORE_FRAGMENTS	0x40	/* M: more fragments follow */
#define PEAP_FLAGS_START		0x20	/* S: PEAP start (TLS handshake begins) */

/* Handle an EAP-Request/PEAP payload (everything after the Type octet). */
void eap_peap_input(ppp_pcb *pcb, u_char id, const u_char *payload, int len);

/* Release all PEAP state (called on link down / auth end). */
void eap_peap_free(ppp_pcb *pcb);

/* A PEAP exchange is in progress on this link. */
int eap_peap_active(ppp_pcb *pcb);

/* The inner authentication completed and was verified; a cleartext
 * EAP Success is now legitimate (Microsoft PEAPv1 ending). */
int eap_peap_done(ppp_pcb *pcb);

/* A verified Crypto-Binding TLV was exchanged (peap_require_cb). */
int eap_peap_cb_done(ppp_pcb *pcb);

#ifdef __cplusplus
}
#endif

#endif /* PPP_EAP_PEAP_H */

#endif /* PPP_SUPPORT && EAP_SUPPORT && MSCHAP_SUPPORT */
