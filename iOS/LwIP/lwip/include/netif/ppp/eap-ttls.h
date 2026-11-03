/*
 * eap-ttls.h - EAP-TTLS (EAP type 21) client, RFC 5281 (TTLSv0),
 *              with an inner EAP method inside the TLS tunnel.
 *
 * The TLS tunnel runs over the EAP frame stream using BoringSSL with a
 * memory BIO pair (same transport pattern as the PEAP engine).  Only the
 * client (authenticatee) side is implemented.
 */

#include "netif/ppp/ppp_opts.h"
#if PPP_SUPPORT && EAP_SUPPORT && MSCHAP_SUPPORT  /* don't build if not configured for use in lwipopts.h */

#ifndef PPP_EAP_TTLS_H
#define PPP_EAP_TTLS_H

#include "ppp.h"

#ifdef __cplusplus
extern "C" {
#endif

/* TTLS frame flags (first octet of the Type-Data), EAP-TLS style;
 * the low 3 bits carry the TTLS version (0 for RFC 5281) */
#define TTLS_FLAGS_LENGTH_INCLUDED	0x80	/* L: 4-octet TLS length follows */
#define TTLS_FLAGS_MORE_FRAGMENTS	0x40	/* M: more fragments follow */
#define TTLS_FLAGS_START		0x20	/* S: TTLS start (TLS handshake begins) */

/* TTLS phase-2 (inner) authentication methods (ppp_settings.eap_ttls_inner) */
#define EAP_TTLS_INNER_EAP	0	/* inner EAP via EAP-Message AVPs (default) */
#define EAP_TTLS_INNER_PAP	1	/* User-Name + User-Password AVPs (RFC 5281 11.2.5) */
#define EAP_TTLS_INNER_CHAP	2	/* User-Name + CHAP-Challenge + CHAP-Password (11.2.2) */

/* Handle an EAP-Request/TTLS payload (everything after the Type octet). */
void eap_ttls_input(ppp_pcb *pcb, u_char id, const u_char *payload, int len);

/* Release all TTLS state (called on link down / auth end). */
void eap_ttls_free(ppp_pcb *pcb);

/* A TTLS exchange is in progress on this link. */
int eap_ttls_active(ppp_pcb *pcb);

/* The inner authentication completed and was verified; a cleartext
 * EAP Success is now legitimate. */
int eap_ttls_done(ppp_pcb *pcb);

#ifdef __cplusplus
}
#endif

#endif /* PPP_EAP_TTLS_H */

#endif /* PPP_SUPPORT && EAP_SUPPORT && MSCHAP_SUPPORT */
