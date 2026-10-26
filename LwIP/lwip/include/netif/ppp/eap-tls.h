/*
 * eap-tls.h - EAP-TLS (EAP type 13) client, RFC 5216 — mutual TLS with a
 *             client certificate, usable bare (PPP EAP) and as an inner
 *             method inside PEAP/TTLS/TEAP tunnels.
 *
 * The engine is transport-agnostic: it owns a BoringSSL session over a
 * memory BIO pair plus the EAP-TLS L/M fragmentation, and reports output
 * frames / completion through callbacks.  The bare-mode wrapper (bottom
 * of eap-tls.c) binds it to the ppp_pcb; the tunnel engines drive the
 * same engine for inner EAP-TLS.
 *
 * Client credentials: PEM blobs (certificate chain + private key) handed
 * down via ppp_settings by the upper layer; the app unwraps the .p12.
 */

#include "netif/ppp/ppp_opts.h"
#if PPP_SUPPORT && EAP_SUPPORT  /* don't build if not configured for use in lwipopts.h */

#ifndef PPP_EAP_TLS_H
#define PPP_EAP_TLS_H

#include "ppp.h"

#ifdef __cplusplus
extern "C" {
#endif

/* EAP-TLS frame flags (first octet of the Type-Data) */
#define EAPTLS_FLAGS_LENGTH_INCLUDED	0x80	/* L: 4-octet TLS length follows */
#define EAPTLS_FLAGS_MORE_FRAGMENTS	0x40	/* M: more fragments follow */
#define EAPTLS_FLAGS_START		0x20	/* S: start (unused by EAP-TLS) */

typedef struct eap_tls_engine eap_tls_engine;

/* Sends one EAP-Response/TLS payload (flags + optional length + TLS data) */
typedef void (*eap_tls_send_fn)(void *arg, u_char eap_id, const u_char *payload, int len);
/* ok=1: TLS handshake done and (for inner use) inner auth may proceed;
 * ok=0: failed. */
typedef void (*eap_tls_done_fn)(void *arg, int ok);

/* Fragment size for tunneled use: large enough that inner EAP-TLS never
 * fragments itself (the tunnel fragments its TLS records instead;
 * FreeRADIUS 3.2.5 loses the inner EAP session across fragment
 * round-trips). */
#define EAPTLS_TUNNELED_MTU 4096

/* cert_pem/key_pem may be NULL for a client that never sends a
 * certificate (only sensible when the server does not request one). */
/* frag_mtu: max TLS bytes per EAP frame; use EAPTLS_TUNNELED_MTU when
 * tunneled (see eap-tls.c) and 0 for the bare default. */
int eap_tls_engine_init(eap_tls_engine **out, ppp_pcb *pcb, int frag_mtu,
    eap_tls_send_fn send_cb, void *send_arg,
    eap_tls_done_fn done_cb, void *done_arg);
void eap_tls_engine_free(eap_tls_engine *e);

/* Handle one EAP-Request/TLS payload (everything after the Type octet). */
void eap_tls_engine_input(eap_tls_engine *e, u_char eap_id, const u_char *payload, int len);

/* Derive the RFC 5216 2.3 key material ("client EAP encryption") into
 * the ppp settings MPPE slots (client-perspective send/recv, 32 octets
 * each, for the SSTP crypto binding). */
int eap_tls_engine_mppe_keys(eap_tls_engine *e, ppp_pcb *pcb);

/* Export the raw 64-octet RFC 5216 key material (for the tunnel engines'
 * crypto-binding when EAP-TLS is the inner method). */
int eap_tls_engine_export_km(eap_tls_engine *e, u_char out[64]);

/* Bare-mode wrapper bound to the pcb (used by eap.c's type-13 dispatch). */
void eap_tls_input(ppp_pcb *pcb, u_char id, const u_char *payload, int len);
void eap_tls_free(ppp_pcb *pcb);
int eap_tls_active(ppp_pcb *pcb);
int eap_tls_done(ppp_pcb *pcb);

#ifdef __cplusplus
}
#endif

#endif /* PPP_EAP_TLS_H */

#endif /* PPP_SUPPORT && EAP_SUPPORT */
