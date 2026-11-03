/*
 * eap-mschapv2.h - Transport-agnostic EAP-MSCHAPv2 client engine
 *                  (draft-kamath-pppext-eap-mschapv2)
 *
 * The engine is used twice: by eap.c for bare EAP-MSCHAPv2 (PPP frames)
 * and by eap-peap.c inside the PEAP TLS tunnel.  The caller provides the
 * credentials and two callbacks; the engine never touches the network
 * itself.
 */

#include "netif/ppp/ppp_opts.h"
#if PPP_SUPPORT && EAP_SUPPORT && MSCHAP_SUPPORT  /* don't build if not configured for use in lwipopts.h */

#ifndef PPP_EAP_MSCHAPV2_ENGINE_H
#define PPP_EAP_MSCHAPV2_ENGINE_H

#include "ppp.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct eap_mschapv2_ctx {
	const char *username;
	const char *secret;
	int secret_len;
	/* Inside a protected tunnel (PEAP) the authenticator response may be
	 * empty/absent; verification can then be skipped safely. */
	int verify_auth_response;

	/* Sends an EAP-Response/MSCHAPv2 with the given payload */
	void (*send_response)(void *arg, u_char eap_id, const u_char *payload, int len);
	void *send_arg;
	/* verified=1: mutual authentication verified and success acked;
	 * verified=0: authentication failed. */
	void (*complete)(void *arg, int verified);
	void *complete_arg;

	u_char eap_id;		/* EAP id of the in-flight exchange */
	u_char ms_id;		/* MS-CHAPv2-ID of the last server packet */
	u_char auth_challenge[EAPMSCHAPV2_CHALLENGE_LEN];
	u_char peer_challenge[EAPMSCHAPV2_CHALLENGE_LEN];
	u_char nt_response[24];
	int started;
} eap_mschapv2_ctx;

void eap_mschapv2_init(eap_mschapv2_ctx *ctx, const char *username,
	const char *secret, int secret_len, int verify_auth_response,
	void (*send_response)(void *, u_char, const u_char *, int), void *send_arg,
	void (*complete)(void *, int), void *complete_arg);

/* Handle an EAP-Request/MSCHAPv2 payload (everything after the Type octet). */
void eap_mschapv2_handle(eap_mschapv2_ctx *ctx, u_char eap_id, const u_char *inp, int len);

#ifdef __cplusplus
}
#endif

#endif /* PPP_EAP_MSCHAPV2_ENGINE_H */

#endif /* PPP_SUPPORT && EAP_SUPPORT && MSCHAP_SUPPORT */
