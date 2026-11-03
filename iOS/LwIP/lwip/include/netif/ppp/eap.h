/*
 * eap.h - Extensible Authentication Protocol for PPP (RFC 2284)
 *
 * Copyright (c) 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 *
 * Non-exclusive rights to redistribute, modify, translate, and use
 * this software in source and binary forms, in whole or in part, is
 * hereby granted, provided that the above copyright notice is
 * duplicated in any source form, and that neither the name of the
 * copyright holder nor the author is used to endorse or promote
 * products derived from this software.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 *
 * Original version by James Carlson
 *
 * $Id: eap.h,v 1.2 2003/06/11 23:56:26 paulus Exp $
 */

#include "netif/ppp/ppp_opts.h"
#if PPP_SUPPORT && EAP_SUPPORT  /* don't build if not configured for use in lwipopts.h */

#ifndef PPP_EAP_H
#define	PPP_EAP_H

#include "ppp.h"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Packet header = Code, id, length.
 */
#define	EAP_HEADERLEN	4


/* EAP message codes. */
#define	EAP_REQUEST	1
#define	EAP_RESPONSE	2
#define	EAP_SUCCESS	3
#define	EAP_FAILURE	4

/* EAP types */
#define	EAPT_IDENTITY		1
#define	EAPT_NOTIFICATION	2
#define	EAPT_NAK		3	/* (response only) */
#define	EAPT_MD5CHAP		4
#define	EAPT_OTP		5	/* One-Time Password; RFC 1938 */
#define	EAPT_TOKEN		6	/* Generic Token Card */
/* 7 and 8 are unassigned. */
#define	EAPT_RSA		9	/* RSA Public Key Authentication */
#define	EAPT_DSS		10	/* DSS Unilateral */
#define	EAPT_KEA		11	/* KEA */
#define	EAPT_KEA_VALIDATE	12	/* KEA-VALIDATE	*/
#define	EAPT_TLS		13	/* EAP-TLS */
#define	EAPT_DEFENDER		14	/* Defender Token (AXENT) */
#define	EAPT_W2K		15	/* Windows 2000 EAP */
#define	EAPT_ARCOT		16	/* Arcot Systems */
#define	EAPT_CISCOWIRELESS	17	/* Cisco Wireless */
#define	EAPT_NOKIACARD		18	/* Nokia IP smart card */
#define	EAPT_SRP		19	/* Secure Remote Password */
/* 20 is deprecated */
#define	EAPT_TTLS		21	/* EAP-TTLS, RFC 5281 */
#define	EAPT_PEAP		25	/* Protected EAP (PEAP) */
#define	EAPT_MSCHAPV2		26	/* EAP-MSCHAPv2, draft-kamath-pppext-eap-mschapv2 */
#define	EAPT_TLV		33	/* EAP-TLV (PEAPv2 result/crypto binding) */
#define	EAPT_TEAP		55	/* TEAP, RFC 7170 */
#define	EAPT_EXPANDED		254	/* Expanded EAP types (RFC 3748 5.7) */

/* EAP MS-CHAPv2 opcodes */
#define	EAPMSCHAPV2_CHALLENGE	1	/* Challenge Request */
#define	EAPMSCHAPV2_RESPONSE	2	/* Response */
#define	EAPMSCHAPV2_SUCCESS	3	/* Success-Request / Success-Response */
#define	EAPMSCHAPV2_FAILURE	4	/* Failure-Request / Failure-Response */

/* MS-Length covers everything after the EAP Type octet */
#define	EAPMSCHAPV2_HDRLEN	4	/* Opcode, MS-CHAPv2-ID, MS-Length */
#define	EAPMSCHAPV2_CHALLENGE_LEN	16
#define	EAPMSCHAPV2_RESPONSE_VALUE_LEN	49	/* peer chall 16 + reserved 8 + NT resp 24 + flags 1 */
#define	EAPMSCHAPV2_AUTH_RESPONSE_LEN	40	/* hex chars of authenticator response */

/* EAP SRP-SHA1 Subtypes */
#define	EAPSRP_CHALLENGE	1	/* Request 1 - Challenge */
#define	EAPSRP_CKEY		1	/* Response 1 - Client Key */
#define	EAPSRP_SKEY		2	/* Request 2 - Server Key */
#define	EAPSRP_CVALIDATOR	2	/* Response 2 - Client Validator */
#define	EAPSRP_SVALIDATOR	3	/* Request 3 - Server Validator */
#define	EAPSRP_ACK		3	/* Response 3 - final ack */
#define	EAPSRP_LWRECHALLENGE	4	/* Req/resp 4 - Lightweight rechal */

#define	SRPVAL_EBIT	0x00000001	/* Use shared key for ECP */

#define	SRP_PSEUDO_ID	"pseudo_"
#define	SRP_PSEUDO_LEN	7

#define MD5_SIGNATURE_SIZE	16
#define EAP_MIN_CHALLENGE_LENGTH	17
#define EAP_MAX_CHALLENGE_LENGTH	24
#define EAP_MIN_MAX_POWER_OF_TWO_CHALLENGE_LENGTH     3   /* 2^3-1 = 7, 17+7 = 24 */

#define	EAP_STATES	\
	"Initial", "Pending", "Closed", "Listen", "Identify", \
	"SRP1", "SRP2", "SRP3", "MD5Chall", "Open", "SRP4", "BadAuth"

#define	eap_client_active(pcb)	((pcb)->eap.es_client.ea_state == eapListen)
#if PPP_SERVER
#define	eap_server_active(pcb)	\
	((pcb)->eap.es_server.ea_state >= eapIdentify && \
	 (pcb)->eap.es_server.ea_state <= eapMD5Chall)
#endif /* PPP_SERVER */

/*
 * Complete EAP state for one PPP session.
 */
enum eap_state_code {
	eapInitial = 0,	/* No EAP authentication yet requested */
	eapPending,	/* Waiting for LCP (no timer) */
	eapClosed,	/* Authentication not in use */
	eapListen,	/* Client ready (and timer running) */
	eapIdentify,	/* EAP Identify sent */
	eapSRP1,	/* Sent EAP SRP-SHA1 Subtype 1 */
	eapSRP2,	/* Sent EAP SRP-SHA1 Subtype 2 */
	eapSRP3,	/* Sent EAP SRP-SHA1 Subtype 3 */
	eapMD5Chall,	/* Sent MD5-Challenge */
	eapOpen,	/* Completed authentication */
	eapSRP4,	/* Sent EAP SRP-SHA1 Subtype 4 */
	eapBadAuth	/* Failed authentication */
};

struct eap_auth {
	const char *ea_name;	/* Our name */
	char ea_peer[MAXNAMELEN +1];	/* Peer's name */
	void *ea_session;	/* Authentication library linkage */
	u_char *ea_skey;	/* Shared encryption key */
	u_short ea_namelen;	/* Length of our name */
	u_short ea_peerlen;	/* Length of peer's name */
	enum eap_state_code ea_state;
	u_char ea_id;		/* Current id */
	u_char ea_requests;	/* Number of Requests sent/received */
	u_char ea_responses;	/* Number of Responses */
	u_char ea_type;		/* One of EAPT_* */
	u32_t ea_keyflags;	/* SRP shared key usage flags */
};

#ifndef EAP_MAX_CHALLENGE_LENGTH
#define EAP_MAX_CHALLENGE_LENGTH	24
#endif
typedef struct eap_state {
	struct eap_auth es_client;	/* Client (authenticatee) data */
#if PPP_SERVER
	struct eap_auth es_server;	/* Server (authenticator) data */
#endif /* PPP_SERVER */
	int es_savedtime;		/* Saved timeout */
	int es_rechallenge;		/* EAP rechallenge interval */
	int es_lwrechallenge;		/* SRP lightweight rechallenge inter */
	u8_t es_usepseudo;		/* Use SRP Pseudonym if offered one */
	int es_usedpseudo;		/* Set if we already sent PN */
	int es_challen;			/* Length of challenge string */
	u_char es_challenge[EAP_MAX_CHALLENGE_LENGTH];
	void *es_peap;			/* PEAP engine state (eap-peap.c) */
	void *es_ttls;			/* TTLS engine state (eap-ttls.c) */
	void *es_teap;			/* TEAP engine state (eap-teap.c) */
	void *es_tls;			/* bare EAP-TLS engine state (eap-tls.c) */
} eap_state;

/*
 * Timeouts.
 */
#if 0 /* moved to ppp_opts.h */
#define	EAP_DEFTIMEOUT		3	/* Timeout (seconds) for rexmit */
#define	EAP_DEFTRANSMITS	10	/* max # times to transmit */
#define	EAP_DEFREQTIME		20	/* Time to wait for peer request */
#define	EAP_DEFALLOWREQ		20	/* max # times to accept requests */
#endif /* moved to ppp_opts.h */

/* Send an EAP Response; shared with the PEAP engine (eap-peap.c) */
void eap_send_response(ppp_pcb *pcb, u_char id, u_char typenum, const u_char *str, int lenstr);

void eap_authwithpeer(ppp_pcb *pcb, const char *localname);
void eap_authpeer(ppp_pcb *pcb, const char *localname);

extern const struct protent eap_protent;

#ifdef	__cplusplus
}
#endif

#endif /* PPP_EAP_H */

#endif /* PPP_SUPPORT && EAP_SUPPORT */
