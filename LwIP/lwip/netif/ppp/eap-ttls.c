/*
 * eap-ttls.c - EAP-TTLS (EAP type 21) client, RFC 5281 (TTLSv0).
 *
 * Wire flow (client side):
 *   <- EAP-Request/TTLS, flags S (start, version 0)
 *   -> EAP-Response/TTLS: TLS ClientHello   (L flag + length, fragmented)
 *   <- ... TLS handshake records (L/M fragmentation both ways) ...
 *   <- TLS app data: TTLS AVP sequence with EAP-Message AVP
 *      carrying EAP-Request/Identity          (RFC 5281 11.2.1)
 *   -> EAP-Message AVP: EAP-Response/Identity (real username)
 *   <- EAP-Message AVP: EAP-Request/MSCHAPv2 Challenge
 *   -> EAP-Message AVP: EAP-Response/MSCHAPv2
 *   <- EAP-Message AVP: EAP-Request/MSCHAPv2 Success (S= verified)
 *   -> EAP-Message AVP: inner Success ack
 *   <- cleartext EAP Success
 *
 * TTLS AVPs are Diameter-flavoured (RFC 5281 10.1): 4-octet AVP Code,
 * 1-octet flags (V/M), 3-octet length, optional Vendor-ID, data padded
 * to a 4-octet boundary.  EAP is tunnelled in EAP-Message AVPs (code 79,
 * RFC 2865), one EAP packet per AVP.
 *
 * Inner TLS certificate policy: like the PEAP engine, BoringSSL cannot
 * use the Apple trust store, so the inner leaf SHA256 is compared with
 * the outer SSTP connection's leaf.  A match is accepted silently.
 * KNOWN LIMITATION: when the EAP server is a different host than the
 * SSTP concentrator (e.g. RRAS relaying to FreeRADIUS), the certificates
 * legitimately differ; in that case a loud warning naming both
 * identities is logged and the connection is allowed to continue in
 * both strict and insecure modes — strict inner-cert pinning for the
 * split-host case needs a proper trust evaluation and is left for a
 * later phase.
 *
 * The TLS-over-EAP transport (BIO pair, L/M/S fragmentation, ack pacing)
 * mirrors the PEAP engine; it is duplicated rather than factored out to
 * keep the proven PEAP code untouched.
 */

#include "netif/ppp/ppp_opts.h"
#if PPP_SUPPORT && EAP_SUPPORT && MSCHAP_SUPPORT  /* don't build if not configured for use in lwipopts.h */

#include "netif/ppp/ppp_impl.h"
#include "netif/ppp/eap.h"
#include "netif/ppp/eap-mschapv2.h"
#include "netif/ppp/chap_ms.h"
#include "netif/ppp/eap-ttls.h"
#include "netif/ppp/eap-tls.h"
#include "netif/ppp/magic.h"
#include "netif/ppp/polarssl/md5.h"

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/x509.h>

#include <string.h>
#include <stdlib.h>

#ifndef EAP_TTLS_DEBUG_DUMP
#define EAP_TTLS_DEBUG_DUMP 0
#endif
#if EAP_TTLS_DEBUG_DUMP
static void ttls_dump(const char *what, const u_char *p, int len) {
	char buf[400];
	int off = 0, i;
	buf[0] = '\0';
	if (p != NULL) {
		for (i = 0; i < len && off < (int)sizeof(buf) - 3; i++)
			off += snprintf(buf + off, sizeof(buf) - off, "%02x", p[i]);
	}
	ppp_info("TTLS %s (%d): %s", what, len, buf);
}
#else
#define ttls_dump(...)
#endif

#define TTLS_EAP_MTU	1000	/* max TLS bytes per EAP frame */
#define TTLS_RX_MAX	16384	/* reassembly buffer */
#define TTLS_TXQ_MAX	16384	/* pending TLS output */

/* TTLS AVP (RFC 5281 10.1) */
#define TTLS_AVP_USER_NAME	1	/* User-Name (RFC 2865) */
#define TTLS_AVP_USER_PASSWORD	2	/* User-Password (RFC 2865) */
#define TTLS_AVP_CHAP_PASSWORD	3	/* CHAP-Password (RFC 2865/1994) */
#define TTLS_AVP_CHAP_CHALLENGE	60	/* CHAP-Challenge (RFC 2866) */
#define TTLS_AVP_EAP_MESSAGE	79	/* EAP-Message (RFC 2865) */
#define TTLS_AVP_FLAG_VENDOR	0x80
#define TTLS_AVP_FLAG_MANDATORY	0x40
#define TTLS_AVP_HDR_LEN	8	/* code(4) + flags(1) + length(3) */

enum ttls_phase {
	TTLS_PHASE_HANDSHAKE = 0,
	TTLS_PHASE_INNER,
};

struct eap_ttls_state {
	ppp_pcb *pcb;
	SSL_CTX *ssl_ctx;
	SSL *ssl;
	BIO *net_bio;		/* our end of the BIO pair (SSL owns the other) */
	enum ttls_phase phase;
	int handshake_done;
	int inner_verified;	/* inner EAP-MSCHAPv2 completed */
	int failed;

	/* TLS output -> EAP fragmentation */
	u_char txq[TTLS_TXQ_MAX];
	int txq_off, txq_len;

	/* EAP fragment reassembly (server -> client TLS records) */
	u_char rx[TTLS_RX_MAX];
	int rx_len;
	u32_t rx_total;

	/* inner AVP/EAP stream reassembly (TLS app data) */
	u_char in_eap[TTLS_RX_MAX];
	int in_eap_len;

	eap_mschapv2_ctx mschap;
	int mschap_started;
	int inner_started;	/* we initiated the inner EAP exchange */
	int ttls_version;	/* negotiated TTLS version (S frame, low 3 bits) */

	/* Inner EAP-TLS (certificate authentication inside the tunnel) */
	struct eap_tls_engine *inner_tls;
	int inner_tls_started;
	int nak_tls_sent;	/* inner method negotiation: NAKed for EAP-TLS once */
};

typedef struct eap_ttls_state eap_ttls_state;

static eap_ttls_state *ttls_get(ppp_pcb *pcb) {
	return (eap_ttls_state *)pcb->eap.es_ttls;
}

int eap_ttls_active(ppp_pcb *pcb) {
	return ttls_get(pcb) != NULL;
}

int eap_ttls_done(ppp_pcb *pcb) {
	eap_ttls_state *st = ttls_get(pcb);
	return st != NULL && st->inner_verified;
}

static void ttls_fail(eap_ttls_state *st) {
	ppp_pcb *pcb = st->pcb;
	st->failed = 1;
	eap_ttls_free(pcb);
	pcb->eap.es_client.ea_state = eapBadAuth;
	auth_withpeer_fail(pcb, PPP_EAP);
}

void eap_ttls_free(ppp_pcb *pcb) {
	eap_ttls_state *st = ttls_get(pcb);
	if (st == NULL)
		return;
	pcb->eap.es_ttls = NULL;
	if (st->ssl != NULL)
		SSL_free(st->ssl);	/* owns its end of the BIO pair */
	if (st->inner_tls != NULL)
		eap_tls_engine_free(st->inner_tls);
	if (st->net_bio != NULL)
		BIO_free(st->net_bio);
	if (st->ssl_ctx != NULL)
		SSL_CTX_free(st->ssl_ctx);
	free(st);
}

/*
 * Certificate policy for the inner TLS tunnel, see the file header.
 */
static int ttls_verify_cert(eap_ttls_state *st) {
	if (!st->pcb->settings.peap_cert_check) {
		ppp_warn("TTLS: inner TLS certificate NOT verified (allowInsecure is on)");
		return 1;
	}
	X509 *cert = SSL_get_peer_certificate(st->ssl);
	if (cert == NULL) {
		ppp_error("TTLS: server presented no inner TLS certificate");
		return 0;
	}
	int derlen = i2d_X509(cert, NULL);
	if (derlen <= 0) {
		X509_free(cert);
		return 0;
	}
	u_char *der = (u_char *)malloc(derlen);
	u_char *dp = der;
	u_char digest[SHA256_DIGEST_LENGTH];
	i2d_X509(cert, &dp);
	SHA256(der, derlen, digest);
	free(der);
	X509_free(cert);
	if (memcmp(digest, st->pcb->settings.peap_cert_sha256, SHA256_DIGEST_LENGTH) == 0) {
		ppp_info("TTLS: inner TLS certificate fingerprint matches the outer connection");
		return 1;
	}
	/* Split-host case (e.g. RRAS relaying EAP to a separate RADIUS
	 * server): the inner identity legitimately differs from the outer
	 * SSTP identity.  No trust evaluation exists for it yet; log both
	 * prominently and continue (see the file header). */
	{
		char inner_fp[65], outer_fp[65];
		int i;
		for (i = 0; i < 32; i++) {
			snprintf(inner_fp + 2 * i, 3, "%02x", digest[i]);
			snprintf(outer_fp + 2 * i, 3, "%02x",
			    st->pcb->settings.peap_cert_sha256[i]);
		}
		inner_fp[64] = outer_fp[64] = '\0';
		ppp_warn("TTLS: inner EAP TLS certificate differs from the SSTP outer connection");
		ppp_warn("TTLS: inner leaf SHA256 %s", inner_fp);
		ppp_warn("TTLS: outer leaf SHA256 %s (this is expected when the "
		    "EAP server is a different host than the SSTP concentrator; "
		    "accepted for now, strict split-host pinning is not implemented yet)",
		    outer_fp);
	}
	return 1;
}

/* Drain pending TLS output into the tx queue. */
static void ttls_drain(eap_ttls_state *st) {
	for (;;) {
		int room = TTLS_TXQ_MAX - st->txq_len;
		int n;
		if (room <= 0)
			break;
		n = BIO_read(st->net_bio, st->txq + st->txq_len, room);
		if (n <= 0)
			break;
		st->txq_len += n;
	}
}

/* Send the next queued fragment (an EAP-Response/TTLS). */
static void ttls_send_fragment(eap_ttls_state *st, u_char id) {
	u_char payload[5 + TTLS_EAP_MTU];
	u_char *o = payload;
	int chunk = st->txq_len - st->txq_off;
	u_char flags = 0;

	if (chunk > TTLS_EAP_MTU) {
		chunk = TTLS_EAP_MTU;
		flags = TTLS_FLAGS_MORE_FRAGMENTS;
	}
	if (st->txq_off == 0) {
		/* First fragment of a TLS message: include the total TLS
		 * message length (Windows and wpa_supplicant behaviour;
		 * some servers mis-behave without it). */
		flags |= TTLS_FLAGS_LENGTH_INCLUDED;
		PUTCHAR(flags, o);
		PUTLONG(st->txq_len, o);
	} else {
		PUTCHAR(flags, o);
	}
	MEMCPY(o, st->txq + st->txq_off, chunk);
	ttls_dump("TX fragment", payload, (int)(o - payload) + chunk);
	eap_send_response(st->pcb, id, EAPT_TTLS, payload, (int)(o - payload) + chunk);
	st->txq_off += chunk;
	if (st->txq_off == st->txq_len) {
		st->txq_off = st->txq_len = 0;
	}
	/* further fragments are sent when the server's empty ack arrives */
}

/* TTLS fragment ack — a single zero flags octet. */
static void ttls_send_ack(eap_ttls_state *st, u_char id) {
	u_char flags = 0;
	ttls_dump("TX ack", &flags, 1);
	eap_send_response(st->pcb, id, EAPT_TTLS, &flags, 1);
}

/* Send whatever the TLS engine produced (or an ack if nothing). */
static void ttls_flush(eap_ttls_state *st, u_char id) {
	ttls_drain(st);
	if (st->txq_len > 0)
		ttls_send_fragment(st, id);
	else
		ttls_send_ack(st, id);
}

/* Write one chunk of tunnelled data into the TLS tunnel. */
static void ttls_tls_write(eap_ttls_state *st, const u_char *pkt, int len) {
	int n = SSL_write(st->ssl, pkt, len);
	if (n <= 0) {
		int err = SSL_get_error(st->ssl, n);
		ppp_error("TTLS: inner TLS write failed (%d)", err);
		ttls_fail(st);
	}
	ttls_drain(st);
}

/* Append one AVP (RFC 5281 10.1: code 4 + flags 1 + length 3 + data,
 * zero-padded to a 4-octet boundary) to a buffer.  Returns the output
 * cursor, or NULL on overflow. */
static u_char *ttls_put_avp(u_char *o, u_char *end, u32_t code, const u_char *data, int len) {
	int padded = (len + 3) & ~3;
	int i;

	if (end - o < TTLS_AVP_HDR_LEN + padded)
		return NULL;
	PUTLONG(code, o);
	PUTCHAR(0, o);				/* flags: no vendor, not mandatory */
	PUTCHAR(0, o);				/* length, 3 octets, big-endian */
	PUTCHAR((u_char)((TTLS_AVP_HDR_LEN + len) >> 8), o);
	PUTCHAR((u_char)(TTLS_AVP_HDR_LEN + len), o);
	if (len > 0) {
		MEMCPY(o, data, len);
		INCPTR(len, o);
	}
	for (i = len; i < padded; i++)
		PUTCHAR(0, o);
	return o;
}

/* Send one EAP packet inside the tunnel as an EAP-Message AVP
 * (RFC 5281 10.1/11.2.1), padded to a 4-octet boundary. */
static void ttls_send_eap_avp(eap_ttls_state *st, const u_char *pkt, int len) {
	u_char avp[TTLS_AVP_HDR_LEN + 4 + 4400];
	u_char *o;

	if (len > 4400) {
		ppp_error("TTLS: inner EAP packet too large (%d)", len);
		ttls_fail(st);
		return;
	}
	o = ttls_put_avp(avp, avp + sizeof(avp), TTLS_AVP_EAP_MESSAGE, pkt, len);
	if (o == NULL) {
		ttls_fail(st);
		return;
	}
	ttls_dump("TX inner AVP", avp, (int)(o - avp));
	ttls_tls_write(st, avp, (int)(o - avp));
}

/* Inner EAP-MSCHAPv2 engine callbacks */
static void ttls_mschap_send(void *arg, u_char eap_id, const u_char *payload, int len) {
	eap_ttls_state *st = (eap_ttls_state *)arg;
	u_char pkt[EAP_HEADERLEN + 1 + 256];
	u_char *o = pkt;

	/* Inner responses carry the inner request's id */
	PUTCHAR(EAP_RESPONSE, o);
	PUTCHAR(eap_id, o);
	PUTSHORT(EAP_HEADERLEN + 1 + len, o);
	PUTCHAR(EAPT_MSCHAPV2, o);
	MEMCPY(o, payload, len);
	INCPTR(len, o);
	ttls_send_eap_avp(st, pkt, (int)(o - pkt));
}

/*
 * Derive the MPPE keys for the SSTP Call Connected crypto binding
 * (RFC 5281 9.1: TLS key material, label "ttls keying material", 64 octets;
 * MS-MPPE-Recv-Key = first 32 octets (NAS recv = client send),
 * MS-MPPE-Send-Key = next 32; stored client-perspective).
 */
static void ttls_derive_mppe_keys(eap_ttls_state *st) {
	u_char keymat[64];

	if (st->pcb->settings.eap_mppe_keys_ok)
		return;
	if (SSL_export_keying_material(st->ssl, keymat, sizeof(keymat),
	    "ttls keying material", 20, NULL, 0, 0) != 1) {
		ppp_error("TTLS: TLS key material export failed (MPPE keys)");
		return;
	}
	MEMCPY(st->pcb->settings.eap_mppe_send_key, keymat, 32);
	MEMCPY(st->pcb->settings.eap_mppe_recv_key, keymat + 32, 32);
	st->pcb->settings.eap_mppe_keys_ok = 1;
	ppp_info("TTLS: MPPE keys derived from the TLS key material");
	BZERO(keymat, sizeof(keymat));
}

static void ttls_mschap_complete(void *arg, int verified) {
	eap_ttls_state *st = (eap_ttls_state *)arg;
	if (verified) {
		ppp_info("TTLS: inner EAP-MSCHAPv2 authentication verified");
		ttls_derive_mppe_keys(st);
		st->inner_verified = 1;
	} else {
		ppp_error("TTLS: inner EAP-MSCHAPv2 authentication failed");
		ttls_fail(st);
	}
}

/* Inner EAP-TLS engine callbacks */
static void ttls_inner_tls_send(void *arg, u_char eap_id, const u_char *payload, int len) {
	eap_ttls_state *st = (eap_ttls_state *)arg;
	u_char pkt[EAP_HEADERLEN + 1 + 4110];
	u_char *o = pkt;

	PUTCHAR(EAP_RESPONSE, o);
	PUTCHAR(eap_id, o);
	PUTSHORT(EAP_HEADERLEN + 1 + len, o);
	PUTCHAR(EAPT_TLS, o);
	MEMCPY(o, payload, len);
	INCPTR(len, o);
	ttls_send_eap_avp(st, pkt, (int)(o - pkt));
}

static void ttls_inner_tls_done(void *arg, int ok) {
	eap_ttls_state *st = (eap_ttls_state *)arg;
	if (!ok) {
		ppp_error("TTLS: inner EAP-TLS authentication failed");
		ttls_fail(st);
		return;
	}
	/* The MPPE keys come from the TTLS TLS session regardless of the
	 * inner method; derive them as soon as the inner tunnel is up. */
	ttls_derive_mppe_keys(st);
	ppp_info("TTLS: inner EAP-TLS handshake complete");
	/* Mutual TLS completed: the server accepted our certificate during
	 * the handshake; the auth verdict arrives as the cleartext EAP
	 * Success/Failure, which the eap.c gate must now allow. */
	st->inner_verified = 1;
}

/* Send an inner EAP-Response/Identity with the real username.  Used to
 * answer an inner Identity-Request and to initiate the inner exchange:
 * per RFC 5281 11.2.1 the client begins phase 2 by tunnelling
 * EAP-Response/Identity (FreeRADIUS prods for it with an empty
 * L-flagged frame rather than sending an Identity-Request). */
static void ttls_send_identity(eap_ttls_state *st, u_char iid) {
	u_char resp[EAP_HEADERLEN + 1 + MAXNAMELEN];
	u_char *o = resp;
	const char *name = st->pcb->eap.es_client.ea_name;
	int namelen = st->pcb->eap.es_client.ea_namelen;

	PUTCHAR(EAP_RESPONSE, o);
	PUTCHAR(iid, o);
	PUTSHORT(EAP_HEADERLEN + 1 + namelen, o);
	PUTCHAR(EAPT_IDENTITY, o);
	MEMCPY(o, name, namelen);
	INCPTR(namelen, o);
	st->inner_started = 1;
	ttls_send_eap_avp(st, resp, (int)(o - resp));
}

/*
 * TTLS-PAP phase 2 (RFC 5281 11.2.5): User-Name + User-Password AVPs.
 * The password is NUL-padded to a 16-octet multiple (obfuscates length);
 * it is NOT RADIUS-encrypted — the TLS tunnel provides the secrecy.
 */
static void ttls_send_pap(eap_ttls_state *st) {
	u_char buf[512];
	u_char *o = buf;
	u_char padded[256];
	const char *name = st->pcb->eap.es_client.ea_name;
	int namelen = st->pcb->eap.es_client.ea_namelen;
	const char *secret = st->pcb->settings.passwd;
	int slen = st->pcb->settings.passwd ? (int)strlen(secret) : 0;
	int plen;

	if (slen <= 0 || slen > 255) {
		ppp_error("TTLS-PAP: no usable password");
		ttls_fail(st);
		return;
	}
	plen = (slen + 15) & ~15;		/* pad to a multiple of 16 */
	BZERO(padded, sizeof(padded));
	MEMCPY(padded, secret, slen);

	o = ttls_put_avp(o, buf + sizeof(buf), TTLS_AVP_USER_NAME,
	    (const u_char *)name, namelen);
	if (o != NULL)
		o = ttls_put_avp(o, buf + sizeof(buf), TTLS_AVP_USER_PASSWORD,
		    padded, plen);
	BZERO(padded, sizeof(padded));
	if (o == NULL) {
		ttls_fail(st);
		return;
	}
	ppp_info("TTLS: inner PAP (User-Name + User-Password, %d+%d AVP bytes)",
	    namelen, plen);
	/* NOTE: deliberately no payload dump — the password is inside. */
	ttls_tls_write(st, buf, (int)(o - buf));
	st->inner_started = 1;
	/* The cleartext EAP Success/Failure is the auth verdict; the SSTP
	 * binding keys are derivable as soon as the tunnel is up. */
	ttls_derive_mppe_keys(st);
	st->inner_verified = 1;
}

/*
 * TTLS-CHAP phase 2 (RFC 5281 11.2.2): the challenge is derived from the
 * TLS session ("ttls challenge" exporter, 17 octets: challenge[16] +
 * identifier[1]); CHAP-Password = id | MD5(id | password | challenge).
 */
static void ttls_send_chap(eap_ttls_state *st) {
	u_char buf[512];
	u_char *o = buf;
	u_char chal[17];
	u_char resp[17];	/* id + MD5 */
	u_char hash[16];
	const char *name = st->pcb->eap.es_client.ea_name;
	int namelen = st->pcb->eap.es_client.ea_namelen;
	const char *secret = st->pcb->settings.passwd;
	int slen = st->pcb->settings.passwd ? (int)strlen(secret) : 0;
	lwip_md5_context md5;

	if (slen <= 0 || slen > 255) {
		ppp_error("TTLS-CHAP: no usable password");
		ttls_fail(st);
		return;
	}
	if (SSL_export_keying_material(st->ssl, chal, sizeof(chal),
	    "ttls challenge", 14, NULL, 0, 0) != 1) {
		ppp_error("TTLS-CHAP: TLS challenge export failed");
		ttls_fail(st);
		return;
	}
	lwip_md5_init(&md5);
	lwip_md5_starts(&md5);
	lwip_md5_update(&md5, chal + 16, 1);		/* identifier octet */
	lwip_md5_update(&md5, (const u_char *)secret, slen);
	lwip_md5_update(&md5, chal, 16);		/* challenge */
	lwip_md5_finish(&md5, hash);
	lwip_md5_free(&md5);

	resp[0] = chal[16];				/* CHAP Identifier */
	MEMCPY(resp + 1, hash, 16);

	o = ttls_put_avp(o, buf + sizeof(buf), TTLS_AVP_USER_NAME,
	    (const u_char *)name, namelen);
	if (o != NULL)
		o = ttls_put_avp(o, buf + sizeof(buf), TTLS_AVP_CHAP_CHALLENGE,
		    chal, 16);
	if (o != NULL)
		o = ttls_put_avp(o, buf + sizeof(buf), TTLS_AVP_CHAP_PASSWORD,
		    resp, sizeof(resp));
	BZERO(chal, sizeof(chal));
	BZERO(resp, sizeof(resp));
	BZERO(hash, sizeof(hash));
	if (o == NULL) {
		ttls_fail(st);
		return;
	}
	ppp_info("TTLS: inner CHAP (User-Name + CHAP-Challenge + CHAP-Password)");
	ttls_tls_write(st, buf, (int)(o - buf));
	st->inner_started = 1;
	ttls_derive_mppe_keys(st);
	st->inner_verified = 1;
}

/* Initiate phase 2 per the configured inner method. */
static void ttls_initiate_inner(eap_ttls_state *st, u_char id) {
	switch (st->pcb->settings.eap_ttls_inner) {
	case EAP_TTLS_INNER_PAP:
		ttls_send_pap(st);
		break;
	case EAP_TTLS_INNER_CHAP:
		ttls_send_chap(st);
		break;
	case EAP_TTLS_INNER_EAP:
	default:
		ttls_send_identity(st, id);
		break;
	}
}

/* Handle one complete inner EAP packet (from an EAP-Message AVP). */
static void ttls_handle_inner_eap(eap_ttls_state *st, const u_char *pkt, int len) {
	u_char code, iid, typenum;
	u_short elen;

	if (len < EAP_HEADERLEN)
		return;
	code = pkt[0];
	iid = pkt[1];
	elen = (u_short)((pkt[2] << 8) | pkt[3]);
	if (elen < EAP_HEADERLEN || elen > len)
		return;

	switch (code) {
	case EAP_REQUEST:
		if (elen < EAP_HEADERLEN + 1)
			return;
		typenum = pkt[4];
		switch (typenum) {
		case EAPT_IDENTITY:
			/* Inside the tunnel always answer with the real username */
			ppp_info("TTLS: inner identity request, answering as the real user");
			ttls_send_identity(st, iid);
			break;
		case EAPT_MSCHAPV2: {
			char secret[MAXSECRETLEN];
			int secret_len;
			/* Certificate profile: negotiate inner EAP-TLS instead */
			if (st->pcb->settings.eap_tls_cert_pem != NULL &&
			    !st->inner_tls_started && !st->nak_tls_sent) {
				u_char nak[EAP_HEADERLEN + 2];
				u_char *o = nak;
				st->nak_tls_sent = 1;
				ppp_info("TTLS: certificate profile, NAKing inner MSCHAPv2 in favor of EAP-TLS");
				PUTCHAR(EAP_RESPONSE, o);
				PUTCHAR(iid, o);
				PUTSHORT(EAP_HEADERLEN + 2, o);
				PUTCHAR(EAPT_NAK, o);
				PUTCHAR(EAPT_TLS, o);
				ttls_send_eap_avp(st, nak, (int)(o - nak));
				break;
			}
			if (!st->mschap_started) {
				if (!get_secret(st->pcb, st->pcb->eap.es_client.ea_name, "",
				    secret, &secret_len, 0)) {
					ppp_error("TTLS: no secret for inner authentication");
					ttls_fail(st);
					return;
				}
				st->mschap_started = 1;
				eap_mschapv2_init(&st->mschap, st->pcb->eap.es_client.ea_name,
				    st->pcb->settings.passwd, secret_len, 1,
				    ttls_mschap_send, st, ttls_mschap_complete, st);
				BZERO(secret, sizeof (secret));
			}
			st->mschap.eap_id = iid;
			eap_mschapv2_handle(&st->mschap, iid, pkt + EAP_HEADERLEN + 1,
			    elen - EAP_HEADERLEN - 1);
			break;
		}
		case EAPT_TLS:
			/* Inner EAP-TLS: certificate authentication inside the tunnel */
			if (st->pcb->settings.eap_tls_cert_pem == NULL ||
			    st->pcb->settings.eap_tls_key_pem == NULL) {
				ppp_error("TTLS: inner EAP-TLS offered but no client certificate configured; failing");
				ttls_fail(st);
				break;
			}
			if (!st->inner_tls_started) {
				if (eap_tls_engine_init(&st->inner_tls, st->pcb, EAPTLS_TUNNELED_MTU,
				    ttls_inner_tls_send, st, ttls_inner_tls_done, st) != 0) {
					ppp_error("TTLS: out of memory (inner EAP-TLS)");
					ttls_fail(st);
					break;
				}
				st->inner_tls_started = 1;
				ppp_info("TTLS: inner EAP-TLS (certificate authentication)");
			}
			eap_tls_engine_input(st->inner_tls, iid, pkt + EAP_HEADERLEN + 1,
			    elen - EAP_HEADERLEN - 1);
			break;
		default:
			ppp_error("TTLS: unsupported inner EAP type %d; failing", typenum);
			ttls_fail(st);
			break;
		}
		break;

	case EAP_SUCCESS:
		ppp_info("TTLS: inner EAP success");
		ttls_derive_mppe_keys(st);
		st->inner_verified = 1;
		break;

	case EAP_FAILURE:
		ppp_error("TTLS: inner EAP failure");
		ttls_fail(st);
		break;

	default:
		ppp_error("TTLS: unexpected inner EAP code %d", code);
		break;
	}
}

/* Parse the tunnelled AVP sequence (RFC 5281 10.1/10.2); returns the
 * number of octets consumed (complete AVPs only). */
static int ttls_handle_avps(eap_ttls_state *st, const u_char *data, int len) {
	const u_char *p = data;
	int l = len;

	while (l >= TTLS_AVP_HDR_LEN) {
		u32_t code, avp_len;
		u_char flags;
		const u_char *vend;
		int hdr = TTLS_AVP_HDR_LEN;
		int padded;

		code = ((u32_t)p[0] << 24) | ((u32_t)p[1] << 16) |
		    ((u32_t)p[2] << 8) | (u32_t)p[3];
		flags = p[4];
		avp_len = ((u32_t)p[5] << 16) | ((u32_t)p[6] << 8) | (u32_t)p[7];
		if (avp_len < TTLS_AVP_HDR_LEN) {
			ppp_error("TTLS: bogus AVP length %u", avp_len);
			ttls_fail(st);
			return -1;
		}
		if (avp_len > (u32_t)l)
			break;	/* wait for the rest of this AVP */
		vend = NULL;
		if (flags & TTLS_AVP_FLAG_VENDOR) {
			if (avp_len < TTLS_AVP_HDR_LEN + 4) {
				ppp_error("TTLS: truncated vendor AVP");
				ttls_fail(st);
				return -1;
			}
			vend = p + TTLS_AVP_HDR_LEN;
			hdr += 4;
		}
		if (code == TTLS_AVP_EAP_MESSAGE && vend == NULL) {
			ttls_dump("inner EAP", p + hdr, (int)(avp_len - hdr));
			ttls_handle_inner_eap(st, p + hdr, (int)(avp_len - hdr));
			if (st->failed)
				return -1;
		} else if (flags & TTLS_AVP_FLAG_MANDATORY) {
			ppp_error("TTLS: unsupported mandatory AVP code %u; failing", code);
			ttls_fail(st);
			return -1;
		} else {
			ppp_info("TTLS: ignoring AVP code %u (len %u)", code, avp_len);
		}
		padded = (int)((avp_len + 3) & ~3u);
		if (padded > l)
			padded = l;
		p += padded;
		l -= padded;
	}
	return (int)(p - data);
}

/* Read and dispatch TLS application data (AVP sequences). */
static void ttls_read_inner(eap_ttls_state *st, u_char id) {
	u_char buf[4096];
	int n;

	LWIP_UNUSED_ARG(id);
	for (;;) {
		n = SSL_read(st->ssl, buf, sizeof(buf));
#if EAP_TTLS_DEBUG_DUMP
		ppp_info("TTLS: SSL_read -> %d (pending %d)", n, SSL_pending(st->ssl));
#endif
		if (n <= 0) {
			int err = SSL_get_error(st->ssl, n);
#if EAP_TTLS_DEBUG_DUMP
			ppp_info("TTLS: SSL_read err %d", err);
#endif
			if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) {
				ppp_error("TTLS: inner TLS read failed (%d)", err);
				ttls_fail(st);
				return;
			}
			break;
		}
		ttls_dump("SSL_read bytes", buf, n);
		if (st->in_eap_len + n > TTLS_RX_MAX) {
			ppp_error("TTLS: inner buffer overflow");
			ttls_fail(st);
			return;
		}
		MEMCPY(st->in_eap + st->in_eap_len, buf, n);
		st->in_eap_len += n;
	}

	if (st->in_eap_len > 0) {
		int used = ttls_handle_avps(st, st->in_eap, st->in_eap_len);
		if (st->failed)
			return;
		if (used > 0) {
			st->in_eap_len -= used;
			if (st->in_eap_len > 0)
				memmove(st->in_eap, st->in_eap + used, st->in_eap_len);
		}
	}
}

/* Feed one complete TLS blob (or a handshake-start frame) into BoringSSL. */
static void ttls_feed_tls(eap_ttls_state *st, u_char id, const u_char *data, int len) {
	if (len > 0)
		BIO_write(st->net_bio, data, len);

	if (!st->handshake_done) {
		int ret = SSL_do_handshake(st->ssl);
		if (ret == 1) {
			st->handshake_done = 1;
			st->phase = TTLS_PHASE_INNER;
			ppp_info("TTLS: TLS handshake complete (%s)", SSL_get_version(st->ssl));
			if (!ttls_verify_cert(st)) {
				ttls_fail(st);
				return;
			}
			/* RFC 5281 11.2: the client initiates phase 2 with the
			 * configured inner method. */
			ppp_info("TTLS: initiating inner authentication (method %d)",
			    st->pcb->settings.eap_ttls_inner);
			ttls_initiate_inner(st, id);
		} else {
			int err = SSL_get_error(st->ssl, ret);
			if (err != SSL_ERROR_WANT_READ) {
				ppp_error("TTLS: TLS handshake failed (%d)", err);
#if EAP_TTLS_DEBUG_DUMP
				{
					unsigned long e;
					while ((e = ERR_get_error()) != 0) {
						char es[160];
						ERR_error_string_n(e, es, sizeof(es));
						ppp_error("TTLS: OpenSSL: %s", es);
					}
				}
#endif
				ttls_fail(st);
				return;
			}
		}
		ttls_flush(st, id);
		return;
	}

	ttls_read_inner(st, id);
	if (st->failed)
		return;
	ttls_flush(st, id);
}

static eap_ttls_state *ttls_new(ppp_pcb *pcb) {
	eap_ttls_state *st;

	st = (eap_ttls_state *)malloc(sizeof(*st));
	if (st == NULL)
		return NULL;
	BZERO(st, sizeof(*st));
	st->pcb = pcb;

	st->ssl_ctx = SSL_CTX_new(TLS_client_method());
	if (st->ssl_ctx == NULL) {
		free(st);
		return NULL;
	}
	/* Certificate policy is enforced by ttls_verify_cert (fingerprint
	 * comparison against the outer connection), not by BoringSSL's
	 * chain verifier. */
	SSL_CTX_set_verify(st->ssl_ctx, SSL_VERIFY_NONE, NULL);
	if (pcb->settings.eap_disable_legacy_tls)
		SSL_CTX_set_min_proto_version(st->ssl_ctx, TLS1_2_VERSION);
	if (!pcb->settings.eap_tls13_enabled)
		SSL_CTX_set_max_proto_version(st->ssl_ctx, TLS1_2_VERSION);

	st->ssl = SSL_new(st->ssl_ctx);
	if (st->ssl == NULL) {
		SSL_CTX_free(st->ssl_ctx);
		free(st);
		return NULL;
	}
	{
		/* BoringSSL memory-BIO pattern: the SSL object owns one end of a
		 * BIO pair for both directions; the engine uses the other end
		 * (BIO_write = data from the server, BIO_read = data to send). */
		BIO *ssl_bio = NULL, *net_bio = NULL;
		if (BIO_new_bio_pair(&ssl_bio, TTLS_RX_MAX, &net_bio, TTLS_TXQ_MAX) != 1) {
			SSL_free(st->ssl);
			SSL_CTX_free(st->ssl_ctx);
			free(st);
			return NULL;
		}
		SSL_set_bio(st->ssl, ssl_bio, ssl_bio);	/* SSL owns ssl_bio */
		st->net_bio = net_bio;
	}
	SSL_set_connect_state(st->ssl);

	pcb->eap.es_ttls = st;
	return st;
}

void eap_ttls_input(ppp_pcb *pcb, u_char id, const u_char *payload, int len) {
	eap_ttls_state *st = ttls_get(pcb);
	u_char flags;
	const u_char *data;
	int dlen;

	if (st == NULL) {
		st = ttls_new(pcb);
		if (st == NULL) {
			ppp_error("TTLS: out of memory");
			auth_withpeer_fail(pcb, PPP_EAP);
			return;
		}
	}
	if (st->failed)
		return;

	/* Empty request: fragment ack (or a liveness probe) */
	if (len == 0) {
		if (st->txq_off < st->txq_len)
			ttls_send_fragment(st, id);
		else
			ttls_send_ack(st, id);
		return;
	}

	flags = payload[0];
	data = payload + 1;
	dlen = len - 1;
	ttls_dump("RX frame", payload, len);

	if (flags & TTLS_FLAGS_START) {
		/* Low 3 bits of the flags octet carry the TTLS version;
		 * RFC 5281 is version 0 */
		st->ttls_version = flags & 0x07;
		ppp_info("TTLS: start, version %d (TLS handshake begins)", st->ttls_version);
	}

	if (flags & TTLS_FLAGS_LENGTH_INCLUDED) {
		u32_t total;
		if (dlen < 4)
			return;
		total = ((u32_t)data[0] << 24) | ((u32_t)data[1] << 16) |
		    ((u32_t)data[2] << 8) | (u32_t)data[3];
		data += 4;
		dlen -= 4;
		/* FreeRADIUS sets the L bit on EVERY fragment of a message
		 * (Windows sets it only on the first); only treat it as the
		 * start of a new message when no reassembly is in progress. */
		if (st->rx_len == 0)
			st->rx_total = total;
	}

	if (st->rx_len + dlen > TTLS_RX_MAX) {
		ppp_error("TTLS: reassembly buffer overflow");
		ttls_fail(st);
		return;
	}
	MEMCPY(st->rx + st->rx_len, data, dlen);
	st->rx_len += dlen;

	if (flags & TTLS_FLAGS_MORE_FRAGMENTS) {
		/* More fragments follow; ack (or piggyback pending output) */
		if (st->txq_off < st->txq_len)
			ttls_send_fragment(st, id);
		else
			ttls_send_ack(st, id);
		return;
	}

	if (st->rx_len == 0 && (flags & TTLS_FLAGS_START) == 0) {
		/* A flags-only frame acks our fragment: send the next one if
		 * there is one queued.  Empty frame otherwise: FreeRADIUS prods
		 * for the client-initiated inner exchange with an empty
		 * L-flagged frame; answer by initiating (once). */
		if (st->txq_off < st->txq_len)
			ttls_send_fragment(st, id);
		else if (st->handshake_done && !st->inner_started)
			ttls_initiate_inner(st, id);
		else
			ttls_send_ack(st, id);
		return;
	}

	{
		u_char blob[TTLS_RX_MAX];
		int blen = st->rx_len;
		MEMCPY(blob, st->rx, blen);
		st->rx_len = 0;
		st->rx_total = 0;
		ttls_feed_tls(st, id, blob, blen);
	}
}

#endif /* PPP_SUPPORT && EAP_SUPPORT && MSCHAP_SUPPORT */
