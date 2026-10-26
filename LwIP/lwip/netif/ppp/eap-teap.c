/*
 * eap-teap.c - TEAP (EAP type 55) client, RFC 7170 (version 1).
 *
 * Wire flow (client side):
 *   <- EAP-Request/TEAP, flags S|1 (start, version 1)
 *   -> EAP-Response/TEAP: TLS ClientHello   (L flag + length, fragmented)
 *   <- ... TLS handshake records (L/M fragmentation both ways) ...
 *   <- TLS app data: EAP-Payload TLV { EAP-Request/Identity }
 *   -> EAP-Payload TLV { EAP-Response/Identity (real username) }
 *   <- EAP-Payload TLV { EAP-Request/MSCHAPv2 Challenge }
 *   -> EAP-Payload TLV { EAP-Response/MSCHAPv2 }
 *   <- EAP-Payload TLV { EAP-Request/MSCHAPv2 Success (S= verified) }
 *   -> EAP-Payload TLV { inner Success ack }
 *   <- Crypto-Binding TLV (request) | Intermediate-Result TLV (=1)
 *   -> Crypto-Binding TLV (response) | Intermediate-Result TLV (=1)
 *   <- Result TLV (=1, success)
 *   -> Result TLV (=1)
 *   <- cleartext EAP Success
 *
 * TEAP TLVs (RFC 7170 4.2): 2-octet type (M bit 0x8000) + 2-octet
 * length + value, no padding.
 *
 * Crypto-Binding TLV (RFC 7170 4.2.13, version 1):
 *   IMCK = TLS-PRF(S-IMCK[j-1] (zeros for j=1),
 *          "Inner Methods Compound Keys" | IMSK, 60)
 *   CMK  = last 20 octets of IMCK
 *   Compound MAC = HMAC-SHA384(CMK, TLV header | binding (MACs zeroed)
 *                  | EAP type (55) | Outer TLVs)[0..20]
 * The TLS PRF digest follows the negotiated cipher (SHA384 for
 * ECDHE-RSA-AES256-GCM-SHA384, which is what FreeRADIUS picks).
 * The HMAC-SHA384 is truncated to the 20-octet MAC field.
 *
 * IMSK interop note (rfc7170bis / EAP-FAST style errata EID5768/5770/
 * 5775): the IMSK is the inner EAP-MSCHAPv2 MSK with its two 16-octet
 * halves SWAPPED relative to the peer's send|recv order, i.e.
 * recv|send.  FreeRADIUS 3.2.x and Windows 10/11 do the swap; the plain
 * RFC 7170 ordering is rejected.  The eap_teap_test_noswap test hook
 * selects the plain order (matrix row 6).
 *
 * EAP-MSCHAPv2 provides no EMSK, so only the MSK Compound MAC is used
 * (Crypto-Binding flags = CMAC_MSK).
 *
 * Inner TLS certificate policy: same as the TTLS engine (fingerprint
 * comparison against the outer SSTP leaf; a mismatch — legitimate for
 * split-host RRAS->RADIUS relaying — is logged loudly with both
 * fingerprints and allowed; strict split-host pinning is future work).
 *
 * The TLS-over-EAP transport mirrors the PEAP/TTLS engines, including
 * the FreeRADIUS every-fragment-L reassembly handling.
 */

#include "netif/ppp/ppp_opts.h"
#if PPP_SUPPORT && EAP_SUPPORT && MSCHAP_SUPPORT  /* don't build if not configured for use in lwipopts.h */

#include "netif/ppp/ppp_impl.h"
#include "netif/ppp/eap.h"
#include "netif/ppp/eap-mschapv2.h"
#include "netif/ppp/chap_ms.h"
#include "netif/ppp/eap-teap.h"
#include "netif/ppp/eap-tls.h"
#include "netif/ppp/magic.h"

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/x509.h>

#include <string.h>
#include <stdlib.h>

#ifndef EAP_TEAP_DEBUG_DUMP
#define EAP_TEAP_DEBUG_DUMP 0
#endif
#if EAP_TEAP_DEBUG_DUMP
static void teap_dump(const char *what, const u_char *p, int len) {
	char buf[400];
	int off = 0, i;
	buf[0] = '\0';
	if (p != NULL) {
		for (i = 0; i < len && off < (int)sizeof(buf) - 3; i++)
			off += snprintf(buf + off, sizeof(buf) - off, "%02x", p[i]);
	}
	ppp_info("TEAP %s (%d): %s", what, len, buf);
}
#else
#define teap_dump(...)
#endif

#define TEAP_EAP_MTU	1000	/* max TLS bytes per EAP frame */
#define TEAP_RX_MAX	16384	/* reassembly buffer */
#define TEAP_TXQ_MAX	16384	/* pending TLS output */

/* TEAP TLV types (RFC 7170 4.2) */
#define TEAP_TLV_RESULT		3
#define TEAP_TLV_NAK		4
#define TEAP_TLV_ERROR		5
#define TEAP_TLV_EAP_PAYLOAD	9
#define TEAP_TLV_INTERMED_RESULT 10
#define TEAP_TLV_CRYPTO_BINDING	12
#define TEAP_TLV_MANDATORY	0x8000
#define TEAP_TLV_TYPE_MASK	0x3fff

#define TEAP_TLV_RESULT_SUCCESS	1
#define TEAP_TLV_RESULT_FAILURE	2

/* Crypto-Binding TLV (RFC 7170 4.2.13) */
#define TEAP_CB_VERSION		1
#define TEAP_CB_SUBTYPE_REQUEST	0
#define TEAP_CB_SUBTYPE_RESPONSE 1
#define TEAP_CB_FLAGS_CMAC_MSK	2
#define TEAP_CB_LEN		76	/* rsvd,ver,rver,subtype,nonce32,emskMAC20,mskMAC20 */
#define TEAP_CMK_LEN		20
#define TEAP_IMSK_LEN		32
#define TEAP_IMCK_LABEL		"Inner Methods Compound Keys"	/* 27, no NUL */

enum teap_phase {
	TEAP_PHASE_HANDSHAKE = 0,
	TEAP_PHASE_INNER,
};

struct eap_teap_state {
	ppp_pcb *pcb;
	SSL_CTX *ssl_ctx;
	SSL *ssl;
	BIO *net_bio;		/* our end of the BIO pair (SSL owns the other) */
	enum teap_phase phase;
	int handshake_done;
	int inner_verified;	/* inner EAP-MSCHAPv2 completed */
	int failed;

	/* TLS output -> EAP fragmentation */
	u_char txq[TEAP_TXQ_MAX];
	int txq_off, txq_len;

	/* EAP fragment reassembly (server -> client TLS records) */
	u_char rx[TEAP_RX_MAX];
	int rx_len;
	u32_t rx_total;

	/* inner TLV stream reassembly (TLS app data) */
	u_char in_eap[TEAP_RX_MAX];
	int in_eap_len;

	eap_mschapv2_ctx mschap;
	int mschap_started;
	int nak_sent;		/* inner EAP-Naks sent (method negotiation) */
	int teap_version;	/* negotiated TEAP version (S frame, low 3 bits) */

	/* Inner EAP-TLS (certificate authentication inside the tunnel) */
	struct eap_tls_engine *inner_tls;
	int inner_tls_started;
	int nak_tls_sent;	/* inner method negotiation: NAKed for EAP-TLS once */
	u_char inner_km[64];	/* inner EAP-TLS key material (IMSK source) */
	int inner_km_ok;

	/* Crypto-Binding state */
	u_char cmk[TEAP_CMK_LEN];
	u_char simck[40];	/* S-IMCK[j] (session key seed for j=0) */
	const EVP_MD *md;	/* negotiated cipher's PRF digest */
	int cmk_ok;
	u_char server_nonce[32];
	u_char server_outer[256];	/* Outer TLVs from the server's Start frame */
	int server_outer_len;
};

typedef struct eap_teap_state eap_teap_state;

/* Test hook for the SSTPTest harness (matrix row 6): use the plain
 * RFC 7170 IMSK ordering (no half swap) — the server must reject. */
int eap_teap_test_noswap = 0;

static eap_teap_state *teap_get(ppp_pcb *pcb) {
	return (eap_teap_state *)pcb->eap.es_teap;
}

int eap_teap_active(ppp_pcb *pcb) {
	return teap_get(pcb) != NULL;
}

int eap_teap_done(ppp_pcb *pcb) {
	eap_teap_state *st = teap_get(pcb);
	return st != NULL && st->inner_verified;
}

static void teap_fail(eap_teap_state *st) {
	ppp_pcb *pcb = st->pcb;
	st->failed = 1;
	eap_teap_free(pcb);
	pcb->eap.es_client.ea_state = eapBadAuth;
	auth_withpeer_fail(pcb, PPP_EAP);
}

void eap_teap_free(ppp_pcb *pcb) {
	eap_teap_state *st = teap_get(pcb);
	if (st == NULL)
		return;
	pcb->eap.es_teap = NULL;
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
static int teap_verify_cert(eap_teap_state *st) {
	if (!st->pcb->settings.peap_cert_check) {
		ppp_warn("TEAP: inner TLS certificate NOT verified (allowInsecure is on)");
		return 1;
	}
	X509 *cert = SSL_get_peer_certificate(st->ssl);
	if (cert == NULL) {
		ppp_error("TEAP: server presented no inner TLS certificate");
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
		ppp_info("TEAP: inner TLS certificate fingerprint matches the outer connection");
		return 1;
	}
	{
		char inner_fp[65], outer_fp[65];
		int i;
		for (i = 0; i < 32; i++) {
			snprintf(inner_fp + 2 * i, 3, "%02x", digest[i]);
			snprintf(outer_fp + 2 * i, 3, "%02x",
			    st->pcb->settings.peap_cert_sha256[i]);
		}
		inner_fp[64] = outer_fp[64] = '\0';
		ppp_warn("TEAP: inner EAP TLS certificate differs from the SSTP outer connection");
		ppp_warn("TEAP: inner leaf SHA256 %s", inner_fp);
		ppp_warn("TEAP: outer leaf SHA256 %s (this is expected when the "
		    "EAP server is a different host than the SSTP concentrator; "
		    "accepted for now, strict split-host pinning is not implemented yet)",
		    outer_fp);
	}
	return 1;
}

/* TLS 1.2 P_hash with the negotiated cipher's PRF digest.
 * label_len is explicit because TEAP key labels may include a trailing
 * NUL (RFC 7170 5.4 key labels are NUL-terminated strings). */
static void teap_p_hash(const EVP_MD *md, const u_char *secret, int secret_len,
			const char *label, int label_len, const u_char *seed, int seed_len,
			u_char *out, int outlen) {
	u_char a[48];	/* largest HMAC output (SHA384) */
	u_char data[256];
	int pos = 0;
	unsigned int a_len = 0;

	/* A(1) = HMAC(secret, label|seed) */
	MEMCPY(data, label, label_len);
	if (seed_len > 0)
		MEMCPY(data + label_len, seed, seed_len);
	HMAC(md, secret, secret_len, data, label_len + seed_len, a, &a_len);
	while (pos < outlen) {
		int dlen = 0, take;
		/* out(i) = HMAC(secret, A(i) | label | seed) */
		MEMCPY(data, a, a_len);
		dlen = a_len;
		MEMCPY(data + dlen, label, label_len);
		dlen += label_len;
		if (seed_len > 0) {
			MEMCPY(data + dlen, seed, seed_len);
			dlen += seed_len;
		}
		{
			unsigned int ol = 0;
			HMAC(md, secret, secret_len, data, dlen, out + pos, &ol);
			take = (int)ol;
		}
		if (take > outlen - pos)
			take = outlen - pos;
		pos += take;
		if (pos >= outlen)
			break;
		/* A(i+1) = HMAC(secret, A(i)) */
		{
			unsigned int al = 0;
			HMAC(md, secret, secret_len, a, a_len, a, &al);
			a_len = al;
		}
	}
	BZERO(a, sizeof(a));
	BZERO(data, sizeof(data));
}

/*
 * Derive the Compound MAC key (RFC 7170 5.1/5.2):
 *   S-IMCK[0] = TLS exporter "EXPORTER: teap session key seed" (40 octets)
 *   IMSK = inner EAP-MSCHAPv2 MSK halves swapped (recv|send), see header
 *   IMCK = TLS-PRF(S-IMCK[0], "Inner Methods Compound Keys" | IMSK, 60)
 *   CMK  = IMCK[40..60]
 * The PRF digest follows the negotiated cipher suite (SHA256 for
 * ECDHE-RSA-AES128-GCM-SHA256, which is what FreeRADIUS picks).
 */
static int teap_derive_cmk(eap_teap_state *st) {
	u_char send_key[16], recv_key[16], imsk[TEAP_IMSK_LEN], imck[60];

	if (st->cmk_ok)
		return 0;
	if (!st->mschap_started && !st->inner_tls_started) {
		ppp_error("TEAP: crypto-binding before inner authentication");
		return -1;
	}
	st->md = SSL_CIPHER_get_handshake_digest(SSL_get_current_cipher(st->ssl));
	if (st->md == NULL) {
		ppp_error("TEAP: cannot determine TLS PRF digest");
		return -1;
	}
	if (SSL_export_keying_material(st->ssl, st->simck, sizeof(st->simck),
	    "EXPORTER: teap session key seed", 31, NULL, 0, 0) != 1) {
		ppp_error("TEAP: TLS session key seed export failed");
		return -1;
	}
	if (st->inner_km_ok) {
		/* Inner EAP-TLS: the inner method's 32-octet MPPE keys (RFC 5216
		 * key material) — no half-swap (that quirk applies only to the
		 * 16-octet EAP-MSCHAPv2 keys). */
		MEMCPY(imsk, st->inner_km, TEAP_IMSK_LEN);
	} else {
		chapms2_eap_master_keys(st->mschap.secret, st->mschap.secret_len,
		    st->mschap.nt_response, send_key, recv_key);
		if (eap_teap_test_noswap) {
			/* TEST MODE (matrix row 6): plain RFC 7170 IMSK (send|recv) */
			ppp_warn("TEAP: TEST MODE noswap — using plain (unswapped) IMSK");
			MEMCPY(imsk, send_key, 16);
			MEMCPY(imsk + 16, recv_key, 16);
		} else {
			/* rfc7170bis / EAP-FAST style: halves swapped (recv|send) */
			MEMCPY(imsk, recv_key, 16);
			MEMCPY(imsk + 16, send_key, 16);
		}
	}
	teap_p_hash(st->md, st->simck, sizeof(st->simck), TEAP_IMCK_LABEL,
	    (int)strlen(TEAP_IMCK_LABEL), imsk, sizeof(imsk), imck, sizeof(imck));
	MEMCPY(st->simck, imck, sizeof(st->simck));	/* S-IMCK[j] = IMCK[0..40] */
	MEMCPY(st->cmk, imck + 40, sizeof(st->cmk));
	st->cmk_ok = 1;
	teap_dump("S-IMCK[0]", st->simck, 40);
	teap_dump("IMSK", imsk, TEAP_IMSK_LEN);
	teap_dump("CMK", st->cmk, TEAP_CMK_LEN);
	BZERO(send_key, sizeof(send_key));
	BZERO(recv_key, sizeof(recv_key));
	BZERO(imsk, sizeof(imsk));
	BZERO(imck, sizeof(imck));
	return 0;
}

/* Compound MAC: HMAC(CMK, buf)[0..20] with the cipher's PRF digest. */
static void teap_compound_mac(eap_teap_state *st, const u_char *buf, int buflen,
			      u_char mac[TEAP_CMK_LEN]) {
	u_char full[48];
	unsigned int mdlen = 0;
	HMAC(st->md, st->cmk, sizeof(st->cmk), buf, buflen, full, &mdlen);
	MEMCPY(mac, full, TEAP_CMK_LEN);
	BZERO(full, sizeof(full));
}

/* Build the Compound-MAC input buffer:
 * tlv_type(2) | tlv_length(2) | binding (MAC fields zeroed) | EAP type (55) |
 * Outer TLVs (server's, then peer's — peer sends none). */
static int teap_cb_mac_input(eap_teap_state *st, const u_char *binding76, u_char *buf, int buflen) {
	int o = 0;
	if (buflen < 2 + 2 + TEAP_CB_LEN + 1 + st->server_outer_len)
		return -1;
	buf[o++] = (TEAP_TLV_MANDATORY | TEAP_TLV_CRYPTO_BINDING) >> 8;
	buf[o++] = (TEAP_TLV_MANDATORY | TEAP_TLV_CRYPTO_BINDING) & 0xff;
	buf[o++] = 0;
	buf[o++] = TEAP_CB_LEN;
	MEMCPY(buf + o, binding76, TEAP_CB_LEN);
	BZERO(buf + o + 4 + 32, 40);	/* zero both Compound MAC fields */
	o += TEAP_CB_LEN;
	buf[o++] = EAPT_TEAP;
	if (st->server_outer_len > 0) {
		MEMCPY(buf + o, st->server_outer, st->server_outer_len);
		o += st->server_outer_len;
	}
	return o;
}

/* Drain pending TLS output into the tx queue. */
static void teap_drain(eap_teap_state *st) {
	for (;;) {
		int room = TEAP_TXQ_MAX - st->txq_len;
		int n;
		if (room <= 0)
			break;
		n = BIO_read(st->net_bio, st->txq + st->txq_len, room);
		if (n <= 0)
			break;
		st->txq_len += n;
	}
}

/* Send the next queued fragment (an EAP-Response/TEAP). */
static void teap_send_fragment(eap_teap_state *st, u_char id) {
	u_char payload[5 + TEAP_EAP_MTU];
	u_char *o = payload;
	int chunk = st->txq_len - st->txq_off;
	u_char flags = (u_char)(st->teap_version & 0x07);

	if (chunk > TEAP_EAP_MTU) {
		chunk = TEAP_EAP_MTU;
		flags |= TEAP_FLAGS_MORE_FRAGMENTS;
	}
	if (st->txq_off == 0) {
		/* First fragment of a TLS message: include the total TLS
		 * message length (Windows and wpa_supplicant behaviour). */
		flags |= TEAP_FLAGS_LENGTH_INCLUDED;
		PUTCHAR(flags, o);
		PUTLONG(st->txq_len, o);
	} else {
		PUTCHAR(flags, o);
	}
	MEMCPY(o, st->txq + st->txq_off, chunk);
	teap_dump("TX fragment", payload, (int)(o - payload) + chunk);
	eap_send_response(st->pcb, id, EAPT_TEAP, payload, (int)(o - payload) + chunk);
	st->txq_off += chunk;
	if (st->txq_off == st->txq_len) {
		st->txq_off = st->txq_len = 0;
	}
	/* further fragments are sent when the server's empty ack arrives */
}

/* TEAP fragment ack — a single flags octet carrying just the version. */
static void teap_send_ack(eap_teap_state *st, u_char id) {
	u_char flags = (u_char)(st->teap_version & 0x07);
	teap_dump("TX ack", &flags, 1);
	eap_send_response(st->pcb, id, EAPT_TEAP, &flags, 1);
}

/* Send whatever the TLS engine produced (or an ack if nothing). */
static void teap_flush(eap_teap_state *st, u_char id) {
	teap_drain(st);
	if (st->txq_len > 0)
		teap_send_fragment(st, id);
	else
		teap_send_ack(st, id);
}

/* Write one chunk of tunnelled data into the TLS tunnel. */
static void teap_tls_write(eap_teap_state *st, const u_char *pkt, int len) {
	int n = SSL_write(st->ssl, pkt, len);
	if (n <= 0) {
		int err = SSL_get_error(st->ssl, n);
		ppp_error("TEAP: inner TLS write failed (%d)", err);
		teap_fail(st);
	}
	teap_drain(st);
}

/* Append one TLV (type with M bit, 2-octet length, value) to a buffer. */
static u_char *teap_put_tlv(u_char *o, u_short type, int mandatory, const void *data, int len) {
	u_short t = type | (mandatory ? TEAP_TLV_MANDATORY : 0);
	PUTSHORT(t, o);
	PUTSHORT(len, o);
	if (len > 0) {
		MEMCPY(o, data, len);
		INCPTR(len, o);
	}
	return o;
}

/* Send a complete TLV sequence as TLS application data. */
static void teap_send_tlvs(eap_teap_state *st, const u_char *tlvs, int len) {
	teap_dump("TX TLVs", tlvs, len);
	teap_tls_write(st, tlvs, len);
}

/* Send one EAP packet inside an EAP-Payload TLV (RFC 7170 4.2.7). */
static void teap_send_eap_payload(eap_teap_state *st, const u_char *pkt, int len) {
	u_char buf[4 + 4400];
	u_char *o = buf;
	if (len > 4400) {
		ppp_error("TEAP: inner EAP packet too large (%d)", len);
		teap_fail(st);
		return;
	}
	o = teap_put_tlv(o, TEAP_TLV_EAP_PAYLOAD, 1, pkt, len);
	teap_send_tlvs(st, buf, (int)(o - buf));
}

/* Inner EAP-MSCHAPv2 engine callbacks */
static void teap_mschap_send(void *arg, u_char eap_id, const u_char *payload, int len) {
	eap_teap_state *st = (eap_teap_state *)arg;
	u_char pkt[EAP_HEADERLEN + 1 + 256];
	u_char *o = pkt;

	/* Inner responses carry the inner request's id */
	PUTCHAR(EAP_RESPONSE, o);
	PUTCHAR(eap_id, o);
	PUTSHORT(EAP_HEADERLEN + 1 + len, o);
	PUTCHAR(EAPT_MSCHAPV2, o);
	MEMCPY(o, payload, len);
	INCPTR(len, o);
	teap_send_eap_payload(st, pkt, (int)(o - pkt));
}

static void teap_mschap_complete(void *arg, int verified) {
	eap_teap_state *st = (eap_teap_state *)arg;
	if (verified) {
		ppp_info("TEAP: inner EAP-MSCHAPv2 authentication verified");
	} else {
		ppp_error("TEAP: inner EAP-MSCHAPv2 authentication failed");
		teap_fail(st);
	}
}

/* Inner EAP-TLS engine callbacks */
static void teap_inner_tls_send(void *arg, u_char eap_id, const u_char *payload, int len) {
	eap_teap_state *st = (eap_teap_state *)arg;
	u_char pkt[EAP_HEADERLEN + 1 + 4110];
	u_char *o = pkt;

	PUTCHAR(EAP_RESPONSE, o);
	PUTCHAR(eap_id, o);
	PUTSHORT(EAP_HEADERLEN + 1 + len, o);
	PUTCHAR(EAPT_TLS, o);
	MEMCPY(o, payload, len);
	INCPTR(len, o);
	teap_send_eap_payload(st, pkt, (int)(o - pkt));
}

static void teap_inner_tls_done(void *arg, int ok) {
	eap_teap_state *st = (eap_teap_state *)arg;
	if (!ok) {
		ppp_error("TEAP: inner EAP-TLS authentication failed");
		teap_fail(st);
		return;
	}
	/* The inner method's key material feeds the crypto-binding IMSK. */
	if (eap_tls_engine_export_km(st->inner_tls, st->inner_km) == 0)
		st->inner_km_ok = 1;
	ppp_info("TEAP: inner EAP-TLS handshake complete");
}

/* Handle one complete inner EAP packet (from an EAP-Payload TLV). */
static void teap_handle_inner_eap(eap_teap_state *st, const u_char *pkt, int len) {
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
		case EAPT_IDENTITY: {
			/* Inside the tunnel always answer with the real username */
			u_char resp[EAP_HEADERLEN + 1 + MAXNAMELEN];
			u_char *o = resp;
			const char *name = st->pcb->eap.es_client.ea_name;
			int namelen = st->pcb->eap.es_client.ea_namelen;
			ppp_info("TEAP: inner identity request, answering as the real user");
			PUTCHAR(EAP_RESPONSE, o);
			PUTCHAR(iid, o);
			PUTSHORT(EAP_HEADERLEN + 1 + namelen, o);
			PUTCHAR(EAPT_IDENTITY, o);
			MEMCPY(o, name, namelen);
			INCPTR(namelen, o);
			teap_send_eap_payload(st, resp, (int)(o - resp));
			break;
		}
		case EAPT_MSCHAPV2: {
			char secret[MAXSECRETLEN];
			int secret_len;
			/* Certificate profile: negotiate inner EAP-TLS instead */
			if (st->pcb->settings.eap_tls_cert_pem != NULL &&
			    !st->inner_tls_started && !st->nak_tls_sent) {
				u_char nak[EAP_HEADERLEN + 2];
				u_char *o = nak;
				st->nak_tls_sent = 1;
				ppp_info("TEAP: certificate profile, NAKing inner MSCHAPv2 in favor of EAP-TLS");
				PUTCHAR(EAP_RESPONSE, o);
				PUTCHAR(iid, o);
				PUTSHORT(EAP_HEADERLEN + 2, o);
				PUTCHAR(EAPT_NAK, o);
				PUTCHAR(EAPT_TLS, o);
				teap_send_eap_payload(st, nak, (int)(o - nak));
				break;
			}
			if (!st->mschap_started) {
				if (!get_secret(st->pcb, st->pcb->eap.es_client.ea_name, "",
				    secret, &secret_len, 0)) {
					ppp_error("TEAP: no secret for inner authentication");
					teap_fail(st);
					return;
				}
				st->mschap_started = 1;
				eap_mschapv2_init(&st->mschap, st->pcb->eap.es_client.ea_name,
				    st->pcb->settings.passwd, secret_len, 1,
				    teap_mschap_send, st, teap_mschap_complete, st);
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
				ppp_error("TEAP: inner EAP-TLS offered but no client certificate configured; failing");
				teap_fail(st);
				break;
			}
			if (!st->inner_tls_started) {
				if (eap_tls_engine_init(&st->inner_tls, st->pcb, EAPTLS_TUNNELED_MTU,
				    teap_inner_tls_send, st, teap_inner_tls_done, st) != 0) {
					ppp_error("TEAP: out of memory (inner EAP-TLS)");
					teap_fail(st);
					break;
				}
				st->inner_tls_started = 1;
				ppp_info("TEAP: inner EAP-TLS (certificate authentication)");
			}
			eap_tls_engine_input(st->inner_tls, iid, pkt + EAP_HEADERLEN + 1,
			    elen - EAP_HEADERLEN - 1);
			break;
		default: {
			/* The inner tunnel may propose a different method first
			 * (FreeRADIUS offers a nested TEAP Start when its inner
			 * default is teap); negotiate EAP-MSCHAPv2 with an EAP-Nak. */
			u_char nak[EAP_HEADERLEN + 2];
			u_char *o = nak;
			if (st->nak_sent >= 2) {
				ppp_error("TEAP: inner EAP type %d insisted by peer; failing", typenum);
				teap_fail(st);
				break;
			}
			st->nak_sent++;
			ppp_info("TEAP: inner EAP type %d not wanted; NAKing in favor of %s", typenum,
			    st->pcb->settings.eap_tls_cert_pem != NULL ? "EAP-TLS" : "EAP-MSCHAPv2");
			PUTCHAR(EAP_RESPONSE, o);
			PUTCHAR(iid, o);
			PUTSHORT(EAP_HEADERLEN + 2, o);
			PUTCHAR(EAPT_NAK, o);
			PUTCHAR(st->pcb->settings.eap_tls_cert_pem != NULL ? EAPT_TLS : EAPT_MSCHAPV2, o);
			teap_send_eap_payload(st, nak, (int)(o - nak));
			break;
		}
		}
		break;

	case EAP_SUCCESS:
		ppp_info("TEAP: inner EAP success (payload)");
		break;

	case EAP_FAILURE:
		ppp_error("TEAP: inner EAP failure (payload)");
		teap_fail(st);
		break;

	default:
		ppp_error("TEAP: unexpected inner EAP code %d", code);
		break;
	}
}

/*
 * Derive the MPPE keys for the SSTP Call Connected crypto binding
 * (RFC 7170 5.4: MSK = TLS-PRF(S-IMCK[j], "Session Key Generating
 * Function"|0x00, 64); MS-MPPE-Recv-Key = MSK[0..32] (NAS recv = client
 * send), MS-MPPE-Send-Key = MSK[32..64]; stored client-perspective).
 * NOTE: the inner-MSK half swap applies to the crypto-binding IMSK only,
 * not to these MPPE keys.
 */
static void teap_derive_mppe_keys(eap_teap_state *st) {
	u_char keymat[64];
	/* "Session Key Generating Function" with the trailing NUL, like
	 * FreeRADIUS's 31-byte label iovec. */
	static const u_char label[31] = "Session Key Generating Function";

	if (st->pcb->settings.eap_mppe_keys_ok)
		return;
	if (!st->cmk_ok)
		return;	/* no completed crypto-binding round yet */
	teap_p_hash(st->md, st->simck, sizeof(st->simck),
	    (const char *)label, sizeof(label), NULL, 0, keymat, sizeof(keymat));
	MEMCPY(st->pcb->settings.eap_mppe_send_key, keymat, 32);
	MEMCPY(st->pcb->settings.eap_mppe_recv_key, keymat + 32, 32);
	st->pcb->settings.eap_mppe_keys_ok = 1;
	ppp_info("TEAP: MPPE keys derived from S-IMCK");
	BZERO(keymat, sizeof(keymat));
}

/* Verify the server's Crypto-Binding request MAC and answer with our own
 * Crypto-Binding TLV (+ an Intermediate-Result TLV when one was given). */
static void teap_answer_binding(eap_teap_state *st, const u_char *req76, int inter_val) {
	u_char resp[4 + TEAP_CB_LEN + 4 + 2];
	u_char macbuf[2 + 2 + TEAP_CB_LEN + 1 + 256];
	u_char mac[TEAP_CMK_LEN];
	u_char *o = resp;
	int maclen;

	if (teap_derive_cmk(st) != 0) {
		ppp_error("TEAP: crypto-binding key derivation failed");
		teap_fail(st);
		return;
	}

	/* Verify the server's request MAC first */
	maclen = teap_cb_mac_input(st, req76, macbuf, sizeof(macbuf));
	if (maclen < 0) {
		teap_fail(st);
		return;
	}
	teap_compound_mac(st, macbuf, maclen, mac);
	if (memcmp(mac, req76 + 4 + 32 + 20, TEAP_CMK_LEN) == 0) {
		ppp_info("TEAP: server crypto-binding verified");
	} else {
		ppp_warn("TEAP: server crypto-binding MAC does not match our computed value%s",
		    eap_teap_test_noswap ? " (expected in noswap test mode)" : "");
		teap_dump("server MAC", req76 + 4 + 32 + 20, TEAP_CMK_LEN);
		teap_dump("our MAC", mac, TEAP_CMK_LEN);
	}

	/* Build our response binding: version 1, received_version 1,
	 * subtype CMAC_MSK|RESPONSE, nonce = server's with low bit set. */
	{
		u_char binding[TEAP_CB_LEN];
		BZERO(binding, sizeof(binding));
		binding[1] = TEAP_CB_VERSION;		/* Version */
		binding[2] = TEAP_CB_VERSION;		/* RecvVersion */
		binding[3] = (TEAP_CB_FLAGS_CMAC_MSK << 4) | TEAP_CB_SUBTYPE_RESPONSE;
		MEMCPY(binding + 4, req76 + 4, 32);	/* echo server nonce... */
		binding[4 + 31] |= 0x01;		/* ...with low bit set (RFC 7170 4.2.13) */

		maclen = teap_cb_mac_input(st, binding, macbuf, sizeof(macbuf));
		if (maclen < 0) {
			teap_fail(st);
			return;
		}
		teap_compound_mac(st, macbuf, maclen, mac);
		MEMCPY(binding + 4 + 32 + 20, mac, TEAP_CMK_LEN);	/* MSK MAC (EMSK MAC stays zero) */
		o = teap_put_tlv(o, TEAP_TLV_CRYPTO_BINDING, 1, binding, TEAP_CB_LEN);
	}
	if (inter_val > 0) {
		u_short v = (u_short)inter_val;
		u_char vb[2];
		vb[0] = (u_char)(v >> 8);
		vb[1] = (u_char)v;
		o = teap_put_tlv(o, TEAP_TLV_INTERMED_RESULT, 1, vb, 2);
	}
	ppp_info("TEAP: answering crypto-binding%s", inter_val > 0 ? " with Intermediate-Result" : "");
	teap_send_tlvs(st, resp, (int)(o - resp));
	teap_derive_mppe_keys(st);
}

/* Parse the tunnelled TLV sequence (RFC 7170 4.2); returns the number of
 * octets consumed (complete TLVs only). */
static int teap_handle_tlvs(eap_teap_state *st, const u_char *data, int len) {
	const u_char *p = data;
	int l = len;
	const u_char *binding = NULL;
	int got_result = 0, result_val = 0;
	int got_inter = 0, inter_val = 0;

	while (l >= 4) {
		u_short t, tlv_len;
		int mandatory;
		t = (u_short)((p[0] << 8) | p[1]);
		tlv_len = (u_short)((p[2] << 8) | p[3]);
		mandatory = (t & TEAP_TLV_MANDATORY) != 0;
		t &= TEAP_TLV_TYPE_MASK;
		if (tlv_len > l - 4)
			break;	/* wait for the rest of this TLV */
		switch (t) {
		case TEAP_TLV_EAP_PAYLOAD:
			teap_dump("inner EAP", p + 4, tlv_len);
			teap_handle_inner_eap(st, p + 4, tlv_len);
			if (st->failed)
				return -1;
			break;
		case TEAP_TLV_CRYPTO_BINDING:
			if (tlv_len != TEAP_CB_LEN) {
				ppp_error("TEAP: malformed Crypto-Binding TLV (len %d)", tlv_len);
				teap_fail(st);
				return -1;
			}
			binding = p + 4;
			MEMCPY(st->server_nonce, p + 4 + 4, 32);
			break;
		case TEAP_TLV_INTERMED_RESULT:
			if (tlv_len == 2) {
				got_inter = 1;
				inter_val = (p[4] << 8) | p[5];
				ppp_info("TEAP: Intermediate-Result = %s",
				    inter_val == TEAP_TLV_RESULT_SUCCESS ? "success" : "failure");
			}
			break;
		case TEAP_TLV_RESULT:
			if (tlv_len == 2) {
				got_result = 1;
				result_val = (p[4] << 8) | p[5];
				ppp_info("TEAP: Result-TLV = %s",
				    result_val == TEAP_TLV_RESULT_SUCCESS ? "success" : "failure");
			}
			break;
		case TEAP_TLV_NAK:
		case TEAP_TLV_ERROR:
			ppp_error("TEAP: server sent %s TLV; failing",
			    t == TEAP_TLV_NAK ? "NAK" : "Error");
			teap_fail(st);
			return -1;
		default:
			if (mandatory) {
				ppp_error("TEAP: unsupported mandatory TLV type %d; failing", t);
				teap_fail(st);
				return -1;
			}
			ppp_info("TEAP: ignoring TLV type %d (len %d)", t, tlv_len);
			break;
		}
		p += 4 + tlv_len;
		l -= 4 + tlv_len;
	}

	/* Compose the response for this TLV sequence */
	if (binding != NULL) {
		teap_answer_binding(st, binding, got_inter ? inter_val : 0);
	} else if (got_inter) {
		u_char resp[8];
		u_char *o = resp;
		u_char vb[2];
		vb[0] = (u_char)(inter_val >> 8);
		vb[1] = (u_char)inter_val;
		o = teap_put_tlv(o, TEAP_TLV_INTERMED_RESULT, 1, vb, 2);
		ppp_info("TEAP: echoing Intermediate-Result");
		teap_send_tlvs(st, resp, (int)(o - resp));
	}
	if (got_result) {
		u_char resp[8];
		u_char *o = resp;
		u_char vb[2];
		vb[0] = (u_char)(result_val >> 8);
		vb[1] = (u_char)result_val;
		o = teap_put_tlv(o, TEAP_TLV_RESULT, 1, vb, 2);
		ppp_info("TEAP: echoing Result-TLV");
		teap_send_tlvs(st, resp, (int)(o - resp));
		if (result_val == TEAP_TLV_RESULT_SUCCESS)
			st->inner_verified = 1;
		else {
			ppp_error("TEAP: server reported failure via Result-TLV");
			teap_fail(st);
			return -1;
		}
	}
	return (int)(p - data);
}

/* Read and dispatch TLS application data (TLV sequences). */
static void teap_read_inner(eap_teap_state *st, u_char id) {
	u_char buf[4096];
	int n;

	LWIP_UNUSED_ARG(id);
	for (;;) {
		n = SSL_read(st->ssl, buf, sizeof(buf));
#if EAP_TEAP_DEBUG_DUMP
		ppp_info("TEAP: SSL_read -> %d (pending %d)", n, SSL_pending(st->ssl));
#endif
		if (n <= 0) {
			int err = SSL_get_error(st->ssl, n);
#if EAP_TEAP_DEBUG_DUMP
			ppp_info("TEAP: SSL_read err %d", err);
#endif
			if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) {
				ppp_error("TEAP: inner TLS read failed (%d)", err);
				teap_fail(st);
				return;
			}
			break;
		}
		teap_dump("SSL_read bytes", buf, n);
		if (st->in_eap_len + n > TEAP_RX_MAX) {
			ppp_error("TEAP: inner buffer overflow");
			teap_fail(st);
			return;
		}
		MEMCPY(st->in_eap + st->in_eap_len, buf, n);
		st->in_eap_len += n;
	}

	if (st->in_eap_len > 0) {
		int used = teap_handle_tlvs(st, st->in_eap, st->in_eap_len);
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
static void teap_feed_tls(eap_teap_state *st, u_char id, const u_char *data, int len) {
	if (len > 0)
		BIO_write(st->net_bio, data, len);

	if (!st->handshake_done) {
		int ret = SSL_do_handshake(st->ssl);
		if (ret == 1) {
			st->handshake_done = 1;
			st->phase = TEAP_PHASE_INNER;
			ppp_info("TEAP: TLS handshake complete (%s)", SSL_get_version(st->ssl));
			if (!teap_verify_cert(st)) {
				teap_fail(st);
				return;
			}
		} else {
			int err = SSL_get_error(st->ssl, ret);
			if (err != SSL_ERROR_WANT_READ) {
				ppp_error("TEAP: TLS handshake failed (%d)", err);
#if EAP_TEAP_DEBUG_DUMP
				{
					unsigned long e;
					while ((e = ERR_get_error()) != 0) {
						char es[160];
						ERR_error_string_n(e, es, sizeof(es));
						ppp_error("TEAP: OpenSSL: %s", es);
					}
				}
#endif
				teap_fail(st);
				return;
			}
		}
		teap_flush(st, id);
		return;
	}

	teap_read_inner(st, id);
	if (st->failed)
		return;
	teap_flush(st, id);
}

static eap_teap_state *teap_new(ppp_pcb *pcb) {
	eap_teap_state *st;

	st = (eap_teap_state *)malloc(sizeof(*st));
	if (st == NULL)
		return NULL;
	BZERO(st, sizeof(*st));
	st->pcb = pcb;
	st->teap_version = TEAP_CB_VERSION;

	st->ssl_ctx = SSL_CTX_new(TLS_client_method());
	if (st->ssl_ctx == NULL) {
		free(st);
		return NULL;
	}
	/* Certificate policy is enforced by teap_verify_cert (fingerprint
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
		if (BIO_new_bio_pair(&ssl_bio, TEAP_RX_MAX, &net_bio, TEAP_TXQ_MAX) != 1) {
			SSL_free(st->ssl);
			SSL_CTX_free(st->ssl_ctx);
			free(st);
			return NULL;
		}
		SSL_set_bio(st->ssl, ssl_bio, ssl_bio);	/* SSL owns ssl_bio */
		st->net_bio = net_bio;
	}
	SSL_set_connect_state(st->ssl);

	pcb->eap.es_teap = st;
	return st;
}

void eap_teap_input(ppp_pcb *pcb, u_char id, const u_char *payload, int len) {
	eap_teap_state *st = teap_get(pcb);
	u_char flags;
	const u_char *data;
	int dlen;

	if (st == NULL) {
		st = teap_new(pcb);
		if (st == NULL) {
			ppp_error("TEAP: out of memory");
			auth_withpeer_fail(pcb, PPP_EAP);
			return;
		}
	}
	if (st->failed)
		return;

	/* Empty request: fragment ack (or a liveness probe) */
	if (len == 0) {
		if (st->txq_off < st->txq_len)
			teap_send_fragment(st, id);
		else
			teap_send_ack(st, id);
		return;
	}

	flags = payload[0];
	data = payload + 1;
	dlen = len - 1;
	teap_dump("RX frame", payload, len);

	if (flags & TEAP_FLAGS_START) {
		/* Low 3 bits of the flags octet carry the TEAP version;
		 * RFC 7170 is version 1. */
		st->teap_version = flags & 0x07;
		ppp_info("TEAP: start, version %d (TLS handshake begins)", st->teap_version);
		if ((flags & TEAP_FLAGS_OUTER_TLV) && dlen >= 4) {
			/* O bit: 4-octet total length, then the Outer TLVs;
			 * they feed the Crypto-Binding Compound MAC. */
			u32_t olen = ((u32_t)data[0] << 24) | ((u32_t)data[1] << 16) |
			    ((u32_t)data[2] << 8) | (u32_t)data[3];
			data += 4;
			dlen -= 4;
			if (olen > (u32_t)dlen)
				olen = (u32_t)dlen;
			if (olen > 0 && olen <= sizeof(st->server_outer)) {
				MEMCPY(st->server_outer, data, (int)olen);
				st->server_outer_len = (int)olen;
				teap_dump("Outer TLVs (server)", data, (int)olen);
			}
		}
		/* A Start packet carries no TLS data — kick off the handshake. */
		teap_feed_tls(st, id, NULL, 0);
		return;
	}

	if (flags & TEAP_FLAGS_LENGTH_INCLUDED) {
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

	if (st->rx_len + dlen > TEAP_RX_MAX) {
		ppp_error("TEAP: reassembly buffer overflow");
		teap_fail(st);
		return;
	}
	MEMCPY(st->rx + st->rx_len, data, dlen);
	st->rx_len += dlen;

	if (flags & TEAP_FLAGS_MORE_FRAGMENTS) {
		/* More fragments follow; ack (or piggyback pending output) */
		if (st->txq_off < st->txq_len)
			teap_send_fragment(st, id);
		else
			teap_send_ack(st, id);
		return;
	}

	if (st->rx_len == 0) {
		/* A flags-only frame acks our fragment: send the next one if
		 * there is one queued, else ack back. */
		if (st->txq_off < st->txq_len)
			teap_send_fragment(st, id);
		else
			teap_send_ack(st, id);
		return;
	}

	{
		u_char blob[TEAP_RX_MAX];
		int blen = st->rx_len;
		MEMCPY(blob, st->rx, blen);
		st->rx_len = 0;
		st->rx_total = 0;
		teap_feed_tls(st, id, blob, blen);
	}
}

#endif /* PPP_SUPPORT && EAP_SUPPORT && MSCHAP_SUPPORT */
