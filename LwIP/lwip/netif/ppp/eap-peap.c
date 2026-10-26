/*
 * eap-peap.c - PEAP (EAP type 25) client, Microsoft PEAPv1.
 *
 * Wire flow (client side):
 *   <- EAP-Request/PEAP, flags S            (start)
 *   -> EAP-Response/PEAP: TLS ClientHello   (fragmented as needed)
 *   <- ... TLS handshake records (L/M fragmentation both ways) ...
 *   <- EAP-Request/PEAP: inner EAP Identity-Request   (TLS app data)
 *   -> inner EAP Identity-Response (real username)
 *   <- inner EAP-MSCHAPv2 Challenge
 *   -> inner EAP-MSCHAPv2 Response
 *   <- inner EAP-MSCHAPv2 Success (S= verified)
 *   -> inner Success ack
 *   <- cleartext EAP Success                  (Microsoft PEAPv1 ending)
 *
 * PEAPv2-style ending (EAP-TLV Result-TLV inside the tunnel) is also
 * handled: the Result-TLV is echoed back, then cleartext EAP Success
 * completes the exchange.  Crypto-Binding TLVs (MS-PEAP 2.2.8.1.1) are
 * fully implemented: the server's compound MAC is verified and our own
 * binding TLV is sent in reply; the phase-1 TLS messages always carry
 * the TLS Message Length field (Windows NPS mis-computes the compound
 * MAC without it).
 *
 * Inner TLS certificate policy: BoringSSL cannot use the Apple trust
 * store, so when the profile has allowInsecure OFF we pin the inner leaf
 * to the SHA256 fingerprint of the outer SSTP connection's leaf
 * certificate (which the Network framework already verified); a mismatch
 * fails authentication.  With allowInsecure ON any inner certificate is
 * accepted and a warning is logged.  Never silently skipped.
 */

#include "netif/ppp/ppp_opts.h"
#if PPP_SUPPORT && EAP_SUPPORT && MSCHAP_SUPPORT  /* don't build if not configured for use in lwipopts.h */

#include "netif/ppp/ppp_impl.h"
#include "netif/ppp/eap.h"
#include "netif/ppp/eap-mschapv2.h"
#include "netif/ppp/chap_ms.h"
#include "netif/ppp/eap-peap.h"
#include "netif/ppp/eap-tls.h"
#include "netif/ppp/magic.h"

#include <openssl/ssl.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/x509.h>

#include <string.h>
#include <stdlib.h>

#ifndef EAP_PEAP_DEBUG_DUMP
#define EAP_PEAP_DEBUG_DUMP 0
#endif
#if EAP_PEAP_DEBUG_DUMP
static void peap_dump(const char *what, const u_char *p, int len) {
	char buf[400];
	int off = 0, i;
	buf[0] = '\0';
	if (p != NULL) {
		for (i = 0; i < len && off < (int)sizeof(buf) - 3; i++)
			off += snprintf(buf + off, sizeof(buf) - off, "%02x", p[i]);
	}
	ppp_info("PEAP %s (%d): %s", what, len, buf);
}
#else
#define peap_dump(...)
#endif

#define PEAP_EAP_MTU	1000	/* max TLS bytes per EAP frame */
#define PEAP_RX_MAX	16384	/* reassembly buffer */
#define PEAP_TXQ_MAX	16384	/* pending TLS output */

/* Inner EAP-TLS fragment size.  PEAPv0 (what FreeRADIUS negotiates) carries
 * inner EAP headerless: the server re-attaches an EAP header using the
 * OUTER request id, and its inner-tunnel session lookup keys on
 * (state, inner eap id).  Inner and outer id sequences stay in lockstep only
 * when every inner response completes within a single outer round trip, so
 * an inner flight that has to be split across outer PEAP fragments desyncs
 * the ids and FreeRADIUS drops the inner session ("No EAP session matching
 * state").  Fragmenting at the INNER EAP-TLS layer instead (one small inner
 * packet per outer round trip, exactly what the server does for its own
 * inner flight) keeps the lockstep intact. */
#define PEAP_INNER_TLS_MTU	900

enum peap_phase {
	PEAP_PHASE_HANDSHAKE = 0,
	PEAP_PHASE_INNER,
};

/* EAP-TLV (type 33) pieces for the PEAPv2 ending */
#define EAP_TLV_RESULT	3	/* Result-TLV (type bits after flags) */
#define EAP_TLV_CRYPTO_BINDING	12	/* Crypto-Binding TLV */
#define EAP_TLV_RESULT_SUCCESS	1
#define EAP_TLV_RESULT_FAILURE	2

struct eap_peap_state {
	ppp_pcb *pcb;
	SSL_CTX *ssl_ctx;
	SSL *ssl;
	BIO *net_bio;		/* our end of the BIO pair (SSL owns the other) */
	enum peap_phase phase;
	int handshake_done;
	int inner_verified;	/* inner EAP-MSCHAPv2 completed */
	int binding_done;	/* verified Crypto-Binding TLV exchanged */
	int failed;

	/* TLS output -> EAP fragmentation */
	u_char txq[PEAP_TXQ_MAX];
	int txq_off, txq_len;

	/* EAP fragment reassembly (server -> client TLS records) */
	u_char rx[PEAP_RX_MAX];
	int rx_len;
	u32_t rx_total;

	/* inner EAP stream reassembly (TLS app data) */
	u_char in_eap[PEAP_RX_MAX];
	int in_eap_len;

	eap_mschapv2_ctx mschap;
	int mschap_started;
	int peap_version;	/* negotiated PEAP version (S frame, low 3 bits) */

	/* Inner EAP-TLS (certificate authentication inside the tunnel) */
	struct eap_tls_engine *inner_tls;
	int inner_tls_started;
	int nak_tls_sent;	/* inner method negotiation: NAKed for EAP-TLS once */
	u_char inner_km[64];	/* inner EAP-TLS key material (ISK source) */
	int inner_km_ok;

	/* Crypto-Binding TLV (MS-PEAP 2.2.8.1.1) state */
	u_char tk[60];		/* TLS exporter "client EAP encryption" key material */
	u_char cmk[20];		/* Compound MAC key (IMCK[40..60]) */
	u_char ipmk[40];	/* Intermediate PEAP MAC Key (IMCK[0..40]) */
	int cmk_ok;
	u_char binding_nonce[32]; /* nonce from the server's request, echoed back */
};

typedef struct eap_peap_state eap_peap_state;

/* Test hooks for the SSTPTest harness (negative-path testing). */
int eap_peap_test_badcb = 0;	/* corrupt our crypto-binding response MAC */
int eap_peap_test_eapnak = 0;	/* answer first inner method with an EAP-NAK of this type */

static eap_peap_state *peap_get(ppp_pcb *pcb) {
	return (eap_peap_state *)pcb->eap.es_peap;
}

int eap_peap_active(ppp_pcb *pcb) {
	return peap_get(pcb) != NULL;
}

int eap_peap_done(ppp_pcb *pcb) {
	eap_peap_state *st = peap_get(pcb);
	return st != NULL && st->inner_verified;
}

/* A verified Crypto-Binding TLV was exchanged (for the peap_require_cb
 * enforcement in eap.c's success gate). */
int eap_peap_cb_done(ppp_pcb *pcb) {
	eap_peap_state *st = peap_get(pcb);
	return st != NULL && st->binding_done;
}

static void peap_fail(eap_peap_state *st) {
	ppp_pcb *pcb = st->pcb;
	st->failed = 1;
	eap_peap_free(pcb);
	pcb->eap.es_client.ea_state = eapBadAuth;
	auth_withpeer_fail(pcb, PPP_EAP);
}

void eap_peap_free(ppp_pcb *pcb) {
	eap_peap_state *st = peap_get(pcb);
	if (st == NULL)
		return;
	pcb->eap.es_peap = NULL;
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
static int peap_verify_cert(eap_peap_state *st) {
	if (!st->pcb->settings.peap_cert_check) {
		ppp_warn("PEAP: inner TLS certificate NOT verified (allowInsecure is on)");
		return 1;
	}
	X509 *cert = SSL_get_peer_certificate(st->ssl);
	if (cert == NULL) {
		ppp_error("PEAP: server presented no inner TLS certificate");
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
	if (memcmp(digest, st->pcb->settings.peap_cert_sha256, SHA256_DIGEST_LENGTH) != 0) {
		/* Split-host deployments (e.g. RRAS relaying EAP to a separate RADIUS
		 * server) legitimately present a different inner identity. Warn loudly
		 * with both fingerprints and continue — strict split-host pinning is
		 * deferred, see the note at the top of this file. */
		u_char outer[SHA256_DIGEST_LENGTH];
		memcpy(outer, st->pcb->settings.peap_cert_sha256, SHA256_DIGEST_LENGTH);
		ppp_warn("PEAP: inner TLS identity differs from the SSTP outer host "
		         "(expected when the EAP server is a different host). inner SHA256 %02x%02x%02x%02x… outer SHA256 %02x%02x%02x%02x…",
		         digest[0], digest[1], digest[2], digest[3],
		         outer[0], outer[1], outer[2], outer[3]);
		return 1;
	}
	ppp_info("PEAP: inner TLS certificate fingerprint matches the outer connection");
	return 1;
}

/* Drain pending TLS output into the tx queue. */
static void peap_drain(eap_peap_state *st) {
	for (;;) {
		int room = PEAP_TXQ_MAX - st->txq_len;
		int n;
		if (room <= 0)
			break;
		n = BIO_read(st->net_bio, st->txq + st->txq_len, room);
		if (n <= 0)
			break;
		st->txq_len += n;
	}
}

/* Send the next queued fragment (an EAP-Response/PEAP). */
static void peap_send_fragment(eap_peap_state *st, u_char id) {
	u_char payload[5 + PEAP_EAP_MTU];
	u_char *o = payload;
	int chunk = st->txq_len - st->txq_off;
	u_char flags = 0;

	if (chunk > PEAP_EAP_MTU) {
		chunk = PEAP_EAP_MTU;
		flags = PEAP_FLAGS_MORE_FRAGMENTS;
	}
	if (st->txq_off == 0) {
		/* First fragment of a TLS message: include the total TLS
		 * message length.  Windows NPS mis-uses the ClientHello as
		 * Outer-TLV data in the cryptobinding Compound MAC when the
		 * length field is absent, so it is always sent (this matches
		 * Windows and wpa_supplicant phase-1 behaviour). */
		flags |= PEAP_FLAGS_LENGTH_INCLUDED;
		PUTCHAR(flags, o);
		PUTLONG(st->txq_len, o);
	} else {
		PUTCHAR(flags, o);
	}
	MEMCPY(o, st->txq + st->txq_off, chunk);
	peap_dump("TX fragment", payload, (int)(o - payload) + chunk);
	eap_send_response(st->pcb, id, EAPT_PEAP, payload, (int)(o - payload) + chunk);
	st->txq_off += chunk;
	if (st->txq_off == st->txq_len) {
		st->txq_off = st->txq_len = 0;
	}
	/* further fragments are sent when the server's empty ack arrives */
}

/* PEAP fragment ack — a single zero flags octet (wpa_supplicant /
 * Microsoft compatible; a bare zero-length frame is rejected by RRAS). */
static void peap_send_ack(eap_peap_state *st, u_char id) {
	u_char flags = 0;
	peap_dump("TX ack", &flags, 1);
	eap_send_response(st->pcb, id, EAPT_PEAP, &flags, 1);
}

/* Send whatever the TLS engine produced (or an ack if nothing). */
static void peap_flush(eap_peap_state *st, u_char id) {
	peap_drain(st);
	if (st->txq_len > 0)
		peap_send_fragment(st, id);
	else
		peap_send_ack(st, id);
}

/* Write one inner EAP packet into the TLS tunnel. */
static void peap_tls_write(eap_peap_state *st, const u_char *pkt, int len) {
	int n = SSL_write(st->ssl, pkt, len);
	if (n <= 0) {
		int err = SSL_get_error(st->ssl, n);
		ppp_error("PEAP: inner TLS write failed (%d)", err);
		peap_fail(st);
	}
	peap_drain(st);
}

/* Send one inner EAP packet into the tunnel; PEAPv0 carries no EAP
 * header inside the tunnel (except TLV frames), strip it there. */
static void peap_send_inner(eap_peap_state *st, const u_char *pkt, int len) {
	if (st->peap_version == 0 &&
	    !(len >= EAP_HEADERLEN + 1 && pkt[EAP_HEADERLEN] == EAPT_TLV)) {
		pkt += EAP_HEADERLEN;
		len -= EAP_HEADERLEN;
	}
	peap_tls_write(st, pkt, len);
}

/* Inner EAP-MSCHAPv2 engine callbacks */
static void peap_mschap_send(void *arg, u_char eap_id, const u_char *payload, int len) {
	eap_peap_state *st = (eap_peap_state *)arg;
	u_char pkt[EAP_HEADERLEN + 1 + 256];
	u_char *o = pkt;

	/* Inner responses carry the inner request's id */
	PUTCHAR(EAP_RESPONSE, o);
	PUTCHAR(eap_id, o);
	PUTSHORT(EAP_HEADERLEN + 1 + len, o);
	PUTCHAR(EAPT_MSCHAPV2, o);
	MEMCPY(o, payload, len);
	INCPTR(len, o);
	peap_send_inner(st, pkt, (int)(o - pkt));
}

static void peap_mschap_complete(void *arg, int verified) {
	eap_peap_state *st = (eap_peap_state *)arg;
	if (verified) {
		ppp_info("PEAP: inner EAP-MSCHAPv2 authentication verified");
		st->inner_verified = 1;
	} else {
		ppp_error("PEAP: inner EAP-MSCHAPv2 authentication failed");
		peap_fail(st);
	}
}

/* Inner EAP-TLS engine callbacks */
static void peap_inner_tls_send(void *arg, u_char eap_id, const u_char *payload, int len) {
	eap_peap_state *st = (eap_peap_state *)arg;
	u_char pkt[EAP_HEADERLEN + 1 + 4110];
	u_char *o = pkt;

	PUTCHAR(EAP_RESPONSE, o);
	PUTCHAR(eap_id, o);
	PUTSHORT(EAP_HEADERLEN + 1 + len, o);
	PUTCHAR(EAPT_TLS, o);
	MEMCPY(o, payload, len);
	INCPTR(len, o);
	peap_send_inner(st, pkt, (int)(o - pkt));
}

static void peap_inner_tls_done(void *arg, int ok) {
	eap_peap_state *st = (eap_peap_state *)arg;
	if (!ok) {
		ppp_error("PEAP: inner EAP-TLS authentication failed");
		peap_fail(st);
		return;
	}
	/* The inner method's key material feeds the crypto-binding ISK
	 * (MS-PEAP 3.1.5.5.2.2: first 32 octets of send|recv = KM[0..32]). */
	if (eap_tls_engine_export_km(st->inner_tls, st->inner_km) == 0)
		st->inner_km_ok = 1;
	ppp_info("PEAP: inner EAP-TLS handshake complete");
}

/* PRF+ from draft-josefsson-pppext-eap-tls-eap, version 0 flavour:
 * T1 = HMAC-SHA1(K, S | 0x01 | 0x00 | 0x00); Tn = HMAC-SHA1(K, Tn-1 | S | n | 0 | 0) */
static void peap_prfplus_v0(const u_char *key, int key_len, const char *label,
			    const u_char *seed, int seed_len, u_char *buf, int buf_len) {
	u_char counter = 0;
	u_char hash[SHA_DIGEST_LENGTH];
	u_char data[256];
	int hash_len = 0;
	int pos = 0;
	int label_len = (int)strlen(label);

	while (pos < buf_len) {
		int dlen = 0;
		int take;
		if (hash_len > 0) {
			MEMCPY(data, hash, hash_len);
			dlen = hash_len;
		}
		MEMCPY(data + dlen, label, label_len);
		dlen += label_len;
		MEMCPY(data + dlen, seed, seed_len);
		dlen += seed_len;
		data[dlen++] = ++counter;
		data[dlen++] = 0;
		data[dlen++] = 0;
		HMAC(EVP_sha1(), key, key_len, data, dlen, hash, NULL);
		hash_len = SHA_DIGEST_LENGTH;
		take = buf_len - pos;
		if (take > SHA_DIGEST_LENGTH)
			take = SHA_DIGEST_LENGTH;
		MEMCPY(buf + pos, hash, take);
		pos += take;
	}
	BZERO(hash, sizeof(hash));
	BZERO(data, sizeof(data));
}

/*
 * Derive the Compound MAC key (MS-PEAP 3.1.5.5):
 *   TK   = TLS key material, label "client EAP encryption" (60 octets)
 *   ISK  = inner EAP-MSCHAPv2 session key (send || receive, peer order)
 *   IMCK = PRF+(TK[0..40], "Inner Methods Compound Keys", ISK, 60)
 *   CMK  = IMCK[40..60]
 */
static int peap_derive_cmk(eap_peap_state *st) {
	u_char isk[32];
	u_char imck[60];

	if (st->cmk_ok)
		return 0;
	if (!st->mschap_started && !st->inner_km_ok) {
		ppp_error("PEAP: crypto-binding before inner authentication");
		return -1;
	}
	if (SSL_export_keying_material(st->ssl, st->tk, sizeof(st->tk),
	    "client EAP encryption", 21, NULL, 0, 0) != 1) {
		ppp_error("PEAP: TLS key material export failed");
		return -1;
	}
	if (st->inner_km_ok) {
		/* Inner EAP-TLS: ISK = first 32 octets of the inner method's
		 * send|recv MPPE keys (MS-PEAP 3.1.5.5.2.2 truncation rule). */
		MEMCPY(isk, st->inner_km, sizeof(isk));
	} else {
		chapms2_eap_master_keys(st->mschap.secret, st->mschap.secret_len,
		    st->mschap.nt_response, isk, isk + 16);
	}
	peap_prfplus_v0(st->tk, 40, "Inner Methods Compound Keys", isk, sizeof(isk),
	    imck, sizeof(imck));
	MEMCPY(st->ipmk, imck, sizeof(st->ipmk));
	MEMCPY(st->cmk, imck + 40, sizeof(st->cmk));
	st->cmk_ok = 1;
	BZERO(isk, sizeof(isk));
	BZERO(imck, sizeof(imck));
	return 0;
}

/* Compound MAC: HMAC-SHA1-160(CMK, TLV (with MAC zeroed) | EAP type) */
static void peap_compound_mac(eap_peap_state *st, u_char *tlv60, u_char mac[SHA_DIGEST_LENGTH]) {
	u_char buf[61];
	MEMCPY(buf, tlv60, 60);
	BZERO(buf + 4 + 4 + 32, 20);	/* zero the Compound_MAC field */
	buf[60] = EAPT_PEAP;
	HMAC(EVP_sha1(), st->cmk, sizeof(st->cmk), buf, sizeof(buf), mac, NULL);
	BZERO(buf, sizeof(buf));
}

/*
 * Derive the MPPE keys for the SSTP Call Connected crypto binding
 * (MS-PEAP 3.1.5.7; MS-SSTP 3.1.5.2 feeds them into the HLAK CMAC).
 * Keys are stored client-perspective: send = the key this client sends with.
 *
 * With crypto-binding exchanged:  CSK = PRF+(IPMK,
 *     "Session Key Generating Function"|0x00, 128);
 *     peer MS-MPPE-Send-Key = CSK[0..32], MS-MPPE-Recv-Key = CSK[32..64].
 * Without crypto-binding:  the first 64 octets of the TLS key material
 *     ("client EAP encryption"), same split.
 */
static void peap_derive_mppe_keys(eap_peap_state *st, int binding_exchanged) {
	u_char keymat[128];

	if (binding_exchanged) {
		u_char nul = 0;
		if (peap_derive_cmk(st) != 0)
			return;
		peap_prfplus_v0(st->ipmk, sizeof(st->ipmk),
		    "Session Key Generating Function", &nul, 1, keymat, 128);
		ppp_info("PEAP: MPPE keys derived from the crypto-binding CSK");
	} else {
		if (SSL_export_keying_material(st->ssl, keymat, 64,
		    "client EAP encryption", 21, NULL, 0, 0) != 1) {
			ppp_error("PEAP: TLS key material export failed (MPPE keys)");
			return;
		}
		ppp_info("PEAP: MPPE keys derived from the TLS key material (no crypto-binding)");
	}
	MEMCPY(st->pcb->settings.eap_mppe_send_key, keymat, 32);
	MEMCPY(st->pcb->settings.eap_mppe_recv_key, keymat + 32, 32);
	st->pcb->settings.eap_mppe_keys_ok = 1;
	BZERO(keymat, sizeof(keymat));
}

/* Answer an inner EAP-TLV request (PEAPv2 ending): echo the Result-TLV. */
static void peap_handle_tlv(eap_peap_state *st, u_char iid, const u_char *data, int len) {
	u_short result = 0;
	const u_char *crypto_tlv = NULL;
	const u_char *p = data;
	int l = len;
	int found = 0;

	while (l >= 4) {
		u_short t, ln;
		GETSHORT(t, p);
		GETSHORT(ln, p);
		l -= 4;
		if (ln > l)
			break;
		if ((t & 0x3fff) == EAP_TLV_RESULT && ln == 2) {
			result = (u_short)((p[0] << 8) | p[1]);	/* peek; INCPTR advances */
			found = 1;
		} else if ((t & 0x3fff) == EAP_TLV_CRYPTO_BINDING && ln == 56) {
			crypto_tlv = p - 4;	/* include the TLV header */
		}
		INCPTR(ln, p);
		l -= ln;
	}
	if (!found) {
		ppp_error("PEAP: EAP-TLV request without Result-TLV");
		peap_fail(st);
		return;
	}
	if (result == EAP_TLV_RESULT_FAILURE) {
		ppp_error("PEAP: server reported failure via Result-TLV");
		peap_dump("TLV failure", data, len);
		peap_fail(st);
		return;
	}

	int answer_binding = 0;
	if (crypto_tlv == NULL && st->pcb->settings.peap_require_cb) {
		ppp_error("PEAP: cryptographic binding was required but not negotiated "
		    "(the server sent no Crypto-Binding TLV); failing");
		peap_fail(st);
		return;
	}
	if (crypto_tlv != NULL) {
		/* MS-PEAP 2.2.8.1.1: verify the server's binding, then answer
		 * with our own (SubType=1, echoed nonce, computed MAC) */
		const u_char *v = crypto_tlv + 4;
		u_char mac[SHA_DIGEST_LENGTH];
		if (peap_derive_cmk(st) != 0) {
			ppp_warn("PEAP: crypto-binding key derivation failed; answering Result-TLV only");
			goto send_result;
		}
#if EAP_PEAP_DEBUG_DUMP
		{
			u_char tk2[60];
			if (SSL_export_keying_material(st->ssl, tk2, sizeof(tk2), "client PEAP encryption", 23, NULL, 0, 0) == 1) {
				peap_dump("TK-newlabel", tk2, 60);
			}
			{
				u_char rnd[32];
				SSL_SESSION *sess = SSL_get_session(st->ssl);
				if (sess != NULL) {
					u_char mk[48];
					size_t mkl = SSL_SESSION_get_master_key(sess, mk, sizeof(mk));
					peap_dump("TLS master key", mk, (int)mkl);
				}
				if (SSL_get_client_random(st->ssl, rnd, sizeof(rnd)) == sizeof(rnd))
					peap_dump("TLS client random", rnd, 32);
				if (SSL_get_server_random(st->ssl, rnd, sizeof(rnd)) == sizeof(rnd))
					peap_dump("TLS server random", rnd, 32);
			}
		}
		peap_dump("TK", st->tk, 60);
		peap_dump("CMK", st->cmk, 20);
		peap_dump("server nonce", v + 4, 32);
		peap_dump("server MAC", v + 36, 20);
		peap_dump("NT response", st->mschap.nt_response, 24);
#endif
		if (v[1] != st->peap_version || v[3] != 0) {
			ppp_error("PEAP: crypto-binding TLV version/subtype mismatch");
			peap_fail(st);
			return;
		}
		MEMCPY(st->binding_nonce, v + 4, 32);
		peap_compound_mac(st, (u_char *)crypto_tlv, mac);
#if EAP_PEAP_DEBUG_DUMP
		peap_dump("our MAC", mac, 20);
#endif
		if (memcmp(mac, v + 36, SHA_DIGEST_LENGTH) != 0) {
			/* Our derivation is verified against the MS-PEAP 4.4 worked
			 * example; a server that computes it differently (e.g. an
			 * implementation that mis-handles Outer TLVs) would also
			 * reject our response, so answering with a MAC is no
			 * better than not answering: send the Result-TLV only. */
			if (st->pcb->settings.peap_require_cb) {
				ppp_error("PEAP: cryptographic binding was required but the "
				    "server's MAC did not verify; failing");
				peap_fail(st);
				return;
			}
			ppp_warn("PEAP: server crypto-binding MAC does not match our "
			    "spec-computed value; answering Result-TLV only");
			goto send_result;
		}
		ppp_info("PEAP: server crypto-binding verified");
		answer_binding = 1;
	}

send_result:

	{
		u_char resp[EAP_HEADERLEN + 1 + 6 + 60];
		u_char *o = resp;
		int rlen = EAP_HEADERLEN + 1 + 6 + (answer_binding ? 60 : 0);

		ppp_info("PEAP: Result-TLV success, acknowledging%s",
		    answer_binding ? " with crypto-binding" : "");
		PUTCHAR(EAP_RESPONSE, o);
		PUTCHAR(iid, o);
		PUTSHORT(rlen, o);
		PUTCHAR(EAPT_TLV, o);
		PUTSHORT(0x8000 | EAP_TLV_RESULT, o);	/* Mandatory | Result-TLV */
		PUTSHORT(2, o);
		PUTSHORT(EAP_TLV_RESULT_SUCCESS, o);
		if (answer_binding) {
			u_char *tlv_start = o;
			u_char mac[SHA_DIGEST_LENGTH];
			PUTSHORT(EAP_TLV_CRYPTO_BINDING, o);
			PUTSHORT(56, o);
			PUTCHAR(0, o);			/* Reserved */
			PUTCHAR(st->peap_version, o);	/* Version */
			PUTCHAR(st->peap_version, o);	/* RecvVersion */
			PUTCHAR(1, o);			/* SubType: response */
			MEMCPY(o, st->binding_nonce, 32);
			INCPTR(32, o);
			BZERO(o, 20);			/* Compound_MAC placeholder */
			INCPTR(20, o);
			peap_compound_mac(st, tlv_start, mac);
			if (eap_peap_test_badcb) {
				mac[0] ^= 0xff;
				ppp_warn("PEAP: TEST MODE badcb — deliberately corrupting binding MAC");
			}
			MEMCPY(tlv_start + 4 + 4 + 32, mac, SHA_DIGEST_LENGTH);
			BZERO(mac, sizeof(mac));
		}
		peap_send_inner(st, resp, (int)(o - resp));
		if (answer_binding)
			st->binding_done = 1;
		peap_derive_mppe_keys(st, answer_binding);
		st->inner_verified = 1;
	}
}

/* Handle one complete inner EAP packet (TLS application data). */
static void peap_handle_inner_eap(eap_peap_state *st, u_char outer_id, const u_char *pkt, int len) {
	u_char code, iid, typenum;
	u_short elen;
	u_char synth[PEAP_RX_MAX];

	if (st->peap_version == 0 &&
	    !(len >= EAP_HEADERLEN + 1 && (pkt[0] == EAP_REQUEST || pkt[0] == EAP_RESPONSE) &&
	      ((pkt[2] << 8) | pkt[3]) == len)) {
		/* PEAPv0: no EAP header inside the tunnel; synthesize it from
		 * the outer request (same trick as wpa_supplicant) */
		if (len + EAP_HEADERLEN > (int)sizeof(synth))
			return;
		synth[0] = EAP_REQUEST;
		synth[1] = outer_id;
		synth[2] = (u_char)((len + EAP_HEADERLEN) >> 8);
		synth[3] = (u_char)(len + EAP_HEADERLEN);
		MEMCPY(synth + EAP_HEADERLEN, pkt, len);
		pkt = synth;
		len += EAP_HEADERLEN;
	}

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
			ppp_info("PEAP: inner identity request, answering as the real user");
			PUTCHAR(EAP_RESPONSE, o);
			PUTCHAR(iid, o);
			PUTSHORT(EAP_HEADERLEN + 1 + namelen, o);
			PUTCHAR(EAPT_IDENTITY, o);
			MEMCPY(o, name, namelen);
			INCPTR(namelen, o);
			peap_send_inner(st, resp, (int)(o - resp));
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
				ppp_info("PEAP: certificate profile, NAKing inner MSCHAPv2 in favor of EAP-TLS");
				PUTCHAR(EAP_RESPONSE, o);
				PUTCHAR(iid, o);
				PUTSHORT(EAP_HEADERLEN + 2, o);
				PUTCHAR(EAPT_NAK, o);
				PUTCHAR(EAPT_TLS, o);
				peap_send_inner(st, nak, (int)(o - nak));
				break;
			}
			if (!st->mschap_started && eap_peap_test_eapnak != 0) {
				/* TEST MODE: NAK the server's inner method once,
				 * proposing the test type (e.g. 55=TEAP, 21=TTLS). */
				u_char nak[EAP_HEADERLEN + 2];
				u_char *o = nak;
				ppp_warn("PEAP: TEST MODE eapnak — NAKing inner type %d, proposing %d",
				    typenum, eap_peap_test_eapnak);
				PUTCHAR(EAP_RESPONSE, o);
				PUTCHAR(iid, o);
				PUTSHORT(EAP_HEADERLEN + 2, o);
				PUTCHAR(EAPT_NAK, o);
				PUTCHAR(eap_peap_test_eapnak, o);
				peap_send_inner(st, nak, (int)(o - nak));
				eap_peap_test_eapnak = 0;
				break;
			}
			if (!st->mschap_started) {
				if (!get_secret(st->pcb, st->pcb->eap.es_client.ea_name, "",
				    secret, &secret_len, 0)) {
					ppp_error("PEAP: no secret for inner authentication");
					peap_fail(st);
					return;
				}
				st->mschap_started = 1;
				/* Inside the TLS tunnel the authenticator response is
				 * still present with Microsoft PEAPv1; verify it. */
				eap_mschapv2_init(&st->mschap, st->pcb->eap.es_client.ea_name,
				    st->pcb->settings.passwd, secret_len, 1,
				    peap_mschap_send, st, peap_mschap_complete, st);
				BZERO(secret, sizeof (secret));
			}
			st->mschap.eap_id = iid;
			eap_mschapv2_handle(&st->mschap, iid, pkt + EAP_HEADERLEN + 1,
			    elen - EAP_HEADERLEN - 1);
			break;
		}
		case EAPT_TLV:
			peap_handle_tlv(st, iid, pkt + EAP_HEADERLEN + 1, elen - EAP_HEADERLEN - 1);
			break;
		case EAPT_TLS:
			/* Inner EAP-TLS: certificate authentication inside the tunnel */
			if (st->pcb->settings.eap_tls_cert_pem == NULL ||
			    st->pcb->settings.eap_tls_key_pem == NULL) {
				ppp_error("PEAP: inner EAP-TLS offered but no client certificate configured; failing");
				peap_fail(st);
				break;
			}
			if (!st->inner_tls_started) {
				if (eap_tls_engine_init(&st->inner_tls, st->pcb, PEAP_INNER_TLS_MTU,
				    peap_inner_tls_send, st, peap_inner_tls_done, st) != 0) {
					ppp_error("PEAP: out of memory (inner EAP-TLS)");
					peap_fail(st);
					break;
				}
				st->inner_tls_started = 1;
				ppp_info("PEAP: inner EAP-TLS (certificate authentication)");
			}
			eap_tls_engine_input(st->inner_tls, iid, pkt + EAP_HEADERLEN + 1,
			    elen - EAP_HEADERLEN - 1);
			break;
		case EAPT_EXPANDED: {
			/* MS-PEAP Capabilities Negotiation (vendor 311, type 34) etc.
			 * We don't implement capability negotiation; per MS-PEAP the
			 * peer answers with an EAP NAK naming the real inner method. */
			u_char nak[EAP_HEADERLEN + 2];
			u_char *o = nak;
			ppp_info("PEAP: expanded inner EAP (capabilities negotiation?) not supported; NAKing");
			PUTCHAR(EAP_RESPONSE, o);
			PUTCHAR(iid, o);
			PUTSHORT(EAP_HEADERLEN + 2, o);
			PUTCHAR(EAPT_NAK, o);
			PUTCHAR(st->pcb->settings.eap_tls_cert_pem != NULL ? EAPT_TLS : EAPT_MSCHAPV2, o);
			peap_send_inner(st, nak, (int)(o - nak));
			break;
		}
		default:
			ppp_error("PEAP: unsupported inner EAP type %d; failing", typenum);
			peap_fail(st);
			break;
		}
		break;

	case EAP_SUCCESS:
		/* Some servers send an inner EAP Success before the outer one */
		ppp_info("PEAP: inner EAP success");
		st->inner_verified = 1;
		break;

	case EAP_FAILURE:
		ppp_error("PEAP: inner EAP failure");
		peap_fail(st);
		break;

	default:
		ppp_error("PEAP: unexpected inner EAP code %d", code);
		break;
	}
}

/* Read and dispatch TLS application data (inner EAP packets). */
static void peap_read_inner(eap_peap_state *st, u_char id) {
	u_char buf[4096];
	int n;

	for (;;) {
		n = SSL_read(st->ssl, buf, sizeof(buf));
#if EAP_PEAP_DEBUG_DUMP
		ppp_info("PEAP: SSL_read -> %d (pending %d)", n, SSL_pending(st->ssl));
#endif
		if (n <= 0) {
			int err = SSL_get_error(st->ssl, n);
#if EAP_PEAP_DEBUG_DUMP
			ppp_info("PEAP: SSL_read err %d", err);
#endif
			if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) {
				ppp_error("PEAP: inner TLS read failed (%d)", err);
				peap_fail(st);
				return;
			}
			break;
		}
		peap_dump("SSL_read bytes", buf, n);
		if (st->in_eap_len + n > PEAP_RX_MAX) {
			ppp_error("PEAP: inner EAP buffer overflow");
			peap_fail(st);
			return;
		}
		MEMCPY(st->in_eap + st->in_eap_len, buf, n);
		st->in_eap_len += n;
	}

	/* PEAPv0: each decrypted chunk is a complete headerless inner message */
	if (st->peap_version == 0) {
		if (st->in_eap_len > 0) {
			peap_dump("inner data (v0)", st->in_eap, st->in_eap_len);
			peap_handle_inner_eap(st, id, st->in_eap, st->in_eap_len);
			st->in_eap_len = 0;
		}
		return;
	}

	/* Dispatch complete inner EAP packets */
	while (st->in_eap_len >= EAP_HEADERLEN) {
		int elen = (st->in_eap[2] << 8) | st->in_eap[3];
		if (elen < EAP_HEADERLEN) {
			ppp_error("PEAP: bogus inner EAP length %d", elen);
			peap_fail(st);
			return;
		}
		if (elen > st->in_eap_len)
			break;	/* wait for the rest */
		peap_dump("inner EAP", st->in_eap, elen);
		peap_handle_inner_eap(st, id, st->in_eap, elen);
		if (st->failed)
			return;
		st->in_eap_len -= elen;
		if (st->in_eap_len > 0)
			memmove(st->in_eap, st->in_eap + elen, st->in_eap_len);
	}
}

/* Feed one complete TLS blob (or a handshake-start frame) into BoringSSL. */
static void peap_feed_tls(eap_peap_state *st, u_char id, const u_char *data, int len) {
	if (len > 0)
		BIO_write(st->net_bio, data, len);

	if (!st->handshake_done) {
		int ret = SSL_do_handshake(st->ssl);
		if (ret == 1) {
			st->handshake_done = 1;
			st->phase = PEAP_PHASE_INNER;
			ppp_info("PEAP: TLS handshake complete (%s)", SSL_get_version(st->ssl));
			if (!peap_verify_cert(st)) {
				peap_fail(st);
				return;
			}
		} else {
			int err = SSL_get_error(st->ssl, ret);
			if (err != SSL_ERROR_WANT_READ) {
				ppp_error("PEAP: TLS handshake failed (%d)", err);
				peap_fail(st);
				return;
			}
		}
		peap_flush(st, id);
		return;
	}

	peap_read_inner(st, id);
	if (st->failed)
		return;
	peap_flush(st, id);
}

static eap_peap_state *peap_new(ppp_pcb *pcb) {
	eap_peap_state *st;

	st = (eap_peap_state *)malloc(sizeof(*st));
	if (st == NULL)
		return NULL;
	BZERO(st, sizeof(*st));
	st->pcb = pcb;

	st->ssl_ctx = SSL_CTX_new(TLS_client_method());
	if (st->ssl_ctx == NULL) {
		free(st);
		return NULL;
	}
	/* Certificate policy is enforced by peap_verify_cert (fingerprint pin
	 * against the outer connection), not by BoringSSL's chain verifier. */
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
		if (BIO_new_bio_pair(&ssl_bio, PEAP_RX_MAX, &net_bio, PEAP_TXQ_MAX) != 1) {
			SSL_free(st->ssl);
			SSL_CTX_free(st->ssl_ctx);
			free(st);
			return NULL;
		}
		SSL_set_bio(st->ssl, ssl_bio, ssl_bio);	/* SSL owns ssl_bio */
		st->net_bio = net_bio;
	}
	SSL_set_connect_state(st->ssl);

	pcb->eap.es_peap = st;
	return st;
}

void eap_peap_input(ppp_pcb *pcb, u_char id, const u_char *payload, int len) {
	eap_peap_state *st = peap_get(pcb);
	u_char flags;
	const u_char *data;
	int dlen;

	if (st == NULL) {
		st = peap_new(pcb);
		if (st == NULL) {
			ppp_error("PEAP: out of memory");
			auth_withpeer_fail(pcb, PPP_EAP);
			return;
		}
	}
	if (st->failed)
		return;

	/* Empty request: fragment ack (or a liveness probe) */
	if (len == 0) {
		if (st->txq_off < st->txq_len)
			peap_send_fragment(st, id);
		else
			peap_send_ack(st, id);
		return;
	}

	flags = payload[0];
	data = payload + 1;
	dlen = len - 1;
	peap_dump("RX frame", payload, len);

	if (flags & PEAP_FLAGS_START) {
		/* Low 3 bits of the flags octet carry the PEAP version;
		 * Windows RRAS/IAS is PEAPv0 (no EAP header inside the tunnel) */
		st->peap_version = flags & 0x07;
		ppp_info("PEAP: start, version %d (TLS handshake begins)", st->peap_version);
	}

	if (flags & PEAP_FLAGS_LENGTH_INCLUDED) {
		u32_t total;
		if (dlen < 4)
			return;
		total = ((u32_t)data[0] << 24) | ((u32_t)data[1] << 16) |
		    ((u32_t)data[2] << 8) | (u32_t)data[3];
		data += 4;
		dlen -= 4;
		/* Some servers set the L bit on EVERY fragment (Windows only
		 * on the first); only treat it as the start of a new message
		 * when no reassembly is in progress. */
		if (st->rx_len == 0)
			st->rx_total = total;
	}

	if (st->rx_len + dlen > PEAP_RX_MAX) {
		ppp_error("PEAP: reassembly buffer overflow");
		peap_fail(st);
		return;
	}
	MEMCPY(st->rx + st->rx_len, data, dlen);
	st->rx_len += dlen;

	if (flags & PEAP_FLAGS_MORE_FRAGMENTS) {
		/* More fragments follow; ack (or piggyback pending output) */
		if (st->txq_off < st->txq_len)
			peap_send_fragment(st, id);
		else
			peap_send_ack(st, id);
		return;
	}

	if (st->rx_len == 0 && (flags & PEAP_FLAGS_START) == 0) {
		/* A flags-only frame acks our fragment: send the next one if
		 * there is one queued, else ack back. */
		if (st->txq_off < st->txq_len)
			peap_send_fragment(st, id);
		else
			peap_send_ack(st, id);
		return;
	}

	{
		u_char blob[PEAP_RX_MAX];
		int blen = st->rx_len;
		MEMCPY(blob, st->rx, blen);
		st->rx_len = 0;
		st->rx_total = 0;
		peap_feed_tls(st, id, blob, blen);
	}
}

#endif /* PPP_SUPPORT && EAP_SUPPORT && MSCHAP_SUPPORT */
