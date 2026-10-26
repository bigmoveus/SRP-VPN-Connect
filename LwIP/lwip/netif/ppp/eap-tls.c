/*
 * eap-tls.c - EAP-TLS (EAP type 13) client, RFC 5216 — mutual TLS with a
 *             client certificate.
 *
 * Wire flow (bare, client side):
 *   <- EAP-Request/TLS (empty)                  -> TLS ClientHello
 *   <- ... handshake records (L/M fragments) ...
 *   <- EAP-Request/TLS (empty ack of our final fragment)
 *   -> empty ack
 *   <- cleartext EAP Success
 *
 * Inside PEAP/TTLS/TEAP the same engine runs nested: the tunnel engine
 * feeds inner EAP-Request/TLS payloads and forwards our output frames
 * into the tunnel.
 *
 * Client credentials: PEM blobs via ppp_settings (eap_tls_cert_pem /
 * eap_tls_key_pem), owned by the upper layer.  BoringSSL verifies nothing
 * itself (SSL_VERIFY_NONE); the caller applies its own certificate policy
 * (for bare EAP-TLS and inner use the engine reports the peer leaf SHA256
 * comparison result via the done callback log only — the PEAP/TTLS policy
 * of "pin to the outer leaf, warn + continue on split-host" applies).
 *
 * MPPE keys (RFC 5216 2.3): TLS exporter "client EAP encryption", 64
 * octets; MS-MPPE-Recv-Key = first 32 (NAS recv = client send),
 * MS-MPPE-Send-Key = next 32 — stored client-perspective in the ppp
 * settings for the SSTP crypto binding.
 */

#include "netif/ppp/ppp_opts.h"
#if PPP_SUPPORT && EAP_SUPPORT  /* don't build if not configured for use in lwipopts.h */

#include "netif/ppp/ppp_impl.h"
#include "netif/ppp/eap.h"
#include "netif/ppp/eap-tls.h"

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/x509.h>

#include <string.h>
#include <stdlib.h>

#ifndef EAP_TLS_DEBUG_DUMP
#define EAP_TLS_DEBUG_DUMP 0
#endif
#if EAP_TLS_DEBUG_DUMP
static void etls_dump(const char *what, const u_char *p, int len) {
	char buf[400];
	int off = 0, i;
	buf[0] = '\0';
	if (p != NULL) {
		for (i = 0; i < len && off < (int)sizeof(buf) - 3; i++)
			off += snprintf(buf + off, sizeof(buf) - off, "%02x", p[i]);
	}
	ppp_info("EAP-TLS %s (%d): %s", what, len, buf);
}
#else
#define etls_dump(...)
#endif

#define EAPTLS_EAP_MTU	1000	/* max TLS bytes per EAP frame (bare) */
#define EAPTLS_RX_MAX	65536	/* reassembly buffer (CertificateRequest CA lists can be large) */
#define EAPTLS_TXQ_MAX	16384	/* pending TLS output */

struct eap_tls_engine {
	ppp_pcb *pcb;
	SSL_CTX *ssl_ctx;
	SSL *ssl;
	BIO *net_bio;
	int handshake_done;
	int failed;
	int done;		/* handshake complete; cleartext EAP Success is legitimate */

	u_char txq[EAPTLS_TXQ_MAX];
	int txq_off, txq_len;

	u_char rx[EAPTLS_RX_MAX];
	int rx_len;
	u32_t rx_total;

	int frag_mtu;		/* max TLS bytes per EAP frame */
	eap_tls_send_fn send_cb;
	void *send_arg;
	eap_tls_done_fn done_cb;
	void *done_arg;
};

static void etls_fail(eap_tls_engine *e) {
	e->failed = 1;
	if (e->done_cb != NULL)
		e->done_cb(e->done_arg, 0);
}

static void etls_drain(eap_tls_engine *e) {
	for (;;) {
		int room = EAPTLS_TXQ_MAX - e->txq_len;
		int n;
		if (room <= 0)
			break;
		n = BIO_read(e->net_bio, e->txq + e->txq_len, room);
		if (n <= 0)
			break;
		e->txq_len += n;
	}
}

static void etls_send_fragment(eap_tls_engine *e, u_char id) {
	u_char payload[5 + EAPTLS_TUNNELED_MTU];
	u_char *o = payload;
	int chunk = e->txq_len - e->txq_off;
	u_char flags = 0;

	if (chunk > e->frag_mtu) {
		chunk = e->frag_mtu;
		flags = EAPTLS_FLAGS_MORE_FRAGMENTS;
	}
	if (e->txq_off == 0) {
		/* First fragment of a TLS message: include the total TLS
		 * message length (Windows and wpa_supplicant behaviour;
		 * NPS mis-computes PEAP crypto-binding without it). */
		flags |= EAPTLS_FLAGS_LENGTH_INCLUDED;
		PUTCHAR(flags, o);
		PUTLONG(e->txq_len, o);
	} else {
		PUTCHAR(flags, o);
	}
	MEMCPY(o, e->txq + e->txq_off, chunk);
	etls_dump("TX fragment", payload, (int)(o - payload) + chunk);
	e->send_cb(e->send_arg, id, payload, (int)(o - payload) + chunk);
	e->txq_off += chunk;
	if (e->txq_off == e->txq_len) {
		e->txq_off = e->txq_len = 0;
	}
}

static void etls_send_ack(eap_tls_engine *e, u_char id) {
	u_char flags = 0;
	etls_dump("TX ack", &flags, 1);
	e->send_cb(e->send_arg, id, &flags, 1);
}

static void etls_flush(eap_tls_engine *e, u_char id) {
	etls_drain(e);
	if (e->txq_len > 0)
		etls_send_fragment(e, id);
	else
		etls_send_ack(e, id);
}

/* Report the peer certificate's relation to the outer SSTP leaf. */
static void etls_report_cert(eap_tls_engine *e) {
	X509 *cert = SSL_get_peer_certificate(e->ssl);
	if (cert == NULL) {
		ppp_error("EAP-TLS: server presented no TLS certificate");
		return;
	}
	int derlen = i2d_X509(cert, NULL);
	if (derlen <= 0) {
		X509_free(cert);
		return;
	}
	u_char *der = (u_char *)malloc(derlen);
	u_char *dp = der;
	u_char digest[SHA256_DIGEST_LENGTH];
	i2d_X509(cert, &dp);
	SHA256(der, derlen, digest);
	free(der);
	X509_free(cert);
	if (!e->pcb->settings.peap_cert_check) {
		ppp_warn("EAP-TLS: TLS certificate NOT verified (allowInsecure is on)");
		return;
	}
	if (memcmp(digest, e->pcb->settings.peap_cert_sha256, SHA256_DIGEST_LENGTH) == 0) {
		ppp_info("EAP-TLS: TLS certificate fingerprint matches the outer connection");
		return;
	}
	{
		char inner_fp[65], outer_fp[65];
		int i;
		for (i = 0; i < 32; i++) {
			snprintf(inner_fp + 2 * i, 3, "%02x", digest[i]);
			snprintf(outer_fp + 2 * i, 3, "%02x",
			    e->pcb->settings.peap_cert_sha256[i]);
		}
		inner_fp[64] = outer_fp[64] = '\0';
		ppp_warn("EAP-TLS: EAP TLS certificate differs from the SSTP outer connection");
		ppp_warn("EAP-TLS: EAP leaf SHA256 %s", inner_fp);
		ppp_warn("EAP-TLS: outer leaf SHA256 %s (expected when the EAP server "
		    "is a different host than the SSTP concentrator; accepted for now, "
		    "strict split-host pinning is not implemented yet)", outer_fp);
	}
}

static void etls_feed(eap_tls_engine *e, u_char id, const u_char *data, int len) {
	if (len > 0)
		BIO_write(e->net_bio, data, len);

	if (!e->handshake_done) {
		int ret = SSL_do_handshake(e->ssl);
		if (ret == 1) {
			e->handshake_done = 1;
			e->done = 1;
			ppp_info("EAP-TLS: TLS handshake complete (%s)", SSL_get_version(e->ssl));
			etls_report_cert(e);
			if (e->done_cb != NULL)
				e->done_cb(e->done_arg, 1);
		} else {
			int err = SSL_get_error(e->ssl, ret);
			if (err != SSL_ERROR_WANT_READ) {
				ppp_error("EAP-TLS: TLS handshake failed (%d)", err);
#if EAP_TLS_DEBUG_DUMP
				{
					unsigned long ev;
					while ((ev = ERR_get_error()) != 0) {
						char es[160];
						ERR_error_string_n(ev, es, sizeof(es));
						ppp_error("EAP-TLS: OpenSSL: %s", es);
					}
				}
#endif
				etls_fail(e);
				return;
			}
		}
		etls_flush(e, id);
		return;
	}

	/* After the handshake the server may still push TLS data (some
	 * servers send a final empty TLS record); nothing is read — the
	 * cleartext EAP Success ends the method. */
	etls_flush(e, id);
}

int eap_tls_engine_init(eap_tls_engine **out, ppp_pcb *pcb, int frag_mtu,
    eap_tls_send_fn send_cb, void *send_arg,
    eap_tls_done_fn done_cb, void *done_arg) {
	eap_tls_engine *e;

	*out = NULL;
	e = (eap_tls_engine *)malloc(sizeof(*e));
	if (e == NULL)
		return -1;
	BZERO(e, sizeof(*e));
	e->pcb = pcb;
	e->frag_mtu = frag_mtu > 0 ? frag_mtu : EAPTLS_EAP_MTU;
	e->send_cb = send_cb;
	e->send_arg = send_arg;
	e->done_cb = done_cb;
	e->done_arg = done_arg;

	e->ssl_ctx = SSL_CTX_new(TLS_client_method());
	if (e->ssl_ctx == NULL)
		goto fail;
	SSL_CTX_set_verify(e->ssl_ctx, SSL_VERIFY_NONE, NULL);
	if (pcb->settings.eap_disable_legacy_tls)
		SSL_CTX_set_min_proto_version(e->ssl_ctx, TLS1_2_VERSION);
	if (!pcb->settings.eap_tls13_enabled)
		SSL_CTX_set_max_proto_version(e->ssl_ctx, TLS1_2_VERSION);

	/* Client certificate (mutual TLS) */
	if (pcb->settings.eap_tls_cert_pem != NULL &&
	    pcb->settings.eap_tls_key_pem != NULL) {
		BIO *cb = BIO_new_mem_buf(pcb->settings.eap_tls_cert_pem,
		    pcb->settings.eap_tls_cert_pem_len);
		BIO *kb = BIO_new_mem_buf(pcb->settings.eap_tls_key_pem,
		    pcb->settings.eap_tls_key_pem_len);
		X509 *cert = cb ? PEM_read_bio_X509(cb, NULL, NULL, NULL) : NULL;
		EVP_PKEY *key = kb ? PEM_read_bio_PrivateKey(kb, NULL, NULL, NULL) : NULL;
		int ok = 0;
		if (cert != NULL && key != NULL &&
		    SSL_CTX_use_certificate(e->ssl_ctx, cert) == 1 &&
		    SSL_CTX_use_PrivateKey(e->ssl_ctx, key) == 1)
			ok = 1;
		if (cert != NULL)
			X509_free(cert);
		if (key != NULL)
			EVP_PKEY_free(key);
		if (cb != NULL)
			BIO_free(cb);
		if (kb != NULL)
			BIO_free(kb);
		if (!ok) {
			ppp_error("EAP-TLS: failed to load the client certificate/key");
			goto fail;
		}
	}

	e->ssl = SSL_new(e->ssl_ctx);
	if (e->ssl == NULL)
		goto fail;
	{
		BIO *ssl_bio = NULL, *net_bio = NULL;
		if (BIO_new_bio_pair(&ssl_bio, EAPTLS_RX_MAX, &net_bio, EAPTLS_TXQ_MAX) != 1) {
			SSL_free(e->ssl);
			goto fail;
		}
		SSL_set_bio(e->ssl, ssl_bio, ssl_bio);	/* SSL owns ssl_bio */
		e->net_bio = net_bio;
	}
	SSL_set_connect_state(e->ssl);

	*out = e;
	return 0;

fail:
	if (e->ssl_ctx != NULL)
		SSL_CTX_free(e->ssl_ctx);
	free(e);
	return -1;
}

void eap_tls_engine_free(eap_tls_engine *e) {
	if (e == NULL)
		return;
	if (e->ssl != NULL)
		SSL_free(e->ssl);
	if (e->net_bio != NULL)
		BIO_free(e->net_bio);
	if (e->ssl_ctx != NULL)
		SSL_CTX_free(e->ssl_ctx);
	free(e);
}

void eap_tls_engine_input(eap_tls_engine *e, u_char eap_id, const u_char *payload, int len) {
	u_char flags;
	const u_char *data;
	int dlen;

	if (e->failed)
		return;

	/* Empty request: fragment ack (or the final post-handshake round) */
	if (len == 0) {
		if (e->txq_off < e->txq_len)
			etls_send_fragment(e, eap_id);
		else
			etls_send_ack(e, eap_id);
		return;
	}

	flags = payload[0];
	data = payload + 1;
	dlen = len - 1;
	etls_dump("RX frame", payload, len);

	if (flags & EAPTLS_FLAGS_LENGTH_INCLUDED) {
		u32_t total;
		if (dlen < 4)
			return;
		total = ((u32_t)data[0] << 24) | ((u32_t)data[1] << 16) |
		    ((u32_t)data[2] << 8) | (u32_t)data[3];
		data += 4;
		dlen -= 4;
		/* Some servers set the L bit on EVERY fragment (Windows only
		 * on the first); only treat it as the start of a new
		 * message when no reassembly is in progress. */
		if (e->rx_len == 0)
			e->rx_total = total;
	}

	if (e->rx_len + dlen > EAPTLS_RX_MAX) {
		ppp_error("EAP-TLS: reassembly buffer overflow");
		etls_fail(e);
		return;
	}
	MEMCPY(e->rx + e->rx_len, data, dlen);
	e->rx_len += dlen;

	if (flags & EAPTLS_FLAGS_MORE_FRAGMENTS) {
		if (e->txq_off < e->txq_len)
			etls_send_fragment(e, eap_id);
		else
			etls_send_ack(e, eap_id);
		return;
	}

	{
		u_char blob[EAPTLS_RX_MAX];
		int blen = e->rx_len;
		MEMCPY(blob, e->rx, blen);
		e->rx_len = 0;
		e->rx_total = 0;
		etls_feed(e, eap_id, blob, blen);
	}
}

int eap_tls_engine_mppe_keys(eap_tls_engine *e, ppp_pcb *pcb) {
	u_char keymat[64];

	if (eap_tls_engine_export_km(e, keymat) != 0)
		return 0;
	MEMCPY(pcb->settings.eap_mppe_send_key, keymat, 32);
	MEMCPY(pcb->settings.eap_mppe_recv_key, keymat + 32, 32);
	pcb->settings.eap_mppe_keys_ok = 1;
	ppp_info("EAP-TLS: MPPE keys derived from the TLS key material");
	BZERO(keymat, sizeof(keymat));
	return 1;
}

int eap_tls_engine_export_km(eap_tls_engine *e, u_char out[64]) {
	if (e == NULL || e->ssl == NULL || !e->handshake_done)
		return -1;
	if (SSL_export_keying_material(e->ssl, out, 64,
	    "client EAP encryption", 21, NULL, 0, 0) != 1)
		return -1;
	return 0;
}

/*
 * Bare-mode wrapper: the EAP-TLS engine bound to the pcb (eap.c drives it
 * for cleartext EAP type 13).
 */
static void etls_bare_send(void *arg, u_char eap_id, const u_char *payload, int len) {
	eap_send_response((ppp_pcb *)arg, eap_id, EAPT_TLS, payload, len);
}

static void etls_bare_done(void *arg, int ok) {
	ppp_pcb *pcb = (ppp_pcb *)arg;
	if (!ok) {
		eap_tls_free(pcb);
		pcb->eap.es_client.ea_state = eapBadAuth;
		auth_withpeer_fail(pcb, PPP_EAP);
		return;
	}
	eap_tls_engine_mppe_keys((eap_tls_engine *)pcb->eap.es_tls, pcb);
}

void eap_tls_input(ppp_pcb *pcb, u_char id, const u_char *payload, int len) {
	eap_tls_engine *e = (eap_tls_engine *)pcb->eap.es_tls;

	if (e == NULL) {
		if (eap_tls_engine_init(&e, pcb, 0, etls_bare_send, pcb,
		    etls_bare_done, pcb) != 0) {
			ppp_error("EAP-TLS: out of memory");
			auth_withpeer_fail(pcb, PPP_EAP);
			return;
		}
		pcb->eap.es_tls = e;
		ppp_info("EAP-TLS: start (TLS handshake begins)");
	}
	eap_tls_engine_input(e, id, payload, len);
}

void eap_tls_free(ppp_pcb *pcb) {
	eap_tls_engine *e = (eap_tls_engine *)pcb->eap.es_tls;
	pcb->eap.es_tls = NULL;
	eap_tls_engine_free(e);
}

int eap_tls_active(ppp_pcb *pcb) {
	return pcb->eap.es_tls != NULL;
}

int eap_tls_done(ppp_pcb *pcb) {
	eap_tls_engine *e = (eap_tls_engine *)pcb->eap.es_tls;
	return e != NULL && e->done;
}

#endif /* PPP_SUPPORT && EAP_SUPPORT */
