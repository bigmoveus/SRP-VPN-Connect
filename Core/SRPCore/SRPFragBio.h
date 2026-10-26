//
//  SRPFragBio.h
//  SRPCore
//
//  OpenSSL filter BIO implementing TCP write splitting (SSTP-TLS-FRAG-001):
//  outgoing bytes are forwarded to the next BIO in ordered chunks; reads and
//  controls pass through untouched. Splitting stops after the first inbound
//  byte is seen (the server's first flight), i.e. only the initial client
//  flight (ClientHello) is split.
//
//  The byte stream is identical to an unsplit stream — only write sizes
//  differ. Partial writes and retry flags are honored (exactly-once,
//  in-order); an optional gap paces chunks so the TCP stack cannot merge
//  them back into one segment.
//

#ifndef SRP_FRAG_BIO_H
#define SRP_FRAG_BIO_H

#include <openssl/ssl.h>

#ifdef __cplusplus
extern "C" {
#endif

/// Returns a new filter BIO (caller owns), or NULL. firstChunk/followingChunk
/// are bytes; gapMs paces chunk writes (0 = no pacing).
BIO *srp_frag_bio_new(size_t firstChunk, size_t followingChunk, unsigned gapMs);

#ifdef __cplusplus
}
#endif

#endif /* SRP_FRAG_BIO_H */
