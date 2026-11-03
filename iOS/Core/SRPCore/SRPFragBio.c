//
//  SRPFragBio.m
//  SRPCore
//

#include "SRPFragBio.h"
#import <unistd.h>

typedef struct {
    size_t firstChunk;
    size_t followingChunk;
    unsigned gapMs;
    int splitActive;    // 1 until the first inbound byte (initial flight)
    int burstStart;     // 1 = next write starts a burst (firstChunk applies)
} SRPFragState;

static BIO_METHOD *fragMethod = NULL;

static int frag_create(BIO *b) {
    SRPFragState *st = calloc(1, sizeof(SRPFragState));
    if (!st) return 0;
    st->splitActive = 1;
    st->burstStart = 1;
    BIO_set_data(b, st);
    BIO_set_init(b, 1);
    return 1;
}

static int frag_destroy(BIO *b) {
    if (!b) return 0;
    free(BIO_get_data(b));
    BIO_set_data(b, NULL);
    BIO_set_init(b, 0);
    return 1;
}

static int frag_write(BIO *b, const char *in, int inl) {
    SRPFragState *st = (SRPFragState *)BIO_get_data(b);
    BIO *next = BIO_next(b);
    if (!st || !next || inl <= 0) return inl <= 0 ? inl : -1;

    if (!st->splitActive) {
        int n = BIO_write(next, in, inl);
        if (n < 0 && BIO_should_retry(next)) BIO_set_retry_write(b);
        return n;
    }

    int consumed = 0;
    while (consumed < inl) {
        size_t chunk = st->burstStart ? st->firstChunk : st->followingChunk;
        if (chunk > (size_t)(inl - consumed)) chunk = (size_t)(inl - consumed);
        int n = BIO_write(next, in + consumed, (int)chunk);
        if (n <= 0) {
            if (BIO_should_retry(next)) BIO_set_retry_write(b);
            return consumed > 0 ? consumed : n;
        }
        consumed += n;
        st->burstStart = 0;
        if (st->gapMs && consumed < inl) usleep(st->gapMs * 1000);
    }
    if (st->gapMs == 0) {
        // Chunks written back-to-back may still coalesce on the wire; that is
        // inherent to TCP and documented in the design.
    }
    return consumed;
}

static int frag_read(BIO *b, char *out, int outl) {
    SRPFragState *st = (SRPFragState *)BIO_get_data(b);
    BIO *next = BIO_next(b);
    if (!st || !next) return -1;
    int n = BIO_read(next, out, outl);
    if (n > 0) {
        st->splitActive = 0;   // the server's first flight arrived — stop splitting
    } else if (BIO_should_retry(next)) {
        BIO_set_retry_read(b);
    }
    return n;
}

static long frag_ctrl(BIO *b, int cmd, long larg, void *parg) {
    BIO *next = BIO_next(b);
    if (!next) return 0;
    if (cmd == BIO_CTRL_FLUSH) return BIO_ctrl(next, cmd, larg, parg);
    return BIO_ctrl(next, cmd, larg, parg);
}

BIO *srp_frag_bio_new(size_t firstChunk, size_t followingChunk, unsigned gapMs) {
    if (!fragMethod) {
        fragMethod = BIO_meth_new(BIO_TYPE_FILTER, "srp-frag");
        if (!fragMethod) return NULL;
        BIO_meth_set_write(fragMethod, frag_write);
        BIO_meth_set_read(fragMethod, frag_read);
        BIO_meth_set_ctrl(fragMethod, frag_ctrl);
        BIO_meth_set_create(fragMethod, frag_create);
        BIO_meth_set_destroy(fragMethod, frag_destroy);
    }
    BIO *b = BIO_new(fragMethod);
    if (!b) return NULL;
    SRPFragState *st = (SRPFragState *)BIO_get_data(b);
    st->firstChunk = firstChunk;
    st->followingChunk = followingChunk;
    st->gapMs = gapMs;
    return b;
}
