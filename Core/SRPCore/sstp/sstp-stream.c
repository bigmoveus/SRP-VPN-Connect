
#include "sstp-stream.h"


status_t sstp_stream_create(sstp_stream_st **stream, sstp_send_fn fn, sstp_get_cert_hash_fn get_hash, void *ctx) {
    /* Create a new stream */
    sstp_stream_st *stream_= calloc(1, sizeof(sstp_stream_st));
    if (!stream_)
    {
        return SSTP_FAIL;
    }
    stream_->ctx = ctx;
    stream_->sender = fn;
    stream_->get_cert_hash = get_hash;
    *stream = stream_;
    /* Success */
    return SSTP_OKAY;
}

/*!
 * @brief Send a buffer using non-blocking I/O on the SSL socket.
 * @param client    [IN] The client context to communicate on
 * @param buf       [IN] The buffer structure
 * @param complete  [IN] The callback to call when SSTP_INPROG is returned
 *
 * @return SSTP_OKAY when buffer is written successfully to the socket,
 *  SSTP_FAIL if an error occured during the write, and
 *  SSTP_INPROG if the operation would block
 */
status_t sstp_stream_send(sstp_stream_st *client, sstp_buff_st *buf,
                          sstp_complete_fn complete, void *ctx, int timeout) {
    client->sender(client, buf, complete, ctx, timeout);
    return SSTP_OKAY;
}
/*!
 * @brief Request another receive operation based on the previous parameters
 */
void sstp_stream_req_recv(sstp_stream_st *ctx){
    
}
/*!
 * @brief Get the certificate hash from the peer certificate
 */
status_t sstp_get_cert_hash(sstp_stream_st *ctx, int proto,
                            unsigned char *hash, int hlen) {
    return ctx->get_cert_hash(ctx, proto, hash, hlen);
}

/*!
 * @brief A Handler for receiving SSTP packets
 */
status_t sstp_stream_recv_sstp(sstp_stream_st *ctx, sstp_buff_st *buf,
                               sstp_complete_fn complete, void *arg, int timeout) {
    return SSTP_OKAY;
}

/*!
 * @brief Setup a socket handler for the SSL connection
 *
 * @par Note:
 *  The @a handler can be either a custom function or it can be any
 *  of the sstp_stream_recv, sstp_client_recv_sstp, or
 *  sstp_stream_recv_http functions.
 */
void sstp_stream_setrecv(sstp_stream_st *ctx, sstp_recv_fn recv_cb,
                         sstp_buff_st *buf, sstp_complete_fn complete, void *arg, int timeout) {
    
}


status_t sstp_stream_destroy(sstp_stream_st *stream) {
    stream->ctx = NULL;
    stream->sender = NULL;
    stream->get_cert_hash = NULL;
    free(stream);
    return SSTP_OKAY;
}
