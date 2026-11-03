
#ifndef sstp_stream_h
#define sstp_stream_h

#include <stdio.h>
#include <openssl/ssl.h>
#include "sstp/sstp-common.h"
#include "sstp/sstp-buff.h"
#include "sstp/sstp-chap.h"
#include "sstp/sstp-packet.h"

typedef struct sstp_stream sstp_stream_st;
typedef struct timeval timeval_st;

/*!
 * @brief A function to notify of complete send or receive event
 */
typedef void (*sstp_complete_fn)(sstp_stream_st *stream,
        sstp_buff_st *buf, void *ctx, status_t status);

/*!
 * @brief The handler function that will handle the receive of the data
 */
typedef status_t (*sstp_recv_fn)(sstp_stream_st *ctx, sstp_buff_st *buf,
        sstp_complete_fn complete, void *arg, int timeout);

/*!
 * @brief stream 的所有消息内容均通过下列回掉使用 SSSSTPClient 进行发送
 */
typedef status_t (*sstp_send_fn)(sstp_stream_st *stream, sstp_buff_st *buf,
        sstp_complete_fn complete, void *ctx, int timeout);

/*!
 * @brief 获取证书函数，通过该回掉获取 Network.framework 库的证书内容
 */
typedef status_t (*sstp_get_cert_hash_fn)(sstp_stream_st *ctx, int proto,
                                       unsigned char *hash, int hlen);

/*!
 * @brief A asynchronous send or recv channel object
 */
typedef struct sstp_operation
{
    /*< The next operation */
    struct sstp_operation *next;

    /*< Timeout if any */
    timeval_st tout;

    /*< Associated buffer with this channel */
    sstp_buff_st *buf;

    /*< Complete callback function */
    sstp_complete_fn complete;

    /*< Argument to pass back the complete function */
    void *arg;
    
} sstp_operation_st;

/*!
 * @brief The ssl client context
 */
struct sstp_stream
{
    /*< The send socket */
    int ssock;

    /*< The recv socket */
    int rsock;

    /*< Last activity seen on socket */
    time_t last;
    
    /*< The connection sender */
    sstp_send_fn sender;
    sstp_get_cert_hash_fn get_cert_hash;

    /*< The length check function */
    sstp_recv_fn recv_cb;


    /*< Channel for receive operation */
    sstp_operation_st recv;


    /*< Channel for send operation */
    sstp_operation_st *send;

    /*< The list of free operations */
    sstp_operation_st *cache;
    
    /*< Context >*/
    void *ctx;
};


status_t sstp_stream_create(sstp_stream_st **stream, sstp_send_fn fn, sstp_get_cert_hash_fn get_cert_hash, void *ctx);

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
        sstp_complete_fn complete, void *ctx, int timeout);
/*!
 * @brief Request another receive operation based on the previous parameters
 */
void sstp_stream_req_recv(sstp_stream_st *ctx);
/*!
 * @brief Get the certificate hash from the peer certificate
 */
status_t sstp_get_cert_hash(sstp_stream_st *ctx, int proto,
    unsigned char *hash, int hlen);

/*!
 * @brief A Handler for receiving SSTP packets
 */
status_t sstp_stream_recv_sstp(sstp_stream_st *ctx, sstp_buff_st *buf,
        sstp_complete_fn complete, void *arg, int timeout);

/*!
 * @brief Setup a socket handler for the SSL connection
 *
 * @par Note:
 *  The @a handler can be either a custom function or it can be any
 *  of the sstp_stream_recv, sstp_client_recv_sstp, or
 *  sstp_stream_recv_http functions.
 */
void sstp_stream_setrecv(sstp_stream_st *ctx, sstp_recv_fn recv_cb,
        sstp_buff_st *buf, sstp_complete_fn complete, void *arg, int timeout);


status_t sstp_stream_destroy(sstp_stream_st *stream);

#endif /* sstp_stream_h */
