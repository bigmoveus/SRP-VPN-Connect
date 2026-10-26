/*!
 * @brief Managing the interface with pppd
 *
 * @file sstp-pppd.c
 *
 * @author Copyright (C) 2011 Eivind Naess, 
 *      All Rights Reserved
 *
 * @par License:
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */


#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <paths.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <sys/types.h>

#ifndef SSTP_PPPD_DEBUG
#define SSTP_PPPD_DEBUG 0
#endif

#include "sstp-private.h"
#include "sstp/sstp-task.h"
#include "sstp/sstp-state.h"
#include "sstp/sstp-pppd.h"
#include "utils.h"
#include <arpa/inet.h>
#include <netinet/ip.h>

/*!
 * @brief Context for the PPPd operations
 */
struct sstp_pppd
{
    /*< Task structure */
    sstp_task_st *task;

    /*< A buffer we can receive data with */
    sstp_buff_st *rx_buf;

    /*< A buffer we can send data with */
    sstp_buff_st *tx_buf;

    /*< The SSL stream context */
    sstp_stream_st *stream;

    /*< The chap structure */
    sstp_chap_st chap;

    /*< The notify function */
    sstp_pppd_fn notify;

    /*< The argument to pass to the notify function */
    void *arg;

    /*< The socket to pppd */
    int sock;

    /*< Should we notify client of ip_up */
    int ip_up;
    
    /*< Should we stil continue checking for CHAP structure */
    int auth_done;

    /*< Enable authentication check */
    int auth_check;

    /*< The time pppd was terminated */
    unsigned long t_end;

    /*< The time pppd was started */
    unsigned long t_start;

    /*< First read from pppd */
    bool first;
};


static status_t ppp_process_data(sstp_pppd_st *ctx);

/*!
 * @brief Throttle receive operation, previous send incomplete.
 *
 * @par Function:
 *  If the send operation was blocked, we'll receive a complete event.
 *  1) Continue sending the remainding data in rx-buffer to server
 *  2) If send() blocks again, we'll re-enter at this point
 *  3) When complete, re-add the sstp_pppd_recv event function here.
 */
static void ppp_send_complete(sstp_stream_st *stream, sstp_buff_st *buf,
    sstp_pppd_st *ctx, status_t status)
{
    if (SSTP_OKAY != status)
    {
        x_debug("Failed to complete write to pppd");
    }

    /* Continue processing input */
    status = ppp_process_data(ctx);
    switch (status)
    {
    case SSTP_INPROG:
        /* Will invoke this function again */
        break;

    case SSTP_OKAY:
        /* Record the number of bytes sent */

        /* We had to trottle the recevie operation, re-start */
//            TODO: 事件添加
//        event_add(ctx->ev_recv, NULL);
        break;

    case SSTP_FAIL:
    default:
        x_debug("Failed to receive data from pppd");
        break;
    }
}


sstp_chap_st *sstp_pppd_getchap(sstp_pppd_st *ctx)
{
    return (&ctx->chap);
}


static void sstp_pppd_ipup(sstp_pppd_st* ctx, sstp_buff_st *tx)
{
    uint8_t *buf = sstp_pkt_data(tx);
    uint16_t proto;

    if (buf[0] == 0xFF && buf[1] == 0x03)
    {
        buf += 2;
    }

    proto = (ntohs(*(uint16_t *) buf));
    if (proto == PPP_PROTO_IPCP)
    {
        if (ctx->notify)
        {
            ctx->notify(ctx->arg, SSTP_PPP_UP);
        }

        ctx->ip_up = 1;
    }

    return;
}

/*!
 * @brief Mark authentication complete (tunneled-EAP paths; see header).
 */
void sstp_pppd_auth_done(sstp_pppd_st *ctx)
{
    if (ctx)
    {
        ctx->auth_done = 1;
    }
}

/*!
 * @brief Intercept any CHAP / PAP authentication with the peer.
 */
static void sstp_pppd_check_auth(sstp_pppd_st* ctx, sstp_buff_st *tx)
{
    ppp_hdr_st *hdr; 
    uint8_t *buf = sstp_pkt_data(tx);
    uint16_t proto;
    bool pcomp;
    
	/* Skip HDLC header */
    if (buf[0] == 0xFF && buf[1] == 0x03) 
    {
        buf += 2;
    }

    /* Get protocol, account for protocol compression 
     * NOTE:
     *   We don't track the LCP configuration protocol and if pcomp has been specified. We'll make an educated guess as far as
     *   trying to parse it here. CHAPv2 (0xC223), or EAP (0xC227) both has LSB set to 0 meaning we read both bytes.
     */
    pcomp = (buf[0] & 0x01);
    proto = pcomp ? buf[0] : buf[0] << 8 | buf[1];
    buf  += (pcomp) ? 1 : 2;

    hdr = (ppp_hdr_st*) buf;
    buf += sizeof(ppp_hdr_st);

    /* Check if we have received the MS-CHAPv2(0xC223) credentials */
    switch (proto)
    {
    case PPP_PROTO_CHAP:

        /* At this point, calculate the MPPE key ourselves */
        if (hdr->code == CHAP_RESPONSE && buf[0] == MSCHAP_VALUE_LEN) {
            memcpy(&ctx->chap, &buf[1], sizeof(sstp_chap_st));
            if (ctx->notify)
            {
                ctx->notify(ctx->arg, SSTP_PPP_AUTH);
            }

            ctx->auth_done = 1;
            break;
        }

        /* Plain CHAP (RFC 1994): the response carries a 16-byte MD5 value,
         * there is no MS-CHAPv2 key material on the wire.  Flag auth as done
         * (like PAP, MPPE keys stay zero) so the SSTP Connected message is
         * sent once IPCP comes up; otherwise the server waits for the call
         * to complete and eventually aborts it. */
        if (hdr->code == CHAP_RESPONSE && !ctx->auth_done) {
            x_debug("Plain CHAP response seen, no MPPE keys available");
            memset(&ctx->chap, 0, sizeof(sstp_chap_st));
            ctx->auth_done = 1;
            break;
        }

        if (hdr->code == CHAP_FAILURE)
        {
            x_debug("CHAP authentication failed");
            break;
        }
        break;

    case PPP_PROTO_EAP:
    
        /* EAP_RESPONSE, and if MSCHAPv2; calculate the MPPE keys */
        if (hdr->code == EAP_RESPONSE) 
        {
            if (buf[0] == EAPT_MSCHAPV2) 
            {
                if (buf[1] == CHAP_RESPONSE &&  buf[5] == MSCHAP_VALUE_LEN)
                {
                    memcpy(&ctx->chap, &buf[6], sizeof(sstp_chap_st));
                    if (ctx->notify) 
                    {
                        ctx->notify(ctx->arg, SSTP_PPP_AUTH);
                    }
                    ctx->auth_done = 1;
                    break;
                }
            }
            if (buf[0] == EAPT_TLS) {
                x_debug("Invalid buf[0] == EAPT_TLS");
                return;
            }
        }
        
        break;

    case PPP_PROTO_PAP:
        /* Flag that auth is done, MPPE keys are all zero */
        ctx->auth_done = 1;
    default:

        break;
    }
}


/*!
 * @brief Process any data in the input buffer and forward them to server
 */
static status_t ppp_process_data(sstp_pppd_st *ctx)
{
    status_t ret = SSTP_OKAY;
    sstp_buff_st *rx = ctx->rx_buf;
    sstp_buff_st *tx = ctx->tx_buf;

#if SSTP_PPPD_DEBUG
    fprintf(stderr, "[PPPD] process_data: rx_len=%d off=%d\n", rx->len, rx->off);
#endif

    /* Initialize TX-buffer */
    sstp_buff_reset(tx);

    /* Iterate over the frames received */
    while (rx->off < rx->len)
    {
        int max = 0;
        int off = 0;

        /* Initialize send buffer */
        ret = sstp_pkt_init(tx, SSTP_MSG_DATA);
        if (SSTP_OKAY != ret)
        {
            return SSTP_FAIL;
        }

        /* Copy a single frame to the tx-buffer */
        max = tx->max - tx->len;
        off = rx->len - rx->off;
        ret = sstp_frame_decode((unsigned char*) rx->data + rx->off, &off,
            (unsigned char*) tx->data + tx->len, &max);
#if SSTP_PPPD_DEBUG
        {
            unsigned char *p = (unsigned char*) rx->data + rx->off;
            fprintf(stderr, "[PPPD] decode ret=%d off=%d max=%d first=%02x %02x %02x %02x %02x\n",
                ret, off, max, p[0], p[1], p[2], p[3], p[4]);
        }
#endif
        if (SSTP_OKAY != ret)
        {
            /* We needed to read more ... */
            if (SSTP_OVERFLOW == ret || (rx->len == (rx->off + off))) {
                /* Move current packet to beginning of buffer */
                memmove(rx->data, rx->data + rx->off, rx->len - rx->off);
                rx->len = off;
                rx->off = 0;

                /* Need more data, re-add read event */
                return SSTP_OKAY;
            }

            /* Checksum Error!, drop this segment */
            rx->off += off;
            continue;
        }

        /* Update length */
        tx->len += max;
        rx->off += off;

        /* Update the final length of the packet */
        sstp_pkt_update(tx);
#if SSTP_PPPD_DEBUG
        {
            unsigned char *p = (unsigned char*) tx->data;
            fprintf(stderr, "[PPPD] send SSTP len=%d hdr=%02x %02x %02x %02x payload-first=%02x %02x %02x %02x\n",
                tx->len, p[0], p[1], p[2], p[3],
                tx->len > 8 ? p[8] : 0, tx->len > 9 ? p[9] : 0, tx->len > 10 ? p[10] : 0, tx->len > 11 ? p[11] : 0);
        }
#endif

        /* If plugin is not enabled, then we need to check for auth */
        if (ctx->auth_check && !ctx->auth_done) 
        {
            sstp_pppd_check_auth(ctx, tx);
        }

        /* If plugin is not enabled, then we need to send ip-up */
        if (ctx->auth_check && ctx->auth_done && !ctx->ip_up)
        {
            sstp_pppd_ipup(ctx, tx);
        }
#if SSTP_LOG_PROTOCOL
        char *buf = (char *)sstp_pkt_data(tx);
        uint16_t protocol = buf ? ntohs(*(uint16_t *)(buf + 2)) : 0;
        if (protocol == 0x21) {
            struct ip *x = (struct ip *)(buf + 4);
            char ip_dst[32] = {0};
            char ip_src[32] = {0};
            char *dst = inet_ntoa(x->ip_dst);
            memcpy(ip_dst, dst, strlen(dst));
            
            char *src = inet_ntoa(x->ip_src);
            memcpy(ip_src, src, strlen(src));
            x_debug("send protocol:%x ip_dst: %s, ip_src:%s\n", protocol, ip_dst, ip_src);
        }
        else {
            x_debug("send protocol:%x\n", protocol);
        }
#endif
        /* Send a PPP frame */
        ret = sstp_stream_send(ctx->stream, tx, (sstp_complete_fn)  ppp_send_complete, ctx, 1);
        if (SSTP_OKAY != ret) {
            return SSTP_INPROG;
        }
    }
    
    /* Start over in an empty buffer */
    if (rx->off == rx->len)
    {
        sstp_buff_reset(rx);
    }
    return ret;
}

void sstp_pppd_recv(sstp_pppd_st *ctx, char *message, int length) {
    sstp_buff_append(ctx->rx_buf, message, length);
    
    /* Notifiy the caller pppd is configured and running */
    if (ctx->first) {
        ctx->notify(ctx->arg, SSTP_PPP_START);
        ctx->first = false;
    }
    
    /* Process the input */
    status_t ret = ppp_process_data(ctx);
    switch (ret)
    {
    case SSTP_INPROG:
        /* Let the ppp_send_complete finish it */
        break;

    case SSTP_OKAY:
        /* Re-add the event to receive more */
//            TODO: 事件添加
//        event_add(ctx->ev_recv, NULL);
        break;

    case SSTP_FAIL:
    default:
        x_debug("Failed to receive data from pppd");
        break;
    }
}

status_t sstp_pppd_create(sstp_pppd_st **ctx, sstp_stream_st *stream, sstp_pppd_fn notify_cb, void *arg)
{
    status_t ret    = SSTP_FAIL;
    status_t status = SSTP_FAIL;

    *ctx = calloc(1, sizeof(sstp_pppd_st));
    if (!*ctx)
    {
        goto done;
    }

    ret = sstp_buff_create(&(*ctx)->tx_buf, 16384);
    if (SSTP_OKAY != ret)
    {
        goto done;
    }

    ret = sstp_buff_create(&(*ctx)->rx_buf, 16384);
    if (SSTP_OKAY != ret)
    {
        goto done;
    }

    /* Save a reference to the stream handle */
    (*ctx)->stream = stream;
    (*ctx)->notify = notify_cb;
    (*ctx)->arg    = arg;
    (*ctx)->first  = true;
    (*ctx)->auth_check = 1;

    /* Success */
    status = SSTP_OKAY;

done:
    
    if (SSTP_OKAY != status)
    {
        sstp_pppd_free(*ctx);
    }

    return status;
}


void sstp_pppd_free(sstp_pppd_st *ctx)
{
    if (!ctx) {
        return;
    }

    /* Cleanup the task */
    if (ctx->task)
    {
        /* Check if task is still running, then kill it */
        if (sstp_task_alive(ctx->task))
        {
            sstp_task_stop(ctx->task);
        }

        /* Free resources */
        sstp_task_destroy(ctx->task);
        ctx->task  = NULL;
        ctx->t_end = time(NULL);
    }

    /* Dispose send buffers */
    if (ctx->tx_buf)
    {
        sstp_buff_destroy(ctx->tx_buf);
        ctx->tx_buf = NULL;
    }

    /* Dispose receive buffers */
    if (ctx->rx_buf)
    {
        sstp_buff_destroy(ctx->rx_buf);
        ctx->rx_buf = NULL;
    }

    /* Dispose of receive event */

    /* Free pppd context */
    free(ctx);
}
