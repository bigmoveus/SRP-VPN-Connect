/*!
 * @brief Managing the interface with pppd
 *
 * @file sstp-pppd.h
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
#ifndef __SSTP_PPPD_H__
#define __SSTP_PPPD_H__

#include "sstp/sstp-task.h"
#include "sstp/sstp-chap.h"
#include "sstp/sstp-ppp.h"

struct sstp_pppd;
typedef struct sstp_pppd sstp_pppd_st;


/*! 
 * @brief PPP state events
 */
typedef enum
{
    SSTP_PPP_DOWN = 1,
    SSTP_PPP_UP   = 2,
    SSTP_PPP_AUTH = 3,
    SSTP_PPP_START= 4,

} sstp_pppd_event_t;


/*!
 * @brief PPP Session details
 */ 
typedef struct 
{
    /*< The established session length */
    unsigned long established;

    /*< The number of bytes received from server */
    unsigned long long rx_bytes;

    /*< The number of bytes sent to server */
    unsigned long long tx_bytes;

} sstp_session_st;


/*!
 * @brief Structure to keep all the options enabled
 */
typedef struct
{
    /*< The range of options enabled */
    int enable;

    /*! the CA certificate in PEM format */
    char *ca_cert;

    /*! The CA certificate path */
    char *ca_path;

    /*! The CRL file in PEM format */
    char *crl_file;

    /*! The CRL directory */
    char *crl_path;

    /*! The original server string */
    char *server;

    /*! The hostname to use if server is an ip address */
    char *host;

    /*! Unique connection parameter */
    char *ipparam;

    /*! Password */
    char *password;

    /*! The proxy URL */
    char *proxy;

    /*! The privilege separation user */
    char *priv_user;
    
    /*! The privilege separation group */
    char *priv_group;

    /*! The privilege separation directory */
    char *priv_dir;

    /*! Username */
    char *user;

    /*! Use a persistent UUID */
    char *uuid;

    /*! The number of arguments to pppd */
    int pppdargc;

    /*! The arguments vector to pppd */
    char **pppdargv;

} sstp_option_st;

/*< Don't launch the pppd daemon */
#define SSTP_OPT_NOLAUNCH       0x0001
#define SSTP_OPT_NODAEMON       0x0002
#define SSTP_OPT_NOPLUGIN       0x0008
#define SSTP_OPT_CERTWARN       0x0010
#define SSTP_OPT_SAVEROUTE      0x0020
#define SSTP_OPT_TLSEXT         0x0040

/*!
 * @brief Client callback
 */
typedef void (*sstp_pppd_fn)(void *ctx, sstp_pppd_event_t ev);

/*!
 * @brief Return the chap context
 */
sstp_chap_st *sstp_pppd_getchap(sstp_pppd_st *ctx);

/*!
 * @brief Mark authentication as done for tunneled-EAP methods (PEAP/TTLS/
 *  TEAP), where the cleartext CHAP/EAP snoop never sees the credentials.
 *  The MPPE keys are pushed separately via sstp_state_mppe_keys().
 */
void sstp_pppd_auth_done(sstp_pppd_st *ctx);


/*!
 * @brief Create the pppd context
 */
status_t sstp_pppd_create(sstp_pppd_st **ctx, sstp_stream_st *stream, sstp_pppd_fn notify, void *arg);


/*!
 * @brief Free the pppd context
 */
void sstp_pppd_free(sstp_pppd_st *ctx);

/// 直接接收 pppd 发送过来的二进制消息内容
/// @param ctx pppd 上下文
/// @param message 消息内容
/// @param length 消息长度
void sstp_pppd_recv(sstp_pppd_st *ctx, char *message, int length);


#endif /* #ifndef __SSTP_SSL_H__ */
