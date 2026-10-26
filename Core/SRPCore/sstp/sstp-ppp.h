/*!
 * @brief Definitions for PPP packet dump
 *
 * @file sstp-ppp.h
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

#ifndef __SSTP_PPP_H__
#define __SSTP_PPP_H__

//0xC023-PAP认证协议 Password Authentication Protocol
#define PPP_PROTO_PAP       0xc023

//0xC223-CHAP认证协议 Challenge Handshake Authentication Protocol
#define PPP_PROTO_CHAP      0xc223
#define PPP_PROTO_EAP       0xc227
#define PPP_PROTO_IPCP      0x8021

//0xC021-链路控制协议Link Control Protocol
#define PPP_PROTO_LCP       0xc021

//0xC025-链路质量报告Link Quality Report
#define PPP_PROTO_LQR       0xc025

/*
 
0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|      FLAG     |     Address   |    Control    |Protoc(8/16bit)|
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                  Information 1500 Bytes ...                   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|             FCS(16bit/32bit) ......           |       FLAG
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
:                   Point-to-Point Protocol                     :
 

0001 to 001f    reserved (transparency inefficient)
0021            Internet Protocol
0023            OSI Network Layer
0025            Xerox NS IDP
0027            DECnet Phase IV
0029            Appletalk
002b            Novell IPX
002d            Van Jacobson Compressed TCP/IP
002f            Van Jacobson Uncompressed TCP/IP
0031            Bridging PDU
0033            Stream Protocol (ST-II)
0035            Banyan Vines
0037            reserved (until 1993)
00ff            reserved (compression inefficient)

0201            802.1d Hello Packets
0231            Luxcom
0233            Sigma Network Systems

8021            Internet Protocol Control Protocol
8023            OSI Network Layer Control Protocol
8025            Xerox NS IDP Control Protocol
8027            DECnet Phase IV Control Protocol
8029            Appletalk Control Protocol
802b            Novell IPX Control Protocol
802d            Reserved
802f            Reserved
8031            Bridging NCP
8033            Stream Protocol Control Protocol
8035            Banyan Vines Control Protocol
8037            reserved till 1993
80ff            reserved (compression inefficient

*/
 
/*
 * PPP Codes
 */
#define FSM_CONFREQ         1
#define FSM_CONFACK         2
#define FSM_CONFNAK         3
#define FSM_CONFREJ         4
#define FSM_TERMREQ         5
#define FSM_TERMACK         6
#define FSM_CODEREJ         7
#define FSM_PROTOREJ        8
#define FSM_ECHOREQ         9
#define FSM_ECHOREP         10
#define FSM_DISCARDREQ      11
#define FSM_RESETREQ        14
#define FSM_RESETACK        15
#define FSM_FIRST           FSM_CONFREQ
#define FSM_LAST            FSM_RESETACK

/* 
 * LCP Options 
 */
#define CI_VENDOR           0       /* Vendor Specific */
#define CI_MRU              1       /* Maximum Receive Unit */
#define CI_ASYNCMAP         2       /* Async Control Character Map */
#define CI_AUTH             3       /* Authentication Type */
#define CI_QUALITY          4       /* Quality Protocol */
#define CI_MAGIC            5       /* Magic Number */
#define CI_PCOMP            7       /* Protocol Field Compression */
#define CI_ACCOMP           8       /* Address/Control Field Compression */
#define CI_FCSALTERN        9       /* FCS-Alternatives */
#define CI_SDP              10      /* Self-Describing-Pad */
#define CI_NUMBERED         11      /* Numbered-Mode */
#define CI_CALLBACK         13      /* callback */
#define CI_MRRU             17      /* max reconstructed receive unit; multilink */
#define CI_SSNHF            18      /* short sequence numbers for multilink */
#define CI_EPDISC           19      /* endpoint discriminator */
#define CI_MPPLUS           22      /* Multi-Link-Plus-Procedure */
#define CI_LDISC            23      /* Link-Discriminator */
#define CI_LCPAUTH          24      /* LCP Authentication */
#define CI_COBS             25      /* Consistent Overhead Byte Stuffing */
#define CI_PREFELIS         26      /* Prefix Elision */
#define CI_MPHDRFMT         27      /* MP Header Format */
#define CI_I18N             28      /* Internationalization */
#define CI_SDL              29      /* Simple Data Link */

/*
 * IPCP Options
 */
#define CI_ADDRS            1
#define CI_COMPRESSTYPE     2
#define CI_ADDR             3
#define CI_MS_DNS1          129
#define CI_MS_WINS1         130
#define CI_MS_DNS2          131
#define CI_MS_WINS2         132

#define IPCP_VJ_COMP        0x002d
#define IPCP_VJ_COMP_OLD    0x0037

/*
 * @brief CCP options 4-15 is unassigned, 255 is reserved.
 */
#define CI_PREDICT1         1
#define CI_PREDICT2         2
#define CI_PUDDLE           3
#define CI_HPPPC            16
#define CI_SELZS            17
#define CI_MPPC             18
#define CI_GFZA             19
#define CI_V42C             20
#define CI_BSD              21

/*
 * CHAP messages
 */
#define CHAP_CHALLENGE      1
#define CHAP_RESPONSE       2
#define CHAP_SUCCESS        3
#define CHAP_FAILURE        4

/*
 * EAP messages
 */
#define EAP_REQUEST         1
#define EAP_RESPONSE        2
#define EAP_SUCCESS         3
#define EAP_FAILURE         4

/*
 * EAP type names, 7 and 8 is unassigned, 20 is deprecated
 */
#define    EAPT_IDENTITY        1
#define    EAPT_NOTIFICATION    2
#define    EAPT_NAK             3     /* (response only) */
#define    EAPT_MD5CHAP         4
#define    EAPT_OTP             5     /* One-Time Password; RFC 1938 */
#define    EAPT_TOKEN           6     /* Generic Token Card */
#define    EAPT_RSA             9     /* RSA Public Key Authentication */
#define    EAPT_DSS             10    /* DSS Unilateral */
#define    EAPT_KEA             11    /* KEA */
#define    EAPT_KEA_VALIDATE    12    /* KEA-VALIDATE    */
#define    EAPT_TLS             13    /* EAP-TLS */
#define    EAPT_DEFENDER        14    /* Defender Token (AXENT) */
#define    EAPT_W2K             15    /* Windows 2000 EAP */
#define    EAPT_ARCOT           16    /* Arcot Systems */
#define    EAPT_CISCOWIRELESS   17    /* Cisco Wireless */
#define    EAPT_NOKIACARD       18    /* Nokia IP smart card */
#define    EAPT_SRP             19    /* Secure Remote Password */
#define    EAPT_DEPRECATED      20    /* Deprecated */
#define    EAPT_TTLS            21    /* EAP Tunneled TLS, RFC5281 */
#define    EAPT_RAS             22    /* Remote Access Service */
#define    EAPT_AKA             23    /* EAP method for 3rd generation authentication and key protocol RFC4187 */
#define    EAPT_3COM            24    /* EAP-3Com Wireless */
#define    EAPT_PEAP            25    /* Protected EAP */
#define    EAPT_MSCHAPV2        26    /* EAP-MSCHAPv2 */

/* 
 * EAP SRP-SHA1 Subtypes
 */
#define    EAPSRP_CHALLENGE     1    /* Request 1 - Challenge */
#define    EAPSRP_CKEY          1    /* Response 1 - Client Key */
#define    EAPSRP_SKEY          2    /* Request 2 - Server Key */
#define    EAPSRP_CVALIDATOR    2    /* Response 2 - Client Validator */
#define    EAPSRP_SVALIDATOR    3    /* Request 3 - Server Validator */
#define    EAPSRP_ACK           3    /* Response 3 - Final ack */
#define    EAPSRP_LWRECHALLENGE 4    /* Req/resp 4 - Lightweight rechal */

/*
 * EAP TLS flags
 */
#define EAP_TLS_FLAG_LI         128
#define EAP_TLS_FLAG_MF         64
#define EAP_TLS_FLAG_START      32

/*
 * MPPE bits
 */
#define MPPE_C_BIT              0x01    /* MPPC */
#define MPPE_D_BIT              0x10    /* Obsolete, usage unknown */
#define MPPE_L_BIT              0x20    /* 40-bit */
#define MPPE_S_BIT              0x40    /* 128-bit */
#define MPPE_M_BIT              0x80    /* 56-bit, not supported */

#define MPPE_H_BIT              0x01    /* Stateless (in a different byte) */

typedef struct 
{
    uint8_t code;
    uint8_t id;
    uint16_t len;

} ppp_hdr_st;

typedef struct 
{
    uint8_t type;
    uint8_t len;

} ppp_opt_st;

#endif /* #ifdef __SSTP_PPP_H__ */
