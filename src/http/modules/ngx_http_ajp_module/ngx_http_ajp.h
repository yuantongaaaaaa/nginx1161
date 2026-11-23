
/*
 * Copyright (C) yaoweibin (nginx_ajp_module)
 * Copyright (C) nginx1161 project (SSL extension)
 *
 * AJP13 protocol constants, packet layouts and shared types used by
 * ngx_http_ajp_module and ngx_http_ajp_handler.
 *
 * The SSL support added here follows the same pattern as
 * ngx_http_proxy_module: the AJP handler only sets u->ssl = 1 and points
 * u->conf->ssl to a properly initialized ngx_ssl_t.  All actual TLS
 * handshake / encrypt / decrypt work is done inside the existing
 * ngx_http_upstream SSL layer, so the AJP layer sees plaintext bytes only.
 */


#ifndef _NGX_HTTP_AJP_H_INCLUDED_
#define _NGX_HTTP_AJP_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


/* ---------------------------------------------------------------------- */
/* AJP13 packet framing                                                    */
/* ---------------------------------------------------------------------- */

/* prefix sent from client (nginx) to server (tomcat) */
#define NGX_AJP_CLIENT_MAGIC             0x1234
/* prefix sent from server (tomcat) to client (nginx) */
#define NGX_AJP_SERVER_MAGIC             0x4142   /* "AB" */

/* header (magic + length) is 4 bytes */
#define NGX_AJP_HEADER_LEN               4

/* AJP13 maximum payload size (Tomcat default packetSize is 8192) */
#define NGX_AJP_MAX_DATA_LEN             8188
#define NGX_AJP_MAX_BODY_LEN             (NGX_AJP_MAX_DATA_LEN - 6)

/* request terminator byte at the end of FORWARD_REQUEST */
#define NGX_AJP_REQUEST_TERMINATOR       0xFF


/* ---------------------------------------------------------------------- */
/* AJP13 message types                                                     */
/* ---------------------------------------------------------------------- */

/* client -> server */
#define NGX_AJP_MSG_FORWARD_REQUEST      0x02
#define NGX_AJP_MSG_SHUTDOWN             0x07
#define NGX_AJP_MSG_PING                 0x08
#define NGX_AJP_MSG_CPONG                0x09
#define NGX_AJP_MSG_CPING                0x0A
#define NGX_AJP_MSG_BODY                 0x0C

/* server -> client */
#define NGX_AJP_MSG_SEND_BODY_CHUNK      0x03
#define NGX_AJP_MSG_SEND_HEADERS         0x04
#define NGX_AJP_MSG_END_RESPONSE         0x05
#define NGX_AJP_MSG_GET_BODY_CHUNK       0x06
#define NGX_AJP_MSG_CPONG_REPLY          0x09
#define NGX_AJP_MSG_CPING_REPLY          0x0A


/* ---------------------------------------------------------------------- */
/* HTTP method codes used in FORWARD_REQUEST                               */
/* ---------------------------------------------------------------------- */

#define NGX_AJP_METHOD_OPTIONS           1
#define NGX_AJP_METHOD_GET               2
#define NGX_AJP_METHOD_HEAD              3
#define NGX_AJP_METHOD_POST              4
#define NGX_AJP_METHOD_PUT               5
#define NGX_AJP_METHOD_DELETE            6
#define NGX_AJP_METHOD_TRACE             7
#define NGX_AJP_METHOD_PROPFIND          8
#define NGX_AJP_METHOD_PROPPATCH         9
#define NGX_AJP_METHOD_MKCOL             10
#define NGX_AJP_METHOD_COPY              11
#define NGX_AJP_METHOD_MOVE              12
#define NGX_AJP_METHOD_LOCK              13
#define NGX_AJP_METHOD_UNLOCK            14
#define NGX_AJP_METHOD_REPORT            15
#define NGX_AJP_METHOD_VERSION_CONTROL   16
#define NGX_AJP_METHOD_CHECKOUT          17
#define NGX_AJP_METHOD_CHECKIN           18
#define NGX_AJP_METHOD_UNCHECKOUT        19
#define NGX_AJP_METHOD_MKWORKSPACE       20
#define NGX_AJP_METHOD_UPDATE            21
#define NGX_AJP_METHOD_LABEL             22
#define NGX_AJP_METHOD_MERGE             23
#define NGX_AJP_METHOD_BASELINE_CONTROL  24
#define NGX_AJP_METHOD_MKACTIVITY        25


/* ---------------------------------------------------------------------- */
/* Well-known request header codes (avoids sending header names in plain   */
/* text; 0xA000 | code)                                                    */
/* ---------------------------------------------------------------------- */

#define NGX_AJP_HDR_ACCEPT               0xA001
#define NGX_AJP_HDR_ACCEPT_CHARSET       0xA002
#define NGX_AJP_HDR_ACCEPT_ENCODING      0xA003
#define NGX_AJP_HDR_ACCEPT_LANGUAGE      0xA004
#define NGX_AJP_HDR_AUTHORIZATION        0xA005
#define NGX_AJP_HDR_CONNECTION           0xA006
#define NGX_AJP_HDR_CONTENT_TYPE         0xA007
#define NGX_AJP_HDR_CONTENT_LENGTH       0xA008
#define NGX_AJP_HDR_COOKIE               0xA009
#define NGX_AJP_HDR_COOKIE2              0xA00A
#define NGX_AJP_HDR_HOST                 0xA00B
#define NGX_AJP_HDR_PRAGMA               0xA00C
#define NGX_AJP_HDR_REFERER              0xA00D
#define NGX_AJP_HDR_USER_AGENT           0xA00E


/* ---------------------------------------------------------------------- */
/* Well-known attribute codes                                              */
/* ---------------------------------------------------------------------- */

#define NGX_AJP_ATTR_CONTEXT             0x01
#define NGX_AJP_ATTR_SERVLET_PATH        0x02
#define NGX_AJP_ATTR_REMOTE_USER         0x03
#define NGX_AJP_ATTR_AUTH_TYPE           0x04
#define NGX_AJP_ATTR_QUERY_STRING        0x05
#define NGX_AJP_ATTR_ROUTE               0x06
#define NGX_AJP_ATTR_SSL_CERT            0x07
#define NGX_AJP_ATTR_SSL_CIPHER          0x08
#define NGX_AJP_ATTR_SSL_SESSION         0x09
#define NGX_AJP_ATTR_SSL_KEY_SIZE        0x0A
#define NGX_AJP_ATTR_SECRET              0x0C
#define NGX_AJP_ATTR_ARE_DONE            0xFF


/* ---------------------------------------------------------------------- */
/* Shared per-request context                                              */
/* ---------------------------------------------------------------------- */

typedef struct {
    /* how many body bytes we still owe to upstream (from client) */
    off_t                          request_body_remains;
    /* how many body bytes upstream still owes to us */
    off_t                          response_body_remains;

    /* buffered AJP message body currently being parsed */
    u_char                        *buf;
    size_t                         buf_len;
    size_t                         buf_pos;

    /* state machine for GET_BODY_CHUNK / SEND_BODY_CHUNK handling */
    unsigned                       in_chunk:1;
    unsigned                       last_chunk_seen:1;
    unsigned                       headers_sent:1;
    unsigned                       end_response_seen:1;

    /* saved pointer for header parsing */
    ngx_http_request_t            *r;
    ngx_chain_t                   *free;
    ngx_chain_t                   *busy;
} ngx_http_ajp_ctx_t;


/* ---------------------------------------------------------------------- */
/* Utility: encode/decode big-endian integers into AJP buffers             */
/* ---------------------------------------------------------------------- */

static ngx_inline void
ngx_ajp_write_uint16(u_char *p, uint16_t v)
{
    p[0] = (u_char) ((v >> 8) & 0xff);
    p[1] = (u_char) (v & 0xff);
}


static ngx_inline uint16_t
ngx_ajp_read_uint16(u_char *p)
{
    return (uint16_t) (((uint16_t) p[0] << 8) | (uint16_t) p[1]);
}


static ngx_inline void
ngx_ajp_write_uint32(u_char *p, uint32_t v)
{
    p[0] = (u_char) ((v >> 24) & 0xff);
    p[1] = (u_char) ((v >> 16) & 0xff);
    p[2] = (u_char) ((v >> 8) & 0xff);
    p[3] = (u_char) (v & 0xff);
}


#endif /* _NGX_HTTP_AJP_H_INCLUDED_ */
