
/*
 * Copyright (C) yaoweibin (nginx_ajp_module)
 * Copyright (C) nginx1161 project (SSL extension)
 *
 * AJP13 protocol encoding / decoding for the nginx upstream pipeline.
 *
 * These callbacks are pure AJP protocol translators -- they do NOT touch
 * OpenSSL.  When `ajp_ssl on;` is configured, the module handler sets
 * u->ssl = 1 and hands a fully-initialized ngx_ssl_t through u->conf->ssl.
 * The upstream core then performs the TLS handshake and, from that point
 * on, every buffer produced by ngx_http_ajp_create_request() and every
 * buffer consumed by ngx_http_ajp_input_filter() travels through the
 * already-established TLS tunnel transparently (ngx_ssl_write / ngx_ssl_read
 * are invoked by the upstream output/input chain, not by this file).
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "ngx_http_ajp_module.h"


/* ---------------------------------------------------------------------- */
/* Small helpers for encoding AJP strings                                  */
/* ---------------------------------------------------------------------- */

static ngx_inline size_t
ngx_ajp_string_size(size_t len)
{
    /* 2-byte length + data + 1-byte NULL */
    return 2 + len + 1;
}


static ngx_inline u_char *
ngx_ajp_write_string(u_char *p, u_char *data, size_t len)
{
    ngx_ajp_write_uint16(p, (uint16_t) len);
    p += 2;

    if (len) {
        p = ngx_cpymem(p, data, len);
    }

    *p++ = '\0';

    return p;
}


static ngx_inline u_char *
ngx_ajp_write_cstring(u_char *p, const char *s)
{
    return ngx_ajp_write_string(p, (u_char *) s, ngx_strlen(s));
}


/* ---------------------------------------------------------------------- */
/* HTTP method -> AJP method code                                          */
/* ---------------------------------------------------------------------- */

static ngx_uint_t
ngx_ajp_method_code(ngx_str_t *m)
{
    if (m->len == 3 && ngx_strncmp(m->data, "GET", 3) == 0) {
        return NGX_AJP_METHOD_GET;
    }
    if (m->len == 4) {
        if (ngx_strncmp(m->data, "POST", 4) == 0) {
            return NGX_AJP_METHOD_POST;
        }
        if (ngx_strncmp(m->data, "HEAD", 4) == 0) {
            return NGX_AJP_METHOD_HEAD;
        }
        if (ngx_strncmp(m->data, "LOCK", 4) == 0) {
            return NGX_AJP_METHOD_LOCK;
        }
        if (ngx_strncmp(m->data, "MOVE", 4) == 0) {
            return NGX_AJP_METHOD_MOVE;
        }
        if (ngx_strncmp(m->data, "COPY", 4) == 0) {
            return NGX_AJP_METHOD_COPY;
        }
    }
    if (m->len == 5 && ngx_strncmp(m->data, "TRACE", 5) == 0) {
        return NGX_AJP_METHOD_TRACE;
    }
    if (m->len == 6) {
        if (ngx_strncmp(m->data, "DELETE", 6) == 0) {
            return NGX_AJP_METHOD_DELETE;
        }
        if (ngx_strncmp(m->data, "OPTIONS", 6) == 0) {
            return NGX_AJP_METHOD_OPTIONS;
        }
        if (ngx_strncmp(m->data, "UNLOCK", 6) == 0) {
            return NGX_AJP_METHOD_UNLOCK;
        }
        if (ngx_strncmp(m->data, "REPORT", 6) == 0) {
            return NGX_AJP_METHOD_REPORT;
        }
        if (ngx_strncmp(m->data, "MKCOL", 5) == 0) {
            return NGX_AJP_METHOD_MKCOL;
        }
        if (ngx_strncmp(m->data, "LABEL", 5) == 0) {
            return NGX_AJP_METHOD_LABEL;
        }
        if (ngx_strncmp(m->data, "MERGE", 5) == 0) {
            return NGX_AJP_METHOD_MERGE;
        }
    }
    if (m->len == 7 && ngx_strncmp(m->data, "OPTIONS", 7) == 0) {
        return NGX_AJP_METHOD_OPTIONS;
    }
    if (m->len == 8) {
        if (ngx_strncmp(m->data, "PROPFIND", 8) == 0) {
            return NGX_AJP_METHOD_PROPFIND;
        }
        if (ngx_strncmp(m->data, "CHECKOUT", 8) == 0) {
            return NGX_AJP_METHOD_CHECKOUT;
        }
        if (ngx_strncmp(m->data, "CHECKIN", 7) == 0) {
            return NGX_AJP_METHOD_CHECKIN;
        }
    }
    if (m->len == 9 && ngx_strncmp(m->data, "PROPPATCH", 9) == 0) {
        return NGX_AJP_METHOD_PROPPATCH;
    }
    if (m->len == 3) {
        if (ngx_strncmp(m->data, "PUT", 3) == 0) {
            return NGX_AJP_METHOD_PUT;
        }
    }

    return NGX_AJP_METHOD_GET;
}


/* ---------------------------------------------------------------------- */
/* Well-known header name -> AJP code (0 = send as plain string)           */
/* ---------------------------------------------------------------------- */

static ngx_uint_t
ngx_ajp_header_code(ngx_str_t *name)
{
    if (name->len == 6 && ngx_strncasecmp(name->data, (u_char *) "accept", 6)) {
        return NGX_AJP_HDR_ACCEPT;
    }
    if (name->len == 10
        && ngx_strncasecmp(name->data, (u_char *) "connection", 10) == 0)
    {
        return NGX_AJP_HDR_CONNECTION;
    }
    if (name->len == 12
        && ngx_strncasecmp(name->data, (u_char *) "content-type", 12) == 0)
    {
        return NGX_AJP_HDR_CONTENT_TYPE;
    }
    if (name->len == 14
        && ngx_strncasecmp(name->data, (u_char *) "content-length", 14) == 0)
    {
        return NGX_AJP_HDR_CONTENT_LENGTH;
    }
    if (name->len == 4
        && ngx_strncasecmp(name->data, (u_char *) "host", 4) == 0)
    {
        return NGX_AJP_HDR_HOST;
    }
    if (name->len == 10
        && ngx_strncasecmp(name->data, (u_char *) "user-agent", 10) == 0)
    {
        return NGX_AJP_HDR_USER_AGENT;
    }
    if (name->len == 6
        && ngx_strncasecmp(name->data, (u_char *) "cookie", 6) == 0)
    {
        return NGX_AJP_HDR_COOKIE;
    }
    if (name->len == 13
        && ngx_strncasecmp(name->data, (u_char *) "authorization", 13) == 0)
    {
        return NGX_AJP_HDR_AUTHORIZATION;
    }
    if (name->len == 7
        && ngx_strncasecmp(name->data, (u_char *) "referer", 7) == 0)
    {
        return NGX_AJP_HDR_REFERER;
    }
    if (name->len == 6
        && ngx_strncasecmp(name->data, (u_char *) "pragma", 6) == 0)
    {
        return NGX_AJP_HDR_PRAGMA;
    }
    if (name->len == 14
        && ngx_strncasecmp(name->data, (u_char *) "accept-charset", 14) == 0)
    {
        return NGX_AJP_HDR_ACCEPT_CHARSET;
    }
    if (name->len == 15
        && ngx_strncasecmp(name->data, (u_char *) "accept-encoding", 15) == 0)
    {
        return NGX_AJP_HDR_ACCEPT_ENCODING;
    }
    if (name->len == 15
        && ngx_strncasecmp(name->data, (u_char *) "accept-language", 15) == 0)
    {
        return NGX_AJP_HDR_ACCEPT_LANGUAGE;
    }

    return 0;
}


/* ---------------------------------------------------------------------- */
/* create_request: build FORWARD_REQUEST + optional BODY message           */
/* ---------------------------------------------------------------------- */

ngx_int_t
ngx_http_ajp_create_request(ngx_http_request_t *r)
{
    u_char                    *p, *buf, *payload_start;
    size_t                     buf_len, payload_len;
    ngx_buf_t                 *b;
    ngx_chain_t               *cl;
    ngx_uint_t                 i, n_headers, method_code;
    ngx_list_part_t           *part;
    ngx_table_elt_t           *header;
    ngx_http_ajp_loc_conf_t   *alcf;
    ngx_http_ajp_req_ctx_t    *ctx;
    ngx_connection_t          *c;

    alcf = ngx_http_get_module_loc_conf(r, ngx_http_ajp_module);
    ctx  = ngx_http_get_module_ctx(r, ngx_http_ajp_module);

    c = r->connection;

    /*
     * Conservative buffer size: 4-byte AJP header + worst-case payload.
     * We only include well-known headers + attributes so the bound is easy.
     */
    buf_len = NGX_AJP_HEADER_LEN + 32;      /* type + method + strings */
    buf_len += ngx_ajp_string_size(sizeof("HTTP/1.1") - 1);
    buf_len += ngx_ajp_string_size(r->uri.len + (r->args.len ? r->args.len + 1 : 0));
    buf_len += ngx_ajp_string_size(r->connection->addr_text.len);
    buf_len += ngx_ajp_string_size(r->headers_in.host ? r->headers_in.host->value.len : 9);
    buf_len += ngx_ajp_string_size(r->headers_in.server.len ? r->headers_in.server.len : 9);
    buf_len += 2 + 1;                       /* server_port + is_ssl */
    buf_len += 2;                           /* num_headers */

    /* headers */
    n_headers = 0;
    part = &r->headers_in.headers.part;
    header = part->elts;

    for (i = 0; /* void */; i++) {
        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }
            part = part->next;
            header = part->elts;
            i = 0;
        }

        if (header[i].hash == 0) {
            continue;
        }
        n_headers++;
        /* worst case: send name as string */
        buf_len += 2 + ngx_ajp_string_size(header[i].key.len)
                     + ngx_ajp_string_size(header[i].value.len);
    }

    /* attributes: query string + are_done */
    if (r->args.len) {
        buf_len += 1 + ngx_ajp_string_size(r->args.len);
    }
    buf_len += 1;                           /* 0xFF terminator */

    /* optional request body appended as BODY message */
    if (r->request_body && r->request_body->buf
        && alcf->pass_request_body)
    {
        buf_len += NGX_AJP_HEADER_LEN + 3 + NGX_AJP_MAX_BODY_LEN;
    }

    buf = ngx_palloc(r->pool, buf_len);
    if (buf == NULL) {
        return NGX_ERROR;
    }

    p = buf;

    /* --- AJP packet header (fill length later) --- */
    ngx_ajp_write_uint16(p, NGX_AJP_CLIENT_MAGIC); p += 2;
    payload_start = p;
    ngx_ajp_write_uint16(p, 0); p += 2;

    /* --- FORWARD_REQUEST payload --- */
    *p++ = NGX_AJP_MSG_FORWARD_REQUEST;

    method_code = ngx_ajp_method_code(&r->method_name);
    *p++ = (u_char) method_code;

    /* protocol */
    if (r->http_protocol.len) {
        p = ngx_ajp_write_string(p, r->http_protocol.data, r->http_protocol.len);
    } else {
        p = ngx_ajp_write_cstring(p, "HTTP/1.1");
    }

    /* request URI (with query string appended by AJP as attribute) */
    p = ngx_ajp_write_string(p, r->unparsed_uri.data,
                             r->unparsed_uri.len - (r->args.len ? r->args.len + 1 : 0));

    /* remote address */
    p = ngx_ajp_write_string(p, c->addr_text.data, c->addr_text.len);

    /* remote host */
    p = ngx_ajp_write_string(p, c->addr_text.data, c->addr_text.len);

    /* server name */
    if (r->headers_in.server.len) {
        p = ngx_ajp_write_string(p, r->headers_in.server.data,
                                 r->headers_in.server.len);
    } else {
        p = ngx_ajp_write_cstring(p, "localhost");
    }

    /* server port */
    {
        in_port_t  port;
        port = ngx_inet_get_port(c->local_sockaddr);
        ngx_ajp_write_uint16(p, (uint16_t) port);
        p += 2;
    }

#if (NGX_HTTP_SSL)
    /* is_ssl: reflect whether the *client* connection is TLS */
    *p++ = (c->ssl ? 1 : 0);
#else
    *p++ = 0;
#endif

    /* num_headers */
    ngx_ajp_write_uint16(p, (uint16_t) n_headers);
    p += 2;

    /* headers */
    part = &r->headers_in.headers.part;
    header = part->elts;

    for (i = 0; /* void */; i++) {
        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }
            part = part->next;
            header = part->elts;
            i = 0;
        }

        if (header[i].hash == 0) {
            continue;
        }

        {
            ngx_uint_t code = ngx_ajp_header_code(&header[i].key);

            if (code) {
                ngx_ajp_write_uint16(p, (uint16_t) code);
                p += 2;
            } else {
                p = ngx_ajp_write_string(p, header[i].key.data,
                                         header[i].key.len);
            }
        }

        p = ngx_ajp_write_string(p, header[i].value.data, header[i].value.len);
    }

    /* attributes */
    if (r->args.len) {
        *p++ = NGX_AJP_ATTR_QUERY_STRING;
        p = ngx_ajp_write_string(p, r->args.data, r->args.len);
    }

    *p++ = NGX_AJP_ATTR_ARE_DONE;

    /* request terminator */
    *p++ = NGX_AJP_REQUEST_TERMINATOR;

    /* fill in payload length now that we know it */
    payload_len = (size_t) (p - payload_start) - 2;
    ngx_ajp_write_uint16(payload_start, (uint16_t) payload_len);

    b = ngx_calloc_buf(r->pool);
    if (b == NULL) {
        return NGX_ERROR;
    }

    b->pos = buf;
    b->last = p;
    b->memory = 1;
    b->tag = (ngx_buf_tag_t) &ngx_http_ajp_module;

    cl = ngx_alloc_chain_link(r->pool);
    if (cl == NULL) {
        return NGX_ERROR;
    }
    cl->buf = b;

    /* append request body as AJP BODY message if present */
    if (r->request_body && r->request_body->buf && alcf->pass_request_body) {
        ngx_buf_t   *body_in = r->request_body->buf;
        size_t       remain = body_in->last - body_in->pos;
        ngx_chain_t *last = cl;

        while (remain) {
            size_t       chunk = remain > NGX_AJP_MAX_BODY_LEN
                                 ? NGX_AJP_MAX_BODY_LEN : remain;
            u_char      *mbuf, *m;
            ngx_buf_t   *mb;
            ngx_chain_t *mcl;

            mbuf = ngx_palloc(r->pool,
                              NGX_AJP_HEADER_LEN + 3 + chunk);
            if (mbuf == NULL) {
                return NGX_ERROR;
            }

            m = mbuf;
            ngx_ajp_write_uint16(m, NGX_AJP_CLIENT_MAGIC); m += 2;
            ngx_ajp_write_uint16(m, (uint16_t) (chunk + 3)); m += 2;
            *m++ = NGX_AJP_MSG_BODY;
            ngx_ajp_write_uint16(m, (uint16_t) chunk); m += 2;
            m = ngx_cpymem(m, body_in->pos, chunk);
            *m++ = '\0';

            body_in->pos += chunk;
            remain -= chunk;

            mb = ngx_calloc_buf(r->pool);
            if (mb == NULL) {
                return NGX_ERROR;
            }
            mb->pos = mbuf;
            mb->last = m;
            mb->memory = 1;
            mb->tag = (ngx_buf_tag_t) &ngx_http_ajp_module;

            mcl = ngx_alloc_chain_link(r->pool);
            if (mcl == NULL) {
                return NGX_ERROR;
            }
            mcl->buf = mb;
            mcl->next = NULL;

            last->next = mcl;
            last = mcl;
        }

        last->next = NULL;

        /* empty BODY message signals end of request body */
        {
            u_char      *ebuf, *e;
            ngx_buf_t   *eb;
            ngx_chain_t *ecl;

            ebuf = ngx_palloc(r->pool, NGX_AJP_HEADER_LEN + 3);
            if (ebuf == NULL) {
                return NGX_ERROR;
            }

            e = ebuf;
            ngx_ajp_write_uint16(e, NGX_AJP_CLIENT_MAGIC); e += 2;
            ngx_ajp_write_uint16(e, 3); e += 2;
            *e++ = NGX_AJP_MSG_BODY;
            ngx_ajp_write_uint16(e, 0); e += 2;
            *e++ = '\0';

            eb = ngx_calloc_buf(r->pool);
            if (eb == NULL) {
                return NGX_ERROR;
            }
            eb->pos = ebuf;
            eb->last = e;
            eb->memory = 1;
            eb->last_buf = 1;
            eb->tag = (ngx_buf_tag_t) &ngx_http_ajp_module;

            ecl = ngx_alloc_chain_link(r->pool);
            if (ecl == NULL) {
                return NGX_ERROR;
            }
            ecl->buf = eb;
            ecl->next = NULL;

            last->next = ecl;
        }
    } else {
        cl->next = NULL;
        b->last_buf = 1;
    }

    r->upstream->request_bufs = cl;

    ctx->request_body_remains = 0;
    ctx->headers_processed = 0;
    ctx->end_response_seen = 0;

    return NGX_OK;
}


/* ---------------------------------------------------------------------- */
/* process_header: parse SEND_HEADERS from server                          */
/* ---------------------------------------------------------------------- */

static ngx_int_t
ngx_ajp_parse_string(u_char **p, u_char *end, ngx_str_t *out)
{
    uint16_t  len;

    if (*p + 2 > end) {
        return NGX_ERROR;
    }
    len = ngx_ajp_read_uint16(*p);
    *p += 2;

    if (*p + len + 1 > end) {
        return NGX_ERROR;
    }

    out->len = len;
    out->data = *p;
    *p += len + 1;   /* skip data + trailing NULL */

    return NGX_OK;
}


ngx_int_t
ngx_http_ajp_process_header(ngx_http_request_t *r)
{
    u_char                    *p, *end, *msg_end;
    uint16_t                   magic, msg_len, status, num_headers, i;
    ngx_str_t                  status_text, hdr_name, hdr_value;
    ngx_uint_t                 code;
    ngx_table_elt_t           *h;
    ngx_http_ajp_req_ctx_t    *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_ajp_module);

    p = r->upstream->buffer.pos;
    end = r->upstream->buffer.last;

    /* need at least 4-byte header + 1-byte type */
    if ((size_t) (end - p) < NGX_AJP_HEADER_LEN + 1) {
        return NGX_AGAIN;
    }

    magic = ngx_ajp_read_uint16(p); p += 2;
    msg_len = ngx_ajp_read_uint16(p); p += 2;

    if (magic != NGX_AJP_SERVER_MAGIC) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "ajp: invalid server magic 0x%04Xd", magic);
        return NGX_HTTP_UPSTREAM_INVALID_HEADER;
    }

    if ((size_t) (end - p) < msg_len) {
        return NGX_AGAIN;
    }

    msg_end = p + msg_len;

    if (*p != NGX_AJP_MSG_SEND_HEADERS) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "ajp: expected SEND_HEADERS(4), got %ud", (ngx_uint_t) *p);
        return NGX_HTTP_UPSTREAM_INVALID_HEADER;
    }
    p++;

    /* status code (2 bytes) + status message (String) */
    if (p + 2 > msg_end) {
        return NGX_HTTP_UPSTREAM_INVALID_HEADER;
    }
    status = ngx_ajp_read_uint16(p); p += 2;

    if (ngx_ajp_parse_string(&p, msg_end, &status_text) != NGX_OK) {
        return NGX_HTTP_UPSTREAM_INVALID_HEADER;
    }

    if (p + 2 > msg_end) {
        return NGX_HTTP_UPSTREAM_INVALID_HEADER;
    }
    num_headers = ngx_ajp_read_uint16(p); p += 2;

    /* fill in ngx_http_upstream headers_in */
    r->upstream->headers_in.status_n = status;
    r->upstream->headers_in.status_line.len =
        (size_t) (ngx_min(msg_end - p, 128));
    r->upstream->headers_in.status_line.data = p;

    for (i = 0; i < num_headers; i++) {
        /* header code (0xA0xx) OR plain string */
        if (p + 2 > msg_end) {
            return NGX_HTTP_UPSTREAM_INVALID_HEADER;
        }

        code = ngx_ajp_read_uint16(p);

        if ((code & 0xFF00) == 0xA000) {
            p += 2;
            switch (code) {
            case NGX_AJP_HDR_CONTENT_TYPE:
                ngx_str_set(&hdr_name, "Content-Type");
                break;
            case NGX_AJP_HDR_CONTENT_LENGTH:
                ngx_str_set(&hdr_name, "Content-Length");
                break;
            case NGX_AJP_HDR_CONNECTION:
                ngx_str_set(&hdr_name, "Connection");
                break;
            case NGX_AJP_HDR_COOKIE:
                ngx_str_set(&hdr_name, "Set-Cookie");
                break;
            case NGX_AJP_HDR_COOKIE2:
                ngx_str_set(&hdr_name, "Set-Cookie2");
                break;
            default:
                ngx_str_set(&hdr_name, "X-AJP-Header");
                break;
            }
        } else {
            if (ngx_ajp_parse_string(&p, msg_end, &hdr_name) != NGX_OK) {
                return NGX_HTTP_UPSTREAM_INVALID_HEADER;
            }
        }

        if (ngx_ajp_parse_string(&p, msg_end, &hdr_value) != NGX_OK) {
            return NGX_HTTP_UPSTREAM_INVALID_HEADER;
        }

        h = ngx_list_push(&r->upstream->headers_in.headers);
        if (h == NULL) {
            return NGX_ERROR;
        }

        h->hash = 1;
        h->key = hdr_name;
        h->value = hdr_value;
        h->lowcase_key = h->key.data;
        ngx_strlow(h->lowcase_key, h->key.data, h->key.len);

        /* Content-Length bookkeeping */
        if (h->key.len == sizeof("Content-Length") - 1
            && ngx_strncasecmp(h->key.data, (u_char *) "Content-Length",
                               sizeof("Content-Length") - 1) == 0)
        {
            r->upstream->headers_in.content_length_n =
                ngx_atoof(h->value.data, h->value.len);
            r->upstream->headers_in.content_length = h;
        }

        if (h->key.len == sizeof("Content-Type") - 1
            && ngx_strncasecmp(h->key.data, (u_char *) "Content-Type",
                               sizeof("Content-Type") - 1) == 0)
        {
            r->upstream->headers_in.content_type = h;
        }
    }

    r->upstream->buffer.pos = msg_end;
    ctx->headers_processed = 1;

    return NGX_OK;
}


/* ---------------------------------------------------------------------- */
/* input_filter: consume SEND_BODY_CHUNK / END_RESPONSE / GET_BODY_CHUNK   */
/* ---------------------------------------------------------------------- */

ngx_int_t
ngx_http_ajp_input_filter_init(void *data)
{
    ngx_http_request_t  *r = data;

    if (r->upstream->headers_in.status_n == NGX_HTTP_NO_CONTENT
        || r->upstream->headers_in.status_n == NGX_HTTP_NOT_MODIFIED
        || r->upstream->headers_in.status_n < NGX_HTTP_SPECIAL_RESPONSE)
    {
        r->upstream->length = 0;
        return NGX_OK;
    }

    if (r->upstream->headers_in.content_length_n >= 0) {
        r->upstream->length = r->upstream->headers_in.content_length_n;
        return NGX_OK;
    }

    r->upstream->length = -1;

    return NGX_OK;
}


ngx_int_t
ngx_http_ajp_input_filter(void *data, ssize_t bytes)
{
    ngx_http_request_t        *r = data;
    u_char                    *p, *end, *msg_end;
    uint16_t                   magic, msg_len, chunk_len;
    ngx_buf_t                 *b;
    ngx_chain_t               *cl;
    ngx_http_ajp_req_ctx_t    *ctx;

    if (bytes <= 0) {
        return NGX_OK;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_ajp_module);

    p = r->upstream->buffer.pos;
    end = r->upstream->buffer.last;

    while (p < end && !ctx->end_response_seen) {
        if ((size_t) (end - p) < NGX_AJP_HEADER_LEN + 1) {
            break;
        }

        magic = ngx_ajp_read_uint16(p); p += 2;
        msg_len = ngx_ajp_read_uint16(p); p += 2;

        if (magic != NGX_AJP_SERVER_MAGIC) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "ajp: invalid server magic 0x%04Xd in body", magic);
            return NGX_ERROR;
        }

        if ((size_t) (end - p) < msg_len) {
            /* partial message: rewind and wait for more data */
            p -= NGX_AJP_HEADER_LEN;
            break;
        }

        msg_end = p + msg_len;

        switch (*p) {

        case NGX_AJP_MSG_SEND_BODY_CHUNK:
            p++;
            if (p + 2 > msg_end) {
                return NGX_ERROR;
            }
            chunk_len = ngx_ajp_read_uint16(p); p += 2;

            if (p + chunk_len > msg_end) {
                return NGX_ERROR;
            }

            if (chunk_len == 0) {
                /* zero-length chunk signals end of body */
                ctx->end_response_seen = 1;
                break;
            }

            b = ngx_calloc_buf(r->pool);
            if (b == NULL) {
                return NGX_ERROR;
            }

            b->pos = p;
            b->last = p + chunk_len;
            b->memory = 1;
            b->tag = (ngx_buf_tag_t) &ngx_http_ajp_module;

            cl = ngx_alloc_chain_link(r->pool);
            if (cl == NULL) {
                return NGX_ERROR;
            }
            cl->buf = b;
            cl->next = NULL;

            /* append at tail of u->out_bufs (single-pointer chain) */
            {
                ngx_chain_t **ll = &r->upstream->out_bufs;
                while (*ll) {
                    ll = &(*ll)->next;
                }
                *ll = cl;
            }

            if (r->upstream->length > 0) {
                r->upstream->length -= chunk_len;
                if (r->upstream->length <= 0) {
                    ctx->end_response_seen = 1;
                }
            }

            p += chunk_len + 1;   /* data + trailing NULL */
            break;

        case NGX_AJP_MSG_END_RESPONSE:
            p++;
            /* 1-byte reuse flag */
            if (p + 1 > msg_end) {
                return NGX_ERROR;
            }
            p++;
            ctx->end_response_seen = 1;
            break;

        case NGX_AJP_MSG_GET_BODY_CHUNK:
            /*
             * Server asks for more request body.  For a minimal impl we
             * simply skip; the request body was already sent eagerly in
             * create_request().
             */
            p = msg_end;
            break;

        default:
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "ajp: unexpected message type %ud",
                          (ngx_uint_t) *p);
            return NGX_ERROR;
        }

        p = msg_end;
    }

    r->upstream->buffer.pos = p;

    if (ctx->end_response_seen) {
        return NGX_OK;
    }

    return NGX_AGAIN;
}


/* ---------------------------------------------------------------------- */
/* reinit / abort / finalize                                               */
/* ---------------------------------------------------------------------- */

ngx_int_t
ngx_http_ajp_reinit_request(ngx_http_request_t *r)
{
    ngx_http_ajp_req_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_ajp_module);
    if (ctx == NULL) {
        return NGX_OK;
    }

    ctx->headers_processed = 0;
    ctx->end_response_seen = 0;
    ctx->request_terminated = 0;
    ctx->response_body_remains = 0;

    return NGX_OK;
}


void
ngx_http_ajp_abort_request(ngx_http_request_t *r)
{
    /* nothing to clean up */
}


void
ngx_http_ajp_finalize_request(ngx_http_request_t *r, ngx_int_t rc)
{
    /* nothing to clean up */
}
