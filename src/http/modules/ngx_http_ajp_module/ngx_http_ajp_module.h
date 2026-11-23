
/*
 * Copyright (C) yaoweibin (nginx_ajp_module)
 * Copyright (C) nginx1161 project (SSL extension)
 */


#ifndef _NGX_HTTP_AJP_MODULE_H_INCLUDED_
#define _NGX_HTTP_AJP_MODULE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "ngx_http_ajp.h"


extern ngx_module_t  ngx_http_ajp_module;


/*
 * Per-location configuration.
 *
 * The `upstream` field embeds the standard ngx_http_upstream_conf_t which
 * carries `ngx_ssl_t *ssl`.  When `ajp_ssl on;` is configured, we allocate
 * that ngx_ssl_t here and initialize it (cipher list, client cert, verify
 * depth, trusted CA, session cache, ...) via ngx_http_ajp_set_ssl(), the
 * same way ngx_http_proxy_module does.  The runtime handler then just sets
 *
 *     u->ssl      = 1;
 *     u->conf     = &alcf->upstream;
 *
 * and the existing ngx_http_upstream_ssl_init_connection() takes over:
 * creates the SSL connection, does the TLS handshake, and after that all
 * AJP binary frames produced by ngx_http_ajp_create_request() flow through
 * the already-established TLS tunnel transparently.
 */
typedef struct {
    ngx_http_upstream_conf_t       upstream;

    /* ajp_pass target */
    ngx_array_t                   *lengths;
    ngx_array_t                   *values;

    /* ajp_ssl on|off  --  global switch required by the design doc */
    ngx_flag_t                     ssl;

#if (NGX_HTTP_SSL)
    /* ajp_ssl_protocols / ajp_ssl_ciphers / ajp_ssl_verify ... */
    ngx_uint_t                     ssl_protocols;
    ngx_str_t                      ssl_ciphers;
    ngx_uint_t                     ssl_verify_depth;
    ngx_str_t                      ssl_trusted_certificate;
    ngx_str_t                      ssl_crl;
    ngx_array_t                   *ssl_conf_commands;
#endif

    /* pass client request body to upstream (default on) */
    ngx_flag_t                     pass_request_body;
} ngx_http_ajp_loc_conf_t;


/*
 * Per-request context used by the handler callbacks.  Declared here so
 * both ngx_http_ajp_module.c and ngx_http_ajp_handler.c can share it.
 */
typedef struct {
    /* request-body bytes still to be forwarded to upstream */
    off_t                          request_body_remains;

    /* AJP message currently being assembled / parsed */
    u_char                        *msg;
    size_t                         msg_len;
    size_t                         msg_pos;

    /* how many body bytes upstream still owes to the client */
    off_t                          response_body_remains;

    unsigned                       headers_processed:1;
    unsigned                       end_response_seen:1;
    unsigned                       request_terminated:1;
} ngx_http_ajp_req_ctx_t;


/* AJP handler entry points (implemented in ngx_http_ajp_handler.c) */
ngx_int_t ngx_http_ajp_create_request(ngx_http_request_t *r);
ngx_int_t ngx_http_ajp_process_header(ngx_http_request_t *r);
ngx_int_t ngx_http_ajp_input_filter_init(void *data);
ngx_int_t ngx_http_ajp_input_filter(void *data, ssize_t bytes);
void      ngx_http_ajp_abort_request(ngx_http_request_t *r);
void      ngx_http_ajp_finalize_request(ngx_http_request_t *r, ngx_int_t rc);
ngx_int_t ngx_http_ajp_reinit_request(ngx_http_request_t *r);

/* SSL context initialization (implemented in ngx_http_ajp_module.c) */
#if (NGX_HTTP_SSL)
ngx_int_t ngx_http_ajp_set_ssl(ngx_conf_t *cf, ngx_http_ajp_loc_conf_t *alcf);
#endif


#endif /* _NGX_HTTP_AJP_MODULE_H_INCLUDED_ */
