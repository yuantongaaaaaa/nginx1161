
/*
 * Copyright (C) yaoweibin (nginx_ajp_module)
 * Copyright (C) nginx1161 project (SSL extension)
 *
 * ngx_http_ajp_module: forwards HTTP requests to a Tomcat AJP13 connector
 * and, when `ajp_ssl on;` is configured, wraps the AJP binary stream into
 * a TLS tunnel by handing over to the existing ngx_http_upstream SSL layer.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "ngx_http_ajp_module.h"


static ngx_int_t ngx_http_ajp_handler(ngx_http_request_t *r);
static void *ngx_http_ajp_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_ajp_merge_loc_conf(ngx_conf_t *cf, void *parent,
    void *child);
static ngx_int_t ngx_http_ajp_init(ngx_conf_t *cf);

static char *ngx_http_ajp_pass(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
#if (NGX_HTTP_SSL)
static char *ngx_http_ajp_ssl_password_file(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
#endif

static ngx_conf_bitmask_t  ngx_http_ajp_ssl_protocols[] = {
    { ngx_string("SSLv2"), NGX_SSL_SSLv2 },
    { ngx_string("SSLv3"), NGX_SSL_SSLv3 },
    { ngx_string("TLSv1"), NGX_SSL_TLSv1 },
    { ngx_string("TLSv1.1"), NGX_SSL_TLSv1_1 },
    { ngx_string("TLSv1.2"), NGX_SSL_TLSv1_2 },
    { ngx_string("TLSv1.3"), NGX_SSL_TLSv1_3 },
    { ngx_null_string, 0 }
};


/* ---------------------------------------------------------------------- */
/* Directives                                                              */
/* ---------------------------------------------------------------------- */

static ngx_command_t  ngx_http_ajp_commands[] = {

    { ngx_string("ajp_pass"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1,
      ngx_http_ajp_pass,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    /* --- SSL extension required by the design doc --- */

    { ngx_string("ajp_ssl"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_ajp_loc_conf_t, ssl),
      NULL },

#if (NGX_HTTP_SSL)

    { ngx_string("ajp_ssl_protocols"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_conf_set_bitmask_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_ajp_loc_conf_t, ssl_protocols),
      &ngx_http_ajp_ssl_protocols },

    { ngx_string("ajp_ssl_ciphers"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_ajp_loc_conf_t, ssl_ciphers),
      NULL },

    { ngx_string("ajp_ssl_certificate"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_set_complex_value_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_ajp_loc_conf_t, upstream.ssl_certificate),
      NULL },

    { ngx_string("ajp_ssl_certificate_key"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_set_complex_value_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_ajp_loc_conf_t, upstream.ssl_certificate_key),
      NULL },

    { ngx_string("ajp_ssl_password_file"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_ajp_ssl_password_file,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("ajp_ssl_verify"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_ajp_loc_conf_t, upstream.ssl_verify),
      NULL },

    { ngx_string("ajp_ssl_verify_depth"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_ajp_loc_conf_t, ssl_verify_depth),
      NULL },

    { ngx_string("ajp_ssl_trusted_certificate"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_ajp_loc_conf_t, ssl_trusted_certificate),
      NULL },

    { ngx_string("ajp_ssl_crl"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_ajp_loc_conf_t, ssl_crl),
      NULL },

    { ngx_string("ajp_ssl_session_reuse"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_ajp_loc_conf_t, upstream.ssl_session_reuse),
      NULL },

    { ngx_string("ajp_ssl_name"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_set_complex_value_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_ajp_loc_conf_t, upstream.ssl_name),
      NULL },

    { ngx_string("ajp_ssl_server_name"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_ajp_loc_conf_t, upstream.ssl_server_name),
      NULL },

    { ngx_string("ajp_ssl_conf_command"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
      ngx_conf_set_keyval_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_ajp_loc_conf_t, ssl_conf_commands),
      NULL },

#endif

      ngx_null_command
};


static ngx_http_module_t  ngx_http_ajp_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_ajp_init,                     /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_ajp_create_loc_conf,          /* create location configuration */
    ngx_http_ajp_merge_loc_conf            /* merge location configuration */
};


ngx_module_t  ngx_http_ajp_module = {
    NGX_MODULE_V1,
    &ngx_http_ajp_module_ctx,              /* module context */
    ngx_http_ajp_commands,                 /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


/* ---------------------------------------------------------------------- */
/* Config create / merge                                                   */
/* ---------------------------------------------------------------------- */

static void *
ngx_http_ajp_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_ajp_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_ajp_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     conf->upstream.ssl = NULL;
     *     conf->upstream.ssl_certificate = NULL;
     *     conf->upstream.ssl_certificate_key = NULL;
     *     conf->upstream.ssl_name = NULL;
     *     conf->ssl_ciphers = { 0, NULL };
     *     conf->ssl_trusted_certificate = { 0, NULL };
     *     conf->ssl_crl = { 0, NULL };
     *     conf->ssl_conf_commands = NULL;
     *     conf->lengths = NULL;
     *     conf->values = NULL;
     */

    conf->upstream.connect_timeout = NGX_CONF_UNSET_MSEC;
    conf->upstream.send_timeout = NGX_CONF_UNSET_MSEC;
    conf->upstream.read_timeout = NGX_CONF_UNSET_MSEC;

    conf->upstream.buffer_size = NGX_CONF_UNSET_SIZE;

    conf->upstream.pass_request_headers = NGX_CONF_UNSET;
    conf->upstream.pass_request_body = NGX_CONF_UNSET;

    conf->upstream.local = NGX_CONF_UNSET_PTR;
    conf->upstream.socket_keepalive = NGX_CONF_UNSET;

    conf->upstream.ignore_client_abort = NGX_CONF_UNSET;
    conf->upstream.intercept_errors = NGX_CONF_UNSET;

#if (NGX_HTTP_SSL)
    conf->upstream.ssl_session_reuse = NGX_CONF_UNSET;
    conf->upstream.ssl_verify = NGX_CONF_UNSET;
    conf->upstream.ssl_server_name = NGX_CONF_UNSET;
    conf->ssl_verify_depth = NGX_CONF_UNSET_UINT;
    /*
     * ssl_protocols uses ngx_conf_set_bitmask_slot, which requires the
     * target field to be initialized to 0 (NOT NGX_CONF_UNSET_UINT).
     * ngx_pcalloc already zeroed it, so we simply leave it as-is.
     */
    conf->upstream.ssl_passwords = NGX_CONF_UNSET_PTR;
#endif

    /* ajp_ssl on|off */
    conf->ssl = NGX_CONF_UNSET;
    conf->pass_request_body = NGX_CONF_UNSET;

    return conf;
}


static char *
ngx_http_ajp_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_ajp_loc_conf_t *prev = parent;
    ngx_http_ajp_loc_conf_t *conf = child;

    ngx_conf_merge_msec_value(conf->upstream.connect_timeout,
                              prev->upstream.connect_timeout, 60000);
    ngx_conf_merge_msec_value(conf->upstream.send_timeout,
                              prev->upstream.send_timeout, 60000);
    ngx_conf_merge_msec_value(conf->upstream.read_timeout,
                              prev->upstream.read_timeout, 60000);

    ngx_conf_merge_size_value(conf->upstream.buffer_size,
                              prev->upstream.buffer_size,
                              (size_t) ngx_pagesize);

    ngx_conf_merge_value(conf->upstream.pass_request_headers,
                         prev->upstream.pass_request_headers, 1);
    ngx_conf_merge_value(conf->upstream.pass_request_body,
                         prev->upstream.pass_request_body, 1);
    ngx_conf_merge_ptr_value(conf->upstream.local,
                             prev->upstream.local, NULL);
    ngx_conf_merge_value(conf->upstream.socket_keepalive,
                         prev->upstream.socket_keepalive, 0);
    ngx_conf_merge_value(conf->upstream.ignore_client_abort,
                         prev->upstream.ignore_client_abort, 0);
    ngx_conf_merge_value(conf->upstream.intercept_errors,
                         prev->upstream.intercept_errors, 0);

    ngx_conf_merge_value(conf->ssl, prev->ssl, 0);
    ngx_conf_merge_value(conf->pass_request_body,
                         prev->pass_request_body, 1);

#if (NGX_HTTP_SSL)
    ngx_conf_merge_value(conf->upstream.ssl_session_reuse,
                         prev->upstream.ssl_session_reuse, 1);
    ngx_conf_merge_bitmask_value(conf->ssl_protocols, prev->ssl_protocols,
                         (NGX_SSL_TLSv1|NGX_SSL_TLSv1_1|NGX_SSL_TLSv1_2
                          |NGX_SSL_TLSv1_3));
    /*
     * Note: ngx_conf_merge_bitmask_value is only used here for the merge
     * fallback; the initial value must be 0 (see create_loc_conf) because
     * ngx_conf_set_bitmask_slot ORs the user-specified bits into it.
     */
    ngx_conf_merge_str_value(conf->ssl_ciphers, prev->ssl_ciphers,
                             "DEFAULT");
    ngx_conf_merge_value(conf->upstream.ssl_verify,
                         prev->upstream.ssl_verify, 0);
    ngx_conf_merge_uint_value(conf->ssl_verify_depth,
                              prev->ssl_verify_depth, 1);
    ngx_conf_merge_str_value(conf->ssl_trusted_certificate,
                             prev->ssl_trusted_certificate, "");
    ngx_conf_merge_str_value(conf->ssl_crl, prev->ssl_crl, "");
    ngx_conf_merge_value(conf->upstream.ssl_server_name,
                         prev->upstream.ssl_server_name, 0);
    ngx_conf_merge_ptr_value(conf->upstream.ssl_passwords,
                             prev->upstream.ssl_passwords, NULL);
    ngx_conf_merge_ptr_value(conf->ssl_conf_commands,
                             prev->ssl_conf_commands, NULL);

    if (conf->upstream.ssl_name == NULL) {
        conf->upstream.ssl_name = prev->upstream.ssl_name;
    }
    if (conf->upstream.ssl_certificate == NULL) {
        conf->upstream.ssl_certificate = prev->upstream.ssl_certificate;
    }
    if (conf->upstream.ssl_certificate_key == NULL) {
        conf->upstream.ssl_certificate_key = prev->upstream.ssl_certificate_key;
    }

    /*
     * Design-doc modification point (1):
     * allocate the ngx_ssl_t that upstream_conf_t expects, so that after
     * the handler sets u->ssl = 1, ngx_http_upstream_ssl_init_connection()
     * can call ngx_ssl_create_connection(u->conf->ssl, c, ...) to build the
     * TLS tunnel.  Nothing else in the AJP layer needs to know about SSL.
     */
    if (conf->ssl && conf->upstream.ssl == NULL) {
        conf->upstream.ssl = ngx_pcalloc(cf->pool, sizeof(ngx_ssl_t));
        if (conf->upstream.ssl == NULL) {
            return NGX_CONF_ERROR;
        }

        conf->upstream.ssl->log = cf->log;

        if (ngx_http_ajp_set_ssl(cf, conf) != NGX_OK) {
            return NGX_CONF_ERROR;
        }
    }
#endif

    if (conf->upstream.upstream == NULL) {
        conf->upstream.upstream = prev->upstream.upstream;
    }

    if (conf->lengths == NULL) {
        conf->lengths = prev->lengths;
        conf->values = prev->values;
    }

    return NGX_CONF_OK;
}


/* ---------------------------------------------------------------------- */
/* Handler: create upstream, tell it to run SSL, wire up AJP callbacks     */
/* ---------------------------------------------------------------------- */

static ngx_int_t
ngx_http_ajp_handler(ngx_http_request_t *r)
{
    ngx_int_t                  rc;
    ngx_http_upstream_t       *u;
    ngx_http_ajp_loc_conf_t   *alcf;
    ngx_http_ajp_req_ctx_t    *ctx;

    alcf = ngx_http_get_module_loc_conf(r, ngx_http_ajp_module);

    if (alcf->upstream.upstream == NULL && alcf->lengths == NULL) {
        return NGX_HTTP_BAD_GATEWAY;
    }

    if (ngx_http_upstream_create(r) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_ajp_req_ctx_t));
    if (ctx == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_http_set_ctx(r, ctx, ngx_http_ajp_module);

    u = r->upstream;

    u->conf = &alcf->upstream;

    /*
     * Design-doc modification point (3):
     * the *only* thing the AJP handler must do to enable TLS is set
     * u->ssl = 1.  ngx_http_upstream_connect() checks this flag after the
     * TCP connect succeeds and, if c->ssl is still NULL, diverts into
     * ngx_http_upstream_ssl_init_connection() which performs the full TLS
     * handshake.  Once handshaked, the upstream code calls
     * ngx_http_upstream_send_request() as usual; the AJP FORWARD_REQUEST
     * bytes produced by ngx_http_ajp_create_request() are handed to
     * ngx_ssl_write() automatically by the upstream output chain, so the
     * AJP layer never touches OpenSSL directly.
     */
#if (NGX_HTTP_SSL)
    u->ssl = (alcf->ssl ? 1 : 0);

    if (u->ssl && alcf->upstream.ssl_name) {
        /* optional SNI/verification name (ajp_ssl_name) */
        if (ngx_http_complex_value(r, alcf->upstream.ssl_name, &u->ssl_name)
            != NGX_OK)
        {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }
#endif

    u->schema.len = sizeof("ajp://") - 1;
    u->schema.data = (u_char *) "ajp://";

    u->output.tag = (ngx_buf_tag_t) &ngx_http_ajp_module;

    u->create_request   = ngx_http_ajp_create_request;
    u->reinit_request   = ngx_http_ajp_reinit_request;
    u->process_header   = ngx_http_ajp_process_header;
    u->abort_request    = ngx_http_ajp_abort_request;
    u->finalize_request = ngx_http_ajp_finalize_request;

    u->input_filter_init = ngx_http_ajp_input_filter_init;
    u->input_filter      = ngx_http_ajp_input_filter;
    u->input_filter_ctx  = r;

    u->buffering = 0;

    if (!alcf->pass_request_body) {
        u->request_bufs = NULL;
    }

    rc = ngx_http_read_client_request_body(r, ngx_http_upstream_init);

    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        return rc;
    }

    return NGX_DONE;
}


/* ---------------------------------------------------------------------- */
/* ajp_pass directive                                                      */
/* ---------------------------------------------------------------------- */

static char *
ngx_http_ajp_pass(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_ajp_loc_conf_t *alcf = conf;

    size_t                      add;
    u_short                     port;
    ngx_str_t                  *value, url;
    ngx_url_t                   u;
    ngx_uint_t                  n;
    ngx_http_core_loc_conf_t   *clcf;
    ngx_http_script_compile_t   sc;

    if (alcf->upstream.upstream || alcf->lengths) {
        return "is duplicate";
    }

    value = cf->args->elts;

    url = value[1];

    if (ngx_strncasecmp(url.data, (u_char *) "ajp://", 6) == 0) {
        add = 6;
        port = 8009;

    } else {
        cf->log->action = "parsing ajp_pass";
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid URL prefix in \"%V\"", &url);
        return NGX_CONF_ERROR;
    }

    ngx_memzero(&u, sizeof(ngx_url_t));

    u.url.len = url.len - add;
    u.url.data = url.data + add;
    u.default_port = port;
    u.uri_part = 1;
    u.no_resolve = 1;

    alcf->upstream.upstream = ngx_http_upstream_add(cf, &u, 0);
    if (alcf->upstream.upstream == NULL) {
        return NGX_CONF_ERROR;
    }

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_ajp_handler;

    if (alcf->upstream.upstream->servers) {
        return NGX_CONF_OK;
    }

    /* runtime-evaluated ajp_pass via variables */

    alcf->lengths = ngx_array_create(cf->pool, 8,
                                     sizeof(ngx_http_script_code_pt));
    if (alcf->lengths == NULL) {
        return NGX_CONF_ERROR;
    }

    alcf->values = ngx_array_create(cf->pool, 8,
                                    sizeof(ngx_http_script_code_pt));
    if (alcf->values == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(&sc, sizeof(ngx_http_script_compile_t));

    sc.cf = cf;
    sc.source = &url;
    sc.lengths = &alcf->lengths;
    sc.values = &alcf->values;
    sc.variables = ngx_http_script_variables_count(&url);
    sc.complete_lengths = 1;
    sc.complete_values = 1;

    if (ngx_http_script_compile(&sc) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    n = 0;

    /* keep upstream NULL: resolved at request time */
    if (alcf->upstream.upstream) {
        n = alcf->upstream.upstream->servers
            ? alcf->upstream.upstream->servers->nelts : 0;
    }

    if (n == 0) {
        alcf->upstream.upstream = NULL;
    }

    return NGX_CONF_OK;
}


/* ---------------------------------------------------------------------- */
#if (NGX_HTTP_SSL)

static char *
ngx_http_ajp_ssl_password_file(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_ajp_loc_conf_t *alcf = conf;

    ngx_str_t  *value;

    if (alcf->upstream.ssl_passwords != NGX_CONF_UNSET_PTR) {
        return "is duplicate";
    }

    value = cf->args->elts;

    alcf->upstream.ssl_passwords = ngx_ssl_read_password_file(cf, &value[1]);

    if (alcf->upstream.ssl_passwords == NULL) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


/*
 * Design-doc modification point (1) implementation:
 * build a full ngx_ssl_t for the AJP upstream.  Mirrors
 * ngx_http_proxy_set_ssl() almost verbatim so that all nginx-side SSL
 * features (client cert, verify, CRL, session reuse, cipher list,
 * OpenSSL conf commands, ...) work identically.
 */
ngx_int_t
ngx_http_ajp_set_ssl(ngx_conf_t *cf, ngx_http_ajp_loc_conf_t *alcf)
{
    ngx_pool_cleanup_t  *cln;

    if (alcf->upstream.ssl->ctx) {
        return NGX_OK;
    }

    if (ngx_ssl_create(alcf->upstream.ssl, alcf->ssl_protocols, NULL)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    cln = ngx_pool_cleanup_add(cf->pool, 0);
    if (cln == NULL) {
        ngx_ssl_cleanup_ctx(alcf->upstream.ssl);
        return NGX_ERROR;
    }

    cln->handler = ngx_ssl_cleanup_ctx;
    cln->data = alcf->upstream.ssl;

    if (ngx_ssl_ciphers(cf, alcf->upstream.ssl, &alcf->ssl_ciphers, 0)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (alcf->upstream.ssl_certificate
        && alcf->upstream.ssl_certificate->value.len)
    {
        if (alcf->upstream.ssl_certificate_key == NULL) {
            ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                          "no \"ajp_ssl_certificate_key\" is defined "
                          "for certificate \"%V\"",
                          &alcf->upstream.ssl_certificate->value);
            return NGX_ERROR;
        }

        if (alcf->upstream.ssl_certificate->lengths == NULL
            && alcf->upstream.ssl_certificate_key->lengths == NULL)
        {
            if (ngx_ssl_certificate(cf, alcf->upstream.ssl,
                                    &alcf->upstream.ssl_certificate->value,
                                    &alcf->upstream.ssl_certificate_key->value,
                                    alcf->upstream.ssl_passwords)
                != NGX_OK)
            {
                return NGX_ERROR;
            }
        }
    }

    if (alcf->upstream.ssl_verify) {
        if (alcf->ssl_trusted_certificate.len == 0) {
            ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                          "no ajp_ssl_trusted_certificate for ajp_ssl_verify");
            return NGX_ERROR;
        }

        if (ngx_ssl_trusted_certificate(cf, alcf->upstream.ssl,
                                        &alcf->ssl_trusted_certificate,
                                        alcf->ssl_verify_depth)
            != NGX_OK)
        {
            return NGX_ERROR;
        }

        if (ngx_ssl_crl(cf, alcf->upstream.ssl, &alcf->ssl_crl) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    if (ngx_ssl_client_session_cache(cf, alcf->upstream.ssl,
                                     alcf->upstream.ssl_session_reuse)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_ssl_conf_commands(cf, alcf->upstream.ssl, alcf->ssl_conf_commands)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}

#endif /* NGX_HTTP_SSL */


/* ---------------------------------------------------------------------- */
/* Module postconfiguration: register content handler is done via          */
/* clcf->handler in ajp_pass.  Nothing extra needed here.                  */
/* ---------------------------------------------------------------------- */

static ngx_int_t
ngx_http_ajp_init(ngx_conf_t *cf)
{
    return NGX_OK;
}
