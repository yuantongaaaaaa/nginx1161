
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_HTTP_UPSTREAM_CHECK_MODULE_H_INCLUDED_
#define _NGX_HTTP_UPSTREAM_CHECK_MODULE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


extern ngx_module_t  ngx_http_upstream_check_module;


/*
 * Register the round robin peer chains of an upstream in the active
 * health check registry.  Called from ngx_http_upstream_init_round_robin()
 * while the configuration is parsed; returns the base index of the
 * registered check peers or NGX_OK without registration when the
 * upstream has no "check" directive.
 */
ngx_int_t ngx_http_upstream_check_add_peers(ngx_conf_t *cf,
    ngx_http_upstream_srv_conf_t *us, ngx_http_upstream_rr_peers_t *peers);

/*
 * Returns 1 when the peer with index "n" of the peer chain identified
 * by "check_index" is marked down by the active health checks.
 * Used by the round robin balancer to skip unavailable peers.
 */
ngx_int_t ngx_http_upstream_check_peer_down(ngx_int_t check_index,
    ngx_uint_t n);


#endif /* _NGX_HTTP_UPSTREAM_CHECK_MODULE_H_INCLUDED_ */
