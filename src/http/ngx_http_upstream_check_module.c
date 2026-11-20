
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


/*
 * Built-in active upstream health checks (Tengine style "check" module).
 *
 * A background timer per upstream peer periodically probes the backend
 * (tcp connect or http request).  The probe results are accumulated in
 * shared memory (rise/fall counters) and a peer that fails "fall" probes
 * in a row is marked down; the round robin balancer skips such peers,
 * so no business request is sent to a dead backend.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_event_connect.h>
#include <ngx_http_upstream_round_robin.h>
#include <ngx_http_upstream_check_module.h>


#define NGX_HTTP_UPSTREAM_CHECK_CONNECT_DONE  1
#define NGX_HTTP_UPSTREAM_CHECK_SEND_DONE     2
#define NGX_HTTP_UPSTREAM_CHECK_RECV_DONE     3


#define NGX_HTTP_UPSTREAM_CHECK_HTTP_2XX      (1 << 2)
#define NGX_HTTP_UPSTREAM_CHECK_HTTP_3XX      (1 << 3)
#define NGX_HTTP_UPSTREAM_CHECK_HTTP_4XX      (1 << 4)
#define NGX_HTTP_UPSTREAM_CHECK_HTTP_5XX      (1 << 5)


#define NGX_HTTP_UPSTREAM_CHECK_MAX_RECV      (4 * (size_t) ngx_pagesize)


typedef struct {
    u_char                            *start;
    u_char                            *pos;
    u_char                            *last;
    u_char                            *end;
} ngx_http_upstream_check_buf_t;


typedef struct ngx_http_upstream_check_peer_s  ngx_http_upstream_check_peer_t;
typedef struct ngx_http_upstream_check_type_s  ngx_http_upstream_check_type_t;


typedef struct {
    ngx_http_upstream_check_buf_t      send;
    ngx_http_upstream_check_buf_t      recv;
    unsigned                           eof:1;
} ngx_http_upstream_check_ctx_t;


/* per peer state shared between all worker processes */
typedef struct {
    ngx_shmtx_t                        mutex;
    ngx_shmtx_sh_t                     mutex_sh;
    ngx_pid_t                          owner;       /* worker doing checks */
    ngx_uint_t                         ref;
    ngx_msec_t                         access_time; /* last check finish */
    ngx_uint_t                         rise_count;
    ngx_uint_t                         fall_count;
    unsigned                           down:1;
} ngx_http_upstream_check_peer_shm_t;


typedef struct {
    ngx_uint_t                         generation;
    ngx_uint_t                         number;
    ngx_http_upstream_check_peer_shm_t peer[1];
} ngx_http_upstream_check_peers_shm_t;


typedef struct {
    ngx_flag_t                         enabled;
    ngx_msec_t                         check_interval;
    ngx_msec_t                         check_timeout;
    ngx_uint_t                         rise_count;
    ngx_uint_t                         fall_count;
    ngx_uint_t                         check_type;
    ngx_http_upstream_check_type_t    *check_type_conf;
    ngx_str_t                          send;
    ngx_uint_t                         status_alive;
} ngx_http_upstream_check_srv_conf_t;


typedef struct {
    ngx_array_t                       *check_peers;  /* check entries, config */
    ngx_shm_zone_t                    *shm_zone;
    ngx_http_upstream_check_peers_shm_t  *peers_shm;
} ngx_http_upstream_check_main_conf_t;


/* configuration time registry entry, one per checked address */
typedef struct {
    ngx_http_upstream_check_srv_conf_t  *conf;
    struct sockaddr                     *sockaddr;
    socklen_t                            socklen;
    ngx_str_t                            name;
} ngx_http_upstream_check_entry_t;


struct ngx_http_upstream_check_peer_s {
    ngx_http_upstream_check_srv_conf_t  *conf;
    struct sockaddr                     *sockaddr;
    socklen_t                            socklen;
    ngx_str_t                            name;

    ngx_event_t                          check_ev;
    ngx_event_t                          check_timeout_ev;

    ngx_peer_connection_t                pc;
    ngx_pool_t                          *pool;
    ngx_http_upstream_check_ctx_t       *check_data;

    ngx_http_upstream_check_peer_shm_t  *shm;

    void                               (*send_handler)(ngx_event_t *ev);
    void                               (*recv_handler)(ngx_event_t *ev);
    ngx_int_t                          (*init)(ngx_http_upstream_check_peer_t *peer);
    ngx_int_t                          (*parse)(ngx_http_upstream_check_peer_t *peer);

    ngx_uint_t                           state;
    ngx_uint_t                           index;
};


typedef struct {
    ngx_array_t                          peers;  /* of check peer */
    ngx_http_upstream_check_peers_shm_t *peers_shm;
} ngx_http_upstream_check_peers_t;


struct ngx_http_upstream_check_type_s {
    ngx_str_t                            name;
    unsigned                             no_recv:1;
    void                               (*send_handler)(ngx_event_t *ev);
    void                               (*recv_handler)(ngx_event_t *ev);
    ngx_int_t                          (*init)(ngx_http_upstream_check_peer_t *peer);
    ngx_int_t                          (*parse)(ngx_http_upstream_check_peer_t *peer);
};


static char *ngx_http_upstream_check(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_upstream_check_set_send(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);

static void *ngx_http_upstream_check_create_main_conf(ngx_conf_t *cf);
static char *ngx_http_upstream_check_init_main_conf(ngx_conf_t *cf, void *conf);
static void *ngx_http_upstream_check_create_srv_conf(ngx_conf_t *cf);

static ngx_int_t ngx_http_upstream_check_init_shm(ngx_shm_zone_t *shm_zone,
    void *data);

static ngx_int_t ngx_http_upstream_check_init_process(ngx_cycle_t *cycle);
static ngx_int_t ngx_http_upstream_check_add_timers(ngx_cycle_t *cycle);
static ngx_int_t ngx_http_upstream_check_add_timer(
    ngx_http_upstream_check_peer_t *peer,
    ngx_http_upstream_check_type_t *check_conf, ngx_msec_t timer,
    ngx_log_t *log);

static void ngx_http_upstream_check_begin_handler(ngx_event_t *event);
static void ngx_http_upstream_check_connect_handler(ngx_event_t *event);
static void ngx_http_upstream_check_send_handler(ngx_event_t *event);
static void ngx_http_upstream_check_recv_handler(ngx_event_t *event);
static void ngx_http_upstream_check_timeout_handler(ngx_event_t *event);

static void ngx_http_upstream_check_status_update(
    ngx_http_upstream_check_peer_t *peer, ngx_int_t success);
static void ngx_http_upstream_check_clean_event(
    ngx_http_upstream_check_peer_t *peer);
static ngx_int_t ngx_http_upstream_check_need_exit(void);

static ngx_int_t ngx_http_upstream_check_tcp_init(
    ngx_http_upstream_check_peer_t *peer);
static ngx_int_t ngx_http_upstream_check_http_init(
    ngx_http_upstream_check_peer_t *peer);
static ngx_int_t ngx_http_upstream_check_http_parse(
    ngx_http_upstream_check_peer_t *peer);


static ngx_conf_bitmask_t  ngx_http_upstream_check_http_alive_masks[] = {
    { ngx_string("http_2xx"), NGX_HTTP_UPSTREAM_CHECK_HTTP_2XX },
    { ngx_string("http_3xx"), NGX_HTTP_UPSTREAM_CHECK_HTTP_3XX },
    { ngx_string("http_4xx"), NGX_HTTP_UPSTREAM_CHECK_HTTP_4XX },
    { ngx_string("http_5xx"), NGX_HTTP_UPSTREAM_CHECK_HTTP_5XX },
    { ngx_null_string, 0 }
};


static ngx_http_upstream_check_type_t  ngx_http_upstream_check_types[] = {
    { ngx_string("tcp"),
      1,
      ngx_http_upstream_check_send_handler,
      ngx_http_upstream_check_recv_handler,
      ngx_http_upstream_check_tcp_init,
      NULL },

    { ngx_string("http"),
      0,
      ngx_http_upstream_check_send_handler,
      ngx_http_upstream_check_recv_handler,
      ngx_http_upstream_check_http_init,
      ngx_http_upstream_check_http_parse },

    { ngx_null_string, 0, NULL, NULL, NULL, NULL }
};


static u_char  ngx_http_upstream_check_http_default_send[] =
    "GET / HTTP/1.0" CRLF CRLF;


static ngx_command_t  ngx_http_upstream_check_commands[] = {

    { ngx_string("check"),
      NGX_HTTP_UPS_CONF|NGX_CONF_1MORE,
      ngx_http_upstream_check,
      NGX_HTTP_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("check_http_send"),
      NGX_HTTP_UPS_CONF|NGX_CONF_TAKE1,
      ngx_http_upstream_check_set_send,
      NGX_HTTP_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("check_http_expect_alive"),
      NGX_HTTP_UPS_CONF|NGX_CONF_1MORE,
      ngx_conf_set_bitmask_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_upstream_check_srv_conf_t, status_alive),
      &ngx_http_upstream_check_http_alive_masks },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_upstream_check_module_ctx = {
    NULL,                                    /* preconfiguration */
    NULL,                                    /* postconfiguration */

    ngx_http_upstream_check_create_main_conf, /* create main configuration */
    ngx_http_upstream_check_init_main_conf,   /* init main configuration */

    ngx_http_upstream_check_create_srv_conf,  /* create server configuration */
    NULL,                                    /* merge server configuration */

    NULL,                                    /* create location configuration */
    NULL                                     /* merge location configuration */
};


ngx_module_t  ngx_http_upstream_check_module = {
    NGX_MODULE_V1,
    &ngx_http_upstream_check_module_ctx,   /* module context */
    ngx_http_upstream_check_commands,      /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    ngx_http_upstream_check_init_process,  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_http_upstream_check_peers_t  *check_peers_ctx;

static ngx_uint_t  ngx_http_upstream_check_shm_generation;


static void *
ngx_http_upstream_check_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_upstream_check_main_conf_t  *mcmcf;

    mcmcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_upstream_check_main_conf_t));
    if (mcmcf == NULL) {
        return NULL;
    }

    return mcmcf;
}


static void *
ngx_http_upstream_check_create_srv_conf(ngx_conf_t *cf)
{
    ngx_http_upstream_check_srv_conf_t  *ucscf;

    ucscf = ngx_pcalloc(cf->pool, sizeof(ngx_http_upstream_check_srv_conf_t));
    if (ucscf == NULL) {
        return NULL;
    }

    ucscf->enabled = NGX_CONF_UNSET;
    ucscf->check_interval = NGX_CONF_UNSET_MSEC;
    ucscf->check_timeout = NGX_CONF_UNSET_MSEC;
    ucscf->rise_count = NGX_CONF_UNSET_UINT;
    ucscf->fall_count = NGX_CONF_UNSET_UINT;
    ucscf->check_type = NGX_CONF_UNSET_UINT;
    ucscf->status_alive = 0;  /* bitmask slot, finalized in add_peers */

    return ucscf;
}


static char *
ngx_http_upstream_check(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_upstream_check_srv_conf_t *ucscf = conf;

    ngx_str_t   *value, s;
    ngx_uint_t   i, type;
    ngx_int_t    n;

    if (ucscf->enabled == 1) {
        return "is duplicate";
    }

    ucscf->enabled = 1;

    value = cf->args->elts;

    for (i = 1; i < cf->args->nelts; i++) {

        if (ngx_strncmp(value[i].data, "interval=", 9) == 0) {
            s.len = value[i].len - 9;
            s.data = value[i].data + 9;
            n = ngx_atoi(s.data, s.len);
            if (n == NGX_ERROR || n == 0) {
                goto invalid;
            }
            ucscf->check_interval = (ngx_msec_t) n;
            continue;
        }

        if (ngx_strncmp(value[i].data, "timeout=", 8) == 0) {
            s.len = value[i].len - 8;
            s.data = value[i].data + 8;
            n = ngx_atoi(s.data, s.len);
            if (n == NGX_ERROR || n == 0) {
                goto invalid;
            }
            ucscf->check_timeout = (ngx_msec_t) n;
            continue;
        }

        if (ngx_strncmp(value[i].data, "rise=", 5) == 0) {
            s.len = value[i].len - 5;
            s.data = value[i].data + 5;
            n = ngx_atoi(s.data, s.len);
            if (n == NGX_ERROR || n == 0) {
                goto invalid;
            }
            ucscf->rise_count = (ngx_uint_t) n;
            continue;
        }

        if (ngx_strncmp(value[i].data, "fall=", 5) == 0) {
            s.len = value[i].len - 5;
            s.data = value[i].data + 5;
            n = ngx_atoi(s.data, s.len);
            if (n == NGX_ERROR || n == 0) {
                goto invalid;
            }
            ucscf->fall_count = (ngx_uint_t) n;
            continue;
        }

        if (ngx_strncmp(value[i].data, "type=", 5) == 0) {
            s.len = value[i].len - 5;
            s.data = value[i].data + 5;

            for (type = 0; ngx_http_upstream_check_types[type].name.len; type++)
            {
                if (ngx_http_upstream_check_types[type].name.len == s.len
                    && ngx_strncasecmp(ngx_http_upstream_check_types[type].name.data,
                                       s.data, s.len) == 0)
                {
                    ucscf->check_type = type;
                    break;
                }
            }

            if (ucscf->check_type == NGX_CONF_UNSET_UINT) {
                goto invalid;
            }

            continue;
        }

        goto invalid;
    }

    ngx_conf_init_msec_value(ucscf->check_interval, 30000);
    ngx_conf_init_msec_value(ucscf->check_timeout, 1000);
    ngx_conf_init_uint_value(ucscf->rise_count, 2);
    ngx_conf_init_uint_value(ucscf->fall_count, 5);
    ngx_conf_init_uint_value(ucscf->check_type, 0);

    ucscf->check_type_conf = &ngx_http_upstream_check_types[ucscf->check_type];

    return NGX_CONF_OK;

invalid:

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "invalid parameter \"%V\"", &value[i]);

    return NGX_CONF_ERROR;
}


static char *
ngx_http_upstream_check_set_send(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_upstream_check_srv_conf_t *ucscf = conf;

    u_char     *p;
    ngx_str_t  *value;
    size_t      i, j;

    if (ucscf->send.len) {
        return "is duplicate";
    }

    value = cf->args->elts;

    p = ngx_pnalloc(cf->pool, value[1].len);
    if (p == NULL) {
        return NGX_CONF_ERROR;
    }

    /* interpret the \r, \n and \t escapes of the request template */

    j = 0;

    for (i = 0; i < value[1].len; i++) {

        if (value[1].data[i] == '\\' && i + 1 < value[1].len) {

            if (value[1].data[i + 1] == 'r') {
                p[j++] = CR;
                i++;
                continue;
            }

            if (value[1].data[i + 1] == 'n') {
                p[j++] = LF;
                i++;
                continue;
            }

            if (value[1].data[i + 1] == 't') {
                p[j++] = '\t';
                i++;
                continue;
            }

            if (value[1].data[i + 1] == '\\') {
                p[j++] = '\\';
                i++;
                continue;
            }
        }

        p[j++] = value[1].data[i];
    }

    ucscf->send.data = p;
    ucscf->send.len = j;

    return NGX_CONF_OK;
}


ngx_int_t
ngx_http_upstream_check_add_peers(ngx_conf_t *cf,
    ngx_http_upstream_srv_conf_t *us, ngx_http_upstream_rr_peers_t *peers)
{
    ngx_http_upstream_check_main_conf_t  *mcmcf;
    ngx_http_upstream_check_srv_conf_t   *ucscf;
    ngx_http_upstream_check_entry_t      *entry;
    ngx_http_upstream_rr_peers_t         *p;
    ngx_uint_t                            i, base;

    ucscf = ngx_http_conf_upstream_srv_conf(us, ngx_http_upstream_check_module);

    if (ucscf == NULL || ucscf->enabled != 1) {
        return NGX_OK;
    }

    /* finalize the per upstream defaults now that all directives are seen */

    if (ucscf->check_type == 1 && ucscf->send.len == 0) {
        ucscf->send.data = ngx_http_upstream_check_http_default_send;
        ucscf->send.len = sizeof(ngx_http_upstream_check_http_default_send) - 1;
    }

    ngx_conf_init_uint_value(ucscf->status_alive,
                             NGX_HTTP_UPSTREAM_CHECK_HTTP_2XX
                             |NGX_HTTP_UPSTREAM_CHECK_HTTP_3XX);

#if (NGX_HTTP_UPSTREAM_ZONE)
    if (us->shm_zone) {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                           "active health checks are not supported"
                           " in upstream \"%V\" with \"zone\"", &us->host);
        return NGX_OK;
    }
#endif

    mcmcf = ngx_http_conf_get_module_main_conf(cf,
                                               ngx_http_upstream_check_module);

    if (mcmcf->check_peers == NULL) {
        mcmcf->check_peers = ngx_array_create(cf->pool, 4,
                                              sizeof(ngx_http_upstream_check_entry_t));
        if (mcmcf->check_peers == NULL) {
            return NGX_ERROR;
        }
    }

    base = mcmcf->check_peers->nelts;

    for (p = peers; p; p = p->next) {

        p->check_index = base;

        for (i = 0; i < p->number; i++) {

            entry = ngx_array_push(mcmcf->check_peers);
            if (entry == NULL) {
                return NGX_ERROR;
            }

            entry->conf = ucscf;
            entry->sockaddr = p->peer[i].sockaddr;
            entry->socklen = p->peer[i].socklen;
            entry->name = p->peer[i].name;

            base++;
        }
    }

    return NGX_OK;
}


static char *
ngx_http_upstream_check_init_main_conf(ngx_conf_t *cf, void *conf)
{
    ngx_http_upstream_check_main_conf_t *mcmcf = conf;

    size_t        size;
    ngx_uint_t    n;
    ngx_str_t     name;
    ngx_shm_zone_t  *zone;

    if (mcmcf->check_peers == NULL || mcmcf->check_peers->nelts == 0) {
        return NGX_CONF_OK;
    }

    n = mcmcf->check_peers->nelts;

    size = sizeof(ngx_http_upstream_check_peers_shm_t)
           + (n - 1) * sizeof(ngx_http_upstream_check_peer_shm_t);

    /* room for the slab allocator page map and the pool header */

    size += size / 128 + sizeof(ngx_slab_pool_t);
    size = ngx_align(size, ngx_pagesize) + 3 * ngx_pagesize;

    name.len = sizeof("upstream_check") - 1;
    name.data = (u_char *) "upstream_check";

    zone = ngx_shared_memory_add(cf, &name, size,
                                 &ngx_http_upstream_check_module);
    if (zone == NULL) {
        return NGX_CONF_ERROR;
    }

    zone->init = ngx_http_upstream_check_init_shm;
    zone->data = mcmcf;

    mcmcf->shm_zone = zone;

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_upstream_check_init_shm(ngx_shm_zone_t *shm_zone, void *data)
{
    ngx_http_upstream_check_main_conf_t  *mcmcf = shm_zone->data;
    ngx_http_upstream_check_main_conf_t  *omcmcf = data;

    size_t                               size;
    ngx_uint_t                           i, n;
    ngx_slab_pool_t                     *shpool;
    ngx_http_upstream_check_peers_shm_t *peers_shm;

    n = mcmcf->check_peers->nelts;

    /* reload with an unchanged peer set: keep the shared state */

    if (omcmcf != NULL && omcmcf->peers_shm != NULL
        && omcmcf->check_peers != NULL
        && omcmcf->check_peers->nelts == n)
    {
        mcmcf->peers_shm = omcmcf->peers_shm;
        return NGX_OK;
    }

    shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;

    size = sizeof(ngx_http_upstream_check_peers_shm_t)
           + (n - 1) * sizeof(ngx_http_upstream_check_peer_shm_t);

    peers_shm = ngx_slab_alloc(shpool, size);
    if (peers_shm == NULL) {
        return NGX_ERROR;
    }

    ngx_memzero(peers_shm, size);

    peers_shm->number = n;

    /*
     * a new generation invalidates the references held by the workers
     * of the old cycle while they are shutting down
     */

    ngx_http_upstream_check_shm_generation++;
    peers_shm->generation = ngx_http_upstream_check_shm_generation;

    for (i = 0; i < n; i++) {

        if (ngx_shmtx_create(&peers_shm->peer[i].mutex,
                             &peers_shm->peer[i].mutex_sh, NULL)
            != NGX_OK)
        {
            return NGX_ERROR;
        }

        peers_shm->peer[i].owner = NGX_INVALID_PID;
        peers_shm->peer[i].access_time = ngx_current_msec;
    }

    mcmcf->peers_shm = peers_shm;

    return NGX_OK;
}


static ngx_int_t
ngx_http_upstream_check_init_process(ngx_cycle_t *cycle)
{
    ngx_http_upstream_check_main_conf_t  *mcmcf;
    ngx_http_upstream_check_entry_t      *entry;
    ngx_http_upstream_check_peer_t       *peer;
    ngx_http_upstream_check_peers_t      *peers;
    ngx_uint_t                            i;

    if (ngx_process != NGX_PROCESS_WORKER && ngx_process != NGX_PROCESS_SINGLE)
    {
        return NGX_OK;
    }

    mcmcf = ngx_http_cycle_get_module_main_conf(cycle,
                                                ngx_http_upstream_check_module);

    if (mcmcf == NULL || mcmcf->check_peers == NULL
        || mcmcf->check_peers->nelts == 0 || mcmcf->peers_shm == NULL)
    {
        return NGX_OK;
    }

    peers = ngx_pcalloc(cycle->pool, sizeof(ngx_http_upstream_check_peers_t));
    if (peers == NULL) {
        return NGX_ERROR;
    }

    if (ngx_array_init(&peers->peers, cycle->pool, mcmcf->check_peers->nelts,
                       sizeof(ngx_http_upstream_check_peer_t))
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    entry = mcmcf->check_peers->elts;

    for (i = 0; i < mcmcf->check_peers->nelts; i++) {

        peer = ngx_array_push(&peers->peers);
        if (peer == NULL) {
            return NGX_ERROR;
        }

        ngx_memzero(peer, sizeof(ngx_http_upstream_check_peer_t));

        peer->conf = entry[i].conf;
        peer->sockaddr = entry[i].sockaddr;
        peer->socklen = entry[i].socklen;
        peer->name = entry[i].name;
        peer->shm = &mcmcf->peers_shm->peer[i];
        peer->index = i;
    }

    peers->peers_shm = mcmcf->peers_shm;

    ngx_http_upstream_check_shm_generation = mcmcf->peers_shm->generation;

    check_peers_ctx = peers;

    return ngx_http_upstream_check_add_timers(cycle);
}


static ngx_int_t
ngx_http_upstream_check_add_timers(ngx_cycle_t *cycle)
{
    ngx_uint_t                            i;
    ngx_msec_t                            t, delay;
    ngx_http_upstream_check_peer_t       *peer;
    ngx_http_upstream_check_srv_conf_t   *ucscf;
    ngx_http_upstream_check_peers_t      *peers;

    peers = check_peers_ctx;

    if (peers == NULL || peers->peers_shm == NULL) {
        return NGX_OK;
    }

    /* spread the first probes of the workers over the interval */

    srandom(ngx_pid);

    peer = peers->peers.elts;

    for (i = 0; i < peers->peers.nelts; i++) {

        ucscf = peer[i].conf;

        delay = ucscf->check_interval > 1000 ? ucscf->check_interval : 1000;

        t = (ngx_msec_t) (ngx_random() % delay);

        if (ngx_http_upstream_check_add_timer(&peer[i],
                                              ucscf->check_type_conf,
                                              t, cycle->log)
            != NGX_OK)
        {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_upstream_check_add_timer(ngx_http_upstream_check_peer_t *peer,
    ngx_http_upstream_check_type_t *check_conf, ngx_msec_t timer,
    ngx_log_t *log)
{
    peer->check_ev.handler = ngx_http_upstream_check_begin_handler;
    peer->check_ev.log = log;
    peer->check_ev.data = peer;
    peer->check_ev.timer_set = 0;

    peer->check_timeout_ev.handler = ngx_http_upstream_check_timeout_handler;
    peer->check_timeout_ev.log = log;
    peer->check_timeout_ev.data = peer;

    peer->send_handler = check_conf->send_handler;
    peer->recv_handler = check_conf->recv_handler;
    peer->init = check_conf->init;
    peer->parse = check_conf->parse;

    ngx_add_timer(&peer->check_ev, timer);

    ngx_shmtx_lock(&peer->shm->mutex);
    peer->shm->ref++;
    ngx_shmtx_unlock(&peer->shm->mutex);

    return NGX_OK;
}


static ngx_int_t
ngx_http_upstream_check_need_exit(void)
{
    if (ngx_quit || ngx_terminate) {
        return 1;
    }

    return 0;
}


static void
ngx_http_upstream_check_begin_handler(ngx_event_t *event)
{
    ngx_msec_t                            interval;
    ngx_http_upstream_check_peer_t       *peer;
    ngx_http_upstream_check_srv_conf_t   *ucscf;
    ngx_http_upstream_check_peers_shm_t  *peers_shm;

    if (ngx_http_upstream_check_need_exit()) {
        return;
    }

    if (check_peers_ctx == NULL) {
        return;
    }

    peers_shm = check_peers_ctx->peers_shm;

    peer = event->data;
    ucscf = peer->conf;

    /* the next election happens in a half of the interval */

    ngx_add_timer(event, ucscf->check_interval / 2);

    /* this worker already probes the peer or a probe is in progress */

    if (peer->shm->owner == ngx_pid || peer->check_timeout_ev.timer_set) {
        return;
    }

    ngx_shmtx_lock(&peer->shm->mutex);

    interval = ngx_current_msec - peer->shm->access_time;

    ngx_log_debug5(NGX_LOG_DEBUG_HTTP, event->log, 0,
                   "http check begin handler index: %ui, owner: %P, "
                   "ngx_pid: %P, interval: %M, check_interval: %M",
                   peer->index, peer->shm->owner, ngx_pid, interval,
                   ucscf->check_interval);

    /* the shared memory was rebuilt, the local references are stale */

    if (peers_shm->generation != ngx_http_upstream_check_shm_generation) {
        ngx_shmtx_unlock(&peer->shm->mutex);
        return;
    }

    /*
     * take over the peer when the interval has passed and nobody owns
     * the peer; a peer left owned for 16 intervals means its owner died
     */

    if (interval >= ucscf->check_interval
        && peer->shm->owner == NGX_INVALID_PID)
    {
        peer->shm->owner = ngx_pid;

    } else if (interval >= (ucscf->check_interval << 4)) {

        peer->shm->owner = ngx_pid;
        peer->shm->access_time = ngx_current_msec;
    }

    ngx_shmtx_unlock(&peer->shm->mutex);

    if (peer->shm->owner == ngx_pid) {
        ngx_http_upstream_check_connect_handler(event);
    }
}


static void
ngx_http_upstream_check_connect_handler(ngx_event_t *event)
{
    ngx_int_t                           rc;
    ngx_connection_t                   *c;
    ngx_peer_connection_t              *pc;
    ngx_http_upstream_check_peer_t     *peer;
    ngx_http_upstream_check_srv_conf_t *ucscf;

    if (ngx_http_upstream_check_need_exit()) {
        return;
    }

    peer = event->data;
    ucscf = peer->conf;

    if (peer->pc.connection) {
        ngx_http_upstream_check_clean_event(peer);
    }

    if (peer->pool == NULL) {
        peer->pool = ngx_create_pool(ngx_pagesize, event->log);
        if (peer->pool == NULL) {
            goto check_connect_fail;
        }
    }

    pc = &peer->pc;

    ngx_memzero(pc, sizeof(ngx_peer_connection_t));

    pc->sockaddr = peer->sockaddr;
    pc->socklen = peer->socklen;
    pc->name = &peer->name;
    pc->get = ngx_event_get_peer;
    pc->log = event->log;
    pc->log_error = NGX_ERROR_INFO;
    pc->type = SOCK_STREAM;

    rc = ngx_event_connect_peer(pc);

    if (rc == NGX_ERROR || rc == NGX_BUSY || rc == NGX_DECLINED) {
        goto check_connect_fail;
    }

    c = pc->connection;

    c->data = peer;
    c->pool = peer->pool;
    c->log = event->log;

    c->read->handler = peer->recv_handler;
    c->write->handler = peer->send_handler;

    peer->state = NGX_HTTP_UPSTREAM_CHECK_CONNECT_DONE;

    ngx_add_timer(&peer->check_timeout_ev, ucscf->check_timeout);

    if (rc == NGX_OK) {
        peer->send_handler(c->write);
    }

    /* NGX_AGAIN: the write event fires when the connect completes */

    return;

check_connect_fail:

    ngx_http_upstream_check_status_update(peer, 0);
    ngx_http_upstream_check_clean_event(peer);
}


static void
ngx_http_upstream_check_send_handler(ngx_event_t *event)
{
    ssize_t                         size;
    ngx_connection_t               *c;
    ngx_http_upstream_check_ctx_t  *ctx;
    ngx_http_upstream_check_peer_t *peer;

    c = event->data;
    peer = c->data;

    if (ngx_http_upstream_check_need_exit()) {
        ngx_http_upstream_check_clean_event(peer);
        return;
    }

    ctx = peer->check_data;

    if (peer->state != NGX_HTTP_UPSTREAM_CHECK_CONNECT_DONE) {
        if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
            goto check_send_fail;
        }

        return;
    }

    if (ctx == NULL) {

        ctx = ngx_pcalloc(peer->pool, sizeof(ngx_http_upstream_check_ctx_t));
        if (ctx == NULL) {
            goto check_send_fail;
        }

        peer->check_data = ctx;

        if (peer->init(peer) != NGX_OK) {
            goto check_send_fail;
        }
    }

    while (ctx->send.pos < ctx->send.last) {

        size = c->send(c, ctx->send.pos, ctx->send.last - ctx->send.pos);

        if (size > 0) {
            ctx->send.pos += size;
            continue;
        }

        if (size == NGX_AGAIN) {
            if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
                goto check_send_fail;
            }

            return;
        }

        goto check_send_fail;
    }

    /* the probe is sent; a tcp probe needs no response */

    if (peer->conf->check_type_conf->no_recv) {
        ngx_http_upstream_check_status_update(peer, 1);
        peer->state = NGX_HTTP_UPSTREAM_CHECK_RECV_DONE;
        ngx_http_upstream_check_clean_event(peer);
        return;
    }

    peer->state = NGX_HTTP_UPSTREAM_CHECK_SEND_DONE;

    if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
        goto check_send_fail;
    }

    return;

check_send_fail:

    ngx_http_upstream_check_status_update(peer, 0);
    ngx_http_upstream_check_clean_event(peer);
}


static void
ngx_http_upstream_check_recv_handler(ngx_event_t *event)
{
    u_char                         *new_buf;
    ssize_t                         size;
    size_t                          old_size;
    ngx_int_t                       rc;
    ngx_connection_t               *c;
    ngx_http_upstream_check_ctx_t  *ctx;
    ngx_http_upstream_check_peer_t *peer;

    c = event->data;
    peer = c->data;

    if (ngx_http_upstream_check_need_exit()) {
        ngx_http_upstream_check_clean_event(peer);
        return;
    }

    if (peer->state != NGX_HTTP_UPSTREAM_CHECK_SEND_DONE) {
        if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
            goto check_recv_fail;
        }

        return;
    }

    ctx = peer->check_data;

    if (ctx->recv.start == NULL) {

        ctx->recv.start = ngx_palloc(peer->pool, ngx_pagesize / 2);
        if (ctx->recv.start == NULL) {
            goto check_recv_fail;
        }

        ctx->recv.last = ctx->recv.pos = ctx->recv.start;
        ctx->recv.end = ctx->recv.start + ngx_pagesize / 2;
    }

    while (1) {

        if (ctx->recv.last == ctx->recv.end) {

            old_size = ctx->recv.end - ctx->recv.start;

            if (old_size >= NGX_HTTP_UPSTREAM_CHECK_MAX_RECV) {
                ngx_log_error(NGX_LOG_ERR, c->log, 0,
                              "check response from %V is too large",
                              &peer->name);
                goto check_recv_fail;
            }

            new_buf = ngx_palloc(peer->pool, old_size * 2);
            if (new_buf == NULL) {
                goto check_recv_fail;
            }

            ngx_memcpy(new_buf, ctx->recv.start, old_size);

            ctx->recv.pos = new_buf + (ctx->recv.pos - ctx->recv.start);
            ctx->recv.last = new_buf + old_size;
            ctx->recv.end = new_buf + old_size * 2;
            ctx->recv.start = new_buf;
        }

        size = c->recv(c, ctx->recv.last, ctx->recv.end - ctx->recv.last);

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "http check recv size: %z, peer: %V",
                       size, &peer->name);

        if (size > 0) {
            ctx->recv.last += size;
            continue;
        }

        if (size == 0 || size == NGX_AGAIN) {
            ctx->eof = (size == 0);
            break;
        }

        c->error = 1;
        goto check_recv_fail;
    }

    rc = peer->parse ? peer->parse(peer) : NGX_OK;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http check parse rc: %i, peer: %V",
                   rc, &peer->name);

    switch (rc) {

    case NGX_AGAIN:
        /* wait for the next read event, the timeout guards us */
        return;

    case NGX_ERROR:
        ngx_log_error(NGX_LOG_ERR, event->log, 0,
                      "check protocol %V error with peer: %V",
                      &peer->conf->check_type_conf->name, &peer->name);
        ngx_http_upstream_check_status_update(peer, 0);
        break;

    default:
        ngx_http_upstream_check_status_update(peer, 1);
        break;
    }

    peer->state = NGX_HTTP_UPSTREAM_CHECK_RECV_DONE;

    ngx_http_upstream_check_clean_event(peer);

    return;

check_recv_fail:

    ngx_http_upstream_check_status_update(peer, 0);
    ngx_http_upstream_check_clean_event(peer);
}


static void
ngx_http_upstream_check_timeout_handler(ngx_event_t *event)
{
    ngx_http_upstream_check_peer_t *peer;

    peer = event->data;

    if (ngx_http_upstream_check_need_exit()) {
        ngx_http_upstream_check_clean_event(peer);
        return;
    }

    ngx_log_error(NGX_LOG_INFO, event->log, NGX_ETIMEDOUT,
                  "check peer %V timed out", &peer->name);

    ngx_http_upstream_check_status_update(peer, 0);
    ngx_http_upstream_check_clean_event(peer);
}


static void
ngx_http_upstream_check_status_update(ngx_http_upstream_check_peer_t *peer,
    ngx_int_t success)
{
    ngx_http_upstream_check_srv_conf_t   *ucscf;
    ngx_http_upstream_check_peer_shm_t   *shm;

    ucscf = peer->conf;
    shm = peer->shm;

    ngx_shmtx_lock(&shm->mutex);

    if (success) {

        shm->fall_count = 0;

        if (shm->down) {

            if (++shm->rise_count >= ucscf->rise_count) {
                shm->down = 0;
                shm->rise_count = 0;

                ngx_log_error(NGX_LOG_NOTICE, peer->check_ev.log, 0,
                              "enable check peer: %V", &peer->name);
            }
        }

    } else {

        shm->rise_count = 0;

        if (!shm->down) {

            if (++shm->fall_count >= ucscf->fall_count) {
                shm->down = 1;
                shm->fall_count = 0;

                ngx_log_error(NGX_LOG_NOTICE, peer->check_ev.log, 0,
                              "disable check peer: %V", &peer->name);
            }
        }
    }

    ngx_shmtx_unlock(&shm->mutex);
}


static void
ngx_http_upstream_check_clean_event(ngx_http_upstream_check_peer_t *peer)
{
    ngx_connection_t  *c;

    if (peer->check_timeout_ev.timer_set) {
        ngx_del_timer(&peer->check_timeout_ev);
    }

    c = peer->pc.connection;

    if (c) {
        c->pool = NULL;
        ngx_close_connection(c);
        peer->pc.connection = NULL;
    }

    if (peer->pool) {
        ngx_destroy_pool(peer->pool);
        peer->pool = NULL;
    }

    peer->check_data = NULL;
    peer->state = 0;

    ngx_shmtx_lock(&peer->shm->mutex);

    if (peer->shm->owner == ngx_pid) {
        peer->shm->owner = NGX_INVALID_PID;
        peer->shm->access_time = ngx_current_msec;
    }

    ngx_shmtx_unlock(&peer->shm->mutex);
}


static ngx_int_t
ngx_http_upstream_check_tcp_init(ngx_http_upstream_check_peer_t *peer)
{
    /* a tcp probe sends nothing: the connect result is the verdict */

    return NGX_OK;
}


static ngx_int_t
ngx_http_upstream_check_http_init(ngx_http_upstream_check_peer_t *peer)
{
    ngx_http_upstream_check_ctx_t        *ctx;
    ngx_http_upstream_check_srv_conf_t   *ucscf;

    ctx = peer->check_data;
    ucscf = peer->conf;

    ctx->send.start = ucscf->send.data;
    ctx->send.pos = ucscf->send.data;
    ctx->send.last = ucscf->send.data + ucscf->send.len;
    ctx->send.end = ctx->send.last;

    return NGX_OK;
}


static ngx_int_t
ngx_http_upstream_check_http_parse(ngx_http_upstream_check_peer_t *peer)
{
    u_char                             *p, *line_end, *code;
    ngx_int_t                           status;
    ngx_uint_t                          status_class;
    ngx_http_upstream_check_ctx_t      *ctx;
    ngx_http_upstream_check_srv_conf_t *ucscf;

    ctx = peer->check_data;
    ucscf = peer->conf;

    line_end = NULL;

    for (p = ctx->recv.start; p < ctx->recv.last; p++) {
        if (*p == LF) {
            line_end = p;
            break;
        }
    }

    if (line_end == NULL) {
        return ctx->eof ? NGX_ERROR : NGX_AGAIN;
    }

    if (line_end - ctx->recv.start < 12
        || ngx_strncmp(ctx->recv.start, "HTTP/", 5) != 0)
    {
        return NGX_ERROR;
    }

    p = ngx_strlchr(ctx->recv.start, line_end, ' ');

    if (p == NULL || p + 4 > line_end) {
        return NGX_ERROR;
    }

    code = p + 1;

    if (code[0] < '0' || code[0] > '9'
        || code[1] < '0' || code[1] > '9'
        || code[2] < '0' || code[2] > '9')
    {
        return NGX_ERROR;
    }

    status = (code[0] - '0') * 100 + (code[1] - '0') * 10 + (code[2] - '0');

    status_class = status / 100;

    if (status_class < 2 || status_class > 5) {
        return NGX_ERROR;
    }

    if (ucscf->status_alive & ((ngx_uint_t) 1 << status_class)) {
        return NGX_OK;
    }

    return NGX_ERROR;
}


ngx_int_t
ngx_http_upstream_check_peer_down(ngx_int_t check_index, ngx_uint_t n)
{
    ngx_uint_t                           index;
    ngx_http_upstream_check_peers_shm_t *peers_shm;

    if (check_index == NGX_ERROR || check_peers_ctx == NULL) {
        return 0;
    }

    peers_shm = check_peers_ctx->peers_shm;

    if (peers_shm == NULL) {
        return 0;
    }

    index = check_index + n;

    if (index >= peers_shm->number) {
        return 0;
    }

    return peers_shm->peer[index].down;
}
