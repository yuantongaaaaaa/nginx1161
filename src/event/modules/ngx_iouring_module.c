
/*
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>

#include <liburing.h>
#include <poll.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <errno.h>

#include "ngx_iouring_module.h"


#if (NGX_HAVE_FILE_AIO)
#error "ngx_iouring_module does not support legacy --with-file-aio yet"
#endif


#ifndef POLLRDHUP
#define POLLRDHUP  0x2000
#endif


typedef struct {
    ngx_uint_t  entries;
    ngx_uint_t  events;
} ngx_iouring_conf_t;


typedef struct {
    ngx_event_t       *ev;
    ngx_connection_t  *c;
    ngx_socket_t       fd;
    ngx_uint_t         events;
    ngx_uint_t         instance;
    ngx_uint_t         next;
    unsigned           cancelled:1;
    unsigned           poll_done:1;
    unsigned           cancel_submitted:1;
    unsigned           cancel_done:1;
} ngx_iouring_request_t;


static ngx_int_t ngx_iouring_init(ngx_cycle_t *cycle, ngx_msec_t timer);
static void ngx_iouring_done(ngx_cycle_t *cycle);
static ngx_int_t ngx_iouring_add_event(ngx_event_t *ev, ngx_int_t event,
    ngx_uint_t flags);
static ngx_int_t ngx_iouring_del_event(ngx_event_t *ev, ngx_int_t event,
    ngx_uint_t flags);
static ngx_int_t ngx_iouring_add_connection(ngx_connection_t *c);
static ngx_int_t ngx_iouring_del_connection(ngx_connection_t *c,
    ngx_uint_t flags);
static ngx_int_t ngx_iouring_process_events(ngx_cycle_t *cycle,
    ngx_msec_t timer, ngx_uint_t flags);
static ngx_int_t ngx_iouring_notify(ngx_event_handler_pt handler);
static void ngx_iouring_handle_cqe(ngx_cycle_t *cycle, struct io_uring_cqe *cqe,
    ngx_uint_t flags);

#if (NGX_SSL && NGX_SSL_ASYNC)
static ngx_int_t ngx_iouring_add_async_connection(ngx_connection_t *c);
static ngx_int_t ngx_iouring_del_async_connection(ngx_connection_t *c,
    ngx_uint_t flags);
#endif

static void *ngx_iouring_create_conf(ngx_cycle_t *cycle);
static char *ngx_iouring_init_conf(ngx_cycle_t *cycle, void *conf);


static struct io_uring         ngx_ring;
static ngx_int_t               ngx_ring_ready = 0;
static struct io_uring         ngx_io_ring;
static ngx_int_t               ngx_io_ring_ready = 0;
static ngx_iouring_request_t  *ngx_requests;
static ngx_uint_t              ngx_requests_n;
static ngx_uint_t              ngx_free_request;
static ngx_uint_t              ngx_nevents;
static int                     ngx_notify_fd = -1;
static ngx_event_t             ngx_notify_event;
static ngx_connection_t        ngx_notify_conn;

/*
 * Phase 2: pure-async TCP I/O function table installed into ngx_io
 * by ngx_iouring_init().  UDP / sendfile entries are intentionally
 * left pointing at the OS defaults; they will be converted in Phase 3.
 */
static ngx_os_io_t  ngx_iouring_io = {
    ngx_iouring_recv,
    ngx_iouring_readv_chain,
    ngx_udp_unix_recv,
    ngx_iouring_send,
    ngx_udp_unix_send,
    ngx_udp_unix_sendmsg_chain,
    ngx_iouring_writev_chain,
    0
};


static ngx_str_t  ngx_iouring_name = ngx_string("iouring");


static ngx_command_t  ngx_iouring_commands[] = {

    { ngx_string("iouring_entries"),
      NGX_EVENT_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      0,
      offsetof(ngx_iouring_conf_t, entries),
      NULL },

    { ngx_string("iouring_events"),
      NGX_EVENT_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      0,
      offsetof(ngx_iouring_conf_t, events),
      NULL },

      ngx_null_command
};


static ngx_event_module_t  ngx_iouring_module_ctx = {
    &ngx_iouring_name,
    ngx_iouring_create_conf,               /* create configuration */
    ngx_iouring_init_conf,                 /* init configuration */

    {
        ngx_iouring_add_event,             /* add an event */
        ngx_iouring_del_event,             /* delete an event */
        ngx_iouring_add_event,             /* enable an event */
        ngx_iouring_del_event,             /* disable an event */
        ngx_iouring_add_connection,        /* add a connection */
        ngx_iouring_del_connection,        /* delete a connection */
        ngx_iouring_notify,                /* notify */
        ngx_iouring_process_events,        /* process events */
        ngx_iouring_init,                  /* init the module */
        ngx_iouring_done,                  /* done the module */
#if (NGX_SSL && NGX_SSL_ASYNC)
        ngx_iouring_add_async_connection,  /* add async connection */
        ngx_iouring_del_async_connection   /* delete async connection */
#endif
    }
};


ngx_module_t  ngx_iouring_module = {
    NGX_MODULE_V1,
    &ngx_iouring_module_ctx,               /* module context */
    ngx_iouring_commands,                  /* module directives */
    NGX_EVENT_MODULE,                      /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static uint64_t
ngx_iouring_poll_data(ngx_uint_t id)
{
    return ((uint64_t) (id + 1)) << 1;
}


static uint64_t
ngx_iouring_cancel_data(ngx_uint_t id)
{
    return (((uint64_t) (id + 1)) << 1) | 1;
}


static ngx_uint_t
ngx_iouring_alloc_request(void)
{
    ngx_uint_t              id;
    ngx_iouring_request_t  *req;

    if (ngx_free_request == NGX_INVALID_INDEX) {
        return NGX_INVALID_INDEX;
    }

    id = ngx_free_request;
    req = &ngx_requests[id];
    ngx_free_request = req->next;
    ngx_memzero(req, sizeof(ngx_iouring_request_t));

    return id;
}


static void
ngx_iouring_free_request(ngx_uint_t id)
{
    ngx_iouring_request_t  *req;

    req = &ngx_requests[id];
    req->ev = NULL;
    req->c = NULL;
    req->next = ngx_free_request;
    ngx_free_request = id;
}


static void
ngx_iouring_release_request(ngx_uint_t id)
{
    ngx_iouring_request_t  *req;

    req = &ngx_requests[id];

    if (req->ev == NULL || !req->poll_done) {
        return;
    }

    if (req->cancel_submitted && !req->cancel_done) {
        return;
    }

    ngx_iouring_free_request(id);
}


static struct io_uring_sqe *
ngx_iouring_get_sqe(ngx_log_t *log)
{
    int                   rc;
    struct io_uring_sqe  *sqe;

    sqe = io_uring_get_sqe(&ngx_ring);
    if (sqe != NULL) {
        return sqe;
    }

    rc = io_uring_submit(&ngx_ring);
    if (rc < 0) {
        ngx_log_error(NGX_LOG_ALERT, log, -rc, "io_uring_submit() failed");
        return NULL;
    }

    sqe = io_uring_get_sqe(&ngx_ring);
    if (sqe == NULL) {
        ngx_log_error(NGX_LOG_ALERT, log, 0, "io_uring SQ ring is still full");
    }

    return sqe;
}


static ngx_int_t
ngx_iouring_arm(ngx_event_t *ev, ngx_connection_t *c, ngx_socket_t fd,
    ngx_uint_t events)
{
    ngx_uint_t              id;
    ngx_iouring_request_t  *req;
    struct io_uring_sqe    *sqe;

    id = ngx_iouring_alloc_request();
    if (id == NGX_INVALID_INDEX) {
        ngx_log_error(NGX_LOG_ALERT, ev->log, 0,
                      "no free io_uring request slots");
        return NGX_ERROR;
    }

    sqe = ngx_iouring_get_sqe(ev->log);
    if (sqe == NULL) {
        ngx_iouring_free_request(id);
        return NGX_ERROR;
    }

    req = &ngx_requests[id];
    req->ev = ev;
    req->c = c;
    req->fd = fd;
    req->events = events;
    req->instance = ev->instance;

    io_uring_prep_poll_add(sqe, fd, events);
    io_uring_sqe_set_data64(sqe, ngx_iouring_poll_data(id));

    ev->index = id;
    ev->active = 1;

    return NGX_OK;
}


static void
ngx_iouring_cancel(ngx_event_t *ev)
{
    ngx_uint_t              id;
    ngx_iouring_request_t  *req;
    struct io_uring_sqe    *sqe;

    id = ev->index;
    ev->index = NGX_INVALID_INDEX;
    ev->active = 0;

    if (id == NGX_INVALID_INDEX || id >= ngx_requests_n) {
        return;
    }

    req = &ngx_requests[id];

    if (req->ev != ev || req->poll_done || req->cancelled) {
        return;
    }

    req->cancelled = 1;

    sqe = ngx_iouring_get_sqe(ev->log);
    if (sqe == NULL) {
        return;
    }

    io_uring_prep_poll_remove(sqe, ngx_iouring_poll_data(id));
    io_uring_sqe_set_data64(sqe, ngx_iouring_cancel_data(id));

    req->cancel_submitted = 1;
}


static ngx_socket_t
ngx_iouring_event_fd(ngx_event_t *ev, ngx_connection_t *c)
{
#if (NGX_SSL && NGX_SSL_ASYNC)
    if (ev == c->async) {
        return c->async_fd;
    }
#endif
    return c->fd;
}


static ngx_int_t
ngx_iouring_add_event(ngx_event_t *ev, ngx_int_t event, ngx_uint_t flags)
{
    ngx_uint_t        events;
    ngx_connection_t  *c;

    if (ev->active) {
        return NGX_OK;
    }

    c = ev->data;

    if (event == NGX_READ_EVENT) {
        events = POLLIN | POLLRDHUP;

    } else {
        events = POLLOUT;
    }

    return ngx_iouring_arm(ev, c, c->fd, events);
}


static ngx_int_t
ngx_iouring_del_event(ngx_event_t *ev, ngx_int_t event, ngx_uint_t flags)
{
    ngx_iouring_cancel(ev);
    return NGX_OK;
}


static ngx_int_t
ngx_iouring_add_connection(ngx_connection_t *c)
{
    if (ngx_iouring_arm(c->read, c, c->fd, POLLIN | POLLRDHUP) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_iouring_arm(c->write, c, c->fd, POLLOUT) != NGX_OK) {
        ngx_iouring_cancel(c->read);
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_iouring_del_connection(ngx_connection_t *c, ngx_uint_t flags)
{
    /*
     * Phase 2: release the per-event I/O contexts (they cache the iovec
     * arrays) before canceling the polls.  All TCP I/O now completes
     * synchronously inside recv/send, so there is never an in-flight op
     * to cancel here -- this only frees the cached context.
     */
    ngx_iouring_io_detach(c->read);
    ngx_iouring_io_detach(c->write);

    ngx_iouring_cancel(c->read);
    ngx_iouring_cancel(c->write);
    return NGX_OK;
}


#if (NGX_SSL && NGX_SSL_ASYNC)

static ngx_int_t
ngx_iouring_add_async_connection(ngx_connection_t *c)
{
    return ngx_iouring_arm(c->async, c, c->async_fd, POLLIN);
}


static ngx_int_t
ngx_iouring_del_async_connection(ngx_connection_t *c, ngx_uint_t flags)
{
    ngx_iouring_cancel(c->async);
    c->async_fd = -1;
    return NGX_OK;
}

#endif


static void
ngx_iouring_notify_handler(ngx_event_t *ev)
{
    ssize_t               n;
    uint64_t              count;
    ngx_event_handler_pt  handler;

    n = read(ngx_notify_fd, &count, sizeof(count));
    if (n != (ssize_t) sizeof(count) && ngx_errno != NGX_EAGAIN) {
        ngx_log_error(NGX_LOG_ALERT, ev->log, ngx_errno,
                      "read(io_uring notify eventfd) failed");
    }

    handler = ev->data;
    handler(ev);
}


static ngx_int_t
ngx_iouring_notify_init(ngx_log_t *log)
{
    ngx_notify_fd = eventfd(0, EFD_NONBLOCK);
    if (ngx_notify_fd == -1) {
        ngx_log_error(NGX_LOG_ALERT, log, ngx_errno, "eventfd() failed");
        return NGX_ERROR;
    }

    ngx_notify_event.handler = ngx_iouring_notify_handler;
    ngx_notify_event.log = log;
    ngx_notify_event.data = &ngx_notify_conn;

    ngx_notify_conn.fd = ngx_notify_fd;
    ngx_notify_conn.read = &ngx_notify_event;
    ngx_notify_conn.log = log;

    if (ngx_iouring_arm(&ngx_notify_event, &ngx_notify_conn,
                        ngx_notify_fd, POLLIN)
        != NGX_OK)
    {
        close(ngx_notify_fd);
        ngx_notify_fd = -1;
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_iouring_notify(ngx_event_handler_pt handler)
{
    static uint64_t  inc = 1;

    ngx_notify_event.data = handler;

    if (write(ngx_notify_fd, &inc, sizeof(inc)) != (ssize_t) sizeof(inc)) {
        ngx_log_error(NGX_LOG_ALERT, ngx_notify_event.log, ngx_errno,
                      "write(io_uring notify eventfd) failed");
        return NGX_ERROR;
    }

    return NGX_OK;
}


/*
 * Phase 2: free an ngx_iouring_io_t together with its cached iovec
 * array.  Safe to call at any time: I/O completes synchronously, so no
 * SQE ever references io->iovs / io->buf after run_io() returns.
 */
void
ngx_iouring_io_free(ngx_iouring_io_t *io)
{
    if (io == NULL) {
        return;
    }

    if (io->iovs != NULL) {
        ngx_free(io->iovs);
        io->iovs = NULL;
    }

    ngx_free(io);
}


/*
 * Phase 2: submit the TCP I/O operation described by io to the
 * dedicated synchronous io_uring instance (ngx_io_ring) and reap its
 * completion before returning.  Because the op is issued and consumed
 * within a single call, the caller's buffer is never left referenced by
 * an in-flight kernel op across an NGX_AGAIN return -- the root cause of
 * the heap corruption in the earlier fully-async design.
 *
 * RECV/SEND carry MSG_DONTWAIT so they complete inline during submit
 * (nginx only calls recv/send once the poll reported the socket ready,
 * so the data is already buffered) and surface a would-block as -EAGAIN
 * instead of parking the worker.  Exactly one op is ever outstanding on
 * ngx_io_ring, so io_uring_wait_cqe() returns our completion.
 */
ngx_int_t
ngx_iouring_run_io(ngx_iouring_io_t *io)
{
    int                   rc;
    struct io_uring_sqe  *sqe;
    struct io_uring_cqe  *cqe;

    if (!ngx_io_ring_ready) {
        return NGX_ERROR;
    }

    sqe = io_uring_get_sqe(&ngx_io_ring);
    if (sqe == NULL) {
        rc = io_uring_submit(&ngx_io_ring);
        if (rc < 0) {
            ngx_log_error(NGX_LOG_ALERT, io->ev->log, -rc,
                          "io_uring_submit() io ring failed");
            return NGX_ERROR;
        }

        sqe = io_uring_get_sqe(&ngx_io_ring);
        if (sqe == NULL) {
            ngx_log_error(NGX_LOG_ALERT, io->ev->log, 0,
                          "io_uring io SQ ring is full");
            return NGX_ERROR;
        }
    }

    switch (io->type) {

    case NGX_IOURING_IO_RECV:
        io_uring_prep_recv(sqe, io->c->fd, io->buf, io->size, MSG_DONTWAIT);
        break;

    case NGX_IOURING_IO_READV:
        io_uring_prep_readv(sqe, io->c->fd, io->iovs, io->iovcnt, 0);
        break;

    case NGX_IOURING_IO_SEND:
        io_uring_prep_send(sqe, io->c->fd, io->buf, io->size, MSG_DONTWAIT);
        break;

    case NGX_IOURING_IO_WRITEV:
        io_uring_prep_writev(sqe, io->c->fd, io->iovs, io->iovcnt, 0);
        break;

    default:
        return NGX_ERROR;
    }

    io_uring_sqe_set_data64(sqe, 1);

    rc = io_uring_submit(&ngx_io_ring);
    if (rc != 1) {
        ngx_log_error(NGX_LOG_ALERT, io->ev->log, rc < 0 ? -rc : 0,
                      "io_uring_submit() io op submitted %d", rc);
        return NGX_ERROR;
    }

    rc = io_uring_wait_cqe(&ngx_io_ring, &cqe);
    if (rc != 0) {
        ngx_log_error(NGX_LOG_ALERT, io->ev->log, -rc,
                      "io_uring_wait_cqe() io op failed");
        return NGX_ERROR;
    }

    io->result = cqe->res;
    io_uring_cqe_seen(&ngx_io_ring, cqe);

    return NGX_OK;
}


/*
 * Phase 2: release the per-event I/O context bound to ev (it caches the
 * iovec array used by readv/writev).  Called from
 * ngx_iouring_del_connection().  Since every op completes synchronously
 * inside recv/send, there is never an in-flight kernel op to cancel --
 * this simply frees the cached context so the reused event structure
 * starts clean on the next connection.
 */
void
ngx_iouring_io_detach(ngx_event_t *ev)
{
    ngx_iouring_io_t  *io;

    io = ev->iouring_io;
    if (io == NULL) {
        return;
    }

    ev->iouring_io = NULL;
    ngx_iouring_io_free(io);
}


static void
ngx_iouring_handle_cqe(ngx_cycle_t *cycle, struct io_uring_cqe *cqe,
    ngx_uint_t flags)
{
    uint64_t                data;
    ngx_uint_t              id, revents, events;
    ngx_int_t               valid;
    ngx_queue_t            *queue;
    ngx_event_t            *ev;
    ngx_connection_t       *c;
    ngx_iouring_request_t  *req;

    data = io_uring_cqe_get_data64(cqe);
    if (data == 0) {
        return;
    }

    id = (ngx_uint_t) (data >> 1) - 1;
    if (id >= ngx_requests_n) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, 0,
                      "invalid io_uring request id: %ui", id);
        return;
    }

    req = &ngx_requests[id];

    if (data & 1) {
        req->cancel_done = 1;
        ngx_iouring_release_request(id);
        return;
    }

    req->poll_done = 1;

    ev = req->ev;
    c = req->c;

    if (ev == NULL || c == NULL) {
        ngx_iouring_release_request(id);
        return;
    }

    valid = !req->cancelled
            && ev->active
            && !ev->closed
            && ev->instance == req->instance
            && ngx_iouring_event_fd(ev, c) == req->fd;

    if (ev->index == id) {
        ev->index = NGX_INVALID_INDEX;
        ev->active = 0;
    }

    if (!valid) {
        ngx_iouring_release_request(id);
        return;
    }

    events = req->events;

    if (cqe->res < 0) {
        if (cqe->res == -ECANCELED) {
            ngx_iouring_release_request(id);
            return;
        }

        ngx_log_error(NGX_LOG_ALERT, ev->log, -cqe->res,
                      "io_uring poll completion failed on fd:%d", req->fd);
        revents = POLLERR | POLLHUP;

    } else {
        revents = (ngx_uint_t) cqe->res;
    }

    /* re-arm the poll so the fd stays monitored */
    if (ngx_iouring_arm(ev, c, req->fd, events) != NGX_OK) {
        ngx_log_error(NGX_LOG_ALERT, ev->log, 0,
                      "failed to rearm io_uring poll on fd:%d", req->fd);
    }

    if (!(revents & events)
        && !(revents & (POLLERR | POLLHUP | POLLNVAL)))
    {
        ngx_iouring_release_request(id);
        return;
    }

    if (ev == c->read) {
        if (revents & POLLRDHUP) {
            ev->pending_eof = 1;
        }
        ev->available = -1;
    }

    ev->ready = 1;

#if (NGX_THREADS)
    if (ev->write) {
        ev->complete = 1;
    }
#endif

    if (flags & NGX_POST_EVENTS) {
        queue = ev->accept ? &ngx_posted_accept_events : &ngx_posted_events;
        ngx_post_event(ev, queue);

    } else {
        ev->handler(ev);
    }

    ngx_iouring_release_request(id);
}


static ngx_int_t
ngx_iouring_process_events(ngx_cycle_t *cycle, ngx_msec_t timer,
    ngx_uint_t flags)
{
    int                       rc;
    ngx_err_t                 err;
    ngx_uint_t                i, level;
    struct io_uring_cqe      *cqe;
    struct __kernel_timespec  ts;

    cqe = NULL;

    rc = io_uring_submit(&ngx_ring);

    if (rc >= 0) {
        if (timer == 0) {
            rc = io_uring_peek_cqe(&ngx_ring, &cqe);

        } else if (timer == NGX_TIMER_INFINITE) {
            rc = io_uring_wait_cqe(&ngx_ring, &cqe);

        } else {
            ts.tv_sec = timer / 1000;
            ts.tv_nsec = (timer % 1000) * 1000000;
            rc = io_uring_wait_cqe_timeout(&ngx_ring, &cqe, &ts);
        }
    }

    err = (rc < 0) ? (ngx_err_t) -rc : 0;

    if (flags & NGX_UPDATE_TIME || ngx_event_timer_alarm) {
        ngx_time_update();
    }

    if (err == NGX_EAGAIN || err == ETIMEDOUT) {
        return NGX_OK;
    }

    if (err) {
        if (err == NGX_EINTR) {
            if (ngx_event_timer_alarm) {
                ngx_event_timer_alarm = 0;
                return NGX_OK;
            }

            level = NGX_LOG_INFO;

        } else {
            level = NGX_LOG_ALERT;
        }

        ngx_log_error(level, cycle->log, err, "io_uring wait/submit failed");
        return NGX_ERROR;
    }

    for (i = 0; i < ngx_nevents; i++) {
        if (i != 0 && io_uring_peek_cqe(&ngx_ring, &cqe) != 0) {
            break;
        }

        ngx_iouring_handle_cqe(cycle, cqe, flags);
        io_uring_cqe_seen(&ngx_ring, cqe);
    }

    return NGX_OK;
}


static ngx_int_t
ngx_iouring_init(ngx_cycle_t *cycle, ngx_msec_t timer)
{
    int                  rc;
    ngx_uint_t           i;
    ngx_iouring_conf_t  *icf;

    if (ngx_ring_ready) {
        return NGX_OK;
    }

    icf = ngx_event_get_conf(cycle->conf_ctx, ngx_iouring_module);

    rc = io_uring_queue_init(icf->entries, &ngx_ring, 0);
    if (rc < 0) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, -rc,
                      "io_uring_queue_init() failed");
        return NGX_ERROR;
    }

    /*
     * Phase 2: a second, dedicated ring for synchronous TCP data
     * transfer (RECV/READV/SEND/WRITEV).  Keeping it separate from the
     * poll ring means exactly one op is outstanding on it at a time, so
     * ngx_iouring_run_io() reaps its completion with a plain
     * io_uring_wait_cqe() and never races with poll/cancel completions.
     */
    rc = io_uring_queue_init(icf->entries, &ngx_io_ring, 0);
    if (rc < 0) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, -rc,
                      "io_uring_queue_init() io ring failed");
        io_uring_queue_exit(&ngx_ring);
        return NGX_ERROR;
    }

    ngx_io_ring_ready = 1;

    ngx_requests_n = cycle->connection_n * 4 + 64;
    ngx_requests = ngx_alloc(sizeof(ngx_iouring_request_t) * ngx_requests_n,
                             cycle->log);
    if (ngx_requests == NULL) {
        io_uring_queue_exit(&ngx_ring);
        return NGX_ERROR;
    }

    for (i = 0; i < ngx_requests_n; i++) {
        ngx_requests[i].next = i + 1;
    }

    ngx_requests[ngx_requests_n - 1].next = NGX_INVALID_INDEX;
    ngx_free_request = 0;

    ngx_nevents = icf->events;
    ngx_ring_ready = 1;

    if (ngx_iouring_notify_init(cycle->log) != NGX_OK) {
        ngx_iouring_module_ctx.actions.notify = NULL;
    }

    ngx_io = ngx_iouring_io;
    ngx_event_actions = ngx_iouring_module_ctx.actions;
    ngx_event_flags = NGX_USE_CLEAR_EVENT
                      | NGX_USE_GREEDY_EVENT
                      | NGX_USE_EPOLL_EVENT;

#if (NGX_HAVE_EPOLLRDHUP)
    ngx_use_epoll_rdhup = 1;
#endif

    return NGX_OK;
}


static void
ngx_iouring_done(ngx_cycle_t *cycle)
{
    if (ngx_notify_fd != -1) {
        close(ngx_notify_fd);
        ngx_notify_fd = -1;
    }

    if (ngx_io_ring_ready) {
        io_uring_queue_exit(&ngx_io_ring);
        ngx_io_ring_ready = 0;
    }

    if (ngx_ring_ready) {
        io_uring_queue_exit(&ngx_ring);
        ngx_ring_ready = 0;
    }

    if (ngx_requests != NULL) {
        ngx_free(ngx_requests);
        ngx_requests = NULL;
    }

    ngx_requests_n = 0;
    ngx_free_request = NGX_INVALID_INDEX;
    ngx_nevents = 0;
}


static void *
ngx_iouring_create_conf(ngx_cycle_t *cycle)
{
    ngx_iouring_conf_t  *icf;

    icf = ngx_palloc(cycle->pool, sizeof(ngx_iouring_conf_t));
    if (icf == NULL) {
        return NULL;
    }

    icf->entries = NGX_CONF_UNSET_UINT;
    icf->events = NGX_CONF_UNSET_UINT;

    return icf;
}


static char *
ngx_iouring_init_conf(ngx_cycle_t *cycle, void *conf)
{
    ngx_iouring_conf_t  *icf = conf;

    ngx_conf_init_uint_value(icf->entries, 1024);
    ngx_conf_init_uint_value(icf->events, 512);

    return NGX_CONF_OK;
}
