
/*
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_IOURING_MODULE_H_INCLUDED_
#define _NGX_IOURING_MODULE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


/*
 * Operation types submitted to io_uring for TCP data transfer.
 * Phase 2 covers TCP recv/readv/send/writev only; UDP, sendfile,
 * file AIO, splice, xquic/xudp and kTLS are intentionally excluded
 * and will be handled in later phases.
 */
#define NGX_IOURING_IO_NONE     0
#define NGX_IOURING_IO_RECV     1
#define NGX_IOURING_IO_READV    2
#define NGX_IOURING_IO_SEND     3
#define NGX_IOURING_IO_WRITEV   4


typedef struct ngx_iouring_io_s  ngx_iouring_io_t;

/*
 * Per-event I/O context.  Phase 2 completes every operation
 * synchronously inside the recv/send call (submit the SQE to the
 * dedicated io_uring instance and reap its CQE before returning), so
 * the context carries no in-flight state: it only describes the
 * operation being built and caches the on-demand iovec array.  This
 * keeps nginx's synchronous c->recv/c->send buffer contract intact --
 * the caller's buffer is never handed to the kernel across an
 * NGX_AGAIN return, which is what corrupted the heap in the earlier
 * fully-async attempt.
 */
struct ngx_iouring_io_s {
    ngx_event_t        *ev;
    ngx_connection_t   *c;

    /* operation type, one of NGX_IOURING_IO_* */
    ngx_uint_t          type;

    /* single-buffer operation (recv/send) */
    u_char             *buf;
    size_t              size;

    /* chain operation (readv/writev): caller-supplied chain head */
    ngx_chain_t        *chain;

    /* iovec array built from chain; allocated on demand, cached per event */
    struct iovec       *iovs;
    ngx_uint_t          iovcnt;

    /* raw CQE result of the last synchronous operation:
     *   > 0  bytes transferred
     *   = 0  peer closed (recv) or zero-length send
     *   < 0  negated errno (NGX_EAGAIN / ...)
     */
    ssize_t             result;
};


/*
 * Submit the operation described by io to the dedicated synchronous
 * io_uring instance and block until its completion is reaped.  The
 * caller must have filled io->ev, io->c, io->type and the type-specific
 * payload fields (buf/size for recv/send, iovs/iovcnt for readv/writev).
 * On NGX_OK the raw cqe->res is stored in io->result; the caller then
 * translates it into nginx's return convention.  RECV/SEND are issued
 * with MSG_DONTWAIT so they never block the worker: a would-block
 * completion surfaces as -EAGAIN in io->result.
 */
ngx_int_t ngx_iouring_run_io(ngx_iouring_io_t *io);

/*
 * Release the per-event I/O context (and its cached iovec array).
 * Called from ngx_iouring_del_connection() so a closing connection does
 * not leak the context bound to its reused read/write event structures.
 */
void ngx_iouring_io_detach(ngx_event_t *ev);

/*
 * Release an ngx_iouring_io_t together with its iovec array.
 */
void ngx_iouring_io_free(ngx_iouring_io_t *io);


/*
 * Pure io_uring replacements for the TCP entries of ngx_os_io_t.
 * Installed into ngx_io by ngx_iouring_init() so that the rest of
 * nginx (HTTP request body, upstream, write filter, ...) transparently
 * drives TCP data transfer through io_uring RECV/READV/SEND/WRITEV ops
 * without touching the existing state machine.
 */
ssize_t ngx_iouring_recv(ngx_connection_t *c, u_char *buf, size_t size);
ssize_t ngx_iouring_readv_chain(ngx_connection_t *c, ngx_chain_t *chain,
    off_t limit);
ssize_t ngx_iouring_send(ngx_connection_t *c, u_char *buf, size_t size);
ngx_chain_t *ngx_iouring_writev_chain(ngx_connection_t *c, ngx_chain_t *in,
    off_t limit);


#endif /* _NGX_IOURING_MODULE_H_INCLUDED_ */
