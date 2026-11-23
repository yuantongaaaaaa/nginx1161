
/*
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>

#include "ngx_iouring_module.h"


/*
 * Lazily allocate (or reuse) the ngx_iouring_io_t bound to ev.  The
 * context lives as long as the event itself and is released by
 * ngx_iouring_io_detach() on connection teardown.  It caches the iovec
 * array so readv/writev do not re-allocate it on every call.
 */
static ngx_iouring_io_t *
ngx_iouring_io_get(ngx_event_t *ev)
{
    ngx_iouring_io_t  *io;

    io = ev->iouring_io;
    if (io != NULL) {
        return io;
    }

    io = ngx_calloc(sizeof(ngx_iouring_io_t), ev->log);
    if (io == NULL) {
        return NULL;
    }

    io->ev = ev;
    io->c = ev->data;

    ev->iouring_io = io;

    return io;
}


/*
 * Reset the per-operation fields so the same io context can be reused
 * for the next recv/send on this event.  The iovs array is preserved
 * (it is allocated once per event and freed by io_free/io_detach).
 */
static void
ngx_iouring_io_reset(ngx_iouring_io_t *io)
{
    io->type = NGX_IOURING_IO_NONE;
    io->buf = NULL;
    io->size = 0;
    io->chain = NULL;
    io->iovcnt = 0;
    io->result = 0;
}


/*
 * Translate a completed RECV / READV result (io->result, filled in
 * synchronously by ngx_iouring_run_io) into the return value nginx's
 * read event consumers expect, mirroring ngx_unix_recv:
 *   n > 0      bytes read, rev->ready / rev->available updated
 *   n == 0     peer closed (rev->eof = 1)
 *   NGX_AGAIN  EAGAIN / EINTR — caller should re-poll
 *   NGX_ERROR  hard error, rev->error = 1
 */
static ssize_t
ngx_iouring_recv_result(ngx_connection_t *c, ngx_iouring_io_t *io)
{
    ssize_t       n;
    size_t        size;
    ngx_err_t     err;
    ngx_event_t  *rev;

    rev = c->read;
    n = io->result;
    size = io->size;

    ngx_iouring_io_reset(io);

    if (n > 0) {

#if (NGX_HAVE_FIONREAD)
        if ((size_t) n == size) {
            if (ngx_socket_nread(c->fd, &rev->available) == -1) {
                rev->ready = 0;
                rev->error = 1;
                return ngx_connection_error(c, ngx_socket_errno,
                                            ngx_socket_nread_n " failed");
            }
        }
#endif

        if ((size_t) n < size) {
            if (!rev->pending_eof) {
                rev->ready = 0;
            }

            rev->available = 0;
        }

        return n;
    }

    rev->ready = 0;

    if (n == 0) {
        rev->eof = 1;
        return 0;
    }

    err = (ngx_err_t) -n;

    if (err == NGX_EAGAIN || err == NGX_EINTR || err == NGX_ECANCELED) {
        return NGX_AGAIN;
    }

    rev->error = 1;
    return ngx_connection_error(c, err, "io_uring recv/readv failed");
}


/*
 * io_uring replacement for ngx_unix_recv on TCP sockets.  The RECV op
 * is submitted with MSG_DONTWAIT and its completion reaped before this
 * function returns, so the caller's buffer is filled (or left untouched
 * on NGX_AGAIN) exactly like a synchronous recv() -- nginx's contract
 * that the buffer is never touched after NGX_AGAIN is preserved.
 */
ssize_t
ngx_iouring_recv(ngx_connection_t *c, u_char *buf, size_t size)
{
    ngx_iouring_io_t  *io;

    if (size == 0) {
        return ngx_os_io.recv(c, buf, size);
    }

    io = ngx_iouring_io_get(c->read);
    if (io == NULL) {
        return NGX_ERROR;
    }

    io->type = NGX_IOURING_IO_RECV;
    io->buf = buf;
    io->size = size;

    if (ngx_iouring_run_io(io) != NGX_OK) {
        ngx_iouring_io_reset(io);
        return NGX_ERROR;
    }

    return ngx_iouring_recv_result(c, io);
}


/*
 * Allocate the iovec array on first use.  Sized to NGX_IOVS_PREALLOCATE
 * (min(IOV_MAX, 64)) which matches nginx's writev/readv convention.
 */
static ngx_int_t
ngx_iouring_io_alloc_iovs(ngx_iouring_io_t *io)
{
    if (io->iovs != NULL) {
        return NGX_OK;
    }

    io->iovs = ngx_alloc(sizeof(struct iovec) * NGX_IOVS_PREALLOCATE,
                         io->ev->log);
    if (io->iovs == NULL) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


/*
 * Walk a buffer chain and coalesce contiguous segments into io->iovs[],
 * mirroring ngx_readv_chain's iovec building logic.  Honors the limit
 * (client_body_buffer_size / proxy buffer budget) and merges adjacent
 * buffers whose last/end pointers touch so we stay under IOV_MAX.
 *
 * Returns NGX_OK on success, NGX_DECLINED when the chain has no
 * writable space (size == 0), NGX_ERROR on allocation failure.
 */
static ngx_int_t
ngx_iouring_build_readv(ngx_iouring_io_t *io, ngx_chain_t *chain,
    off_t limit)
{
    u_char       *prev;
    ssize_t       n;
    size_t        size;
    ngx_uint_t    count;
    struct iovec  *iov;

    if (ngx_iouring_io_alloc_iovs(io) != NGX_OK) {
        return NGX_ERROR;
    }

    prev = NULL;
    iov = NULL;
    size = 0;
    count = 0;

    while (chain) {

        n = chain->buf->end - chain->buf->last;

        if (limit) {
            if ((off_t) size >= limit) {
                break;
            }

            if ((off_t) (size + n) > limit) {
                n = (ssize_t) (limit - size);
            }
        }

        if (n <= 0) {
            chain = chain->next;
            continue;
        }

        if (prev == chain->buf->last) {
            iov->iov_len += n;

        } else {
            if (count == NGX_IOVS_PREALLOCATE) {
                break;
            }

            iov = &io->iovs[count++];
            iov->iov_base = chain->buf->last;
            iov->iov_len = n;
        }

        size += n;
        prev = chain->buf->end;
        chain = chain->next;
    }

    if (size == 0) {
        return NGX_DECLINED;
    }

    io->iovcnt = count;
    io->size = size;

    return NGX_OK;
}


/*
 * io_uring replacement for ngx_readv_chain.  Builds the iovec from the
 * chain, submits a READV and reaps it synchronously, then translates the
 * result exactly like ngx_iouring_recv.
 */
ssize_t
ngx_iouring_readv_chain(ngx_connection_t *c, ngx_chain_t *chain,
    off_t limit)
{
    ngx_int_t         rc;
    ngx_iouring_io_t  *io;

    io = ngx_iouring_io_get(c->read);
    if (io == NULL) {
        return NGX_ERROR;
    }

    io->type = NGX_IOURING_IO_READV;
    io->chain = chain;

    rc = ngx_iouring_build_readv(io, chain, limit);

    if (rc == NGX_DECLINED) {
        ngx_iouring_io_reset(io);
        return 0;
    }

    if (rc != NGX_OK) {
        ngx_iouring_io_reset(io);
        return NGX_ERROR;
    }

    if (ngx_iouring_run_io(io) != NGX_OK) {
        ngx_iouring_io_reset(io);
        return NGX_ERROR;
    }

    return ngx_iouring_recv_result(c, io);
}


/*
 * Translate a completed SEND / WRITEV result.  Mirrors
 * ngx_iouring_recv_result but for the write side: updates c->sent,
 * clears wev->ready on partial writes, maps EAGAIN/EINTR/ECANCELED
 * back to NGX_AGAIN so the caller re-parks on the poll.
 */
static ssize_t
ngx_iouring_send_result(ngx_connection_t *c, ngx_iouring_io_t *io)
{
    ssize_t       n;
    size_t        size;
    ngx_err_t     err;
    ngx_event_t  *wev;

    wev = c->write;
    n = io->result;
    size = io->size;

    ngx_iouring_io_reset(io);

    if (n > 0) {

        if ((size_t) n < size) {
            wev->ready = 0;
        }

        c->sent += n;

        return n;
    }

    if (n == 0) {
        ngx_log_error(NGX_LOG_ALERT, c->log, 0,
                      "io_uring send returned zero");
        wev->ready = 0;
        return 0;
    }

    err = (ngx_err_t) -n;

    wev->ready = 0;

    if (err == NGX_EAGAIN || err == NGX_EINTR || err == NGX_ECANCELED) {
        return NGX_AGAIN;
    }

    wev->error = 1;
    return ngx_connection_error(c, err, "io_uring send/writev failed");
}


/*
 * io_uring replacement for ngx_unix_send on TCP sockets.  The SEND op
 * carries MSG_DONTWAIT and is reaped synchronously, so the caller's
 * buffer is never read by the kernel after this function returns.
 */
ssize_t
ngx_iouring_send(ngx_connection_t *c, u_char *buf, size_t size)
{
    ngx_iouring_io_t  *io;

    if (size == 0) {
        return 0;
    }

    io = ngx_iouring_io_get(c->write);
    if (io == NULL) {
        return NGX_ERROR;
    }

    io->type = NGX_IOURING_IO_SEND;
    io->buf = buf;
    io->size = size;

    if (ngx_iouring_run_io(io) != NGX_OK) {
        ngx_iouring_io_reset(io);
        return NGX_ERROR;
    }

    return ngx_iouring_send_result(c, io);
}


/*
 * Convert an output chain into io->iovs[] via ngx_output_chain_to_iovec.
 * Phase 2 deliberately rejects file buffers — sendfile / file AIO are
 * out of scope and will be converted in Phase 3.  If a file buf reaches
 * this point it means the caller bypassed the sendfile path, which is
 * a configuration / code-path bug worth an ALERT.
 */
static ngx_int_t
ngx_iouring_build_writev(ngx_iouring_io_t *io, ngx_chain_t *in,
    size_t limit)
{
    ngx_chain_t   *cl;
    ngx_iovec_t    vec;

    if (ngx_iouring_io_alloc_iovs(io) != NGX_OK) {
        return NGX_ERROR;
    }

    vec.iovs = io->iovs;
    vec.nalloc = NGX_IOVS_PREALLOCATE;

    cl = ngx_output_chain_to_iovec(&vec, in, limit, io->c->log);

    if (cl == NGX_CHAIN_ERROR) {
        return NGX_ERROR;
    }

    if (cl && cl->buf->in_file) {
        ngx_log_error(NGX_LOG_ALERT, io->c->log, 0,
                      "file buf reached io_uring writev");
        return NGX_ERROR;
    }

    if (vec.size == 0) {
        return NGX_DECLINED;
    }

    io->iovcnt = vec.count;
    io->size = vec.size;

    return NGX_OK;
}


/*
 * io_uring replacement for ngx_writev_chain / ngx_linux_sendfile_chain
 * on TCP sockets.  Returns the remaining unsent chain head (or NULL when
 * everything was flushed), matching nginx's send_chain contract.
 *
 * The loop mirrors ngx_writev_chain: build the iovec, issue a WRITEV,
 * reap it synchronously, advance the chain by the bytes actually sent,
 * and stop as soon as the socket is no longer writable (partial write /
 * EAGAIN) or the whole chain / limit has been flushed.
 */
ngx_chain_t *
ngx_iouring_writev_chain(ngx_connection_t *c, ngx_chain_t *in, off_t limit)
{
    ssize_t           n, sent;
    off_t             send, prev_send;
    ngx_int_t         rc;
    ngx_err_t         err;
    ngx_event_t      *wev;
    ngx_iouring_io_t *io;

    wev = c->write;

    if (!wev->ready) {
        return in;
    }

    /* the maximum limit size is the maximum size_t value - the page size */

    if (limit == 0 || limit > (off_t) (NGX_MAX_SIZE_T_VALUE - ngx_pagesize)) {
        limit = NGX_MAX_SIZE_T_VALUE - ngx_pagesize;
    }

    io = ngx_iouring_io_get(wev);
    if (io == NULL) {
        return NGX_CHAIN_ERROR;
    }

    send = 0;

    for ( ;; ) {
        prev_send = send;

        io->type = NGX_IOURING_IO_WRITEV;
        io->chain = in;

        rc = ngx_iouring_build_writev(io, in, limit - send);

        if (rc == NGX_DECLINED) {
            ngx_iouring_io_reset(io);
            return in;
        }

        if (rc != NGX_OK) {
            ngx_iouring_io_reset(io);
            return NGX_CHAIN_ERROR;
        }

        send += io->size;

        if (ngx_iouring_run_io(io) != NGX_OK) {
            ngx_iouring_io_reset(io);
            return NGX_CHAIN_ERROR;
        }

        n = io->result;
        ngx_iouring_io_reset(io);

        if (n < 0) {
            err = (ngx_err_t) -n;

            if (err == NGX_EAGAIN || err == NGX_EINTR) {
                sent = 0;

            } else {
                wev->error = 1;
                (void) ngx_connection_error(c, err, "io_uring writev failed");
                return NGX_CHAIN_ERROR;
            }

        } else {
            sent = n;
        }

        c->sent += sent;

        in = ngx_chain_update_sent(in, sent);

        if (send - prev_send != sent) {
            wev->ready = 0;
            return in;
        }

        if (send >= limit || in == NULL) {
            return in;
        }
    }
}
