#define _GNU_SOURCE
#include "binder.h"
#include <core/int.h>
#include <core/log.h>
#include <core/util.h>
#include <core/vector.h>
#include <errno.h>
#include <string.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdbool.h>
#include <inttypes.h>
#include <stdatomic.h>
#include <fcntl.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <linux/android/binder.h>

#define MODULE_NAME "binder"

#define N_DOMAINS 3
struct domain_order;
static void bubble_sort_domain_ptrs(struct domain_order * d_ptrs [N_DOMAINS]);

static const char *domain_to_device_name(enum kmhal_binder_domain);

static void write_generic_ref_cmd(u32 cmd, VECTOR(u8) *cmd_buf_p, u32 handle);
static void write_free_buf_cmd(VECTOR(u8) *write_buf_p, const void *free_buf);

struct transaction_data;
static void reset_transaction_output_data(VECTOR(struct transaction_data) data);
static void set_transaction_input_data(VECTOR(struct transaction_data) data,
                                       bool fail);

#define WR_FAIL_IOCTL ((u32)(1 << 0))
#define WR_FAIL_TRUNC ((u32)(1 << 1))
#define WR_FAIL_INVAL ((u32)(1 << 2))
#define WR_FAIL_DEAD_OBJECT ((u32)(1 << 3))
#define WR_FAIL_ERROR ((u32)(1 << 4))
static u32 do_write_read_ioctl_loop(int fd, struct kmhal_binder_txn *txn);

static int call_write_read_ioctl(int fd, struct binder_write_read *bwr);
static void sanity_check_bwr_or_abort(const struct binder_write_read *bwr,
        bool do_receive);

static void process_advance_current_transaction(
        VECTOR(struct transaction_data) td,
        size_t *td_idx_p,
        struct transaction_data **out_curr_td_p
);

/* Runs while `ctx->ioctl_lock` is locked */
static u32 handle_ioctl_response(const u8 **p, const u8 *end,
        struct transaction_data *td);

static const char *binder_reply_to_string(u32);

enum kmhal_binder_fail_flags {
    FAIL_DEAD_OBJECT        = 1 << 0, /* Binder died */
    FAIL_FREE               = 1 << 1, /* Reply free failed */
    FAIL_INIT               = 1 << 2, /* Init failed */
};

/* A structure that holds the context necessary to talk to the binder driver
 * and perform binder transactions */
struct kmhal_binder_ctx {
    _Atomic bool initialized_; /* Sanity flag to prevent double-frees */

    /* Flags set when the binder device is no longer fit
     * to handle transactions (`enum kmhal_binder_fail_flags`) */
    u32 fail_flags;

    /* The binder driver device file descriptor */
    int fd;

    /* The binder transaction data read buffer
     * (of size `KMHAL_BINDER_READ_BUF_SIZE`).
     * The kernel will write transaction results to this buffer,
     * and we will read from it to interpret them.
     *
     * Note that this is different from the buffer passed in as `read_buffer`
     * in the ioctl - this map is used to hold values of `data.ptr.buffer`s
     * returned by callers, not the protocol messages themselves.
     *
     * If there are  */
    void *td_map;

    /* A lock used to ensure that no two threads call the ioctl
     * on the same fd at the same time */
    pthread_mutex_t ioctl_lock;
};

struct transaction_data {
    enum transaction_type {
        TRANSACTION,
    } type;
    union {
        struct td_transaction_sg {
            struct kmhal_binder_txn_args_out *out_data;
            bool got_reply, got_tr_complete;
        } txn;
    } data;
};
struct kmhal_binder_txn {
    VECTOR(u8) buf;
    VECTOR(struct transaction_data) data;
};

struct domain_order {
    enum kmhal_binder_domain domain;
    u8 order;
};
#define DOMAIN_ORDER(mask_, domain_) (struct domain_order) {        \
    .domain = domain_,                                              \
    .order = (u8)(                                                  \
            ((mask_) & (((u32)(0x0000FF00U << ((domain_) * 8)))))   \
                 >> (((domain_) + 1) * 8)                           \
    ),                                                              \
}

struct kmhal_binder_ctx *
kmhal_binder_open(kmhal_binder_domain_ordered_mask_t domains_to_try)
{
    struct domain_order domains[N_DOMAINS] = {
        DOMAIN_ORDER(domains_to_try, KMHAL_BINDER),
        DOMAIN_ORDER(domains_to_try, KMHAL_HWBINDER),
        DOMAIN_ORDER(domains_to_try, KMHAL_VNDBINDER),
    };

    struct domain_order * domain_ptrs[N_DOMAINS] =
        { &domains[0], &domains[1], &domains[2] };
    bubble_sort_domain_ptrs(domain_ptrs);

    const u8 domain_mask_byte = (u8)(domains_to_try & 0x000000FFU);
    for (int i = 0; i < N_DOMAINS; i++) {
        if (!(domain_mask_byte & (1 << domain_ptrs[i]->domain)))
            continue;

        const char *dev_path = domain_to_device_name(domain_ptrs[i]->domain);
        struct kmhal_binder_ctx *const ret =
            kmhal_binder_open_dev(dev_path);

        if (ret == NULL) {
            s_log_warn("Failed to open binder device \"%s\"", dev_path);
        } else {
            return ret;
        }
    }

    s_log_error("Couldn't open any requested binder devices");
    return NULL;
}

#undef DOMAIN_ORDER

struct kmhal_binder_ctx * kmhal_binder_open_dev(const char *dev_path)
{
    if (dev_path == NULL) {
        s_log_error("Invalid parameters!");
        return NULL;
    }

    struct kmhal_binder_ctx *ret = NULL;

    ret = malloc(sizeof(struct kmhal_binder_ctx));
    if (ret == NULL)
        goto_error("Failed to allocate a new binder context");
    atomic_store(&ret->initialized_, false);
    ret->fd = -1;
    ret->td_map = MAP_FAILED;
    ret->fail_flags = FAIL_INIT;
    ret->ioctl_lock = (pthread_mutex_t){ 0 };
    atomic_store(&ret->initialized_, true);

    /* always successful */
    (void) pthread_mutex_init(&ret->ioctl_lock, NULL);

    /* Open driver device */
    ret->fd = open(dev_path, O_RDWR | O_CLOEXEC);
    if (ret->fd == -1)
        goto_error("Failed to open binder device \"%s\": %d (%s)",
                dev_path, errno, strerror(errno));

    /* Check binder protocol version */
    {
        struct binder_version ver = { 0 };
        int r_;
        do {
            r_ = ioctl(ret->fd, BINDER_VERSION, &ver);
        } while (r_ == -1 && errno == EINTR);

        if (r_ == -1)
            goto_error("Failed to get the binder protocol version");
        else if (ver.protocol_version != BINDER_CURRENT_PROTOCOL_VERSION)
            goto_error("Kernel binder protocol version (%"PRIi32") "
                    "doesn't match the current userspace version (%"PRIi32")",
                    ver.protocol_version, BINDER_CURRENT_PROTOCOL_VERSION);
        else
            s_log_debug("Binder protocol version: %"PRIi32,
                    ver.protocol_version);
    }

    /* Map the transaction data read buffer */
    ret->td_map = mmap(NULL, KMHAL_BINDER_TD_READ_BUF_SIZE,
            PROT_READ, MAP_PRIVATE | MAP_NORESERVE, ret->fd, 0);
    if (ret->td_map == MAP_FAILED)
        goto_error("Failed to map the binder transaction data "
                "read buffer: %d (%s)", errno, strerror(errno));

    ret->fail_flags = 0;
    s_log_info("Successfully opened binder device \"%s\"", dev_path);
    return ret;

err:
    if (ret != NULL)
        kmhal_binder_close(&ret);

    return NULL;
}

struct kmhal_binder_txn * kmhal_binder_txn_new(void)
{
    struct kmhal_binder_txn *ret = NULL;

    ret = malloc(sizeof(struct kmhal_binder_txn));
    if (ret == NULL) {
        s_log_error("Failed to allocate a new binder transaction context");
        return NULL;
    }

    ret->buf = vector_new(u8);

    ret->data = vector_new(struct transaction_data);

    return ret;
}

bool kmhal_binder_ctx_ok(const struct kmhal_binder_ctx *ctx)
{
    return ctx != NULL &&
        atomic_load(&ctx->initialized_) &&
        ctx->fail_flags == 0;
}

void kmhal_binder_write_acquire(struct kmhal_binder_txn *txn,
                                u32 handle)
{
    u_check_params(txn != NULL && txn->buf != NULL);
    write_generic_ref_cmd(BC_ACQUIRE, &txn->buf, handle);
}

void kmhal_binder_write_increfs(struct kmhal_binder_txn *txn,
                                u32 handle)
{
    u_check_params(txn != NULL && txn->buf != NULL);
    write_generic_ref_cmd(BC_INCREFS, &txn->buf, handle);
}

void kmhal_binder_write_release(struct kmhal_binder_txn *txn,
                                u32 handle)
{
    u_check_params(txn != NULL && txn->buf != NULL);
    write_generic_ref_cmd(BC_RELEASE, &txn->buf, handle);
}

void kmhal_binder_write_decrefs(struct kmhal_binder_txn *txn,
                                u32 handle)
{
    u_check_params(txn != NULL && txn->buf != NULL);
    write_generic_ref_cmd(BC_DECREFS, &txn->buf, handle);
}

void kmhal_binder_write_transact(struct kmhal_binder_txn_args *arg)
{
    u_check_params(arg != NULL && arg->in_txn != NULL);

    const size_t off = vector_size(arg->in_txn->buf);

    const struct kmhal_binder_txn_args_in *const i = &arg->in_data;

    const u32 cmd = BC_TRANSACTION;
    const struct binder_transaction_data td = {
        .target.handle = i->handle,
        .cookie = 0,
        .code = i->cmd,
        .flags = i->flags,
        .sender_euid = 0, .sender_pid = 0,

        .data_size = i->data_size,
        .offsets_size = i->offsets_count * sizeof(binder_size_t),
        .data.ptr.buffer = (binder_uintptr_t)i->data_buf,
        .data.ptr.offsets = (binder_uintptr_t)i->offsets_buf
    };

    vector_resize(&arg->in_txn->buf, off + sizeof(cmd) + sizeof(td));
    memcpy(arg->in_txn->buf + off, &cmd, sizeof(cmd));
    memcpy(arg->in_txn->buf + off + sizeof(cmd), &td, sizeof(td));

    vector_push_back(&arg->in_txn->data, (struct transaction_data) {
            .type = TRANSACTION,
            .data.txn = { .out_data = &arg->out_reply }
    });

    memset(&arg->out_reply, 0, sizeof(arg->out_reply));
    arg->out_reply.status = KMHAL_BINDER_TXN_PENDING;
}

void kmhal_binder_write_transact_sg(struct kmhal_binder_txn_args *arg)
{
    u_check_params(arg != NULL && arg->in_txn != NULL);

    const struct kmhal_binder_txn_args_in *const i = &arg->in_data;

    const struct binder_transaction_data_sg td_sg = {
        .transaction_data = {
            .target.handle = i->handle,
            .cookie = 0,
            .code = i->cmd,
            .flags = i->flags,
            .sender_euid = 0, .sender_pid = 0,

            .data_size = i->data_size,
            .offsets_size = i->offsets_count * sizeof(binder_size_t),
            .data.ptr.buffer = (binder_uintptr_t)i->data_buf,
            .data.ptr.offsets = (binder_uintptr_t)i->offsets_buf
        },
        .buffers_size = arg->in_data.sg_buffers_size
    };

    const u32 cmd = BC_TRANSACTION_SG;

    const size_t off = vector_size(arg->in_txn->buf);
    vector_resize(&arg->in_txn->buf, off + sizeof(cmd) + sizeof(td_sg));

    memcpy(arg->in_txn->buf + off, &cmd, sizeof(cmd));
    memcpy(arg->in_txn->buf + off + sizeof(cmd), &td_sg, sizeof(td_sg));

    vector_push_back(&arg->in_txn->data, (struct transaction_data) {
            .type = TRANSACTION,
            .data.txn = { .out_data = &arg->out_reply }
    });

    memset(&arg->out_reply, 0, sizeof(arg->out_reply));
    arg->out_reply.status = KMHAL_BINDER_TXN_PENDING;
}

void kmhal_binder_write_free_reply(struct kmhal_binder_txn *txn,
                                   const void *reply)
{
    u_check_params(txn != NULL && txn->buf != NULL);
    write_free_buf_cmd(&txn->buf, reply);
}

int kmhal_binder_do_write_read_ioctl(struct kmhal_binder_ctx *ctx,
                                     struct kmhal_binder_txn **txn_p)
{
    if (!kmhal_binder_ctx_ok(ctx) || txn_p == NULL || *txn_p == NULL ||
            (*txn_p)->buf == NULL)
    {
        s_log_error("Invalid parameters!");
        return -1;
    }
    int r_;
    u32 status = 0;
    struct kmhal_binder_txn *txn = *txn_p;

    *txn_p = NULL; /* Prevent any possible use early, just in case */

    reset_transaction_output_data(txn->data);

    if ((r_ = pthread_mutex_lock(&ctx->ioctl_lock)))
        s_log_fatal("pthread_mutex_lock failed: %d (%s)", r_, strerror(r_));
    {
        status = do_write_read_ioctl_loop(ctx->fd, txn);
    }
    if ((r_ = pthread_mutex_unlock(&ctx->ioctl_lock)))
        s_log_fatal("pthread_mutex_unlock failed: %d (%s)", r_, strerror(r_));

    set_transaction_input_data(txn->data, status != 0);

    /* `*txn_p` already set to NULL earlier */
    kmhal_binder_txn_destroy(&txn);

    if (status) {
        s_log_error("Binder transaction failed: "
                "ioctl failed: %d, truncated data: %d, "
                "parsing error: %d, object died: %d, got error: %d",
                !!(status & WR_FAIL_IOCTL),
                !!(status & WR_FAIL_TRUNC),
                !!(status & WR_FAIL_INVAL),
                !!(status & WR_FAIL_DEAD_OBJECT),
                !!(status & WR_FAIL_ERROR));
    }

    return status == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

void kmhal_binder_txn_destroy(struct kmhal_binder_txn **txn_p)
{
    if (txn_p == NULL || *txn_p == NULL)
        return;

    vector_destroy(&(*txn_p)->data);
    vector_destroy(&(*txn_p)->buf);

    free(*txn_p);
    *txn_p = NULL;
}

void kmhal_binder_close(struct kmhal_binder_ctx **ctx_p)
{
    if (ctx_p == NULL || *ctx_p == NULL ||
            !atomic_exchange(&(*ctx_p)->initialized_, false))
        return;

    struct kmhal_binder_ctx *const ctx = *ctx_p;

    if (ctx->td_map != MAP_FAILED) {
        if (munmap(ctx->td_map, KMHAL_BINDER_TD_READ_BUF_SIZE))
            s_log_error("Failed to unmap the binder transaction data "
                    "read buffer: %d (%s)", errno, strerror(errno));
        ctx->td_map = MAP_FAILED;
    }

    if (ctx->fd != -1) {
        if (close(ctx->fd)) {
            s_log_error("Failed to close the binder fd: %d (%s)",
                    errno, strerror(errno));
        }
        ctx->fd = -1;
    }

    /* Print out the fail flags if something more that `FAIL_INIT` is set */
    if (ctx->fail_flags && ctx->fail_flags != FAIL_INIT) {
        s_log_info("Binder ctx->fail_flags: DEAD: %d, FREE: %d, INIT: %d",
                ((ctx->fail_flags & FAIL_DEAD_OBJECT) != 0),
                ((ctx->fail_flags & FAIL_FREE) != 0),
                ((ctx->fail_flags & FAIL_INIT) != 0)
        );
    }
    ctx->fail_flags = FAIL_INIT;

    int r;
    if ((r = pthread_mutex_destroy(&ctx->ioctl_lock))) {
        /* Most likely use-after-free */
        s_log_fatal("Failed to destroy write_read mutex: %d (%s)!",
                r, strerror(r));
    }

    free(ctx);
    *ctx_p = NULL;
}

static void bubble_sort_domain_ptrs(struct domain_order * d_ptrs[N_DOMAINS])
{
    for (int i = 0; i < N_DOMAINS - 1; ++i) {
        for (int j = 0; j < N_DOMAINS - i - 1; ++j) {

            const enum kmhal_binder_domain
                domain_i = d_ptrs[i]->domain,
                domain_j_1 = d_ptrs[j + 1]->domain;
            const u8
                order_i = d_ptrs[i]->order,
                order_j_1 = d_ptrs[j + 1]->order;

            if (order_i > order_j_1 ||
                (order_i == order_j_1 && domain_i > domain_j_1))
            {
                void *const tmp = d_ptrs[i];
                d_ptrs[i] = d_ptrs[j + 1];
                d_ptrs[j + 1] = tmp;
            }
        }
    }
}

static const char *domain_to_device_name(enum kmhal_binder_domain d)
{
    switch (d) {
    case KMHAL_BINDER: return "/dev/binder";
    case KMHAL_HWBINDER: return "/dev/hwbinder";
    case KMHAL_VNDBINDER: return "/dev/vndbinder";
    default: return NULL;
    }
}

static void write_generic_ref_cmd(u32 cmd, VECTOR(u8) *cmd_buf_p, u32 handle)
{
    uint32_t cmd_ = cmd;
    uint32_t handle_ = handle;

    const size_t off = vector_size(*cmd_buf_p);
    vector_resize(cmd_buf_p, off + 8);

    memcpy(*cmd_buf_p + off, &cmd_, 4);
    memcpy(*cmd_buf_p + off + 4, &handle_, 4);
}

static void write_free_buf_cmd(VECTOR(u8) *write_buf_p, const void *free_buf)
{
    u32 cmd = BC_FREE_BUFFER;
    binder_uintptr_t ptr = (binder_uintptr_t)free_buf;

    const size_t off = vector_size(*write_buf_p);

    vector_resize(write_buf_p, off + sizeof(cmd) + sizeof(ptr));
    memcpy((*write_buf_p) + off, &cmd, sizeof(cmd));
    memcpy((*write_buf_p) + off + sizeof(cmd), &ptr, sizeof(ptr));
}

static void reset_transaction_output_data(VECTOR(struct transaction_data) data)
{
    for (u32 i = 0; i < vector_size(data); i++) {
        struct transaction_data *const curr = &data[i];

        switch (curr->type) {
        case TRANSACTION:
            if (curr->data.txn.out_data == NULL)
                s_log_fatal("Missing out_data pointer");

            memset(curr->data.txn.out_data, 0,
                    sizeof(struct kmhal_binder_txn_args_out));
            curr->data.txn.out_data->status = KMHAL_BINDER_TXN_UNINITIALIZED;

            curr->data.txn.got_reply = false;
            curr->data.txn.got_tr_complete = false;
            break;
        default:
            s_log_fatal("Invalid transaction data type: %d", curr->type);
        }
    }
}

static void set_transaction_input_data(VECTOR(struct transaction_data) data,
                                       bool fail)
{
    for (u32 i = 0; i < vector_size(data); i++) {
        struct transaction_data *const curr = &data[i];

        switch (curr->type) {
        case TRANSACTION:
            if (curr->data.txn.out_data == NULL)
                s_log_fatal("Missing out_data pointer");

            if (!fail &&
                    curr->data.txn.got_reply &&
                    curr->data.txn.got_tr_complete)
            {
                curr->data.txn.out_data->status = KMHAL_BINDER_TXN_OK;
            } else {
                memset(curr->data.txn.out_data, 0,
                        sizeof(struct kmhal_binder_txn_args_out));
                curr->data.txn.out_data->status =
                    KMHAL_BINDER_TXN_FAILED;
            }

            curr->data.txn.got_reply = false;
            curr->data.txn.got_tr_complete = false;
            break;
        default:
            s_log_fatal("Invalid transaction data type: %d", curr->type);
        }
    }
}

static u32 do_write_read_ioctl_loop(int fd, struct kmhal_binder_txn *txn)
{
    u8 proto_read_buf[KMHAL_BINDER_PROTO_READ_BUF_SIZE] = { 0 };
    u32 ret = 0;

    const bool do_receive = vector_size(txn->data) > 0;
    struct binder_write_read bwr = {
        .write_buffer = (binder_uintptr_t)txn->buf,
        .write_size = vector_size(txn->buf),
        .read_buffer = do_receive ? (binder_uintptr_t)proto_read_buf : 0,
        .read_size = do_receive ? KMHAL_BINDER_PROTO_READ_BUF_SIZE : 0,
    };

    bool all_cmds_processed = false;
    while (!all_cmds_processed && ret == 0) {
        /* transact ioctl */
        bwr.read_consumed = bwr.write_consumed = 0;
        if (call_write_read_ioctl(fd, &bwr)) {
            ret |= WR_FAIL_IOCTL;
            break;
        }
        sanity_check_bwr_or_abort(&bwr, do_receive);

        /* We only give the kernel data on the first iteration,
         * any later ones are just waiting for output */
        bwr.write_size = 0;

        if (do_receive && bwr.read_consumed == 0) {
            s_log_warn("No data written by kernel to the read buffer");
            continue;
        }
        /* Everything below is only relevant
         * if we're waiting for some data to be returned */
        if (!do_receive)
            break;

        /* Read the output buffer & handle the reply */
        const u8 *p = (u8 *)bwr.read_buffer;
        const u8 *const end = (u8 *)bwr.read_buffer + bwr.read_consumed;
        if ((size_t)(end - p) < sizeof(u32))
            s_log_fatal("Too few data written by kernel to read buffer!");

        size_t curr_txn_idx = 0;
        struct transaction_data *curr_txn = NULL;
        process_advance_current_transaction(txn->data,
                &curr_txn_idx, &curr_txn);
        do {
            ret |= handle_ioctl_response(&p, end, curr_txn);

            process_advance_current_transaction(txn->data,
                    &curr_txn_idx, &curr_txn);
            if (curr_txn == NULL)
                all_cmds_processed = true;
        } while (p < end && ret == 0);
    }

    return ret;
}

static int call_write_read_ioctl(int fd, struct binder_write_read *bwr)
{
    int r;
    do {
        r = ioctl(fd, BINDER_WRITE_READ, bwr);
    } while (r == -1 && errno == EINTR);
    if (r == -1) {
        s_log_error("Binder transact (WRITE_READ) "
                "ioctl failed: %d (%s)", errno, strerror(errno));
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

static void sanity_check_bwr_or_abort(const struct binder_write_read *bwr,
        bool do_receive)
{
    if (bwr->write_size > 0 && bwr->write_size != bwr->write_consumed)
        s_log_fatal("The kernel didn't consume the "
                "write buffer properly");
    else if (bwr->read_consumed > KMHAL_BINDER_PROTO_READ_BUF_SIZE)
        s_log_fatal("The kernel wrote too much data into our "
                "read buffer");
    else if (!do_receive && bwr->read_consumed > 0)
        s_log_fatal("The kernel wrote data to our read buffer when "
                "it wasn't supposed to do so");
}

static void process_advance_current_transaction(
        VECTOR(struct transaction_data) td,
        size_t *td_idx_p,
        struct transaction_data **out_curr_td_p
)
{
    if (*td_idx_p == (size_t)-1) { /* we're already done */
        *out_curr_td_p = NULL;
        return;
    }

    /* `vector_at` does automatic bounds checking */
    struct transaction_data curr_td = vector_at(td, *td_idx_p);

    const struct td_transaction_sg *const td_sg = &curr_td.data.txn;

    bool advance = false;
    switch (curr_td.type) {
    case TRANSACTION:
        if (td_sg->got_tr_complete && td_sg->got_reply)
            advance = true;
        break;
    default:
        s_log_fatal("Invalid transaction data type: %d", curr_td.type);
    }

    if (advance) {
        if (++(*td_idx_p) >= vector_size(td)) {
#if 0
            s_log_debug("No more transactions to track");
#endif /* 0 */
            *td_idx_p = (size_t)-1;
            *out_curr_td_p = NULL;
            return;
        }

#if 0
        s_log_debug("Tracking new transaction: %zu", *td_idx_p);
#endif /* 0 */
    }

    *out_curr_td_p = &td[*td_idx_p];
}

/* Runs while `ctx->read_write.lock` is locked */
static u32 handle_ioctl_response(const u8 **p, const u8 *end,
                                 struct transaction_data *td)
{
    u32 ret = 0;

#define try_read_advance(var) do {              \
    if ((size_t)(end - *p) < sizeof(var)) {     \
        ret |= WR_FAIL_TRUNC;                   \
        return ret;                             \
    }                                           \
    memcpy(&(var), *p, sizeof((var)));          \
    *p += sizeof((var));                        \
} while (0)

    u32 reply_cmd = 0;
    try_read_advance(reply_cmd);

    switch ((enum binder_driver_return_protocol)reply_cmd) {
    case BR_ERROR: {
        i32 err;
        try_read_advance(err);
        s_log_error("Error received: %"PRIi32" (%s)", err, strerror(err));
        ret |= WR_FAIL_ERROR;
        break;
    }
    case BR_OK:
    case BR_NOOP:
        break;
    case BR_REPLY: {
        if (td == NULL || td->type != TRANSACTION) {
            s_log_error("Received unexpected BR_REPLY");
            ret |= WR_FAIL_INVAL;
            break;
        } else if (!td->data.txn.out_data) {
            s_log_error("No reply pointer in transaction context");
            ret |= WR_FAIL_INVAL;
            break;
        }

        struct binder_transaction_data binder_td;
        try_read_advance(binder_td);

        struct kmhal_binder_txn_args_out *const o = td->data.txn.out_data;
        o->data_buf = (void *)binder_td.data.ptr.buffer;
        o->data_size = binder_td.data_size;
        o->offsets_buf = (void *)binder_td.data.ptr.offsets;
        o->offsets_count = binder_td.offsets_size / sizeof(binder_size_t);

        o->flags = binder_td.flags;

        /* reset later in `set_transaction_input_data` if needed */
        o->status = KMHAL_BINDER_TXN_OK;

        td->data.txn.got_reply = true;
#if 0
        s_log_debug("Received reply");
#endif /* 0 */
        break;
    }
    case BR_TRANSACTION_COMPLETE: {
        if (td == NULL) {
            s_log_error("Received unexpected BR_TRANSACTION_COMPLETE");
            ret |= WR_FAIL_INVAL;
            break;
        }

        td->data.txn.got_tr_complete = true;
#if 0
        s_log_debug("Received transaction_complete");
#endif /* 0 */
        break;
    }
    case BR_FAILED_REPLY:
        s_log_error("Binder transaction failed in kernel driver");
        ret |= WR_FAIL_ERROR | WR_FAIL_DEAD_OBJECT;
        break;
    case BR_DEAD_REPLY:
    case BR_DEAD_BINDER:
        s_log_error("Binder object died or error in kernel driver");
        ret |= WR_FAIL_ERROR | WR_FAIL_DEAD_OBJECT;
        break;
    case BR_ONEWAY_SPAM_SUSPECT:
        s_log_info("BR_ONEWAY_SPAM_SUSPECT message received");
        break;
    default:
        ret |= WR_FAIL_INVAL;
        s_log_error("Unexpected binder reply received: %"PRIu32" (%s)",
                reply_cmd, binder_reply_to_string(reply_cmd));
    }
#undef try_read_advance

    return ret;
}

static const char *binder_reply_to_string(u32 cmd)
{
    switch (cmd) {
    case BR_ERROR: return "BR_ERROR";
    case BR_OK: return "BR_OK";
    case BR_TRANSACTION_SEC_CTX: return "BR_TRANSACTION_SEC_CTX";
    case BR_TRANSACTION: return "BR_TRANSACTION";
    case BR_REPLY: return "BR_REPLY";
    case BR_ACQUIRE_RESULT: return "BR_ACQUIRE_RESULT";
    case BR_DEAD_REPLY: return "BR_DEAD_REPLY";
    case BR_TRANSACTION_COMPLETE: return "BR_TRANSACTION_COMPLETE";
    case BR_INCREFS: return "BR_INCREFS";
    case BR_ACQUIRE: return "BR_ACQUIRE";
    case BR_RELEASE: return "BR_RELEASE";
    case BR_DECREFS: return "BR_DECREFS";
    case BR_ATTEMPT_ACQUIRE: return "BR_ATTEMPT_ACQUIRE";
    case BR_NOOP: return "BR_NOOP";
    case BR_SPAWN_LOOPER: return "BR_SPAWN_LOOPER";
    case BR_FINISHED: return "BR_FINISHED";
    case BR_DEAD_BINDER: return "BR_DEAD_BINDER";
    case BR_CLEAR_DEATH_NOTIFICATION_DONE:
        return "BR_CLEAR_DEATH_NOTIFICATION_DONE";
    case BR_FAILED_REPLY: return "BR_FAILED_REPLY";
    case BR_FROZEN_REPLY: return "BR_FROZEN_REPLY";
    case BR_ONEWAY_SPAM_SUSPECT: return "BR_ONEWAY_SPAM_SUSPECT";
    case BR_TRANSACTION_PENDING_FROZEN:
        return "BR_TRANSACTION_PENDING_FROZEN";
        /*
    case BR_FROZEN_BINDER: return "BR_FROZEN_BINDER";
    */
                           /*
    case BR_CLEAR_FREEZE_NOTIFICATION_DONE:
        return "BR_CLEAR_FREEZE_NOTIFICATION_DONE";
        */
    default:
        return "(unknown)";
    }
}
