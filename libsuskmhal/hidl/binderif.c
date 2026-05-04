#define _GNU_SOURCE
#include "binderif.h"
#include <core/int.h>
#include <core/log.h>
#include <core/util.h>
#include <errno.h>
#include <string.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <linux/android/binder.h>

#define MODULE_NAME "hidl-binder-if"

#define N_DOMAINS 3
struct domain_order;
static void bubble_sort_domain_ptrs(struct domain_order * d_ptrs [N_DOMAINS]);

static const char *domain_to_device_name(enum kmhal_hidl_binder_domain);

static const char *binder_reply_to_string(u32);

/* A structure that holds the context necessary to talk to the binder driver
 * and perform binder transactions */
struct kmhal_hidl_binder_ctx {
    _Atomic bool initialized_; /* Sanity flag to prevent double-frees */

    enum {
        FAIL_DEAD_OBJECT        = 1 << 0, /* Binder died */
        FAIL_FREE               = 1 << 1, /* Reply free failed */
        FAIL_INIT               = 1 << 2, /* Init failed */
    };
    /* Flags set when the binder device is no longer fit
     * to handle transactions */
    u32 fail_flags;

    /* The binder driver device file descriptor */
    int fd;

    /* The binder transaction read buffer
     * (of size `KMHAL_HIDL_BINDER_READ_BUF_SIZE`).
     * The kernel will write transaction results to this buffer,
     * and we will read from it to interpret them. */
    void *map;

    /* A flag indicating the the ENTER_LOOPER ioctl has been successfully
     * called. Used to determine whether to call EXIT_LOOPER during cleanup. */
    bool looper_entered;
};

struct domain_order {
    enum kmhal_hidl_binder_domain domain;
    u8 order;
};
#define DOMAIN_ORDER(mask_, domain_) (struct domain_order) {        \
    .domain = domain_,                                              \
    .order = (u8)(                                                  \
            ((mask_) & (((u32)(0x0000FF00U << ((domain_) * 8))))    \
                 >> ((domain_) * 8))                                \
    ),                                                              \
}

struct kmhal_hidl_binder_ctx * kmhal_hidl_binder_open(
        kmhal_hidl_binder_domain_ordered_mask_t domains_to_try)
{
    struct domain_order domains[N_DOMAINS] = {
        DOMAIN_ORDER(domains_to_try, KMHAL_HIDL_BINDER),
        DOMAIN_ORDER(domains_to_try, KMHAL_HIDL_HWBINDER),
        DOMAIN_ORDER(domains_to_try, KMHAL_HIDL_VNDBINDER),
    };

    struct domain_order * domain_ptrs[N_DOMAINS] =
        { &domains[0], &domains[1], &domains[2] };
    bubble_sort_domain_ptrs(domain_ptrs);

    const u8 domain_mask_byte = (u8)(domains_to_try & 0x000000FFU);
    for (int i = 0; i < N_DOMAINS; i++) {
        if (!(domain_mask_byte & (1 << domains[i].domain)))
            continue;

        const char *dev_path = domain_to_device_name(domains[i].domain);
        struct kmhal_hidl_binder_ctx *const ret =
            kmhal_hidl_binder_open_dev(dev_path);

        if (ret == NULL) {
            s_log_warn("Failed to open HIDL binder device \"%s\"", dev_path);
        } else {
            return ret;
        }
    }

    s_log_error("Couldn't open any requested HIDL binder devices");
    return NULL;
}

#undef DOMAIN_ORDER

struct kmhal_hidl_binder_ctx * kmhal_hidl_binder_open_dev(const char *dev_path)
{
    if (dev_path == NULL) {
        s_log_error("Invalid parameters!");
        return NULL;
    }

    struct kmhal_hidl_binder_ctx *ret = NULL;

    ret = malloc(sizeof(struct kmhal_hidl_binder_ctx));
    if (ret == NULL)
        goto_error("Failed to allocate a new HIDL binder context");
    atomic_store(&ret->initialized_, false);
    ret->fd = -1;
    ret->map = MAP_FAILED;
    ret->looper_entered = false;
    ret->fail_flags = FAIL_INIT;

    atomic_store(&ret->initialized_, true);

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
            goto_error("Kernel binder protocol version (%ld) "
                    "doesn't match the current userspace version (%ld)",
                    (long int)ver.protocol_version,
                    (long int)BINDER_CURRENT_PROTOCOL_VERSION);
        else
            s_log_debug("Binder protocol version: %ld",
                    (long int)ver.protocol_version);
    }

    /* Map the read buffer
     * (the buffer to which transaction results are written by the kernel) */
    ret->map = mmap(NULL, KMHAL_HIDL_BINDER_READ_BUF_SIZE,
            PROT_READ, MAP_PRIVATE, ret->fd, 0);
    if (ret->map == MAP_FAILED)
        goto_error("Failed to map the binder read buffer: %d (%s)",
                errno, strerror(errno));

    /* Register the thread as a binder "looper";
     * make the kernel aware that it can receive transactions */
    {
        uint32_t cmd = BC_ENTER_LOOPER;
        int r_;
        do {
            r_ = ioctl(ret->fd, BINDER_WRITE_READ, &(struct binder_write_read) {
                    .write_size = sizeof(cmd),
                    .write_buffer = (uintptr_t)&cmd
            });
        } while (r_ == -1 && errno == EINTR);
        if (r_ == -1)
            goto_error("Binder ENTER_LOOPER ioctl failed: %d (%s)",
                    errno, strerror(errno));
    }
    ret->looper_entered = true;

    /* We don't really need this, but since it exists, why not? */
    {
        uint32_t enable = 1;
        int r_;
        do {
            r_ = ioctl(ret->fd, BINDER_ENABLE_ONEWAY_SPAM_DETECTION, &enable);
        } while (r_ == -1 && errno == EINTR);
        if (r_ == -1)
            s_log_warn("Failed to enable binder one-way spam detection: "
                    "%d (%s)", errno, strerror(errno));
    }

    ret->fail_flags = 0;
    return ret;

err:
    if (ret != NULL)
        kmhal_hidl_binder_close(&ret);

    return NULL;
}

bool kmhal_hidl_binder_ctx_ok(const struct kmhal_hidl_binder_ctx *ctx)
{
    return ctx != NULL &&
        atomic_load(&ctx->initialized_) &&
        ctx->fail_flags == 0;
}

int kmhal_hidl_binder_transact(struct kmhal_hidl_binder_ctx *ctx,
        uint32_t handle, uint32_t cmd_code, uint32_t flags,
        const void *data, size_t data_size,
        const binder_size_t *offsets, size_t offsets_count,
        const void **out_reply, size_t *out_reply_size)
{
    if (!kmhal_hidl_binder_ctx_ok(ctx) ||
            ((out_reply != NULL || out_reply_size != NULL) &&
            !(out_reply != NULL && out_reply_size != NULL))
    ) {
        s_log_error("Invalid parameters!");
        return -1;
    }

    struct transaction_buf {
        u32 cmd;
        struct binder_transaction_data td;
    } __attribute__((packed)) write_buf = {
        .cmd = BC_TRANSACTION,
        .td = {
            .target.handle = handle,
            .code = cmd_code,
            .flags = flags,

            .data_size = data_size,
            .offsets_size = offsets_count * sizeof(binder_size_t),
            .data.ptr.buffer = (uintptr_t)data,
            .data.ptr.offsets = (uintptr_t)offsets,
        }
    };
    _Static_assert(offsetof(struct transaction_buf, td) == sizeof(u32),
            "Invalid offset of the transaction data");

    struct binder_write_read bwr = {
        .write_buffer = (uintptr_t)&write_buf,
        .write_size = sizeof(write_buf),

        .read_buffer = (uintptr_t)ctx->map,
        .read_size = KMHAL_HIDL_BINDER_READ_BUF_SIZE,
    };

    bool trunc = false, fail = false, got_reply = false;
    while (1) {
        /* transact ioctl */
        bwr.read_consumed = bwr.write_consumed = 0;
        int r_;
        do {
            r_ = ioctl(ctx->fd, BINDER_WRITE_READ, &bwr);
        } while (r_ == -1 && errno == EINTR);
        if (r_ == -1) {
            s_log_error("Binder transact (WRITE_READ) ioctl failed: %d (%s)",
                    errno, strerror(errno));
            return EXIT_FAILURE;
        }
        /* From AOSP:
         *  We don't want to write anything if we are still reading
         *  from data left in the input buffer (...)
         * which we will be on the next iteration of this loop,
         * if it ever happens
         */
        const binder_size_t orig_write_size = bwr.write_size;
        bwr.write_size = 0;

        if (bwr.read_consumed == 0)
            continue;

        /* sanity checks */
        if (orig_write_size > 0 && bwr.write_consumed != sizeof(write_buf))
            s_log_fatal("The kernel didn't consume the write buffer properly");
        else if (bwr.read_consumed > KMHAL_HIDL_BINDER_READ_BUF_SIZE)
            s_log_fatal("The kernel wrote too much data into our read buffer");

        /* Read the output buffer to determine the reply type */
        const u8 *start = (u8 *)bwr.read_buffer;
        const u8 *const end = (u8 *)bwr.read_buffer + bwr.read_consumed;
        if (end - start < sizeof(u32))
            s_log_fatal("Too few data written by kernel to read buffer!");

#define try_read_advance(var) do {                      \
            if (end - start < sizeof(var)) {        \
                trunc = true;                       \
                goto loop_out;                      \
            }                                       \
            memcpy(&(var), start, sizeof((var)));   \
            start += sizeof((var));                 \
        } while (0)

        /* Handle the reply */
        while (start < end) {
            u32 reply_cmd = 0;
            try_read_advance(reply_cmd);

            switch ((enum binder_driver_return_protocol)reply_cmd) {
            case BR_ERROR: {
                i32 error = 0;
                try_read_advance(error);

                if (error != 0) {
                    s_log_error("BR Error: %lu", (long unsigned)error);
                    fail = true;
                    goto loop_out;
                }

                continue;
            }
            case BR_OK:
            case BR_NOOP:
            case BR_TRANSACTION_COMPLETE:
                continue;

            case BR_REPLY: {
                if (got_reply) {
                    s_log_error("Multiple replies in one transaction");
                    fail = true;
                    goto loop_out;
                }

                struct binder_transaction_data reply = { 0 };
                try_read_advance(reply);

                if (out_reply_size != NULL)
                    *out_reply_size = reply.data_size;

                if (out_reply != NULL) {
                    *out_reply = (void *)reply.data.ptr.buffer;
                } else {
                    if (kmhal_hidl_binder_free_reply(ctx,
                                (const void **)&reply.data.ptr.buffer)) {
                        fail = true;
                        goto loop_out;
                    }
                }

                got_reply = true;
                goto loop_out;
            }

            case BR_DEAD_BINDER:
            case BR_DEAD_REPLY:
                s_log_error("Binder died :(");
                ctx->fail_flags |= FAIL_DEAD_OBJECT;
                goto loop_out;

            default:
                s_log_error("Unexpected binder reply cmd %lu (%s)",
                        (long unsigned)reply_cmd,
                        binder_reply_to_string(reply_cmd)
                );
                fail = true;
                goto loop_out;
            }
        }
#undef try_read
    }
loop_out:

    if (fail)
        s_log_error("Binder transaction failed");
    if (trunc)
        s_log_error("Binder transaction reply data invalid or truncated");
    if (fail || trunc)
        return EXIT_FAILURE;

    if (!got_reply) {
        s_log_error("Didn't get any reply");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

int kmhal_hidl_binder_free_reply(struct kmhal_hidl_binder_ctx *ctx,
        const void **reply_p)
{
    if (!kmhal_hidl_binder_ctx_ok(ctx) || reply_p == NULL || *reply_p == NULL) {
        s_log_error("Invalid parameters!");
        return -1;
    }

    const binder_uintptr_t reply = (const binder_uintptr_t)*reply_p;

    struct free_buf {
        u32 cmd;
        binder_uintptr_t ptr;
    } __attribute__((packed)) free_buf = {
        .cmd = BC_FREE_BUFFER,
        .ptr = reply
    };
    _Static_assert(offsetof(struct free_buf, ptr) == sizeof(u32),
            "Invalid offset of the to-be-freed buffer pointer");
    struct binder_write_read bwr = {
        .write_buffer = (binder_uintptr_t)&free_buf,
        .write_size = sizeof(free_buf)
    };

    int r_;
    do {
        r_ = ioctl(ctx->fd, BINDER_WRITE_READ, &bwr);
    } while (r_ == -1 && errno == EINTR);
    if (r_ == -1) {
        s_log_error("Binder FREE_BUFFER WRITE_READ ioctl failed: %d (%s)",
                errno, strerror(errno));
        ctx->fail_flags |= FAIL_FREE;
        *reply_p = NULL;
        return EXIT_FAILURE;
    }

    *reply_p = NULL;
    return EXIT_SUCCESS;
}

void kmhal_hidl_binder_close(struct kmhal_hidl_binder_ctx **ctx_p)
{
    if (ctx_p == NULL || *ctx_p == NULL ||
            !atomic_exchange(&(*ctx_p)->initialized_, false))
        return;

    struct kmhal_hidl_binder_ctx *const ctx = *ctx_p;

    if (ctx->looper_entered) {
        s_assert(ctx->fd != -1, "Impossible outcome");

        uint32_t cmd = BC_EXIT_LOOPER;
        {
            int r_;
            do {
                r_ = ioctl(ctx->fd, BINDER_WRITE_READ,
                    &(struct binder_write_read) {
                        .write_size = sizeof(cmd),
                        .write_buffer = (uintptr_t)&cmd
                    }
                );
            } while (r_ == -1 && errno == EINTR);
            if (r_ == -1)
                s_log_error("Binder ENTER_LOOPER ioctl failed: %d (%s)",
                        errno, strerror(errno));
        }

        ctx->looper_entered = false;
    }

    if (ctx->map != MAP_FAILED) {
        if (munmap(ctx->map, KMHAL_HIDL_BINDER_READ_BUF_SIZE))
            s_log_error("Failed to unmap the binder read buffer: %d (%s)",
                    errno, strerror(errno));
        ctx->map = NULL;
    }

    if (ctx->fd != -1) {
        if (close(ctx->fd)) {
            s_log_error("Failed to close the binder fd: %d (%s)",
                    errno, strerror(errno));
        }
        ctx->fd = -1;
    }

    if (ctx->fail_flags) {
        s_log_info("Binder ctx->fail_flags: DEAD: %d, FREE: %d, INIT: %d",
                ((ctx->fail_flags & FAIL_DEAD_OBJECT) != 0),
                ((ctx->fail_flags & FAIL_FREE) != 0),
                ((ctx->fail_flags & FAIL_INIT) != 0)
        );
    }
    ctx->fail_flags = FAIL_INIT;

    free(ctx);
    *ctx_p = NULL;
}

static void bubble_sort_domain_ptrs(struct domain_order * d_ptrs[N_DOMAINS])
{
    for (int i = 0; i < N_DOMAINS - 1; ++i) {
        for (int j = 0; j < N_DOMAINS - i - 1; ++j) {

            const enum kmhal_hidl_binder_domain
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

static const char *domain_to_device_name(enum kmhal_hidl_binder_domain d)
{
    switch (d) {
    case KMHAL_HIDL_BINDER: return "/dev/binder";
    case KMHAL_HIDL_HWBINDER: return "/dev/hwbinder";
    case KMHAL_HIDL_VNDBINDER: return "/dev/vndbinder";
    default: return NULL;
    }
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
	case BR_FROZEN_BINDER: return "BR_FROZEN_BINDER";
	case BR_CLEAR_FREEZE_NOTIFICATION_DONE:
        return "BR_CLEAR_FREEZE_NOTIFICATION_DONE";
    default:
        return "(unknown)";
    }
}
