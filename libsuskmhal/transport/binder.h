#ifndef SUSKEYMASTER_KMHAL_BINDER_H_
#define SUSKEYMASTER_KMHAL_BINDER_H_

/**
 * Wrapper around the Android binder device for HAL clients.
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <core/vector.h>
#include <linux/android/binder.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/* Binder device context used for transactions */
struct kmhal_binder_ctx;

/* A struct used to hold the context of a single binder transaction.
 * Internally, stores the serialized commands & data to be consumed
 * later by the `BINDER_WRITE_READ` ioctl call. */
struct kmhal_binder_txn;

/* Binder transaction data read buffer size */
#define KMHAL_BINDER_TD_READ_BUF_SIZE (1024 * 1024)

/* Binder protocol read buffer size for WRITE_READ ioctl */
#define KMHAL_BINDER_PROTO_READ_BUF_SIZE 256

/* Type for binder open order and domain mask */
typedef uint32_t kmhal_binder_domain_ordered_mask_t;

/* Binder domains */
enum kmhal_binder_domain {
    KMHAL_BINDER_DEV_BINDER    = UINT32_C(0x00000001), /* /dev/binder */
    KMHAL_BINDER_DEV_HWBINDER  = UINT32_C(0x00000002), /* /dev/hwbinder */
    KMHAL_BINDER_DEV_VNDBINDER = UINT32_C(0x00000004), /* /dev/vndbinder */
};

/* Fallback order enums for kmhal_binder_open */
enum kmhal_binder_domain_binder_order {
    KMHAL_BINDER_DEV_BINDER_1 = UINT32_C(0x01000001),
    KMHAL_BINDER_DEV_BINDER_2 = UINT32_C(0x02000001),
    KMHAL_BINDER_DEV_BINDER_3 = UINT32_C(0x03000001),
};
enum kmhal_binder_domain_hwbinder_order {
    KMHAL_BINDER_DEV_HWBINDER_1 = UINT32_C(0x00010002),
    KMHAL_BINDER_DEV_HWBINDER_2 = UINT32_C(0x00020002),
    KMHAL_BINDER_DEV_HWBINDER_3 = UINT32_C(0x00030002),
};
enum kmhal_binder_domain_vndbinder_order {
    KMHAL_BINDER_DEV_VNDBINDER_1 = UINT32_C(0x00000104),
    KMHAL_BINDER_DEV_VNDBINDER_2 = UINT32_C(0x00000204),
    KMHAL_BINDER_DEV_VNDBINDER_3 = UINT32_C(0x00000304),
};

/**
 * Open a binder device using domain fallback order.
 * @param domains_to_try: Mask defining order of domains.
 * Example (try "/dev/binder", then "/dev/vndbinder"):
 *  (KMHAL_BINDER_DEV_BINDER_1 | KMHAL_BINDER_DEV_VNDBINDER_2)
 * Or just simply try only "/dev/hwbinder":
 *  (KMHAL_BINDER_DEV_HWBINDER)
 *
 * @return: New context or NULL on failure.
 */
struct kmhal_binder_ctx *
kmhal_binder_open(kmhal_binder_domain_ordered_mask_t domains_to_try);

/**
 * Open a binder device at the given path.
 * @param dev_path: Path to the binder device.
 * @return: New context or NULL on failure.
 */
struct kmhal_binder_ctx *
kmhal_binder_open_dev(const char *dev_path);

/**
 * Return the path to the device associated with the given context.
 * @param ctx Binder device context.
 * @return String with the path or NULL if not available.
 */
const char * kmhal_binder_get_dev_path(const struct kmhal_binder_ctx *ctx);

/**
 * Return the binder device file descriptor associated with the given context.
 * @param ctx Binder device context.
 * @return Binder device file descriptor or -1 if not available.
 */
int kmhal_binder_get_fd(const struct kmhal_binder_ctx *ctx);

/**
 * Check whether a binder context is valid.
 * @param ctx: Context to check.
 * @return: true if valid, false otherwise.
 */
bool kmhal_binder_ctx_ok(const struct kmhal_binder_ctx *ctx);

/**
 * Create a new binder transaction context struct.
 * @return: New transaction context or NULL on failure */
struct kmhal_binder_txn * kmhal_binder_txn_new(void);

/**
 * Serialize `BC_ACQUIRE` command to increment strong reference count.
 * Call before using `handle`.
 */
void kmhal_binder_write_acquire(struct kmhal_binder_txn *txn, u32 handle);

/**
 * Serialize `BC_INCREFS` command to increment weak reference count.
 * Call before using `handle`.
 */
void kmhal_binder_write_increfs(struct kmhal_binder_txn *txn, u32 handle);

/**
 * Serialize `BC_RELEASE` command to decrement strong reference count.
 * Call after using `handle` if `BC_INCREFS` was previously used.
 */
void kmhal_binder_write_release(struct kmhal_binder_txn *txn, u32 handle);

/**
 * Serialize BC_DECREFS command to decrement weak reference count.
 * Call after using `handle` if `BC_ACQUIRE` was previously used.
 */
void kmhal_binder_write_decrefs(struct kmhal_binder_txn *txn, u32 handle);

/* The binder transaction input data */
struct kmhal_binder_txn_args_in {
    u32 handle; /* Target object handle */
    u32 cmd; /* Command ID */
    u32 flags; /* Transaction flags */

    void *data_buf; /* Transaction data */
    binder_size_t data_size; /* Number of bytes of transaction data */

    /* Offsets from buffer to any binder objects */
    binder_size_t *offsets_buf;
    size_t offsets_count; /* Number of offsets */

    /* The total size of all scatter-gather binder objects,
     * used with `kmhal_binder_write_transact_sg`. Ignored otherwise. */
    binder_size_t sg_buffers_size;
};

/* Binder transaction status */
enum kmhal_binder_txn_status {
    KMHAL_BINDER_TXN_UNINITIALIZED = 0,
    KMHAL_BINDER_TXN_PENDING = 1,
    KMHAL_BINDER_TXN_OK = 2,
    KMHAL_BINDER_TXN_FAILED = 3
};
/* Binder transaction output data */
struct kmhal_binder_txn_args_out {
    enum kmhal_binder_txn_status status; /* Transaction status */

    u32 flags; /* Flags decribing the data, such as `TF_STATUS_CODE` */

    const void *data_buf; /* Transaction data */
    binder_size_t data_size; /* Number of bytes of transaction data */

    /* Offsets from buffer to any binder objects */
    const binder_size_t *offsets_buf;
    size_t offsets_count; /* Number of offsets */
};

/* A struct containing the parameter for `kmhal_binder_write_transact(_sg)` */
struct kmhal_binder_txn_args {
    /* The transaction context struct, to which the serialized command
     * will be written.
     * Must be non-null. */
    struct kmhal_binder_txn *in_txn;

    /* The binder transaction input data. Initialize appropriately. */
    struct kmhal_binder_txn_args_in in_data;

    /* Data returned by the object.
     * This should be initialized to zero and read out
     * only after a successful ioctl call. */
    struct kmhal_binder_txn_args_out out_reply;
};

/**
 * Serialize the `BC_TRANSACTION` command for a standard binder transaction.
 *
 * `arg->in_txn` and any referenced data must not go out of scope
 *  until after the a call to `kmhal_binder_write_read_ioctl`
 *  with the same `in_txn`.
 *
 * @return: 0 on success, non-zero on failure.
 */
void kmhal_binder_write_transact(struct kmhal_binder_txn_args *arg);

/**
 * Serialize the `BC_TRANSACTION_SG` command
 * for a scatter-gather binder transaction.
 *
 * `arg->in_txn` and any referenced data must not go out of scope
 *  until after the a call to `kmhal_binder_write_read_ioctl`
 *  with the same `in_txn`.
 *
 * @return: 0 on success, non-zero on failure.
 */
void kmhal_binder_write_transact_sg(struct kmhal_binder_txn_args *arg);

/**
 * Serialize `BC_FREE_BUFFER` command to free a transaction reply buffer.
 * Must be in a separate ioctl than the transaction that created it.
 */
void kmhal_binder_write_free_reply(struct kmhal_binder_txn *txn,
                                   const void *reply);

/**
 * Send all commands in `*txn_p` to binder device `ctx`.
 * `*txn_p` is always freed and set to `NULL` after the call.
 * @return: 0 on success, non-zero on failure.
 */
int kmhal_binder_do_write_read_ioctl(struct kmhal_binder_ctx *ctx,
                                     struct kmhal_binder_txn **txn_p);

/**
 * Free the transaction context pointed to by `*txn_p`
 * and set `*txn_p` to NULL.
 *
 * Note that this should not normally be called; the transaction context
 * is supposed to be destroyed in `kmhal_binder_write_read_ioctl`.
 */
void kmhal_binder_txn_destroy(struct kmhal_binder_txn **txn_p);

/**
 * Close and free a binder device context.
 * Sets the pointer to NULL.
 */
void kmhal_binder_close(struct kmhal_binder_ctx **ctx_p);

#ifdef __cplusplus
} /* extern "C" */
#endif /* __cplusplus */

#endif /* SUSKEYMASTER_KMHAL_BINDER_H_ */
