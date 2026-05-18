#ifndef SUSKEYMASTER_KMHAL_HIDL_BINDERIF_H_
#define SUSKEYMASTER_KMHAL_HIDL_BINDERIF_H_

/**
 * BINDER-IF - HIDL Binder interface
 * Wrapper around the Android binder device for HIDL clients.
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
struct kmhal_hidl_binder_ctx;

/* A struct used to hold the context of a single binder transaction.
 * Internally, stores the serialized commands & data to be consumed
 * later by the `BINDER_WRITE_READ` ioctl call. */
struct kmhal_hidl_binder_transaction;

/* Binder transaction data read buffer size */
#define KMHAL_HIDL_BINDER_TD_READ_BUF_SIZE (1024 * 1024)

/* Binder protocol read buffer size for WRITE_READ ioctl */
#define KMHAL_HIDL_BINDER_PROTO_READ_BUF_SIZE 256

/* Type for binder open order and domain mask */
typedef uint32_t kmhal_hidl_binder_domain_ordered_mask_t;

/* Binder domains */
enum kmhal_hidl_binder_domain {
    KMHAL_HIDL_BINDER    = 0x00000000U, /* /dev/binder */
    KMHAL_HIDL_HWBINDER  = 0x00000001U, /* /dev/hwbinder */
    KMHAL_HIDL_VNDBINDER = 0x00000002U, /* /dev/vndbinder */
};

/* Domain bit masks */
enum kmhal_hidl_binder_domain_mask {
    KMHAL_HIDL_BINDER_BIT    = 0x00000001U,
    KMHAL_HIDL_HWBINDER_BIT  = 0x00000002U,
    KMHAL_HIDL_VNDBINDER_BIT = 0x00000004U,
};

/* Fallback order enums for kmhal_hidl_binder_open */
enum kmhal_hidl_binder_domain_binder_order {
    KMHAL_HIDL_BINDER_1 = 0x01000001U,
    KMHAL_HIDL_BINDER_2 = 0x02000001U,
    KMHAL_HIDL_BINDER_3 = 0x03000001U,
};
enum kmhal_hidl_binder_domain_hwbinder_order {
    KMHAL_HIDL_HWBINDER_1 = 0x00010002U,
    KMHAL_HIDL_HWBINDER_2 = 0x00020002U,
    KMHAL_HIDL_HWBINDER_3 = 0x00030002U,
};
enum kmhal_hidl_binder_domain_vndbinder_order {
    KMHAL_HIDL_VNDBINDER_1 = 0x00000104U,
    KMHAL_HIDL_VNDBINDER_2 = 0x00000204U,
    KMHAL_HIDL_VNDBINDER_3 = 0x00000304U,
};

/* Default domain order: /dev/hwbinder, /dev/binder, /dev/vndbinder */
#define KMHAL_HIDL_BINDER_DEFAULT_ORDER    \
(                                         \
    KMHAL_HIDL_HWBINDER_1 |               \
    KMHAL_HIDL_BINDER_2   |               \
    KMHAL_HIDL_VNDBINDER_3                \
)

/**
 * Open a binder device using domain fallback order.
 * @param domains_to_try: Mask defining order of domains.
 * @return: New context or NULL on failure.
 */
struct kmhal_hidl_binder_ctx *
kmhal_hidl_binder_open(kmhal_hidl_binder_domain_ordered_mask_t domains_to_try);

/**
 * Open a binder device at the given path.
 * @param dev_path: Path to the binder device.
 * @return: New context or NULL on failure.
 */
struct kmhal_hidl_binder_ctx *
kmhal_hidl_binder_open_dev(const char *dev_path);

/**
 * Check whether a binder context is valid.
 * @param ctx: Context to check.
 * @return: true if valid, false otherwise.
 */
bool kmhal_hidl_binder_ctx_ok(const struct kmhal_hidl_binder_ctx *ctx);

/**
 * Create a new binder transaction context struct.
 * @return: New transaction context or NULL on failure */
struct kmhal_hidl_binder_transaction * kmhal_hidl_binder_transaction_new(void);

/**
 * Serialize `BC_ACQUIRE` command to increment strong reference count.
 * Call before using `handle`.
 */
void kmhal_hidl_binder_write_acquire_strong(
        struct kmhal_hidl_binder_transaction *txn, u32 handle
);

/**
 * Serialize `BC_INCREFS` command to increment weak reference count.
 * Call before using `handle`.
 */
void kmhal_hidl_binder_write_increfs_weak(
        struct kmhal_hidl_binder_transaction *txn, u32 handle
);

/**
 * Serialize `BC_RELEASE` command to decrement strong reference count.
 * Call after using `handle` if `BC_INCREFS` was previously used.
 */
void kmhal_hidl_binder_write_release_strong(
        struct kmhal_hidl_binder_transaction *txn, u32 handle
);

/**
 * Serialize BC_DECREFS command to decrement weak reference count.
 * Call after using `handle` if `BC_ACQUIRE` was previously used.
 */
void kmhal_hidl_binder_write_decrefs_weak(
        struct kmhal_hidl_binder_transaction *txn, u32 handle
);

/* The binder transaction input data */
struct kmhal_hidl_binder_tr_sg_args_in {
    u32 handle; /* Target object handle */
    u32 cmd; /* Command ID */
    u32 flags; /* Transaction flags */

    void *data_buf; /* Transaction data */
    binder_size_t data_size; /* Number of bytes of transaction data */

    /* Offsets from buffer to any `flat_binder_object` structs */
    binder_size_t *offsets_buf;
    size_t offsets_count; /* Number of offsets */

    /* The total size of all scatter-gather `flat_binder_object`s */
    binder_size_t sg_buffers_size;
};

/* Binder transaction status */
enum kmhal_hidl_binder_tr_sg_status {
    KMHAL_HIDL_BINDER_TR_SG_UNINITIALIZED = 0,
    KMHAL_HIDL_BINDER_TR_SG_PENDING = 1,
    KMHAL_HIDL_BINDER_TR_SG_OK = 2,
    KMHAL_HIDL_BINDER_TR_SG_FAILED = 3
};
/* Binder transaction output data */
struct kmhal_hidl_binder_tr_sg_args_out {
    enum kmhal_hidl_binder_tr_sg_status status; /* Transaction status */

    u32 flags; /* Flags decribing the data, such as `TF_STATUS_CODE` */

    const void *data_buf; /* Transaction data */
    binder_size_t data_size; /* Number of bytes of transaction data */

    /* Offsets from buffer to any `flat_binder_object` structs */
    const binder_size_t *offsets_buf;
    size_t offsets_count; /* Number of offsets */
};

/* A struct containing the parameter for `kmhal_hidl_binder_add_transact_sg` */
struct kmhal_hidl_binder_tr_sg_args {
    /* The transaction context struct, to which the serialized command
     * will be written.
     * Must be non-null. */
    struct kmhal_hidl_binder_transaction *in_txn;

    /* The binder transaction input data. Initialize appropriately. */
    struct kmhal_hidl_binder_tr_sg_args_in in_data;

    /* Data returned by the object.
     * This should be initialized to zero and read out
     * only after a successful ioctl call. */
    struct kmhal_hidl_binder_tr_sg_args_out out_reply;
};

/**
 * Serialize `BC_TRANSACTION_SG` command for a transaction.
 *
 * `transact_sg_ctx` must not go out of scope until after the a call to
 * `kmhal_hidl_binder_write_read_ioctl` with the same `in_txn`.
 *
 * @return: 0 on success, non-zero on failure.
 */
void kmhal_hidl_binder_add_transact_sg(
        struct kmhal_hidl_binder_tr_sg_args *arg
);

/**
 * Serialize `BC_FREE_BUFFER` command to free a reply buffer.
 * Must be in a separate ioctl than the transaction that created it.
 */
void kmhal_hidl_binder_write_free_reply(
        struct kmhal_hidl_binder_transaction *txn,
        const void *reply
);

/**
 * Send all commands in `*txn_p` to binder device `ctx`.
 * `*txn_p` is always freed and set to `NULL` after the call.
 * @return: 0 on success, non-zero on failure.
 */
int kmhal_hidl_binder_write_read_ioctl(
        struct kmhal_hidl_binder_ctx *ctx,
        struct kmhal_hidl_binder_transaction **txn_p
);

/**
 * Free the transaction context pointed to by `*txn_p`
 * and set `*txn_p` to NULL.
 *
 * Note that this should not normally be called; the transaction context
 * is supposed to be destroyed in `kmhal_hidl_binder_write_read_ioctl`.
 */
void kmhal_hidl_binder_transaction_destroy(
        struct kmhal_hidl_binder_transaction **txn_p
);

/**
 * Close and free a binder device context.
 * Sets the pointer to NULL.
 */
void kmhal_hidl_binder_close(struct kmhal_hidl_binder_ctx **ctx_p);

#ifdef __cplusplus
} /* extern "C" */
#endif /* __cplusplus */

#endif /* SUSKEYMASTER_KMHAL_HIDL_BINDERIF_H_ */
