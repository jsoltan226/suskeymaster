#ifndef SUSKEYMASTER_KMHAL_HIDL_TXN_UTIL_H_
#define SUSKEYMASTER_KMHAL_HIDL_TXN_UTIL_H_

/**
 * Helpers for common tasks performed during HIDL transactions.
 */

#include "base.h"
#include "parcel.h"
#include "binderif.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/* Checks if the provided transaction context and/or parcel are NULL,
 * and if so, allocates new ones.
 *
 * @param txn_p A pointer to a binder transaction struct.
 *  May itself be NULL, in which case it's ignored.
 *  If `*txn_p` is NULL, a new transaction context is
 *      allocated and written into it.
 *
 * @param parcel_p A pointer to a parcel.
 *  May itself be NULL, in which case it's ignored.
 *  If `*parcel_p` is NULL, a new parcel is allocated and written into it.
 *
 * @return `OK` on success, `NO_MEMORY` on allocation failure.
 *  See `enum kmhal_hidl_android_status`.
 */
enum kmhal_hidl_android_status kmhal_hidl_util_check_allocate_txn_tmps(
        struct kmhal_hidl_binder_transaction **txn_p,
        struct kmhal_hidl_parcel **parcel_p
);

/* Performs a binder transaction with the (packed) parcel,
 * unpacks the result and checks for any errors.
 *
 * After that, allocates a new transaction context and parcel,
 * and if so requested, queues the FREE_BUFFER command for the reply buffer.
 *
 * @param binder A valid binder device context.
 *
 * @param txn_p A pointer to a valid binder transaction context.
 *  After the transaction, a new transaction context is allocated
 *  and written into `*txn_p`.
 *
 * @param parcel_p A valid pointer to a parcel that is
 *  packed and ready for transact.
 *  After a successful transaction, `*parcel_p` will contain a new parcel
 *  initialized from the reply data. See `kmhal_hidl_parcel_new_from_reply`.
 *
 * @param out_reply Optional output pointer for the returned reply.
 *
 * @param write_free_reply Whether to queue the FREE_BUFFER command
 *  (for the reply buffer) into the new transaction context.
 *
 * @return `OK` on success, anything else on failure.
 *  Note: On success, only the parcel should be destroyed,
 *  while on failure, both `txn_p` and `parcel_p` should be passed to
 *  `kmhal_hidl_util_destroy_txn_tmps`.
 *
 * Note: In any case, `txn_p` and `parcel_p` should later be freed
 * with `kmhal_hidl_util_destroy_txn_tmps` as needed.
 * The parcel should always get destroyed after the transaction,
 * but `txn_p` - on success and if `write_free_reply` is set -
 * will already contain the FREE_BUFFER command, so it should be flushed
 * before being destroyed.
 */
enum kmhal_hidl_android_status kmhal_hidl_util_transact_and_unpack(
        struct kmhal_hidl_binder_ctx *binder,
        struct kmhal_hidl_binder_transaction **txn_p,
        struct kmhal_hidl_parcel **parcel_p,
        struct kmhal_hidl_binder_tr_sg_args_out *out_reply,
        bool write_free_reply
);

/*
 * Destroys the binder transaction context and parcel, if they exist.
 *
 * @param txn_p A pointer to a binder transaction context. May be NULL.
 *
 * @param parcel_p A pointer to a parcel. May be NULL.
 */
void kmhal_hidl_util_destroy_txn_tmps(
        struct kmhal_hidl_binder_transaction **txn_p,
        struct kmhal_hidl_parcel **parcel_p
);

#ifdef __cplusplus
} /* extern "C" */
#endif /* __cplusplus */

#endif /* SUSKEYMASTER_KMHAL_HIDL_TXN_UTIL_H_ */
