#ifndef SUSKEYMASTER_KMHAL_HIDL_BINDERIF_H_
#define SUSKEYMASTER_KMHAL_HIDL_BINDERIF_H_

/** BINDER-IF - HIDL Binder interface
 * A wrapper around the android binder device,
 * made for use in the context of an HIDL client
**/

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <linux/android/binder.h>

#ifdef __cplusplus
namespace suskeymaster {
namespace kmhal {
namespace hidl {
extern "C" {
#endif /* __cplusplus */

/* A structure that holds the context necessary to talk to the binder driver
 * and perform binder transactions */
struct kmhal_hidl_binder_ctx;

/* The size of the binder read buffer -
 * the buffer to which the kernel writes the results of binder transactions */
#define KMHAL_HIDL_BINDER_READ_BUF_SIZE (1024 * 1024)

/* Encodes the desired behavior of `kmhal_hidl_binder_open`.
 * For example, `KMHAL_HIDL_BINDER_DEFAULT_ORDER` is interpreted as:
 *
 * 02   | Byte 1: binder order - /dev/binder will be tried 2nd
 * 01   | Byte 2: hwbinder order - /dev/hwbinder will be tried 1st
 * 03   | Byte 3: vndbinder order - /dev/vndbinder will be tried 3rd
 * 07   | Byte 4: domain mask - a mask of which domains to try,
 *              in this case it's 0x7 which is 0b0111 which means all of them
 */
typedef uint32_t kmhal_hidl_binder_domain_ordered_mask_t;

/* The default order for HIDL is:
 *  /dev/hwbinder, /dev/binder and /dev/vndbinder
 */
#define KMHAL_HIDL_BINDER_DEFAULT_ORDER     \
(                                           \
        KMHAL_HIDL_HWBINDER_1   |           \
        KMHAL_HIDL_BINDER_2     |           \
        KMHAL_HIDL_VNDBINDER_3              \
)

/* An enum representing the three binder domains */
enum kmhal_hidl_binder_domain {
    KMHAL_HIDL_BINDER           = 0x00000000U, /* /dev/binder */
    KMHAL_HIDL_HWBINDER         = 0x00000001U, /* /dev/hwbinder */
    KMHAL_HIDL_VNDBINDER        = 0x00000002U, /* /dev/vndbinder */
};

/* An enum representing bits correspinding to the three binder domains */
enum kmhal_hidl_binder_domain_mask {
    KMHAL_HIDL_BINDER_BIT       = 0x00000001U,
    KMHAL_HIDL_HWBINDER_BIT     = 0x00000002U,
    KMHAL_HIDL_VNDBINDER_BIT    = 0x00000004U,
};

/* enums used to configure the fallback order of `kmhal_hidl_binder_open` */

enum kmhal_hidl_binder_domain_binder_order {
    KMHAL_HIDL_BINDER_1         = 0x01000001U,
    KMHAL_HIDL_BINDER_2         = 0x02000001U,
    KMHAL_HIDL_BINDER_3         = 0x03000001U,
};
enum kmhal_hidl_binder_domain_hwbinder_order {
    KMHAL_HIDL_HWBINDER_1       = 0x00010002U,
    KMHAL_HIDL_HWBINDER_2       = 0x00020002U,
    KMHAL_HIDL_HWBINDER_3       = 0x00030002U,
};
enum kmhal_hidl_binder_domain_vndbinder_order {
    KMHAL_HIDL_VNDBINDER_1      = 0x00000104U,
    KMHAL_HIDL_VNDBINDER_2      = 0x00000204U,
    KMHAL_HIDL_VNDBINDER_3      = 0x00000304U,
};

/* Opens and initializes a binder device, trying & falling back
 * according to `domains_to_try`.
 * Return value:
 *  On success: A new binder device context
 *  On failure: `NULL`
 */
struct kmhal_hidl_binder_ctx * kmhal_hidl_binder_open(
        kmhal_hidl_binder_domain_ordered_mask_t domains_to_try
);

/* Opens and initializes the binder device at `dev_path`.
 * Return value:
 *  On success: A new binder device context
 *  On failure: `NULL`
 */
struct kmhal_hidl_binder_ctx * kmhal_hidl_binder_open_dev(const char *dev_path);

/* Checks whether the binder device context `ctx` is OK
 * and fit for further use.
 * If not, it should be destroyed immediately.
 */
bool kmhal_hidl_binder_ctx_ok(const struct kmhal_hidl_binder_ctx *ctx);

/* Performs a binder transaction using the device context `ctx`.
 * `handle`, `cmd_code`, `flags`, `data`, `data_size`,
 * `offsets` and `offsets_count` are all related to fields of
 * `struct binder_transact_data`.
 *
 * If `out_reply` is not `NULL`, the transaction result (reply) buffer
 * will be written to it, and its size to `out_reply_size`.
 * The buffer must be freed using `kmhal_hidl_binder_free_reply`
 * before another call to this function.
 * Note that if either `out_reply` or `out_reply_size` is non-`NULL`,
 * the other one also has to be.
 *
 * Returns 0 on success and non-zero on failure.
 */
int kmhal_hidl_binder_transact(struct kmhal_hidl_binder_ctx *ctx,
        uint32_t handle, uint32_t cmd_code, uint32_t flags,
        const void *data, size_t data_size,
        const binder_size_t *offsets, size_t offsets_count,
        const void **out_reply, size_t *out_reply_size);

/* Frees the binder device `ctx`'s reply pointer to by `reply_p`
 * and sets `*reply_p` to `NULL`.
 * Returns 0 on sucess and non-zero on failure.
 */
int kmhal_hidl_binder_free_reply(struct kmhal_hidl_binder_ctx *ctx,
        const void **reply_p);

/* Destroys and cleans up the binder device context pointed to by `ctx_p`
 * and sets `*ctx_p` to `NULL`.
 */
void kmhal_hidl_binder_close(struct kmhal_hidl_binder_ctx **ctx_p);

#ifdef __cplusplus
} /* extern "C" */
} /* namespace hidl */
} /* namespace kmhal */
} /* namespace suskeymaster */
#endif /* __cplusplus */

#endif /* SUSKEYMASTER_KMHAL_HIDL_BINDERIF_H_ */
