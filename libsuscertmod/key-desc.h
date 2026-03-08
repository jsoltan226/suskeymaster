#ifndef SUS_CERT_MOD_REPACK_KEY_DESC_H_
#define SUS_CERT_MOD_REPACK_KEY_DESC_H_

#include "keymaster-types.h"
#include <openssl/asn1.h>

#ifdef __cplusplus
extern "C" {
namespace suskeymaster {
#endif /* __cplusplus */

/* Various utilities for working with Android Attestation Extension objects,
 * represented by the KeyDescription struct (see `keymaster-types.h`).
 *
 * For more information, visit the official Google/AOSP documentation at
 *  https://source.android.com/docs/security/features/keystore/attestation
*/

/** Implemented in `key-desc-unpack.c` **/

/* Allocates and initializes an empty key description struct.
 * Internal function; you should probably use `key_desc_repack` instead.
 * Returns `NULL` on failure. */
struct KM_KeyDescription_v3 * key_desc_new(void);

/* Unpacks the ASN.1 string `desc`
 * (that contains the Android Attestation Extension object)
 * into a new key description struct.
 *
 * On success, returns a new `struct KM_KeyDescription_v3` populated
 * with data from the ASN.1 string `desc`.
 * On failure, returns `NULL`.
 */
struct KM_KeyDescription_v3 * key_desc_unpack(const ASN1_OCTET_STRING *desc);


/** Implemented in `key-desc-repack.c` **/

/* Repacks the key description struct `desc` into a new ASN.1 octet string
 * with an Android Attestation Extension object.
 *
 * On success, returns a new `ASN1_OCTET_STRING` populated with data
 * from the key description struct `desc`.
 * On failure, returns `NULL`.
 */
ASN1_OCTET_STRING * key_desc_repack(const struct KM_KeyDescription_v3 *desc);

/* Destroys and de-allocates the key description struct pointed to by `desc_p`,
 * and sets `*desc_p` to `NULL`. */
void key_desc_destroy(struct KM_KeyDescription_v3 **desc_p);


/** Implemented in `key-desc-dump.c` **/

/* A function that prints the printf-style `fmt` & varargs to some log output */
typedef void (*key_desc_log_proc_t)(const char *fmt, ...);

/* Prints the contents of the key description `desc` using `log_proc`.
 * This is a debugging routine. Use with caution. */
void key_desc_dump(const struct KM_KeyDescription_v3 *desc,
        key_desc_log_proc_t log_proc);


/** Internal procedures & interfaces of `key-desc-unpack.c`,
 ** exposed here only because they were needed in other modules
 **/

/* Parses an AuthorizationList ASN.1 SEQUENCE starting at `*p`,
 * stored in a container of length `len`,
 * and writes the resulting struct in `out`.
 *
 * Note that `*p` will be incremented to point past the parsed
 * AuthorizationList sequence.
 *
 * Returns `true` on success and `false` on failure.
 */
bool key_desc_parse_auth_list(struct KM_AuthorizationList_v3 *out,
        const unsigned char **p, long len);

/* Parses a RootOfTrust ASN.1 SEQUENCE starting at `*p`,
 * stored in a container of length `len`,
 * and writes the resulting struct in `out`.
 *
 * Note that `*p` will be incremented to point past the parsed
 * RootOfTrust sequence.
 *
 * Returns `true` on success and `false` on failure.
 */
bool key_desc_parse_root_of_trust(struct KM_RootOfTrust_v3 *out,
        const unsigned char **p, long len);


/** Internal procedures & interfaces of `key-desc-repack.c`,
 ** exposed here only because they were needed in other modules
 **/

/* Frees and cleans up all the data in `al` (see `KM_AuthorizationList_v3`) */
void key_desc_destroy_auth_list(struct KM_AuthorizationList_v3 *al);

/* Frees and cleans up all the data in `rot` (see `KM_RootOfTrust_v3`) */
void key_desc_destroy_root_of_trust(struct KM_RootOfTrust_v3 *rot);

/* The possible variants of the AuthorizationList
 * (see `KM_KeyDescription_v3`) */
enum key_desc_measure_auth_list_variant {

    /* Corresponds to the `softwareEnforced` authorization list */
    MEASURE_AL_SOFTWARE_ENFORCED,

    /* Corresponds to the `hardwareEnforced` authorization list */
    MEASURE_AL_HARDWARE_ENFORCED,
};

/* A structure used to store temporary/cached state when measuring
 * the KeyDescription sequence's required DER size */
struct key_desc_measure_ctx {
    bool initialized_;
    ASN1_INTEGER *i;
    ASN1_OCTET_STRING *str;
    ASN1_ENUMERATED *e;

    /* This will contain the sizes of nested SEQUENCEs in the Key Description.
     * This is their layout:
     *
     * KeyDescription
     *           \-> ...
     *              hardwareEnforced AuthorizationList
     *                      \-> ...
     *                          RootOfTrust
     *                          ...
     *              ...
     *              softwareEnforced AuthorizationList
     *                      \-> ...
     *                          ...
     */
    struct measure_auth_list_data {
        u32 al_size;
        u32 al_rot_size;
    } hardwareEnforced, softwareEnforced;
};

/* Initializes a new measuring context (see `key_desc_measure_ctx`).
 * Returns 0 on success and non-zero on failure. */
i32 key_desc_measure_ctx_init(struct key_desc_measure_ctx *ctx);

/* Destroys a key description measuring context (see `key_desc_measure_ctx`). */
void key_desc_measure_ctx_destroy(struct key_desc_measure_ctx *ctx);

/* Measures the amount of bytes required to store a DER-encoded representation
 * of the KeyDescription in `key_desc` (see `KM_KeyDescription_v3`),
 * using the measurement context `ctx`.
 *
 * Note: The returned value *DOES NOT INCLUDE* the ASN.1 SEQUENCE TLV container!
 *
 * Returns a negative value on error.
 * Otherwise, the return value is the measured number of bytes.
 */
i32 key_desc_measure_inner_key_desc(struct key_desc_measure_ctx *ctx,
        const struct KM_KeyDescription_v3 *auth_list);

/* Measures the amount of bytes required to store a DER-encoded representation
 * of the AuthorizationList in `auth_list` of variant `variant`
 * (see `key_desc_measure_auth_list_variant`),
 * using the measurement context `ctx`.
 *
 * Note: The returned value *INCLUDES* the ASN.1 SEQUENCE TLV container!
 *
 * Returns a negative value on error.
 * Otherwise, the return value is the measured number of bytes.
 */
i32 key_desc_measure_outer_auth_list(struct key_desc_measure_ctx *ctx,
        const struct KM_AuthorizationList_v3 *auth_list,
        enum key_desc_measure_auth_list_variant variant);

/* Measures the amount of bytes required to store a DER-encoded representation
 * of the RootOfTrust sequence in `rot` of variant `variant`
 * (see `key_desc_measure_auth_list_variant`),
 * using the measurement context `ctx`.
 *
 * Note: The returned value *DOES NOT INCLUDE* the ASN.1 SEQUENCE TLV container!
 *
 * Returns a negative value on error.
 * Otherwise, the return value is the measured number of bytes.
 */
i32 key_desc_measure_inner_root_of_trust(struct key_desc_measure_ctx *ctx,
        const struct KM_RootOfTrust_v3 *rot,
        enum key_desc_measure_auth_list_variant variant);

/* Writes a DER-encoded ASN.1 AuthorizationList SEQUENCE, starting at `*p`
 * and incrementing it to point past the written bytes,
 * stopping before reaching `end`.
 *
 * `auth_list` cntains the values to be encoded, `mctx` is the measurement
 * context used previously to measure the size of the sequence,
 * and `variant` is the variant of the AuthorizationList being encoded
 * (see `key_desc_measure_auth_list_variant`).
 *
 * Returns `true` on success and `false` on failure.
 */
bool key_desc_write_auth_list(unsigned char **p, unsigned char *end,
        const struct KM_AuthorizationList_v3 *auth_list,
        const struct key_desc_measure_ctx *mctx,
        enum key_desc_measure_auth_list_variant variant);

/* Writes a DER-encoded ASN.1 RootOfTrust SEQUENCE, starting at `*p`
 * and incrementing it to point past the written bytes,
 * stopping before reaching `end`.
 *
 * `rot` cntains the values to be encoded, `mctx` is the measurement
 * context used previously to measure the size of the sequence,
 * and `variant` corresponds to the AuthorizationList sequence
 * in which the RootOfTrust is contained
 * (see `key_desc_measure_auth_list_variant`).
 *
 * Returns `true` on success and `false` on failure.
 */
bool key_desc_write_root_of_trust(unsigned char **p, unsigned char *end,
        const struct KM_RootOfTrust_v3 *rot,
        const struct key_desc_measure_ctx *mctx,
        enum key_desc_measure_auth_list_variant variant);

/* Writes the DER-encoded ASN.1 EXPLICIT OPTIONAL Tag and Length
 * present in the AuthorizationList SEQUENCE, starting at `*p`
 * and incrementing it to point past the written bytes,
 * stopping before reaching `end`.
 *
 * `content_len` is the length of the inner contained SEQUENCE, while
 * `tag` is the KeyMaster tag (see `KM_Tag`) associated with the contained data.
 * If no KeyMaster tag should be written, set `tag` to `KM_TAG_INVALID`.
 *
 * Returns `true` on success and `false` on failure.
 */
bool key_desc_write_sequence_header(unsigned char **p, unsigned char *end,
        u32 content_len, u32 tag);

#ifdef __cplusplus
} /* namespace suskeymaster */
} /* extern "C" */
#endif /* __cplusplus */

#endif /* SUS_CERT_MOD_REPACK_KEY_DESC_H_ */
