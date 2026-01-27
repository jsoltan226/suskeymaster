#ifndef SUS_CERT_MOD_REPACK_KEY_DESC_H_
#define SUS_CERT_MOD_REPACK_KEY_DESC_H_

#include "keymaster-types.h"
#include <openssl/asn1.h>

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

/* Prints the contents of the key description `desc` to the CGD log.
 * This is a debugging routine. Use with caution. */
void key_desc_dump(const struct KM_KeyDescription_v3 *desc);

#endif /* SUS_CERT_MOD_REPACK_KEY_DESC_H_ */
