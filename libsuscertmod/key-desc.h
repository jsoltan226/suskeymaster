#ifndef SUS_CERT_MOD_REPACK_KEY_DESC_H_
#define SUS_CERT_MOD_REPACK_KEY_DESC_H_

#define OPENSSL_API_COMPAT 0x10002000L
#include <libsuskmhal/util/dump-utils.h>
#include <libsuskmhal/util/keymaster-types-c.h>
#include <openssl/asn1.h>

#ifdef __cplusplus
extern "C" {
namespace suskeymaster {
namespace certmod {
using ::suskeymaster::kmhal::util::KM_KEY_DESC_V3;
using ::suskeymaster::kmhal::util::KM_dump_log_proc_t;
#endif /* __cplusplus */

/* Various utilities for working with Android Attestation Extension objects,
 * represented by the KeyDescription struct
 * (see `libsuskmhal/util/keymaster-types-c.h`).
 *
 * For more information, visit the official Google/AOSP documentation at
 *  https://source.android.com/docs/security/features/keystore/attestation
*/

/* Unpacks the ASN.1 string `desc`
 * (that contains the Android Attestation Extension object)
 * into a new key description struct.
 *
 * On success, returns a new `KM_KEY_DESC_V3` populated
 * with data from the ASN.1 string `desc`.
 * On failure, returns `NULL`.
 */
KM_KEY_DESC_V3 * key_desc_unpack(const ASN1_OCTET_STRING *desc);

/* Repacks the key description struct `desc` into a new ASN.1 octet string
 * with an Android Attestation Extension object.
 *
 * On success, returns a new `ASN1_OCTET_STRING` populated with data
 * from the key description struct `desc`.
 * On failure, returns `NULL`.
 */
ASN1_OCTET_STRING * key_desc_repack(const KM_KEY_DESC_V3 *desc);

/* Prints the contents of the key description `desc` using `log_proc`,
 * with the base indentation level `indent`.
 *
 * If `field_name` is `NULL`, the dump will look something like this:
 *
 * ===== BEGIN KEY DESCRIPTION DUMP =====
 * KM_KEY_DESC_V3 key_desc = {
 *      ... (contents) ...
 * };
 * =====  END KEY DESCRIPTION DUMP  =====
 *
 * Otherwise (if `field_name` is spefified):
 *
 * .<field_name> = {
 *      ... (contents) ...
 * },
 *
 * where in both cases indentation is added according to `indent`.
 * */
void key_desc_dump(KM_dump_log_proc_t log_proc,
        const KM_KEY_DESC_V3 *desc,
        uint8_t indent, const char *field_name);

#ifdef __cplusplus
} /* namespace certmod */
} /* namespace suskeymaster */
} /* extern "C" */
#endif /* __cplusplus */

#endif /* SUS_CERT_MOD_REPACK_KEY_DESC_H_ */
