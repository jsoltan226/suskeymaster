#ifndef SUS_CERT_SIGN_KEYBOX_H_
#define SUS_CERT_SIGN_KEYBOX_H_

#include <core/int.h>
#include <core/vector.h>
#include <libgenericutil/cert-types.h>

#ifdef __cplusplus
namespace suskeymaster {
extern "C" {
#endif /* __cplusplus */

struct keybox;

struct keybox * keybox_load(VECTOR(u8 const) bytes);

struct keybox * keybox_init(
        VECTOR(VECTOR(u8)) ec_cert_chain, VECTOR(u8) ec_key,
        VECTOR(VECTOR(u8)) rsa_cert_chain, VECTOR(u8) rsa_key,
        bool should_own
);

VECTOR(u8) keybox_store(const struct keybox *kb);

void keybox_destroy(struct keybox **kb_p);

const struct keybox * keybox_get_builtin(void);

VECTOR(VECTOR(u8 const) const)
keybox_get_cert_chain(const struct keybox *kb, enum sus_key_variant key_type);

VECTOR(u8 const) keybox_get_batch_key_serial(const struct keybox *kb,
        enum sus_key_variant key_type);

i32 keybox_get_not_after(i64 *out, const struct keybox *kb,
        enum sus_key_variant key_type);

VECTOR(u8 const) keybox_get_wrapped_key(const struct keybox *kb,
        enum sus_key_variant key_type);

#ifdef __cplusplus
} /* extern "C" */
} /* namespace suskeymaster */
#endif /* __cplusplus */

#endif /* SUS_CERT_SIGN_KEYBOX_H_ */
