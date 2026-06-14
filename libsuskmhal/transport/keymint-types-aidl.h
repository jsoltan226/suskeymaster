#ifndef SUSKEYMASTER_KMHAL_TRANSPORT_KEYMINT_TYPES_AIDL_H_
#define SUSKEYMASTER_KMHAL_TRANSPORT_KEYMINT_TYPES_AIDL_H_

#ifndef SUSKEYMASTER_BUILD_HOST

#include "parcel.h"
#include "../keymaster-types-c.h"
#include <core/int.h>
#include <core/vector.h>
#include <string.h>
#include <stdlib.h>
#include <stddef.h>
#include <assert.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

struct aidl_keymint_hardware_info {
    i32 versionNumber;
    enum KM_SecurityLevel securityLevel;
    char *keyMintName;
    char *keyMintAuthorName;
    i32 timestampTokenRequired;
};
void destroy_aidl_keymint_hardware_info(
        struct aidl_keymint_hardware_info *hwinfo
);

/**
 * @param out A pointer to a zero-initialized
 *  `struct aidl_keymint_hardware_info`. Must not be NULL.
 *
 * @param out_size sizeof(struct aidl_keymint_hardware_info).
 *
 * Callers should later destroy the hardware info struct with
 *  `destroy_aidl_keymint_hardware_info`.
 */
int parse_aidl_keymint_hardware_info(const struct kmhal_parcel *p,
                                     size_t *off_p,
                                     void *out, size_t out_size);

struct aidl_vec_generic {
    void *ptr;
    i32 size;
    bool owns;
};

#define AIDL_VEC_OF_STATIC_TESTS(T)                                            \
    static_assert(offsetof(T, ptr) == offsetof(struct aidl_vec_generic, ptr),  \
            "Wrong offset");                                                   \
    static_assert(offsetof(T, size) == offsetof(struct aidl_vec_generic, size),\
            "Wrong offset");                                                   \
    static_assert(offsetof(T, owns) == offsetof(struct aidl_vec_generic, owns),\
            "Wrong offset");                                                   \
    static_assert(sizeof(T) == sizeof(struct aidl_vec_generic), "Wrong size")

#define AIDL_VEC_OF_PARCELABLE_DECL(T, name)                                   \
    struct aidl_vec_of_##name {                                                \
        T *ptr;                                                                \
        i32 size;                                                              \
        bool owns;                                                             \
    };                                                                         \
    void destroy_aidl_vec_of_##name(struct aidl_vec_of_##name *vec);           \
                                                                               \
    /**                                                                        \
     * @param data A pointer to a valid `struct aidl_vec_of_##name`, or NULL   \
     *  if the parameter is nullable and the value is not specified            \
     *  (std::nullopt).                                                        \
     */                                                                        \
    void write_nullable_aidl_vec_of_##name(struct kmhal_parcel *p,             \
                                           const void *data);                  \
                                                                               \
    /**                                                                        \
     * @param data A pointer to a valid `struct aidl_vec_of_##name`.           \
     * Must not be NULL.                                                       \
     */                                                                        \
    void write_aidl_vec_of_##name(struct kmhal_parcel *p, const void *data);   \
                                                                               \
    /**                                                                        \
     * @param out A pointer to a zero-initialized `struct aidl_vec_of_##name`. \
     *  Must not be NULL.                                                      \
     *  Written to only on success.                                            \
     *                                                                         \
     * @param out_size sizeof(struct aidl_vec_of_##name).                      \
     *                                                                         \
     * If the written vector's `ptr` is NULL, that means                       \
     * that the nullable parameter wasn't specified (std::nullopt).            \
     *                                                                         \
     * Callers should later destroy the vector struct with                     \
     *  `destroy_aidl_vec_of_##name`.                                          \
     */                                                                        \
    int parse_nullable_aidl_vec_of_##name(const struct kmhal_parcel *p,        \
                                          size_t *off_p,                       \
                                          void *out, size_t out_size);         \
                                                                               \
    /**                                                                        \
     * @param out A pointer to a zero-initialized `struct aidl_vec_of_##name`. \
     *  Must not be NULL.                                                      \
     *  Written to only on success.                                            \
     *                                                                         \
     * @param out_size sizeof(struct aidl_vec_of_##name).                      \
     *                                                                         \
     * Callers should later destroy the vector struct with                     \
     *  `destroy_aidl_vec_of_##name`.                                          \
     */                                                                        \
    int parse_aidl_vec_of_##name(const struct kmhal_parcel *p, size_t *off_p,  \
                                 void *out, size_t out_size);                  \
                                                                               \
    AIDL_VEC_OF_STATIC_TESTS(struct aidl_vec_of_##name);


struct aidl_vec_of_u8 {
    u8 *ptr;
    i32 size;
    bool owns;
};
void destroy_aidl_vec_of_u8(struct aidl_vec_of_u8 *vec);

/**
 * @param data A pointer to a valid `struct aidl_vec_of_u8`, or NULL
 *  if the parameter is nullable and the value is not specified (std::nullopt).
 */
void write_nullable_aidl_vec_of_u8(struct kmhal_parcel *p, const void *data);

/**
 * @param data A pointer to a valid `struct aidl_vec_of_u8`. Must not be NULL.
 */
void write_aidl_vec_of_u8(struct kmhal_parcel *p, const void *data);

/**
 * @param out A pointer to a zero-initialized `struct aidl_vec_of_u8`.
 *  Must not be NULL.
 *  Written to only on success.
 *
 * @param out_size sizeof(struct aidl_vec_of_u8).
 *
 * Callers should later destroy the vector struct with
 *  `destroy_aidl_vec_of_u8`.
 */
int parse_aidl_vec_of_u8(const struct kmhal_parcel *p, size_t *off_p,
                         void *out, size_t out_size);

/**
 * @param out A pointer to a zero-initialized `struct aidl_vec_of_u8`.
 *  Must not be NULL.
 *  Written to only on success.
 *
 * @param out_size sizeof(struct aidl_vec_of_u8).
 *
 * If the written vector's `ptr` is NULL, that means
 * that the nullable parameter wasn't specified (std::nullopt).
 *
 * Callers should later destroy the vector struct with
 *  `destroy_aidl_vec_of_u8`.
 */
int parse_nullable_aidl_vec_of_u8(const struct kmhal_parcel *p, size_t *off_p,
                                  void *out, size_t out_size);

struct aidl_key_parameter {
    enum KM_Tag tag;

    /* See `union IntegerParams` in the HIDL definitions */
    union {
        i32 i;
        i64 l;
    } integer_value;

    /* Depending on the Tag, only one of `integer_value` and `blob`
     * is set at a time */
    struct aidl_vec_of_u8 blob;
};
void destroy_aidl_key_parameter(struct aidl_key_parameter *kp);

/**
 * @param data A non-null pointer to a valid `struct aidl_key_parameter`.
 */
void write_aidl_key_parameter(struct kmhal_parcel *p, const void *data);

/**
 * @param out A pointer to a zero-initialized `struct aidl_key_parameter`.
 *  Must not be NULL.
 *  Written to only on success.
 *
 * @param out_size sizeof(struct aidl_key_parameter).
 *
 * Callers should later destroy the key parameter struct with
 *  `destroy_aidl_key_parameter`.
 */
int parse_aidl_key_parameter(const struct kmhal_parcel *p, size_t *off_p,
                             void *out, size_t out_size);

AIDL_VEC_OF_PARCELABLE_DECL(struct aidl_key_parameter, key_parameter);

/* In KeyMint, KeyCharacteristics only appear in a vector
 * (KeyCharacteristics[]). */
struct aidl_key_characteristics {
    enum KM_SecurityLevel security_level;
    struct aidl_vec_of_key_parameter authorizations;
};
void destroy_aidl_key_characteristics(struct aidl_key_characteristics *kp);

/**
 * @param data A non-null pointer to a valid `struct aidl_key_characteristics`.
 */
void write_aidl_key_characteristics(struct kmhal_parcel *p, const void *data);

/**
 * @param out A pointer to a zero-initialized
 *  `struct aidl_key_characteristics`. Must not be NULL.
 *  Written to only on success.
 *
 * @param out_size sizeof(struct aidl_key_characteristics).
 *
 * Callers should later destroy the key characteristics struct with
 *  `destroy_aidl_key_characteristics`.
 */
int parse_aidl_key_characteristics(const struct kmhal_parcel *p, size_t *off_p,
                                   void *out, size_t out_size);

AIDL_VEC_OF_PARCELABLE_DECL(struct aidl_key_characteristics,
                            key_characteristics);

/* Fuck java */
struct aidl_certificate {
    struct aidl_vec_of_u8 encoded_certificate;
};
void destroy_aidl_certificate(struct aidl_certificate *cert);
void write_aidl_certificate(struct kmhal_parcel *p, const void *data);
int parse_aidl_certificate(const struct kmhal_parcel *p, size_t *off_p,
                           void *out, size_t out_size);

AIDL_VEC_OF_PARCELABLE_DECL(struct aidl_certificate, certificate);

struct aidl_key_creation_result {
    struct aidl_vec_of_u8 key_blob;
    struct aidl_vec_of_key_characteristics key_characteristics;
    struct aidl_vec_of_certificate certificate_chain;
};
void destroy_aidl_key_creation_result(struct aidl_key_creation_result *cr);

/**
 * @param out A non-null pointer to a zero-initialized
 *  `struct aidl_key_creation_result`.
 *
 * @param out_size `sizeof(struct aidl_key_creation_result)`.
 */
int parse_aidl_key_creation_result(const struct kmhal_parcel *p, size_t *off_p,
                                   void *out, size_t out_size);

struct aidl_hardware_auth_token {
    u64 challenge;
    u64 user_id;
    u64 authenticator_id;
    u32 authenticator_type;
    u64 timestamp;
    struct aidl_vec_of_u8 mac;
};
void destroy_aidl_hardware_auth_token(struct aidl_hardware_auth_token *hat);

/**
 * @param data A pointer to a valid `struct aidl_hardware_auth_token`, or NULL
 *  if the parameter is nullable and the value is not specified (std::nullopt).
 */
void write_nullable_aidl_hardware_auth_token(struct kmhal_parcel *p,
                                             const void *data);

/**
 * @param out A non-null pointer to a zero-initialized
 *  `struct aidl_hardware_auth_token`.
 *
 * @param out_size `sizeof(struct aidl_hardware_auth_token)`.
 */
int parse_aidl_hardware_auth_token(const struct kmhal_parcel *p, size_t *off_p,
                                   void *out, size_t out_size);

struct aidl_begin_result {
    u64 challenge;
    struct aidl_vec_of_key_parameter params;
    u32 IKeyMintOperation_binder_handle;
};
/**
 * Note: this doesn't doesn't unref the binder handle.
 */
void destroy_aidl_begin_result(struct aidl_begin_result *res);

/**
 * @param out A non-null pointer to a zero-initialized
 *  `struct aidl_begin_result`.
 *
 * @param out_size `sizeof(struct aidl_begin_result)`.
 *
 * Note: This itself doesn't incref the handle,
 * but when passed to `kmhal_call`, it will cause it to do so
 * automatically via `out_handle_to_incref`.
 */
int parse_aidl_begin_result(const struct kmhal_parcel *p, size_t *off_p,
                            u32 *out_handle_to_incref,
                            void *out, size_t out_size);


#ifdef __cplusplus
} /* extern "C" */
#endif /* __cplusplus */

#endif /* SUSKEYMASTER_BUILD_HOST */

#endif /* SUSKEYMASTER_KMHAL_TRANSPORT_KEYMINT_TYPES_AIDL_H_ */
