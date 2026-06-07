#ifndef KEYMASTER_TYPES_H_
#define KEYMASTER_TYPES_H_

#include "km-def.h"
#include "transport/hidl-types.h"
#include <stdint.h>
#include <stdbool.h>
#include <core/vector.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/crypto.h>
#include <openssl/safestack.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**
 * Time in milliseconds since some arbitrary point in time.  Time must be monotonically increasing,
 * and a secure environment's notion of "current time" must not repeat until the Android device
 * reboots, or until at least 50 million years have elapsed (note that this requirement is satisfied
 * by setting the clock to zero during each boot, and then counting time accurately).
 */
typedef uint64_t KM_Timestamp;

/**
 * A place to define any needed constants.
 */
enum KM_Constants {
    KM_AUTH_TOKEN_MAC_LENGTH = 32u,
};

#define __KM_TAG_TYPE_MASK(tag) ((tag) & 0xF0000000)
#define __KM_TAG_MASK(tag) ((tag) & 0x0FFFFFFF)

enum KM_TagType {
    /**
     * Invalid type, used to designate a tag as uninitialized.
     */
    KM_TAG_TYPE_INVALID = 0u /* 0 << 28 */,
    /**
     * Enumeration value.
     */
    KM_TAG_TYPE_ENUM = 268435456u /* 1 << 28 */,
    /**
     * Repeatable enumeration value.
     */
    KM_TAG_TYPE_ENUM_REP = 536870912u /* 2 << 28 */,
    /**
     * 32-bit unsigned integer.
     */
    KM_TAG_TYPE_UINT = 805306368u /* 3 << 28 */,
    /**
     * Repeatable 32-bit unsigned integer.
     */
    KM_TAG_TYPE_UINT_REP = 1073741824u /* 4 << 28 */,
    /**
     * 64-bit unsigned integer.
     */
    KM_TAG_TYPE_ULONG = 1342177280u /* 5 << 28 */,
    /**
     * 64-bit unsigned integer representing a date and time, in milliseconds since 1 Jan 1970.
     */
    KM_TAG_TYPE_DATE = 1610612736u /* 6 << 28 */,
    /**
     * Boolean.  If a tag with this type is present, the value is "true".  If absent, "false".
     */
    KM_TAG_TYPE_BOOL = 1879048192u /* 7 << 28 */,
    /**
     * Byte string containing an arbitrary-length integer, big-endian ordering.
     */
    KM_TAG_TYPE_BIGNUM = 2147483648u /* 8 << 28 */,
    /**
     * Byte string
     */
    KM_TAG_TYPE_BYTES = 2415919104u /* 9 << 28 */,
    /**
     * Repeatable 64-bit unsigned integer
     */
    KM_TAG_TYPE_ULONG_REP = 2684354560u /* 10 << 28 */,
};
const char * KM_TagType_toString(uint32_t tt);

/**
 * Keymaster tags
 */
enum KM_Tag {
    KM_TAG_INVALID = 0u,
#define KM_DECL_TAG(name, type, tag_val, param_list_field, bound_enum, asn1_type, asn1_rep) \
    KM_TAG_##name = KM_TAG_TYPE_##type | tag_val##u,

    KM_TAG_LIST__
#undef KM_DECL_TAG
};
bool KM_Tag_is_repeatable(uint32_t tag);
const char * KM_Tag_toString(uint32_t t);

/**
 * Keymaster error codes.
 */
enum KM_ErrorCode {
    KM_OK = 0u,
#define KM_DECL_ERR(name, value) \
    KM_ERROR_##name = value,

    KM_ERR_LIST__
#undef KM_DECL_ERR
};
const char * KM_ErrorCode_toString(int32_t e);

/* for compatibility with `KM_dump_*` */
static inline const char * KM_ErrorCode_toString_u32(uint32_t e)
{
    return KM_ErrorCode_toString((int32_t)e);
}

enum KM_HardwareAuthenticatorType {
#define KM_DECL_ENUM_VAL(c_prefix, name, value) \
    KM_AUTHENTICATOR_##name = value, \

    KM_HARDWARE_AUTHENTICATOR_TYPE_LIST__
#undef KM_DECL_ENUM_VAL
};
const char * KM_HardwareAuthenticatorType_toString(uint32_t hwautht);

#define KM_DECL_ENUM_VAL(c_prefix, name, value) c_prefix##name = value, \

#define KM_DECL_ENUM(enum_name, list_name)  \
enum KM_##enum_name {                                 \
    KM_##list_name##_LIST__                           \
};                                                    \
const char * KM_##enum_name##_toString(uint32_t);     \

KM_ENUM_LIST__
#undef KM_DECL_ENUM
#undef KM_DECL_ENUM_VAL

union KM_IntegerParams {
    /*
     * Enum types
     */
    enum KM_Algorithm algorithm __attribute__ ((aligned(4)));
    enum KM_BlockMode blockMode __attribute__ ((aligned(4)));
    enum KM_PaddingMode paddingMode __attribute__ ((aligned(4)));
    enum KM_Digest digest __attribute__ ((aligned(4)));
    enum KM_EcCurve ecCurve __attribute__ ((aligned(4)));
    enum KM_KeyOrigin origin __attribute__ ((aligned(4)));
    enum KM_KeyBlobUsageRequirements keyBlobUsageRequirements __attribute__ ((aligned(4)));
    enum KM_KeyPurpose purpose __attribute__ ((aligned(4)));
    enum KM_KeyDerivationFunction keyDerivationFunction __attribute__ ((aligned(4)));
    enum KM_HardwareAuthenticatorType hardwareAuthenticatorType __attribute__ ((aligned(4)));

    /*
     * Other types
     */
    bool boolValue __attribute__ ((aligned(1)));
    uint32_t integer __attribute__ ((aligned(4)));
    uint64_t longInteger __attribute__ ((aligned(8)));
    uint64_t dateTime __attribute__ ((aligned(8)));
};
static_assert(offsetof(union KM_IntegerParams, algorithm) == 0, "wrong offset");
static_assert(offsetof(union KM_IntegerParams, blockMode) == 0, "wrong offset");
static_assert(offsetof(union KM_IntegerParams, paddingMode) == 0, "wrong offset");
static_assert(offsetof(union KM_IntegerParams, digest) == 0, "wrong offset");
static_assert(offsetof(union KM_IntegerParams, ecCurve) == 0, "wrong offset");
static_assert(offsetof(union KM_IntegerParams, origin) == 0, "wrong offset");
static_assert(offsetof(union KM_IntegerParams, keyBlobUsageRequirements) == 0, "wrong offset");
static_assert(offsetof(union KM_IntegerParams, purpose) == 0, "wrong offset");
static_assert(offsetof(union KM_IntegerParams, keyDerivationFunction) == 0, "wrong offset");
static_assert(offsetof(union KM_IntegerParams, hardwareAuthenticatorType) == 0, "wrong offset");
static_assert(offsetof(union KM_IntegerParams, boolValue) == 0, "wrong offset");
static_assert(offsetof(union KM_IntegerParams, integer) == 0, "wrong offset");
static_assert(offsetof(union KM_IntegerParams, longInteger) == 0, "wrong offset");
static_assert(offsetof(union KM_IntegerParams, dateTime) == 0, "wrong offset");
static_assert(sizeof(union KM_IntegerParams) == 8, "wrong size");
static_assert(__alignof(union KM_IntegerParams) == 8, "wrong alignment");

struct KM_KeyParameter {

    /**
     * Discriminates the union/blob field used.  The blob cannot be placed in the union, but only
     * one of "f" and "blob" may ever be used at a time.
     */
    enum KM_Tag tag __attribute__((aligned(4)));
    union KM_IntegerParams f __attribute__((aligned(8)));
    KMHAL_HIDL_VEC_OF(uint8_t) blob __attribute__((aligned(8)));
};
static_assert(offsetof(struct KM_KeyParameter, tag) == 0, "wrong offset");
static_assert(offsetof(struct KM_KeyParameter, f) == 8, "wrong offset");
static_assert(offsetof(struct KM_KeyParameter, blob) == 16, "wrong offset");
static_assert(sizeof(struct KM_KeyParameter) == 32, "wrong size");
static_assert(__alignof(struct KM_KeyParameter) == 8, "wrong alignment");

KMHAL_HIDL_VEC_OF_STRUCT_DECL(KM_KeyParameter);

/**
 * The OID for Android attestation records.  For the curious, it breaks down as follows:
 *
 * 1 = ISO
 * 3 = org
 * 6 = DoD (Huh? OIDs are weird.)
 * 1 = IANA
 * 4 = Private
 * 1 = Enterprises
 * 11129 = Google
 * 2 = Google security
 * 1 = certificate extension
 * 17 = Android attestation extension.
 */
__attribute__ ((unused))
static const char KM_kAttestionRecordOid[] = "1.3.6.1.4.1.11129.2.1.17";

/**
 * KeyCharacteristics defines the attributes of a key, including cryptographic parameters, and usage
 * restrictions.  It consits of two vectors of KeyParameters, one for "softwareEnforced" attributes
 * and one for "hardwareEnforced" attributes.
 *
 * KeyCharacteristics objects are returned by generateKey, importKey, importWrappedKey and
 * getKeyCharacteristics.  The IKeymasterDevice secure environment is responsible for allocating the
 * parameters, all of which are Tags with associated values, to the correct vector.  The
 * hardwareEnforced vector must contain only those attributes which are enforced by secure hardware.
 * All others should be in the softwareEnforced vector.  See the definitions of individual Tag enums
 * for specification of which must be hardware-enforced, which may be software-enforced and which
 * must never appear in KeyCharacteristics.
 */
struct KM_KeyCharacteristics {
    KMHAL_HIDL_VEC_OF_STRUCT(KM_KeyParameter) softwareEnforced __attribute__((aligned(8)));
    KMHAL_HIDL_VEC_OF_STRUCT(KM_KeyParameter) hardwareEnforced __attribute__((aligned(8)));
};
static_assert(offsetof(struct KM_KeyCharacteristics, softwareEnforced) == 0, "wrong offset");
static_assert(offsetof(struct KM_KeyCharacteristics, hardwareEnforced) == 16, "wrong offset");
static_assert(sizeof(struct KM_KeyCharacteristics) == 32, "wrong size");
static_assert(__alignof(struct KM_KeyCharacteristics) == 8, "wrong alignment");

/**
 * HardwareAuthToken is used to prove successful user authentication, to unlock the use of a key.
 *
 * HardwareAuthTokens are produced by other secure environment applications, notably GateKeeper and
 * Fingerprint, in response to successful user authentication events.  These tokens are passed to
 * begin(), update(), and finish() to prove that authentication occurred.  See those methods for
 * more details.  It is up to the caller to determine which of the generated auth tokens is
 * appropriate for a given key operation.
 */
struct KM_HardwareAuthToken {
    /**
     * challenge is a value that's used to enable authentication tokens to authorize specific
     * events.  The primary use case for challenge is to authorize an IKeymasterDevice cryptographic
     * operation, for keys that require authentication per operation. See begin() for details.
     */
    uint64_t challenge __attribute__ ((aligned(8)));
    /**
     *  userId is the a "secure" user ID.  It is not related to any Android user ID or UID, but is
     *  created in the Gatekeeper application in the secure environment.
     */
    uint64_t userId __attribute__ ((aligned(8)));
    /**
     *  authenticatorId is the a "secure" user ID.  It is not related to any Android user ID or UID,
     *  but is created in an authentication application in the secure environment, such as the
     *  Fingerprint application.
     */
    uint64_t authenticatorId __attribute__ ((aligned(8)));
    /**
     * authenticatorType describes the type of authentication that took place, e.g. password or
     * fingerprint.
     */
    enum KM_HardwareAuthenticatorType authenticatorType __attribute__ ((aligned(4)));
    /**
     * timestamp indicates when the user authentication took place, in milliseconds since some
     * starting point (generally the most recent device boot) which all of the applications within
     * one secure environment must agree upon.  This timestamp is used to determine whether or not
     * the authentication occurred recently enough to unlock a key (see Tag::AUTH_TIMEOUT).
     */
    uint64_t timestamp __attribute__ ((aligned(8)));
    /**
     * MACs are computed with a backward-compatible method, used by Keymaster 3.0, Gatekeeper 1.0
     * and Fingerprint 1.0, as well as pre-treble HALs.
     *
     * The MAC is Constants::AUTH_TOKEN_MAC_LENGTH bytes in length and is computed as follows:
     *
     *     HMAC_SHA256(
     *         H, 0 || challenge || user_id || authenticator_id || authenticator_type || timestamp)
     *
     * where ``||'' represents concatenation, the leading zero is a single byte, and all integers
     * are represented as unsigned values, the full width of the type.  The challenge, userId and
     * authenticatorId values are in machine order, but authenticatorType and timestamp are in
     * network order (big-endian).  This odd construction is compatible with the hw_auth_token_t
     * structure,
     *
     * Note that mac is a vec rather than an array, not because it's actually variable-length but
     * because it could be empty.  As documented in the IKeymasterDevice::begin,
     * IKeymasterDevice::update and IKeymasterDevice::finish doc comments, an empty mac indicates
     * that this auth token is empty.
     */
    KMHAL_HIDL_VEC_OF(uint8_t) mac __attribute__ ((aligned(8)));
};

static_assert(offsetof(struct KM_HardwareAuthToken, challenge) == 0, "wrong offset");
static_assert(offsetof(struct KM_HardwareAuthToken, userId) == 8, "wrong offset");
static_assert(offsetof(struct KM_HardwareAuthToken, authenticatorId) == 16, "wrong offset");
static_assert(offsetof(struct KM_HardwareAuthToken, authenticatorType) == 24, "wrong offset");
static_assert(offsetof(struct KM_HardwareAuthToken, timestamp) == 32, "wrong offset");
static_assert(offsetof(struct KM_HardwareAuthToken, mac) == 40, "wrong offset");
static_assert(sizeof(struct KM_HardwareAuthToken) == 56, "wrong size");
static_assert(__alignof(struct KM_HardwareAuthToken) == 8, "wrong alignment");

typedef uint64_t KM_OperationHandle_t;

/**
 * HmacSharingParameters holds the data used in the process of establishing a shared HMAC key
 * between multiple Keymaster instances.  Sharing parameters are returned in this struct by
 * getHmacSharingParameters() and send to computeSharedHmac().  See the named methods in IKeymaster
 * for details of usage.
 */
struct KM_HmacSharingParameters {
    /**
     * Either empty or contains a persistent value that is associated with the pre-shared HMAC
     * agreement key (see documentation of computeSharedHmac in @4.0::IKeymaster).  It is either
     * empty or 32 bytes in length.
     */
    KMHAL_HIDL_VEC_OF(uint8_t) seed __attribute__ ((aligned(8)));
    /**
     * A 32-byte value which is guaranteed to be different each time
     * getHmacSharingParameters() is called.  Probabilistic uniqueness (i.e. random) is acceptable,
     * though a stronger uniqueness guarantee (e.g. counter) is recommended where possible.
     */
    uint8_t nonce[32] __attribute__ ((aligned(1)));
};

static_assert(offsetof(struct KM_HmacSharingParameters, seed) == 0, "wrong offset");
static_assert(offsetof(struct KM_HmacSharingParameters, nonce) == 16, "wrong offset");
static_assert(sizeof(struct KM_HmacSharingParameters) == 48, "wrong size");
static_assert(__alignof(struct KM_HmacSharingParameters) == 8, "wrong alignment");
KMHAL_HIDL_VEC_OF_STRUCT_DECL(KM_HmacSharingParameters);

/**
 * VerificationToken enables one Keymaster instance to validate authorizations for another.  See
 * verifyAuthorizations() in IKeymaster for details.
 */
struct KM_VerificationToken {
    /**
     * The operation handle, used to ensure freshness.
     */
    uint64_t challenge __attribute__ ((aligned(8)));
    /**
     * The current time of the secure environment that generates the VerificationToken.  This can be
     * checked against auth tokens generated by the same secure environment, which avoids needing to
     * synchronize clocks.
     */
    uint64_t timestamp __attribute__ ((aligned(8)));
    /**
     * A list of the parameters verified.  Empty if the only parameters verified are time-related.
     * In that case the timestamp is the payload.
     */
    KMHAL_HIDL_VEC_OF_STRUCT(KM_KeyParameter) parametersVerified __attribute__ ((aligned(8)));
    /**
     * SecurityLevel of the secure environment that generated the token.
     */
    enum KM_SecurityLevel securityLevel __attribute__ ((aligned(4)));
    /**
     * 32-byte HMAC-SHA256 of the above values, computed as:
     *
     *    HMAC(H,
     *         "Auth Verification" || challenge || timestamp || securityLevel || parametersVerified)
     *
     * where:
     *
     *   ``HMAC'' is the shared HMAC key (see computeSharedHmac() in IKeymaster).
     *
     *   ``||'' represents concatenation
     *
     * The representation of challenge and timestamp is as 64-bit unsigned integers in big-endian
     * order.  securityLevel is represented as a 32-bit unsigned integer in big-endian order.
     *
     * If parametersVerified is non-empty, the representation of parametersVerified is an ASN.1 DER
     * encoded representation of the values.  The ASN.1 schema used is the AuthorizationList schema
     * from the Keystore attestation documentation.  If parametersVerified is empty, it is simply
     * omitted from the HMAC computation.
     */
    KMHAL_HIDL_VEC_OF(uint8_t) mac __attribute__ ((aligned(8)));
};

static_assert(offsetof(struct KM_VerificationToken, challenge) == 0, "wrong offset");
static_assert(offsetof(struct KM_VerificationToken, timestamp) == 8, "wrong offset");
static_assert(offsetof(struct KM_VerificationToken, parametersVerified) == 16, "wrong offset");
static_assert(offsetof(struct KM_VerificationToken, securityLevel) == 32, "wrong offset");
static_assert(offsetof(struct KM_VerificationToken, mac) == 40, "wrong offset");
static_assert(sizeof(struct KM_VerificationToken) == 56, "wrong size");
static_assert(__alignof(struct KM_VerificationToken) == 8, "wrong alignment");

typedef struct KM_ROOT_OF_TRUST {
    ASN1_OCTET_STRING *verifiedBootKey;
    ASN1_BOOLEAN deviceLocked;
    ASN1_ENUMERATED *verifiedBootState;
    ASN1_OCTET_STRING *verifiedBootHash;
} KM_ROOT_OF_TRUST;
DECLARE_ASN1_FUNCTIONS(KM_ROOT_OF_TRUST);

#define ASN1_ROOT_OF_TRUST KM_ROOT_OF_TRUST
#define ASN1_SET_OF_INTEGER STACK_OF(ASN1_INTEGER)

typedef struct KM_PARAM_LIST {
#define KM_DECL_TAG(name, type, tag_val, param_list_field, bound_enum, asn1_type, asn1_rep)    \
    ASN1##asn1_rep##asn1_type * param_list_field;
    KM_TAG_LIST__
#undef KM_DECL_TAG
} KM_PARAM_LIST;
DECLARE_ASN1_FUNCTIONS(KM_PARAM_LIST)

typedef int64_t KM_DateTime_t;

/* The C struct representation of the `KeyDescription` ASN.1 sequence
 * that stores the result of an Android Key Attestation request.
 *
 * This struct, and all of its sub-structs and enums
 * (`AuthorizationList`, `RootOfTrust`, `SecurityLevel` and `VerifiedBootState`)
 * reflect version 3 of the Android Attestation Extension.
 *
 * For more information and detailed documentation, see
 *  https://source.android.com/docs/security/features/keystore/attestation#attestation-v3
 */
typedef struct KM_KEY_DESC {
    ASN1_INTEGER *attestationVersion;
    ASN1_ENUMERATED *attestationSecurityLevel;
    ASN1_INTEGER *keymasterVersion;
    ASN1_ENUMERATED *keymasterSecurityLevel;
    ASN1_OCTET_STRING *attestationChallenge;
    ASN1_OCTET_STRING *uniqueId;

    /* `KM_PARAM_LIST` is used instead of `KM_AUTH_LIST`
     * for more flexibility (some tags don't appear in `KM_AUTH_LIST`) */

    KM_PARAM_LIST *softwareEnforced;
    KM_PARAM_LIST *hardwareEnforced;
} KM_KEY_DESC;
DECLARE_ASN1_FUNCTIONS(KM_KEY_DESC);

typedef const char * (*KM_enum_toString_proc_t)(uint32_t);

#ifdef __cplusplus
} /* extern "C" */
#endif /* __cplusplus */

#endif /* KEYMASTER_TYPES_H_ */
