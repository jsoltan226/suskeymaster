#ifndef KEYMASTER_TYPES_H_
#define KEYMASTER_TYPES_H_

#include <stdint.h>
#include <stdbool.h>
#include <core/vector.h>
#include <string.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/crypto.h>
#include <openssl/safestack.h>

#ifdef __cplusplus
extern "C" {
namespace suskeymaster {
namespace kmhal {
namespace util {
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

#include "km-tags-def.h"

enum KM_Tag {
    KM_TAG_INVALID = 0u,
#define KM_DECL_TAG(name, type, tag_val, param_list_field, bound_enum, asn1_type, asn1_rep) \
    KM_TAG_##name = KM_TAG_TYPE_##type | tag_val##u,

    KM_TAG_LIST__
#undef KM_DECL_TAG
};

/**
 * Algorithms provided by IKeymasterDevice implementations.
 */
enum KM_Algorithm {
    /**
     * Asymmetric algorithms.
     */
    KM_ALG_RSA = 1u,
    KM_ALG_EC = 3u,
    /**
     * Block cipher algorithms
     */
    KM_ALG_AES = 32u,
    KM_ALG_TRIPLE_DES = 33u,
    /**
     * MAC algorithms
     */
    KM_ALG_HMAC = 128u,
};

/**
 * Symmetric block cipher modes provided by keymaster implementations.
 */
enum KM_BlockMode {
    /*
     * Unauthenticated modes, usable only for encryption/decryption and not generally recommended
     * except for compatibility with existing other protocols.
     */
    KM_BLOCK_MODE_ECB = 1u,
    KM_BLOCK_MODE_CBC = 2u,
    KM_BLOCK_MODE_CTR = 3u,
    /*
     * Authenticated modes, usable for encryption/decryption and signing/verification.  Recommended
     * over unauthenticated modes for all purposes.
     */
    KM_BLOCK_MODE_GCM = 32u,
};

/**
 * Padding modes that may be applied to plaintext for encryption operations.  This list includes
 * padding modes for both symmetric and asymmetric algorithms.  Note that implementations should not
 * provide all possible combinations of algorithm and padding, only the
 * cryptographically-appropriate pairs.
 */
enum KM_PaddingMode {
    KM_PADDING_NONE = 1u,
    /*
     * deprecated
     */
    KM_PADDING_RSA_OAEP = 2u,
    KM_PADDING_RSA_PSS = 3u,
    KM_PADDING_RSA_PKCS1_1_5_ENCRYPT = 4u,
    KM_PADDING_RSA_PKCS1_1_5_SIGN = 5u,
    KM_PADDING_PKCS7 = 64u,
};

/**
 * Digests provided by keymaster implementations.
 */
enum KM_Digest {
    KM_DIGEST_NONE = 0u,
    KM_DIGEST_MD5 = 1u,
    KM_DIGEST_SHA1 = 2u,
    KM_DIGEST_SHA_2_224 = 3u,
    KM_DIGEST_SHA_2_256 = 4u,
    KM_DIGEST_SHA_2_384 = 5u,
    KM_DIGEST_SHA_2_512 = 6u,
};

/**
 * Supported EC curves, used in ECDSA
 */
enum KM_EcCurve {
    KM_EC_CURVE_P_224 = 0u,
    KM_EC_CURVE_P_256 = 1u,
    KM_EC_CURVE_P_384 = 2u,
    KM_EC_CURVE_P_521 = 3u,
};

/**
 * The origin of a key (or pair), i.e. where it was generated.  Note that ORIGIN can be found in
 * either the hardware-enforced or software-enforced list for a key, indicating whether the key is
 * hardware or software-based.  Specifically, a key with GENERATED in the hardware-enforced list
 * must be guaranteed never to have existed outide the secure hardware.
 */
enum KM_KeyOrigin {
    /**
     * Generated in keymaster.  Should not exist outside the TEE.
     */
    KM_ORIGIN_GENERATED = 0u,
    /**
     * Derived inside keymaster.  Likely exists off-device.
     */
    KM_ORIGIN_DERIVED = 1u,
    /**
     * Imported into keymaster.  Existed as cleartext in Android.
     */
    KM_ORIGIN_IMPORTED = 2u,
    /**
     * Keymaster did not record origin.  This value can only be seen on keys in a keymaster0
     * implementation.  The keymaster0 adapter uses this value to document the fact that it is
     * unkown whether the key was generated inside or imported into keymaster.
     */
    KM_ORIGIN_UNKNOWN = 3u,
    /**
     * Securely imported into Keymaster.  Was created elsewhere, and passed securely through Android
     * to secure hardware.
     */
    KM_ORIGIN_SECURELY_IMPORTED = 4u,
};

/**
 * Usability requirements of key blobs.  This defines what system functionality must be available
 * for the key to function.  For example, key "blobs" which are actually handles referencing
 * encrypted key material stored in the file system cannot be used until the file system is
 * available, and should have BLOB_REQUIRES_FILE_SYSTEM.
 */
enum KM_KeyBlobUsageRequirements {
    KM_USAGE_STANDALONE = 0u,
    KM_USAGE_REQUIRES_FILE_SYSTEM = 1u,
};

/**
 * Possible purposes of a key (or pair).
 */
enum KM_KeyPurpose {
    KM_PURPOSE_ENCRYPT = 0u,
    /*
     * Usable with RSA, EC and AES keys.
     */
    KM_PURPOSE_DECRYPT = 1u,
    /*
     * Usable with RSA, EC and AES keys.
     */
    KM_PURPOSE_SIGN = 2u,
    /*
     * Usable with RSA, EC and HMAC keys.
     */
    KM_PURPOSE_VERIFY = 3u,
    /*
     * Usable with RSA, EC and HMAC keys.
     *
     *
     * 4 is reserved
     */
    KM_PURPOSE_WRAP_KEY = 5u,
};


/**
 * Keymaster error codes.
 */
enum KM_ErrorCode {
    KM_OK = 0,
    KM_ERR_ROOT_OF_TRUST_ALREADY_SET = -1 /* -1 */,
    KM_ERR_UNSUPPORTED_PURPOSE = -2 /* -2 */,
    KM_ERR_INCOMPATIBLE_PURPOSE = -3 /* -3 */,
    KM_ERR_UNSUPPORTED_ALGORITHM = -4 /* -4 */,
    KM_ERR_INCOMPATIBLE_ALGORITHM = -5 /* -5 */,
    KM_ERR_UNSUPPORTED_KEY_SIZE = -6 /* -6 */,
    KM_ERR_UNSUPPORTED_BLOCK_MODE = -7 /* -7 */,
    KM_ERR_INCOMPATIBLE_BLOCK_MODE = -8 /* -8 */,
    KM_ERR_UNSUPPORTED_MAC_LENGTH = -9 /* -9 */,
    KM_ERR_UNSUPPORTED_PADDING_MODE = -10 /* -10 */,
    KM_ERR_INCOMPATIBLE_PADDING_MODE = -11 /* -11 */,
    KM_ERR_UNSUPPORTED_DIGEST = -12 /* -12 */,
    KM_ERR_INCOMPATIBLE_DIGEST = -13 /* -13 */,
    KM_ERR_INVALID_EXPIRATION_TIME = -14 /* -14 */,
    KM_ERR_INVALID_USER_ID = -15 /* -15 */,
    KM_ERR_INVALID_AUTHORIZATION_TIMEOUT = -16 /* -16 */,
    KM_ERR_UNSUPPORTED_KEY_FORMAT = -17 /* -17 */,
    KM_ERR_INCOMPATIBLE_KEY_FORMAT = -18 /* -18 */,
    KM_ERR_UNSUPPORTED_KEY_ENCRYPTION_ALGORITHM = -19 /* -19 */,
    /**
     * For PKCS8 & PKCS12
     */
    KM_ERR_UNSUPPORTED_KEY_VERIFICATION_ALGORITHM = -20 /* -20 */,
    /**
     * For PKCS8 & PKCS12
     */
    KM_ERR_INVALID_INPUT_LENGTH = -21 /* -21 */,
    KM_ERR_KEY_EXPORT_OPTIONS_INVALID = -22 /* -22 */,
    KM_ERR_DELEGATION_NOT_ALLOWED = -23 /* -23 */,
    KM_ERR_KEY_NOT_YET_VALID = -24 /* -24 */,
    KM_ERR_KEY_EXPIRED = -25 /* -25 */,
    KM_ERR_KEY_USER_NOT_AUTHENTICATED = -26 /* -26 */,
    KM_ERR_OUTPUT_PARAMETER_NULL = -27 /* -27 */,
    KM_ERR_INVALID_OPERATION_HANDLE = -28 /* -28 */,
    KM_ERR_INSUFFICIENT_BUFFER_SPACE = -29 /* -29 */,
    KM_ERR_VERIFICATION_FAILED = -30 /* -30 */,
    KM_ERR_TOO_MANY_OPERATIONS = -31 /* -31 */,
    KM_ERR_UNEXPECTED_NULL_POINTER = -32 /* -32 */,
    KM_ERR_INVALID_KEY_BLOB = -33 /* -33 */,
    KM_ERR_IMPORTED_KEY_NOT_ENCRYPTED = -34 /* -34 */,
    KM_ERR_IMPORTED_KEY_DECRYPTION_FAILED = -35 /* -35 */,
    KM_ERR_IMPORTED_KEY_NOT_SIGNED = -36 /* -36 */,
    KM_ERR_IMPORTED_KEY_VERIFICATION_FAILED = -37 /* -37 */,
    KM_ERR_INVALID_ARGUMENT = -38 /* -38 */,
    KM_ERR_UNSUPPORTED_TAG = -39 /* -39 */,
    KM_ERR_INVALID_TAG = -40 /* -40 */,
    KM_ERR_MEMORY_ALLOCATION_FAILED = -41 /* -41 */,
    KM_ERR_IMPORT_PARAMETER_MISMATCH = -44 /* -44 */,
    KM_ERR_SECURE_HW_ACCESS_DENIED = -45 /* -45 */,
    KM_ERR_OPERATION_CANCELLED = -46 /* -46 */,
    KM_ERR_CONCURRENT_ACCESS_CONFLICT = -47 /* -47 */,
    KM_ERR_SECURE_HW_BUSY = -48 /* -48 */,
    KM_ERR_SECURE_HW_COMMUNICATION_FAILED = -49 /* -49 */,
    KM_ERR_UNSUPPORTED_EC_FIELD = -50 /* -50 */,
    KM_ERR_MISSING_NONCE = -51 /* -51 */,
    KM_ERR_INVALID_NONCE = -52 /* -52 */,
    KM_ERR_MISSING_MAC_LENGTH = -53 /* -53 */,
    KM_ERR_KEY_RATE_LIMIT_EXCEEDED = -54 /* -54 */,
    KM_ERR_CALLER_NONCE_PROHIBITED = -55 /* -55 */,
    KM_ERR_KEY_MAX_OPS_EXCEEDED = -56 /* -56 */,
    KM_ERR_INVALID_MAC_LENGTH = -57 /* -57 */,
    KM_ERR_MISSING_MIN_MAC_LENGTH = -58 /* -58 */,
    KM_ERR_UNSUPPORTED_MIN_MAC_LENGTH = -59 /* -59 */,
    KM_ERR_UNSUPPORTED_KDF = -60 /* -60 */,
    KM_ERR_UNSUPPORTED_EC_CURVE = -61 /* -61 */,
    KM_ERR_KEY_REQUIRES_UPGRADE = -62 /* -62 */,
    KM_ERR_ATTESTATION_CHALLENGE_MISSING = -63 /* -63 */,
    KM_ERR_KEYMASTER_NOT_CONFIGURED = -64 /* -64 */,
    KM_ERR_ATTESTATION_APPLICATION_ID_MISSING = -65 /* -65 */,
    KM_ERR_CANNOT_ATTEST_IDS = -66 /* -66 */,
    KM_ERR_ROLLBACK_RESISTANCE_UNAVAILABLE = -67 /* -67 */,
    KM_ERR_HARDWARE_TYPE_UNAVAILABLE = -68 /* -68 */,
    KM_ERR_PROOF_OF_PRESENCE_REQUIRED = -69 /* -69 */,
    KM_ERR_CONCURRENT_PROOF_OF_PRESENCE_REQUESTED = -70 /* -70 */,
    KM_ERR_NO_USER_CONFIRMATION = -71 /* -71 */,
    KM_ERR_DEVICE_LOCKED = -72 /* -72 */,
    KM_ERR_UNIMPLEMENTED = -100 /* -100 */,
    KM_ERR_VERSION_MISMATCH = -101 /* -101 */,
    KM_ERR_UNKNOWN_ERROR = -1000 /* -1000 */,
};

/**
 * Key derivation functions, mostly used in ECIES.
 */
enum KM_KeyDerivationFunction {
    /**
     * Do not apply a key derivation function; use the raw agreed key
     */
    KM_DERIVATION_NONE = 0u,
    /**
     * HKDF defined in RFC 5869 with SHA256
     */
    KM_DERIVATION_RFC5869_SHA256 = 1u,
    /**
     * KDF1 defined in ISO 18033-2 with SHA1
     */
    KM_DERIVATION_ISO18033_2_KDF1_SHA1 = 2u,
    /**
     * KDF1 defined in ISO 18033-2 with SHA256
     */
    KM_DERIVATION_ISO18033_2_KDF1_SHA256 = 3u,
    /**
     * KDF2 defined in ISO 18033-2 with SHA1
     */
    KM_DERIVATION_ISO18033_2_KDF2_SHA1 = 4u,
    /**
     * KDF2 defined in ISO 18033-2 with SHA256
     */
    KM_DERIVATION_ISO18033_2_KDF2_SHA256 = 5u,
};

/**
 * Hardware authentication type, used by HardwareAuthTokens to specify the mechanism used to
 * authentiate the user, and in KeyCharacteristics to specify the allowable mechanisms for
 * authenticating to activate a key.
 */
enum KM_HardwareAuthenticatorType {
    KM_AUTHENTICATOR_NONE = 0u,
    KM_AUTHENTICATOR_PASSWORD = 1u /* 1 << 0 */,
    KM_AUTHENTICATOR_FINGERPRINT = 2u /* 1 << 1 */,
    KM_AUTHENTICATOR_ANY = 4294967295u /* 0xFFFFFFFF */,
};

/**
 * Device security levels.
 */
enum KM_SecurityLevel {
    KM_SECURITY_LEVEL_SOFTWARE = 0u,
    KM_SECURITY_LEVEL_TRUSTED_ENVIRONMENT = 1u,
    /**
     * STRONGBOX specifies that the secure hardware satisfies the requirements specified in CDD
     * 9.11.2.
     */
    KM_SECURITY_LEVEL_STRONGBOX = 2u,
};

/**
 * Formats for key import and export.
 */
enum KM_KeyFormat {
    /**
     * X.509 certificate format, for public key export.
     */
    KM_FORMAT_X509 = 0u,
    /**
     * PCKS#8 format, asymmetric key pair import.
     */
    KM_FORMAT_PKCS8 = 1u,
    /**
     * Raw bytes, for symmetric key import.
     */
    KM_FORMAT_RAW = 3u,
};

union KM_IntegerParams {
    /*
     * Enum types
     */
    enum KM_Algorithm algorithm;
    enum KM_BlockMode blockMode;
    enum KM_PaddingMode paddingMode;
    enum KM_Digest digest;
    enum KM_EcCurve ecCurve;
    enum KM_KeyOrigin origin;
    enum KM_KeyBlobUsageRequirements keyBlobUsageRequirements;
    enum KM_KeyPurpose purpose;
    enum KM_KeyDerivationFunction keyDerivationFunction;
    enum KM_HardwareAuthenticatorType hardwareAuthenticatorType;
    enum KM_SecurityLevel hardwareType;

    /*
     * Other types
     */
    bool boolValue;
    uint32_t integer;
    uint64_t longInteger;
    uint64_t dateTime;
};

struct KM_KeyParameter {

    /**
     * Discriminates the union/blob field used.  The blob cannot be placed in the union, but only
     * one of "f" and "blob" may ever be used at a time.
     */
    enum KM_Tag tag;
    union KM_IntegerParams f;
    VECTOR(u8) blob; /* hidl_vec<uint8_t> */
};
static inline void km_destroy_key_parameter(struct KM_KeyParameter *kp)
{
    if (kp == NULL)
        return;

    kp->tag = KM_TAG_INVALID;
    memset(&kp->f, 0, sizeof(union KM_IntegerParams));
    vector_destroy(&kp->blob);
}
static inline void km_destroy_key_parameters(VECTOR(struct KM_KeyParameter) *kps_p)
{
    if (kps_p == NULL || *kps_p == NULL)
        return;

    VECTOR(struct KM_KeyParameter) const kps = *kps_p;

    for (u32 i = 0; i < vector_size(kps); i++)
        km_destroy_key_parameter(&kps[i]);

    vector_destroy(kps_p);
}

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

/* The C enum representation of the `VerifiedBootState` ASN.1 ENUMERATED type.
 * Present in the `RootOfTrust` struct. */
enum KM_VerifiedBootState {
    KM_VERIFIED_BOOT_VERIFIED = 0,
    KM_VERIFIED_BOOT_SELF_SIGNED = 1,
    KM_VERIFIED_BOOT_UNVERIFIED = 2,
    KM_VERIFIED_BOOT_FAILED = 3,
};

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
    VECTOR(struct KM_KeyParameter) softwareEnforced;
    VECTOR(struct KM_KeyParameter) hardwareEnforced;
};
static inline void km_destroy_key_characteristics(struct KM_KeyCharacteristics *kc)
{
    if (kc == NULL)
        return;

    if (kc->softwareEnforced != NULL) {
        for (u32 i = 0; i < vector_size(kc->softwareEnforced); i++)
            km_destroy_key_parameter(&kc->softwareEnforced[i]);

        vector_destroy(&kc->softwareEnforced);
    }

    if (kc->hardwareEnforced != NULL) {
        for (u32 i = 0; i < vector_size(kc->hardwareEnforced); i++)
            km_destroy_key_parameter(&kc->hardwareEnforced[i]);

        vector_destroy(&kc->hardwareEnforced);
    }
}

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
    uint64_t challenge;
    /**
     *  userId is the a "secure" user ID.  It is not related to any Android user ID or UID, but is
     *  created in the Gatekeeper application in the secure environment.
     */
    uint64_t userId;
    /**
     *  authenticatorId is the a "secure" user ID.  It is not related to any Android user ID or UID,
     *  but is created in an authentication application in the secure environment, such as the
     *  Fingerprint application.
     */
    uint64_t authenticatorId;
    /**
     * authenticatorType describes the type of authentication that took place, e.g. password or
     * fingerprint.
     */
    enum KM_HardwareAuthenticatorType authenticatorType;
    /**
     * timestamp indicates when the user authentication took place, in milliseconds since some
     * starting point (generally the most recent device boot) which all of the applications within
     * one secure environment must agree upon.  This timestamp is used to determine whether or not
     * the authentication occurred recently enough to unlock a key (see Tag::AUTH_TIMEOUT).
     */
    uint64_t timestamp;
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
    uint8_t mac[KM_AUTH_TOKEN_MAC_LENGTH];
};
static inline void km_destroy_hardware_auth_token(struct KM_HardwareAuthToken *auth_token)
{
    if (auth_token == NULL)
        return;

    auth_token->challenge = 0;
    auth_token->userId = 0;
    auth_token->authenticatorId = 0;
    auth_token->authenticatorType = KM_AUTHENTICATOR_NONE;
    auth_token->timestamp = 0;
    memset(auth_token->mac, 0, KM_AUTH_TOKEN_MAC_LENGTH);
}

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
    VECTOR(u8) seed;
    /**
     * A 32-byte value which is guaranteed to be different each time
     * getHmacSharingParameters() is called.  Probabilistic uniqueness (i.e. random) is acceptable,
     * though a stronger uniqueness guarantee (e.g. counter) is recommended where possible.
     */
    u8 nonce[32];
};
static inline void km_destroy_hmac_sharing_parameters(struct KM_HmacSharingParameters *params)
{
    if (params == NULL)
        return;

    vector_destroy(&params->seed);
    memset(params->nonce, 0, sizeof(params->nonce));
}

/**
 * VerificationToken enables one Keymaster instance to validate authorizations for another.  See
 * verifyAuthorizations() in IKeymaster for details.
 */
struct KM_VerificationToken {
    /**
     * The operation handle, used to ensure freshness.
     */
    uint64_t challenge;
    /**
     * The current time of the secure environment that generates the VerificationToken.  This can be
     * checked against auth tokens generated by the same secure environment, which avoids needing to
     * synchronize clocks.
     */
    uint64_t timestamp;
    /**
     * A list of the parameters verified.  Empty if the only parameters verified are time-related.
     * In that case the timestamp is the payload.
     */
    VECTOR(struct KM_KeyParameter) parametersVerified;
    /**
     * SecurityLevel of the secure environment that generated the token.
     */
    enum KM_SecurityLevel securityLevel;
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
    u8 mac[KM_AUTH_TOKEN_MAC_LENGTH];
};
static inline void km_destroy_verification_token(struct KM_VerificationToken *vt)
{
    if (vt == NULL)
        return;

    vt->challenge = 0;
    vt->timestamp = 0;
    vector_destroy(&vt->parametersVerified);
    vt->securityLevel = KM_SECURITY_LEVEL_SOFTWARE;
    memset(vt->mac, 0, KM_AUTH_TOKEN_MAC_LENGTH);
}

typedef struct KM_RootOfTrust_V3 {
    ASN1_OCTET_STRING *verifiedBootKey;
    ASN1_BOOLEAN deviceLocked;
    ASN1_ENUMERATED *verifiedBootState;
    ASN1_OCTET_STRING *verifiedBootHash;
} KM_ROOT_OF_TRUST_V3;
DECLARE_ASN1_FUNCTIONS(KM_ROOT_OF_TRUST_V3);

#define ASN1_ROOT_OF_TRUST_V3 KM_ROOT_OF_TRUST_V3
#define ASN1_SET_OF_INTEGER STACK_OF(ASN1_INTEGER)

typedef struct KM_param_list {
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
typedef struct KM_KeyDescription_v3 {
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
} KM_KEY_DESC_V3;
DECLARE_ASN1_FUNCTIONS(KM_KEY_DESC_V3);

typedef const char * (*KM_enum_toString_proc_t)(uint32_t);

bool KM_Tag_is_repeatable(uint32_t tag);

const char * KM_TagType_toString(uint32_t tt);
const char * KM_Tag_toString(uint32_t t);

const char * KM_ErrorCode_toString(uint32_t o);
const char * KM_SecurityLevel_toString(uint32_t sl);
const char * KM_VerifiedBootState_toString(uint32_t vb);
const char * KM_KeyPurpose_toString(uint32_t kp);
const char * KM_Algorithm_toString(uint32_t alg);
const char * KM_BlockMode_toString(uint32_t bm);
const char * KM_Digest_toString(uint32_t dig);
const char * KM_PaddingMode_toString(uint32_t pm);
const char * KM_EcCurve_toString(uint32_t ec);
const char * KM_KeyOrigin_toString(uint32_t ko);
const char * KM_KeyBlobUsageRequirements_toString(uint32_t kbur);
const char * KM_KeyDerivationFunction_toString(uint32_t kdf);
const char * KM_HardwareAuthenticatorType_toString(uint32_t hwautht);

#ifdef __cplusplus
} /* namespace util */
} /* namespace kmhal */
} /* namespace suskeymaster */
} /* extern "C" */
#endif /* __cplusplus */

#endif /* KEYMASTER_TYPES_H_ */
