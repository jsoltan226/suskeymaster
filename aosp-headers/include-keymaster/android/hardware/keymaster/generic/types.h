#ifndef HIDL_GENERATED_ANDROID_HARDWARE_KEYMASTER_GENERIC_TYPES_H
#define HIDL_GENERATED_ANDROID_HARDWARE_KEYMASTER_GENERIC_TYPES_H

#include "../../../../../../libsuskmhal/util/km-tags-def.h"
#include <hidl/HidlSupport.h>
#include <hidl/MQDescriptor.h>
#include <utils/NativeHandle.h>
#include <utils/misc.h>
#include <cstdint>

namespace android {
namespace hardware {
namespace keymaster {
namespace generic {

// Forward declaration for forward reference support:
enum class Constants : uint32_t;
enum class TagType : uint32_t;
enum class Tag : uint32_t;
enum class Algorithm : uint32_t;
enum class BlockMode : uint32_t;
enum class PaddingMode : uint32_t;
enum class Digest : uint32_t;
enum class EcCurve : uint32_t;
enum class KeyOrigin : uint32_t;
enum class KeyBlobUsageRequirements : uint32_t;
enum class KeyPurpose : uint32_t;
enum class ErrorCode : int32_t;
enum class KeyDerivationFunction : uint32_t;
enum class HardwareAuthenticatorType : uint32_t;
enum class SecurityLevel : uint32_t;
enum class KeyFormat : uint32_t;
struct KeyParameter;
struct KeyCharacteristics;
struct HardwareAuthToken;
struct HmacSharingParameters;
struct VerificationToken;

/**
 * Time in milliseconds since some arbitrary point in time.  Time must be monotonically increasing,
 * and a secure environment's notion of "current time" must not repeat until the Android device
 * reboots, or until at least 50 million years have elapsed (note that this requirement is satisfied
 * by setting the clock to zero during each boot, and then counting time accurately).
 */
typedef uint64_t Timestamp;

/**
 * A place to define any needed constants.
 */
enum class Constants : uint32_t {
    AUTH_TOKEN_MAC_LENGTH = 32u,
};

enum class TagType : uint32_t {
    /**
     * Invalid type, used to designate a tag as uninitialized.
     */
    INVALID = 0u /* 0 << 28 */,
    /**
     * Enumeration value.
     */
    ENUM = 268435456u /* 1 << 28 */,
    /**
     * Repeatable enumeration value.
     */
    ENUM_REP = 536870912u /* 2 << 28 */,
    /**
     * 32-bit unsigned integer.
     */
    UINT = 805306368u /* 3 << 28 */,
    /**
     * Repeatable 32-bit unsigned integer.
     */
    UINT_REP = 1073741824u /* 4 << 28 */,
    /**
     * 64-bit unsigned integer.
     */
    ULONG = 1342177280u /* 5 << 28 */,
    /**
     * 64-bit unsigned integer representing a date and time, in milliseconds since 1 Jan 1970.
     */
    DATE = 1610612736u /* 6 << 28 */,
    /**
     * Boolean.  If a tag with this type is present, the value is "true".  If absent, "false".
     */
    BOOL = 1879048192u /* 7 << 28 */,
    /**
     * Byte string containing an arbitrary-length integer, big-endian ordering.
     */
    BIGNUM = 2147483648u /* 8 << 28 */,
    /**
     * Byte string
     */
    BYTES = 2415919104u /* 9 << 28 */,
    /**
     * Repeatable 64-bit unsigned integer
     */
    ULONG_REP = 2684354560u /* 10 << 28 */,
};

enum class Tag : uint32_t {
    INVALID = 0u,

#define KM_DECL_TAG(name, type, tag_val, param_list_field, bound_enum, asn1_type, asn1_rep) \
    name = static_cast<uint32_t>(TagType::type) | static_cast<uint32_t>(tag_val),

    KM_TAG_LIST__

#undef KM_DECL_TAG
};

/**
 * Algorithms provided by IKeymasterDevice implementations.
 */
enum class Algorithm : uint32_t {
    /**
     * Asymmetric algorithms.
     */
    RSA = 1u,
    EC = 3u,
    /**
     * Block cipher algorithms
     */
    AES = 32u,
    TRIPLE_DES = 33u,
    /**
     * MAC algorithms
     */
    HMAC = 128u,
};

/**
 * Symmetric block cipher modes provided by keymaster implementations.
 */
enum class BlockMode : uint32_t {
    /*
     * Unauthenticated modes, usable only for encryption/decryption and not generally recommended
     * except for compatibility with existing other protocols.
     */
    ECB = 1u,
    CBC = 2u,
    CTR = 3u,
    /*
     * Authenticated modes, usable for encryption/decryption and signing/verification.  Recommended
     * over unauthenticated modes for all purposes.
     */
    GCM = 32u,
};

/**
 * Padding modes that may be applied to plaintext for encryption operations.  This list includes
 * padding modes for both symmetric and asymmetric algorithms.  Note that implementations should not
 * provide all possible combinations of algorithm and padding, only the
 * cryptographically-appropriate pairs.
 */
enum class PaddingMode : uint32_t {
    NONE = 1u,
    /*
     * deprecated
     */
    RSA_OAEP = 2u,
    RSA_PSS = 3u,
    RSA_PKCS1_1_5_ENCRYPT = 4u,
    RSA_PKCS1_1_5_SIGN = 5u,
    PKCS7 = 64u,
};

/**
 * Digests provided by keymaster implementations.
 */
enum class Digest : uint32_t {
    NONE = 0u,
    MD5 = 1u,
    SHA1 = 2u,
    SHA_2_224 = 3u,
    SHA_2_256 = 4u,
    SHA_2_384 = 5u,
    SHA_2_512 = 6u,
};

/**
 * Supported EC curves, used in ECDSA
 */
enum class EcCurve : uint32_t {
    P_224 = 0u,
    P_256 = 1u,
    P_384 = 2u,
    P_521 = 3u,
};

/**
 * The origin of a key (or pair), i.e. where it was generated.  Note that ORIGIN can be found in
 * either the hardware-enforced or software-enforced list for a key, indicating whether the key is
 * hardware or software-based.  Specifically, a key with GENERATED in the hardware-enforced list
 * must be guaranteed never to have existed outide the secure hardware.
 */
enum class KeyOrigin : uint32_t {
    /**
     * Generated in keymaster.  Should not exist outside the TEE.
     */
    GENERATED = 0u,
    /**
     * Derived inside keymaster.  Likely exists off-device.
     */
    DERIVED = 1u,
    /**
     * Imported into keymaster.  Existed as cleartext in Android.
     */
    IMPORTED = 2u,
    /**
     * Keymaster did not record origin.  This value can only be seen on keys in a keymaster0
     * implementation.  The keymaster0 adapter uses this value to document the fact that it is
     * unkown whether the key was generated inside or imported into keymaster.
     */
    UNKNOWN = 3u,
    /**
     * Securely imported into Keymaster.  Was created elsewhere, and passed securely through Android
     * to secure hardware.
     */
    SECURELY_IMPORTED = 4u,
};

/**
 * Usability requirements of key blobs.  This defines what system functionality must be available
 * for the key to function.  For example, key "blobs" which are actually handles referencing
 * encrypted key material stored in the file system cannot be used until the file system is
 * available, and should have BLOB_REQUIRES_FILE_SYSTEM.
 */
enum class KeyBlobUsageRequirements : uint32_t {
    STANDALONE = 0u,
    REQUIRES_FILE_SYSTEM = 1u,
};

/**
 * Possible purposes of a key (or pair).
 */
enum class KeyPurpose : uint32_t {
    ENCRYPT = 0u,
    /*
     * Usable with RSA, EC and AES keys.
     */
    DECRYPT = 1u,
    /*
     * Usable with RSA, EC and AES keys.
     */
    SIGN = 2u,
    /*
     * Usable with RSA, EC and HMAC keys.
     */
    VERIFY = 3u,
    /*
     * Usable with RSA, EC and HMAC keys.
     *
     *
     * 4 is reserved
     */
    WRAP_KEY = 5u,
};

/**
 * Keymaster error codes.
 */
enum class ErrorCode : int32_t {
    OK = 0,
    ROOT_OF_TRUST_ALREADY_SET = -1 /* -1 */,
    UNSUPPORTED_PURPOSE = -2 /* -2 */,
    INCOMPATIBLE_PURPOSE = -3 /* -3 */,
    UNSUPPORTED_ALGORITHM = -4 /* -4 */,
    INCOMPATIBLE_ALGORITHM = -5 /* -5 */,
    UNSUPPORTED_KEY_SIZE = -6 /* -6 */,
    UNSUPPORTED_BLOCK_MODE = -7 /* -7 */,
    INCOMPATIBLE_BLOCK_MODE = -8 /* -8 */,
    UNSUPPORTED_MAC_LENGTH = -9 /* -9 */,
    UNSUPPORTED_PADDING_MODE = -10 /* -10 */,
    INCOMPATIBLE_PADDING_MODE = -11 /* -11 */,
    UNSUPPORTED_DIGEST = -12 /* -12 */,
    INCOMPATIBLE_DIGEST = -13 /* -13 */,
    INVALID_EXPIRATION_TIME = -14 /* -14 */,
    INVALID_USER_ID = -15 /* -15 */,
    INVALID_AUTHORIZATION_TIMEOUT = -16 /* -16 */,
    UNSUPPORTED_KEY_FORMAT = -17 /* -17 */,
    INCOMPATIBLE_KEY_FORMAT = -18 /* -18 */,
    UNSUPPORTED_KEY_ENCRYPTION_ALGORITHM = -19 /* -19 */,
    /**
     * For PKCS8 & PKCS12
     */
    UNSUPPORTED_KEY_VERIFICATION_ALGORITHM = -20 /* -20 */,
    /**
     * For PKCS8 & PKCS12
     */
    INVALID_INPUT_LENGTH = -21 /* -21 */,
    KEY_EXPORT_OPTIONS_INVALID = -22 /* -22 */,
    DELEGATION_NOT_ALLOWED = -23 /* -23 */,
    KEY_NOT_YET_VALID = -24 /* -24 */,
    KEY_EXPIRED = -25 /* -25 */,
    KEY_USER_NOT_AUTHENTICATED = -26 /* -26 */,
    OUTPUT_PARAMETER_NULL = -27 /* -27 */,
    INVALID_OPERATION_HANDLE = -28 /* -28 */,
    INSUFFICIENT_BUFFER_SPACE = -29 /* -29 */,
    VERIFICATION_FAILED = -30 /* -30 */,
    TOO_MANY_OPERATIONS = -31 /* -31 */,
    UNEXPECTED_NULL_POINTER = -32 /* -32 */,
    INVALID_KEY_BLOB = -33 /* -33 */,
    IMPORTED_KEY_NOT_ENCRYPTED = -34 /* -34 */,
    IMPORTED_KEY_DECRYPTION_FAILED = -35 /* -35 */,
    IMPORTED_KEY_NOT_SIGNED = -36 /* -36 */,
    IMPORTED_KEY_VERIFICATION_FAILED = -37 /* -37 */,
    INVALID_ARGUMENT = -38 /* -38 */,
    UNSUPPORTED_TAG = -39 /* -39 */,
    INVALID_TAG = -40 /* -40 */,
    MEMORY_ALLOCATION_FAILED = -41 /* -41 */,
    IMPORT_PARAMETER_MISMATCH = -44 /* -44 */,
    SECURE_HW_ACCESS_DENIED = -45 /* -45 */,
    OPERATION_CANCELLED = -46 /* -46 */,
    CONCURRENT_ACCESS_CONFLICT = -47 /* -47 */,
    SECURE_HW_BUSY = -48 /* -48 */,
    SECURE_HW_COMMUNICATION_FAILED = -49 /* -49 */,
    UNSUPPORTED_EC_FIELD = -50 /* -50 */,
    MISSING_NONCE = -51 /* -51 */,
    INVALID_NONCE = -52 /* -52 */,
    MISSING_MAC_LENGTH = -53 /* -53 */,
    KEY_RATE_LIMIT_EXCEEDED = -54 /* -54 */,
    CALLER_NONCE_PROHIBITED = -55 /* -55 */,
    KEY_MAX_OPS_EXCEEDED = -56 /* -56 */,
    INVALID_MAC_LENGTH = -57 /* -57 */,
    MISSING_MIN_MAC_LENGTH = -58 /* -58 */,
    UNSUPPORTED_MIN_MAC_LENGTH = -59 /* -59 */,
    UNSUPPORTED_KDF = -60 /* -60 */,
    UNSUPPORTED_EC_CURVE = -61 /* -61 */,
    KEY_REQUIRES_UPGRADE = -62 /* -62 */,
    ATTESTATION_CHALLENGE_MISSING = -63 /* -63 */,
    KEYMASTER_NOT_CONFIGURED = -64 /* -64 */,
    ATTESTATION_APPLICATION_ID_MISSING = -65 /* -65 */,
    CANNOT_ATTEST_IDS = -66 /* -66 */,
    ROLLBACK_RESISTANCE_UNAVAILABLE = -67 /* -67 */,
    HARDWARE_TYPE_UNAVAILABLE = -68 /* -68 */,
    PROOF_OF_PRESENCE_REQUIRED = -69 /* -69 */,
    CONCURRENT_PROOF_OF_PRESENCE_REQUESTED = -70 /* -70 */,
    NO_USER_CONFIRMATION = -71 /* -71 */,
    DEVICE_LOCKED = -72 /* -72 */,
    UNIMPLEMENTED = -100 /* -100 */,
    VERSION_MISMATCH = -101 /* -101 */,
    UNKNOWN_ERROR = -1000 /* -1000 */,
};

/**
 * Key derivation functions, mostly used in ECIES.
 */
enum class KeyDerivationFunction : uint32_t {
    /**
     * Do not apply a key derivation function; use the raw agreed key
     */
    NONE = 0u,
    /**
     * HKDF defined in RFC 5869 with SHA256
     */
    RFC5869_SHA256 = 1u,
    /**
     * KDF1 defined in ISO 18033-2 with SHA1
     */
    ISO18033_2_KDF1_SHA1 = 2u,
    /**
     * KDF1 defined in ISO 18033-2 with SHA256
     */
    ISO18033_2_KDF1_SHA256 = 3u,
    /**
     * KDF2 defined in ISO 18033-2 with SHA1
     */
    ISO18033_2_KDF2_SHA1 = 4u,
    /**
     * KDF2 defined in ISO 18033-2 with SHA256
     */
    ISO18033_2_KDF2_SHA256 = 5u,
};

/**
 * Hardware authentication type, used by HardwareAuthTokens to specify the mechanism used to
 * authentiate the user, and in KeyCharacteristics to specify the allowable mechanisms for
 * authenticating to activate a key.
 */
enum class HardwareAuthenticatorType : uint32_t {
    NONE = 0u,
    PASSWORD = 1u /* 1 << 0 */,
    FINGERPRINT = 2u /* 1 << 1 */,
    ANY = 4294967295u /* 0xFFFFFFFF */,
};

/**
 * Device security levels.
 */
enum class SecurityLevel : uint32_t {
    SOFTWARE = 0u,
    TRUSTED_ENVIRONMENT = 1u,
    /**
     * STRONGBOX specifies that the secure hardware satisfies the requirements specified in CDD
     * 9.11.2.
     */
    STRONGBOX = 2u,
};

/**
 * Formats for key import and export.
 */
enum class KeyFormat : uint32_t {
    /**
     * X.509 certificate format, for public key export.
     */
    X509 = 0u,
    /**
     * PCKS#8 format, asymmetric key pair import.
     */
    PKCS8 = 1u,
    /**
     * Raw bytes, for symmetric key import.
     */
    RAW = 3u,
};

struct KeyParameter final {
    // Forward declaration for forward reference support:
    union IntegerParams;

    union IntegerParams final {
        /*
         * Enum types
         */
        ::android::hardware::keymaster::generic::Algorithm algorithm __attribute__ ((aligned(4)));
        ::android::hardware::keymaster::generic::BlockMode blockMode __attribute__ ((aligned(4)));
        ::android::hardware::keymaster::generic::PaddingMode paddingMode __attribute__ ((aligned(4)));
        ::android::hardware::keymaster::generic::Digest digest __attribute__ ((aligned(4)));
        ::android::hardware::keymaster::generic::EcCurve ecCurve __attribute__ ((aligned(4)));
        ::android::hardware::keymaster::generic::KeyOrigin origin __attribute__ ((aligned(4)));
        ::android::hardware::keymaster::generic::KeyBlobUsageRequirements keyBlobUsageRequirements __attribute__ ((aligned(4)));
        ::android::hardware::keymaster::generic::KeyPurpose purpose __attribute__ ((aligned(4)));
        ::android::hardware::keymaster::generic::KeyDerivationFunction keyDerivationFunction __attribute__ ((aligned(4)));
        ::android::hardware::keymaster::generic::HardwareAuthenticatorType hardwareAuthenticatorType __attribute__ ((aligned(4)));
        ::android::hardware::keymaster::generic::SecurityLevel hardwareType __attribute__ ((aligned(4)));
        /*
         * Other types
         */
        bool boolValue __attribute__ ((aligned(1)));
        uint32_t integer __attribute__ ((aligned(4)));
        uint64_t longInteger __attribute__ ((aligned(8)));
        uint64_t dateTime __attribute__ ((aligned(8)));
    };


    /**
     * Discriminates the union/blob field used.  The blob cannot be placed in the union, but only
     * one of "f" and "blob" may ever be used at a time.
     */
    ::android::hardware::keymaster::generic::Tag tag __attribute__ ((aligned(4)));
    ::android::hardware::keymaster::generic::KeyParameter::IntegerParams f __attribute__ ((aligned(8)));
    ::android::hardware::hidl_vec<uint8_t> blob __attribute__ ((aligned(8)));
};

static_assert(offsetof(::android::hardware::keymaster::generic::KeyParameter, tag) == 0, "wrong offset");
static_assert(offsetof(::android::hardware::keymaster::generic::KeyParameter, f) == 8, "wrong offset");
static_assert(offsetof(::android::hardware::keymaster::generic::KeyParameter, blob) == 16, "wrong offset");
static_assert(sizeof(::android::hardware::keymaster::generic::KeyParameter) == 32, "wrong size");
static_assert(__alignof(::android::hardware::keymaster::generic::KeyParameter) == 8, "wrong alignment");

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
struct KeyCharacteristics final {
    ::android::hardware::hidl_vec<::android::hardware::keymaster::generic::KeyParameter> softwareEnforced __attribute__ ((aligned(8)));
    ::android::hardware::hidl_vec<::android::hardware::keymaster::generic::KeyParameter> hardwareEnforced __attribute__ ((aligned(8)));
};

static_assert(offsetof(::android::hardware::keymaster::generic::KeyCharacteristics, softwareEnforced) == 0, "wrong offset");
static_assert(offsetof(::android::hardware::keymaster::generic::KeyCharacteristics, hardwareEnforced) == 16, "wrong offset");
static_assert(sizeof(::android::hardware::keymaster::generic::KeyCharacteristics) == 32, "wrong size");
static_assert(__alignof(::android::hardware::keymaster::generic::KeyCharacteristics) == 8, "wrong alignment");

/**
 * HardwareAuthToken is used to prove successful user authentication, to unlock the use of a key.
 *
 * HardwareAuthTokens are produced by other secure environment applications, notably GateKeeper and
 * Fingerprint, in response to successful user authentication events.  These tokens are passed to
 * begin(), update(), and finish() to prove that authentication occurred.  See those methods for
 * more details.  It is up to the caller to determine which of the generated auth tokens is
 * appropriate for a given key operation.
 */
struct HardwareAuthToken final {
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
    ::android::hardware::keymaster::generic::HardwareAuthenticatorType authenticatorType __attribute__ ((aligned(4)));
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
    ::android::hardware::hidl_vec<uint8_t> mac __attribute__ ((aligned(8)));
};

static_assert(offsetof(::android::hardware::keymaster::generic::HardwareAuthToken, challenge) == 0, "wrong offset");
static_assert(offsetof(::android::hardware::keymaster::generic::HardwareAuthToken, userId) == 8, "wrong offset");
static_assert(offsetof(::android::hardware::keymaster::generic::HardwareAuthToken, authenticatorId) == 16, "wrong offset");
static_assert(offsetof(::android::hardware::keymaster::generic::HardwareAuthToken, authenticatorType) == 24, "wrong offset");
static_assert(offsetof(::android::hardware::keymaster::generic::HardwareAuthToken, timestamp) == 32, "wrong offset");
static_assert(offsetof(::android::hardware::keymaster::generic::HardwareAuthToken, mac) == 40, "wrong offset");
static_assert(sizeof(::android::hardware::keymaster::generic::HardwareAuthToken) == 56, "wrong size");
static_assert(__alignof(::android::hardware::keymaster::generic::HardwareAuthToken) == 8, "wrong alignment");

typedef uint64_t OperationHandle;

/**
 * HmacSharingParameters holds the data used in the process of establishing a shared HMAC key
 * between multiple Keymaster instances.  Sharing parameters are returned in this struct by
 * getHmacSharingParameters() and send to computeSharedHmac().  See the named methods in IKeymaster
 * for details of usage.
 */
struct HmacSharingParameters final {
    /**
     * Either empty or contains a persistent value that is associated with the pre-shared HMAC
     * agreement key (see documentation of computeSharedHmac in @4.0::IKeymaster).  It is either
     * empty or 32 bytes in length.
     */
    ::android::hardware::hidl_vec<uint8_t> seed __attribute__ ((aligned(8)));
    /**
     * A 32-byte value which is guaranteed to be different each time
     * getHmacSharingParameters() is called.  Probabilistic uniqueness (i.e. random) is acceptable,
     * though a stronger uniqueness guarantee (e.g. counter) is recommended where possible.
     */
    ::android::hardware::hidl_array<uint8_t, 32> nonce __attribute__ ((aligned(1)));
};

static_assert(offsetof(::android::hardware::keymaster::generic::HmacSharingParameters, seed) == 0, "wrong offset");
static_assert(offsetof(::android::hardware::keymaster::generic::HmacSharingParameters, nonce) == 16, "wrong offset");
static_assert(sizeof(::android::hardware::keymaster::generic::HmacSharingParameters) == 48, "wrong size");
static_assert(__alignof(::android::hardware::keymaster::generic::HmacSharingParameters) == 8, "wrong alignment");

/**
 * VerificationToken enables one Keymaster instance to validate authorizations for another.  See
 * verifyAuthorizations() in IKeymaster for details.
 */
struct VerificationToken final {
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
    ::android::hardware::hidl_vec<::android::hardware::keymaster::generic::KeyParameter> parametersVerified __attribute__ ((aligned(8)));
    /**
     * SecurityLevel of the secure environment that generated the token.
     */
    ::android::hardware::keymaster::generic::SecurityLevel securityLevel __attribute__ ((aligned(4)));
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
    ::android::hardware::hidl_vec<uint8_t> mac __attribute__ ((aligned(8)));
};

static_assert(offsetof(::android::hardware::keymaster::generic::VerificationToken, challenge) == 0, "wrong offset");
static_assert(offsetof(::android::hardware::keymaster::generic::VerificationToken, timestamp) == 8, "wrong offset");
static_assert(offsetof(::android::hardware::keymaster::generic::VerificationToken, parametersVerified) == 16, "wrong offset");
static_assert(offsetof(::android::hardware::keymaster::generic::VerificationToken, securityLevel) == 32, "wrong offset");
static_assert(offsetof(::android::hardware::keymaster::generic::VerificationToken, mac) == 40, "wrong offset");
static_assert(sizeof(::android::hardware::keymaster::generic::VerificationToken) == 56, "wrong size");
static_assert(__alignof(::android::hardware::keymaster::generic::VerificationToken) == 8, "wrong alignment");

//
// type declarations for package
//

template<typename>
static inline std::string toString(uint32_t o);
static inline std::string toString(::android::hardware::keymaster::generic::Constants o);
static inline void PrintTo(::android::hardware::keymaster::generic::Constants o, ::std::ostream* os);
constexpr uint32_t operator|(const ::android::hardware::keymaster::generic::Constants lhs, const ::android::hardware::keymaster::generic::Constants rhs) {
    return static_cast<uint32_t>(static_cast<uint32_t>(lhs) | static_cast<uint32_t>(rhs));
}
constexpr uint32_t operator|(const uint32_t lhs, const ::android::hardware::keymaster::generic::Constants rhs) {
    return static_cast<uint32_t>(lhs | static_cast<uint32_t>(rhs));
}
constexpr uint32_t operator|(const ::android::hardware::keymaster::generic::Constants lhs, const uint32_t rhs) {
    return static_cast<uint32_t>(static_cast<uint32_t>(lhs) | rhs);
}
constexpr uint32_t operator&(const ::android::hardware::keymaster::generic::Constants lhs, const ::android::hardware::keymaster::generic::Constants rhs) {
    return static_cast<uint32_t>(static_cast<uint32_t>(lhs) & static_cast<uint32_t>(rhs));
}
constexpr uint32_t operator&(const uint32_t lhs, const ::android::hardware::keymaster::generic::Constants rhs) {
    return static_cast<uint32_t>(lhs & static_cast<uint32_t>(rhs));
}
constexpr uint32_t operator&(const ::android::hardware::keymaster::generic::Constants lhs, const uint32_t rhs) {
    return static_cast<uint32_t>(static_cast<uint32_t>(lhs) & rhs);
}
constexpr uint32_t &operator|=(uint32_t& v, const ::android::hardware::keymaster::generic::Constants e) {
    v |= static_cast<uint32_t>(e);
    return v;
}
constexpr uint32_t &operator&=(uint32_t& v, const ::android::hardware::keymaster::generic::Constants e) {
    v &= static_cast<uint32_t>(e);
    return v;
}

template<typename>
static inline std::string toString(uint32_t o);
static inline std::string toString(::android::hardware::keymaster::generic::TagType o);
static inline void PrintTo(::android::hardware::keymaster::generic::TagType o, ::std::ostream* os);
constexpr uint32_t operator|(const ::android::hardware::keymaster::generic::TagType lhs, const ::android::hardware::keymaster::generic::TagType rhs) {
    return static_cast<uint32_t>(static_cast<uint32_t>(lhs) | static_cast<uint32_t>(rhs));
}
constexpr uint32_t operator|(const uint32_t lhs, const ::android::hardware::keymaster::generic::TagType rhs) {
    return static_cast<uint32_t>(lhs | static_cast<uint32_t>(rhs));
}
constexpr uint32_t operator|(const ::android::hardware::keymaster::generic::TagType lhs, const uint32_t rhs) {
    return static_cast<uint32_t>(static_cast<uint32_t>(lhs) | rhs);
}
constexpr uint32_t operator&(const ::android::hardware::keymaster::generic::TagType lhs, const ::android::hardware::keymaster::generic::TagType rhs) {
    return static_cast<uint32_t>(static_cast<uint32_t>(lhs) & static_cast<uint32_t>(rhs));
}
constexpr uint32_t operator&(const uint32_t lhs, const ::android::hardware::keymaster::generic::TagType rhs) {
    return static_cast<uint32_t>(lhs & static_cast<uint32_t>(rhs));
}
constexpr uint32_t operator&(const ::android::hardware::keymaster::generic::TagType lhs, const uint32_t rhs) {
    return static_cast<uint32_t>(static_cast<uint32_t>(lhs) & rhs);
}
constexpr uint32_t &operator|=(uint32_t& v, const ::android::hardware::keymaster::generic::TagType e) {
    v |= static_cast<uint32_t>(e);
    return v;
}
constexpr uint32_t &operator&=(uint32_t& v, const ::android::hardware::keymaster::generic::TagType e) {
    v &= static_cast<uint32_t>(e);
    return v;
}

template<typename>
static inline std::string toString(uint32_t o);
static inline std::string toString(::android::hardware::keymaster::generic::Tag o);
static inline void PrintTo(::android::hardware::keymaster::generic::Tag o, ::std::ostream* os);
constexpr uint32_t operator|(const ::android::hardware::keymaster::generic::Tag lhs, const ::android::hardware::keymaster::generic::Tag rhs) {
    return static_cast<uint32_t>(static_cast<uint32_t>(lhs) | static_cast<uint32_t>(rhs));
}
constexpr uint32_t operator|(const uint32_t lhs, const ::android::hardware::keymaster::generic::Tag rhs) {
    return static_cast<uint32_t>(lhs | static_cast<uint32_t>(rhs));
}
constexpr uint32_t operator|(const ::android::hardware::keymaster::generic::Tag lhs, const uint32_t rhs) {
    return static_cast<uint32_t>(static_cast<uint32_t>(lhs) | rhs);
}
constexpr uint32_t operator&(const ::android::hardware::keymaster::generic::Tag lhs, const ::android::hardware::keymaster::generic::Tag rhs) {
    return static_cast<uint32_t>(static_cast<uint32_t>(lhs) & static_cast<uint32_t>(rhs));
}
constexpr uint32_t operator&(const uint32_t lhs, const ::android::hardware::keymaster::generic::Tag rhs) {
    return static_cast<uint32_t>(lhs & static_cast<uint32_t>(rhs));
}
constexpr uint32_t operator&(const ::android::hardware::keymaster::generic::Tag lhs, const uint32_t rhs) {
    return static_cast<uint32_t>(static_cast<uint32_t>(lhs) & rhs);
}
constexpr uint32_t &operator|=(uint32_t& v, const ::android::hardware::keymaster::generic::Tag e) {
    v |= static_cast<uint32_t>(e);
    return v;
}
constexpr uint32_t &operator&=(uint32_t& v, const ::android::hardware::keymaster::generic::Tag e) {
    v &= static_cast<uint32_t>(e);
    return v;
}

template<typename>
static inline std::string toString(uint32_t o);
static inline std::string toString(::android::hardware::keymaster::generic::Algorithm o);
static inline void PrintTo(::android::hardware::keymaster::generic::Algorithm o, ::std::ostream* os);
constexpr uint32_t operator|(const ::android::hardware::keymaster::generic::Algorithm lhs, const ::android::hardware::keymaster::generic::Algorithm rhs) {
    return static_cast<uint32_t>(static_cast<uint32_t>(lhs) | static_cast<uint32_t>(rhs));
}
constexpr uint32_t operator|(const uint32_t lhs, const ::android::hardware::keymaster::generic::Algorithm rhs) {
    return static_cast<uint32_t>(lhs | static_cast<uint32_t>(rhs));
}
constexpr uint32_t operator|(const ::android::hardware::keymaster::generic::Algorithm lhs, const uint32_t rhs) {
    return static_cast<uint32_t>(static_cast<uint32_t>(lhs) | rhs);
}
constexpr uint32_t operator&(const ::android::hardware::keymaster::generic::Algorithm lhs, const ::android::hardware::keymaster::generic::Algorithm rhs) {
    return static_cast<uint32_t>(static_cast<uint32_t>(lhs) & static_cast<uint32_t>(rhs));
}
constexpr uint32_t operator&(const uint32_t lhs, const ::android::hardware::keymaster::generic::Algorithm rhs) {
    return static_cast<uint32_t>(lhs & static_cast<uint32_t>(rhs));
}
constexpr uint32_t operator&(const ::android::hardware::keymaster::generic::Algorithm lhs, const uint32_t rhs) {
    return static_cast<uint32_t>(static_cast<uint32_t>(lhs) & rhs);
}
constexpr uint32_t &operator|=(uint32_t& v, const ::android::hardware::keymaster::generic::Algorithm e) {
    v |= static_cast<uint32_t>(e);
    return v;
}
constexpr uint32_t &operator&=(uint32_t& v, const ::android::hardware::keymaster::generic::Algorithm e) {
    v &= static_cast<uint32_t>(e);
    return v;
}

template<typename>
static inline std::string toString(uint32_t o);
static inline std::string toString(::android::hardware::keymaster::generic::BlockMode o);
static inline void PrintTo(::android::hardware::keymaster::generic::BlockMode o, ::std::ostream* os);
constexpr uint32_t operator|(const ::android::hardware::keymaster::generic::BlockMode lhs, const ::android::hardware::keymaster::generic::BlockMode rhs) {
    return static_cast<uint32_t>(static_cast<uint32_t>(lhs) | static_cast<uint32_t>(rhs));
}
constexpr uint32_t operator|(const uint32_t lhs, const ::android::hardware::keymaster::generic::BlockMode rhs) {
    return static_cast<uint32_t>(lhs | static_cast<uint32_t>(rhs));
}
constexpr uint32_t operator|(const ::android::hardware::keymaster::generic::BlockMode lhs, const uint32_t rhs) {
    return static_cast<uint32_t>(static_cast<uint32_t>(lhs) | rhs);
}
constexpr uint32_t operator&(const ::android::hardware::keymaster::generic::BlockMode lhs, const ::android::hardware::keymaster::generic::BlockMode rhs) {
    return static_cast<uint32_t>(static_cast<uint32_t>(lhs) & static_cast<uint32_t>(rhs));
}
constexpr uint32_t operator&(const uint32_t lhs, const ::android::hardware::keymaster::generic::BlockMode rhs) {
    return static_cast<uint32_t>(lhs & static_cast<uint32_t>(rhs));
}
constexpr uint32_t operator&(const ::android::hardware::keymaster::generic::BlockMode lhs, const uint32_t rhs) {
    return static_cast<uint32_t>(static_cast<uint32_t>(lhs) & rhs);
}
constexpr uint32_t &operator|=(uint32_t& v, const ::android::hardware::keymaster::generic::BlockMode e) {
    v |= static_cast<uint32_t>(e);
    return v;
}
constexpr uint32_t &operator&=(uint32_t& v, const ::android::hardware::keymaster::generic::BlockMode e) {
    v &= static_cast<uint32_t>(e);
    return v;
}

template<typename>
static inline std::string toString(uint32_t o);
static inline std::string toString(::android::hardware::keymaster::generic::PaddingMode o);
static inline void PrintTo(::android::hardware::keymaster::generic::PaddingMode o, ::std::ostream* os);
constexpr uint32_t operator|(const ::android::hardware::keymaster::generic::PaddingMode lhs, const ::android::hardware::keymaster::generic::PaddingMode rhs) {
    return static_cast<uint32_t>(static_cast<uint32_t>(lhs) | static_cast<uint32_t>(rhs));
}
constexpr uint32_t operator|(const uint32_t lhs, const ::android::hardware::keymaster::generic::PaddingMode rhs) {
    return static_cast<uint32_t>(lhs | static_cast<uint32_t>(rhs));
}
constexpr uint32_t operator|(const ::android::hardware::keymaster::generic::PaddingMode lhs, const uint32_t rhs) {
    return static_cast<uint32_t>(static_cast<uint32_t>(lhs) | rhs);
}
constexpr uint32_t operator&(const ::android::hardware::keymaster::generic::PaddingMode lhs, const ::android::hardware::keymaster::generic::PaddingMode rhs) {
    return static_cast<uint32_t>(static_cast<uint32_t>(lhs) & static_cast<uint32_t>(rhs));
}
constexpr uint32_t operator&(const uint32_t lhs, const ::android::hardware::keymaster::generic::PaddingMode rhs) {
    return static_cast<uint32_t>(lhs & static_cast<uint32_t>(rhs));
}
constexpr uint32_t operator&(const ::android::hardware::keymaster::generic::PaddingMode lhs, const uint32_t rhs) {
    return static_cast<uint32_t>(static_cast<uint32_t>(lhs) & rhs);
}
constexpr uint32_t &operator|=(uint32_t& v, const ::android::hardware::keymaster::generic::PaddingMode e) {
    v |= static_cast<uint32_t>(e);
    return v;
}
constexpr uint32_t &operator&=(uint32_t& v, const ::android::hardware::keymaster::generic::PaddingMode e) {
    v &= static_cast<uint32_t>(e);
    return v;
}

template<typename>
static inline std::string toString(uint32_t o);
static inline std::string toString(::android::hardware::keymaster::generic::Digest o);
static inline void PrintTo(::android::hardware::keymaster::generic::Digest o, ::std::ostream* os);
constexpr uint32_t operator|(const ::android::hardware::keymaster::generic::Digest lhs, const ::android::hardware::keymaster::generic::Digest rhs) {
    return static_cast<uint32_t>(static_cast<uint32_t>(lhs) | static_cast<uint32_t>(rhs));
}
constexpr uint32_t operator|(const uint32_t lhs, const ::android::hardware::keymaster::generic::Digest rhs) {
    return static_cast<uint32_t>(lhs | static_cast<uint32_t>(rhs));
}
constexpr uint32_t operator|(const ::android::hardware::keymaster::generic::Digest lhs, const uint32_t rhs) {
    return static_cast<uint32_t>(static_cast<uint32_t>(lhs) | rhs);
}
constexpr uint32_t operator&(const ::android::hardware::keymaster::generic::Digest lhs, const ::android::hardware::keymaster::generic::Digest rhs) {
    return static_cast<uint32_t>(static_cast<uint32_t>(lhs) & static_cast<uint32_t>(rhs));
}
constexpr uint32_t operator&(const uint32_t lhs, const ::android::hardware::keymaster::generic::Digest rhs) {
    return static_cast<uint32_t>(lhs & static_cast<uint32_t>(rhs));
}
constexpr uint32_t operator&(const ::android::hardware::keymaster::generic::Digest lhs, const uint32_t rhs) {
    return static_cast<uint32_t>(static_cast<uint32_t>(lhs) & rhs);
}
constexpr uint32_t &operator|=(uint32_t& v, const ::android::hardware::keymaster::generic::Digest e) {
    v |= static_cast<uint32_t>(e);
    return v;
}
constexpr uint32_t &operator&=(uint32_t& v, const ::android::hardware::keymaster::generic::Digest e) {
    v &= static_cast<uint32_t>(e);
    return v;
}

template<typename>
static inline std::string toString(uint32_t o);
static inline std::string toString(::android::hardware::keymaster::generic::EcCurve o);
static inline void PrintTo(::android::hardware::keymaster::generic::EcCurve o, ::std::ostream* os);
constexpr uint32_t operator|(const ::android::hardware::keymaster::generic::EcCurve lhs, const ::android::hardware::keymaster::generic::EcCurve rhs) {
    return static_cast<uint32_t>(static_cast<uint32_t>(lhs) | static_cast<uint32_t>(rhs));
}
constexpr uint32_t operator|(const uint32_t lhs, const ::android::hardware::keymaster::generic::EcCurve rhs) {
    return static_cast<uint32_t>(lhs | static_cast<uint32_t>(rhs));
}
constexpr uint32_t operator|(const ::android::hardware::keymaster::generic::EcCurve lhs, const uint32_t rhs) {
    return static_cast<uint32_t>(static_cast<uint32_t>(lhs) | rhs);
}
constexpr uint32_t operator&(const ::android::hardware::keymaster::generic::EcCurve lhs, const ::android::hardware::keymaster::generic::EcCurve rhs) {
    return static_cast<uint32_t>(static_cast<uint32_t>(lhs) & static_cast<uint32_t>(rhs));
}
constexpr uint32_t operator&(const uint32_t lhs, const ::android::hardware::keymaster::generic::EcCurve rhs) {
    return static_cast<uint32_t>(lhs & static_cast<uint32_t>(rhs));
}
constexpr uint32_t operator&(const ::android::hardware::keymaster::generic::EcCurve lhs, const uint32_t rhs) {
    return static_cast<uint32_t>(static_cast<uint32_t>(lhs) & rhs);
}
constexpr uint32_t &operator|=(uint32_t& v, const ::android::hardware::keymaster::generic::EcCurve e) {
    v |= static_cast<uint32_t>(e);
    return v;
}
constexpr uint32_t &operator&=(uint32_t& v, const ::android::hardware::keymaster::generic::EcCurve e) {
    v &= static_cast<uint32_t>(e);
    return v;
}

template<typename>
static inline std::string toString(uint32_t o);
static inline std::string toString(::android::hardware::keymaster::generic::KeyOrigin o);
static inline void PrintTo(::android::hardware::keymaster::generic::KeyOrigin o, ::std::ostream* os);
constexpr uint32_t operator|(const ::android::hardware::keymaster::generic::KeyOrigin lhs, const ::android::hardware::keymaster::generic::KeyOrigin rhs) {
    return static_cast<uint32_t>(static_cast<uint32_t>(lhs) | static_cast<uint32_t>(rhs));
}
constexpr uint32_t operator|(const uint32_t lhs, const ::android::hardware::keymaster::generic::KeyOrigin rhs) {
    return static_cast<uint32_t>(lhs | static_cast<uint32_t>(rhs));
}
constexpr uint32_t operator|(const ::android::hardware::keymaster::generic::KeyOrigin lhs, const uint32_t rhs) {
    return static_cast<uint32_t>(static_cast<uint32_t>(lhs) | rhs);
}
constexpr uint32_t operator&(const ::android::hardware::keymaster::generic::KeyOrigin lhs, const ::android::hardware::keymaster::generic::KeyOrigin rhs) {
    return static_cast<uint32_t>(static_cast<uint32_t>(lhs) & static_cast<uint32_t>(rhs));
}
constexpr uint32_t operator&(const uint32_t lhs, const ::android::hardware::keymaster::generic::KeyOrigin rhs) {
    return static_cast<uint32_t>(lhs & static_cast<uint32_t>(rhs));
}
constexpr uint32_t operator&(const ::android::hardware::keymaster::generic::KeyOrigin lhs, const uint32_t rhs) {
    return static_cast<uint32_t>(static_cast<uint32_t>(lhs) & rhs);
}
constexpr uint32_t &operator|=(uint32_t& v, const ::android::hardware::keymaster::generic::KeyOrigin e) {
    v |= static_cast<uint32_t>(e);
    return v;
}
constexpr uint32_t &operator&=(uint32_t& v, const ::android::hardware::keymaster::generic::KeyOrigin e) {
    v &= static_cast<uint32_t>(e);
    return v;
}

template<typename>
static inline std::string toString(uint32_t o);
static inline std::string toString(::android::hardware::keymaster::generic::KeyBlobUsageRequirements o);
static inline void PrintTo(::android::hardware::keymaster::generic::KeyBlobUsageRequirements o, ::std::ostream* os);
constexpr uint32_t operator|(const ::android::hardware::keymaster::generic::KeyBlobUsageRequirements lhs, const ::android::hardware::keymaster::generic::KeyBlobUsageRequirements rhs) {
    return static_cast<uint32_t>(static_cast<uint32_t>(lhs) | static_cast<uint32_t>(rhs));
}
constexpr uint32_t operator|(const uint32_t lhs, const ::android::hardware::keymaster::generic::KeyBlobUsageRequirements rhs) {
    return static_cast<uint32_t>(lhs | static_cast<uint32_t>(rhs));
}
constexpr uint32_t operator|(const ::android::hardware::keymaster::generic::KeyBlobUsageRequirements lhs, const uint32_t rhs) {
    return static_cast<uint32_t>(static_cast<uint32_t>(lhs) | rhs);
}
constexpr uint32_t operator&(const ::android::hardware::keymaster::generic::KeyBlobUsageRequirements lhs, const ::android::hardware::keymaster::generic::KeyBlobUsageRequirements rhs) {
    return static_cast<uint32_t>(static_cast<uint32_t>(lhs) & static_cast<uint32_t>(rhs));
}
constexpr uint32_t operator&(const uint32_t lhs, const ::android::hardware::keymaster::generic::KeyBlobUsageRequirements rhs) {
    return static_cast<uint32_t>(lhs & static_cast<uint32_t>(rhs));
}
constexpr uint32_t operator&(const ::android::hardware::keymaster::generic::KeyBlobUsageRequirements lhs, const uint32_t rhs) {
    return static_cast<uint32_t>(static_cast<uint32_t>(lhs) & rhs);
}
constexpr uint32_t &operator|=(uint32_t& v, const ::android::hardware::keymaster::generic::KeyBlobUsageRequirements e) {
    v |= static_cast<uint32_t>(e);
    return v;
}
constexpr uint32_t &operator&=(uint32_t& v, const ::android::hardware::keymaster::generic::KeyBlobUsageRequirements e) {
    v &= static_cast<uint32_t>(e);
    return v;
}

template<typename>
static inline std::string toString(uint32_t o);
static inline std::string toString(::android::hardware::keymaster::generic::KeyPurpose o);
static inline void PrintTo(::android::hardware::keymaster::generic::KeyPurpose o, ::std::ostream* os);
constexpr uint32_t operator|(const ::android::hardware::keymaster::generic::KeyPurpose lhs, const ::android::hardware::keymaster::generic::KeyPurpose rhs) {
    return static_cast<uint32_t>(static_cast<uint32_t>(lhs) | static_cast<uint32_t>(rhs));
}
constexpr uint32_t operator|(const uint32_t lhs, const ::android::hardware::keymaster::generic::KeyPurpose rhs) {
    return static_cast<uint32_t>(lhs | static_cast<uint32_t>(rhs));
}
constexpr uint32_t operator|(const ::android::hardware::keymaster::generic::KeyPurpose lhs, const uint32_t rhs) {
    return static_cast<uint32_t>(static_cast<uint32_t>(lhs) | rhs);
}
constexpr uint32_t operator&(const ::android::hardware::keymaster::generic::KeyPurpose lhs, const ::android::hardware::keymaster::generic::KeyPurpose rhs) {
    return static_cast<uint32_t>(static_cast<uint32_t>(lhs) & static_cast<uint32_t>(rhs));
}
constexpr uint32_t operator&(const uint32_t lhs, const ::android::hardware::keymaster::generic::KeyPurpose rhs) {
    return static_cast<uint32_t>(lhs & static_cast<uint32_t>(rhs));
}
constexpr uint32_t operator&(const ::android::hardware::keymaster::generic::KeyPurpose lhs, const uint32_t rhs) {
    return static_cast<uint32_t>(static_cast<uint32_t>(lhs) & rhs);
}
constexpr uint32_t &operator|=(uint32_t& v, const ::android::hardware::keymaster::generic::KeyPurpose e) {
    v |= static_cast<uint32_t>(e);
    return v;
}
constexpr uint32_t &operator&=(uint32_t& v, const ::android::hardware::keymaster::generic::KeyPurpose e) {
    v &= static_cast<uint32_t>(e);
    return v;
}

template<typename>
static inline std::string toString(int32_t o);
static inline std::string toString(::android::hardware::keymaster::generic::ErrorCode o);
static inline void PrintTo(::android::hardware::keymaster::generic::ErrorCode o, ::std::ostream* os);
constexpr int32_t operator|(const ::android::hardware::keymaster::generic::ErrorCode lhs, const ::android::hardware::keymaster::generic::ErrorCode rhs) {
    return static_cast<int32_t>(static_cast<int32_t>(lhs) | static_cast<int32_t>(rhs));
}
constexpr int32_t operator|(const int32_t lhs, const ::android::hardware::keymaster::generic::ErrorCode rhs) {
    return static_cast<int32_t>(lhs | static_cast<int32_t>(rhs));
}
constexpr int32_t operator|(const ::android::hardware::keymaster::generic::ErrorCode lhs, const int32_t rhs) {
    return static_cast<int32_t>(static_cast<int32_t>(lhs) | rhs);
}
constexpr int32_t operator&(const ::android::hardware::keymaster::generic::ErrorCode lhs, const ::android::hardware::keymaster::generic::ErrorCode rhs) {
    return static_cast<int32_t>(static_cast<int32_t>(lhs) & static_cast<int32_t>(rhs));
}
constexpr int32_t operator&(const int32_t lhs, const ::android::hardware::keymaster::generic::ErrorCode rhs) {
    return static_cast<int32_t>(lhs & static_cast<int32_t>(rhs));
}
constexpr int32_t operator&(const ::android::hardware::keymaster::generic::ErrorCode lhs, const int32_t rhs) {
    return static_cast<int32_t>(static_cast<int32_t>(lhs) & rhs);
}
constexpr int32_t &operator|=(int32_t& v, const ::android::hardware::keymaster::generic::ErrorCode e) {
    v |= static_cast<int32_t>(e);
    return v;
}
constexpr int32_t &operator&=(int32_t& v, const ::android::hardware::keymaster::generic::ErrorCode e) {
    v &= static_cast<int32_t>(e);
    return v;
}

template<typename>
static inline std::string toString(uint32_t o);
static inline std::string toString(::android::hardware::keymaster::generic::KeyDerivationFunction o);
static inline void PrintTo(::android::hardware::keymaster::generic::KeyDerivationFunction o, ::std::ostream* os);
constexpr uint32_t operator|(const ::android::hardware::keymaster::generic::KeyDerivationFunction lhs, const ::android::hardware::keymaster::generic::KeyDerivationFunction rhs) {
    return static_cast<uint32_t>(static_cast<uint32_t>(lhs) | static_cast<uint32_t>(rhs));
}
constexpr uint32_t operator|(const uint32_t lhs, const ::android::hardware::keymaster::generic::KeyDerivationFunction rhs) {
    return static_cast<uint32_t>(lhs | static_cast<uint32_t>(rhs));
}
constexpr uint32_t operator|(const ::android::hardware::keymaster::generic::KeyDerivationFunction lhs, const uint32_t rhs) {
    return static_cast<uint32_t>(static_cast<uint32_t>(lhs) | rhs);
}
constexpr uint32_t operator&(const ::android::hardware::keymaster::generic::KeyDerivationFunction lhs, const ::android::hardware::keymaster::generic::KeyDerivationFunction rhs) {
    return static_cast<uint32_t>(static_cast<uint32_t>(lhs) & static_cast<uint32_t>(rhs));
}
constexpr uint32_t operator&(const uint32_t lhs, const ::android::hardware::keymaster::generic::KeyDerivationFunction rhs) {
    return static_cast<uint32_t>(lhs & static_cast<uint32_t>(rhs));
}
constexpr uint32_t operator&(const ::android::hardware::keymaster::generic::KeyDerivationFunction lhs, const uint32_t rhs) {
    return static_cast<uint32_t>(static_cast<uint32_t>(lhs) & rhs);
}
constexpr uint32_t &operator|=(uint32_t& v, const ::android::hardware::keymaster::generic::KeyDerivationFunction e) {
    v |= static_cast<uint32_t>(e);
    return v;
}
constexpr uint32_t &operator&=(uint32_t& v, const ::android::hardware::keymaster::generic::KeyDerivationFunction e) {
    v &= static_cast<uint32_t>(e);
    return v;
}

template<typename>
static inline std::string toString(uint32_t o);
static inline std::string toString(::android::hardware::keymaster::generic::HardwareAuthenticatorType o);
static inline void PrintTo(::android::hardware::keymaster::generic::HardwareAuthenticatorType o, ::std::ostream* os);
constexpr uint32_t operator|(const ::android::hardware::keymaster::generic::HardwareAuthenticatorType lhs, const ::android::hardware::keymaster::generic::HardwareAuthenticatorType rhs) {
    return static_cast<uint32_t>(static_cast<uint32_t>(lhs) | static_cast<uint32_t>(rhs));
}
constexpr uint32_t operator|(const uint32_t lhs, const ::android::hardware::keymaster::generic::HardwareAuthenticatorType rhs) {
    return static_cast<uint32_t>(lhs | static_cast<uint32_t>(rhs));
}
constexpr uint32_t operator|(const ::android::hardware::keymaster::generic::HardwareAuthenticatorType lhs, const uint32_t rhs) {
    return static_cast<uint32_t>(static_cast<uint32_t>(lhs) | rhs);
}
constexpr uint32_t operator&(const ::android::hardware::keymaster::generic::HardwareAuthenticatorType lhs, const ::android::hardware::keymaster::generic::HardwareAuthenticatorType rhs) {
    return static_cast<uint32_t>(static_cast<uint32_t>(lhs) & static_cast<uint32_t>(rhs));
}
constexpr uint32_t operator&(const uint32_t lhs, const ::android::hardware::keymaster::generic::HardwareAuthenticatorType rhs) {
    return static_cast<uint32_t>(lhs & static_cast<uint32_t>(rhs));
}
constexpr uint32_t operator&(const ::android::hardware::keymaster::generic::HardwareAuthenticatorType lhs, const uint32_t rhs) {
    return static_cast<uint32_t>(static_cast<uint32_t>(lhs) & rhs);
}
constexpr uint32_t &operator|=(uint32_t& v, const ::android::hardware::keymaster::generic::HardwareAuthenticatorType e) {
    v |= static_cast<uint32_t>(e);
    return v;
}
constexpr uint32_t &operator&=(uint32_t& v, const ::android::hardware::keymaster::generic::HardwareAuthenticatorType e) {
    v &= static_cast<uint32_t>(e);
    return v;
}

template<typename>
static inline std::string toString(uint32_t o);
static inline std::string toString(::android::hardware::keymaster::generic::SecurityLevel o);
static inline void PrintTo(::android::hardware::keymaster::generic::SecurityLevel o, ::std::ostream* os);
constexpr uint32_t operator|(const ::android::hardware::keymaster::generic::SecurityLevel lhs, const ::android::hardware::keymaster::generic::SecurityLevel rhs) {
    return static_cast<uint32_t>(static_cast<uint32_t>(lhs) | static_cast<uint32_t>(rhs));
}
constexpr uint32_t operator|(const uint32_t lhs, const ::android::hardware::keymaster::generic::SecurityLevel rhs) {
    return static_cast<uint32_t>(lhs | static_cast<uint32_t>(rhs));
}
constexpr uint32_t operator|(const ::android::hardware::keymaster::generic::SecurityLevel lhs, const uint32_t rhs) {
    return static_cast<uint32_t>(static_cast<uint32_t>(lhs) | rhs);
}
constexpr uint32_t operator&(const ::android::hardware::keymaster::generic::SecurityLevel lhs, const ::android::hardware::keymaster::generic::SecurityLevel rhs) {
    return static_cast<uint32_t>(static_cast<uint32_t>(lhs) & static_cast<uint32_t>(rhs));
}
constexpr uint32_t operator&(const uint32_t lhs, const ::android::hardware::keymaster::generic::SecurityLevel rhs) {
    return static_cast<uint32_t>(lhs & static_cast<uint32_t>(rhs));
}
constexpr uint32_t operator&(const ::android::hardware::keymaster::generic::SecurityLevel lhs, const uint32_t rhs) {
    return static_cast<uint32_t>(static_cast<uint32_t>(lhs) & rhs);
}
constexpr uint32_t &operator|=(uint32_t& v, const ::android::hardware::keymaster::generic::SecurityLevel e) {
    v |= static_cast<uint32_t>(e);
    return v;
}
constexpr uint32_t &operator&=(uint32_t& v, const ::android::hardware::keymaster::generic::SecurityLevel e) {
    v &= static_cast<uint32_t>(e);
    return v;
}

template<typename>
static inline std::string toString(uint32_t o);
static inline std::string toString(::android::hardware::keymaster::generic::KeyFormat o);
static inline void PrintTo(::android::hardware::keymaster::generic::KeyFormat o, ::std::ostream* os);
constexpr uint32_t operator|(const ::android::hardware::keymaster::generic::KeyFormat lhs, const ::android::hardware::keymaster::generic::KeyFormat rhs) {
    return static_cast<uint32_t>(static_cast<uint32_t>(lhs) | static_cast<uint32_t>(rhs));
}
constexpr uint32_t operator|(const uint32_t lhs, const ::android::hardware::keymaster::generic::KeyFormat rhs) {
    return static_cast<uint32_t>(lhs | static_cast<uint32_t>(rhs));
}
constexpr uint32_t operator|(const ::android::hardware::keymaster::generic::KeyFormat lhs, const uint32_t rhs) {
    return static_cast<uint32_t>(static_cast<uint32_t>(lhs) | rhs);
}
constexpr uint32_t operator&(const ::android::hardware::keymaster::generic::KeyFormat lhs, const ::android::hardware::keymaster::generic::KeyFormat rhs) {
    return static_cast<uint32_t>(static_cast<uint32_t>(lhs) & static_cast<uint32_t>(rhs));
}
constexpr uint32_t operator&(const uint32_t lhs, const ::android::hardware::keymaster::generic::KeyFormat rhs) {
    return static_cast<uint32_t>(lhs & static_cast<uint32_t>(rhs));
}
constexpr uint32_t operator&(const ::android::hardware::keymaster::generic::KeyFormat lhs, const uint32_t rhs) {
    return static_cast<uint32_t>(static_cast<uint32_t>(lhs) & rhs);
}
constexpr uint32_t &operator|=(uint32_t& v, const ::android::hardware::keymaster::generic::KeyFormat e) {
    v |= static_cast<uint32_t>(e);
    return v;
}
constexpr uint32_t &operator&=(uint32_t& v, const ::android::hardware::keymaster::generic::KeyFormat e) {
    v &= static_cast<uint32_t>(e);
    return v;
}

static inline std::string toString(const ::android::hardware::keymaster::generic::KeyParameter::IntegerParams& o);
static inline void PrintTo(const ::android::hardware::keymaster::generic::KeyParameter::IntegerParams& o, ::std::ostream*);
// operator== and operator!= are not generated for IntegerParams

static inline std::string toString(const ::android::hardware::keymaster::generic::KeyParameter& o);
static inline void PrintTo(const ::android::hardware::keymaster::generic::KeyParameter& o, ::std::ostream*);
// operator== and operator!= are not generated for KeyParameter

static inline std::string toString(const ::android::hardware::keymaster::generic::KeyCharacteristics& o);
static inline void PrintTo(const ::android::hardware::keymaster::generic::KeyCharacteristics& o, ::std::ostream*);
// operator== and operator!= are not generated for KeyCharacteristics

static inline std::string toString(const ::android::hardware::keymaster::generic::HardwareAuthToken& o);
static inline void PrintTo(const ::android::hardware::keymaster::generic::HardwareAuthToken& o, ::std::ostream*);
static inline bool operator==(const ::android::hardware::keymaster::generic::HardwareAuthToken& lhs, const ::android::hardware::keymaster::generic::HardwareAuthToken& rhs);
static inline bool operator!=(const ::android::hardware::keymaster::generic::HardwareAuthToken& lhs, const ::android::hardware::keymaster::generic::HardwareAuthToken& rhs);

static inline std::string toString(const ::android::hardware::keymaster::generic::HmacSharingParameters& o);
static inline void PrintTo(const ::android::hardware::keymaster::generic::HmacSharingParameters& o, ::std::ostream*);
static inline bool operator==(const ::android::hardware::keymaster::generic::HmacSharingParameters& lhs, const ::android::hardware::keymaster::generic::HmacSharingParameters& rhs);
static inline bool operator!=(const ::android::hardware::keymaster::generic::HmacSharingParameters& lhs, const ::android::hardware::keymaster::generic::HmacSharingParameters& rhs);

static inline std::string toString(const ::android::hardware::keymaster::generic::VerificationToken& o);
static inline void PrintTo(const ::android::hardware::keymaster::generic::VerificationToken& o, ::std::ostream*);
// operator== and operator!= are not generated for VerificationToken

//
// type header definitions for package
//

template<>
inline std::string toString<::android::hardware::keymaster::generic::Constants>(uint32_t o) {
    using ::android::hardware::details::toHexString;
    std::string os;
    ::android::hardware::hidl_bitfield<::android::hardware::keymaster::generic::Constants> flipped = 0;
    bool first = true;
    if ((o & ::android::hardware::keymaster::generic::Constants::AUTH_TOKEN_MAC_LENGTH) == static_cast<uint32_t>(::android::hardware::keymaster::generic::Constants::AUTH_TOKEN_MAC_LENGTH)) {
        os += (first ? "" : " | ");
        os += "AUTH_TOKEN_MAC_LENGTH";
        first = false;
        flipped |= ::android::hardware::keymaster::generic::Constants::AUTH_TOKEN_MAC_LENGTH;
    }
    if (o != flipped) {
        os += (first ? "" : " | ");
        os += toHexString(o & (~flipped));
    }os += " (";
    os += toHexString(o);
    os += ")";
    return os;
}

static inline std::string toString(::android::hardware::keymaster::generic::Constants o) {
    using ::android::hardware::details::toHexString;
    if (o == ::android::hardware::keymaster::generic::Constants::AUTH_TOKEN_MAC_LENGTH) {
        return "AUTH_TOKEN_MAC_LENGTH";
    }
    std::string os;
    os += toHexString(static_cast<uint32_t>(o));
    return os;
}

static inline void PrintTo(::android::hardware::keymaster::generic::Constants o, ::std::ostream* os) {
    *os << toString(o);
}

template<>
inline std::string toString<::android::hardware::keymaster::generic::TagType>(uint32_t o) {
    using ::android::hardware::details::toHexString;
    std::string os;
    ::android::hardware::hidl_bitfield<::android::hardware::keymaster::generic::TagType> flipped = 0;
    bool first = true;
    if ((o & ::android::hardware::keymaster::generic::TagType::INVALID) == static_cast<uint32_t>(::android::hardware::keymaster::generic::TagType::INVALID)) {
        os += (first ? "" : " | ");
        os += "INVALID";
        first = false;
        flipped |= ::android::hardware::keymaster::generic::TagType::INVALID;
    }
    if ((o & ::android::hardware::keymaster::generic::TagType::ENUM) == static_cast<uint32_t>(::android::hardware::keymaster::generic::TagType::ENUM)) {
        os += (first ? "" : " | ");
        os += "ENUM";
        first = false;
        flipped |= ::android::hardware::keymaster::generic::TagType::ENUM;
    }
    if ((o & ::android::hardware::keymaster::generic::TagType::ENUM_REP) == static_cast<uint32_t>(::android::hardware::keymaster::generic::TagType::ENUM_REP)) {
        os += (first ? "" : " | ");
        os += "ENUM_REP";
        first = false;
        flipped |= ::android::hardware::keymaster::generic::TagType::ENUM_REP;
    }
    if ((o & ::android::hardware::keymaster::generic::TagType::UINT) == static_cast<uint32_t>(::android::hardware::keymaster::generic::TagType::UINT)) {
        os += (first ? "" : " | ");
        os += "UINT";
        first = false;
        flipped |= ::android::hardware::keymaster::generic::TagType::UINT;
    }
    if ((o & ::android::hardware::keymaster::generic::TagType::UINT_REP) == static_cast<uint32_t>(::android::hardware::keymaster::generic::TagType::UINT_REP)) {
        os += (first ? "" : " | ");
        os += "UINT_REP";
        first = false;
        flipped |= ::android::hardware::keymaster::generic::TagType::UINT_REP;
    }
    if ((o & ::android::hardware::keymaster::generic::TagType::ULONG) == static_cast<uint32_t>(::android::hardware::keymaster::generic::TagType::ULONG)) {
        os += (first ? "" : " | ");
        os += "ULONG";
        first = false;
        flipped |= ::android::hardware::keymaster::generic::TagType::ULONG;
    }
    if ((o & ::android::hardware::keymaster::generic::TagType::DATE) == static_cast<uint32_t>(::android::hardware::keymaster::generic::TagType::DATE)) {
        os += (first ? "" : " | ");
        os += "DATE";
        first = false;
        flipped |= ::android::hardware::keymaster::generic::TagType::DATE;
    }
    if ((o & ::android::hardware::keymaster::generic::TagType::BOOL) == static_cast<uint32_t>(::android::hardware::keymaster::generic::TagType::BOOL)) {
        os += (first ? "" : " | ");
        os += "BOOL";
        first = false;
        flipped |= ::android::hardware::keymaster::generic::TagType::BOOL;
    }
    if ((o & ::android::hardware::keymaster::generic::TagType::BIGNUM) == static_cast<uint32_t>(::android::hardware::keymaster::generic::TagType::BIGNUM)) {
        os += (first ? "" : " | ");
        os += "BIGNUM";
        first = false;
        flipped |= ::android::hardware::keymaster::generic::TagType::BIGNUM;
    }
    if ((o & ::android::hardware::keymaster::generic::TagType::BYTES) == static_cast<uint32_t>(::android::hardware::keymaster::generic::TagType::BYTES)) {
        os += (first ? "" : " | ");
        os += "BYTES";
        first = false;
        flipped |= ::android::hardware::keymaster::generic::TagType::BYTES;
    }
    if ((o & ::android::hardware::keymaster::generic::TagType::ULONG_REP) == static_cast<uint32_t>(::android::hardware::keymaster::generic::TagType::ULONG_REP)) {
        os += (first ? "" : " | ");
        os += "ULONG_REP";
        first = false;
        flipped |= ::android::hardware::keymaster::generic::TagType::ULONG_REP;
    }
    if (o != flipped) {
        os += (first ? "" : " | ");
        os += toHexString(o & (~flipped));
    }os += " (";
    os += toHexString(o);
    os += ")";
    return os;
}

static inline std::string toString(::android::hardware::keymaster::generic::TagType o) {
    using ::android::hardware::details::toHexString;
    if (o == ::android::hardware::keymaster::generic::TagType::INVALID) {
        return "INVALID";
    }
    if (o == ::android::hardware::keymaster::generic::TagType::ENUM) {
        return "ENUM";
    }
    if (o == ::android::hardware::keymaster::generic::TagType::ENUM_REP) {
        return "ENUM_REP";
    }
    if (o == ::android::hardware::keymaster::generic::TagType::UINT) {
        return "UINT";
    }
    if (o == ::android::hardware::keymaster::generic::TagType::UINT_REP) {
        return "UINT_REP";
    }
    if (o == ::android::hardware::keymaster::generic::TagType::ULONG) {
        return "ULONG";
    }
    if (o == ::android::hardware::keymaster::generic::TagType::DATE) {
        return "DATE";
    }
    if (o == ::android::hardware::keymaster::generic::TagType::BOOL) {
        return "BOOL";
    }
    if (o == ::android::hardware::keymaster::generic::TagType::BIGNUM) {
        return "BIGNUM";
    }
    if (o == ::android::hardware::keymaster::generic::TagType::BYTES) {
        return "BYTES";
    }
    if (o == ::android::hardware::keymaster::generic::TagType::ULONG_REP) {
        return "ULONG_REP";
    }
    std::string os;
    os += toHexString(static_cast<uint32_t>(o));
    return os;
}

static inline void PrintTo(::android::hardware::keymaster::generic::TagType o, ::std::ostream* os) {
    *os << toString(o);
}

template<>
inline std::string toString<::android::hardware::keymaster::generic::Tag>(uint32_t o) {
    using ::android::hardware::keymaster::generic::Tag;
    using ::android::hardware::details::toHexString;
    using ::android::hardware::hidl_bitfield;

    std::string os;
    hidl_bitfield<Tag> flipped = 0;
    bool first = true;

#define KM_DECL_TAG(name, type, tag_val, param_list_field, bound_enum, asn1_type, asn1_rep)        \
    if ((o & Tag::name) == static_cast<uint32_t>(Tag::name)) {                                     \
        os += (first ? "" : " | ");                                                                \
        os += #name;                                                                               \
        first = false;                                                                             \
        flipped |= Tag::INVALID;                                                                   \
    }

    KM_TAG_LIST__
#undef KM_DECL_TAG

    if (o != flipped) {
        os += (first ? "" : " | ");
        os += toHexString(o & (~flipped));
    }
    os += " (";
    os += toHexString(o);
    os += ")";
    return os;
}

static inline std::string toString(::android::hardware::keymaster::generic::Tag o) {
    using ::android::hardware::details::toHexString;
    using ::android::hardware::keymaster::generic::Tag;

#define KM_DECL_TAG(name, type, tag_val, param_list_field, bound_enum, asn1_type, asn1_rep)        \
    if (o == Tag::name) {                                                                          \
        return #name;                                                                              \
    }

    KM_TAG_LIST__
#undef KM_DECL_TAG

    std::string os;
    os += toHexString(static_cast<uint32_t>(o));
    return os;
}

static inline void PrintTo(::android::hardware::keymaster::generic::Tag o, ::std::ostream* os) {
    *os << toString(o);
}

template<>
inline std::string toString<::android::hardware::keymaster::generic::Algorithm>(uint32_t o) {
    using ::android::hardware::details::toHexString;
    std::string os;
    ::android::hardware::hidl_bitfield<::android::hardware::keymaster::generic::Algorithm> flipped = 0;
    bool first = true;
    if ((o & ::android::hardware::keymaster::generic::Algorithm::RSA) == static_cast<uint32_t>(::android::hardware::keymaster::generic::Algorithm::RSA)) {
        os += (first ? "" : " | ");
        os += "RSA";
        first = false;
        flipped |= ::android::hardware::keymaster::generic::Algorithm::RSA;
    }
    if ((o & ::android::hardware::keymaster::generic::Algorithm::EC) == static_cast<uint32_t>(::android::hardware::keymaster::generic::Algorithm::EC)) {
        os += (first ? "" : " | ");
        os += "EC";
        first = false;
        flipped |= ::android::hardware::keymaster::generic::Algorithm::EC;
    }
    if ((o & ::android::hardware::keymaster::generic::Algorithm::AES) == static_cast<uint32_t>(::android::hardware::keymaster::generic::Algorithm::AES)) {
        os += (first ? "" : " | ");
        os += "AES";
        first = false;
        flipped |= ::android::hardware::keymaster::generic::Algorithm::AES;
    }
    if ((o & ::android::hardware::keymaster::generic::Algorithm::TRIPLE_DES) == static_cast<uint32_t>(::android::hardware::keymaster::generic::Algorithm::TRIPLE_DES)) {
        os += (first ? "" : " | ");
        os += "TRIPLE_DES";
        first = false;
        flipped |= ::android::hardware::keymaster::generic::Algorithm::TRIPLE_DES;
    }
    if ((o & ::android::hardware::keymaster::generic::Algorithm::HMAC) == static_cast<uint32_t>(::android::hardware::keymaster::generic::Algorithm::HMAC)) {
        os += (first ? "" : " | ");
        os += "HMAC";
        first = false;
        flipped |= ::android::hardware::keymaster::generic::Algorithm::HMAC;
    }
    if (o != flipped) {
        os += (first ? "" : " | ");
        os += toHexString(o & (~flipped));
    }os += " (";
    os += toHexString(o);
    os += ")";
    return os;
}

static inline std::string toString(::android::hardware::keymaster::generic::Algorithm o) {
    using ::android::hardware::details::toHexString;
    if (o == ::android::hardware::keymaster::generic::Algorithm::RSA) {
        return "RSA";
    }
    if (o == ::android::hardware::keymaster::generic::Algorithm::EC) {
        return "EC";
    }
    if (o == ::android::hardware::keymaster::generic::Algorithm::AES) {
        return "AES";
    }
    if (o == ::android::hardware::keymaster::generic::Algorithm::TRIPLE_DES) {
        return "TRIPLE_DES";
    }
    if (o == ::android::hardware::keymaster::generic::Algorithm::HMAC) {
        return "HMAC";
    }
    std::string os;
    os += toHexString(static_cast<uint32_t>(o));
    return os;
}

static inline void PrintTo(::android::hardware::keymaster::generic::Algorithm o, ::std::ostream* os) {
    *os << toString(o);
}

template<>
inline std::string toString<::android::hardware::keymaster::generic::BlockMode>(uint32_t o) {
    using ::android::hardware::details::toHexString;
    std::string os;
    ::android::hardware::hidl_bitfield<::android::hardware::keymaster::generic::BlockMode> flipped = 0;
    bool first = true;
    if ((o & ::android::hardware::keymaster::generic::BlockMode::ECB) == static_cast<uint32_t>(::android::hardware::keymaster::generic::BlockMode::ECB)) {
        os += (first ? "" : " | ");
        os += "ECB";
        first = false;
        flipped |= ::android::hardware::keymaster::generic::BlockMode::ECB;
    }
    if ((o & ::android::hardware::keymaster::generic::BlockMode::CBC) == static_cast<uint32_t>(::android::hardware::keymaster::generic::BlockMode::CBC)) {
        os += (first ? "" : " | ");
        os += "CBC";
        first = false;
        flipped |= ::android::hardware::keymaster::generic::BlockMode::CBC;
    }
    if ((o & ::android::hardware::keymaster::generic::BlockMode::CTR) == static_cast<uint32_t>(::android::hardware::keymaster::generic::BlockMode::CTR)) {
        os += (first ? "" : " | ");
        os += "CTR";
        first = false;
        flipped |= ::android::hardware::keymaster::generic::BlockMode::CTR;
    }
    if ((o & ::android::hardware::keymaster::generic::BlockMode::GCM) == static_cast<uint32_t>(::android::hardware::keymaster::generic::BlockMode::GCM)) {
        os += (first ? "" : " | ");
        os += "GCM";
        first = false;
        flipped |= ::android::hardware::keymaster::generic::BlockMode::GCM;
    }
    if (o != flipped) {
        os += (first ? "" : " | ");
        os += toHexString(o & (~flipped));
    }os += " (";
    os += toHexString(o);
    os += ")";
    return os;
}

static inline std::string toString(::android::hardware::keymaster::generic::BlockMode o) {
    using ::android::hardware::details::toHexString;
    if (o == ::android::hardware::keymaster::generic::BlockMode::ECB) {
        return "ECB";
    }
    if (o == ::android::hardware::keymaster::generic::BlockMode::CBC) {
        return "CBC";
    }
    if (o == ::android::hardware::keymaster::generic::BlockMode::CTR) {
        return "CTR";
    }
    if (o == ::android::hardware::keymaster::generic::BlockMode::GCM) {
        return "GCM";
    }
    std::string os;
    os += toHexString(static_cast<uint32_t>(o));
    return os;
}

static inline void PrintTo(::android::hardware::keymaster::generic::BlockMode o, ::std::ostream* os) {
    *os << toString(o);
}

template<>
inline std::string toString<::android::hardware::keymaster::generic::PaddingMode>(uint32_t o) {
    using ::android::hardware::details::toHexString;
    std::string os;
    ::android::hardware::hidl_bitfield<::android::hardware::keymaster::generic::PaddingMode> flipped = 0;
    bool first = true;
    if ((o & ::android::hardware::keymaster::generic::PaddingMode::NONE) == static_cast<uint32_t>(::android::hardware::keymaster::generic::PaddingMode::NONE)) {
        os += (first ? "" : " | ");
        os += "NONE";
        first = false;
        flipped |= ::android::hardware::keymaster::generic::PaddingMode::NONE;
    }
    if ((o & ::android::hardware::keymaster::generic::PaddingMode::RSA_OAEP) == static_cast<uint32_t>(::android::hardware::keymaster::generic::PaddingMode::RSA_OAEP)) {
        os += (first ? "" : " | ");
        os += "RSA_OAEP";
        first = false;
        flipped |= ::android::hardware::keymaster::generic::PaddingMode::RSA_OAEP;
    }
    if ((o & ::android::hardware::keymaster::generic::PaddingMode::RSA_PSS) == static_cast<uint32_t>(::android::hardware::keymaster::generic::PaddingMode::RSA_PSS)) {
        os += (first ? "" : " | ");
        os += "RSA_PSS";
        first = false;
        flipped |= ::android::hardware::keymaster::generic::PaddingMode::RSA_PSS;
    }
    if ((o & ::android::hardware::keymaster::generic::PaddingMode::RSA_PKCS1_1_5_ENCRYPT) == static_cast<uint32_t>(::android::hardware::keymaster::generic::PaddingMode::RSA_PKCS1_1_5_ENCRYPT)) {
        os += (first ? "" : " | ");
        os += "RSA_PKCS1_1_5_ENCRYPT";
        first = false;
        flipped |= ::android::hardware::keymaster::generic::PaddingMode::RSA_PKCS1_1_5_ENCRYPT;
    }
    if ((o & ::android::hardware::keymaster::generic::PaddingMode::RSA_PKCS1_1_5_SIGN) == static_cast<uint32_t>(::android::hardware::keymaster::generic::PaddingMode::RSA_PKCS1_1_5_SIGN)) {
        os += (first ? "" : " | ");
        os += "RSA_PKCS1_1_5_SIGN";
        first = false;
        flipped |= ::android::hardware::keymaster::generic::PaddingMode::RSA_PKCS1_1_5_SIGN;
    }
    if ((o & ::android::hardware::keymaster::generic::PaddingMode::PKCS7) == static_cast<uint32_t>(::android::hardware::keymaster::generic::PaddingMode::PKCS7)) {
        os += (first ? "" : " | ");
        os += "PKCS7";
        first = false;
        flipped |= ::android::hardware::keymaster::generic::PaddingMode::PKCS7;
    }
    if (o != flipped) {
        os += (first ? "" : " | ");
        os += toHexString(o & (~flipped));
    }os += " (";
    os += toHexString(o);
    os += ")";
    return os;
}

static inline std::string toString(::android::hardware::keymaster::generic::PaddingMode o) {
    using ::android::hardware::details::toHexString;
    if (o == ::android::hardware::keymaster::generic::PaddingMode::NONE) {
        return "NONE";
    }
    if (o == ::android::hardware::keymaster::generic::PaddingMode::RSA_OAEP) {
        return "RSA_OAEP";
    }
    if (o == ::android::hardware::keymaster::generic::PaddingMode::RSA_PSS) {
        return "RSA_PSS";
    }
    if (o == ::android::hardware::keymaster::generic::PaddingMode::RSA_PKCS1_1_5_ENCRYPT) {
        return "RSA_PKCS1_1_5_ENCRYPT";
    }
    if (o == ::android::hardware::keymaster::generic::PaddingMode::RSA_PKCS1_1_5_SIGN) {
        return "RSA_PKCS1_1_5_SIGN";
    }
    if (o == ::android::hardware::keymaster::generic::PaddingMode::PKCS7) {
        return "PKCS7";
    }
    std::string os;
    os += toHexString(static_cast<uint32_t>(o));
    return os;
}

static inline void PrintTo(::android::hardware::keymaster::generic::PaddingMode o, ::std::ostream* os) {
    *os << toString(o);
}

template<>
inline std::string toString<::android::hardware::keymaster::generic::Digest>(uint32_t o) {
    using ::android::hardware::details::toHexString;
    std::string os;
    ::android::hardware::hidl_bitfield<::android::hardware::keymaster::generic::Digest> flipped = 0;
    bool first = true;
    if ((o & ::android::hardware::keymaster::generic::Digest::NONE) == static_cast<uint32_t>(::android::hardware::keymaster::generic::Digest::NONE)) {
        os += (first ? "" : " | ");
        os += "NONE";
        first = false;
        flipped |= ::android::hardware::keymaster::generic::Digest::NONE;
    }
    if ((o & ::android::hardware::keymaster::generic::Digest::MD5) == static_cast<uint32_t>(::android::hardware::keymaster::generic::Digest::MD5)) {
        os += (first ? "" : " | ");
        os += "MD5";
        first = false;
        flipped |= ::android::hardware::keymaster::generic::Digest::MD5;
    }
    if ((o & ::android::hardware::keymaster::generic::Digest::SHA1) == static_cast<uint32_t>(::android::hardware::keymaster::generic::Digest::SHA1)) {
        os += (first ? "" : " | ");
        os += "SHA1";
        first = false;
        flipped |= ::android::hardware::keymaster::generic::Digest::SHA1;
    }
    if ((o & ::android::hardware::keymaster::generic::Digest::SHA_2_224) == static_cast<uint32_t>(::android::hardware::keymaster::generic::Digest::SHA_2_224)) {
        os += (first ? "" : " | ");
        os += "SHA_2_224";
        first = false;
        flipped |= ::android::hardware::keymaster::generic::Digest::SHA_2_224;
    }
    if ((o & ::android::hardware::keymaster::generic::Digest::SHA_2_256) == static_cast<uint32_t>(::android::hardware::keymaster::generic::Digest::SHA_2_256)) {
        os += (first ? "" : " | ");
        os += "SHA_2_256";
        first = false;
        flipped |= ::android::hardware::keymaster::generic::Digest::SHA_2_256;
    }
    if ((o & ::android::hardware::keymaster::generic::Digest::SHA_2_384) == static_cast<uint32_t>(::android::hardware::keymaster::generic::Digest::SHA_2_384)) {
        os += (first ? "" : " | ");
        os += "SHA_2_384";
        first = false;
        flipped |= ::android::hardware::keymaster::generic::Digest::SHA_2_384;
    }
    if ((o & ::android::hardware::keymaster::generic::Digest::SHA_2_512) == static_cast<uint32_t>(::android::hardware::keymaster::generic::Digest::SHA_2_512)) {
        os += (first ? "" : " | ");
        os += "SHA_2_512";
        first = false;
        flipped |= ::android::hardware::keymaster::generic::Digest::SHA_2_512;
    }
    if (o != flipped) {
        os += (first ? "" : " | ");
        os += toHexString(o & (~flipped));
    }os += " (";
    os += toHexString(o);
    os += ")";
    return os;
}

static inline std::string toString(::android::hardware::keymaster::generic::Digest o) {
    using ::android::hardware::details::toHexString;
    if (o == ::android::hardware::keymaster::generic::Digest::NONE) {
        return "NONE";
    }
    if (o == ::android::hardware::keymaster::generic::Digest::MD5) {
        return "MD5";
    }
    if (o == ::android::hardware::keymaster::generic::Digest::SHA1) {
        return "SHA1";
    }
    if (o == ::android::hardware::keymaster::generic::Digest::SHA_2_224) {
        return "SHA_2_224";
    }
    if (o == ::android::hardware::keymaster::generic::Digest::SHA_2_256) {
        return "SHA_2_256";
    }
    if (o == ::android::hardware::keymaster::generic::Digest::SHA_2_384) {
        return "SHA_2_384";
    }
    if (o == ::android::hardware::keymaster::generic::Digest::SHA_2_512) {
        return "SHA_2_512";
    }
    std::string os;
    os += toHexString(static_cast<uint32_t>(o));
    return os;
}

static inline void PrintTo(::android::hardware::keymaster::generic::Digest o, ::std::ostream* os) {
    *os << toString(o);
}

template<>
inline std::string toString<::android::hardware::keymaster::generic::EcCurve>(uint32_t o) {
    using ::android::hardware::details::toHexString;
    std::string os;
    ::android::hardware::hidl_bitfield<::android::hardware::keymaster::generic::EcCurve> flipped = 0;
    bool first = true;
    if ((o & ::android::hardware::keymaster::generic::EcCurve::P_224) == static_cast<uint32_t>(::android::hardware::keymaster::generic::EcCurve::P_224)) {
        os += (first ? "" : " | ");
        os += "P_224";
        first = false;
        flipped |= ::android::hardware::keymaster::generic::EcCurve::P_224;
    }
    if ((o & ::android::hardware::keymaster::generic::EcCurve::P_256) == static_cast<uint32_t>(::android::hardware::keymaster::generic::EcCurve::P_256)) {
        os += (first ? "" : " | ");
        os += "P_256";
        first = false;
        flipped |= ::android::hardware::keymaster::generic::EcCurve::P_256;
    }
    if ((o & ::android::hardware::keymaster::generic::EcCurve::P_384) == static_cast<uint32_t>(::android::hardware::keymaster::generic::EcCurve::P_384)) {
        os += (first ? "" : " | ");
        os += "P_384";
        first = false;
        flipped |= ::android::hardware::keymaster::generic::EcCurve::P_384;
    }
    if ((o & ::android::hardware::keymaster::generic::EcCurve::P_521) == static_cast<uint32_t>(::android::hardware::keymaster::generic::EcCurve::P_521)) {
        os += (first ? "" : " | ");
        os += "P_521";
        first = false;
        flipped |= ::android::hardware::keymaster::generic::EcCurve::P_521;
    }
    if (o != flipped) {
        os += (first ? "" : " | ");
        os += toHexString(o & (~flipped));
    }os += " (";
    os += toHexString(o);
    os += ")";
    return os;
}

static inline std::string toString(::android::hardware::keymaster::generic::EcCurve o) {
    using ::android::hardware::details::toHexString;
    if (o == ::android::hardware::keymaster::generic::EcCurve::P_224) {
        return "P_224";
    }
    if (o == ::android::hardware::keymaster::generic::EcCurve::P_256) {
        return "P_256";
    }
    if (o == ::android::hardware::keymaster::generic::EcCurve::P_384) {
        return "P_384";
    }
    if (o == ::android::hardware::keymaster::generic::EcCurve::P_521) {
        return "P_521";
    }
    std::string os;
    os += toHexString(static_cast<uint32_t>(o));
    return os;
}

static inline void PrintTo(::android::hardware::keymaster::generic::EcCurve o, ::std::ostream* os) {
    *os << toString(o);
}

template<>
inline std::string toString<::android::hardware::keymaster::generic::KeyOrigin>(uint32_t o) {
    using ::android::hardware::details::toHexString;
    std::string os;
    ::android::hardware::hidl_bitfield<::android::hardware::keymaster::generic::KeyOrigin> flipped = 0;
    bool first = true;
    if ((o & ::android::hardware::keymaster::generic::KeyOrigin::GENERATED) == static_cast<uint32_t>(::android::hardware::keymaster::generic::KeyOrigin::GENERATED)) {
        os += (first ? "" : " | ");
        os += "GENERATED";
        first = false;
        flipped |= ::android::hardware::keymaster::generic::KeyOrigin::GENERATED;
    }
    if ((o & ::android::hardware::keymaster::generic::KeyOrigin::DERIVED) == static_cast<uint32_t>(::android::hardware::keymaster::generic::KeyOrigin::DERIVED)) {
        os += (first ? "" : " | ");
        os += "DERIVED";
        first = false;
        flipped |= ::android::hardware::keymaster::generic::KeyOrigin::DERIVED;
    }
    if ((o & ::android::hardware::keymaster::generic::KeyOrigin::IMPORTED) == static_cast<uint32_t>(::android::hardware::keymaster::generic::KeyOrigin::IMPORTED)) {
        os += (first ? "" : " | ");
        os += "IMPORTED";
        first = false;
        flipped |= ::android::hardware::keymaster::generic::KeyOrigin::IMPORTED;
    }
    if ((o & ::android::hardware::keymaster::generic::KeyOrigin::UNKNOWN) == static_cast<uint32_t>(::android::hardware::keymaster::generic::KeyOrigin::UNKNOWN)) {
        os += (first ? "" : " | ");
        os += "UNKNOWN";
        first = false;
        flipped |= ::android::hardware::keymaster::generic::KeyOrigin::UNKNOWN;
    }
    if ((o & ::android::hardware::keymaster::generic::KeyOrigin::SECURELY_IMPORTED) == static_cast<uint32_t>(::android::hardware::keymaster::generic::KeyOrigin::SECURELY_IMPORTED)) {
        os += (first ? "" : " | ");
        os += "SECURELY_IMPORTED";
        first = false;
        flipped |= ::android::hardware::keymaster::generic::KeyOrigin::SECURELY_IMPORTED;
    }
    if (o != flipped) {
        os += (first ? "" : " | ");
        os += toHexString(o & (~flipped));
    }os += " (";
    os += toHexString(o);
    os += ")";
    return os;
}

static inline std::string toString(::android::hardware::keymaster::generic::KeyOrigin o) {
    using ::android::hardware::details::toHexString;
    if (o == ::android::hardware::keymaster::generic::KeyOrigin::GENERATED) {
        return "GENERATED";
    }
    if (o == ::android::hardware::keymaster::generic::KeyOrigin::DERIVED) {
        return "DERIVED";
    }
    if (o == ::android::hardware::keymaster::generic::KeyOrigin::IMPORTED) {
        return "IMPORTED";
    }
    if (o == ::android::hardware::keymaster::generic::KeyOrigin::UNKNOWN) {
        return "UNKNOWN";
    }
    if (o == ::android::hardware::keymaster::generic::KeyOrigin::SECURELY_IMPORTED) {
        return "SECURELY_IMPORTED";
    }
    std::string os;
    os += toHexString(static_cast<uint32_t>(o));
    return os;
}

static inline void PrintTo(::android::hardware::keymaster::generic::KeyOrigin o, ::std::ostream* os) {
    *os << toString(o);
}

template<>
inline std::string toString<::android::hardware::keymaster::generic::KeyBlobUsageRequirements>(uint32_t o) {
    using ::android::hardware::details::toHexString;
    std::string os;
    ::android::hardware::hidl_bitfield<::android::hardware::keymaster::generic::KeyBlobUsageRequirements> flipped = 0;
    bool first = true;
    if ((o & ::android::hardware::keymaster::generic::KeyBlobUsageRequirements::STANDALONE) == static_cast<uint32_t>(::android::hardware::keymaster::generic::KeyBlobUsageRequirements::STANDALONE)) {
        os += (first ? "" : " | ");
        os += "STANDALONE";
        first = false;
        flipped |= ::android::hardware::keymaster::generic::KeyBlobUsageRequirements::STANDALONE;
    }
    if ((o & ::android::hardware::keymaster::generic::KeyBlobUsageRequirements::REQUIRES_FILE_SYSTEM) == static_cast<uint32_t>(::android::hardware::keymaster::generic::KeyBlobUsageRequirements::REQUIRES_FILE_SYSTEM)) {
        os += (first ? "" : " | ");
        os += "REQUIRES_FILE_SYSTEM";
        first = false;
        flipped |= ::android::hardware::keymaster::generic::KeyBlobUsageRequirements::REQUIRES_FILE_SYSTEM;
    }
    if (o != flipped) {
        os += (first ? "" : " | ");
        os += toHexString(o & (~flipped));
    }os += " (";
    os += toHexString(o);
    os += ")";
    return os;
}

static inline std::string toString(::android::hardware::keymaster::generic::KeyBlobUsageRequirements o) {
    using ::android::hardware::details::toHexString;
    if (o == ::android::hardware::keymaster::generic::KeyBlobUsageRequirements::STANDALONE) {
        return "STANDALONE";
    }
    if (o == ::android::hardware::keymaster::generic::KeyBlobUsageRequirements::REQUIRES_FILE_SYSTEM) {
        return "REQUIRES_FILE_SYSTEM";
    }
    std::string os;
    os += toHexString(static_cast<uint32_t>(o));
    return os;
}

static inline void PrintTo(::android::hardware::keymaster::generic::KeyBlobUsageRequirements o, ::std::ostream* os) {
    *os << toString(o);
}

template<>
inline std::string toString<::android::hardware::keymaster::generic::KeyPurpose>(uint32_t o) {
    using ::android::hardware::details::toHexString;
    std::string os;
    ::android::hardware::hidl_bitfield<::android::hardware::keymaster::generic::KeyPurpose> flipped = 0;
    bool first = true;
    if ((o & ::android::hardware::keymaster::generic::KeyPurpose::ENCRYPT) == static_cast<uint32_t>(::android::hardware::keymaster::generic::KeyPurpose::ENCRYPT)) {
        os += (first ? "" : " | ");
        os += "ENCRYPT";
        first = false;
        flipped |= ::android::hardware::keymaster::generic::KeyPurpose::ENCRYPT;
    }
    if ((o & ::android::hardware::keymaster::generic::KeyPurpose::DECRYPT) == static_cast<uint32_t>(::android::hardware::keymaster::generic::KeyPurpose::DECRYPT)) {
        os += (first ? "" : " | ");
        os += "DECRYPT";
        first = false;
        flipped |= ::android::hardware::keymaster::generic::KeyPurpose::DECRYPT;
    }
    if ((o & ::android::hardware::keymaster::generic::KeyPurpose::SIGN) == static_cast<uint32_t>(::android::hardware::keymaster::generic::KeyPurpose::SIGN)) {
        os += (first ? "" : " | ");
        os += "SIGN";
        first = false;
        flipped |= ::android::hardware::keymaster::generic::KeyPurpose::SIGN;
    }
    if ((o & ::android::hardware::keymaster::generic::KeyPurpose::VERIFY) == static_cast<uint32_t>(::android::hardware::keymaster::generic::KeyPurpose::VERIFY)) {
        os += (first ? "" : " | ");
        os += "VERIFY";
        first = false;
        flipped |= ::android::hardware::keymaster::generic::KeyPurpose::VERIFY;
    }
    if ((o & ::android::hardware::keymaster::generic::KeyPurpose::WRAP_KEY) == static_cast<uint32_t>(::android::hardware::keymaster::generic::KeyPurpose::WRAP_KEY)) {
        os += (first ? "" : " | ");
        os += "WRAP_KEY";
        first = false;
        flipped |= ::android::hardware::keymaster::generic::KeyPurpose::WRAP_KEY;
    }
    if (o != flipped) {
        os += (first ? "" : " | ");
        os += toHexString(o & (~flipped));
    }os += " (";
    os += toHexString(o);
    os += ")";
    return os;
}

static inline std::string toString(::android::hardware::keymaster::generic::KeyPurpose o) {
    using ::android::hardware::details::toHexString;
    if (o == ::android::hardware::keymaster::generic::KeyPurpose::ENCRYPT) {
        return "ENCRYPT";
    }
    if (o == ::android::hardware::keymaster::generic::KeyPurpose::DECRYPT) {
        return "DECRYPT";
    }
    if (o == ::android::hardware::keymaster::generic::KeyPurpose::SIGN) {
        return "SIGN";
    }
    if (o == ::android::hardware::keymaster::generic::KeyPurpose::VERIFY) {
        return "VERIFY";
    }
    if (o == ::android::hardware::keymaster::generic::KeyPurpose::WRAP_KEY) {
        return "WRAP_KEY";
    }
    std::string os;
    os += toHexString(static_cast<uint32_t>(o));
    return os;
}

static inline void PrintTo(::android::hardware::keymaster::generic::KeyPurpose o, ::std::ostream* os) {
    *os << toString(o);
}

template<>
inline std::string toString<::android::hardware::keymaster::generic::ErrorCode>(int32_t o) {
    using ::android::hardware::details::toHexString;
    std::string os;
    ::android::hardware::hidl_bitfield<::android::hardware::keymaster::generic::ErrorCode> flipped = 0;
    bool first = true;
    if ((o & ::android::hardware::keymaster::generic::ErrorCode::OK) == static_cast<int32_t>(::android::hardware::keymaster::generic::ErrorCode::OK)) {
        os += (first ? "" : " | ");
        os += "OK";
        first = false;
        flipped |= ::android::hardware::keymaster::generic::ErrorCode::OK;
    }
    if ((o & ::android::hardware::keymaster::generic::ErrorCode::ROOT_OF_TRUST_ALREADY_SET) == static_cast<int32_t>(::android::hardware::keymaster::generic::ErrorCode::ROOT_OF_TRUST_ALREADY_SET)) {
        os += (first ? "" : " | ");
        os += "ROOT_OF_TRUST_ALREADY_SET";
        first = false;
        flipped |= ::android::hardware::keymaster::generic::ErrorCode::ROOT_OF_TRUST_ALREADY_SET;
    }
    if ((o & ::android::hardware::keymaster::generic::ErrorCode::UNSUPPORTED_PURPOSE) == static_cast<int32_t>(::android::hardware::keymaster::generic::ErrorCode::UNSUPPORTED_PURPOSE)) {
        os += (first ? "" : " | ");
        os += "UNSUPPORTED_PURPOSE";
        first = false;
        flipped |= ::android::hardware::keymaster::generic::ErrorCode::UNSUPPORTED_PURPOSE;
    }
    if ((o & ::android::hardware::keymaster::generic::ErrorCode::INCOMPATIBLE_PURPOSE) == static_cast<int32_t>(::android::hardware::keymaster::generic::ErrorCode::INCOMPATIBLE_PURPOSE)) {
        os += (first ? "" : " | ");
        os += "INCOMPATIBLE_PURPOSE";
        first = false;
        flipped |= ::android::hardware::keymaster::generic::ErrorCode::INCOMPATIBLE_PURPOSE;
    }
    if ((o & ::android::hardware::keymaster::generic::ErrorCode::UNSUPPORTED_ALGORITHM) == static_cast<int32_t>(::android::hardware::keymaster::generic::ErrorCode::UNSUPPORTED_ALGORITHM)) {
        os += (first ? "" : " | ");
        os += "UNSUPPORTED_ALGORITHM";
        first = false;
        flipped |= ::android::hardware::keymaster::generic::ErrorCode::UNSUPPORTED_ALGORITHM;
    }
    if ((o & ::android::hardware::keymaster::generic::ErrorCode::INCOMPATIBLE_ALGORITHM) == static_cast<int32_t>(::android::hardware::keymaster::generic::ErrorCode::INCOMPATIBLE_ALGORITHM)) {
        os += (first ? "" : " | ");
        os += "INCOMPATIBLE_ALGORITHM";
        first = false;
        flipped |= ::android::hardware::keymaster::generic::ErrorCode::INCOMPATIBLE_ALGORITHM;
    }
    if ((o & ::android::hardware::keymaster::generic::ErrorCode::UNSUPPORTED_KEY_SIZE) == static_cast<int32_t>(::android::hardware::keymaster::generic::ErrorCode::UNSUPPORTED_KEY_SIZE)) {
        os += (first ? "" : " | ");
        os += "UNSUPPORTED_KEY_SIZE";
        first = false;
        flipped |= ::android::hardware::keymaster::generic::ErrorCode::UNSUPPORTED_KEY_SIZE;
    }
    if ((o & ::android::hardware::keymaster::generic::ErrorCode::UNSUPPORTED_BLOCK_MODE) == static_cast<int32_t>(::android::hardware::keymaster::generic::ErrorCode::UNSUPPORTED_BLOCK_MODE)) {
        os += (first ? "" : " | ");
        os += "UNSUPPORTED_BLOCK_MODE";
        first = false;
        flipped |= ::android::hardware::keymaster::generic::ErrorCode::UNSUPPORTED_BLOCK_MODE;
    }
    if ((o & ::android::hardware::keymaster::generic::ErrorCode::INCOMPATIBLE_BLOCK_MODE) == static_cast<int32_t>(::android::hardware::keymaster::generic::ErrorCode::INCOMPATIBLE_BLOCK_MODE)) {
        os += (first ? "" : " | ");
        os += "INCOMPATIBLE_BLOCK_MODE";
        first = false;
        flipped |= ::android::hardware::keymaster::generic::ErrorCode::INCOMPATIBLE_BLOCK_MODE;
    }
    if ((o & ::android::hardware::keymaster::generic::ErrorCode::UNSUPPORTED_MAC_LENGTH) == static_cast<int32_t>(::android::hardware::keymaster::generic::ErrorCode::UNSUPPORTED_MAC_LENGTH)) {
        os += (first ? "" : " | ");
        os += "UNSUPPORTED_MAC_LENGTH";
        first = false;
        flipped |= ::android::hardware::keymaster::generic::ErrorCode::UNSUPPORTED_MAC_LENGTH;
    }
    if ((o & ::android::hardware::keymaster::generic::ErrorCode::UNSUPPORTED_PADDING_MODE) == static_cast<int32_t>(::android::hardware::keymaster::generic::ErrorCode::UNSUPPORTED_PADDING_MODE)) {
        os += (first ? "" : " | ");
        os += "UNSUPPORTED_PADDING_MODE";
        first = false;
        flipped |= ::android::hardware::keymaster::generic::ErrorCode::UNSUPPORTED_PADDING_MODE;
    }
    if ((o & ::android::hardware::keymaster::generic::ErrorCode::INCOMPATIBLE_PADDING_MODE) == static_cast<int32_t>(::android::hardware::keymaster::generic::ErrorCode::INCOMPATIBLE_PADDING_MODE)) {
        os += (first ? "" : " | ");
        os += "INCOMPATIBLE_PADDING_MODE";
        first = false;
        flipped |= ::android::hardware::keymaster::generic::ErrorCode::INCOMPATIBLE_PADDING_MODE;
    }
    if ((o & ::android::hardware::keymaster::generic::ErrorCode::UNSUPPORTED_DIGEST) == static_cast<int32_t>(::android::hardware::keymaster::generic::ErrorCode::UNSUPPORTED_DIGEST)) {
        os += (first ? "" : " | ");
        os += "UNSUPPORTED_DIGEST";
        first = false;
        flipped |= ::android::hardware::keymaster::generic::ErrorCode::UNSUPPORTED_DIGEST;
    }
    if ((o & ::android::hardware::keymaster::generic::ErrorCode::INCOMPATIBLE_DIGEST) == static_cast<int32_t>(::android::hardware::keymaster::generic::ErrorCode::INCOMPATIBLE_DIGEST)) {
        os += (first ? "" : " | ");
        os += "INCOMPATIBLE_DIGEST";
        first = false;
        flipped |= ::android::hardware::keymaster::generic::ErrorCode::INCOMPATIBLE_DIGEST;
    }
    if ((o & ::android::hardware::keymaster::generic::ErrorCode::INVALID_EXPIRATION_TIME) == static_cast<int32_t>(::android::hardware::keymaster::generic::ErrorCode::INVALID_EXPIRATION_TIME)) {
        os += (first ? "" : " | ");
        os += "INVALID_EXPIRATION_TIME";
        first = false;
        flipped |= ::android::hardware::keymaster::generic::ErrorCode::INVALID_EXPIRATION_TIME;
    }
    if ((o & ::android::hardware::keymaster::generic::ErrorCode::INVALID_USER_ID) == static_cast<int32_t>(::android::hardware::keymaster::generic::ErrorCode::INVALID_USER_ID)) {
        os += (first ? "" : " | ");
        os += "INVALID_USER_ID";
        first = false;
        flipped |= ::android::hardware::keymaster::generic::ErrorCode::INVALID_USER_ID;
    }
    if ((o & ::android::hardware::keymaster::generic::ErrorCode::INVALID_AUTHORIZATION_TIMEOUT) == static_cast<int32_t>(::android::hardware::keymaster::generic::ErrorCode::INVALID_AUTHORIZATION_TIMEOUT)) {
        os += (first ? "" : " | ");
        os += "INVALID_AUTHORIZATION_TIMEOUT";
        first = false;
        flipped |= ::android::hardware::keymaster::generic::ErrorCode::INVALID_AUTHORIZATION_TIMEOUT;
    }
    if ((o & ::android::hardware::keymaster::generic::ErrorCode::UNSUPPORTED_KEY_FORMAT) == static_cast<int32_t>(::android::hardware::keymaster::generic::ErrorCode::UNSUPPORTED_KEY_FORMAT)) {
        os += (first ? "" : " | ");
        os += "UNSUPPORTED_KEY_FORMAT";
        first = false;
        flipped |= ::android::hardware::keymaster::generic::ErrorCode::UNSUPPORTED_KEY_FORMAT;
    }
    if ((o & ::android::hardware::keymaster::generic::ErrorCode::INCOMPATIBLE_KEY_FORMAT) == static_cast<int32_t>(::android::hardware::keymaster::generic::ErrorCode::INCOMPATIBLE_KEY_FORMAT)) {
        os += (first ? "" : " | ");
        os += "INCOMPATIBLE_KEY_FORMAT";
        first = false;
        flipped |= ::android::hardware::keymaster::generic::ErrorCode::INCOMPATIBLE_KEY_FORMAT;
    }
    if ((o & ::android::hardware::keymaster::generic::ErrorCode::UNSUPPORTED_KEY_ENCRYPTION_ALGORITHM) == static_cast<int32_t>(::android::hardware::keymaster::generic::ErrorCode::UNSUPPORTED_KEY_ENCRYPTION_ALGORITHM)) {
        os += (first ? "" : " | ");
        os += "UNSUPPORTED_KEY_ENCRYPTION_ALGORITHM";
        first = false;
        flipped |= ::android::hardware::keymaster::generic::ErrorCode::UNSUPPORTED_KEY_ENCRYPTION_ALGORITHM;
    }
    if ((o & ::android::hardware::keymaster::generic::ErrorCode::UNSUPPORTED_KEY_VERIFICATION_ALGORITHM) == static_cast<int32_t>(::android::hardware::keymaster::generic::ErrorCode::UNSUPPORTED_KEY_VERIFICATION_ALGORITHM)) {
        os += (first ? "" : " | ");
        os += "UNSUPPORTED_KEY_VERIFICATION_ALGORITHM";
        first = false;
        flipped |= ::android::hardware::keymaster::generic::ErrorCode::UNSUPPORTED_KEY_VERIFICATION_ALGORITHM;
    }
    if ((o & ::android::hardware::keymaster::generic::ErrorCode::INVALID_INPUT_LENGTH) == static_cast<int32_t>(::android::hardware::keymaster::generic::ErrorCode::INVALID_INPUT_LENGTH)) {
        os += (first ? "" : " | ");
        os += "INVALID_INPUT_LENGTH";
        first = false;
        flipped |= ::android::hardware::keymaster::generic::ErrorCode::INVALID_INPUT_LENGTH;
    }
    if ((o & ::android::hardware::keymaster::generic::ErrorCode::KEY_EXPORT_OPTIONS_INVALID) == static_cast<int32_t>(::android::hardware::keymaster::generic::ErrorCode::KEY_EXPORT_OPTIONS_INVALID)) {
        os += (first ? "" : " | ");
        os += "KEY_EXPORT_OPTIONS_INVALID";
        first = false;
        flipped |= ::android::hardware::keymaster::generic::ErrorCode::KEY_EXPORT_OPTIONS_INVALID;
    }
    if ((o & ::android::hardware::keymaster::generic::ErrorCode::DELEGATION_NOT_ALLOWED) == static_cast<int32_t>(::android::hardware::keymaster::generic::ErrorCode::DELEGATION_NOT_ALLOWED)) {
        os += (first ? "" : " | ");
        os += "DELEGATION_NOT_ALLOWED";
        first = false;
        flipped |= ::android::hardware::keymaster::generic::ErrorCode::DELEGATION_NOT_ALLOWED;
    }
    if ((o & ::android::hardware::keymaster::generic::ErrorCode::KEY_NOT_YET_VALID) == static_cast<int32_t>(::android::hardware::keymaster::generic::ErrorCode::KEY_NOT_YET_VALID)) {
        os += (first ? "" : " | ");
        os += "KEY_NOT_YET_VALID";
        first = false;
        flipped |= ::android::hardware::keymaster::generic::ErrorCode::KEY_NOT_YET_VALID;
    }
    if ((o & ::android::hardware::keymaster::generic::ErrorCode::KEY_EXPIRED) == static_cast<int32_t>(::android::hardware::keymaster::generic::ErrorCode::KEY_EXPIRED)) {
        os += (first ? "" : " | ");
        os += "KEY_EXPIRED";
        first = false;
        flipped |= ::android::hardware::keymaster::generic::ErrorCode::KEY_EXPIRED;
    }
    if ((o & ::android::hardware::keymaster::generic::ErrorCode::KEY_USER_NOT_AUTHENTICATED) == static_cast<int32_t>(::android::hardware::keymaster::generic::ErrorCode::KEY_USER_NOT_AUTHENTICATED)) {
        os += (first ? "" : " | ");
        os += "KEY_USER_NOT_AUTHENTICATED";
        first = false;
        flipped |= ::android::hardware::keymaster::generic::ErrorCode::KEY_USER_NOT_AUTHENTICATED;
    }
    if ((o & ::android::hardware::keymaster::generic::ErrorCode::OUTPUT_PARAMETER_NULL) == static_cast<int32_t>(::android::hardware::keymaster::generic::ErrorCode::OUTPUT_PARAMETER_NULL)) {
        os += (first ? "" : " | ");
        os += "OUTPUT_PARAMETER_NULL";
        first = false;
        flipped |= ::android::hardware::keymaster::generic::ErrorCode::OUTPUT_PARAMETER_NULL;
    }
    if ((o & ::android::hardware::keymaster::generic::ErrorCode::INVALID_OPERATION_HANDLE) == static_cast<int32_t>(::android::hardware::keymaster::generic::ErrorCode::INVALID_OPERATION_HANDLE)) {
        os += (first ? "" : " | ");
        os += "INVALID_OPERATION_HANDLE";
        first = false;
        flipped |= ::android::hardware::keymaster::generic::ErrorCode::INVALID_OPERATION_HANDLE;
    }
    if ((o & ::android::hardware::keymaster::generic::ErrorCode::INSUFFICIENT_BUFFER_SPACE) == static_cast<int32_t>(::android::hardware::keymaster::generic::ErrorCode::INSUFFICIENT_BUFFER_SPACE)) {
        os += (first ? "" : " | ");
        os += "INSUFFICIENT_BUFFER_SPACE";
        first = false;
        flipped |= ::android::hardware::keymaster::generic::ErrorCode::INSUFFICIENT_BUFFER_SPACE;
    }
    if ((o & ::android::hardware::keymaster::generic::ErrorCode::VERIFICATION_FAILED) == static_cast<int32_t>(::android::hardware::keymaster::generic::ErrorCode::VERIFICATION_FAILED)) {
        os += (first ? "" : " | ");
        os += "VERIFICATION_FAILED";
        first = false;
        flipped |= ::android::hardware::keymaster::generic::ErrorCode::VERIFICATION_FAILED;
    }
    if ((o & ::android::hardware::keymaster::generic::ErrorCode::TOO_MANY_OPERATIONS) == static_cast<int32_t>(::android::hardware::keymaster::generic::ErrorCode::TOO_MANY_OPERATIONS)) {
        os += (first ? "" : " | ");
        os += "TOO_MANY_OPERATIONS";
        first = false;
        flipped |= ::android::hardware::keymaster::generic::ErrorCode::TOO_MANY_OPERATIONS;
    }
    if ((o & ::android::hardware::keymaster::generic::ErrorCode::UNEXPECTED_NULL_POINTER) == static_cast<int32_t>(::android::hardware::keymaster::generic::ErrorCode::UNEXPECTED_NULL_POINTER)) {
        os += (first ? "" : " | ");
        os += "UNEXPECTED_NULL_POINTER";
        first = false;
        flipped |= ::android::hardware::keymaster::generic::ErrorCode::UNEXPECTED_NULL_POINTER;
    }
    if ((o & ::android::hardware::keymaster::generic::ErrorCode::INVALID_KEY_BLOB) == static_cast<int32_t>(::android::hardware::keymaster::generic::ErrorCode::INVALID_KEY_BLOB)) {
        os += (first ? "" : " | ");
        os += "INVALID_KEY_BLOB";
        first = false;
        flipped |= ::android::hardware::keymaster::generic::ErrorCode::INVALID_KEY_BLOB;
    }
    if ((o & ::android::hardware::keymaster::generic::ErrorCode::IMPORTED_KEY_NOT_ENCRYPTED) == static_cast<int32_t>(::android::hardware::keymaster::generic::ErrorCode::IMPORTED_KEY_NOT_ENCRYPTED)) {
        os += (first ? "" : " | ");
        os += "IMPORTED_KEY_NOT_ENCRYPTED";
        first = false;
        flipped |= ::android::hardware::keymaster::generic::ErrorCode::IMPORTED_KEY_NOT_ENCRYPTED;
    }
    if ((o & ::android::hardware::keymaster::generic::ErrorCode::IMPORTED_KEY_DECRYPTION_FAILED) == static_cast<int32_t>(::android::hardware::keymaster::generic::ErrorCode::IMPORTED_KEY_DECRYPTION_FAILED)) {
        os += (first ? "" : " | ");
        os += "IMPORTED_KEY_DECRYPTION_FAILED";
        first = false;
        flipped |= ::android::hardware::keymaster::generic::ErrorCode::IMPORTED_KEY_DECRYPTION_FAILED;
    }
    if ((o & ::android::hardware::keymaster::generic::ErrorCode::IMPORTED_KEY_NOT_SIGNED) == static_cast<int32_t>(::android::hardware::keymaster::generic::ErrorCode::IMPORTED_KEY_NOT_SIGNED)) {
        os += (first ? "" : " | ");
        os += "IMPORTED_KEY_NOT_SIGNED";
        first = false;
        flipped |= ::android::hardware::keymaster::generic::ErrorCode::IMPORTED_KEY_NOT_SIGNED;
    }
    if ((o & ::android::hardware::keymaster::generic::ErrorCode::IMPORTED_KEY_VERIFICATION_FAILED) == static_cast<int32_t>(::android::hardware::keymaster::generic::ErrorCode::IMPORTED_KEY_VERIFICATION_FAILED)) {
        os += (first ? "" : " | ");
        os += "IMPORTED_KEY_VERIFICATION_FAILED";
        first = false;
        flipped |= ::android::hardware::keymaster::generic::ErrorCode::IMPORTED_KEY_VERIFICATION_FAILED;
    }
    if ((o & ::android::hardware::keymaster::generic::ErrorCode::INVALID_ARGUMENT) == static_cast<int32_t>(::android::hardware::keymaster::generic::ErrorCode::INVALID_ARGUMENT)) {
        os += (first ? "" : " | ");
        os += "INVALID_ARGUMENT";
        first = false;
        flipped |= ::android::hardware::keymaster::generic::ErrorCode::INVALID_ARGUMENT;
    }
    if ((o & ::android::hardware::keymaster::generic::ErrorCode::UNSUPPORTED_TAG) == static_cast<int32_t>(::android::hardware::keymaster::generic::ErrorCode::UNSUPPORTED_TAG)) {
        os += (first ? "" : " | ");
        os += "UNSUPPORTED_TAG";
        first = false;
        flipped |= ::android::hardware::keymaster::generic::ErrorCode::UNSUPPORTED_TAG;
    }
    if ((o & ::android::hardware::keymaster::generic::ErrorCode::INVALID_TAG) == static_cast<int32_t>(::android::hardware::keymaster::generic::ErrorCode::INVALID_TAG)) {
        os += (first ? "" : " | ");
        os += "INVALID_TAG";
        first = false;
        flipped |= ::android::hardware::keymaster::generic::ErrorCode::INVALID_TAG;
    }
    if ((o & ::android::hardware::keymaster::generic::ErrorCode::MEMORY_ALLOCATION_FAILED) == static_cast<int32_t>(::android::hardware::keymaster::generic::ErrorCode::MEMORY_ALLOCATION_FAILED)) {
        os += (first ? "" : " | ");
        os += "MEMORY_ALLOCATION_FAILED";
        first = false;
        flipped |= ::android::hardware::keymaster::generic::ErrorCode::MEMORY_ALLOCATION_FAILED;
    }
    if ((o & ::android::hardware::keymaster::generic::ErrorCode::IMPORT_PARAMETER_MISMATCH) == static_cast<int32_t>(::android::hardware::keymaster::generic::ErrorCode::IMPORT_PARAMETER_MISMATCH)) {
        os += (first ? "" : " | ");
        os += "IMPORT_PARAMETER_MISMATCH";
        first = false;
        flipped |= ::android::hardware::keymaster::generic::ErrorCode::IMPORT_PARAMETER_MISMATCH;
    }
    if ((o & ::android::hardware::keymaster::generic::ErrorCode::SECURE_HW_ACCESS_DENIED) == static_cast<int32_t>(::android::hardware::keymaster::generic::ErrorCode::SECURE_HW_ACCESS_DENIED)) {
        os += (first ? "" : " | ");
        os += "SECURE_HW_ACCESS_DENIED";
        first = false;
        flipped |= ::android::hardware::keymaster::generic::ErrorCode::SECURE_HW_ACCESS_DENIED;
    }
    if ((o & ::android::hardware::keymaster::generic::ErrorCode::OPERATION_CANCELLED) == static_cast<int32_t>(::android::hardware::keymaster::generic::ErrorCode::OPERATION_CANCELLED)) {
        os += (first ? "" : " | ");
        os += "OPERATION_CANCELLED";
        first = false;
        flipped |= ::android::hardware::keymaster::generic::ErrorCode::OPERATION_CANCELLED;
    }
    if ((o & ::android::hardware::keymaster::generic::ErrorCode::CONCURRENT_ACCESS_CONFLICT) == static_cast<int32_t>(::android::hardware::keymaster::generic::ErrorCode::CONCURRENT_ACCESS_CONFLICT)) {
        os += (first ? "" : " | ");
        os += "CONCURRENT_ACCESS_CONFLICT";
        first = false;
        flipped |= ::android::hardware::keymaster::generic::ErrorCode::CONCURRENT_ACCESS_CONFLICT;
    }
    if ((o & ::android::hardware::keymaster::generic::ErrorCode::SECURE_HW_BUSY) == static_cast<int32_t>(::android::hardware::keymaster::generic::ErrorCode::SECURE_HW_BUSY)) {
        os += (first ? "" : " | ");
        os += "SECURE_HW_BUSY";
        first = false;
        flipped |= ::android::hardware::keymaster::generic::ErrorCode::SECURE_HW_BUSY;
    }
    if ((o & ::android::hardware::keymaster::generic::ErrorCode::SECURE_HW_COMMUNICATION_FAILED) == static_cast<int32_t>(::android::hardware::keymaster::generic::ErrorCode::SECURE_HW_COMMUNICATION_FAILED)) {
        os += (first ? "" : " | ");
        os += "SECURE_HW_COMMUNICATION_FAILED";
        first = false;
        flipped |= ::android::hardware::keymaster::generic::ErrorCode::SECURE_HW_COMMUNICATION_FAILED;
    }
    if ((o & ::android::hardware::keymaster::generic::ErrorCode::UNSUPPORTED_EC_FIELD) == static_cast<int32_t>(::android::hardware::keymaster::generic::ErrorCode::UNSUPPORTED_EC_FIELD)) {
        os += (first ? "" : " | ");
        os += "UNSUPPORTED_EC_FIELD";
        first = false;
        flipped |= ::android::hardware::keymaster::generic::ErrorCode::UNSUPPORTED_EC_FIELD;
    }
    if ((o & ::android::hardware::keymaster::generic::ErrorCode::MISSING_NONCE) == static_cast<int32_t>(::android::hardware::keymaster::generic::ErrorCode::MISSING_NONCE)) {
        os += (first ? "" : " | ");
        os += "MISSING_NONCE";
        first = false;
        flipped |= ::android::hardware::keymaster::generic::ErrorCode::MISSING_NONCE;
    }
    if ((o & ::android::hardware::keymaster::generic::ErrorCode::INVALID_NONCE) == static_cast<int32_t>(::android::hardware::keymaster::generic::ErrorCode::INVALID_NONCE)) {
        os += (first ? "" : " | ");
        os += "INVALID_NONCE";
        first = false;
        flipped |= ::android::hardware::keymaster::generic::ErrorCode::INVALID_NONCE;
    }
    if ((o & ::android::hardware::keymaster::generic::ErrorCode::MISSING_MAC_LENGTH) == static_cast<int32_t>(::android::hardware::keymaster::generic::ErrorCode::MISSING_MAC_LENGTH)) {
        os += (first ? "" : " | ");
        os += "MISSING_MAC_LENGTH";
        first = false;
        flipped |= ::android::hardware::keymaster::generic::ErrorCode::MISSING_MAC_LENGTH;
    }
    if ((o & ::android::hardware::keymaster::generic::ErrorCode::KEY_RATE_LIMIT_EXCEEDED) == static_cast<int32_t>(::android::hardware::keymaster::generic::ErrorCode::KEY_RATE_LIMIT_EXCEEDED)) {
        os += (first ? "" : " | ");
        os += "KEY_RATE_LIMIT_EXCEEDED";
        first = false;
        flipped |= ::android::hardware::keymaster::generic::ErrorCode::KEY_RATE_LIMIT_EXCEEDED;
    }
    if ((o & ::android::hardware::keymaster::generic::ErrorCode::CALLER_NONCE_PROHIBITED) == static_cast<int32_t>(::android::hardware::keymaster::generic::ErrorCode::CALLER_NONCE_PROHIBITED)) {
        os += (first ? "" : " | ");
        os += "CALLER_NONCE_PROHIBITED";
        first = false;
        flipped |= ::android::hardware::keymaster::generic::ErrorCode::CALLER_NONCE_PROHIBITED;
    }
    if ((o & ::android::hardware::keymaster::generic::ErrorCode::KEY_MAX_OPS_EXCEEDED) == static_cast<int32_t>(::android::hardware::keymaster::generic::ErrorCode::KEY_MAX_OPS_EXCEEDED)) {
        os += (first ? "" : " | ");
        os += "KEY_MAX_OPS_EXCEEDED";
        first = false;
        flipped |= ::android::hardware::keymaster::generic::ErrorCode::KEY_MAX_OPS_EXCEEDED;
    }
    if ((o & ::android::hardware::keymaster::generic::ErrorCode::INVALID_MAC_LENGTH) == static_cast<int32_t>(::android::hardware::keymaster::generic::ErrorCode::INVALID_MAC_LENGTH)) {
        os += (first ? "" : " | ");
        os += "INVALID_MAC_LENGTH";
        first = false;
        flipped |= ::android::hardware::keymaster::generic::ErrorCode::INVALID_MAC_LENGTH;
    }
    if ((o & ::android::hardware::keymaster::generic::ErrorCode::MISSING_MIN_MAC_LENGTH) == static_cast<int32_t>(::android::hardware::keymaster::generic::ErrorCode::MISSING_MIN_MAC_LENGTH)) {
        os += (first ? "" : " | ");
        os += "MISSING_MIN_MAC_LENGTH";
        first = false;
        flipped |= ::android::hardware::keymaster::generic::ErrorCode::MISSING_MIN_MAC_LENGTH;
    }
    if ((o & ::android::hardware::keymaster::generic::ErrorCode::UNSUPPORTED_MIN_MAC_LENGTH) == static_cast<int32_t>(::android::hardware::keymaster::generic::ErrorCode::UNSUPPORTED_MIN_MAC_LENGTH)) {
        os += (first ? "" : " | ");
        os += "UNSUPPORTED_MIN_MAC_LENGTH";
        first = false;
        flipped |= ::android::hardware::keymaster::generic::ErrorCode::UNSUPPORTED_MIN_MAC_LENGTH;
    }
    if ((o & ::android::hardware::keymaster::generic::ErrorCode::UNSUPPORTED_KDF) == static_cast<int32_t>(::android::hardware::keymaster::generic::ErrorCode::UNSUPPORTED_KDF)) {
        os += (first ? "" : " | ");
        os += "UNSUPPORTED_KDF";
        first = false;
        flipped |= ::android::hardware::keymaster::generic::ErrorCode::UNSUPPORTED_KDF;
    }
    if ((o & ::android::hardware::keymaster::generic::ErrorCode::UNSUPPORTED_EC_CURVE) == static_cast<int32_t>(::android::hardware::keymaster::generic::ErrorCode::UNSUPPORTED_EC_CURVE)) {
        os += (first ? "" : " | ");
        os += "UNSUPPORTED_EC_CURVE";
        first = false;
        flipped |= ::android::hardware::keymaster::generic::ErrorCode::UNSUPPORTED_EC_CURVE;
    }
    if ((o & ::android::hardware::keymaster::generic::ErrorCode::KEY_REQUIRES_UPGRADE) == static_cast<int32_t>(::android::hardware::keymaster::generic::ErrorCode::KEY_REQUIRES_UPGRADE)) {
        os += (first ? "" : " | ");
        os += "KEY_REQUIRES_UPGRADE";
        first = false;
        flipped |= ::android::hardware::keymaster::generic::ErrorCode::KEY_REQUIRES_UPGRADE;
    }
    if ((o & ::android::hardware::keymaster::generic::ErrorCode::ATTESTATION_CHALLENGE_MISSING) == static_cast<int32_t>(::android::hardware::keymaster::generic::ErrorCode::ATTESTATION_CHALLENGE_MISSING)) {
        os += (first ? "" : " | ");
        os += "ATTESTATION_CHALLENGE_MISSING";
        first = false;
        flipped |= ::android::hardware::keymaster::generic::ErrorCode::ATTESTATION_CHALLENGE_MISSING;
    }
    if ((o & ::android::hardware::keymaster::generic::ErrorCode::KEYMASTER_NOT_CONFIGURED) == static_cast<int32_t>(::android::hardware::keymaster::generic::ErrorCode::KEYMASTER_NOT_CONFIGURED)) {
        os += (first ? "" : " | ");
        os += "KEYMASTER_NOT_CONFIGURED";
        first = false;
        flipped |= ::android::hardware::keymaster::generic::ErrorCode::KEYMASTER_NOT_CONFIGURED;
    }
    if ((o & ::android::hardware::keymaster::generic::ErrorCode::ATTESTATION_APPLICATION_ID_MISSING) == static_cast<int32_t>(::android::hardware::keymaster::generic::ErrorCode::ATTESTATION_APPLICATION_ID_MISSING)) {
        os += (first ? "" : " | ");
        os += "ATTESTATION_APPLICATION_ID_MISSING";
        first = false;
        flipped |= ::android::hardware::keymaster::generic::ErrorCode::ATTESTATION_APPLICATION_ID_MISSING;
    }
    if ((o & ::android::hardware::keymaster::generic::ErrorCode::CANNOT_ATTEST_IDS) == static_cast<int32_t>(::android::hardware::keymaster::generic::ErrorCode::CANNOT_ATTEST_IDS)) {
        os += (first ? "" : " | ");
        os += "CANNOT_ATTEST_IDS";
        first = false;
        flipped |= ::android::hardware::keymaster::generic::ErrorCode::CANNOT_ATTEST_IDS;
    }
    if ((o & ::android::hardware::keymaster::generic::ErrorCode::ROLLBACK_RESISTANCE_UNAVAILABLE) == static_cast<int32_t>(::android::hardware::keymaster::generic::ErrorCode::ROLLBACK_RESISTANCE_UNAVAILABLE)) {
        os += (first ? "" : " | ");
        os += "ROLLBACK_RESISTANCE_UNAVAILABLE";
        first = false;
        flipped |= ::android::hardware::keymaster::generic::ErrorCode::ROLLBACK_RESISTANCE_UNAVAILABLE;
    }
    if ((o & ::android::hardware::keymaster::generic::ErrorCode::HARDWARE_TYPE_UNAVAILABLE) == static_cast<int32_t>(::android::hardware::keymaster::generic::ErrorCode::HARDWARE_TYPE_UNAVAILABLE)) {
        os += (first ? "" : " | ");
        os += "HARDWARE_TYPE_UNAVAILABLE";
        first = false;
        flipped |= ::android::hardware::keymaster::generic::ErrorCode::HARDWARE_TYPE_UNAVAILABLE;
    }
    if ((o & ::android::hardware::keymaster::generic::ErrorCode::PROOF_OF_PRESENCE_REQUIRED) == static_cast<int32_t>(::android::hardware::keymaster::generic::ErrorCode::PROOF_OF_PRESENCE_REQUIRED)) {
        os += (first ? "" : " | ");
        os += "PROOF_OF_PRESENCE_REQUIRED";
        first = false;
        flipped |= ::android::hardware::keymaster::generic::ErrorCode::PROOF_OF_PRESENCE_REQUIRED;
    }
    if ((o & ::android::hardware::keymaster::generic::ErrorCode::CONCURRENT_PROOF_OF_PRESENCE_REQUESTED) == static_cast<int32_t>(::android::hardware::keymaster::generic::ErrorCode::CONCURRENT_PROOF_OF_PRESENCE_REQUESTED)) {
        os += (first ? "" : " | ");
        os += "CONCURRENT_PROOF_OF_PRESENCE_REQUESTED";
        first = false;
        flipped |= ::android::hardware::keymaster::generic::ErrorCode::CONCURRENT_PROOF_OF_PRESENCE_REQUESTED;
    }
    if ((o & ::android::hardware::keymaster::generic::ErrorCode::NO_USER_CONFIRMATION) == static_cast<int32_t>(::android::hardware::keymaster::generic::ErrorCode::NO_USER_CONFIRMATION)) {
        os += (first ? "" : " | ");
        os += "NO_USER_CONFIRMATION";
        first = false;
        flipped |= ::android::hardware::keymaster::generic::ErrorCode::NO_USER_CONFIRMATION;
    }
    if ((o & ::android::hardware::keymaster::generic::ErrorCode::DEVICE_LOCKED) == static_cast<int32_t>(::android::hardware::keymaster::generic::ErrorCode::DEVICE_LOCKED)) {
        os += (first ? "" : " | ");
        os += "DEVICE_LOCKED";
        first = false;
        flipped |= ::android::hardware::keymaster::generic::ErrorCode::DEVICE_LOCKED;
    }
    if ((o & ::android::hardware::keymaster::generic::ErrorCode::UNIMPLEMENTED) == static_cast<int32_t>(::android::hardware::keymaster::generic::ErrorCode::UNIMPLEMENTED)) {
        os += (first ? "" : " | ");
        os += "UNIMPLEMENTED";
        first = false;
        flipped |= ::android::hardware::keymaster::generic::ErrorCode::UNIMPLEMENTED;
    }
    if ((o & ::android::hardware::keymaster::generic::ErrorCode::VERSION_MISMATCH) == static_cast<int32_t>(::android::hardware::keymaster::generic::ErrorCode::VERSION_MISMATCH)) {
        os += (first ? "" : " | ");
        os += "VERSION_MISMATCH";
        first = false;
        flipped |= ::android::hardware::keymaster::generic::ErrorCode::VERSION_MISMATCH;
    }
    if ((o & ::android::hardware::keymaster::generic::ErrorCode::UNKNOWN_ERROR) == static_cast<int32_t>(::android::hardware::keymaster::generic::ErrorCode::UNKNOWN_ERROR)) {
        os += (first ? "" : " | ");
        os += "UNKNOWN_ERROR";
        first = false;
        flipped |= ::android::hardware::keymaster::generic::ErrorCode::UNKNOWN_ERROR;
    }
    if (o != flipped) {
        os += (first ? "" : " | ");
        os += toHexString(o & (~flipped));
    }os += " (";
    os += toHexString(o);
    os += ")";
    return os;
}

static inline std::string toString(::android::hardware::keymaster::generic::ErrorCode o) {
    using ::android::hardware::details::toHexString;
    if (o == ::android::hardware::keymaster::generic::ErrorCode::OK) {
        return "OK";
    }
    if (o == ::android::hardware::keymaster::generic::ErrorCode::ROOT_OF_TRUST_ALREADY_SET) {
        return "ROOT_OF_TRUST_ALREADY_SET";
    }
    if (o == ::android::hardware::keymaster::generic::ErrorCode::UNSUPPORTED_PURPOSE) {
        return "UNSUPPORTED_PURPOSE";
    }
    if (o == ::android::hardware::keymaster::generic::ErrorCode::INCOMPATIBLE_PURPOSE) {
        return "INCOMPATIBLE_PURPOSE";
    }
    if (o == ::android::hardware::keymaster::generic::ErrorCode::UNSUPPORTED_ALGORITHM) {
        return "UNSUPPORTED_ALGORITHM";
    }
    if (o == ::android::hardware::keymaster::generic::ErrorCode::INCOMPATIBLE_ALGORITHM) {
        return "INCOMPATIBLE_ALGORITHM";
    }
    if (o == ::android::hardware::keymaster::generic::ErrorCode::UNSUPPORTED_KEY_SIZE) {
        return "UNSUPPORTED_KEY_SIZE";
    }
    if (o == ::android::hardware::keymaster::generic::ErrorCode::UNSUPPORTED_BLOCK_MODE) {
        return "UNSUPPORTED_BLOCK_MODE";
    }
    if (o == ::android::hardware::keymaster::generic::ErrorCode::INCOMPATIBLE_BLOCK_MODE) {
        return "INCOMPATIBLE_BLOCK_MODE";
    }
    if (o == ::android::hardware::keymaster::generic::ErrorCode::UNSUPPORTED_MAC_LENGTH) {
        return "UNSUPPORTED_MAC_LENGTH";
    }
    if (o == ::android::hardware::keymaster::generic::ErrorCode::UNSUPPORTED_PADDING_MODE) {
        return "UNSUPPORTED_PADDING_MODE";
    }
    if (o == ::android::hardware::keymaster::generic::ErrorCode::INCOMPATIBLE_PADDING_MODE) {
        return "INCOMPATIBLE_PADDING_MODE";
    }
    if (o == ::android::hardware::keymaster::generic::ErrorCode::UNSUPPORTED_DIGEST) {
        return "UNSUPPORTED_DIGEST";
    }
    if (o == ::android::hardware::keymaster::generic::ErrorCode::INCOMPATIBLE_DIGEST) {
        return "INCOMPATIBLE_DIGEST";
    }
    if (o == ::android::hardware::keymaster::generic::ErrorCode::INVALID_EXPIRATION_TIME) {
        return "INVALID_EXPIRATION_TIME";
    }
    if (o == ::android::hardware::keymaster::generic::ErrorCode::INVALID_USER_ID) {
        return "INVALID_USER_ID";
    }
    if (o == ::android::hardware::keymaster::generic::ErrorCode::INVALID_AUTHORIZATION_TIMEOUT) {
        return "INVALID_AUTHORIZATION_TIMEOUT";
    }
    if (o == ::android::hardware::keymaster::generic::ErrorCode::UNSUPPORTED_KEY_FORMAT) {
        return "UNSUPPORTED_KEY_FORMAT";
    }
    if (o == ::android::hardware::keymaster::generic::ErrorCode::INCOMPATIBLE_KEY_FORMAT) {
        return "INCOMPATIBLE_KEY_FORMAT";
    }
    if (o == ::android::hardware::keymaster::generic::ErrorCode::UNSUPPORTED_KEY_ENCRYPTION_ALGORITHM) {
        return "UNSUPPORTED_KEY_ENCRYPTION_ALGORITHM";
    }
    if (o == ::android::hardware::keymaster::generic::ErrorCode::UNSUPPORTED_KEY_VERIFICATION_ALGORITHM) {
        return "UNSUPPORTED_KEY_VERIFICATION_ALGORITHM";
    }
    if (o == ::android::hardware::keymaster::generic::ErrorCode::INVALID_INPUT_LENGTH) {
        return "INVALID_INPUT_LENGTH";
    }
    if (o == ::android::hardware::keymaster::generic::ErrorCode::KEY_EXPORT_OPTIONS_INVALID) {
        return "KEY_EXPORT_OPTIONS_INVALID";
    }
    if (o == ::android::hardware::keymaster::generic::ErrorCode::DELEGATION_NOT_ALLOWED) {
        return "DELEGATION_NOT_ALLOWED";
    }
    if (o == ::android::hardware::keymaster::generic::ErrorCode::KEY_NOT_YET_VALID) {
        return "KEY_NOT_YET_VALID";
    }
    if (o == ::android::hardware::keymaster::generic::ErrorCode::KEY_EXPIRED) {
        return "KEY_EXPIRED";
    }
    if (o == ::android::hardware::keymaster::generic::ErrorCode::KEY_USER_NOT_AUTHENTICATED) {
        return "KEY_USER_NOT_AUTHENTICATED";
    }
    if (o == ::android::hardware::keymaster::generic::ErrorCode::OUTPUT_PARAMETER_NULL) {
        return "OUTPUT_PARAMETER_NULL";
    }
    if (o == ::android::hardware::keymaster::generic::ErrorCode::INVALID_OPERATION_HANDLE) {
        return "INVALID_OPERATION_HANDLE";
    }
    if (o == ::android::hardware::keymaster::generic::ErrorCode::INSUFFICIENT_BUFFER_SPACE) {
        return "INSUFFICIENT_BUFFER_SPACE";
    }
    if (o == ::android::hardware::keymaster::generic::ErrorCode::VERIFICATION_FAILED) {
        return "VERIFICATION_FAILED";
    }
    if (o == ::android::hardware::keymaster::generic::ErrorCode::TOO_MANY_OPERATIONS) {
        return "TOO_MANY_OPERATIONS";
    }
    if (o == ::android::hardware::keymaster::generic::ErrorCode::UNEXPECTED_NULL_POINTER) {
        return "UNEXPECTED_NULL_POINTER";
    }
    if (o == ::android::hardware::keymaster::generic::ErrorCode::INVALID_KEY_BLOB) {
        return "INVALID_KEY_BLOB";
    }
    if (o == ::android::hardware::keymaster::generic::ErrorCode::IMPORTED_KEY_NOT_ENCRYPTED) {
        return "IMPORTED_KEY_NOT_ENCRYPTED";
    }
    if (o == ::android::hardware::keymaster::generic::ErrorCode::IMPORTED_KEY_DECRYPTION_FAILED) {
        return "IMPORTED_KEY_DECRYPTION_FAILED";
    }
    if (o == ::android::hardware::keymaster::generic::ErrorCode::IMPORTED_KEY_NOT_SIGNED) {
        return "IMPORTED_KEY_NOT_SIGNED";
    }
    if (o == ::android::hardware::keymaster::generic::ErrorCode::IMPORTED_KEY_VERIFICATION_FAILED) {
        return "IMPORTED_KEY_VERIFICATION_FAILED";
    }
    if (o == ::android::hardware::keymaster::generic::ErrorCode::INVALID_ARGUMENT) {
        return "INVALID_ARGUMENT";
    }
    if (o == ::android::hardware::keymaster::generic::ErrorCode::UNSUPPORTED_TAG) {
        return "UNSUPPORTED_TAG";
    }
    if (o == ::android::hardware::keymaster::generic::ErrorCode::INVALID_TAG) {
        return "INVALID_TAG";
    }
    if (o == ::android::hardware::keymaster::generic::ErrorCode::MEMORY_ALLOCATION_FAILED) {
        return "MEMORY_ALLOCATION_FAILED";
    }
    if (o == ::android::hardware::keymaster::generic::ErrorCode::IMPORT_PARAMETER_MISMATCH) {
        return "IMPORT_PARAMETER_MISMATCH";
    }
    if (o == ::android::hardware::keymaster::generic::ErrorCode::SECURE_HW_ACCESS_DENIED) {
        return "SECURE_HW_ACCESS_DENIED";
    }
    if (o == ::android::hardware::keymaster::generic::ErrorCode::OPERATION_CANCELLED) {
        return "OPERATION_CANCELLED";
    }
    if (o == ::android::hardware::keymaster::generic::ErrorCode::CONCURRENT_ACCESS_CONFLICT) {
        return "CONCURRENT_ACCESS_CONFLICT";
    }
    if (o == ::android::hardware::keymaster::generic::ErrorCode::SECURE_HW_BUSY) {
        return "SECURE_HW_BUSY";
    }
    if (o == ::android::hardware::keymaster::generic::ErrorCode::SECURE_HW_COMMUNICATION_FAILED) {
        return "SECURE_HW_COMMUNICATION_FAILED";
    }
    if (o == ::android::hardware::keymaster::generic::ErrorCode::UNSUPPORTED_EC_FIELD) {
        return "UNSUPPORTED_EC_FIELD";
    }
    if (o == ::android::hardware::keymaster::generic::ErrorCode::MISSING_NONCE) {
        return "MISSING_NONCE";
    }
    if (o == ::android::hardware::keymaster::generic::ErrorCode::INVALID_NONCE) {
        return "INVALID_NONCE";
    }
    if (o == ::android::hardware::keymaster::generic::ErrorCode::MISSING_MAC_LENGTH) {
        return "MISSING_MAC_LENGTH";
    }
    if (o == ::android::hardware::keymaster::generic::ErrorCode::KEY_RATE_LIMIT_EXCEEDED) {
        return "KEY_RATE_LIMIT_EXCEEDED";
    }
    if (o == ::android::hardware::keymaster::generic::ErrorCode::CALLER_NONCE_PROHIBITED) {
        return "CALLER_NONCE_PROHIBITED";
    }
    if (o == ::android::hardware::keymaster::generic::ErrorCode::KEY_MAX_OPS_EXCEEDED) {
        return "KEY_MAX_OPS_EXCEEDED";
    }
    if (o == ::android::hardware::keymaster::generic::ErrorCode::INVALID_MAC_LENGTH) {
        return "INVALID_MAC_LENGTH";
    }
    if (o == ::android::hardware::keymaster::generic::ErrorCode::MISSING_MIN_MAC_LENGTH) {
        return "MISSING_MIN_MAC_LENGTH";
    }
    if (o == ::android::hardware::keymaster::generic::ErrorCode::UNSUPPORTED_MIN_MAC_LENGTH) {
        return "UNSUPPORTED_MIN_MAC_LENGTH";
    }
    if (o == ::android::hardware::keymaster::generic::ErrorCode::UNSUPPORTED_KDF) {
        return "UNSUPPORTED_KDF";
    }
    if (o == ::android::hardware::keymaster::generic::ErrorCode::UNSUPPORTED_EC_CURVE) {
        return "UNSUPPORTED_EC_CURVE";
    }
    if (o == ::android::hardware::keymaster::generic::ErrorCode::KEY_REQUIRES_UPGRADE) {
        return "KEY_REQUIRES_UPGRADE";
    }
    if (o == ::android::hardware::keymaster::generic::ErrorCode::ATTESTATION_CHALLENGE_MISSING) {
        return "ATTESTATION_CHALLENGE_MISSING";
    }
    if (o == ::android::hardware::keymaster::generic::ErrorCode::KEYMASTER_NOT_CONFIGURED) {
        return "KEYMASTER_NOT_CONFIGURED";
    }
    if (o == ::android::hardware::keymaster::generic::ErrorCode::ATTESTATION_APPLICATION_ID_MISSING) {
        return "ATTESTATION_APPLICATION_ID_MISSING";
    }
    if (o == ::android::hardware::keymaster::generic::ErrorCode::CANNOT_ATTEST_IDS) {
        return "CANNOT_ATTEST_IDS";
    }
    if (o == ::android::hardware::keymaster::generic::ErrorCode::ROLLBACK_RESISTANCE_UNAVAILABLE) {
        return "ROLLBACK_RESISTANCE_UNAVAILABLE";
    }
    if (o == ::android::hardware::keymaster::generic::ErrorCode::HARDWARE_TYPE_UNAVAILABLE) {
        return "HARDWARE_TYPE_UNAVAILABLE";
    }
    if (o == ::android::hardware::keymaster::generic::ErrorCode::PROOF_OF_PRESENCE_REQUIRED) {
        return "PROOF_OF_PRESENCE_REQUIRED";
    }
    if (o == ::android::hardware::keymaster::generic::ErrorCode::CONCURRENT_PROOF_OF_PRESENCE_REQUESTED) {
        return "CONCURRENT_PROOF_OF_PRESENCE_REQUESTED";
    }
    if (o == ::android::hardware::keymaster::generic::ErrorCode::NO_USER_CONFIRMATION) {
        return "NO_USER_CONFIRMATION";
    }
    if (o == ::android::hardware::keymaster::generic::ErrorCode::DEVICE_LOCKED) {
        return "DEVICE_LOCKED";
    }
    if (o == ::android::hardware::keymaster::generic::ErrorCode::UNIMPLEMENTED) {
        return "UNIMPLEMENTED";
    }
    if (o == ::android::hardware::keymaster::generic::ErrorCode::VERSION_MISMATCH) {
        return "VERSION_MISMATCH";
    }
    if (o == ::android::hardware::keymaster::generic::ErrorCode::UNKNOWN_ERROR) {
        return "UNKNOWN_ERROR";
    }
    std::string os;
    os += toHexString(static_cast<int32_t>(o));
    return os;
}

static inline void PrintTo(::android::hardware::keymaster::generic::ErrorCode o, ::std::ostream* os) {
    *os << toString(o);
}

template<>
inline std::string toString<::android::hardware::keymaster::generic::KeyDerivationFunction>(uint32_t o) {
    using ::android::hardware::details::toHexString;
    std::string os;
    ::android::hardware::hidl_bitfield<::android::hardware::keymaster::generic::KeyDerivationFunction> flipped = 0;
    bool first = true;
    if ((o & ::android::hardware::keymaster::generic::KeyDerivationFunction::NONE) == static_cast<uint32_t>(::android::hardware::keymaster::generic::KeyDerivationFunction::NONE)) {
        os += (first ? "" : " | ");
        os += "NONE";
        first = false;
        flipped |= ::android::hardware::keymaster::generic::KeyDerivationFunction::NONE;
    }
    if ((o & ::android::hardware::keymaster::generic::KeyDerivationFunction::RFC5869_SHA256) == static_cast<uint32_t>(::android::hardware::keymaster::generic::KeyDerivationFunction::RFC5869_SHA256)) {
        os += (first ? "" : " | ");
        os += "RFC5869_SHA256";
        first = false;
        flipped |= ::android::hardware::keymaster::generic::KeyDerivationFunction::RFC5869_SHA256;
    }
    if ((o & ::android::hardware::keymaster::generic::KeyDerivationFunction::ISO18033_2_KDF1_SHA1) == static_cast<uint32_t>(::android::hardware::keymaster::generic::KeyDerivationFunction::ISO18033_2_KDF1_SHA1)) {
        os += (first ? "" : " | ");
        os += "ISO18033_2_KDF1_SHA1";
        first = false;
        flipped |= ::android::hardware::keymaster::generic::KeyDerivationFunction::ISO18033_2_KDF1_SHA1;
    }
    if ((o & ::android::hardware::keymaster::generic::KeyDerivationFunction::ISO18033_2_KDF1_SHA256) == static_cast<uint32_t>(::android::hardware::keymaster::generic::KeyDerivationFunction::ISO18033_2_KDF1_SHA256)) {
        os += (first ? "" : " | ");
        os += "ISO18033_2_KDF1_SHA256";
        first = false;
        flipped |= ::android::hardware::keymaster::generic::KeyDerivationFunction::ISO18033_2_KDF1_SHA256;
    }
    if ((o & ::android::hardware::keymaster::generic::KeyDerivationFunction::ISO18033_2_KDF2_SHA1) == static_cast<uint32_t>(::android::hardware::keymaster::generic::KeyDerivationFunction::ISO18033_2_KDF2_SHA1)) {
        os += (first ? "" : " | ");
        os += "ISO18033_2_KDF2_SHA1";
        first = false;
        flipped |= ::android::hardware::keymaster::generic::KeyDerivationFunction::ISO18033_2_KDF2_SHA1;
    }
    if ((o & ::android::hardware::keymaster::generic::KeyDerivationFunction::ISO18033_2_KDF2_SHA256) == static_cast<uint32_t>(::android::hardware::keymaster::generic::KeyDerivationFunction::ISO18033_2_KDF2_SHA256)) {
        os += (first ? "" : " | ");
        os += "ISO18033_2_KDF2_SHA256";
        first = false;
        flipped |= ::android::hardware::keymaster::generic::KeyDerivationFunction::ISO18033_2_KDF2_SHA256;
    }
    if (o != flipped) {
        os += (first ? "" : " | ");
        os += toHexString(o & (~flipped));
    }os += " (";
    os += toHexString(o);
    os += ")";
    return os;
}

static inline std::string toString(::android::hardware::keymaster::generic::KeyDerivationFunction o) {
    using ::android::hardware::details::toHexString;
    if (o == ::android::hardware::keymaster::generic::KeyDerivationFunction::NONE) {
        return "NONE";
    }
    if (o == ::android::hardware::keymaster::generic::KeyDerivationFunction::RFC5869_SHA256) {
        return "RFC5869_SHA256";
    }
    if (o == ::android::hardware::keymaster::generic::KeyDerivationFunction::ISO18033_2_KDF1_SHA1) {
        return "ISO18033_2_KDF1_SHA1";
    }
    if (o == ::android::hardware::keymaster::generic::KeyDerivationFunction::ISO18033_2_KDF1_SHA256) {
        return "ISO18033_2_KDF1_SHA256";
    }
    if (o == ::android::hardware::keymaster::generic::KeyDerivationFunction::ISO18033_2_KDF2_SHA1) {
        return "ISO18033_2_KDF2_SHA1";
    }
    if (o == ::android::hardware::keymaster::generic::KeyDerivationFunction::ISO18033_2_KDF2_SHA256) {
        return "ISO18033_2_KDF2_SHA256";
    }
    std::string os;
    os += toHexString(static_cast<uint32_t>(o));
    return os;
}

static inline void PrintTo(::android::hardware::keymaster::generic::KeyDerivationFunction o, ::std::ostream* os) {
    *os << toString(o);
}

template<>
inline std::string toString<::android::hardware::keymaster::generic::HardwareAuthenticatorType>(uint32_t o) {
    using ::android::hardware::details::toHexString;
    std::string os;
    ::android::hardware::hidl_bitfield<::android::hardware::keymaster::generic::HardwareAuthenticatorType> flipped = 0;
    bool first = true;
    if ((o & ::android::hardware::keymaster::generic::HardwareAuthenticatorType::NONE) == static_cast<uint32_t>(::android::hardware::keymaster::generic::HardwareAuthenticatorType::NONE)) {
        os += (first ? "" : " | ");
        os += "NONE";
        first = false;
        flipped |= ::android::hardware::keymaster::generic::HardwareAuthenticatorType::NONE;
    }
    if ((o & ::android::hardware::keymaster::generic::HardwareAuthenticatorType::PASSWORD) == static_cast<uint32_t>(::android::hardware::keymaster::generic::HardwareAuthenticatorType::PASSWORD)) {
        os += (first ? "" : " | ");
        os += "PASSWORD";
        first = false;
        flipped |= ::android::hardware::keymaster::generic::HardwareAuthenticatorType::PASSWORD;
    }
    if ((o & ::android::hardware::keymaster::generic::HardwareAuthenticatorType::FINGERPRINT) == static_cast<uint32_t>(::android::hardware::keymaster::generic::HardwareAuthenticatorType::FINGERPRINT)) {
        os += (first ? "" : " | ");
        os += "FINGERPRINT";
        first = false;
        flipped |= ::android::hardware::keymaster::generic::HardwareAuthenticatorType::FINGERPRINT;
    }
    if ((o & ::android::hardware::keymaster::generic::HardwareAuthenticatorType::ANY) == static_cast<uint32_t>(::android::hardware::keymaster::generic::HardwareAuthenticatorType::ANY)) {
        os += (first ? "" : " | ");
        os += "ANY";
        first = false;
        flipped |= ::android::hardware::keymaster::generic::HardwareAuthenticatorType::ANY;
    }
    if (o != flipped) {
        os += (first ? "" : " | ");
        os += toHexString(o & (~flipped));
    }os += " (";
    os += toHexString(o);
    os += ")";
    return os;
}

static inline std::string toString(::android::hardware::keymaster::generic::HardwareAuthenticatorType o) {
    using ::android::hardware::details::toHexString;
    if (o == ::android::hardware::keymaster::generic::HardwareAuthenticatorType::NONE) {
        return "NONE";
    }
    if (o == ::android::hardware::keymaster::generic::HardwareAuthenticatorType::PASSWORD) {
        return "PASSWORD";
    }
    if (o == ::android::hardware::keymaster::generic::HardwareAuthenticatorType::FINGERPRINT) {
        return "FINGERPRINT";
    }
    if (o == ::android::hardware::keymaster::generic::HardwareAuthenticatorType::ANY) {
        return "ANY";
    }
    std::string os;
    os += toHexString(static_cast<uint32_t>(o));
    return os;
}

static inline void PrintTo(::android::hardware::keymaster::generic::HardwareAuthenticatorType o, ::std::ostream* os) {
    *os << toString(o);
}

template<>
inline std::string toString<::android::hardware::keymaster::generic::SecurityLevel>(uint32_t o) {
    using ::android::hardware::details::toHexString;
    std::string os;
    ::android::hardware::hidl_bitfield<::android::hardware::keymaster::generic::SecurityLevel> flipped = 0;
    bool first = true;
    if ((o & ::android::hardware::keymaster::generic::SecurityLevel::SOFTWARE) == static_cast<uint32_t>(::android::hardware::keymaster::generic::SecurityLevel::SOFTWARE)) {
        os += (first ? "" : " | ");
        os += "SOFTWARE";
        first = false;
        flipped |= ::android::hardware::keymaster::generic::SecurityLevel::SOFTWARE;
    }
    if ((o & ::android::hardware::keymaster::generic::SecurityLevel::TRUSTED_ENVIRONMENT) == static_cast<uint32_t>(::android::hardware::keymaster::generic::SecurityLevel::TRUSTED_ENVIRONMENT)) {
        os += (first ? "" : " | ");
        os += "TRUSTED_ENVIRONMENT";
        first = false;
        flipped |= ::android::hardware::keymaster::generic::SecurityLevel::TRUSTED_ENVIRONMENT;
    }
    if ((o & ::android::hardware::keymaster::generic::SecurityLevel::STRONGBOX) == static_cast<uint32_t>(::android::hardware::keymaster::generic::SecurityLevel::STRONGBOX)) {
        os += (first ? "" : " | ");
        os += "STRONGBOX";
        first = false;
        flipped |= ::android::hardware::keymaster::generic::SecurityLevel::STRONGBOX;
    }
    if (o != flipped) {
        os += (first ? "" : " | ");
        os += toHexString(o & (~flipped));
    }os += " (";
    os += toHexString(o);
    os += ")";
    return os;
}

static inline std::string toString(::android::hardware::keymaster::generic::SecurityLevel o) {
    using ::android::hardware::details::toHexString;
    if (o == ::android::hardware::keymaster::generic::SecurityLevel::SOFTWARE) {
        return "SOFTWARE";
    }
    if (o == ::android::hardware::keymaster::generic::SecurityLevel::TRUSTED_ENVIRONMENT) {
        return "TRUSTED_ENVIRONMENT";
    }
    if (o == ::android::hardware::keymaster::generic::SecurityLevel::STRONGBOX) {
        return "STRONGBOX";
    }
    std::string os;
    os += toHexString(static_cast<uint32_t>(o));
    return os;
}

static inline void PrintTo(::android::hardware::keymaster::generic::SecurityLevel o, ::std::ostream* os) {
    *os << toString(o);
}

template<>
inline std::string toString<::android::hardware::keymaster::generic::KeyFormat>(uint32_t o) {
    using ::android::hardware::details::toHexString;
    std::string os;
    ::android::hardware::hidl_bitfield<::android::hardware::keymaster::generic::KeyFormat> flipped = 0;
    bool first = true;
    if ((o & ::android::hardware::keymaster::generic::KeyFormat::X509) == static_cast<uint32_t>(::android::hardware::keymaster::generic::KeyFormat::X509)) {
        os += (first ? "" : " | ");
        os += "X509";
        first = false;
        flipped |= ::android::hardware::keymaster::generic::KeyFormat::X509;
    }
    if ((o & ::android::hardware::keymaster::generic::KeyFormat::PKCS8) == static_cast<uint32_t>(::android::hardware::keymaster::generic::KeyFormat::PKCS8)) {
        os += (first ? "" : " | ");
        os += "PKCS8";
        first = false;
        flipped |= ::android::hardware::keymaster::generic::KeyFormat::PKCS8;
    }
    if ((o & ::android::hardware::keymaster::generic::KeyFormat::RAW) == static_cast<uint32_t>(::android::hardware::keymaster::generic::KeyFormat::RAW)) {
        os += (first ? "" : " | ");
        os += "RAW";
        first = false;
        flipped |= ::android::hardware::keymaster::generic::KeyFormat::RAW;
    }
    if (o != flipped) {
        os += (first ? "" : " | ");
        os += toHexString(o & (~flipped));
    }os += " (";
    os += toHexString(o);
    os += ")";
    return os;
}

static inline std::string toString(::android::hardware::keymaster::generic::KeyFormat o) {
    using ::android::hardware::details::toHexString;
    if (o == ::android::hardware::keymaster::generic::KeyFormat::X509) {
        return "X509";
    }
    if (o == ::android::hardware::keymaster::generic::KeyFormat::PKCS8) {
        return "PKCS8";
    }
    if (o == ::android::hardware::keymaster::generic::KeyFormat::RAW) {
        return "RAW";
    }
    std::string os;
    os += toHexString(static_cast<uint32_t>(o));
    return os;
}

static inline void PrintTo(::android::hardware::keymaster::generic::KeyFormat o, ::std::ostream* os) {
    *os << toString(o);
}

static inline std::string toString(const ::android::hardware::keymaster::generic::KeyParameter::IntegerParams& o) {
    using ::android::hardware::toString;
    std::string os;
    os += "{";
    os += ".algorithm = ";
    os += ::android::hardware::keymaster::generic::toString(o.algorithm);
    os += ", .blockMode = ";
    os += ::android::hardware::keymaster::generic::toString(o.blockMode);
    os += ", .paddingMode = ";
    os += ::android::hardware::keymaster::generic::toString(o.paddingMode);
    os += ", .digest = ";
    os += ::android::hardware::keymaster::generic::toString(o.digest);
    os += ", .ecCurve = ";
    os += ::android::hardware::keymaster::generic::toString(o.ecCurve);
    os += ", .origin = ";
    os += ::android::hardware::keymaster::generic::toString(o.origin);
    os += ", .keyBlobUsageRequirements = ";
    os += ::android::hardware::keymaster::generic::toString(o.keyBlobUsageRequirements);
    os += ", .purpose = ";
    os += ::android::hardware::keymaster::generic::toString(o.purpose);
    os += ", .keyDerivationFunction = ";
    os += ::android::hardware::keymaster::generic::toString(o.keyDerivationFunction);
    os += ", .hardwareAuthenticatorType = ";
    os += ::android::hardware::keymaster::generic::toString(o.hardwareAuthenticatorType);
    os += ", .hardwareType = ";
    os += ::android::hardware::keymaster::generic::toString(o.hardwareType);
    os += ", .boolValue = ";
    os += ::android::hardware::toString(o.boolValue);
    os += ", .integer = ";
    os += ::android::hardware::toString(o.integer);
    os += ", .longInteger = ";
    os += ::android::hardware::toString(o.longInteger);
    os += ", .dateTime = ";
    os += ::android::hardware::toString(o.dateTime);
    os += "}"; return os;
}

static inline void PrintTo(const ::android::hardware::keymaster::generic::KeyParameter::IntegerParams& o, ::std::ostream* os) {
    *os << toString(o);
}

// operator== and operator!= are not generated for IntegerParams

static inline std::string toString(const ::android::hardware::keymaster::generic::KeyParameter& o) {
    using ::android::hardware::toString;
    std::string os;
    os += "{";
    os += ".tag = ";
    os += ::android::hardware::keymaster::generic::toString(o.tag);
    os += ", .f = ";
    os += ::android::hardware::keymaster::generic::toString(o.f);
    os += ", .blob = ";
    os += ::android::hardware::toString(o.blob);
    os += "}"; return os;
}

static inline void PrintTo(const ::android::hardware::keymaster::generic::KeyParameter& o, ::std::ostream* os) {
    *os << toString(o);
}

// operator== and operator!= are not generated for KeyParameter

static inline std::string toString(const ::android::hardware::keymaster::generic::KeyCharacteristics& o) {
    using ::android::hardware::toString;
    std::string os;
    os += "{";
    os += ".softwareEnforced = ";
    os += ::android::hardware::toString(o.softwareEnforced);
    os += ", .hardwareEnforced = ";
    os += ::android::hardware::toString(o.hardwareEnforced);
    os += "}"; return os;
}

static inline void PrintTo(const ::android::hardware::keymaster::generic::KeyCharacteristics& o, ::std::ostream* os) {
    *os << toString(o);
}

// operator== and operator!= are not generated for KeyCharacteristics

static inline std::string toString(const ::android::hardware::keymaster::generic::HardwareAuthToken& o) {
    using ::android::hardware::toString;
    std::string os;
    os += "{";
    os += ".challenge = ";
    os += ::android::hardware::toString(o.challenge);
    os += ", .userId = ";
    os += ::android::hardware::toString(o.userId);
    os += ", .authenticatorId = ";
    os += ::android::hardware::toString(o.authenticatorId);
    os += ", .authenticatorType = ";
    os += ::android::hardware::keymaster::generic::toString(o.authenticatorType);
    os += ", .timestamp = ";
    os += ::android::hardware::toString(o.timestamp);
    os += ", .mac = ";
    os += ::android::hardware::toString(o.mac);
    os += "}"; return os;
}

static inline void PrintTo(const ::android::hardware::keymaster::generic::HardwareAuthToken& o, ::std::ostream* os) {
    *os << toString(o);
}

static inline bool operator==(const ::android::hardware::keymaster::generic::HardwareAuthToken& lhs, const ::android::hardware::keymaster::generic::HardwareAuthToken& rhs) {
    if (lhs.challenge != rhs.challenge) {
        return false;
    }
    if (lhs.userId != rhs.userId) {
        return false;
    }
    if (lhs.authenticatorId != rhs.authenticatorId) {
        return false;
    }
    if (lhs.authenticatorType != rhs.authenticatorType) {
        return false;
    }
    if (lhs.timestamp != rhs.timestamp) {
        return false;
    }
    if (lhs.mac != rhs.mac) {
        return false;
    }
    return true;
}

static inline bool operator!=(const ::android::hardware::keymaster::generic::HardwareAuthToken& lhs, const ::android::hardware::keymaster::generic::HardwareAuthToken& rhs){
    return !(lhs == rhs);
}

static inline std::string toString(const ::android::hardware::keymaster::generic::HmacSharingParameters& o) {
    using ::android::hardware::toString;
    std::string os;
    os += "{";
    os += ".seed = ";
    os += ::android::hardware::toString(o.seed);
    os += ", .nonce = ";
    os += ::android::hardware::toString(o.nonce);
    os += "}"; return os;
}

static inline void PrintTo(const ::android::hardware::keymaster::generic::HmacSharingParameters& o, ::std::ostream* os) {
    *os << toString(o);
}

static inline bool operator==(const ::android::hardware::keymaster::generic::HmacSharingParameters& lhs, const ::android::hardware::keymaster::generic::HmacSharingParameters& rhs) {
    if (lhs.seed != rhs.seed) {
        return false;
    }
    if (lhs.nonce != rhs.nonce) {
        return false;
    }
    return true;
}

static inline bool operator!=(const ::android::hardware::keymaster::generic::HmacSharingParameters& lhs, const ::android::hardware::keymaster::generic::HmacSharingParameters& rhs){
    return !(lhs == rhs);
}

static inline std::string toString(const ::android::hardware::keymaster::generic::VerificationToken& o) {
    using ::android::hardware::toString;
    std::string os;
    os += "{";
    os += ".challenge = ";
    os += ::android::hardware::toString(o.challenge);
    os += ", .timestamp = ";
    os += ::android::hardware::toString(o.timestamp);
    os += ", .parametersVerified = ";
    os += ::android::hardware::toString(o.parametersVerified);
    os += ", .securityLevel = ";
    os += ::android::hardware::keymaster::generic::toString(o.securityLevel);
    os += ", .mac = ";
    os += ::android::hardware::toString(o.mac);
    os += "}"; return os;
}

static inline void PrintTo(const ::android::hardware::keymaster::generic::VerificationToken& o, ::std::ostream* os) {
    *os << toString(o);
}

// operator== and operator!= are not generated for VerificationToken


}  // namespace GENERIC
}  // namespace keymaster
}  // namespace hardware
}  // namespace android

//
// global type declarations for package
//

namespace android {
namespace hardware {
namespace details {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wc++17-extensions"
template<> inline constexpr std::array<::android::hardware::keymaster::generic::Constants, 1> hidl_enum_values<::android::hardware::keymaster::generic::Constants> = {
    ::android::hardware::keymaster::generic::Constants::AUTH_TOKEN_MAC_LENGTH,
};
#pragma clang diagnostic pop
}  // namespace details
}  // namespace hardware
}  // namespace android

namespace android {
namespace hardware {
namespace details {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wc++17-extensions"
template<> inline constexpr std::array<::android::hardware::keymaster::generic::TagType, 11> hidl_enum_values<::android::hardware::keymaster::generic::TagType> = {
    ::android::hardware::keymaster::generic::TagType::INVALID,
    ::android::hardware::keymaster::generic::TagType::ENUM,
    ::android::hardware::keymaster::generic::TagType::ENUM_REP,
    ::android::hardware::keymaster::generic::TagType::UINT,
    ::android::hardware::keymaster::generic::TagType::UINT_REP,
    ::android::hardware::keymaster::generic::TagType::ULONG,
    ::android::hardware::keymaster::generic::TagType::DATE,
    ::android::hardware::keymaster::generic::TagType::BOOL,
    ::android::hardware::keymaster::generic::TagType::BIGNUM,
    ::android::hardware::keymaster::generic::TagType::BYTES,
    ::android::hardware::keymaster::generic::TagType::ULONG_REP,
};
#pragma clang diagnostic pop
}  // namespace details
}  // namespace hardware
}  // namespace android

namespace android {
namespace hardware {
namespace details {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wc++17-extensions"
template<> inline constexpr std::array<::android::hardware::keymaster::generic::Tag, 55> hidl_enum_values<::android::hardware::keymaster::generic::Tag> = {
    ::android::hardware::keymaster::generic::Tag::INVALID,
    ::android::hardware::keymaster::generic::Tag::PURPOSE,
    ::android::hardware::keymaster::generic::Tag::ALGORITHM,
    ::android::hardware::keymaster::generic::Tag::KEY_SIZE,
    ::android::hardware::keymaster::generic::Tag::BLOCK_MODE,
    ::android::hardware::keymaster::generic::Tag::DIGEST,
    ::android::hardware::keymaster::generic::Tag::PADDING,
    ::android::hardware::keymaster::generic::Tag::CALLER_NONCE,
    ::android::hardware::keymaster::generic::Tag::MIN_MAC_LENGTH,
    ::android::hardware::keymaster::generic::Tag::EC_CURVE,
    ::android::hardware::keymaster::generic::Tag::RSA_PUBLIC_EXPONENT,
    ::android::hardware::keymaster::generic::Tag::INCLUDE_UNIQUE_ID,
    ::android::hardware::keymaster::generic::Tag::BLOB_USAGE_REQUIREMENTS,
    ::android::hardware::keymaster::generic::Tag::BOOTLOADER_ONLY,
    ::android::hardware::keymaster::generic::Tag::ROLLBACK_RESISTANCE,
    ::android::hardware::keymaster::generic::Tag::HARDWARE_TYPE,
    ::android::hardware::keymaster::generic::Tag::ACTIVE_DATETIME,
    ::android::hardware::keymaster::generic::Tag::ORIGINATION_EXPIRE_DATETIME,
    ::android::hardware::keymaster::generic::Tag::USAGE_EXPIRE_DATETIME,
    ::android::hardware::keymaster::generic::Tag::MIN_SECONDS_BETWEEN_OPS,
    ::android::hardware::keymaster::generic::Tag::MAX_USES_PER_BOOT,
    ::android::hardware::keymaster::generic::Tag::USER_ID,
    ::android::hardware::keymaster::generic::Tag::USER_SECURE_ID,
    ::android::hardware::keymaster::generic::Tag::NO_AUTH_REQUIRED,
    ::android::hardware::keymaster::generic::Tag::USER_AUTH_TYPE,
    ::android::hardware::keymaster::generic::Tag::AUTH_TIMEOUT,
    ::android::hardware::keymaster::generic::Tag::ALLOW_WHILE_ON_BODY,
    ::android::hardware::keymaster::generic::Tag::TRUSTED_USER_PRESENCE_REQUIRED,
    ::android::hardware::keymaster::generic::Tag::TRUSTED_CONFIRMATION_REQUIRED,
    ::android::hardware::keymaster::generic::Tag::UNLOCKED_DEVICE_REQUIRED,
    ::android::hardware::keymaster::generic::Tag::APPLICATION_ID,
    ::android::hardware::keymaster::generic::Tag::APPLICATION_DATA,
    ::android::hardware::keymaster::generic::Tag::CREATION_DATETIME,
    ::android::hardware::keymaster::generic::Tag::ORIGIN,
    ::android::hardware::keymaster::generic::Tag::ROOT_OF_TRUST,
    ::android::hardware::keymaster::generic::Tag::OS_VERSION,
    ::android::hardware::keymaster::generic::Tag::OS_PATCHLEVEL,
    ::android::hardware::keymaster::generic::Tag::UNIQUE_ID,
    ::android::hardware::keymaster::generic::Tag::ATTESTATION_CHALLENGE,
    ::android::hardware::keymaster::generic::Tag::ATTESTATION_APPLICATION_ID,
    ::android::hardware::keymaster::generic::Tag::ATTESTATION_ID_BRAND,
    ::android::hardware::keymaster::generic::Tag::ATTESTATION_ID_DEVICE,
    ::android::hardware::keymaster::generic::Tag::ATTESTATION_ID_PRODUCT,
    ::android::hardware::keymaster::generic::Tag::ATTESTATION_ID_SERIAL,
    ::android::hardware::keymaster::generic::Tag::ATTESTATION_ID_IMEI,
    ::android::hardware::keymaster::generic::Tag::ATTESTATION_ID_MEID,
    ::android::hardware::keymaster::generic::Tag::ATTESTATION_ID_MANUFACTURER,
    ::android::hardware::keymaster::generic::Tag::ATTESTATION_ID_MODEL,
    ::android::hardware::keymaster::generic::Tag::VENDOR_PATCHLEVEL,
    ::android::hardware::keymaster::generic::Tag::BOOT_PATCHLEVEL,
    ::android::hardware::keymaster::generic::Tag::ASSOCIATED_DATA,
    ::android::hardware::keymaster::generic::Tag::NONCE,
    ::android::hardware::keymaster::generic::Tag::MAC_LENGTH,
    ::android::hardware::keymaster::generic::Tag::RESET_SINCE_ID_ROTATION,
    ::android::hardware::keymaster::generic::Tag::CONFIRMATION_TOKEN,
};
#pragma clang diagnostic pop
}  // namespace details
}  // namespace hardware
}  // namespace android

namespace android {
namespace hardware {
namespace details {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wc++17-extensions"
template<> inline constexpr std::array<::android::hardware::keymaster::generic::Algorithm, 5> hidl_enum_values<::android::hardware::keymaster::generic::Algorithm> = {
    ::android::hardware::keymaster::generic::Algorithm::RSA,
    ::android::hardware::keymaster::generic::Algorithm::EC,
    ::android::hardware::keymaster::generic::Algorithm::AES,
    ::android::hardware::keymaster::generic::Algorithm::TRIPLE_DES,
    ::android::hardware::keymaster::generic::Algorithm::HMAC,
};
#pragma clang diagnostic pop
}  // namespace details
}  // namespace hardware
}  // namespace android

namespace android {
namespace hardware {
namespace details {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wc++17-extensions"
template<> inline constexpr std::array<::android::hardware::keymaster::generic::BlockMode, 4> hidl_enum_values<::android::hardware::keymaster::generic::BlockMode> = {
    ::android::hardware::keymaster::generic::BlockMode::ECB,
    ::android::hardware::keymaster::generic::BlockMode::CBC,
    ::android::hardware::keymaster::generic::BlockMode::CTR,
    ::android::hardware::keymaster::generic::BlockMode::GCM,
};
#pragma clang diagnostic pop
}  // namespace details
}  // namespace hardware
}  // namespace android

namespace android {
namespace hardware {
namespace details {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wc++17-extensions"
template<> inline constexpr std::array<::android::hardware::keymaster::generic::PaddingMode, 6> hidl_enum_values<::android::hardware::keymaster::generic::PaddingMode> = {
    ::android::hardware::keymaster::generic::PaddingMode::NONE,
    ::android::hardware::keymaster::generic::PaddingMode::RSA_OAEP,
    ::android::hardware::keymaster::generic::PaddingMode::RSA_PSS,
    ::android::hardware::keymaster::generic::PaddingMode::RSA_PKCS1_1_5_ENCRYPT,
    ::android::hardware::keymaster::generic::PaddingMode::RSA_PKCS1_1_5_SIGN,
    ::android::hardware::keymaster::generic::PaddingMode::PKCS7,
};
#pragma clang diagnostic pop
}  // namespace details
}  // namespace hardware
}  // namespace android

namespace android {
namespace hardware {
namespace details {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wc++17-extensions"
template<> inline constexpr std::array<::android::hardware::keymaster::generic::Digest, 7> hidl_enum_values<::android::hardware::keymaster::generic::Digest> = {
    ::android::hardware::keymaster::generic::Digest::NONE,
    ::android::hardware::keymaster::generic::Digest::MD5,
    ::android::hardware::keymaster::generic::Digest::SHA1,
    ::android::hardware::keymaster::generic::Digest::SHA_2_224,
    ::android::hardware::keymaster::generic::Digest::SHA_2_256,
    ::android::hardware::keymaster::generic::Digest::SHA_2_384,
    ::android::hardware::keymaster::generic::Digest::SHA_2_512,
};
#pragma clang diagnostic pop
}  // namespace details
}  // namespace hardware
}  // namespace android

namespace android {
namespace hardware {
namespace details {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wc++17-extensions"
template<> inline constexpr std::array<::android::hardware::keymaster::generic::EcCurve, 4> hidl_enum_values<::android::hardware::keymaster::generic::EcCurve> = {
    ::android::hardware::keymaster::generic::EcCurve::P_224,
    ::android::hardware::keymaster::generic::EcCurve::P_256,
    ::android::hardware::keymaster::generic::EcCurve::P_384,
    ::android::hardware::keymaster::generic::EcCurve::P_521,
};
#pragma clang diagnostic pop
}  // namespace details
}  // namespace hardware
}  // namespace android

namespace android {
namespace hardware {
namespace details {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wc++17-extensions"
template<> inline constexpr std::array<::android::hardware::keymaster::generic::KeyOrigin, 5> hidl_enum_values<::android::hardware::keymaster::generic::KeyOrigin> = {
    ::android::hardware::keymaster::generic::KeyOrigin::GENERATED,
    ::android::hardware::keymaster::generic::KeyOrigin::DERIVED,
    ::android::hardware::keymaster::generic::KeyOrigin::IMPORTED,
    ::android::hardware::keymaster::generic::KeyOrigin::UNKNOWN,
    ::android::hardware::keymaster::generic::KeyOrigin::SECURELY_IMPORTED,
};
#pragma clang diagnostic pop
}  // namespace details
}  // namespace hardware
}  // namespace android

namespace android {
namespace hardware {
namespace details {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wc++17-extensions"
template<> inline constexpr std::array<::android::hardware::keymaster::generic::KeyBlobUsageRequirements, 2> hidl_enum_values<::android::hardware::keymaster::generic::KeyBlobUsageRequirements> = {
    ::android::hardware::keymaster::generic::KeyBlobUsageRequirements::STANDALONE,
    ::android::hardware::keymaster::generic::KeyBlobUsageRequirements::REQUIRES_FILE_SYSTEM,
};
#pragma clang diagnostic pop
}  // namespace details
}  // namespace hardware
}  // namespace android

namespace android {
namespace hardware {
namespace details {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wc++17-extensions"
template<> inline constexpr std::array<::android::hardware::keymaster::generic::KeyPurpose, 5> hidl_enum_values<::android::hardware::keymaster::generic::KeyPurpose> = {
    ::android::hardware::keymaster::generic::KeyPurpose::ENCRYPT,
    ::android::hardware::keymaster::generic::KeyPurpose::DECRYPT,
    ::android::hardware::keymaster::generic::KeyPurpose::SIGN,
    ::android::hardware::keymaster::generic::KeyPurpose::VERIFY,
    ::android::hardware::keymaster::generic::KeyPurpose::WRAP_KEY,
};
#pragma clang diagnostic pop
}  // namespace details
}  // namespace hardware
}  // namespace android

namespace android {
namespace hardware {
namespace details {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wc++17-extensions"
template<> inline constexpr std::array<::android::hardware::keymaster::generic::ErrorCode, 74> hidl_enum_values<::android::hardware::keymaster::generic::ErrorCode> = {
    ::android::hardware::keymaster::generic::ErrorCode::OK,
    ::android::hardware::keymaster::generic::ErrorCode::ROOT_OF_TRUST_ALREADY_SET,
    ::android::hardware::keymaster::generic::ErrorCode::UNSUPPORTED_PURPOSE,
    ::android::hardware::keymaster::generic::ErrorCode::INCOMPATIBLE_PURPOSE,
    ::android::hardware::keymaster::generic::ErrorCode::UNSUPPORTED_ALGORITHM,
    ::android::hardware::keymaster::generic::ErrorCode::INCOMPATIBLE_ALGORITHM,
    ::android::hardware::keymaster::generic::ErrorCode::UNSUPPORTED_KEY_SIZE,
    ::android::hardware::keymaster::generic::ErrorCode::UNSUPPORTED_BLOCK_MODE,
    ::android::hardware::keymaster::generic::ErrorCode::INCOMPATIBLE_BLOCK_MODE,
    ::android::hardware::keymaster::generic::ErrorCode::UNSUPPORTED_MAC_LENGTH,
    ::android::hardware::keymaster::generic::ErrorCode::UNSUPPORTED_PADDING_MODE,
    ::android::hardware::keymaster::generic::ErrorCode::INCOMPATIBLE_PADDING_MODE,
    ::android::hardware::keymaster::generic::ErrorCode::UNSUPPORTED_DIGEST,
    ::android::hardware::keymaster::generic::ErrorCode::INCOMPATIBLE_DIGEST,
    ::android::hardware::keymaster::generic::ErrorCode::INVALID_EXPIRATION_TIME,
    ::android::hardware::keymaster::generic::ErrorCode::INVALID_USER_ID,
    ::android::hardware::keymaster::generic::ErrorCode::INVALID_AUTHORIZATION_TIMEOUT,
    ::android::hardware::keymaster::generic::ErrorCode::UNSUPPORTED_KEY_FORMAT,
    ::android::hardware::keymaster::generic::ErrorCode::INCOMPATIBLE_KEY_FORMAT,
    ::android::hardware::keymaster::generic::ErrorCode::UNSUPPORTED_KEY_ENCRYPTION_ALGORITHM,
    ::android::hardware::keymaster::generic::ErrorCode::UNSUPPORTED_KEY_VERIFICATION_ALGORITHM,
    ::android::hardware::keymaster::generic::ErrorCode::INVALID_INPUT_LENGTH,
    ::android::hardware::keymaster::generic::ErrorCode::KEY_EXPORT_OPTIONS_INVALID,
    ::android::hardware::keymaster::generic::ErrorCode::DELEGATION_NOT_ALLOWED,
    ::android::hardware::keymaster::generic::ErrorCode::KEY_NOT_YET_VALID,
    ::android::hardware::keymaster::generic::ErrorCode::KEY_EXPIRED,
    ::android::hardware::keymaster::generic::ErrorCode::KEY_USER_NOT_AUTHENTICATED,
    ::android::hardware::keymaster::generic::ErrorCode::OUTPUT_PARAMETER_NULL,
    ::android::hardware::keymaster::generic::ErrorCode::INVALID_OPERATION_HANDLE,
    ::android::hardware::keymaster::generic::ErrorCode::INSUFFICIENT_BUFFER_SPACE,
    ::android::hardware::keymaster::generic::ErrorCode::VERIFICATION_FAILED,
    ::android::hardware::keymaster::generic::ErrorCode::TOO_MANY_OPERATIONS,
    ::android::hardware::keymaster::generic::ErrorCode::UNEXPECTED_NULL_POINTER,
    ::android::hardware::keymaster::generic::ErrorCode::INVALID_KEY_BLOB,
    ::android::hardware::keymaster::generic::ErrorCode::IMPORTED_KEY_NOT_ENCRYPTED,
    ::android::hardware::keymaster::generic::ErrorCode::IMPORTED_KEY_DECRYPTION_FAILED,
    ::android::hardware::keymaster::generic::ErrorCode::IMPORTED_KEY_NOT_SIGNED,
    ::android::hardware::keymaster::generic::ErrorCode::IMPORTED_KEY_VERIFICATION_FAILED,
    ::android::hardware::keymaster::generic::ErrorCode::INVALID_ARGUMENT,
    ::android::hardware::keymaster::generic::ErrorCode::UNSUPPORTED_TAG,
    ::android::hardware::keymaster::generic::ErrorCode::INVALID_TAG,
    ::android::hardware::keymaster::generic::ErrorCode::MEMORY_ALLOCATION_FAILED,
    ::android::hardware::keymaster::generic::ErrorCode::IMPORT_PARAMETER_MISMATCH,
    ::android::hardware::keymaster::generic::ErrorCode::SECURE_HW_ACCESS_DENIED,
    ::android::hardware::keymaster::generic::ErrorCode::OPERATION_CANCELLED,
    ::android::hardware::keymaster::generic::ErrorCode::CONCURRENT_ACCESS_CONFLICT,
    ::android::hardware::keymaster::generic::ErrorCode::SECURE_HW_BUSY,
    ::android::hardware::keymaster::generic::ErrorCode::SECURE_HW_COMMUNICATION_FAILED,
    ::android::hardware::keymaster::generic::ErrorCode::UNSUPPORTED_EC_FIELD,
    ::android::hardware::keymaster::generic::ErrorCode::MISSING_NONCE,
    ::android::hardware::keymaster::generic::ErrorCode::INVALID_NONCE,
    ::android::hardware::keymaster::generic::ErrorCode::MISSING_MAC_LENGTH,
    ::android::hardware::keymaster::generic::ErrorCode::KEY_RATE_LIMIT_EXCEEDED,
    ::android::hardware::keymaster::generic::ErrorCode::CALLER_NONCE_PROHIBITED,
    ::android::hardware::keymaster::generic::ErrorCode::KEY_MAX_OPS_EXCEEDED,
    ::android::hardware::keymaster::generic::ErrorCode::INVALID_MAC_LENGTH,
    ::android::hardware::keymaster::generic::ErrorCode::MISSING_MIN_MAC_LENGTH,
    ::android::hardware::keymaster::generic::ErrorCode::UNSUPPORTED_MIN_MAC_LENGTH,
    ::android::hardware::keymaster::generic::ErrorCode::UNSUPPORTED_KDF,
    ::android::hardware::keymaster::generic::ErrorCode::UNSUPPORTED_EC_CURVE,
    ::android::hardware::keymaster::generic::ErrorCode::KEY_REQUIRES_UPGRADE,
    ::android::hardware::keymaster::generic::ErrorCode::ATTESTATION_CHALLENGE_MISSING,
    ::android::hardware::keymaster::generic::ErrorCode::KEYMASTER_NOT_CONFIGURED,
    ::android::hardware::keymaster::generic::ErrorCode::ATTESTATION_APPLICATION_ID_MISSING,
    ::android::hardware::keymaster::generic::ErrorCode::CANNOT_ATTEST_IDS,
    ::android::hardware::keymaster::generic::ErrorCode::ROLLBACK_RESISTANCE_UNAVAILABLE,
    ::android::hardware::keymaster::generic::ErrorCode::HARDWARE_TYPE_UNAVAILABLE,
    ::android::hardware::keymaster::generic::ErrorCode::PROOF_OF_PRESENCE_REQUIRED,
    ::android::hardware::keymaster::generic::ErrorCode::CONCURRENT_PROOF_OF_PRESENCE_REQUESTED,
    ::android::hardware::keymaster::generic::ErrorCode::NO_USER_CONFIRMATION,
    ::android::hardware::keymaster::generic::ErrorCode::DEVICE_LOCKED,
    ::android::hardware::keymaster::generic::ErrorCode::UNIMPLEMENTED,
    ::android::hardware::keymaster::generic::ErrorCode::VERSION_MISMATCH,
    ::android::hardware::keymaster::generic::ErrorCode::UNKNOWN_ERROR,
};
#pragma clang diagnostic pop
}  // namespace details
}  // namespace hardware
}  // namespace android

namespace android {
namespace hardware {
namespace details {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wc++17-extensions"
template<> inline constexpr std::array<::android::hardware::keymaster::generic::KeyDerivationFunction, 6> hidl_enum_values<::android::hardware::keymaster::generic::KeyDerivationFunction> = {
    ::android::hardware::keymaster::generic::KeyDerivationFunction::NONE,
    ::android::hardware::keymaster::generic::KeyDerivationFunction::RFC5869_SHA256,
    ::android::hardware::keymaster::generic::KeyDerivationFunction::ISO18033_2_KDF1_SHA1,
    ::android::hardware::keymaster::generic::KeyDerivationFunction::ISO18033_2_KDF1_SHA256,
    ::android::hardware::keymaster::generic::KeyDerivationFunction::ISO18033_2_KDF2_SHA1,
    ::android::hardware::keymaster::generic::KeyDerivationFunction::ISO18033_2_KDF2_SHA256,
};
#pragma clang diagnostic pop
}  // namespace details
}  // namespace hardware
}  // namespace android

namespace android {
namespace hardware {
namespace details {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wc++17-extensions"
template<> inline constexpr std::array<::android::hardware::keymaster::generic::HardwareAuthenticatorType, 4> hidl_enum_values<::android::hardware::keymaster::generic::HardwareAuthenticatorType> = {
    ::android::hardware::keymaster::generic::HardwareAuthenticatorType::NONE,
    ::android::hardware::keymaster::generic::HardwareAuthenticatorType::PASSWORD,
    ::android::hardware::keymaster::generic::HardwareAuthenticatorType::FINGERPRINT,
    ::android::hardware::keymaster::generic::HardwareAuthenticatorType::ANY,
};
#pragma clang diagnostic pop
}  // namespace details
}  // namespace hardware
}  // namespace android

namespace android {
namespace hardware {
namespace details {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wc++17-extensions"
template<> inline constexpr std::array<::android::hardware::keymaster::generic::SecurityLevel, 3> hidl_enum_values<::android::hardware::keymaster::generic::SecurityLevel> = {
    ::android::hardware::keymaster::generic::SecurityLevel::SOFTWARE,
    ::android::hardware::keymaster::generic::SecurityLevel::TRUSTED_ENVIRONMENT,
    ::android::hardware::keymaster::generic::SecurityLevel::STRONGBOX,
};
#pragma clang diagnostic pop
}  // namespace details
}  // namespace hardware
}  // namespace android

namespace android {
namespace hardware {
namespace details {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wc++17-extensions"
template<> inline constexpr std::array<::android::hardware::keymaster::generic::KeyFormat, 3> hidl_enum_values<::android::hardware::keymaster::generic::KeyFormat> = {
    ::android::hardware::keymaster::generic::KeyFormat::X509,
    ::android::hardware::keymaster::generic::KeyFormat::PKCS8,
    ::android::hardware::keymaster::generic::KeyFormat::RAW,
};
#pragma clang diagnostic pop
}  // namespace details
}  // namespace hardware
}  // namespace android


#endif  // HIDL_GENERATED_ANDROID_HARDWARE_KEYMASTER_GENERIC_TYPES_H
