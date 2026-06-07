#ifndef HIDL_GENERATED_ANDROID_HARDWARE_KEYMASTER_GENERIC_TYPES_H
#define HIDL_GENERATED_ANDROID_HARDWARE_KEYMASTER_GENERIC_TYPES_H

#include "km-def.h"
#include "keymaster-types-c.h"
#include "transport/aosp-hidl-support.hpp"
#include <cstdint>

namespace android {
namespace hardware {
namespace keymaster {
namespace generic {

// Forward declaration for forward reference support:
enum class TagType : uint32_t;
enum class Tag : uint32_t;
enum class ErrorCode : int32_t;
enum class HardwareAuthenticatorType : uint32_t;
#define KM_DECL_ENUM(enum_name, list_name) \
enum class enum_name : uint32_t;

KM_ENUM_LIST__
#undef KM_DECL_ENUM

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
static inline std::string toString(TagType t) {
    return KM_TagType_toString(static_cast<uint32_t>(t));
}

enum class Tag : uint32_t {
    INVALID = 0u,

#define KM_DECL_TAG(name, type, tag_val, param_list_field, bound_enum, asn1_type, asn1_rep) \
    name = static_cast<uint32_t>(TagType::type) | static_cast<uint32_t>(tag_val),

    KM_TAG_LIST__

#undef KM_DECL_TAG
};
static inline std::string toString(Tag t) {
    return KM_Tag_toString(static_cast<uint32_t>(t));
}

enum class ErrorCode : int32_t {
#define KM_DECL_ERR(name, value) \
    name = value,
KM_ERR_LIST__
#undef KM_DECL_ENUM_VAL
};
static inline std::string toString(ErrorCode e) {
    return KM_ErrorCode_toString(static_cast<int32_t>(e));
}

enum class HardwareAuthenticatorType : uint32_t {
#define KM_DECL_ENUM_VAL(c_prefix, name, value) \
    name = value##u,
KM_HARDWARE_AUTHENTICATOR_TYPE_LIST__
#undef KM_DECL_ENUM_VAL
};
static inline std::string toString(HardwareAuthenticatorType h) {
    return KM_HardwareAuthenticatorType_toString(static_cast<uint32_t>(h));
}

#define KM_DECL_ENUM_VAL(c_prefix, name, value) \
    name = value##u,

#define KM_DECL_ENUM(enum_name, list_name)                      \
enum class enum_name : uint32_t {                               \
    KM_##list_name##_LIST__                                     \
};                                                              \
static inline std::string toString(enum_name v) {               \
    return KM_##enum_name##_toString(static_cast<uint32_t>(v)); \
}                                                               \

KM_ENUM_LIST__

#undef KM_DECL_ENUM
#undef KM_DECL_ENUM_VAL

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

#endif  // HIDL_GENERATED_ANDROID_HARDWARE_KEYMASTER_GENERIC_TYPES_H
