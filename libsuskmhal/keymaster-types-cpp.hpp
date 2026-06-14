#ifndef HIDL_GENERATED_ANDROID_HARDWARE_KEYMASTER_GENERIC_TYPES_H
#define HIDL_GENERATED_ANDROID_HARDWARE_KEYMASTER_GENERIC_TYPES_H

#include "km-def.h"
#include "keymaster-types-c.h"
#include "transport/aosp-hidl-support.hpp"
#include <cstdint>
#include <vector>
#include <array>

namespace suskeymaster {
namespace kmhal {

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

typedef uint64_t OperationHandle;

typedef void * OpaqueOpHandle; /* Needed for KeyMint support */

struct KeyParameter;
struct KeyCharacteristics;
struct HardwareAuthToken;
struct HmacSharingParameters;
struct VerificationToken;

} /* namespace generic */

namespace hidl {

using namespace ::android::hardware;

std::vector<u8> fromHidl(const hidl_vec<u8>&);
std::vector<std::vector<u8>> fromHidl(const hidl_vec<hidl_vec<u8>>&);

struct KeyParameter final {
    // Forward declaration for forward reference support:
    union IntegerParams;

    union IntegerParams final {
        /*
         * Enum types
         */
        generic::Algorithm algorithm __attribute__ ((aligned(4)));
        generic::BlockMode blockMode __attribute__ ((aligned(4)));
        generic::PaddingMode paddingMode __attribute__ ((aligned(4)));
        generic::Digest digest __attribute__ ((aligned(4)));
        generic::EcCurve ecCurve __attribute__ ((aligned(4)));
        generic::KeyOrigin origin __attribute__ ((aligned(4)));
        generic::KeyBlobUsageRequirements keyBlobUsageRequirements __attribute__ ((aligned(4)));
        generic::KeyPurpose purpose __attribute__ ((aligned(4)));
        generic::KeyDerivationFunction keyDerivationFunction __attribute__ ((aligned(4)));
        generic::HardwareAuthenticatorType hardwareAuthenticatorType __attribute__ ((aligned(4)));
        generic::SecurityLevel hardwareType __attribute__ ((aligned(4)));
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
    generic::Tag tag __attribute__ ((aligned(4)));
    hidl::KeyParameter::IntegerParams f __attribute__ ((aligned(8)));
    hidl_vec<uint8_t> blob __attribute__ ((aligned(8)));
};

static_assert(offsetof(hidl::KeyParameter, tag) == 0, "wrong offset");
static_assert(offsetof(hidl::KeyParameter, f) == 8, "wrong offset");
static_assert(offsetof(hidl::KeyParameter, blob) == 16, "wrong offset");
static_assert(sizeof(hidl::KeyParameter) == 32, "wrong size");
static_assert(__alignof(hidl::KeyParameter) == 8, "wrong alignment");

generic::KeyParameter fromHidl(const KeyParameter&);
std::vector<generic::KeyParameter> fromHidl(const hidl_vec<KeyParameter>&);

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
    hidl_vec<KeyParameter> softwareEnforced __attribute__ ((aligned(8)));
    hidl_vec<KeyParameter> hardwareEnforced __attribute__ ((aligned(8)));
};

static_assert(offsetof(KeyCharacteristics, softwareEnforced) == 0, "wrong offset");
static_assert(offsetof(KeyCharacteristics, hardwareEnforced) == 16, "wrong offset");
static_assert(sizeof(KeyCharacteristics) == 32, "wrong size");
static_assert(__alignof(KeyCharacteristics) == 8, "wrong alignment");

generic::KeyCharacteristics fromHidl(const KeyCharacteristics&);

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
    generic::HardwareAuthenticatorType authenticatorType __attribute__ ((aligned(4)));
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
    hidl_vec<uint8_t> mac __attribute__ ((aligned(8)));
};

generic::HardwareAuthToken fromHidl(const HardwareAuthToken&);

static_assert(offsetof(HardwareAuthToken, challenge) == 0, "wrong offset");
static_assert(offsetof(HardwareAuthToken, userId) == 8, "wrong offset");
static_assert(offsetof(HardwareAuthToken, authenticatorId) == 16, "wrong offset");
static_assert(offsetof(HardwareAuthToken, authenticatorType) == 24, "wrong offset");
static_assert(offsetof(HardwareAuthToken, timestamp) == 32, "wrong offset");
static_assert(offsetof(HardwareAuthToken, mac) == 40, "wrong offset");
static_assert(sizeof(HardwareAuthToken) == 56, "wrong size");
static_assert(__alignof(HardwareAuthToken) == 8, "wrong alignment");

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
    hidl_vec<uint8_t> seed __attribute__ ((aligned(8)));
    /**
     * A 32-byte value which is guaranteed to be different each time
     * getHmacSharingParameters() is called.  Probabilistic uniqueness (i.e. random) is acceptable,
     * though a stronger uniqueness guarantee (e.g. counter) is recommended where possible.
     */
    hidl_array<uint8_t, 32> nonce __attribute__ ((aligned(1)));
};

static_assert(offsetof(HmacSharingParameters, seed) == 0, "wrong offset");
static_assert(offsetof(HmacSharingParameters, nonce) == 16, "wrong offset");
static_assert(sizeof(HmacSharingParameters) == 48, "wrong size");
static_assert(__alignof(HmacSharingParameters) == 8, "wrong alignment");

generic::HmacSharingParameters fromHidl(const HmacSharingParameters&);
std::vector<generic::HmacSharingParameters> fromHidl(const hidl_vec<HmacSharingParameters>&);

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
    hidl_vec<KeyParameter> parametersVerified __attribute__ ((aligned(8)));
    /**
     * SecurityLevel of the secure environment that generated the token.
     */
    generic::SecurityLevel securityLevel __attribute__ ((aligned(4)));
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
    hidl_vec<uint8_t> mac __attribute__ ((aligned(8)));
};

static_assert(offsetof(VerificationToken, challenge) == 0, "wrong offset");
static_assert(offsetof(VerificationToken, timestamp) == 8, "wrong offset");
static_assert(offsetof(VerificationToken, parametersVerified) == 16, "wrong offset");
static_assert(offsetof(VerificationToken, securityLevel) == 32, "wrong offset");
static_assert(offsetof(VerificationToken, mac) == 40, "wrong offset");
static_assert(sizeof(VerificationToken) == 56, "wrong size");
static_assert(__alignof(VerificationToken) == 8, "wrong alignment");

generic::VerificationToken fromHidl(const VerificationToken&);

//
// type declarations for package
//

std::string toString(const KeyParameter::IntegerParams& o);
void PrintTo(const KeyParameter::IntegerParams& o, ::std::ostream*);
// operator== and operator!= are not generated for IntegerParams

std::string toString(const KeyParameter& o);
void PrintTo(const KeyParameter& o, ::std::ostream*);
// operator== and operator!= are not generated for KeyParameter

std::string toString(const KeyCharacteristics& o);
void PrintTo(const KeyCharacteristics& o, ::std::ostream*);
// operator== and operator!= are not generated for KeyCharacteristics

std::string toString(const HardwareAuthToken& o);
void PrintTo(const HardwareAuthToken& o, ::std::ostream*);
bool operator==(const HardwareAuthToken& lhs, const HardwareAuthToken& rhs);
bool operator!=(const HardwareAuthToken& lhs, const HardwareAuthToken& rhs);

std::string toString(const HmacSharingParameters& o);
void PrintTo(const HmacSharingParameters& o, ::std::ostream*);
bool operator==(const HmacSharingParameters& lhs, const HmacSharingParameters& rhs);
bool operator!=(const HmacSharingParameters& lhs, const HmacSharingParameters& rhs);

std::string toString(const VerificationToken& o);
void PrintTo(const VerificationToken& o, ::std::ostream*);
// operator== and operator!= are not generated for VerificationToken

//
// type header definitions for package
//

//
} /* namespace hidl */

namespace generic {

using ::android::hardware::hidl_vec;

const hidl_vec<u8> toHidlView(const std::vector<u8>&);
const hidl_vec<hidl_vec<u8>> toHidlView(const std::vector<std::vector<u8>>&);

struct KeyParameter final {
    union IntegerParams final {
        /*
         * Enum types
         */
        Algorithm algorithm;
        BlockMode blockMode;
        PaddingMode paddingMode;
        Digest digest;
        EcCurve ecCurve;
        KeyOrigin origin;
        KeyBlobUsageRequirements keyBlobUsageRequirements;
        KeyPurpose purpose;
        KeyDerivationFunction keyDerivationFunction;
        HardwareAuthenticatorType hardwareAuthenticatorType;
        SecurityLevel hardwareType;
        /*
         * Other types
         */
        bool boolValue;
        uint32_t integer;
        uint64_t longInteger;
        uint64_t dateTime;
    };


    /**
     * Discriminates the union/blob field used
     * The blob cannot be placed in the union, but only
     * one of "f" and "blob" may ever be used at a time.
     */
    Tag tag;
    KeyParameter::IntegerParams f;
    std::vector<u8> blob;
};
const hidl::KeyParameter toHidlView(const KeyParameter& kp);
const hidl_vec<hidl::KeyParameter> toHidlView(const std::vector<KeyParameter>&);

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
    std::vector<KeyParameter> softwareEnforced;
    std::vector<KeyParameter> hardwareEnforced;
};
const hidl::KeyCharacteristics toHidlView(const KeyCharacteristics&);

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
    HardwareAuthenticatorType authenticatorType;
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
    std::vector<uint8_t> mac;

    /**
     * See above (`mac`)
     */
    bool empty() const { return mac.empty(); }
};
const hidl::HardwareAuthToken toHidlView(const HardwareAuthToken&);

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
    std::vector<uint8_t> seed;
    /**
     * A 32-byte value which is guaranteed to be different each time
     * getHmacSharingParameters() is called.  Probabilistic uniqueness (i.e. random) is acceptable,
     * though a stronger uniqueness guarantee (e.g. counter) is recommended where possible.
     */
    std::array<uint8_t, 32> nonce;
};
const hidl::HmacSharingParameters toHidlView(const HmacSharingParameters&);
const hidl_vec<hidl::HmacSharingParameters> toHidlView(const std::vector<HmacSharingParameters>&);

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
    std::vector<KeyParameter> parametersVerified __attribute__ ((aligned(8)));
    /**
     * SecurityLevel of the secure environment that generated the token.
     */
    SecurityLevel securityLevel __attribute__ ((aligned(4)));
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
    std::vector<uint8_t> mac __attribute__ ((aligned(8)));
};
const hidl::VerificationToken toHidlView(const VerificationToken&);

} /* namespace generic */

} /* namespace kmhal */
} /* namespace suskeymaster */

#endif  // HIDL_GENERATED_ANDROID_HARDWARE_KEYMASTER_GENERIC_TYPES_H
