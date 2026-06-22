#include "keymaster-types-cpp.hpp"
#include "keymaster-types-c.h"
#include "util/endian.h"
#include "transport/aosp-hidl-support.hpp"
#include <cstring>

using ::android::hardware::hidl_vec;
using ::android::hardware::hidl_array;

namespace suskeymaster {
namespace kmhal {

namespace generic {

const hidl_vec<u8> toHidlView(const std::vector<u8>& generic)
{
    hidl_vec<u8> ret;

    ret.setToExternal(const_cast<u8 *>(generic.data()), generic.size(), false);
    return ret;
}

const hidl_vec<hidl_vec<u8>> toHidlView(const std::vector<std::vector<u8>>& generic)
{
    hidl_vec<hidl_vec<u8>> ret(generic.size());
    for (size_t i = 0; i < generic.size(); i++)
        ret[i].setToExternal(const_cast<u8 *>(generic[i].data()), generic[i].size(), false);

    return ret;
}

const hidl::KeyParameter toHidlView(const KeyParameter& generic)
{
    hidl::KeyParameter ret;

    ret.tag = generic.tag;
    ret.f.longInteger = generic.f.longInteger;
    ret.blob = toHidlView(generic.blob);

    return ret;
}

const hidl_vec<hidl::KeyParameter> toHidlView(const std::vector<KeyParameter>& generic)
{
    hidl_vec<hidl::KeyParameter> ret(generic.size());

    for (size_t i = 0; i < generic.size(); i++)
        ret[i] = toHidlView(generic[i]);

    return ret;
}

const hidl::KeyCharacteristics toHidlView(const KeyCharacteristics& generic)
{
    return { toHidlView(generic.softwareEnforced), toHidlView(generic.hardwareEnforced) };
}

const hidl::HardwareAuthToken toHidlView(const HardwareAuthToken& generic)
{
    return {
        generic.challenge,
        generic.userId,
        generic.authenticatorId,
        generic.authenticatorType,
        generic.timestamp,
        toHidlView(generic.mac)
    };
}

const hidl::HmacSharingParameters toHidlView(const HmacSharingParameters& generic)
{
    return { toHidlView(generic.seed), hidl_array<u8, 32>(generic.nonce) };
}

const hidl_vec<hidl::HmacSharingParameters>
toHidlView(const std::vector<HmacSharingParameters>& generic)
{
    hidl_vec<hidl::HmacSharingParameters> ret(generic.size());

    for (size_t i = 0; i < generic.size(); i++)
        ret[i] = toHidlView(generic[i]);

    return ret;
}

const hidl::VerificationToken toHidlView(const VerificationToken& generic)
{
    return {
        generic.challenge,
        generic.timestamp,
        toHidlView(generic.parametersVerified),
        generic.securityLevel,
        toHidlView(generic.mac)
    };
}

HardwareAuthToken deserialize_auth_token(const std::vector<u8>& data)
{
    if (data.size() != sizeof(hw_auth_token_t)) {
        std::cerr << "Invalid serialized auth token data; not parsing" << std::endl;
        return {};
    }

    hw_auth_token_t serialized;
    memcpy(&serialized, data.data(), sizeof(hw_auth_token_t));

    if (serialized.version != HW_AUTH_TOKEN_VERSION) {
        std::cerr << "WARNING: Unexpected serialized auth token version: "
            << static_cast<int>(serialized.version) << std::endl;
    }

    HardwareAuthToken ret;
    ret.challenge = serialized.challenge;
    ret.userId = serialized.user_id;
    ret.authenticatorId = serialized.authenticator_id;
    ret.authenticatorType = static_cast<HardwareAuthenticatorType>
        (be32toh(serialized.authenticator_type));
    ret.timestamp = be64toh(serialized.timestamp);

    static constexpr size_t TOKEN_MAC_LENGTH =
        static_cast<size_t>(Constants::AUTH_TOKEN_MAC_LENGTH);

    ret.mac.resize(TOKEN_MAC_LENGTH);
    memcpy(ret.mac.data(), serialized.hmac, TOKEN_MAC_LENGTH);

    return ret;
}

std::vector<u8> serialize_auth_token(const HardwareAuthToken& at)
{
    if (at.empty())
        return {};

    static constexpr size_t TOKEN_MAC_LENGTH =
        static_cast<size_t>(Constants::AUTH_TOKEN_MAC_LENGTH);
    if (at.mac.size() != TOKEN_MAC_LENGTH) {
        std::cerr << "Invalid HardwareAuthToken MAC length: " << at.mac.size() << std::endl;
        return {};
    }

    hw_auth_token_t serialized = {
        HW_AUTH_TOKEN_VERSION,
        at.challenge,
        at.userId,
        at.authenticatorId,
        htobe32(static_cast<u32>(at.authenticatorType)),
        htobe64(at.timestamp),
        {}
    };
    memcpy(serialized.hmac, at.mac.data(), TOKEN_MAC_LENGTH);

    std::vector<u8> ret(sizeof(hw_auth_token_t));
    memcpy(ret.data(), &serialized, sizeof(hw_auth_token_t));
    return ret;
}

} /* namespace generic */

namespace hidl {

std::vector<u8> fromHidl(const hidl_vec<u8>& hidl)
{
    return std::vector<u8>(hidl.begin(), hidl.end());
}

std::vector<std::vector<u8>> fromHidl(const hidl_vec<hidl_vec<u8>>& hidl)
{
    std::vector<std::vector<u8>> ret;
    ret.reserve(hidl.size());

    for (size_t i = 0; i < hidl.size(); i++)
        ret.emplace_back(hidl[i].begin(), hidl[i].end());

    return ret;
}

generic::KeyParameter fromHidl(const KeyParameter& hidl)
{
    generic::KeyParameter ret;
    ret.tag = hidl.tag;
    ret.f.longInteger = hidl.f.longInteger;
    ret.blob = fromHidl(hidl.blob);
    return ret;
}

std::vector<generic::KeyParameter> fromHidl(const hidl_vec<KeyParameter>& hidl)
{
    std::vector<generic::KeyParameter> ret;
    ret.reserve(hidl.size());
    for (size_t i = 0; i < hidl.size(); i++)
        ret.emplace_back(fromHidl(hidl[i]));

    return ret;
}

generic::KeyCharacteristics fromHidl(const KeyCharacteristics& hidl)
{
    return { fromHidl(hidl.softwareEnforced), fromHidl(hidl.hardwareEnforced) };
}

generic::HardwareAuthToken fromHidl(const HardwareAuthToken& hidl)
{
    return {
        hidl.challenge,
        hidl.userId,
        hidl.authenticatorId,
        hidl.authenticatorType,
        hidl.timestamp,
        fromHidl(hidl.mac)
    };
}

generic::HmacSharingParameters fromHidl(const HmacSharingParameters& hidl)
{
    return { fromHidl(hidl.seed), std::array<u8, 32>(hidl.nonce) };
}

std::vector<generic::HmacSharingParameters> fromHidl(const hidl_vec<HmacSharingParameters>& hidl)
{
    std::vector<generic::HmacSharingParameters> ret;
    ret.reserve(hidl.size());
    for (size_t i = 0; i < hidl.size(); i++)
        ret.emplace_back(fromHidl(hidl[i]));

    return ret;
}

generic::VerificationToken fromHidl(const VerificationToken& hidl)
{
    return {
        hidl.challenge,
        hidl.timestamp,
        fromHidl(hidl.parametersVerified),
        hidl.securityLevel,
        fromHidl(hidl.mac)
    };
}

std::string toString(const KeyParameter::IntegerParams& o) {
    using ::android::hardware::toString;
    std::string os;
    os += "{";
    os += ".algorithm = ";
    os += toString(o.algorithm);
    os += ", .blockMode = ";
    os += toString(o.blockMode);
    os += ", .paddingMode = ";
    os += toString(o.paddingMode);
    os += ", .digest = ";
    os += toString(o.digest);
    os += ", .ecCurve = ";
    os += toString(o.ecCurve);
    os += ", .origin = ";
    os += toString(o.origin);
    os += ", .keyBlobUsageRequirements = ";
    os += toString(o.keyBlobUsageRequirements);
    os += ", .purpose = ";
    os += toString(o.purpose);
    os += ", .keyDerivationFunction = ";
    os += toString(o.keyDerivationFunction);
    os += ", .hardwareAuthenticatorType = ";
    os += toString(o.hardwareAuthenticatorType);
    os += ", .hardwareType = ";
    os += toString(o.hardwareType);
    os += ", .boolValue = ";
    os += toString(o.boolValue);
    os += ", .integer = ";
    os += toString(o.integer);
    os += ", .longInteger = ";
    os += toString(o.longInteger);
    os += ", .dateTime = ";
    os += toString(o.dateTime);
    os += "}"; return os;
}

void PrintTo(const KeyParameter::IntegerParams& o, ::std::ostream* os) {
    *os << toString(o);
}

// operator== and operator!= are not generated for IntegerParams

std::string toString(const KeyParameter& o) {
    using ::android::hardware::toString;
    std::string os;
    os += "{";
    os += ".tag = ";
    os += toString(o.tag);
    os += ", .f = ";
    os += toString(o.f);
    os += ", .blob = ";
    os += toString(o.blob);
    os += "}"; return os;
}

void PrintTo(const KeyParameter& o, ::std::ostream* os) {
    *os << toString(o);
}

// operator== and operator!= are not generated for KeyParameter

std::string toString(const KeyCharacteristics& o) {
    using ::android::hardware::toString;
    std::string os;
    os += "{";
    os += ".softwareEnforced = ";
    os += toString(o.softwareEnforced);
    os += ", .hardwareEnforced = ";
    os += toString(o.hardwareEnforced);
    os += "}"; return os;
}

void PrintTo(const KeyCharacteristics& o, ::std::ostream* os) {
    *os << toString(o);
}

// operator== and operator!= are not generated for KeyCharacteristics

std::string toString(const HardwareAuthToken& o) {
    using ::android::hardware::toString;
    std::string os;
    os += "{";
    os += ".challenge = ";
    os += toString(o.challenge);
    os += ", .userId = ";
    os += toString(o.userId);
    os += ", .authenticatorId = ";
    os += toString(o.authenticatorId);
    os += ", .authenticatorType = ";
    os += toString(o.authenticatorType);
    os += ", .timestamp = ";
    os += toString(o.timestamp);
    os += ", .mac = ";
    os += toString(o.mac);
    os += "}"; return os;
}

void PrintTo(const HardwareAuthToken& o, ::std::ostream* os) {
    *os << toString(o);
}

bool operator==(const HardwareAuthToken& lhs, const HardwareAuthToken& rhs) {
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

bool operator!=(const HardwareAuthToken& lhs, const HardwareAuthToken& rhs){
    return !(lhs == rhs);
}

std::string toString(const HmacSharingParameters& o) {
    using ::android::hardware::toString;
    std::string os;
    os += "{";
    os += ".seed = ";
    os += toString(o.seed);
    os += ", .nonce = ";
    os += toString(o.nonce);
    os += "}"; return os;
}

void PrintTo(const HmacSharingParameters& o, ::std::ostream* os) {
    *os << toString(o);
}

bool operator==(const HmacSharingParameters& lhs, const HmacSharingParameters& rhs) {
    if (lhs.seed != rhs.seed) {
        return false;
    }
    if (lhs.nonce != rhs.nonce) {
        return false;
    }
    return true;
}

bool operator!=(const HmacSharingParameters& lhs, const HmacSharingParameters& rhs){
    return !(lhs == rhs);
}

std::string toString(const VerificationToken& o) {
    using ::android::hardware::toString;
    std::string os;
    os += "{";
    os += ".challenge = ";
    os += toString(o.challenge);
    os += ", .timestamp = ";
    os += toString(o.timestamp);
    os += ", .parametersVerified = ";
    os += toString(o.parametersVerified);
    os += ", .securityLevel = ";
    os += toString(o.securityLevel);
    os += ", .mac = ";
    os += toString(o.mac);
    os += "}"; return os;
}

void PrintTo(const VerificationToken& o, ::std::ostream* os) {
    *os << toString(o);
}

// operator== and operator!= are not generated for VerificationToken
} /* namespace hidl */

} /* namespace kmhal */
} /* namespace suskeymaster */
