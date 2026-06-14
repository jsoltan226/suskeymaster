#ifndef SUSKEYMASTER_BUILD_HOST

#include "aidl2generic.hpp"
#include "keymint-types-aidl.h"
#include "../keymaster-types-c.h"
#include "../keymaster-types-cpp.hpp"
#include <core/log.h>

#define MODULE_NAME "aidl2generic"

namespace suskeymaster {
namespace kmhal {
namespace transport {

using namespace generic;

template<>
aidl_vec_of_u8 AidlVecOfU8View::toAidlView(const std::vector<u8>& generic)
{
    aidl_vec_of_u8 ret{};

    ret.ptr = const_cast<u8 *>(generic.data());
    if (generic.size() > INT32_MAX)
        s_log_fatal("Vector too large for AIDL");

    ret.size = static_cast<i32>(generic.size());
    ret.owns = false;

    return ret;
}

std::vector<u8> fromAidlDestroy(aidl_vec_of_u8& aidl)
{
    if (!aidl.ptr || aidl.size <= 0) {
        destroy_aidl_vec_of_u8(&aidl);
        return {};
    }

    std::vector<u8> ret(static_cast<size_t>(aidl.size));
    memcpy(ret.data(), aidl.ptr, aidl.size);

    destroy_aidl_vec_of_u8(&aidl);
    return ret;
}

template<>
aidl_key_parameter AidlKeyParameterView::toAidlView(const KeyParameter& generic)
{
    aidl_key_parameter ret{};
    ret.tag = static_cast<enum KM_Tag>(generic.tag);

    switch (static_cast<enum KM_TagType>(__KM_TAG_TYPE_MASK(ret.tag))) {
    case KM_TAG_TYPE_BOOL: /* A TagTYpe::BOOL's value presence automatically means `true` */
        ret.integer_value.i = static_cast<i32>(true);
        break;
    case KM_TAG_TYPE_ENUM: case KM_TAG_TYPE_ENUM_REP:
    case KM_TAG_TYPE_UINT: case KM_TAG_TYPE_UINT_REP:
        ret.integer_value.i = generic.f.integer;
        break;
    case KM_TAG_TYPE_ULONG: case KM_TAG_TYPE_ULONG_REP:
    case KM_TAG_TYPE_DATE:
        ret.integer_value.l = generic.f.longInteger;
        break;
    case KM_TAG_TYPE_BYTES: case KM_TAG_TYPE_BIGNUM:
        ret.blob = *AidlVecOfU8View(generic.blob).get();
        break;
    default:
        s_log_fatal("Invalid tag type");
    }

    return ret;
}

KeyParameter fromAidlDestroy(aidl_key_parameter& aidl)
{
    KeyParameter ret;
    ret.tag = static_cast<Tag>(aidl.tag);
    ret.f.longInteger = UINT64_C(0);
    ret.blob = {};

    switch (static_cast<enum KM_TagType>(__KM_TAG_TYPE_MASK(aidl.tag))) {
    case KM_TAG_TYPE_BOOL: /* A TagTYpe::BOOL's value presence automatically means `true` */
        ret.f.boolValue = true;
        break;
    case KM_TAG_TYPE_ENUM: case KM_TAG_TYPE_ENUM_REP:
    case KM_TAG_TYPE_UINT: case KM_TAG_TYPE_UINT_REP:
        ret.f.integer = aidl.integer_value.i;
        break;
    case KM_TAG_TYPE_ULONG: case KM_TAG_TYPE_ULONG_REP:
    case KM_TAG_TYPE_DATE:
        ret.f.longInteger = aidl.integer_value.l;
        break;
    case KM_TAG_TYPE_BYTES: case KM_TAG_TYPE_BIGNUM:
        ret.blob = fromAidlDestroy(aidl.blob);
        break;
    default:
        s_log_fatal("Invalid tag type");
    }

    destroy_aidl_key_parameter(&aidl);
    return ret;
}

template<> aidl_vec_of_key_parameter
AidlVecOfKeyParameterView::toAidlView(const std::vector<KeyParameter>& generic)
{
    if (generic.size() == 0)
        return {};
    else if (generic.size() > INT32_MAX)
        s_log_fatal("Vector size too large");

    aidl_vec_of_key_parameter ret{};

    ret.size = static_cast<i32>(generic.size());

    ret.owns = true;
    ret.ptr = reinterpret_cast<aidl_key_parameter *>
        (malloc(sizeof(aidl_key_parameter) * ret.size));
    if (!ret.ptr)
        s_log_fatal("Failed to allocate vector copy");

    for (i32 i = 0; i < ret.size; i++)
        ret.ptr[i] = AidlKeyParameterView::toAidlView(generic[i]);

    return ret;
}

std::vector<KeyParameter> fromAidlDestroy(aidl_vec_of_key_parameter& aidl)
{
    std::vector<KeyParameter> ret{};
    if (aidl.size <= 0 || !aidl.ptr)
        return ret;

    ret.reserve(static_cast<size_t>(aidl.size));
    for (i32 i = 0; i < aidl.size; i++)
        ret.emplace_back(fromAidlDestroy(aidl.ptr[i]));

    /* avoid looping over the whole empty vec again
     * in `destroy_aidl_vec_of_key_parameter`
     * (but we still need to free() the ptr, so don't reset that) */
    aidl.size = 0;

    destroy_aidl_vec_of_key_parameter(&aidl);
    return ret;
}

template<> aidl_hardware_auth_token
AidlHardwareAuthTokenView::toAidlView(const HardwareAuthToken &generic)
{
    aidl_hardware_auth_token ret{};

    ret.challenge = generic.challenge;
    ret.user_id = generic.userId;
    ret.authenticator_id = generic.authenticatorId;
    ret.authenticator_type = static_cast<u32>(generic.authenticatorType);
    ret.timestamp = generic.timestamp;
    ret.mac = AidlVecOfU8View::toAidlView(generic.mac);

    return ret;
}

HardwareAuthToken fromAidlDestroy(aidl_hardware_auth_token& aidl)
{
    HardwareAuthToken ret{};

    ret.challenge = aidl.challenge;
    ret.userId = aidl.user_id;
    ret.authenticatorId = aidl.authenticator_id;
    ret.authenticatorType = static_cast<HardwareAuthenticatorType>(aidl.authenticator_type);
    ret.timestamp = aidl.timestamp;
    ret.mac = fromAidlDestroy(aidl.mac);

    destroy_aidl_hardware_auth_token(&aidl);
    return ret;
}

std::vector<std::vector<u8>> fromAidlDestroy(aidl_vec_of_certificate& aidl)
{
    std::vector<std::vector<u8>> ret{};

    if (!aidl.ptr || aidl.size <= 0)
        return ret;

    ret.reserve(static_cast<size_t>(aidl.size));
    for (i32 i = 0; i < aidl.size; i++) {
        ret.emplace_back(fromAidlDestroy(aidl.ptr[i].encoded_certificate));
    }

    destroy_aidl_vec_of_certificate(&aidl);
    return ret;
}

} /* namespace transport */
} /* namespace kmhal */
} /* namespace suskeymaster */

#endif /* SUSKEYMASTER_BUILD_HOST */
