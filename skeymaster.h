#pragma once

#include <android/hardware/keymaster/4.0/types.h>
#include <functional>

class SKeymaster4Device;

extern "C" SKeymaster4Device *
_ZN10skeymaster22CreateSKeymasterDeviceEN7android8hardware9keymaster4V4_013SecurityLevelE(
        ::android::hardware::keymaster::V4_0::SecurityLevel level
    );
#define SKeymaster4_CreateDevice(security_level) \
    _ZN10skeymaster22CreateSKeymasterDeviceEN7android8hardware9keymaster4V4_013SecurityLevelE(security_level)

extern "C" void _ZN10skeymaster17SKeymaster4DeviceD0Ev(SKeymaster4Device *_this);
#define SKeymaster4_DeleteDestroy(_this) \
    _ZN10skeymaster17SKeymaster4DeviceD0Ev(_this)

extern "C" void
_ZN10skeymaster17SKeymaster4Device9attestKeyERKN7android8hardware8hidl_vecIhEERKNS3_INS2_9keymaster4V4_012KeyParameterEEENSt3__18functionIFvNS8_9ErrorCodeERKNS3_IS4_EEEEE(
        SKeymaster4Device *_this,
        ::android::hardware::hidl_vec<unsigned char> const& key_blob,
        ::android::hardware::hidl_vec<::android::hardware::keymaster::V4_0::KeyParameter> const& key_param,
        std::function<
            void (
                ::android::hardware::keymaster::V4_0::ErrorCode err,
                ::android::hardware::hidl_vec<::android::hardware::hidl_vec<unsigned char>> const& cert_chain
            )
        > _attestKey_cb
);
#define SKeymaster4_attestKey(_this, key_blob, key_param, cb) \
    _ZN10skeymaster17SKeymaster4Device9attestKeyERKN7android8hardware8hidl_vecIhEERKNS3_INS2_9keymaster4V4_012KeyParameterEEENSt3__18functionIFvNS8_9ErrorCodeERKNS3_IS4_EEEEE( \
            _this, key_blob, key_param, cb  \
    )

extern "C" void
_ZN10skeymaster17SKeymaster4Device11generateKeyERKN7android8hardware8hidl_vecINS2_9keymaster4V4_012KeyParameterEEENSt3__18functionIFvNS5_9ErrorCodeERKNS3_IhEERKNS5_18KeyCharacteristicsEEEE(
        SKeymaster4Device *_this,
        ::android::hardware::hidl_vec<::android::hardware::keymaster::V4_0::KeyParameter> const& key_params,
        std::function<
            void (
                ::android::hardware::keymaster::V4_0::ErrorCode err,
                ::android::hardware::hidl_vec<unsigned char> const& out_key,
                ::android::hardware::keymaster::V4_0::KeyCharacteristics const& out_characteristics
            )
        > _generateKey_cb
);
#define SKeymaster4_generateKey(_this, key_params, cb) \
    _ZN10skeymaster17SKeymaster4Device11generateKeyERKN7android8hardware8hidl_vecINS2_9keymaster4V4_012KeyParameterEEENSt3__18functionIFvNS5_9ErrorCodeERKNS3_IhEERKNS5_18KeyCharacteristicsEEEE( \
            _this, key_params, cb \
    )

extern "C" void
_ZN10skeymaster17SKeymaster4Device9deleteKeyERKN7android8hardware8hidl_vecIhEE(
        SKeymaster4Device *_this,
        ::android::hardware::hidl_vec<unsigned char> const& key
);
#define SKeymaster4_deleteKey(_this, key) \
    _ZN10skeymaster17SKeymaster4Device9deleteKeyERKN7android8hardware8hidl_vecIhEE(_this, key)
