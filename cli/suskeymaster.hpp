#ifndef CLI_SUSKEYMASTER_HPP_
#define CLI_SUSKEYMASTER_HPP_

#include <vector>
#include <string>
#include <cstdint>
#include <utils/StrongPointer.h>
#include <android/hardware/keymaster/4.0/types.h>
#include <android/hardware/keymaster/4.0/IKeymasterDevice.h>

namespace suskeymaster {
    int generate_key(
        ::android::sp<::android::hardware::keymaster::V4_0::IKeymasterDevice>   hal,
        ::android::hardware::keymaster::V4_0::Algorithm                         alg,

        ::android::hardware::hidl_vec<uint8_t>&                                 out_wrapped_blob
    );
    int attest_key(
        ::android::sp<::android::hardware::keymaster::V4_0::IKeymasterDevice>   hal,
        ::android::hardware::hidl_vec<uint8_t> const&                           key
    );

    int import_key(
        ::android::sp<::android::hardware::keymaster::V4_0::IKeymasterDevice>   hal,
        ::android::hardware::hidl_vec<uint8_t> const&                           priv_pkcs8,
        ::android::hardware::keymaster::V4_0::Algorithm                         alg,

        ::android::hardware::hidl_vec<uint8_t>&                                 out_wrapped_blob
    );
    int export_key(
        ::android::sp<::android::hardware::keymaster::V4_0::IKeymasterDevice>   hal,
        ::android::hardware::hidl_vec<uint8_t> const&                           key,

        ::android::hardware::hidl_vec<uint8_t>&                                 out_public_key_x509
    );

    int sign(
        ::android::sp<::android::hardware::keymaster::V4_0::IKeymasterDevice>   hal,
        ::android::hardware::hidl_vec<uint8_t> const&                           message,
        ::android::hardware::hidl_vec<uint8_t> const&                           key,

        ::android::hardware::hidl_vec<uint8_t>&                                 out_signature
    );

    ::android::hardware::hidl_vec<uint8_t> const& get_sus_application_id(void);

    int make_keybox(
        std::vector<std::string> const& ec_cert_paths,
        std::string const& ec_wrapped_key_path,

        std::vector<std::string> const& rsa_cert_paths,
        std::string const& rsa_wrapped_key_path,

        std::string const& out_file_path
    );

    int dump_keybox(
        std::string const& keybox_path,

        std::string const& out_dir_path
    );
};

#endif /* CLI_SUSKEYMASTER_HPP_ */
