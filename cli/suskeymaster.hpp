#ifndef CLI_SUSKEYMASTER_HPP_
#define CLI_SUSKEYMASTER_HPP_

#include <libgenericutil/cert-types.h>
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

    int transact_c_generate_and_attest_wrapping_key(
        ::android::sp<::android::hardware::keymaster::V4_0::IKeymasterDevice>   hal,

        ::android::hardware::hidl_vec<uint8_t>&                                 out_wrapping_blob,
        ::android::hardware::hidl_vec<uint8_t>&                                 out_wrapping_pubkey,
        ::android::hardware::hidl_vec<::android::hardware::hidl_vec<uint8_t>> * out_cert_chain
    );
    int transact_s_verify_attestation(
        ::android::hardware::hidl_vec<::android::hardware::hidl_vec<uint8_t>> const& cert_chain
    );
    int transact_s_wrap_key(
        ::android::hardware::hidl_vec<uint8_t> const&                           in_private_key,
        enum sus_key_variant                                                    in_key_variant,
        ::android::hardware::hidl_vec<uint8_t> const&                           in_wrapping_key,

        ::android::hardware::hidl_vec<uint8_t>&                                 out_wrapped_data,
        ::android::hardware::hidl_vec<uint8_t>&                                 out_masking_key
    );
    int transact_c_import_wrapped_key(
        ::android::sp<::android::hardware::keymaster::V4_0::IKeymasterDevice>   hal,

        ::android::hardware::hidl_vec<uint8_t> const&                           in_wrapped_data,
        ::android::hardware::hidl_vec<uint8_t> const&                           in_masking_key,
        ::android::hardware::hidl_vec<uint8_t> const&                           in_wrapping_blob,

        ::android::hardware::hidl_vec<uint8_t>&                                 out_key_blob
    );
};

#endif /* CLI_SUSKEYMASTER_HPP_ */
