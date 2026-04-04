#define HIDL_DISABLE_INSTRUMENTATION
#include "cli.hpp"
#include <libsuskmhal/hidl/hidl-hal.hpp>
#include <libsuskmhal/util/km-params.hpp>
#include <libsuskmhal/keymaster-types-c.h>
#include <android/hardware/keymaster/4.0/types.h>
#include <android/hardware/keymaster/4.0/IKeymasterDevice.h>
#include <cstdbool>
#include <iostream>
#include <semaphore.h>
#include <openssl/evp.h>

namespace suskeymaster {
namespace cli {
namespace hidl_ops {

using namespace ::android::hardware::keymaster::V4_0;
using ::android::hardware::hidl_vec;

static Algorithm determine_key_algorithm(hidl_vec<uint8_t> const& priv_pkcs8);

int import_key(HidlSusKeymaster4& hal, hidl_vec<uint8_t> const& priv_pkcs8,
        hidl_vec<KeyParameter> const& in_import_params,
        hidl_vec<uint8_t>& out_keyblob
)
{
    Algorithm alg = determine_key_algorithm(priv_pkcs8);
    if (alg == static_cast<Algorithm>(-1)) {
        std::cerr << "The key blob is not a valid EC or RSA PKCS#8 private key!" << std::endl;
        return 1;
    }
    std::cout << "Private key algorithm is " << toString(alg) << std::endl;

    hidl_vec<KeyParameter> params(in_import_params);
    kmhal::util::init_default_params(params, { { Tag::ALGORITHM, alg } });

    KeyCharacteristics c;
    ErrorCode e = hal.importKey(params, KeyFormat::PKCS8, priv_pkcs8, out_keyblob, c);
    if (e != ErrorCode::OK) {
        std::cerr << "importKey operation failed: "
            << static_cast<int32_t>(e) << " (" << toString(e) << ")" << std::endl;
        return 1;
    }

    std::cout << "Successfully imported an " << toString(alg)
        << " private key into KeyMaster" << std::endl;
    return 0;
}

int export_key(HidlSusKeymaster4& hal,
    hidl_vec<uint8_t> const& key,
    hidl_vec<uint8_t>& out_public_key_x509,
    hidl_vec<KeyParameter> const& in_application_id_data)
{
    hidl_vec<uint8_t> app_id;
    hidl_vec<uint8_t> app_data;

    for (const auto& kp : in_application_id_data) {
        if (kp.tag == Tag::APPLICATION_ID)
            app_id = kp.blob;
        else if (kp.tag == Tag::APPLICATION_DATA)
            app_data = kp.blob;
    }

    ErrorCode e = hal.exportKey(KeyFormat::X509, key, app_id, app_data, out_public_key_x509);

    if (e != ErrorCode::OK) {
        std::cerr << "exportKey operation failed: "
            << static_cast<int32_t>(e) << " (" << toString(e) << ")" << std::endl;
        return 1;
    }

    std::cout << "Successfully exported public key from KeyMaster" << std::endl;
    return 0;
}

static Algorithm determine_key_algorithm(hidl_vec<uint8_t> const& priv_pkcs8)
{
    EVP_PKEY *pkey = NULL;
    const unsigned char *p = NULL;

    p = priv_pkcs8.data();
    pkey = d2i_PrivateKey(EVP_PKEY_EC, NULL, &p, priv_pkcs8.size());
    if (pkey != NULL) {
        EVP_PKEY_free(pkey);
        return Algorithm::EC;
    }

    p = priv_pkcs8.data();
    pkey = d2i_PrivateKey(EVP_PKEY_RSA, NULL, &p, priv_pkcs8.size());
    if (pkey != NULL) {
        EVP_PKEY_free(pkey);
        return Algorithm::RSA;
    }

    return static_cast<Algorithm>(-1);
}

} /* namespace hidl_ops */
} /* namespace cli */
} /* namespace suskeymaster */
