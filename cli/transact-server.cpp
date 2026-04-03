#define HIDL_DISABLE_INSTRUMENTATION
#define OPENSSL_API_COMPAT 0x10002000L
#include "cli.hpp"
#include "google-root.h"
#include <core/int.h>
#include <core/vector.h>
#include <libsuskmhal/hidl/hidl-hal.hpp>
#include <libsuskmhal/util/km-params.hpp>
#include <libsuskmhal/keymaster-types-c.h>
#include <libsuscertmod/certmod.h>
#include <libsuscertmod/key-desc.h>
#include <libsuscertmod/leaf-cert.h>
#include <hidl/HidlSupport.h>
#include <android/hardware/keymaster/4.0/types.h>
#include <cstddef>
#include <cstring>
#include <iostream>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/asn1.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <stdio.h>

namespace suskeymaster {
namespace cli {
namespace transact {
namespace server {

using ::android::hardware::hidl_vec;
using namespace ::android::hardware::keymaster::V4_0;

/** Functions used by `verify_attestation` */

static int deserialize_cert_chain(hidl_vec<hidl_vec<uint8_t>> const& in_cert_chain,
        X509 **out_leaf, STACK_OF(X509) **out_intermediates, X509 **out_root);
static int verify_cert_chain(bool root_old, int root_depth,
        X509 *leaf, STACK_OF(X509) *intermediates, X509 *root,
        bool *out_ok);
static int check_google_root(hidl_vec<uint8_t> const& root_der, bool *is_old_root);
static void destroy_certs(X509 **leaf_p, STACK_OF(X509) **intermediates_p, X509 **root_p);

struct verify_exdata {
    int depth_of_root_cert;
    bool root_is_the_old_one;
};
static int ignore_old_root_expiry_vfy_cb(int preverify_ok, X509_STORE_CTX *ctx);

static int openssl_err_print_cb(const char *msg, size_t size, void *userdata);
static void print_openssl_errors(void);

/** Functions used by `transact_s_wrap_key` */
static EVP_PKEY * extract_x509_public_key(hidl_vec<uint8_t> const& x509_der);

#define TRANSPORT_KEY_SIZE 32
#define TRANSPORT_IV_SIZE 12
#define TRANSPORT_TAG_SIZE 16
static int wrap_with_transport_key(
        const uint8_t transport_key[TRANSPORT_KEY_SIZE],
        const uint8_t iv[TRANSPORT_IV_SIZE],
        const uint8_t *aad, int aad_size,
        uint8_t *data, int data_size,
        uint8_t out_tag[TRANSPORT_TAG_SIZE]
);

static int encrypt_transport_key(const uint8_t plaintext[TRANSPORT_KEY_SIZE],
        const uint8_t masking_key[TRANSPORT_KEY_SIZE], EVP_PKEY *wrapping_key,
        hidl_vec<uint8_t>& out_ciphertext);

static int do_transport_encryption(
        hidl_vec<uint8_t> const& in_wrapping_key_x509, hidl_vec<uint8_t> const& in_aad,
        hidl_vec<uint8_t> &private_key, hidl_vec<uint8_t>& out_encrypted_transport_key,
        hidl_vec<uint8_t>& out_iv, hidl_vec<uint8_t>& out_tag, hidl_vec<uint8_t>& out_masking_key
);

static int encode_iwk_key_description_der(hidl_vec<uint8_t>& der,
        const struct certmod::KM_AuthorizationList_v3 *auth_list);

static int encode_iwk_secure_key_wrapper_der(hidl_vec<uint8_t>& der,
        hidl_vec<uint8_t> const& encrypted_transport_key,
        hidl_vec<uint8_t> const& initialization_vector,
        hidl_vec<uint8_t> const& key_description_der,
        hidl_vec<uint8_t> const& encrypted_key,
        hidl_vec<uint8_t> const& tag
);

/* from `libsuscertmod/key-desc-repack.c` */
static i32 measure_integer_size(struct certmod::key_desc_measure_ctx *ctx, i64 val);
static i32 measure_octet_string_size(struct certmod::key_desc_measure_ctx *ctx,
        hidl_vec<uint8_t> const& str);
static bool write_integer(unsigned char **p, unsigned char *end,
        const struct certmod::key_desc_measure_ctx *mctx, i64 val);
static bool write_octet_string(unsigned char **p, unsigned char *end,
        const struct certmod::key_desc_measure_ctx *mctx, hidl_vec<uint8_t> const& str);

static void pr_info(const char *fmt, ...)
{
    va_list vlist;
    va_start(vlist, fmt);
    vfprintf(stdout, fmt, vlist);
    putchar('\n');
    va_end(vlist);
}

int verify_attestation(const hidl_vec<hidl_vec<uint8_t>> &cert_chain)
{
    if (cert_chain.size() < 2) {
        std::cerr << "Cert chain size (" << cert_chain.size() << ") too small!" << std::endl;
        return 1;
    }

    const int root_idx = static_cast<int>(cert_chain.size() - 1);
    hidl_vec<uint8_t> const& root_der = cert_chain[cert_chain.size() - 1];
    hidl_vec<uint8_t> const& leaf_der = cert_chain[0];

    X509 *leaf = NULL;
    STACK_OF(X509) *intermediates = NULL;
    X509 *root = NULL;
    bool root_old = false;
    bool verify_ok = false;

    VECTOR(u8) leaf_vec = NULL;
    struct certmod::KM_KeyDescription_v3 *km_desc = NULL;

    bool ok = false;

    if (deserialize_cert_chain(cert_chain, &leaf, &intermediates, &root)) {
        std::cerr << "Failed to deserialize the certificate chain" << std::endl;
        goto err;
    }

    leaf_vec = vector_new(u8);
    vector_resize(&leaf_vec, leaf_der.size());
    std::memcpy(leaf_vec, leaf_der.data(), leaf_der.size());

    if (certmod::leaf_cert_parse(leaf_vec, NULL, NULL, &km_desc)) {
        std::cerr << "Failed to parse the leaf certificate!" << std::endl;
        vector_destroy(&leaf_vec);
        goto err;
    }

    certmod::key_desc_dump(km_desc, pr_info);

    if (check_google_root(root_der, &root_old)) {
        std::cerr << "The root cert is not a Google Attestation Root certificate!" << std::endl;
        goto err;
    }

    if (verify_cert_chain(root_old, root_idx, leaf, intermediates, root, &verify_ok)) {
        std::cerr << "Unexpected failure while trying to verify the certificate chain"
            << std::endl;
        goto err;
    } else if (!verify_ok) {
        std::cerr << "Certificate chain verification failed!" << std::endl;
        goto err;
    }

    ok = true;

err:
    certmod::key_desc_destroy(&km_desc);
    vector_destroy(&leaf_vec);

    destroy_certs(&leaf, &intermediates, &root);

    if (!ok) {
        print_openssl_errors();
        std::cerr << "Failed to verify the attestation certificate chain" << std::endl;
        return 1;
    } else {
        std::cout << "Successfully verified the attestation certificate chain" << std::endl;
        return 0;
    }
}

int wrap_key(hidl_vec<uint8_t> const& in_private_key, enum certmod::sus_key_variant key_variant,
        hidl_vec<uint8_t> const& in_wrapping_key, hidl_vec<KeyParameter> const& in_key_params,
        hidl_vec<uint8_t>& out_wrapped_data, hidl_vec<uint8_t>& out_masking_key)
{
    hidl_vec<KeyParameter> params(in_key_params);
    struct kmhal::KM_AuthorizationList_v3 auth_list = {};

    hidl_vec<uint8_t> iwk_key_description_der = {};
    hidl_vec<uint8_t> encrypted_transport_key;
    hidl_vec<uint8_t> transport_iv;
    hidl_vec<uint8_t> transport_tag;
    hidl_vec<uint8_t> encrypted_key(in_private_key);

    if (key_variant != certmod::SUS_KEY_EC && key_variant != certmod::SUS_KEY_RSA) {
        std::cerr << "Invalid parameters (key_variant: " << key_variant << ")" << std::endl;
        return 1;
    } else {
        std::cout << "Private key variant is " <<
            (key_variant == certmod::SUS_KEY_RSA ? "RSA" : "EC")
            << std::endl;
    }

    if (key_variant == certmod::SUS_KEY_RSA) {
        kmhal::util::init_default_params(params, {
            { Tag::ALGORITHM, Algorithm::RSA },
            { Tag::DIGEST, { Digest::SHA_2_256 } },
            { Tag::PADDING, { PaddingMode::RSA_PKCS1_1_5_SIGN } },
            { Tag::KEY_SIZE, 2048 },
            { Tag::RSA_PUBLIC_EXPONENT, 65537 },
            { Tag::PURPOSE, { KeyPurpose::SIGN, KeyPurpose::VERIFY } },
            { Tag::NO_AUTH_REQUIRED, true }
        });
    } else /* if (key_variant == SUS_KEY_EC) */ {
        kmhal::util::init_default_params(params, {
            { Tag::ALGORITHM, Algorithm::EC },
            { Tag::DIGEST, { Digest::SHA_2_256 } },
            { Tag::EC_CURVE, EcCurve::P_256 },
            { Tag::PURPOSE, { KeyPurpose::SIGN, KeyPurpose::VERIFY } },
            { Tag::NO_AUTH_REQUIRED, true }
        });
    }

    kmhal::util::key_params_2_auth_list(params, &auth_list);

    if (encode_iwk_key_description_der(iwk_key_description_der, &auth_list)) {
        std::cerr << "Failed to encode the importWrappedKey KeyDescription" << std::endl;
        certmod::key_desc_destroy_auth_list(&auth_list);
        return 1;
    }
    certmod::key_desc_destroy_auth_list(&auth_list);

    if (do_transport_encryption(in_wrapping_key, iwk_key_description_der, encrypted_key,
                encrypted_transport_key, transport_iv, transport_tag, out_masking_key))
    {
        std::cerr << "Failed to perform the transport wrapping" << std::endl;
        return 1;
    }

    if (encode_iwk_secure_key_wrapper_der(out_wrapped_data,
                encrypted_transport_key, transport_iv, iwk_key_description_der,
                encrypted_key, transport_tag))
    {
        std::cerr << "Failed to encode the importWrappedKey SecureKeyWrapper" << std::endl;
        return 1;
    }

    certmod::key_desc_destroy_auth_list(&auth_list);
    std::cout << "Successfully wrapped private key for transact" << std::endl;
    return 0;
}

static int deserialize_cert_chain(hidl_vec<hidl_vec<uint8_t>> const& in_cert_chain,
        X509 **out_leaf, STACK_OF(X509) **out_intermediates, X509 **out_root)
{
    const unsigned char *p = NULL;

    *out_leaf = NULL;
    *out_intermediates = NULL;
    *out_root = NULL;

    hidl_vec<uint8_t> const& leaf_hidl = in_cert_chain[0];
    hidl_vec<uint8_t> const& root_hidl = in_cert_chain[in_cert_chain.size() - 1];

    /* De-serialize everything */
    p = leaf_hidl.data();
    *out_leaf = d2i_X509(NULL, &p, leaf_hidl.size());
    if (*out_leaf == NULL) {
        std::cerr << "Failed to deserialize the leaf cert" << std::endl;
        return 1;
    }

    p = root_hidl.data();
    *out_root = d2i_X509(NULL, &p, root_hidl.size());
    if (*out_root == NULL) {
        std::cerr << "Failed to deserialize the root cert" << std::endl;
        return 1;
    }

    *out_intermediates = sk_X509_new_null();
    if (*out_intermediates == NULL) {
        std::cerr << "Couldn't create the intermediate cert stack" << std::endl;
        return 1;
    }
    for (uint32_t i = 1; i <= in_cert_chain.size() - 2; i++) {
        p = in_cert_chain[i].data();
        X509 *curr = d2i_X509(NULL, &p, in_cert_chain[i].size());
        if (curr == NULL) {
            std::cerr << "Failed to deserialize intermediate cert no. " << i << std::endl;
            return 1;
        }

        if (sk_X509_push(*out_intermediates, curr) == 0) {
            std::cerr << "Failed to push cert no. " << i <<
                "to the intermediates stack" << std::endl;
            X509_free(curr);
            return 1;
        }
    }

    return 0;
}

static int verify_cert_chain(bool root_old, int root_depth,
        X509 *leaf, STACK_OF(X509) *intermediates, X509 *root,
        bool *out_ok)
{
    X509_STORE *root_store = NULL;
    X509_STORE_CTX *ctx = NULL;
    int r = 0;
    struct verify_exdata exdata = {};
    long vfy_err = 0;

    int ret = 1;

    *out_ok = false;

    root_store = X509_STORE_new();
    if (root_store == NULL) {
        std::cerr << "Failed to create a new X509 store" << std::endl;
        goto err;
    }

    if (X509_STORE_add_cert(root_store, root) == 0) {
        std::cerr << "Failed to add the root certificate to the X509 store" << std::endl;
        goto err;
    }

    ctx = X509_STORE_CTX_new();
    if (ctx == NULL) {
        std::cerr << "Failed to create a new X509 store context" << std::endl;
        goto err;
    }

    if (X509_STORE_CTX_init(ctx, root_store, leaf, intermediates) == 0) {
        std::cerr << "Failed to initialize the X509 store context" << std::endl;
        goto err;
    }

    X509_STORE_CTX_set_verify_cb(ctx, ignore_old_root_expiry_vfy_cb);
    exdata.depth_of_root_cert = root_depth;
    exdata.root_is_the_old_one = root_old;
    if (X509_STORE_CTX_set_ex_data(ctx, 0, &exdata) == 0) {
        std::cerr << "Failed to set user data on the X509 store context" << std::endl;
        goto err;
    }

    r = X509_verify_cert(ctx);
    if (r == 0) {
        vfy_err = X509_STORE_CTX_get_error(ctx);
        std::cerr << "Certificate chain verification failed ("
            << vfy_err << " - " << X509_verify_cert_error_string(vfy_err) << ")" << std::endl;
        *out_ok = false;
    } else if (r < 0) {
        std::cerr << "X509_verify_cert failed unexpectedely: " << r << std::endl;
        *out_ok = false;
        goto err;
    } else /* if (r == 1) */ {
        *out_ok = true;
    }

    ret = 0;

err:
    if (ctx != NULL) {
        X509_STORE_CTX_free(ctx);
        ctx = NULL;
    }
    if (root_store != NULL) {
        X509_STORE_free(root_store);
        root_store = NULL;
    }

    return ret;
}

static int check_google_root(hidl_vec<uint8_t> const& root_der, bool *is_old_root)
{
    *is_old_root = false;

    if (root_der.size() == google_root_1_rsa_4096_der_len) {
        if (!std::memcmp(root_der.data(), google_root_1_rsa_4096_der,
                google_root_1_rsa_4096_der_len))
            return 0;
    }

    if (root_der.size() == google_root_2_ec_p384_der_len) {
        if (!std::memcmp(root_der.data(), google_root_2_ec_p384_der,
                google_root_2_ec_p384_der_len))
            return 0;
    }

    if (root_der.size() == google_root_3_rsa_4096_der_len) {
        if (!std::memcmp(root_der.data(), google_root_3_rsa_4096_der,
                google_root_3_rsa_4096_der_len))
            return 0;
    }

    if (root_der.size() == google_root_4_rsa_4096_der_len) {
        if (!std::memcmp(root_der.data(), google_root_4_rsa_4096_der,
                google_root_4_rsa_4096_der_len))
            return 0;
    }

    if (root_der.size() == google_root_5_rsa_4096_old_der_len) {
        if (!std::memcmp(root_der.data(), google_root_5_rsa_4096_old_der,
                google_root_5_rsa_4096_old_der_len))
        {
            std::cout << "WARNING: using old attestation root" << std::endl;
            *is_old_root = true;
            return 0;
        }
    }

    return 1;
}

static void destroy_certs(X509 **leaf_p, STACK_OF(X509) **intermediates_p, X509 **root_p)
{
    if (*intermediates_p != NULL) {
        for (unsigned int i = 0; i < (unsigned int)sk_X509_num(*intermediates_p); i++) {
            X509 *const curr = sk_X509_value(*intermediates_p, i);
            if (curr != NULL)
                X509_free(curr);

            sk_X509_set(*intermediates_p, i, NULL);
        }
        sk_X509_free(*intermediates_p);
        *intermediates_p = NULL;
    }
    if (*root_p != NULL) {
        X509_free(*root_p);
        *root_p = NULL;
    }
    if (*leaf_p != NULL) {
        X509_free(*leaf_p);
        *leaf_p = NULL;
    }
}

static int ignore_old_root_expiry_vfy_cb(int preverify_ok, X509_STORE_CTX *ctx)
{
    int err = 0;
    void *exdata = NULL; struct verify_exdata *data = NULL;
    int curr_depth = -1;

    if (preverify_ok)
        return 1;

    exdata = X509_STORE_CTX_get_ex_data(ctx, 0);
    if (exdata == NULL) {
        std::cerr << "Couldn't get the exdata from the X509 store context" << std::endl;
        return 0;
    }
    data = reinterpret_cast<struct verify_exdata *>(exdata);

    err = X509_STORE_CTX_get_error(ctx);
    curr_depth = X509_STORE_CTX_get_error_depth(ctx);

    /* Ignore expiration errors on the old root */
    if (err == X509_V_ERR_CERT_HAS_EXPIRED &&
        curr_depth == data->depth_of_root_cert &&
        data->root_is_the_old_one)
    {
        std::cerr << "WARNING: Using old attestation root, which is expired" << std::endl;
        return 1;
    }

    std::cerr << "Verification err " << err << " on cert " << curr_depth << std::endl;

    return 0;
}

static int openssl_err_print_cb(const char *msg, size_t size, void *userdata)
{
    (void) size;
    (void) userdata;
    std::cerr << msg;
    return 1;
}

static void print_openssl_errors(void)
{
    std::cerr << "BEGIN OPENSSL ERRORS" << std::endl;
    ERR_print_errors_cb(openssl_err_print_cb, NULL);
    std::cerr << "END OPENSSL ERRORS" << std::endl;
}

static EVP_PKEY * extract_x509_public_key(hidl_vec<uint8_t> const& x509_der)
{
    const uint8_t *p = NULL;

    EVP_PKEY *ret = NULL;
    int bits = 0;
    bool ok = false;

    p = x509_der.data();
    ret = d2i_PUBKEY(NULL, &p, x509_der.size());
    if (ret == NULL) {
        std::cerr << "Couldn't deserialize the X.509 public key" << std::endl;
        goto err;
    }

    if (EVP_PKEY_base_id(ret) != EVP_PKEY_RSA) {
        std::cerr << "The key is not an RSA key" << std::endl;
        goto err;
    }

    bits = EVP_PKEY_bits(ret);
    if (bits != 2048) {
        std::cerr << "Invalid RSA key size (" << bits << " - expected 2048)" << std::endl;
        goto err;
    }

    ok = true;

err:
    if (!ok && ret != NULL) {
        EVP_PKEY_free(ret);
        ret = NULL;
    }

    if (!ok) {
        print_openssl_errors();
    }

    return ok ? ret : NULL;
}

static int wrap_with_transport_key(
        const uint8_t transport_key[TRANSPORT_KEY_SIZE],
        const uint8_t iv[TRANSPORT_IV_SIZE],
        const uint8_t *aad, int aad_size,
        uint8_t *data, int data_size,
        uint8_t out_tag[TRANSPORT_TAG_SIZE]
)
{
    EVP_CIPHER_CTX *ctx = NULL;
    int len = 0, total = 0;
    bool ok = false;

    /* Init the context */
    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        std::cerr << "Couldn't create a new EVP cipher context" << std::endl;
        goto err;
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
        std::cerr << "Failed to initialize the encryption context" << std::endl;
        goto err;
    }
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, transport_key, iv) != 1) {
        std::cerr << "Failed to set the encryption context parameters" << std::endl;
        goto err;
    }

    /* Provide the AAD data */
    if (EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_size) != 1) {
        std::cerr << "Update operation failed for AAD" << std::endl;
        goto err;
    }

    /* Provide the plaintext data */
    if (EVP_EncryptUpdate(ctx, data, &len, data, data_size) != 1) {
        OPENSSL_cleanse(data, data_size);
        std::cerr << "Update operation failed for plaintext" << std::endl;
        goto err;
    }
    total += len;

    /* Do the encryption */
    if (EVP_EncryptFinal_ex(ctx, data + total, &len) != 1) {
        std::cerr << "Final operation failed" << std::endl;
        goto err;
    }
    total += len;

    if (total != data_size) {
        std::cerr << "Incorrect number of bytes written to ciphertext output buffer (" <<
            total << ", expected " << data_size << ")!" << std::endl;
        std::abort();
    }

    /* Extract the GCM tag */
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TRANSPORT_TAG_SIZE, out_tag) != 1) {
        OPENSSL_cleanse(out_tag, TRANSPORT_TAG_SIZE);
        std::cerr << "Couldn't get the AES-GCM tag" << std::endl;
        goto err;
    }

    ok = true;

err:
    if (ctx != NULL) {
        EVP_CIPHER_CTX_free(ctx);
        ctx = NULL;
    }

    return ok ? 0 : 1;
}

static int encrypt_transport_key(const uint8_t plaintext[TRANSPORT_KEY_SIZE],
        const uint8_t masking_key[TRANSPORT_KEY_SIZE], EVP_PKEY *wrapping_key,
        hidl_vec<uint8_t>& out_ciphertext)
{
    EVP_PKEY_CTX *ctx = NULL;
    uint8_t masked_plaintext[TRANSPORT_KEY_SIZE] = { 0 };
    size_t out_len = 0;

    bool ok = false;

    ctx = EVP_PKEY_CTX_new(wrapping_key, NULL);
    if (ctx == NULL) {
        std::cerr << "Failed to create the wrapping public key context" << std::endl;
        goto err;
    }

    if (EVP_PKEY_encrypt_init(ctx) != 1) {
        std::cerr << "Failed to initialize the wrapping encryption context" << std::endl;
        goto err;
    }

    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
        std::cerr << "Failed to set the OAEP padding mode" << std::endl;
        goto err;
    }
    if (EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256()) <= 0) {
        std::cerr << "Failed to set the OAEP hash" << std::endl;
        goto err;
    }
    if (EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, EVP_sha1()) <= 0) {
        std::cerr << "Failed to set the OAEP MGF1" << std::endl;
        goto err;
    }

    /* Apply the masking key */
    for (uint32_t i = 0; i < TRANSPORT_KEY_SIZE; i++)
        masked_plaintext[i] = plaintext[i] ^ masking_key[i];

    if (EVP_PKEY_encrypt(ctx, NULL, &out_len, masked_plaintext, TRANSPORT_KEY_SIZE) <= 0) {
        std::cerr << "Failed to determine ciphertext size" << std::endl;
        goto err;
    }

    out_ciphertext.resize(out_len);
    if (EVP_PKEY_encrypt(ctx, out_ciphertext.data(), &out_len,
                masked_plaintext, TRANSPORT_KEY_SIZE) <= 0)
    {
        OPENSSL_cleanse(out_ciphertext.data(), out_ciphertext.size());
        std::cerr << "RSA encrypt operation failed" << std::endl;
        goto err;
    }

    ok = true;

err:
    if (ctx != NULL) {
        EVP_PKEY_CTX_free(ctx);
        ctx = NULL;
    }

    return ok ? 0 : 1;
}

static int do_transport_encryption(
        hidl_vec<uint8_t> const& in_wrapping_key_x509, hidl_vec<uint8_t> const& in_aad,
        hidl_vec<uint8_t> &private_key, hidl_vec<uint8_t>& out_encrypted_transport_key,
        hidl_vec<uint8_t>& out_iv, hidl_vec<uint8_t>& out_tag, hidl_vec<uint8_t>& out_masking_key
)
{
    bool ok = false;

    uint8_t transport_key[TRANSPORT_KEY_SIZE] = { 0 };
    uint8_t iv[TRANSPORT_IV_SIZE] = { 0 };
    uint8_t tag[TRANSPORT_TAG_SIZE] = { 0 };
    uint8_t masking_key[TRANSPORT_KEY_SIZE] = { 0 };

    out_iv.resize(TRANSPORT_IV_SIZE);
    out_tag.resize(TRANSPORT_TAG_SIZE);
    OPENSSL_cleanse(out_iv.data(), out_iv.size());
    OPENSSL_cleanse(out_tag.data(), out_tag.size());

    out_encrypted_transport_key.resize(0);

    EVP_PKEY *wrapping_public_key = NULL;

    if (RAND_bytes(iv, TRANSPORT_IV_SIZE) != 1) {
        std::cerr << "Couldn't generate the transport key IV" << std::endl;
        goto err;
    }

    if (RAND_bytes(transport_key, TRANSPORT_KEY_SIZE) != 1) {
        std::cerr << "Couldn't generate the transport key" << std::endl;
        goto err;
    }

    if (RAND_bytes(masking_key, TRANSPORT_KEY_SIZE) != 1) {
        std::cerr << "Couldn't generate the masking key" << std::endl;
        goto err;
    }

    if (wrap_with_transport_key(transport_key, iv,
                in_aad.data(), in_aad.size(),
                private_key.data(), private_key.size(), tag))
    {
        std::cerr << "Failed to wrap the private key with the transport key" << std::endl;
        goto err;
    }

    wrapping_public_key = extract_x509_public_key(in_wrapping_key_x509);
    if (wrapping_public_key == NULL) {
        std::cerr << "Failed to extract the wrapping public key from the X.509 cert" << std::endl;
        goto err;
    }

    if (encrypt_transport_key(transport_key, masking_key,
                wrapping_public_key, out_encrypted_transport_key))
    {
        OPENSSL_cleanse(transport_key, TRANSPORT_KEY_SIZE);
        std::cerr << "Failed to encrypt the transport key with the wrapping key" << std::endl;
        goto err;
    }
    OPENSSL_cleanse(transport_key, TRANSPORT_KEY_SIZE);

    std::cout << "Successfully encrypted the private & transport keys" << std::endl;
    ok = true;

err:

    if (wrapping_public_key != NULL) {
        EVP_PKEY_free(wrapping_public_key);
        wrapping_public_key = NULL;
    }

    if (ok) {
        out_iv.resize(TRANSPORT_IV_SIZE);
        std::memcpy(out_iv.data(), iv, TRANSPORT_IV_SIZE);

        out_tag.resize(TRANSPORT_TAG_SIZE);
        std::memcpy(out_tag.data(), tag, TRANSPORT_TAG_SIZE);

        out_masking_key.resize(TRANSPORT_KEY_SIZE);
        std::memcpy(out_masking_key.data(), masking_key, TRANSPORT_KEY_SIZE);
    }

    OPENSSL_cleanse(tag, TRANSPORT_TAG_SIZE);
    OPENSSL_cleanse(iv, TRANSPORT_IV_SIZE);
    OPENSSL_cleanse(masking_key, TRANSPORT_KEY_SIZE);

    return ok ? 0 : 1;
}

static int encode_iwk_key_description_der(hidl_vec<uint8_t>& der,
        const struct certmod::KM_AuthorizationList_v3 *auth_list)
{
    struct certmod::key_desc_measure_ctx mctx = {};
    i32 tmp = 0;
    u32 content_bytes = 0, total_bytes = 0;
    u8 *p = NULL;
    u8 *end = NULL;
    bool ok = false;

    if (certmod::key_desc_measure_ctx_init(&mctx)) {
        std::cerr << "Failed to initialize the measurement context" << std::endl;
        goto err;
    }

    /* Measure the SEQUENCE's content */
    tmp = measure_integer_size(&mctx, static_cast<i64>(KeyFormat::PKCS8));
    if (tmp < 0) {
        std::cerr << "Failed to measure the KeyFormat INTEGER" << std::endl;
        goto err;
    }
    content_bytes += static_cast<u32>(tmp);

    tmp = certmod::key_desc_measure_outer_auth_list(&mctx, auth_list,
                certmod::KEY_DESC_MEASURE_AL_HARDWARE_ENFORCED);
    if (tmp < 0) {
        std::cerr << "Failed to measure the authorization list" << std::endl;
        goto err;
    }
    content_bytes += static_cast<u32>(tmp);

    /* Measure the entire SEQUENCE's TLV */
    tmp = ASN1_object_size(true, content_bytes, V_ASN1_SEQUENCE);
    if (tmp < 0) {
        std::cerr << "Failed to measure the iwk key description sequence" << std::endl;
        goto err;
    }
    total_bytes = tmp;

    der.resize(total_bytes);
    p = der.data();
    end = der.data() + der.size();

    if (!certmod::key_desc_write_sequence_header(&p, end,
                content_bytes, static_cast<u32>(kmhal::KM_TAG_INVALID)))
    {
        std::cerr << "Failed to write the iwk key description SEQUENCE header" << std::endl;
        goto err;
    }

    if (!write_integer(&p, end, &mctx, static_cast<i64>(KeyFormat::PKCS8))) {
        std::cerr << "Failed to write the KeyFormat integer" << std::endl;
        goto err;
    }

    if (!certmod::key_desc_write_auth_list(&p, end, auth_list,
                &mctx, certmod::KEY_DESC_MEASURE_AL_HARDWARE_ENFORCED))
    {
        std::cerr << "Failed to write the AuthorizationList sequence" << std::endl;
        goto err;
    }

    if (p != end) {
        std::cerr << "Wrote an incorrect amount of bytes!" << std::endl;
        goto err;
    }

    ok = true;

err:
    certmod::key_desc_measure_ctx_destroy(&mctx);
    p = end = NULL;
    content_bytes = total_bytes = tmp = 0;

    return ok ? 0 : 1;
}

static int encode_iwk_secure_key_wrapper_der(hidl_vec<uint8_t>& der,
        hidl_vec<uint8_t> const& encrypted_transport_key,
        hidl_vec<uint8_t> const& initialization_vector,
        hidl_vec<uint8_t> const& key_description_der,
        hidl_vec<uint8_t> const& encrypted_key,
        hidl_vec<uint8_t> const& tag
)
{
    struct certmod::key_desc_measure_ctx mctx = {};
    size_t len = 0, total_len = 0;
    i32 tmp = 0;
    u8 *p = NULL, *end = NULL;
    bool ok = false;

    /** Measure the requiered DER length **/

    if (certmod::key_desc_measure_ctx_init(&mctx)) {
        std::cerr << "Failed to initialize the measurement context" << std::endl;
        goto err;
    }

    /* for >version INTEGER< (which always contains `0`) */
    tmp = measure_integer_size(&mctx, 0);
    if (tmp < 0) {
        std::cerr << "Failed to measure the size of an ASN.1 INTEGER" << std::endl;
        goto err;
    }
    len += tmp;

    for (auto const& s : { encrypted_transport_key, initialization_vector, encrypted_key, tag }) {
        tmp = measure_octet_string_size(&mctx, s);
        if (tmp < 0) {
            std::cerr << "Failed to measure the size of an ASN.1 OCTET STRING" << std::endl;
            goto err;
        }
        len += tmp;
    }

    len += key_description_der.size();

    /* Add the SEQUENCE tag size */
    total_len = ASN1_object_size(true, len, V_ASN1_SEQUENCE);

    der.resize(total_len);

    /** Encode the DER **/
    p = der.data();
    end = p + der.size();

    if (!certmod::key_desc_write_sequence_header(&p, end, len, kmhal::KM_TAG_INVALID)) {
        std::cerr << "Failed to write the SecureKeyWrapper SEQUENCE header" << std::endl;
        goto err;
    }

    if (!write_integer(&p, end, &mctx, 0)) {
        std::cerr << "Failed to write the `version` INTEGER" << std::endl;
        goto err;
    }

    if (!write_octet_string(&p, end, &mctx, encrypted_transport_key)) {
        std::cerr << "Failed to write the encrypted transport key OCTET STRING" << std::endl;
        goto err;
    }
    if (!write_octet_string(&p, end, &mctx, initialization_vector)) {
        std::cerr << "Failed to write the initialization vector OCTET STRING" << std::endl;
        goto err;
    }

    if (p + key_description_der.size() > end) {
        std::cerr << "Key description SEQUENCE overruns buffer!" << std::endl;
        goto err;
    }
    std::memcpy(p, key_description_der.data(), key_description_der.size());
    p += key_description_der.size();

    if (!write_octet_string(&p, end, &mctx, encrypted_key)) {
        std::cerr << "Failed to write the encrypted key OCTET STRING" << std::endl;
        goto err;
    }
    if (!write_octet_string(&p, end, &mctx, tag)) {
        std::cerr << "Failed to write the authentication tag OCTET STRING" << std::endl;
        goto err;
    }

    if (p != end) {
        std::cerr << "Wrote an incorrect amount of bytes!" << std::endl;
        goto err;
    }

    std::cout << "Successfully encoded the SecureKeyWrapper DER sequence" << std::endl;
    ok = true;

err:
    key_desc_measure_ctx_destroy(&mctx);

    return ok ? 0 : 1;
}


static i32 measure_integer_size(struct certmod::key_desc_measure_ctx *ctx, i64 val)
{
    if (ctx == NULL || !ctx->initialized_) {
        std::cerr << "Invalid parameters!";
        return -1;
    }

    if (ASN1_INTEGER_set_int64(ctx->i, val) == 0) {
        std::cerr << "Couldn't set the value of an ASN.1 INTEGER to an int64";
        return -1;
    }

    return i2d_ASN1_INTEGER(ctx->i, NULL);
}

static i32 measure_octet_string_size(struct certmod::key_desc_measure_ctx *ctx,
        hidl_vec<uint8_t> const& str)
{
    if (ctx == NULL || !ctx->initialized_ || str == NULL) {
        std::cerr << "Invalid parameters!";
        return -1;
    }

    if (ASN1_OCTET_STRING_set(ctx->str, str.data(), str.size()) == 0) {
        std::cerr << "Couldn't set the value of an ASN.1 OCTET_STRING";
        return -1;
    }

    return i2d_ASN1_OCTET_STRING(ctx->str, NULL);
}

static bool write_integer(unsigned char **p, unsigned char *end,
        const struct certmod::key_desc_measure_ctx *mctx, i64 val)
{
    if (ASN1_INTEGER_set_int64(mctx->i, val) == 0) {
        std::cerr << "Couldn't set the value of an ASN.1 INTEGER!";
        return false;
    }

    i32 content_len = i2d_ASN1_INTEGER(mctx->i, NULL);
    if (content_len < 0) {
        std::cerr << "Failed to measure the length of an ASN.1 INTEGER!";
        return false;
    }

    if (*p + content_len > end) {
        std::cerr << "ASN.1 INTEGER overruns buffer!";
        return false;
    }

    if (i2d_ASN1_INTEGER(mctx->i, p) < 0) {
        std::cerr << "Failed to serialize an ASN.1 INTEGER value!";
        return false;
    }

    return true;
}

static bool write_octet_string(unsigned char **p, unsigned char *end,
        const struct certmod::key_desc_measure_ctx *mctx, hidl_vec<uint8_t> const& str)
{
    if (ASN1_OCTET_STRING_set(mctx->str, str.data(), str.size()) == 0) {
        std::cerr << "Failed to set the value of an ASN.1 OCTET_STRING!";
        return false;
    }

    i32 content_len = i2d_ASN1_OCTET_STRING(mctx->str, NULL);
    if (content_len < 0) {
        std::cerr << "Failed to measure the length of an ASN.1 OCTET_STRING!";
        return false;
    }

    if (*p + content_len > end) {
        std::cerr << "ASN.1 OCTET_STRING overruns buffer!";
        return false;
    }

    if (i2d_ASN1_OCTET_STRING(mctx->str, p) < 0) {
        std::cerr << "Failed to serialize an ASN.1 OCTET_STRING!";
        return false;
    }

    return true;
}

} /* namespace server */
} /* namespace transact */
} /* namespace cli */
} /* namespace suskeymaster */
