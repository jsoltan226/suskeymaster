#include "suskeymaster.hpp"
#include "google-root.h"
#include <android/hardware/keymaster/4.0/types.h>
#include <android/hardware/keymaster/4.0/IKeymasterDevice.h>
#include <hidl/HidlSupport.h>
#include <cstddef>
#include <cstring>
#include <iostream>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

namespace suskeymaster {

using ::android::hardware::hidl_vec;
using namespace ::android::hardware::keymaster::V4_0;

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

int transact_s_verify_attestation(const hidl_vec<hidl_vec<uint8_t>> &cert_chain)
{
    if (cert_chain.size() < 2) {
        std::cerr << "Cert chain size (" << cert_chain.size() << ") too small!" << std::endl;
        return 1;
    }

    const int root_idx = static_cast<int>(cert_chain.size() - 1);
    hidl_vec<uint8_t> const& root_der = cert_chain[cert_chain.size() - 1];

    X509 *leaf = NULL;
    STACK_OF(X509) *intermediates = NULL;
    X509 *root = NULL;
    bool root_old = false;
    bool verify_ok = false;

    bool ok = false;

    if (deserialize_cert_chain(cert_chain, &leaf, &intermediates, &root)) {
        std::cerr << "Failed to deserialize the certificate chain" << std::endl;
        goto err;
    }

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
    }

    ok = true;

err:
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

int transact_s_wrap_key(hidl_vec<uint8_t> const& in_private_key,
        hidl_vec<uint8_t> const& in_wrapping_key, hidl_vec<uint8_t> &out_wrapped_data)
{
    (void) in_private_key;
    (void) in_wrapping_key;
    (void) out_wrapped_data;
    return -1;
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
        {
            *is_old_root = true;
            return 0;
        }
    }

    if (root_der.size() == google_root_2_ec_p384_der_len) {
        if (!std::memcmp(root_der.data(), google_root_2_ec_p384_der,
                google_root_2_ec_p384_der_len))
            return 0;
    }

    return 1;
}

static void destroy_certs(X509 **leaf_p, STACK_OF(X509) **intermediates_p, X509 **root_p)
{
    if (*intermediates_p != NULL) {
        for (int i = 0; i < sk_X509_num(*intermediates_p); i++) {
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

} /* namespace suskeymaster */
