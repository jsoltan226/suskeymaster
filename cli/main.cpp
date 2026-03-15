#include "cli.hpp"
#include <libgenericutil/cert-types.h>
#include <core/log.h>
#include <android/hardware/keymaster/4.0/types.h>
#include <android/hardware/keymaster/4.0/IKeymasterDevice.h>
#include <iomanip>
#include <istream>
#include <netinet/in.h>
#include <utils/StrongPointer.h>
#include <strings.h>
#include <arpa/inet.h>
#include <cstdio>
#include <sstream>
#include <cerrno>
#include <vector>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <ostream>
#include <iostream>

using namespace ::android::hardware::keymaster::V4_0;
using namespace ::android::hardware;

static const char *g_argv0 = NULL;
static ::android::sp<IKeymasterDevice> g_hal;

static void setup_cgd_log(void);

static void check_args(int argc, const char **argv,
        bool *o_should_return, int *o_return_val);
static int dispatch_cmd(int argc, const char **argv);

static int init_g_hal(void);

static void print_usage(void);
static void print_not_enough_args_for_cmd(const char *cmd);

int main(int argc, char **argv)
{
    g_argv0 = argv[0];
    setup_cgd_log();

    bool should_return = false;
    int ret = 0;
    check_args(argc, (const char **)argv, &should_return, &ret);
    if (should_return)
        return ret;

    ret = dispatch_cmd(argc, (const char **)argv);
    if (ret < 0) {
        std::cerr << "Unknown command: " << argv[1] << std::endl;
        print_usage();
        return EXIT_FAILURE;
    } else {
        return ret;
    }
}

namespace suskeymaster {

static int read_file(const char *path, hidl_vec<uint8_t>& out, const char *name);
static int write_file(const char *path, const hidl_vec<uint8_t>& in, const char *name);

static int read_and_deserialize_cert_chain(const char *path,
        hidl_vec<hidl_vec<uint8_t>>& cert_chain);
static int serialize_and_write_cert_chain(const char *path,
        const hidl_vec<hidl_vec<uint8_t>>& cert_chain);

static int handle_cmd_attest(const char *key_source, const char *key_spec);
static int handle_cmd_import(const char *algorithm_name,
        const char *in_private_pkcs8_path, const char *out_km_keyblob_path);
static int handle_cmd_export(const char *in_km_keyblob_path,
        const char *out_public_x509_path);
static int handle_cmd_sign(const char *in_km_keyblob_path,
        const char *in_message_path, const char *out_signature_path);
static int handle_cmd_generate(const char *algorithm_name,
        const char *out_km_keyblob_path);
static int handle_cmd_mkkeybox(const char *out,
        const char *cmdline1, const char *cmdline2);
static int scan_keybox_arg(const char *cmdline,
        std::vector<std::string>& out_cert_chain,
        std::string& out_key_path);
static int handle_cmd_dumpkeybox(const char *in_keybox_path,
        const char *out_dir_path);
static int handle_cmd_transact(const char *actor, const char *cmd,
        const char *arg1, const char *arg2, const char *arg3, const char *arg4, const char *arg5);

static int handle_cmd_transact_client_generate(const char *out_wrapping_keyblob_path,
        const char *out_wrapping_pubkey_path, const char *out_attestation_path);
static int handle_cmd_transact_server_verify(const char *in_attestation_path);
static int handle_cmd_transact_server_wrap(const char *in_private_pkcs8_path,
        const char *in_alg_str, const char *in_wrapping_key_path,
        const char *out_wrapped_data_path, const char *out_masking_key_path);
static int handle_cmd_transact_client_import(const char *in_wrapped_data_path,
        const char *in_masking_key_path, const char *in_wrapping_keyblob_path,
        const char *out_keyblob_path);

namespace cli {
    hidl_vec<uint8_t> const& get_sus_application_id(void)
    {
        /*
        static const hidl_vec<uint8_t> application_id = hidl_vec<uint8_t>(
                { 's', 'u', 's', 'k', 'e', 'y', 'm', 'a', 's', 't', 'e', 'r' }
        );
        */
        static const hidl_vec<uint8_t> application_id = {};

        return application_id;
    }
} /* namespace cli */

static int read_file(const char *path, hidl_vec<uint8_t>& out, const char *name)
{
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        std::cerr << "Failed to open " << name << " \"" << path << "\": "
            << errno << " (" << std::strerror(errno) << ")" << std::endl;
        return 1;
    }

    /* std::ios::ate tells ifstream to seek to the end */
    std::streamsize sz = file.tellg();

    file.seekg(0, std::ios::beg);
    if (file.fail()) {
        std::cerr << "Failed to set the position in " << name << " \"" << path
            << "\" to the beginning: " << errno << " (" << std::strerror(errno) << ")"
            << std::endl;
        return 1;
    }

    out.resize(sz);
    file.read(reinterpret_cast<char *>(out.data()), sz);
    if (file.fail()) {
        std::cerr << "Failed to read " << name << " \"" << path << "\" : "
            << errno << " (" << std::strerror(errno) << ")" << std::endl;
        return 1;
    }
    file.close();
    if (file.fail()) {
        std::cerr << "Failed to close " << name << " \"" << path << "\" : "
            << errno << " (" << std::strerror(errno) << ")" << std::endl;
        return 1;
    }

    std::cout << "Successfully read " << name << " \"" << path << "\"" << std::endl;
    return 0;
}

static int write_file(const char *path, const hidl_vec<uint8_t>& in, const char *name)
{
    std::ofstream file(path, std::ios::binary | std::ios::trunc);
    if (!file.is_open()) {
        std::cerr << "Failed to open " << name << " \"" << path << "\": "
            << errno << " (" << std::strerror(errno) << ")" << std::endl;
        return 1;
    }

    file.write(reinterpret_cast<const char *>(in.data()), in.size());
    if (file.fail()) {
        std::cerr << "Failed to write " << name << " \"" << path << "\" : "
            << errno << " (" << std::strerror(errno) << ")" << std::endl;
        return 1;
    }
    file.close();

    std::cout << "Successfully wrote " << name << " to \"" << path << "\"" << std::endl;
    return 0;
}

static int read_and_deserialize_cert_chain(const char *path,
        hidl_vec<hidl_vec<uint8_t>>& cert_chain)
{
    std::ifstream file(path, std::ios::binary);
    if (!file.is_open()) {
        std::cerr << "Failed to open attestation cert chain file \"" << path << "\": "
            << errno << " (" << std::strerror(errno) << ")" << std::endl;
        return 1;
    }

    uint32_t n_certs = 0;
    file.read(reinterpret_cast<char *>(&n_certs), sizeof(uint32_t));
    if (file.fail()) {
        std::cerr << "Failed to read the number of certs from \"" << path << "\" : "
            << errno << " (" << std::strerror(errno) << ")" << std::endl;
        return 1;
    }
    n_certs = ntohl(n_certs);
    if (n_certs > 100) {
        std::cerr << "Suspicious value of n_certs (" << n_certs <<
            ") in attestation cert chain file \"" << path << "\"" << std::endl;
        return 1;
    }

    std::cout << "Attestation: Number of certs: " << n_certs << std::endl;
    cert_chain.resize(n_certs);

    for (uint32_t i = 0; i < n_certs; i++) {
        uint32_t cert_size = 0;
        file.read(reinterpret_cast<char *>(&cert_size), sizeof(uint32_t));
        if (file.fail()) {
            std::cerr << "Failed to read the size of cert no. " << i << " from \"" << path <<
                "\" : " << errno << " (" << std::strerror(errno) << ")" << std::endl;
            return 1;
        }
        cert_size = ntohl(cert_size);
        if (cert_size > 100000) {
            std::cerr << "Suspicious size of cert no. " << i << " (" << cert_size <<
                ") in attestation cert chain file \"" << path << "\"" << std::endl;
            return 1;
        }
        std::cout << "Attestation: Cert [" << i << "]: " << cert_size << " bytes" << std::endl;

        cert_chain[i].resize(cert_size);
        file.read(reinterpret_cast<char *>(cert_chain[i].data()), cert_size);
        if (file.fail()) {
            std::cerr << "Failed to read cert no. " << i << " from \"" << path <<
                "\" : " << errno << " (" << std::strerror(errno) << ")" << std::endl;
            return 1;
        }
    }

    std::cout << "Successfully read attestation cert chain file \"" << path << "\"" << std::endl;
    return 0;
}

static int serialize_and_write_cert_chain(const char *path,
        const hidl_vec<hidl_vec<uint8_t>>& cert_chain)
{
    std::ofstream file(path, std::ios::binary | std::ios::trunc);
    if (!file.is_open()) {
        std::cerr << "Failed to open attestation cert chain file \"" << path << "\": "
            << errno << " (" << std::strerror(errno) << ")" << std::endl;
        return 1;
    }

    uint32_t be_n_certs = htonl(cert_chain.size());
    file.write(reinterpret_cast<const char *>(&be_n_certs), sizeof(uint32_t));
    if (file.fail()) {
        std::cerr << "Failed to write the number of certs to \"" << path << "\" : "
            << errno << " (" << std::strerror(errno) << ")" << std::endl;
        return 1;
    }

    for (uint32_t i = 0; i < cert_chain.size(); i++) {
        uint32_t cert_size = htonl(cert_chain[i].size());
        file.write(reinterpret_cast<const char *>(&cert_size), sizeof(uint32_t));
        if (file.fail()) {
            std::cerr << "Failed to write the size of cert no. " << i << " to \"" << path <<
                "\" : " << errno << " (" << std::strerror(errno) << ")" << std::endl;
            return 1;
        }

        file.write(reinterpret_cast<const char *>(cert_chain[i].data()), cert_chain[i].size());
        if (file.fail()) {
            std::cerr << "Failed to write cert no. " << i << " to \"" << path <<
                "\" : " << errno << " (" << std::strerror(errno) << ")" << std::endl;
            return 1;
        }
    }

    file.close();
    if (file.fail()) {
        std::cerr << "Failed to close attestation cert chain file \"" << path << "\" : "
            << errno << " (" << std::strerror(errno) << ")" << std::endl;
        return 1;
    }

    std::cout << "Successfully wrote attestation cert chain to \"" << path << "\"" << std::endl;
    return 0;
}

static int handle_cmd_attest(const char *key_source, const char *key_spec)
{
    hidl_vec<uint8_t> keyblob;

    if (!strcmp(key_source, "generated")) {
        Algorithm alg;
        if (!strcmp(key_spec, "ec")) {
            alg = Algorithm::EC;
        } else if (!strcmp(key_spec, "rsa")) {
            alg = Algorithm::RSA;
        } else {
            std::cerr << "Invalid key algorithm: " << key_spec << std::endl;
            print_usage();
            return EXIT_FAILURE;
        }

        if (cli::generate_key(g_hal, alg, keyblob)) {
            std::cerr << "Failed to generate an " << toString(alg) << " key" << std::endl;
            return EXIT_FAILURE;
        }
    } else if (!strcmp(key_source, "file")) {
        if (read_file(key_spec, keyblob, "keymaster key blob")) {
            std::cerr << "Failed to read the keymaster key blob!" << std::endl;
            return EXIT_FAILURE;
        }
    } else {
        std::cerr << "Invalid key source: " << key_source << std::endl;
        return EXIT_FAILURE;
    }

    return cli::attest_key(g_hal, keyblob);
}

static int handle_cmd_import(const char *algorithm_name,
        const char *in_private_pkcs8_path, const char *out_km_keyblob_path)
{
    Algorithm alg;
    hidl_vec<uint8_t> priv_key_pkcs8;
    hidl_vec<uint8_t> out_key_blob;

    if (!strcmp(algorithm_name, "ec"))
        alg = Algorithm::EC;
    else if (!strcmp(algorithm_name, "rsa"))
        alg = Algorithm::RSA;
    else {
        std::cerr << "Unsupported key algorithm: " << algorithm_name << std::endl;
        return EXIT_FAILURE;
    }

    if (read_file(in_private_pkcs8_path, priv_key_pkcs8, "PKCS8 private key file")) {
        std::cerr << "Failed to read the PKCS8 private key file!" << std::endl;
        return EXIT_FAILURE;
    }

    if (cli::import_key(g_hal, priv_key_pkcs8, alg, out_key_blob)) {
        std::cerr << "Couldn't import private key!" << std::endl;
        return EXIT_FAILURE;
    }

    if (write_file(out_km_keyblob_path, out_key_blob, "keymaster key blob")) {
        std::cerr << "Failed to write the keymaster key blob!" << std::endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

static int handle_cmd_export(const char *in_km_keyblob_path,
        const char *out_public_x509_path)
{
    hidl_vec<uint8_t> key_blob;
    hidl_vec<uint8_t> out_pubkey_x509;

    if (read_file(in_km_keyblob_path, key_blob, "keymaster key blob")) {
        std::cerr << "Failed to read the keymaster key blob!" << std::endl;
        return EXIT_FAILURE;
    }

    if (cli::export_key(g_hal, key_blob, out_pubkey_x509)) {
        std::cerr << "Couldn't export keymaster key!" << std::endl;
        return EXIT_FAILURE;
    }

    if (write_file(out_public_x509_path, out_pubkey_x509, "X.509 public key")) {
        std::cerr << "Failed to write the X.509 public key!" << std::endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

static int handle_cmd_sign(const char *in_km_keyblob_path,
        const char *in_message_path, const char *out_signature_path)
{
    hidl_vec<uint8_t> keyblob;
    hidl_vec<uint8_t> message;
    hidl_vec<uint8_t> signature;

    if (read_file(in_message_path, message, "message file")) {
        std::cerr << "Failed to read the message!" << std::endl;
        return EXIT_FAILURE;
    }
    if (read_file(in_km_keyblob_path, keyblob, "keymaster key blob")) {
        std::cerr << "Failed to read the keymaster key blob!" << std::endl;
        return EXIT_FAILURE;
    }

    if (cli::sign(g_hal, message, keyblob, signature)) {
        std::cerr << "Signing operation failed!" << std::endl;
        return EXIT_FAILURE;
    }

    if (write_file(out_signature_path, signature, "signature file")) {
        std::cerr << "Failed to write the signature!" << std::endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

static int handle_cmd_generate(const char *algorithm_name,
        const char *out_km_keyblob_path)
{
    Algorithm alg;
    hidl_vec<uint8_t> keyblob;

    if (!strcasecmp(algorithm_name, "ec"))
        alg = Algorithm::EC;
    else if (!strcasecmp(algorithm_name, "rsa"))
        alg = Algorithm::RSA;
    else {
        std::cerr << "Unsupported key algorithm: " << algorithm_name << std::endl;
        return EXIT_FAILURE;
    }

    if (cli::generate_key(g_hal, alg, keyblob)) {
        std::cerr << "Failed to generate key!" << std::endl;
        return EXIT_FAILURE;
    }

    if (write_file(out_km_keyblob_path, keyblob, "new KeyMaster key blob")) {
        std::cerr << "Failed to write the new KeyMaster key blob!" << std::endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

static int handle_cmd_mkkeybox(const char *out,
        const char *cmdline1, const char *cmdline2)
{
    const char *ec_cmdline = NULL, *rsa_cmdline = NULL;

    if (!strncasecmp(cmdline1, "ec ", sizeof("ec ") - 1))
        ec_cmdline = cmdline1;
    else if (!strncasecmp(cmdline2, "ec ", sizeof("ec ") - 1))
        ec_cmdline = cmdline2;

    if (!strncasecmp(cmdline1, "rsa ", sizeof("rsa ") - 1))
        rsa_cmdline = cmdline1;
    else if (!strncasecmp(cmdline2, "rsa ", sizeof("rsa ") - 1))
        rsa_cmdline = cmdline2;

    if (rsa_cmdline == NULL || ec_cmdline == NULL) {
        std::cerr << "keybox: Missing EC or RSA command line" << std::endl;
        print_usage();
        return 1;
    }

    ec_cmdline += sizeof("ec ") - 1;
    rsa_cmdline += sizeof("rsa ") - 1;

    std::vector<std::string> ec_cert_paths;
    std::string ec_key_path;
    if (scan_keybox_arg(ec_cmdline, ec_cert_paths, ec_key_path)) {
        std::cerr << "keybox: Invalid EC command line" << std::endl;
        return 1;
    }

    std::vector<std::string> rsa_cert_paths;
    std::string rsa_key_path;
    if (scan_keybox_arg(rsa_cmdline, rsa_cert_paths, rsa_key_path)) {
        std::cerr << "keybox: Invalid RSA command line" << std::endl;
        return 1;
    }

    return cli::keybox::make_kb(ec_cert_paths, ec_key_path,
            rsa_cert_paths, rsa_key_path,
            std::string(out)
    );
}

static int handle_cmd_dumpkeybox(const char *in_keybox_path,
        const char *out_dir_path)
{
    return cli::keybox::dump_kb(in_keybox_path, out_dir_path);
}

static int handle_cmd_transact(const char *actor, const char *cmd,
        const char *arg1, const char *arg2, const char *arg3, const char *arg4, const char *arg5)
{
    (void) arg4;

    if (!strcmp(actor, "client") && !strcmp(cmd, "generate")) {
        if (init_g_hal())
            return EXIT_FAILURE;

        const char *const out_keyblob_path = arg1;
        const char *const out_pubkey_path = arg2;
        const char *const out_attestation_path = arg3;

        if (out_keyblob_path == NULL || out_pubkey_path == NULL) {
            print_not_enough_args_for_cmd("transact client generate");
            return 1;
        }

        return handle_cmd_transact_client_generate(out_keyblob_path,
                out_pubkey_path, out_attestation_path);
    } else if (!strcmp(actor, "server") && !strcmp(cmd, "verify")) {
        const char *const in_attestation_path = arg1;

        if (in_attestation_path == NULL) {
            print_not_enough_args_for_cmd("transact server verify");
            return 1;
        }

        return handle_cmd_transact_server_verify(in_attestation_path);

    } else if (!strcmp(actor, "server") && !strcmp(cmd, "wrap")) {
        const char *const in_private_pkcs8_path = arg1;
        const char *const in_alg_str = arg2;
        const char *const in_wrapping_key_path = arg3;
        const char *const out_wrapped_data_path = arg4;
        const char *const out_masking_key_path = arg5;

        if (in_private_pkcs8_path == NULL || in_alg_str == NULL ||
                in_wrapping_key_path == NULL || out_wrapped_data_path == NULL ||
                out_masking_key_path == NULL)
        {
            print_not_enough_args_for_cmd("transact server wrap");
            return 1;
        }

        return handle_cmd_transact_server_wrap(in_private_pkcs8_path, in_alg_str,
                in_wrapping_key_path, out_wrapped_data_path, out_masking_key_path);

    } else if (!strcmp(actor, "client") && !strcmp(cmd, "import")) {
        if (init_g_hal())
            return EXIT_FAILURE;

        const char *const in_wrapped_data_path = arg1;
        const char *const in_masking_key_path = arg2;
        const char *const in_wrapping_keyblob_path = arg3;
        const char *const out_keyblob_path = arg4;

        if (in_wrapped_data_path == NULL || in_masking_key_path == NULL ||
                in_wrapping_keyblob_path == NULL || out_keyblob_path == NULL)
        {
            print_not_enough_args_for_cmd("transact client import");
            return 1;
        }

        return handle_cmd_transact_client_import(in_wrapped_data_path, in_masking_key_path,
                in_wrapping_keyblob_path, out_keyblob_path);
    }

    std::cerr << "transact: Invalid actor \"" << actor <<
        "\" and/or command \"" << cmd << "\"" << std::endl;
    print_usage();
    return 1;
}

static int handle_cmd_transact_client_generate(const char *out_wrapping_keyblob_path,
        const char *out_wrapping_pubkey_path, const char *out_attestation_path)
{
    hidl_vec<uint8_t> out_keyblob;
    hidl_vec<uint8_t> out_pubkey;
    hidl_vec<hidl_vec<uint8_t>> out_attestation;
    int r = cli::transact::client::generate_and_attest_wrapping_key(
            g_hal, out_keyblob, out_pubkey,
            (out_attestation_path != NULL) ? &out_attestation : NULL
    );
    if (r) {
        std::cerr << "Failed to generate and/or attest the transact wrapping key" << std::endl;
        return 1;
    }

    if (write_file(out_wrapping_keyblob_path, out_keyblob, "transact wrapping key blob")) {
        std::cerr << "Failed to write the transact wrapping key blob!" << std::endl;
        return 1;
    }
    if (write_file(out_wrapping_pubkey_path, out_pubkey, "transact wrapping public key")) {
        std::cerr << "Failed to write the transact wrapping public key!" << std::endl;
        return 1;
    }

    if (out_attestation_path != NULL) {
        if (serialize_and_write_cert_chain(out_attestation_path, out_attestation)) {
            std::cerr << "Failed to serialize & write the attestation cert chain!"
                << std::endl;
            return 1;
        }
    }

    std::cout << "Successfully generated the transact wrapping key" << std::endl;
    return 0;
}

static int handle_cmd_transact_server_verify(const char *in_attestation_path)
{
    hidl_vec<hidl_vec<uint8_t>> attestation;
    if (read_and_deserialize_cert_chain(in_attestation_path, attestation)) {
        std::cerr << "Failed to read & deserialize the attestation cert chain" << std::endl;
        return 1;
    }

    return cli::transact::server::verify_attestation(attestation);
}


static int handle_cmd_transact_server_wrap(const char *in_private_pkcs8_path,
        const char *in_alg_str, const char *in_wrapping_key_path,
        const char *out_wrapped_data_path, const char *out_masking_key_path)
{
    enum util::sus_key_variant variant;
    if (!strcasecmp(in_alg_str, "ec"))
        variant = util::SUS_KEY_EC;
    else if (!strcasecmp(in_alg_str, "rsa"))
        variant = util::SUS_KEY_RSA;
    else {
        std::cerr << "Invalid algorithm name: " << in_alg_str << std::endl;
        return 1;
    }

    hidl_vec<uint8_t> in_private_pkcs8;
    hidl_vec<uint8_t> in_wrapping_key;
    if (read_file(in_private_pkcs8_path, in_private_pkcs8, "private key PKCS8")) {
        std::cerr << "Failed to read the private key file" << std::endl;
        return 1;
    }
    if (read_file(in_wrapping_key_path, in_wrapping_key, "wrapping key X.509")) {
        std::cerr << "Failed to read the wrapping key file" << std::endl;
        return 1;
    }

    hidl_vec<uint8_t> out_wrapped_data;
    hidl_vec<uint8_t> out_masking_key;

    if (cli::transact::server::wrap_key(in_private_pkcs8, variant,
            in_wrapping_key, out_wrapped_data, out_masking_key))
    {
        std::cerr << "Failed to wrap the private key for transact" << std::endl;
        return 1;
    }

    if (write_file(out_wrapped_data_path, out_wrapped_data, "wrapped key data")) {
        std::cerr << "Failed to write the wrapped key data" << std::endl;
        return 1;
    }
    if (write_file(out_masking_key_path, out_masking_key, "masking key")) {
        std::cerr << "Failed to write the masking key" << std::endl;
        return 1;
    }

    return 0;
}

static int handle_cmd_transact_client_import(const char *in_wrapped_data_path,
        const char *in_masking_key_path, const char *in_wrapping_keyblob_path,
        const char *out_keyblob_path)
{
    hidl_vec<uint8_t> in_wrapped_data;
    hidl_vec<uint8_t> in_masking_key;
    hidl_vec<uint8_t> in_wrapping_keyblob;
    if (read_file(in_wrapped_data_path, in_wrapped_data, "wrapped key data")) {
        std::cerr << "Failed to read the wrapped key data" << std::endl;
        return 1;
    }
    if (read_file(in_masking_key_path, in_masking_key, "masking key")) {
        std::cerr << "Failed to read the masking key" << std::endl;
        return 1;
    }
    if (read_file(in_wrapping_keyblob_path, in_wrapping_keyblob, "wrapping key blob")) {
        std::cerr << "Failed to read the wrapping key blob" << std::endl;
        return 1;
    }

    hidl_vec<uint8_t> out_keyblob;
    if (cli::transact::client::import_wrapped_key(g_hal, in_wrapped_data,
                in_masking_key, in_wrapping_keyblob, out_keyblob))
    {
        std::cerr << "Failed to securely import wrapped key blob" << std::endl;
        return 1;
    }

    if (write_file(out_keyblob_path, out_keyblob, "securely imported key blob")) {
        std::cerr << "Failed to write the securely imported key blob" << std::endl;
        return 1;
    }

    std::cout << "Successfully performed secure transact & import of private key!" << std::endl;
    return 0;
}

static int scan_keybox_arg(const char *cmdline,
        std::vector<std::string>& out_cert_chain,
        std::string& out_key_path)
{
    std::istringstream iss(cmdline);
    uint32_t n_certs;

    iss >> n_certs;
    if (iss.fail()) {
        std::cerr << "Couldn't get number of certs from cmdline" << std::endl;
        return 1;
    }

    out_cert_chain.clear();
    out_cert_chain.reserve(n_certs);
    for (uint32_t i = 0; i < n_certs; i++) {
        std::string curr_path;
        iss >> std::quoted(curr_path);
        if (iss.fail()) {
            std::cerr << "Failed to parse cert path no. " << i << std::endl;
            return 1;
        }

        out_cert_chain.push_back(curr_path);
    }

    std::string key_path;
    iss >> std::quoted(key_path);
    if (iss.fail()) {
        std::cerr << "Couldn't parse the wrapped key file path" << std::endl;
        return 1;
    }

    out_key_path = key_path;

    iss >> std::ws;
    if (!iss.eof()) {
        std::cerr << "Trailing characters at the end of cmdline" << std::endl;
        return 1;
    }

    return 0;
}

} /* namespace suskeymaster */

using namespace suskeymaster;

static void setup_cgd_log(void)
{
    struct s_log_output_cfg s_log_cfg;
    s_log_cfg.type = s_log_output_cfg::S_LOG_OUTPUT_FILE;
    s_log_cfg.out.file = stdout;
    s_log_cfg.flags = static_cast<s_log_output_cfg::s_log_config_flags>(
        s_log_output_cfg::s_log_config_flags::S_LOG_CONFIG_FLAG_APPEND |
        s_log_output_cfg::s_log_config_flags::S_LOG_CONFIG_FLAG_COPY
    );
    (void) s_configure_log_outputs(S_LOG_STDOUT_MASKS, &s_log_cfg);
    s_log_cfg.out.file = stderr;
    (void) s_configure_log_outputs(S_LOG_STDERR_MASKS, &s_log_cfg);
}

static void check_args(int argc, const char **argv,
        bool *o_should_return, int *o_return_val)
{
    *o_should_return = false;
    *o_return_val = EXIT_SUCCESS;

    if (argc < 2) {
        std::cerr << "Not enough arguments!" << std::endl;
        print_usage();
        *o_should_return = true;
        *o_return_val = EXIT_FAILURE;
        return;
    }

    if (!strcmp(argv[1], "help")) {
        print_usage();
        *o_should_return = true;
        *o_return_val = EXIT_SUCCESS;
        return;
    }
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
            print_usage();
            *o_should_return = true;
            *o_return_val = EXIT_SUCCESS;
            return;
        }
    }
}

static int dispatch_cmd(int argc, const char **argv)
{
    const char *const cmd = argv[1];

    if (!strcmp(cmd, "attest")) {
        if (argc < 4) {
            print_not_enough_args_for_cmd(cmd);
            return EXIT_FAILURE;
        }
        if (init_g_hal())
            return EXIT_FAILURE;

        const char *const key_source = argv[2];
        const char *const key_spec = argv[3];
        return handle_cmd_attest(key_source, key_spec);

    } else if (!strcmp(cmd, "import")) {
        if (argc < 5) {
            print_not_enough_args_for_cmd(cmd);
            return EXIT_FAILURE;
        }
        if (init_g_hal())
            return EXIT_FAILURE;

        const char *const alg_name = argv[2];
        const char *const in_priv_pkcs8_path = argv[3];
        const char *const out_km_keyblob_path = argv[4];
        return handle_cmd_import(alg_name, in_priv_pkcs8_path, out_km_keyblob_path);

    } else if (!strcmp(cmd, "export")) {
        if (argc < 4) {
            print_not_enough_args_for_cmd(cmd);
            return EXIT_FAILURE;
        }
        if (init_g_hal())
            return EXIT_FAILURE;

        const char *const in_keyblob_path = argv[2];
        const char *const out_pubkey_x509_path = argv[3];
        return handle_cmd_export(in_keyblob_path, out_pubkey_x509_path);

    } else if (!strcmp(cmd, "sign")) {
        if (argc < 5) {
            print_not_enough_args_for_cmd(cmd);
            return EXIT_FAILURE;
        }
        if (init_g_hal())
            return EXIT_FAILURE;

        const char *const in_km_keyblob_path = argv[2];
        const char *const in_message_path = argv[3];
        const char *const out_signature_path = argv[4];
        return handle_cmd_sign(in_km_keyblob_path, in_message_path, out_signature_path);

    } else if (!strcmp(cmd, "generate")) {
        if (argc < 4) {
            print_not_enough_args_for_cmd(cmd);
            return EXIT_FAILURE;
        }
        if (init_g_hal())
            return EXIT_FAILURE;

        const char *const alg_name = argv[2];
        const char *const out_km_keyblob_path = argv[3];
        return handle_cmd_generate(alg_name, out_km_keyblob_path);
    } else if (!strcmp(cmd, "mkkeybox")) {
        if (argc < 5) {
            print_not_enough_args_for_cmd(cmd);
            return EXIT_FAILURE;
        }

        const char *const out = argv[2];
        const char *const cmdline1 = argv[3];
        const char *const cmdline2 = argv[4];
        return handle_cmd_mkkeybox(out, cmdline1, cmdline2);
    } else if (!strcmp(cmd, "dumpkeybox")) {
        if (argc < 4) {
            print_not_enough_args_for_cmd(cmd);
            return EXIT_FAILURE;
        }

        const char *const in_keybox_path = argv[2];
        const char *const out_dir_path = argv[3];
        return handle_cmd_dumpkeybox(in_keybox_path, out_dir_path);
    } else if (!strcmp(cmd, "transact")) {
        if (argc < 4) {
            print_not_enough_args_for_cmd(cmd);
            return EXIT_FAILURE;
        }

        const char *const actor = argv[2];
        const char *const subcmd = argv[3];
        const char *const arg1 = argc >= 5 ? argv[4] : NULL;
        const char *const arg2 = argc >= 6 ? argv[5] : NULL;
        const char *const arg3 = argc >= 7 ? argv[6] : NULL;
        const char *const arg4 = argc >= 8 ? argv[7] : NULL;
        const char *const arg5 = argc >= 9 ? argv[8] : NULL;

        return handle_cmd_transact(actor, subcmd, arg1, arg2, arg3, arg4, arg5);
    } else {
        return -1;
    }
}

static int init_g_hal(void)
{
    g_hal = ::android::hardware::keymaster::V4_0::IKeymasterDevice::tryGetService();
    if (g_hal == nullptr || !g_hal->ping().isOk()) {
        std::cerr << "Couldn't obtain handle to KeyMaster HAL service" << std::endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

static void print_usage()
{
    const char *progname = g_argv0 ? g_argv0 : "suskeymaster";

    std::cout << "Usage: " << progname << " <command> <args...>\n"
        "Available commands:\n"
        "   generate <algorithm> <out_key_blob>\n"
        "       Generate a new keypair in KeyMaster and save the resulting key blob"
            "to <out_key_blob>\n"
        "\n"
        "   attest <key_source> <key_spec>\n"
        "       Generate a KeyMaster attestation for a given key\n"
        "       <key_source> can be either \"generated\" or \"file\"\n"
        "       If <key_source> is \"generated\", then <key_spec> must be:\n"
        "           \"ec\" for an ECDSA key\n"
        "           \"rsa\" for an RSA key\n"
        "       If <key_source> is \"file\", then <key_spec> must be "
                "the path to a keymaster key blob file.\n"
        "\n"
        "   import <in_private_pkcs8> <algorithm> <out_key_blob>\n"
        "       Imports a PKCS#8 DER-encoded ECDSA or RSA private key <in_private_pkcs8> "
                "into the device's keymaster, writing the resulting key blob to <out_key_blob>.\n"
        "       <algorithm> must be either \"ec\" or \"rsa\", "
                "in accordance to the content of <in_private_pkcs8>.\n"
        "\n"
        "   export <in_keyblob> <out_public_x509>\n"
        "       Exports the given keymaster key blob <in_keyblob>'s public key "
                "to a DER-encoded X.509 certificate <out_public_x509>\n"
        "\n"
        "   sign <in_keyblob> <in_message> <out_signature>\n"
        "       Signs <in_message> with <in_keyblob>, saving the signature to <out_signature>\n"
        "\n"
        "   mkkeybox <out_keybox> <cmdline1> <cmdline2>\n"
        "       Creates a new suskeymaster binary keybox file <out_keybox> "
                "from the two command lines (for EC and RSA).\n"
        "       The command lines have the following format:\n"
        "           <alg> <n_certs> <cert_1> ... <cert_n> <wrapped_key>\n"
        "       Where:\n"
        "           <alg> must be either \"ec\" or \"rsa\", depening on which key type "
                    "the given command line corresponds to.\n"
        "           <n_certs> is the number of certificates in the keybox\n"
        "           <cert_1> ... <cert_n> are the file paths of the individual DER-encoded "
                    "X.509 certificate files. They may be quoted if they contain spaces.\n"
        "           <wrapped_key> is the file path of the wrapped keymaster key blob "
                    "which contains the private leaf cert signing key of the given keybox\n"
        "       Note: The command lines have to be supplied in quotes if written in a shell.\n"
        "\n"
        "   dumpkeybox <in_keybox> <out_dir_path>\n"
        "       Dumps the suskeymaster binary keybox file <in_keybox> "
                "to the directory <out_dir_path>\n"
        "       Note: The directory <out_dir_path> must already exist\n"
        "\n"
        "   transact client generate <out_keyblob> <out_pubkey> [out_attestation]\n"
        "       Generates the wrapping key for a secure import transaction, "
                "writing the resulting keyblob to <out_keyblob> and exports the public part"
                "to a DER-encoded X.509 certificate <out_pubkey>.\n"
        "       Optionally also generates an attestation certificate chain for the wrapping key, "
                "writing it to <out_attestation>\n"
        "\n"
        "   transact server verify <attestation>\n"
        "       Verifies the KeyMaster attestation certificate chain <attestation>\n"
        "\n"
        "   transact server wrap <in_private_key> <algorithm> <wrapping_key> <out_wrapped_data>\n"
        "       Wraps the DER-encoded PKCS#8 private key <in_private_key> "
                "for a secure import transaction.\n"
        "       <algorithm> must be either \"ec\" or \"rsa\", "
                "depending on the content of <in_private_key>.\n"
        "       <wrapping_key> is the DER-encoded X.509 public wrapping key "
                "received from the client.\n"
        "       <out_wrapped_data> is the path to the file to which the wrapped data "
                "(which is supposed to be sent to the client) will be written.\n"
        "       <out_masking_key> is the path to the file to which "
                "the ephemeral masking key will be written\n"
        "\n"
        "   transact client import <in_wrapped_data> <in_masking_key> "
            "<in_wrapping_keyblob> <out_keyblob>\n"
        "       Performs the secure import of <in_wrapped_data> (masked with `<in_masking_key>`) "
                "using <in_wrapping_keyblob>.\n"
        "       This finalizes the secure import transaction, "
        "and the resulting keyblob is written to <out_keyblob>.\n"
        "\n"
        "\n"
        "Examples:\n"
        "   To generate an ECDSA key and attest it:\n"
        "   $ " << progname << " attest generated ec\n"
        "\n"
        "   To import an RSA private key:\n"
        "   $ " << progname << " import rsa rsa-private-pkcs8.der keyblob-rsa.bin\n"
        "\n"
        "   To generate and save an ECDSA KeyMaster key:\n"
        "   $ " << progname << " generate ec keyblob-ec.bin\n"
        "\n"
        "   To export the public part of an EC key:\n"
        "   $ " << progname << " export keyblob-ec.bin pubkey.x509\n"
        "\n"
        "   To sign a message with a KeyMaster key:\n"
        "   $ " << progname << " sign keyblob.bin message.txt signature.bin\n"
        "\n"
        "   To generate a binary suskeymaster keybox file from certificates and key blobs:\n"
        "   $ " << progname << " mkkeybox keybox.bin \\\n"
        "       'ec 3 cert1-ec.der cert2-ec.der cert3-ec.der key-ec.bin' \\\n"
        "       'rsa 3 cert1-rsa.der cert2-rsa.der cert3-rsa.der key-rsa.der'\n"
        "\n"
        "   To dump a binary keybox file to the current working directory:\n"
        "   $ " << progname << " dumpkeybox keybox.bin .\n"
        "\n"
        "   To securely provision an EC key from a server to the KeyMaster of the client:\n"
        "   (client) $ " << progname << " transact client generate "
                                        "wrapping-key.bin wrapping-pub.x509 attestation.bin\n"
        "   (server) $ " << progname << " transact server verify attestation.bin\n"
        "   (server) $ " << progname << " transact server wrap private-ec-key-pkcs8.der ec "
                                        "wrapping-pub.x509 wrapped-data.bin\n"
        "   (client) $ " << progname << " transact client import "
                                        "wrapped-data.bin wrapping-key.bin keyblob-ec.bin\n"
        "\n"
        << std::endl;
}

static void print_not_enough_args_for_cmd(const char *cmd)
{
    std::cerr << "Not enough arguments for command \"" << cmd << "\"" << std::endl;
    print_usage();
}
