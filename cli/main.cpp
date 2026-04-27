#define HIDL_DISABLE_INSTRUMENTATION
#include "cli.hpp"
#include <core/log.h>
#include <libsuscertmod/certmod.h>
#include <libsuskmhal/hidl/hidl-hal.hpp>
#include <libsuskmhal/util/km-params.hpp>
#include <android/hardware/keymaster/generic/types.h>
#include <strings.h>
#include <cstdio>
#include <string>
#include <cerrno>
#include <vector>
#include <memory>
#include <iomanip>
#include <sstream>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <ostream>
#include <iostream>
#include <charconv>
#include <system_error>
#include <unordered_map>

using namespace ::android::hardware::keymaster::generic;
using namespace ::android::hardware;
using namespace suskeymaster;

static const char *g_argv0 = NULL;

namespace suskeymaster {

static std::unique_ptr<kmhal::hidl::HidlSusKeymaster> g_hal = nullptr;

enum hal_version : uint8_t {
    HAL_NOT_NEEDED = 0x00,
    HAL_NONE = 0x00,

    HAL_NEEDED_3_0 = 0x30,
    HAL_3_0 = 0x30,

    HAL_NEEDED_4_0 = 0x40,
    HAL_4_0 = 0x40,

    HAL_NEEDED_4_1 = 0x41,
    HAL_4_1 = 0x41
};
static constexpr int hal_version_major(hal_version ver) {
    return (static_cast<uint8_t>(ver) & 0xF0) >> 4;
}
static constexpr int hal_version_minor(hal_version ver) {
    return (static_cast<uint8_t>(ver) & 0x0F);
}

enum cli_arg_type {
    INPUT_FILE,
    OUTPUT_FILE,
    KEY_PARAMETERS,
    INPUT_STRING,
};
enum cli_arg_mandatory {
    OPTIONAL,
    MANDATORY,
};
struct cli_arg {
    const char *name;
    cli_arg_type type;
    cli_arg_mandatory mandatory = MANDATORY;
    const char *description;
};

struct cli_arg_value {
private:
    hidl_vec<uint8_t> bytes;
    hidl_vec<KeyParameter> key_params;

    /* also used with cli_arg_type::OUTPUT_FILE as the output file path */
    std::string str;
    bool is_out_file_ = false;

public:

    cli_arg_value() { }

    /* For cli_arg_type::INPUT_FILE */
    cli_arg_value(hidl_vec<uint8_t>&& b) {
        bytes = std::move(b);
    }

    /* For cli_arg_type::OUTPUT_FILE and cli_arg_type::INPUT_STRING */
    cli_arg_value(std::string const& s, bool is_out_file) {
        str = s;
        this->is_out_file_ = is_out_file;
    }

    /* For cli_arg_type::KEY_PARAMETERS */
    cli_arg_value(hidl_vec<KeyParameter>&& kp) {
        key_params = std::move(kp);
    }

    const hidl_vec<uint8_t>& in_bytes(void) const {
        return bytes;
    }
    const hidl_vec<KeyParameter>& in_key_params(void) const {
        return key_params;
    }
    const std::string& in_string(void) const {
        return str;
    }

    hidl_vec<uint8_t>& out_bytes(void) {
        return bytes;
    }
    const std::string& out_string(void) const {
        return str;
    }

    bool is_out_file(void) const {
        return is_out_file_;
    }
    void disable_out_file(void) {
        this->is_out_file_ = false;
    }
};

typedef std::unordered_map<std::string, cli_arg_value> arg_map_t;

struct cli_command {
    std::vector<const char *> argv_match;
    std::vector<const char *> description;

    hal_version required_hal_version;
    std::vector<cli_arg> args;

    int (*handler)(arg_map_t& args);
};

static void setup_cgd_log(void);

static void check_print_help(int argc, const char **argv,
        bool *o_should_return, int *o_return_val);

static int init_g_hal(hal_version min_ver);

static int read_file(const std::string& path, const std::string& param_name,
        hidl_vec<uint8_t>& out);
static int write_file(const std::string& path, const std::string& param_name,
        const hidl_vec<uint8_t>& in);

static int read_and_deserialize_cert_chain(const std::string& path,
        hidl_vec<hidl_vec<uint8_t>>& cert_chain);
#ifndef SUSKEYMASTER_BUILD_HOST
static int serialize_and_write_cert_chain(const std::string& path,
        const hidl_vec<hidl_vec<uint8_t>>& cert_chain);
#endif /* SUSKEYMASTER_BUILD_HOST */

static int scan_keybox_arg(const char *cmdline,
        std::vector<std::string>& out_cert_chain,
        std::string& out_key_path);

#ifdef SUSKEYMASTER_ENABLE_SAMSUNG_SEND_INDATA
static int scan_indata_arg(const char *cmdline, uint32_t *& out_cmd,
        uint32_t *& out_ver, uint32_t *& out_km_ver, uint32_t *& out_pid,
        uint32_t *& out_int0, uint64_t *& out_long0, uint64_t *& out_long1,
        hidl_vec<uint8_t> *& out_bin0, hidl_vec<uint8_t> *& out_bin1,
        hidl_vec<uint8_t> *& out_bin2, hidl_vec<uint8_t> *& out_key,
        hidl_vec<KeyParameter> *& out_par);
#endif /* SUSKEYMASTER_ENABLE_SAMSUNG_SEND_INDATA */

static void print_generic_usage(void);

static const cli_command * match_command(int argc, const char **argv, int& out_n_consumed);

static void print_cmd_usage(const cli_command& c);
static int match_and_run_handler(int argc, const char **argv);

} /* namespace suskeymaster */

namespace _ {
    static uint32_t ntohl_(uint32_t);
#ifndef SUSKEYMASTER_BUILD_HOST
    static uint32_t htonl_(uint32_t);
#endif /* SUSKEYMASTER_BUILD_HOST */
};

int main(int argc, char **argv)
{
    using namespace suskeymaster;

    g_argv0 = argv[0];
    setup_cgd_log();

    bool should_return = false;
    int ret = 0;
    check_print_help(argc, (const char **)argv, &should_return, &ret);
    if (should_return)
        return ret;

    return match_and_run_handler(argc, (const char **)argv);
}

namespace suskeymaster {

static const std::vector<cli_command> cmds = {
{
    { "__line_break__" }, {}, HAL_NOT_NEEDED, {}, {}
},
#ifndef SUSKEYMASTER_BUILD_HOST
{
    { "get-characteristics" },
    {
        "Print the characteristics (properties) of <key_blob>.",
    },
    HAL_NEEDED_3_0,
    {
        { "key_blob", INPUT_FILE, MANDATORY,
            "The key blob whose characteristics are to be read"
        },
        { "deserialization_params", KEY_PARAMETERS, OPTIONAL,
            "Key parameters containing the `APPLICATION_ID` and/or `APPLICATION_DATA` "
                "required to use the key. Any other tags are ignored."
        }
    },
    [](arg_map_t& a) {
        return cli::hal_ops::get_key_characteristics(*g_hal,
                a["key_blob"].in_bytes(),
                a["deserialization_params"].in_key_params()
        );
    }
},
{
    { "generate" },
    {
        "Generate a new key in KeyMaster using <params> "
        "and save the resulting key blob to <out_key_blob>"
    },
    HAL_NEEDED_3_0,
    {
        { "params", KEY_PARAMETERS, MANDATORY,
            "Key generation parameters, such as ALGORITHM and PURPOSE"
        },
        { "out_key_blob", OUTPUT_FILE, MANDATORY,
            "The file to which the keymaster keyblob will be written"
        },
    },
    [](arg_map_t& a) {
        return cli::hal_ops::generate_key(*g_hal,
                a["params"].in_key_params(), a["out_key_blob"].out_bytes());
    }
},
{
    { "attest", "generated" },
    {
        "Generate a temporary key (with the optional [generate_params])",
        "   and attest it (optionally using [attest_params]),",
        "   also optionally saving it to [out_attestation].",
    },
    HAL_NEEDED_3_0,
    {
        { "generate_params", KEY_PARAMETERS, OPTIONAL,
            "A space-separated list of key parameters used to generate the ephemeral attested key"
        },
        { "attest_params", KEY_PARAMETERS, OPTIONAL,
            "A space-separated list of key parameters "
                "passed in as `attestParams` to the `attestKey` call"
        },
        { "attestation", OUTPUT_FILE, OPTIONAL,
            "The file to which the serialized attestation certificate chain will be written"
        },
    },
    [](arg_map_t& a) {
        hidl_vec<uint8_t> keyblob;
        if (cli::hal_ops::generate_key(*g_hal, a["generate_params"].in_key_params(), keyblob)) {
            std::cerr << "Failed to generate ephemeral attested key!" << std::endl;
            return 1;
        }

        return cli::hal_ops::attest_key(*g_hal, keyblob, a["attest_params"].in_key_params());
    }
},
{
    { "attest", "file" },
    {
        "Attest <keyblob> (optionally using [attest_params])",
        "   optionally saving the resulting serialized attestation cert chain "
            "to [out_attestation]"
    },
    HAL_NEEDED_3_0,
    {
        { "keyblob", INPUT_FILE, MANDATORY,
            "The KeyMaster key blob to attest"
        },
        { "attest params", KEY_PARAMETERS, OPTIONAL,
            "A space-separated list of key parameters "
                "passed in as `attestParams` to the `attestKey` call"
        },
        { "attestation", OUTPUT_FILE, OPTIONAL,
            "The file to which the serialized attestation certificate chain will be written"
        },
    },
    [](arg_map_t& a) {
        const hidl_vec<uint8_t>& keyblob = a["keyblob"].in_bytes();
        const hidl_vec<KeyParameter>& params = a["attest params"].in_key_params();

        return cli::hal_ops::attest_key(*g_hal, keyblob, params);
    }
},
{
    { "import" },
    {
        "Imports the private key <in_private_key>",
        "   into the device's KeyMaster, writing the resulting key blob to <out_key_blob>."
    },
    HAL_NEEDED_3_0,
    {
        { "in_private_key", INPUT_FILE, MANDATORY,
            "The private key to import - "
                "DER-encoded PKCS#8 for asymmetric keys and raw bytes otherwise"
        },
        { "in_key_blob", OUTPUT_FILE, MANDATORY,
            "The file to which the imported key blob will be written"
        },
        { "params", KEY_PARAMETERS, OPTIONAL,
            "A space-separated list of key parameters that the imported key blob should have"
        },
    },
    [](arg_map_t& a) {
        return cli::hal_ops::import_key(*g_hal, a["in_private_key"].in_bytes(),
                a["params"].in_key_params(), a["in_key_blob"].out_bytes());
    }
},
{
    { "export" },
    {
        "Exports the given keymaster key blob <in_keyblob> to <out_exported>.",
        "For asymmetric keys, a DER-encoded X.509 certificate containing "
            "the public part of the key is exported",
        "while for other algorithms raw bytes are written."
    },
    HAL_NEEDED_3_0,
    {
        { "in_keyblob", INPUT_FILE, MANDATORY,
            "The key blob whose public key is to be exported"
        },
        { "out_exported", OUTPUT_FILE, MANDATORY,
            "The file to which the exported key material will be written",
        },
        { "deserialization_params", KEY_PARAMETERS, OPTIONAL,
            "Key parameters containing the `APPLICATION_ID` and/or `APPLICATION_DATA` "
                "required to use the key. Any other tags are ignored."
        },
    },
    [](arg_map_t& a) {
        return cli::hal_ops::export_key(*g_hal,
                a["in_keyblob"].in_bytes(), a["out_public_x509"].out_bytes(),
                a["deserialization_params"].in_key_params());
    }
},
{
    { "upgrade" },
    {
        "Upgrades a key blob generated on a system with older security patch levels, ",
        "enabling its usage on the current system."
    },
    HAL_NEEDED_3_0,
    {
        { "in_keyblob_to_upgrade", INPUT_FILE, MANDATORY,
            "The key blob to be upgraded"
        },
        { "out_upgraded_keyblob", OUTPUT_FILE, MANDATORY,
            "The file to which the new (upgraded) keyblob will be written"
        },
        { "upgrade_params", KEY_PARAMETERS, OPTIONAL,
            "Any parameters required to complete the `upgradeKey` operation, "
                "including APPLICATION_ID and/or APPLICATION_DATA, if applicable."
        }
    },
    [](arg_map_t& a) {
        return cli::hal_ops::upgrade_key(*g_hal,
                a["in_keyblob_to_upgrade"].in_bytes(),
                a["upgrade_params"].in_key_params(),
                a["out_upgraded_keyblob"].out_bytes()
        );
    }
},
{
    { "__line_break__" }, {}, HAL_NOT_NEEDED, {}, {}
},
{
    { "crypto", "encrypt" },
    {
        "Encrypts <in_plaintext> with <in_key_blob>, optionally using [params], "
            "saving the ciphertext to <out_ciphertext>"
    },
    HAL_NEEDED_3_0,
    {
        { "in_key_blob", INPUT_FILE, MANDATORY,
            "The encryption key blob"
        },
        { "in_plaintext", INPUT_FILE, MANDATORY,
            "The data to be encrypted"
        },
        { "out_ciphertext", OUTPUT_FILE, MANDATORY,
            "The file to which the encrypted data will be written"
        },
        { "params", KEY_PARAMETERS, OPTIONAL,
            "A space-separated list of key parameters used in the call to `begin`"
        },
        { "out_aes_gcm_iv", OUTPUT_FILE, OPTIONAL,
            "If performing AES encryption in GCM mode without a custom IV, "
                "the file to which the keymaster-generated IV will be written"
        },
    },
    [](arg_map_t& a) {
        hidl_vec<uint8_t> aes_gcm_iv;

        if (cli::hal_ops::crypto::encrypt(*g_hal,
                a["in_plaintext"].in_bytes(), a["in_key_blob"].in_bytes(),
                a["params"].in_key_params(), a["out_ciphertext"].out_bytes(), aes_gcm_iv))
            return EXIT_FAILURE;

        if (aes_gcm_iv.size() == 0)
            a["out_aes_gcm_iv"].disable_out_file();
        else
            a["out_aes_gcm_iv"].out_bytes() = aes_gcm_iv;

        return EXIT_SUCCESS;
    }
},
{
    { "crypto", "decrypt" },
    {
        "Decrypts <in_ciphertext> with <in_key_blob>, optionally using [params], "
            "saving the plaintext to <out_plaintext>"
    },
    HAL_NEEDED_3_0,
    {
        { "in_key_blob", INPUT_FILE, MANDATORY,
            "The decryption key blob"
        },
        { "in_ciphertext", INPUT_FILE, MANDATORY,
            "The data to be decrypted"
        },
        { "out_plaintext", OUTPUT_FILE, MANDATORY,
            "The file to which the decrypted data will be written"
        },
        { "params", KEY_PARAMETERS, OPTIONAL,
            "A space-separated list of key parameters used in the call to `begin`"
        },
    },
    [](arg_map_t& a) {
        return cli::hal_ops::crypto::decrypt(*g_hal,
                a["in_ciphertext"].in_bytes(), a["in_key_blob"].in_bytes(),
                a["params"].in_key_params(), a["out_plaintext"].out_bytes());
    }
},
{
    { "crypto", "sign" },
    {
        "Signs <in_message> with <in_key_blob>, optionally using [params], "
            "saving the signature to <out_signature>"
    },
    HAL_NEEDED_3_0,
    {
        { "in_key_blob", INPUT_FILE, MANDATORY,
            "The signing key blob"
        },
        { "in_message", INPUT_FILE, MANDATORY,
            "The data to be signed"
        },
        { "out_signature", OUTPUT_FILE, MANDATORY,
            "The file to which the signature will be written"
        },
        { "params", KEY_PARAMETERS, OPTIONAL,
            "A space-separated list of key parameters used in the call to `begin`"
        },
    },
    [](arg_map_t& a) {
        return cli::hal_ops::crypto::sign(*g_hal, a["in_message"].in_bytes(),
                a["in_key_blob"].in_bytes(), a["params"].in_key_params(),
                a["out_signature"].out_bytes());
    }
},
{
    { "crypto", "verify" },
    {
        "Verifies <in_signature> (generated over <in_message>) with <in_key_blob>, "
            "optionally using [params]"
    },
    HAL_NEEDED_3_0,
    {
        { "in_key_blob", INPUT_FILE, MANDATORY,
            "The key blob with which the signature was generated"
        },
        { "in_message", INPUT_FILE, MANDATORY,
            "The data that the signature applies to"
        },
        { "in_signature", INPUT_FILE, MANDATORY,
            "The signature to be verified"
        },
        { "params", KEY_PARAMETERS, OPTIONAL,
            "A space-separated list of key parameters used in the call to `begin`"
        },
    },
    [](arg_map_t& a) {
        return cli::hal_ops::crypto::verify(*g_hal,
                a["in_message"].in_bytes(), a["in_signature"].in_bytes(),
                a["in_key_blob"].in_bytes(), a["params"].in_key_params());
    }
},
{
    { "__line_break__" }, {}, HAL_NOT_NEEDED, {}, {}
},
#endif /* SUSKEYMASTER_BUILD_HOST */
{
    { "mkkeybox" },
    {
        "Creates a new suskeymaster binary keybox file <out_keybox> rom the two command lines "
            "(for EC and RSA).",
        "The command lines have the following format:",
        "   <alg> <n_certs> <cert_1> ... <cert_n> <keyblob>",
        "Where:",
        "   <alg> must be either \"ec\" or \"rsa\", depening on which key type "
                "the given command line corresponds to",
        "   <n_certs> is the number of certificates in the keybox",
        "   <cert_1> ... <cert_n> are the file paths of the individual DER-encoded "
                "X.509 certificate files. They may be quoted if they contain spaces.",
        "   <keyblob> is the file path of the wrapped keymaster key blob "
                "which contains the private leaf cert signing key of the given keybox.",
        "Note: The command lines have to be supplied in quotes if written in a shell."
    },
    HAL_NOT_NEEDED,
    {
        { "out_keybox", INPUT_STRING, MANDATORY, nullptr },
        { "cmdline1", INPUT_STRING, MANDATORY, nullptr },
        { "cmdline2", INPUT_STRING, MANDATORY, nullptr },
    },
    [](arg_map_t& a) {
        const char *const cmdline1 = a["cmdline1"].in_string().c_str();
        const char *const cmdline2 = a["cmdline2"].in_string().c_str();

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

        return cli::keybox::make_kb(ec_cert_paths, ec_key_path, rsa_cert_paths, rsa_key_path,
                a["out_keybox"].out_string() /* output file */);
    },
},
{
    { "dumpkeybox" },
    {
        "Dumps the suskeymaster binary keybox file <in_keybox> to the directory <out_dir_path>"
    },
    HAL_NOT_NEEDED,
    {
        {
            "in_keybox", INPUT_STRING, MANDATORY,
            "The keybox file to be dumped"
        },
        {
            "out_dir", INPUT_STRING, MANDATORY,
            "The directory to which the keybox will be dumped. "
                "Note: the directory has to already exist!"
        }
    },
    [](arg_map_t& a) {
        return cli::keybox::dump_kb(a["in_keybox"].in_string(), a["out_dir"].out_string());
    }
},
{
    { "__line_break__" }, {}, HAL_NOT_NEEDED, {}, {}
},
#ifndef SUSKEYMASTER_BUILD_HOST
{
    { "transact", "client", "generate" },
    {
        "Generates (optionally using [key_params]) the wrapping key "
            "for a secure import transaction.",
        "The key blob will be written to <out_keyblob>, while the public part "
            "will be exported to a DER-encoded X.509 certificate <out_pubkey>.",
        "Optionally an attestation for the wrapping key may be generated and written to "
            "[out_attestation]."
    },
    HAL_NEEDED_4_0,
    {
        {
            "out_keyblob", OUTPUT_FILE, MANDATORY,
            "The file to which the wrapping keyblob will be written"
        },
        {
            "out_pubkey", OUTPUT_FILE, MANDATORY,
            "The file to which the public part of the wrapping key will be written"
        },
        {
            "key_params", KEY_PARAMETERS, OPTIONAL,
            "Optional key generation parameters for the wrapping keyblob"
        },
        {
            "out_attestation", INPUT_STRING, OPTIONAL,
            "The path to which the serialized attestation of the wrapping keyblob will be written"
        }
    },
    {
        [](arg_map_t& a) {
            const std::string& out_attestation_path = a["out_attestation"].in_string();
            hidl_vec<hidl_vec<uint8_t>> cert_chain;

            const bool gen_att = !out_attestation_path.empty();
            hidl_vec<hidl_vec<uint8_t>> *const cert_chain_p =
                gen_att ? &cert_chain : nullptr;

            int r = cli::transact::client::generate_and_attest_wrapping_key(*g_hal,
                    a["out_keyblob"].out_bytes(), a["out_pubkey"].out_bytes(),
                    cert_chain_p, a["key_params"].in_key_params());
            if (r)
                return EXIT_FAILURE;

            if (gen_att) {
                if (serialize_and_write_cert_chain(out_attestation_path, cert_chain)) {
                    std::cerr << "Couldn't serialize and write the attestation cert chain"
                        << std::endl;
                    return EXIT_FAILURE;
                }
            }

            return EXIT_SUCCESS;
        }
    }
},
#endif /* SUSKEYMASTER_BUILD_HOST */
{
    { "transact", "server", "verify" },
    {
        "Verifies the KeyMaster attestation certificate chain <attestation>"
    },
    HAL_NOT_NEEDED,
    {
        {
            "attestation", INPUT_STRING, MANDATORY,
            "The serialized attestation certificate chain to be verified"
        }
    },
    [](arg_map_t& a) {
        hidl_vec<hidl_vec<uint8_t>> cert_chain;
        if (read_and_deserialize_cert_chain(a["attestation"].in_string(), cert_chain)) {
            std::cerr << "Couldn't read and deserialize the attestation cert chain" << std::endl;
            return EXIT_FAILURE;
        }

        return cli::transact::server::verify_attestation(cert_chain);
    }
},
{
    { "transact", "server", "wrap" },
    {
        "Wraps the private key <in_private_key> using <in_wrapping_pubkey> for a secure import.",
        "For RSA and EC keys, <in_private_key> should contain a DER-encoded PKCS#8 private key,",
        "while for other algorithms the raw bytes are read."
    },
    HAL_NOT_NEEDED,
    {
        {
            "in_private_key", INPUT_FILE, MANDATORY,
            "The private key to be wrapped for a secure import"
        },
        {
            "in_wrapping_pubkey", INPUT_FILE, MANDATORY,
            "The DER-encoded X.509 certificate containing the public part of the wrapping key"
        },
        {
            "out_wrapped_data", OUTPUT_FILE, MANDATORY,
            "The path to which the wrapped key data will be written"
        },
        {
            "out_masking_key", OUTPUT_FILE, MANDATORY,
            "The path to which the masking key will be written"
        },
        {
            "key_params", KEY_PARAMETERS, OPTIONAL,
            "A space-separated list of key parameters that the key should be given "
                "after a successful secure import"
        }
    },
    [](arg_map_t& a) {
        return cli::transact::server::wrap_key(
                a["in_private_key"].in_bytes(),
                a["in_wrapping_pubkey"].in_bytes(),
                a["key_params"].in_key_params(),
                a["out_wrapped_data"].out_bytes(),
                a["out_masking_key"].out_bytes()
        );
    }
},
#ifndef SUSKEYMASTER_BUILD_HOST
{
    { "transact", "client", "import" },
    {
        "Performs the secure import of <in_wrapped_data> (masked with <in_masking_key>) "
            "using <in_wrapping_keyblob>.",
        "This finalizes the secure import transaction.",
        "Additionally, [unwrapping_params] may contain a space-separated list of key parameters "
            "that will be passed as the `unwrappingParams` to the `importWrappedKey` call."
    },
    HAL_NEEDED_4_0,
    {
        {
            "in_wrapped_data", INPUT_FILE, MANDATORY,
            "The wrapped key data to be imported"
        },
        {
            "in_masking_key", INPUT_FILE, MANDATORY,
            "The masking key generated during the wrapping process"
        },
        {
            "in_wrapping_keyblob", INPUT_FILE, MANDATORY,
            "The wrapping key blob file"
        },
        {
            "out_keyblob", OUTPUT_FILE, MANDATORY,
            "The file to which the securely imported key blob will be written"
        },
        {
            "unwrapping_params", KEY_PARAMETERS, OPTIONAL,
            "A space-separated list of key parameters needed by the TEE to unwrap the key data"
        }
    },
    [](arg_map_t& a) {
        return cli::transact::client::import_wrapped_key(*g_hal,
                a["in_wrapped_data"].in_bytes(),
                a["in_masking_key"].in_bytes(),
                a["in_wrapping_keyblob"].in_bytes(),
                a["unwrapping_params"].in_key_params(),
                a["out_keyblob"].out_bytes()
        );
    }
},
#endif /* SUSKEYMASTER_BUILD_HOST */
{
    { "__line_break__" }, {}, HAL_NOT_NEEDED, {}, {}
},
{
    { "vold", "gen-appid" },
    {
        "Generates a value for Tag::APPLICATION_ID required to use vold keys"
    },
    HAL_NOT_NEEDED,
    {
        {
            "in_secdiscardable", INPUT_FILE, MANDATORY,
            "The `secdiscardable` file in the given vold `key` directory"
        },
        {
            "out_appid", OUTPUT_FILE, OPTIONAL,
            "The file to which the binary value of the generated APPLICATION_ID will be written"
        }
    },
    [](arg_map_t& a) {
        hidl_vec<uint8_t> app_id;
        if (cli::vold::generate_app_id(a["in_secdiscardable"].in_bytes(), app_id)) {
            std::cerr << "Failed to generate app_id" << std::endl;
            return EXIT_FAILURE;
        }

        std::puts("===== BEGIN APPLICATION ID HEX DUMP =====");
        for (uint8_t b : app_id) {
            std::printf("%02x", (unsigned)b);
        }
        std::putchar('\n');
        std::puts("=====  END APPLICATION ID HEX DUMP  =====");

        a["out_appid"].out_bytes() = app_id;
        return EXIT_SUCCESS;
    }
},
#ifndef SUSKEYMASTER_BUILD_HOST
{
    { "vold", "decrypt-with-keystore-key" },
    {
        "Decrypts the <in_vold_encrypted_key> using <in_keystore_key> and <in_secdiscardable>."
    },
    HAL_NEEDED_3_0,
    {
        {
            "in_vold_encrypted_key", INPUT_FILE, MANDATORY,
            "The vold key to decrypt"
        },
        {
            "in_keystore_key", INPUT_FILE, MANDATORY,
            "The keystore key used to encrypt <in_vold_encrypted_key>"
        },
        {
            "in_secdiscardable", INPUT_FILE, MANDATORY,
            "The secdiscardable file used to encrypt <in_vold_encrypted_key>"
        },
        {
            "out_decrypted_key", OUTPUT_FILE, MANDATORY,
            "The file to which the decrypted vold key will be written"
        }
    },
    [](arg_map_t& a) {
        return cli::vold::decrypt_vold_key_with_keystore_key(*g_hal,
                a["in_keystore_key"].in_bytes(), a["in_secdiscardable"].in_bytes(),
                a["in_vold_encrypted_key"].in_bytes(), a["out_decrypted_key"].out_bytes());
    }
},
#endif /* SUSKEYMASTER_BUILD_HOST */
{
    { "__line_break__" }, {}, HAL_NOT_NEEDED, {}, {}
},
{
    { "samsung", "ekey", "list-tags" },
    {
        "Prints out values of tags attached to a samsung keymaster encrypted key blob"
    },
    HAL_NOT_NEEDED,
    {
        {
            "in_keyblob", INPUT_FILE, MANDATORY,
            "The key blob whose tags are to be listed"
        }
    },
    [](arg_map_t& a) {
        return cli::samsung::ekey::list_tags(a["in_keyblob"].in_bytes());
    }
},
{
    { "samsung", "ekey", "add-tags" },
    {
        "Adds tags to a samsung keymaster encrypted key blob"
    },
    HAL_NOT_NEEDED,
    {
        {
            "in_keyblob", INPUT_FILE, MANDATORY,
            "The key blob to add the tags to"
        },
        {
            "out_keyblob", OUTPUT_FILE, MANDATORY,
            "The file to which the key blob with the added parameters will be written"
        },
        {
            "tags", KEY_PARAMETERS, MANDATORY,
            "A space-separated list of key parameters (tags) to add"
        }
    },
    [](arg_map_t& a) {
        return cli::samsung::ekey::add_tags(a["in_keyblob"].in_bytes(),
                a["tags"].in_key_params(), a["out_keyblob"].out_bytes());
    }
},
{
    { "samsung", "ekey", "del-tags" },
    {
        "Deletes tags from a samsung keymaster encrypted key blob"
    },
    HAL_NOT_NEEDED,
    {
        {
            "in_keyblob", INPUT_FILE, MANDATORY,
            "The key blob to delete the tags from"
        },
        {
            "out_keyblob", OUTPUT_FILE, MANDATORY,
            "The file to which the key blob with the deleted parameters will be written"
        },
        {
            "tags", KEY_PARAMETERS, MANDATORY,
            "A space-separated list of key parameters (tags) to delete"
        }
    },
    [](arg_map_t& a) {
        return cli::samsung::ekey::del_tags(a["in_keyblob"].in_bytes(),
                a["tags"].in_key_params(), a["out_keyblob"].out_bytes());
    }
},
#ifdef SUSKEYMASTER_ENABLE_SAMSUNG_SEND_INDATA
{
    { "__line_break__" }, {}, HAL_NOT_NEEDED, {}, {}
},
{
    { "samsung", "send-indata" },
    {
        "Asks libsuskeymaster to send raw indata to the skeymaster TA.",
        "The KM_INDATA fields are passed in in the <cmdline> like this:",
        "   <field>:<value>",
        "where <field> is a field in the KM_INDATA struct (see below), and",
        "<value> is the value the field is to be set to "
            "(the type depends on the field, also see below).",
        "",
        "Example cmdline (get-characteristics with keyblob.bin):",
        "   \"cmd:0x3 key:$(base64 -w 0 keyblob.bin) par:\\\"\\\"\"",
        "",
        "Another example cmdline (attest file keyblob-rsa.bin):",
        "   \"cmd:0xe key:$(base64 -w 0 keyblob-rsa.bin) par:\\\" \\",
        "       ATTESTATION_CHALLENGE= ATTESTATION_APPLICATION_ID= \\",
        "       PROV_GAC_RSA1=$(base64 -w 0 /mnt/vendor/efs/DAK/gakrsacert0.der) \\",
        "       PROV_GAK_RSA=$(base64 -w 0 /mnt/vendor/efs/DAK/GAK_RSA.private)\\\"\"",
        "Note: In this example only the leaf cert is generated by the TEE;",
        "   the rest of the cert chain lives under /mnt/vendor/efs/DAK/gak*cert*.der ",
        "   (or device-specific equivalent) and is normally appended by the HAL.",
        "   The TEE needs the attestation private key issuer cert's serial number to put ",
        "   in the leaf's `issuer` though, hence the `PROV_GAC_RSA1` tag providing it.",
        "",
        "The <cmdline> must provide:",
        "   <cmd>: INTEGER - the command which the TA is to run",
        "",
        "Additionally, <cmdline> may specify (values must be non-zero):",
        "   [ver]: INTEGER - the KM_INDATA blob version field, default: 0x3",
        "   [km_ver]: INTEGER - the version of the skeymaster TA, default: 0x28 (40)",
        "   [pid]: INTEGER - the PID of the HAL process, default: result of `getpid()`",
        "",
        "Also, parameters for the specified command may be given (not set at all by default):",
        "   [int0]: INTEGER - a parameter containing a regular integer value",
        "   [long0]: INTEGER - a parameter containing a BIGNUM value",
        "   [long1]: INTEGER - another parameter for a BIGNUM value",
        "   [bin0]: BASE64 - the first binary data parameter",
        "   [bin1]: BASE64 - the second binary data parameter",
        "   [bin2]: BASE64 - the third binary data parameter",
        "   [key]: BASE64 - a parameter containing a key blob processed by the command",
        "   [par]: KEY PARAMETERS - a quoted list of key parameters for the command"
    },
    HAL_NEEDED_3_0,
    {
        { "cmdline", INPUT_STRING, MANDATORY, nullptr }
    },
    [](arg_map_t& a) {
        uint32_t cmd, *cmd_p = &cmd;
        uint32_t ver, *ver_p = &ver;
        uint32_t km_ver, *km_ver_p = &km_ver;
        uint32_t pid, *pid_p = &pid;

        uint32_t int0, *int0_p = &int0;
        uint64_t long0, *long0_p = &long0;
        uint64_t long1, *long1_p = &long1;
        hidl_vec<uint8_t> bin0, *bin0_p = &bin0;
        hidl_vec<uint8_t> bin1, *bin1_p = &bin1;
        hidl_vec<uint8_t> bin2, *bin2_p = &bin2;
        hidl_vec<uint8_t> key, *key_p = &key;
        hidl_vec<KeyParameter> par, *par_p = &par;

        if (scan_indata_arg(a["cmdline"].in_string().c_str(), cmd_p, ver_p, km_ver_p, pid_p,
                int0_p, long0_p, long1_p, bin0_p, bin1_p, bin2_p, key_p, par_p))
        {
            std::cerr << "Failed to parse KM_INDATA struct fields from command line"
                << std::endl;
            return 1;
        }

        return cli::samsung::send_indata(*g_hal, ver_p, km_ver_p, cmd, pid_p,
                int0_p, long0_p, long1_p, bin0_p, bin1_p, bin2_p, key_p, par_p);
    }
}
#endif /* SUSKEYMASTER_ENABLE_SEND_INDATA */
};

struct cli_cmd_example_cmdline {
    std::string cmdline;
    std::string ps1;
    bool include_argv0;
};
struct cli_cmd_example {
    std::string description;
    std::vector<cli_cmd_example_cmdline> cmdlines;

    cli_cmd_example(std::string description, std::vector<cli_cmd_example_cmdline> cmdlines) {
        this->description = description;
        this->cmdlines = cmdlines;
    }
    cli_cmd_example(std::string description, std::string cmdline) {
        this->description = description;
        this->cmdlines = { { cmdline, "$ ", true } };
    }
};
static const std::vector<cli_cmd_example> cmd_examples = {
#ifndef SUSKEYMASTER_BUILD_HOST
    {
        "print out the characteristics of a key generated with APPLICATION_ID='test'",
        "get-characteristics keyblob.bin \"APPLICATION_ID=$(printf 'test' | base64)\""
    },
    {
        "generate an ECDSA-P384 key and attest it, with an empty attestation challenge",
        "attest generated \"ALGORITHM=EC EC_CURVE=P_384\" \"ATTESTATION_CHALLENGE= \""
    },
    {
        "generate an EC key with the ability to use it for encryption and decryption",
        "generate \"ALGORITHM=EC PURPOSE=ENCRYPT PURPOSE=DECRYPT\" keyblob-ec.bin"
    },
    {
        "export the public part of an EC key",
        "export keyblob-ec.bin pubkey.x509"
    },
    {
        "sign a message with a keyblob created with APPLICATION_ID='1234'",
        "crypto sign keyblob.bin message.txt signature.bin "
            "\"APPLICATION_ID=$(printf '1234' | base64)\""
    },
#endif /* SUSKEYMASTER_BUILD_HOST */
    {
        "generate a binary suskeymaster keybox file from certificates and keyblobs",
        {
            { "mkkeybox keybox.bin \\", "$ ", true },
            { "'ec 3 cert1-ec.der cert2-ec.der cert3-ec.der keyblob-ec.bin' \\", "    ", 0 },
            { "'rsa 3 cert1-rsa.der cert2-rsa.der cert3-rsa.der keyblob-rsa.bin'", "    ", 0 },
        }
    },
    {
        "dump a binary keybox file to the current working directory",
        "dumpkeybox keybox.bin ."
    },
#ifndef SUSKEYMASTER_BUILD_HOST
    {
        "securely import an EC key (`private-ec.der`) from a remote server "
            "to the KeyMaster of the client device (`keyblob-ec.bin`)",
        {
            { "transact client generate wrapping-key.bin wrapping-pub.x509 ' ' attestation.bin",
                "(client) $ ", true },
            { "    >>> (upload `wrapping-pub.x509` to the server)", "", false },
            { "transact server verify attestation.bin   # Optional", "(server) $ ", true },
            { "transact server wrap "
                "private-ec.der wrapping-pub.x509 wrapped-data.bin masking-key.bin",
                "(server) $ ", true },
            { "    <<< (send `wrapped-data.bin` and `masking-key.bin` to the client)",
                "", false },
            { "transact client import "
                "wrapped-data.bin masking-key.bin wrapping-key.bin keyblob-ec.bin",
                "(client) $ ", true },
        }
    }
#else
    {
        "prepare an EC key (`private-ec.der`) for a secure import on a client device",
        {
            { "transact server verify attestation.bin   # Optional", "$ ", true },
            { "transact server wrap private-ec.der wrapping-pub.x509 "
                    "wrapped-data.bin masking-key.bin", "$ ", true },
        }
    }
#endif /* SUSKEYMASTER_BUILD_HOST */
};

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

static void check_print_help(int argc, const char **argv,
        bool *o_should_return, int *o_return_val)
{
    *o_should_return = false;
    *o_return_val = EXIT_SUCCESS;

    if (argc < 2) {
        std::cerr << "Not enough arguments!" << std::endl;
        print_generic_usage();
        *o_should_return = true;
        *o_return_val = EXIT_FAILURE;
        return;
    }

    if (!strcmp(argv[1], "help")) {
        *o_should_return = true;
        *o_return_val = EXIT_SUCCESS;

        if (argc > 2) {
            int n_consumed = 0;
            /* Skip argv[0] and argv[1] */
            argc -= 2;
            argv += 2;
            const cli_command *cmd = match_command(argc, argv, n_consumed);
            if (cmd == nullptr)
                print_generic_usage();
            else
                print_cmd_usage(*cmd);
        } else {
            print_generic_usage();
        }
        return;
    }

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
            print_generic_usage();
            *o_should_return = true;
            *o_return_val = EXIT_SUCCESS;
            return;
        }
    }
}

static __attribute__((unused)) void print_inithal_ok_msg(hal_version hal_ver)
{
    SecurityLevel slvl;
    hidl_string km_name;
    hidl_string km_author_name;
    g_hal->getHardwareInfo(slvl, km_name, km_author_name);
    std::cout << "Using " << toString(slvl) << " Keymaster " <<
        hal_version_major(hal_ver) << "." << hal_version_minor(hal_ver) <<
        " HAL \"" << km_name.c_str() <<
        "\" (by \"" << km_author_name.c_str() << "\") " << std::endl;
}
static __attribute__((unused)) void print_inithal_fail_msg(hal_version hal_ver)
{
    std::cerr << "Couldn't initialize a keymaster " <<
        hal_version_major(hal_ver) << "." << hal_version_minor(hal_ver) <<
        " HAL instance" << std::endl;
}
static int init_g_hal(hal_version min_ver)
{
    if (min_ver == HAL_NONE)
        return EXIT_SUCCESS;

    const char *km_ver_env = std::getenv("SUSKEYMASTER_HAL_VERSION");
    (void) km_ver_env;

#ifndef SUSKEYMASTER_HAL_DISABLE_4_1
    if ((min_ver <= HAL_4_1 && !km_ver_env) || !strcmp(km_ver_env, "4.1")) {
        g_hal = std::make_unique<kmhal::hidl::HidlSusKeymaster4_1>();
        if (g_hal->isHALOk()) {
            print_inithal_ok_msg(HAL_4_1);
            return EXIT_SUCCESS;
        } else if (km_ver_env && !strcmp(km_ver_env, "4.1")) {
            print_inithal_fail_msg(HAL_4_1);
            return EXIT_FAILURE;
        }
    }
#endif /* SUSKEYMASTER_HAL_DISABLE_4_1 */

#ifndef SUSKEYMASTER_HAL_DISABLE_4_0
    if ((min_ver <= HAL_4_0 && !km_ver_env) || !strcmp(km_ver_env, "4.0")) {
        g_hal = std::make_unique<kmhal::hidl::HidlSusKeymaster4_0>();
        if (g_hal->isHALOk()) {
            print_inithal_ok_msg(HAL_4_0);
            return EXIT_SUCCESS;
        } else if (km_ver_env && !strcmp(km_ver_env, "4.0")) {
            print_inithal_fail_msg(HAL_4_0);
            return EXIT_FAILURE;
        }
    }
#endif /* SUSKEYMASTER_HAL_DISABLE_4_0 */

#ifndef SUSKEYMASTER_HAL_DISABLE_3_0
    if ((min_ver <= HAL_3_0 && !km_ver_env) || !strcmp(km_ver_env, "3.0")) {
        g_hal = std::make_unique<kmhal::hidl::HidlSusKeymaster3_0>();
        if (g_hal->isHALOk()) {
            print_inithal_ok_msg(HAL_3_0);
            return EXIT_SUCCESS;
        } else if (km_ver_env && !strcmp(km_ver_env, "3.0")) {
            print_inithal_fail_msg(HAL_3_0);
            return EXIT_FAILURE;
        }
    }
#endif /* SUSKEYMASTER_HAL_DISABLE_3_0 */

    std::cerr << "Couldn't initialize a keymaster >= " <<
        hal_version_major(min_ver) << "." << hal_version_minor(min_ver) <<
        " HAL instance" << std::endl;
    return EXIT_FAILURE;
}

static int read_file(const std::string& path, const std::string& param_name,
        hidl_vec<uint8_t>& out)
{
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        std::cerr << "Failed to open \"" << path << "\": "
            << errno << " (" << std::strerror(errno) << ")" << std::endl;
        return 1;
    }

    /* std::ios::ate tells ifstream to seek to the end */
    std::streamsize sz = file.tellg();

    file.seekg(0, std::ios::beg);
    if (file.fail()) {
        std::cerr << "Failed to set the position in \"" << path
            << "\" to the beginning: " << errno << " (" << std::strerror(errno) << ")"
            << std::endl;
        return 1;
    }

    out.resize(sz);
    file.read(reinterpret_cast<char *>(out.data()), sz);
    if (file.fail()) {
        std::cerr << "Failed to read \"" << path << "\" : "
            << errno << " (" << std::strerror(errno) << ")" << std::endl;
        return 1;
    }
    file.close();
    if (file.fail()) {
        std::cerr << "Failed to close \"" << path << "\" : "
            << errno << " (" << std::strerror(errno) << ")" << std::endl;
        return 1;
    }

    std::cout << "Successfully read `" << param_name << "` \"" << path << "\"" << std::endl;
    return 0;
}

static int write_file(const std::string& path, const std::string& param_name,
        const hidl_vec<uint8_t>& in)
{
    std::ofstream file(path, std::ios::binary | std::ios::trunc);
    if (!file.is_open()) {
        std::cerr << "Failed to open \"" << path << "\": "
            << errno << " (" << std::strerror(errno) << ")" << std::endl;
        return 1;
    }

    file.write(reinterpret_cast<const char *>(in.data()), in.size());
    if (file.fail()) {
        std::cerr << "Failed to write \"" << path << "\" : "
            << errno << " (" << std::strerror(errno) << ")" << std::endl;
        return 1;
    }
    file.close();

    std::cout << "Successfully wrote `" << param_name << "` \"" << path << "\"" << std::endl;
    return 0;
}

static int read_and_deserialize_cert_chain(const std::string& path,
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
    n_certs = ::_::ntohl_(n_certs);
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
        cert_size = ::_::ntohl_(cert_size);
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

#ifndef SUSKEYMASTER_BUILD_HOST
static int serialize_and_write_cert_chain(const std::string& path,
        const hidl_vec<hidl_vec<uint8_t>>& cert_chain)
{
    std::ofstream file(path, std::ios::binary | std::ios::trunc);
    if (!file.is_open()) {
        std::cerr << "Failed to open attestation cert chain file \"" << path << "\": "
            << errno << " (" << std::strerror(errno) << ")" << std::endl;
        return 1;
    }

    uint32_t be_n_certs = ::_::htonl_(cert_chain.size());
    file.write(reinterpret_cast<const char *>(&be_n_certs), sizeof(uint32_t));
    if (file.fail()) {
        std::cerr << "Failed to write the number of certs to \"" << path << "\" : "
            << errno << " (" << std::strerror(errno) << ")" << std::endl;
        return 1;
    }

    for (uint32_t i = 0; i < cert_chain.size(); i++) {
        uint32_t cert_size = ::_::htonl_(cert_chain[i].size());
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
#endif /* SUSKEYMASTER_BUILD_HOST */

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

#ifdef SUSKEYMASTER_ENABLE_SAMSUNG_SEND_INDATA
template<typename T>
static int str_to_int(const std::string &str_, T& out)
{

    std::string str(str_);
    bool hex = false;
    if (str.substr(0, 2) == "0x" || str.substr(0, 2) == "0X") {
        str = str.substr(2);
        hex = true;
    }

    const char *const start = str.data();
    const char *const end = str.data() + str.size();

    auto res = std::from_chars(start, end, out, hex ? 16 : 10);
    if (res.ec != std::errc()) {
        std::error_code e = std::make_error_code(res.ec);
        std::cerr << "std::from_chars failed: " << e
            << " (" << e.message() << ")" << std::endl;
        return 1;
    } else if (res.ptr != end) {
        std::cerr << "Trailing garbage at the end of string" << std::endl;
        return 1;
    }

    return 0;
}
static int scan_indata_arg(const char *cmdline, uint32_t *& out_cmd,
        uint32_t *& out_ver, uint32_t *& out_km_ver, uint32_t *& out_pid,
        uint32_t *& out_int0, uint64_t *& out_long0, uint64_t *& out_long1,
        hidl_vec<uint8_t> *& out_bin0, hidl_vec<uint8_t> *& out_bin1,
        hidl_vec<uint8_t> *& out_bin2, hidl_vec<uint8_t> *& out_key,
        hidl_vec<KeyParameter> *& out_par)
{
    std::istringstream iss(cmdline);

    struct out_param {
        union {
            uint32_t **intp;
            uint64_t **longp;
            hidl_vec<uint8_t> **binp;
            hidl_vec<KeyParameter> **parp;

            void **vp;
        } out;
        enum { INT, LONG, BIN, PAR } type;

        bool found = false;
        bool mandatory = false;

        out_param(uint32_t **intp) { this->out.intp = intp; this->type = INT; }
        out_param(uint64_t **longp) { this->out.longp = longp; this->type = LONG; }
        out_param(hidl_vec<uint8_t> **binp) { this->out.binp = binp; this->type = BIN; }
        out_param(hidl_vec<KeyParameter> **parp) { this->out.parp = parp; this->type = PAR; }

        /* for `cmd` */
        out_param(uint32_t **intp, bool mandatory) {
            this->out.intp = intp;
            this->type = INT;
            this->mandatory = mandatory;
        }
    };
    std::unordered_map<std::string, out_param> out_par_map = {
        { "cmd", { &out_cmd, true } },
        { "ver", { &out_ver } },
        { "km_ver", { &out_km_ver } },
        { "pid", { &out_pid } },
        { "int0", { &out_int0 } },
        { "long0", { &out_long0 } },
        { "long1", { &out_long1 } },
        { "bin0", { &out_bin0 } },
        { "bin1", { &out_bin1 } },
        { "bin2", { &out_bin2 } },
        { "key", { &out_key } },
        { "par", { &out_par } },
    };

    std::string arg;
    auto argstartpos = iss.tellg();
    while (argstartpos = iss.tellg(), std::getline(iss, arg, ' ')) {
        const bool is_end = iss.eof();

        auto separator_pos = arg.find(':');
        if (separator_pos == std::string::npos) {
            std::cerr << "Parsing failed: missing ':' separator in arg `"
                << arg << "`" << std::endl;
            return 1;
        }

        std::string field = arg.substr(0, separator_pos);
        std::string value = arg.substr(separator_pos + 1);
        char qc = 0;
        if (value.length() > 0 && (qc = value[0], (qc == '"' || qc == '\'' || qc == '`'))) {
            std::string tmp, tmp2;

            if (!iss.seekg(argstartpos) ||
                !std::getline(iss, tmp, qc) ||
                (!std::getline(iss, tmp, qc) && !is_end) ||
                (std::getline(iss, tmp2, ' '), tmp2.size() > 0))
            {
                std::cerr << "Invalid quoted value in field "
                    << "\"" << field << "\" " << std::endl;
                return 1;
            }

            value = tmp;
        }

        auto it = out_par_map.find(field);
        if (it == out_par_map.end()) {
            std::cerr << "Unknown KM_INDATA field: \"" << field << "\"" << std::endl;
            return 1;
        }

        if (it->second.found) {
            std::cerr << "Duplicate value for field: \"" << field << "\"" << std::endl;
            return 1;
        }
        it->second.found = true;

        switch (it->second.type) {
        case out_param::INT:
            {
                uint32_t out;
                if (str_to_int<uint32_t>(value, out)) {
                    std::cerr << "Couldn't parse uint32 value for field \""
                        << field << "\"" << std::endl;
                }
                **it->second.out.intp = out;
            }
            break;
        case out_param::LONG:
            {
                uint64_t out;
                if (str_to_int<uint64_t>(value, out)) {
                    std::cerr << "Couldn't parse uint64 value for field \""
                        << field << "\"" << std::endl;
                }
                **it->second.out.longp = out;
            }
            break;
        case out_param::BIN:
            {
                std::vector<uint8_t> bytes;
                if (kmhal::util::b64decode(value, bytes)) {
                    std::cerr << "Couldn't decode base64 value for field \""
                        << field << "\"" << std::endl;
                    return 1;
                }

                (**it->second.out.binp).resize(bytes.size());
                std::memcpy((**it->second.out.binp).data(), bytes.data(), bytes.size());
            }
            break;
        case out_param::PAR:
            {
                hidl_vec<KeyParameter> out;
                if (kmhal::util::parse_km_tag_params(value.c_str(), out)) {
                    std::cerr << "Invalid key parameters for field \""
                        << field << "\"" << std::endl;
                    return 1;
                }

                **it->second.out.parp = out;
            }
            break;
        }
    }

    for (const auto& it : out_par_map) {
        if (!it.second.found) {
            if (it.second.mandatory) {
                std::cerr << "Missing mandatory field: \"" << it.first << "\"" << std::endl;
                return 1;
            }

            *it.second.out.vp = nullptr;
        }
    }

    return 0;
}
#endif /* SUSKEYMASTER_ENABLE_SAMSUNG_SEND_INDATA */

static void print_generic_usage(void)
{
    const char *progname = g_argv0 ? g_argv0 : "suskeymaster";

    std::cout << "Usage: " << progname << " <command> <args...>" << std::endl
        << "Available commands:" << std::endl;
    std::cout << "    help [command...]" << std::endl;
    for (const auto& c : cmds) {
        if (c.argv_match.size() == 1 && !std::strcmp(c.argv_match[0], "__line_break__")) {
            std::cout << std::endl;
            continue;
        }

#ifdef SUSKEYMASTER_BUILD_HOST
        if (c.required_hal_version > HAL_NONE)
            continue;
#endif /* SUSKEYMASTER_BUILD_HOST */

        std::cout << "    ";

        if (c.required_hal_version > HAL_3_0) {
            std::cout << "(since Keymaster " << hal_version_major(c.required_hal_version)
                << "." << hal_version_minor(c.required_hal_version) << ") ";
        }

        for (const char *s : c.argv_match)
            std::cout << s << " ";

        for (const auto& a : c.args) {
            char c1 = a.mandatory ? '<' : '[';
            char c2 = a.mandatory ? '>' : ']';

            std::cout << c1 << a.name << c2 << " ";
        }

        std::cout << std::endl;
    }

    std::cout << std::endl;

    std::cout << "Examples:" << std::endl;
    for (const auto& e : cmd_examples) {
        std::cout << "    To " << e.description << ":" << std::endl;
        for (const auto& c : e.cmdlines) {
            std::cout << "    "
                << c.ps1
                << (c.include_argv0 ? std::string(progname) + " " : std::string(""))
                << c.cmdline
                << std::endl;
        }

        std::cout << std::endl;
    }

    std::cout << "To get more detailed info about a specific command, run:" << std::endl
        << "$ " << progname << " help <command>" << std::endl;

    std::cout << std::endl;
}

static const cli_command * match_command(int argc, const char **argv, int& out_n_consumed)
{
    const cli_command *ret = nullptr;
    out_n_consumed = 0;

    for (const auto& cmd : cmds) {
        if (cmd.argv_match.size() == 1 && !std::strcmp(cmd.argv_match[0], "__line_break__"))
            continue;

        if (argc < static_cast<long long>(cmd.argv_match.size()))
            continue;

        bool matched = true;
        for (size_t i = 0; i < cmd.argv_match.size(); i++) {
            if (strcmp(cmd.argv_match[i], argv[i])) {
                matched = false;
                break;
            }
        }

        if (matched) {
            ret = &cmd;
            out_n_consumed = cmd.argv_match.size();
            break;
        }
    }

    return ret;
}

static void print_cmd_usage(const cli_command& c)
{
    const char *progname = g_argv0 ? g_argv0 : "suskeymaster";

    std::cout << "Usage: " << progname << " ";

    for (const char *s : c.argv_match)
        std::cout << s << " ";

    for (const auto& a : c.args) {
        char c1 = a.mandatory ? '<' : '[';
        char c2 = a.mandatory ? '>' : ']';

        std::cout << c1 << a.name << c2 << " ";
    }
    std::cout << std::endl;

    for (const char *s : c.description)
        std::cout << "    " << s << std::endl;

    std::cout << std::endl;

    bool all_null = true;
    for (const auto& a : c.args) {
        if (a.description != nullptr) {
            all_null = false;
            break;
        }
    }
    if (!all_null) {
        std::cout << "Arguments:" << std::endl;
        for (const auto& a : c.args) {
            if (a.description == nullptr)
                continue;

            char c1 = a.mandatory ? '<' : '[';
            char c2 = a.mandatory ? '>' : ']';

            std::cout << "    " << c1 << a.name << c2 << ": " << a.description << std::endl;
        }

        std::cout << std::endl;
    }

}

static int match_and_run_handler(int argc, const char **argv)
{
    /* Skip argv[0] */
    argc--;
    argv++;

    int n_consumed = 0;

    const cli_command *matched_cmd = match_command(argc, argv, n_consumed);
    if (matched_cmd == nullptr) {
        print_generic_usage();

        std::cerr << "Unknown command: \"";
        for (int i = 0; i < argc; i++) {
            std::string s(argv[i]);
            if (s.length() > 20)
                std::cerr << s.substr(0, 20) << "...";
            else
                std::cerr << s;

            if (i < argc - 1)
                std::cerr << " ";
        }
        std::cerr << "\"" << std::endl;
        return EXIT_FAILURE;
    }

    std::string full_cmd_name;
    for (int i = 0; i < std::min(n_consumed, argc); i++) {
        full_cmd_name += argv[i];
        if (i < n_consumed - 1)
            full_cmd_name += " ";
    }
    /* Skip the args that were "consumed" as part of the command name */
    argc -= n_consumed;
    argv += n_consumed;

    /* Read the arguments from the rest of the command line */

    std::unordered_map<std::string, cli_arg_value> arg_values;
    int i = 0;
    for (const cli_arg& a : matched_cmd->args) {
        if (i >= argc && a.mandatory) {
            std::cout << "Not enough arguments for command: " << full_cmd_name << std::endl;
            print_cmd_usage(*matched_cmd);
            return EXIT_FAILURE;
        } else if (i >= argc && !a.mandatory) {
            /* If an optional argument is missing, during lookup
             * the default constructor will create an empty vector in place of its value */
            (void) 0;
        } else {

            hidl_vec<uint8_t> bytes;
            hidl_vec<KeyParameter> key_params;

            switch (a.type) {
            case INPUT_FILE:
                if (read_file(argv[i], a.name, bytes)) {
                    std::cerr << "Failed to read the " << a.name << " file" << std::endl;
                    return EXIT_FAILURE;
                }

                arg_values.emplace(a.name, cli_arg_value(std::move(bytes)));

                break;
            case KEY_PARAMETERS:
                if (kmhal::util::parse_km_tag_params(argv[i], key_params)) {
                    std::cerr << "Invalid key parameters" << std::endl;
                    return EXIT_FAILURE;
                }

                arg_values.emplace(a.name, cli_arg_value(std::move(key_params)));

                break;
            case OUTPUT_FILE:
                arg_values.emplace(a.name, cli_arg_value(std::string(argv[i]), true));
                break;
            case INPUT_STRING:
                arg_values.emplace(a.name, cli_arg_value(std::string(argv[i]), false));
                break;
            }
        }

        i++;
    }

    /* Init HAL if needed */
    if (matched_cmd->required_hal_version > HAL_NONE) {
        if (init_g_hal(matched_cmd->required_hal_version)) {
            std::cerr << "HAL initialization failed for a command that requires it " <<
                "(\"" << full_cmd_name << "\")" << std::endl;
            return EXIT_FAILURE;
        }
    }

    /* Run the handler with the parsed arguments */
    if (matched_cmd->handler(arg_values))
        return EXIT_FAILURE;

    /* Write any output files */
    for (auto& a : arg_values) {
        if (!a.second.is_out_file())
            continue;

        const std::string& path = a.second.out_string();
        const std::string& param_name = a.first;
        const hidl_vec<uint8_t>& bytes = a.second.out_bytes();

        if (write_file(path, param_name, bytes)) {
            std::cerr << "Failed to write \"" << path << "\"" << std::endl;
            return EXIT_FAILURE;
        }
    }

    return EXIT_SUCCESS;
}

} /* namespace suskeymaster */

#ifdef _WIN32
#include <winsock2.h>
#else
#include <netinet/in.h>
#endif /* _WIN32 */
namespace _ {
    static uint32_t ntohl_(uint32_t n)
    {
        return ::ntohl(n);
    }

#ifndef SUSKEYMASTER_BUILD_HOST
    static uint32_t htonl_(uint32_t h)
    {
        return ::htonl(h);
    }
#endif /* SUSKEYMASTER_BUILD_HOST */
};

