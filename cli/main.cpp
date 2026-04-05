#define HIDL_DISABLE_INSTRUMENTATION
#include "cli.hpp"
#include <core/log.h>
#include <libsuscertmod/certmod.h>
#include <libsuskmhal/hidl/hidl-hal.hpp>
#include <libsuskmhal/util/km-params.hpp>
#include <android/hardware/keymaster/4.0/types.h>
#include <strings.h>
#include <cstdio>
#include <string>
#include <cerrno>
#include <vector>
#include <iomanip>
#include <sstream>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <ostream>
#include <iostream>
#include <unordered_map>

using namespace ::android::hardware::keymaster::V4_0;
using namespace ::android::hardware;
using namespace suskeymaster;

static const char *g_argv0 = NULL;
static suskeymaster::kmhal::hidl::HidlSusKeymaster4 g_hal;

namespace suskeymaster {
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
};

enum cli_cmd_hal_needed {
    HAL_NOT_NEEDED,
    HAL_NEEDED,
};

typedef std::unordered_map<std::string, cli_arg_value> arg_map_t;

struct cli_command {
    std::vector<const char *> argv_match;
    std::vector<const char *> description;

    cli_cmd_hal_needed hal_needed;
    std::vector<cli_arg> args;

    int (*handler)(arg_map_t& args);
};

static void setup_cgd_log(void);

static void check_print_help(int argc, const char **argv,
        bool *o_should_return, int *o_return_val);

static int init_g_hal(void);

static int read_file(const std::string& path, hidl_vec<uint8_t>& out);
static int write_file(const std::string& path, const hidl_vec<uint8_t>& in);

static int read_and_deserialize_cert_chain(const std::string& path,
        hidl_vec<hidl_vec<uint8_t>>& cert_chain);
static int serialize_and_write_cert_chain(const std::string& path,
        const hidl_vec<hidl_vec<uint8_t>>& cert_chain);

static int scan_keybox_arg(const char *cmdline,
        std::vector<std::string>& out_cert_chain,
        std::string& out_key_path);

static void print_generic_usage(void);

static const cli_command * match_command(int argc, const char **argv, int& out_n_consumed);

static void print_cmd_usage(const cli_command& c);
static int match_and_run_handler(int argc, const char **argv);

} /* namespace suskeymaster */

namespace _ {
    static uint32_t ntohl_(uint32_t);
    static uint32_t htonl_(uint32_t);
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
{
    { "get-characteristics" },
    {
        "Print the characteristics (properties) of <key_blob>.",
    },
    HAL_NEEDED,
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
        return cli::hal_ops::get_key_characteristics(g_hal,
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
    HAL_NEEDED,
    {
        { "params", KEY_PARAMETERS, MANDATORY,
            "Key generation parameters, such as ALGORITHM and PURPOSE"
        },
        { "out_key_blob", OUTPUT_FILE, MANDATORY,
            "The file to which the keymaster keyblob will be written"
        },
    },
    [](arg_map_t& a) {
        return cli::hal_ops::generate_key(g_hal,
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
    HAL_NEEDED,
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
        if (cli::hal_ops::generate_key(g_hal, a["generate_params"].in_key_params(), keyblob)) {
            std::cerr << "Failed to generate ephemeral attested key!" << std::endl;
            return 1;
        }

        return cli::hal_ops::attest_key(g_hal, keyblob, a["attest_params"].in_key_params());
    }
},
{
    { "attest", "file" },
    {
        "Attest <keyblob> (optionally using [attest_params])",
        "   optionally saving the resulting serialized attestation cert chain "
            "to [out_attestation]"
    },
    HAL_NEEDED,
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

        return cli::hal_ops::attest_key(g_hal, keyblob, params);
    }
},
{
    { "import" },
    {
        "Imports a PKCS#8 DER-encoded ECDSA or RSA private key <in_private_pkcs8>",
        "   into the device's KeyMaster, writing the resulting key blob to <out_key_blob>."
    },
    HAL_NEEDED,
    {
        { "in_private_pkcs8", INPUT_FILE, MANDATORY,
            "The DER-encoded PKCS#8 private key to import"
        },
        { "in_key_blob", OUTPUT_FILE, MANDATORY,
            "The file to which the imported key blob will be written"
        },
        { "params", KEY_PARAMETERS, OPTIONAL,
            "A space-separated list of key parameters that the imported key blob should have"
        },
    },
    [](arg_map_t& a) {
        return cli::hal_ops::import_key(g_hal, a["in_private_pkcs8"].in_bytes(),
                a["params"].in_key_params(), a["in_key_blob"].out_bytes());
    }
},
{
    { "export" },
    {
        "Exports the given keymaster key blob <in_keyblob>'s public key",
        "to a DER-encoded X.509 certificate <out_public_x509>"
    },
    HAL_NEEDED,
    {
        { "in_keyblob", INPUT_FILE, MANDATORY,
            "The key blob whose public key is to be exported"
        },
        { "out_public_x509", OUTPUT_FILE, MANDATORY,
            "The file to which the DER-encoded X.509 certificate containing the public key "
                "will be written"
        },
        { "deserialization_params", KEY_PARAMETERS, OPTIONAL,
            "Key parameters containing the `APPLICATION_ID` and/or `APPLICATION_DATA` "
                "required to use the key. Any other tags are ignored."
        },
    },
    [](arg_map_t& a) {
        return cli::hal_ops::export_key(g_hal,
                a["in_keyblob"].in_bytes(), a["out_public_x509"].out_bytes(),
                a["deserialization_params"].in_key_params());
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
    HAL_NEEDED,
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
    },
    [](arg_map_t& a) {
        return cli::hal_ops::crypto::encrypt(g_hal,
                a["in_plaintext"].in_bytes(), a["in_key_blob"].in_bytes(),
                a["params"].in_key_params(), a["out_ciphertext"].out_bytes());
    }
},
{
    { "crypto", "decrypt" },
    {
        "Decrypts <in_ciphertext> with <in_key_blob>, optionally using [params], "
            "saving the plaintext to <out_plaintext>"
    },
    HAL_NEEDED,
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
        return cli::hal_ops::crypto::decrypt(g_hal,
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
    HAL_NEEDED,
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
        return cli::hal_ops::crypto::sign(g_hal, a["in_message"].in_bytes(),
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
    HAL_NEEDED,
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
        return cli::hal_ops::crypto::verify(g_hal,
                a["in_message"].in_bytes(), a["in_signature"].in_bytes(),
                a["in_key_blob"].in_bytes(), a["params"].in_key_params());
    }
},
{
    { "__line_break__" }, {}, HAL_NOT_NEEDED, {}, {}
},
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
    HAL_NEEDED,
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

            int r = cli::transact::client::generate_and_attest_wrapping_key(g_hal,
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
        "Wraps the DER-encoded PKCS#8 private key <in_private_key> "
            "for a secure import transaction"
    },
    HAL_NOT_NEEDED,
    {
        {
            "in_private_pkcs8", INPUT_FILE, MANDATORY,
            "The DER-encoded PKCS#8 private key to be wrapped for a secure import"
        },
        {
            "in_wrapping_key", INPUT_FILE, MANDATORY,
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
                a["in_private_pkcs8"].in_bytes(),
                a["in_wrapping_key"].in_bytes(),
                a["key_params"].in_key_params(),
                a["out_wrapped_data"].out_bytes(),
                a["out_masking_key"].out_bytes()
        );
    }
},
{
    { "transact", "client", "import" },
    {
        "Performs the secure import of <in_wrapped_data> (masked with <in_masking_key>) "
            "using <in_wrapping_keyblob>.",
        "This finalizes the secure import transaction.",
        "Additionally, [unwrapping_params] may contain a space-separated list of key parameters "
            "that will be passed as the `unwrappingParams` to the `importWrappedKey` call."
    },
    HAL_NEEDED,
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
        return cli::transact::client::import_wrapped_key(g_hal,
                a["in_wrapped_data"].in_bytes(),
                a["in_masking_key"].in_bytes(),
                a["in_wrapping_keyblob"].in_bytes(),
                a["unwrapping_params"].in_key_params(),
                a["out_keyblob"].out_bytes()
        );
    }
}
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

static int init_g_hal(void)
{
    if (!g_hal.isHALOk()) {
        std::cerr << "Couldn't obtain handle to KeyMaster HAL service" << std::endl;
        return EXIT_FAILURE;
    }

    SecurityLevel slvl;
    hidl_string km_name;
    hidl_string km_author_name;
    g_hal.getHardwareInfo(slvl, km_name, km_author_name);
    std::cout << "Using keymaster \"" << km_name.c_str()
        << "\" (of \"" << km_author_name.c_str() << "\") " <<
        "with SecurityLevel::" << toString(slvl) << std::endl;
    return EXIT_SUCCESS;
}

static int read_file(const std::string& path, hidl_vec<uint8_t>& out)
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

    std::cout << "Successfully read \"" << path << "\"" << std::endl;
    return 0;
}

static int write_file(const std::string& path, const hidl_vec<uint8_t>& in)
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

    std::cout << "Successfully wrote \"" << path << "\"" << std::endl;
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

        std::cout << "    ";

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

    for (const std::string& s : c.description)
        std::cout << "    " << s << std::endl;

    std::cout << std::endl;

    std::cout << "Arguments:" << std::endl;
    for (const auto& a : c.args) {
        char c1 = a.mandatory ? '<' : '[';
        char c2 = a.mandatory ? '>' : ']';

        std::cout << "    " << c1 << a.name << c2 << ": " << a.description << std::endl;
    }

    std::cout << std::endl;
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
                if (read_file(argv[i], bytes)) {
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
    if (matched_cmd->hal_needed) {
        if (init_g_hal()) {
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
        const hidl_vec<uint8_t>& bytes = a.second.out_bytes();

        if (write_file(path, bytes)) {
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

    static uint32_t htonl_(uint32_t h)
    {
        return ::htonl(h);
    }
};
