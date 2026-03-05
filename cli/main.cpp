#include "suskeymaster.hpp"
#include <core/log.h>
#include <android/hardware/keymaster/4.0/types.h>
#include <android/hardware/keymaster/4.0/IKeymasterDevice.h>
#include <iomanip>
#include <istream>
#include <utils/StrongPointer.h>
#include <strings.h>
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

static void print_usage(void);
static void print_not_enough_args_for_cmd(const char *cmd);

static int read_file(const char *path, hidl_vec<uint8_t>& out, const char *name);
static int write_file(const char *path, const hidl_vec<uint8_t>& in, const char *name);

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

static void setup_cgd_log(void);

static void check_args(int argc, const char **argv,
        bool *o_should_return, int *o_return_val);
static int dispatch_cmd(int argc, const char **argv);

static int init_g_hal(void);

static const char *g_argv0 = NULL;
static ::android::sp<IKeymasterDevice> g_hal;

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
    hidl_vec<uint8_t> const& get_sus_application_id(void)
    {
        static const hidl_vec<uint8_t> application_id = hidl_vec<uint8_t>(
                { 's', 'u', 's', 'k', 'e', 'y', 'm', 'a', 's', 't', 'e', 'r' }
        );

        return application_id;
    }
}

static void print_usage()
{
    const char *progname = g_argv0 ? g_argv0 : "suskeymaster";

    std::cout << "Usage: " << progname << " <command> <args...>" << std::endl
        << "Available commands:" << std::endl
        << "    generate <algorithm> <out_key_blob>" << std::endl
        << "        Generate a new keypair in KeyMaster and save the resulting key blob" <<
            std::endl
        << std::endl
        << "    attest <key_source> <key_spec>" << std::endl
        << "        Generate a KeyMaster attestation for a given key" << std::endl
        << std::endl
        << "        <key_source> can be either \"generated\" or \"file\"" << std::endl
        << std::endl
        << "        If <key_source> is \"generated\", then <key_spec> must be:" << std::endl
        << "            \"ec\" for an ECDSA key" << std::endl
        << "            \"rsa\" for an RSA key" << std::endl
        << std::endl
        << "        If <key_source> is \"file\", then <key_spec> must be " <<
            "the path to a keymaster key blob file." << std::endl
        << std::endl
        << "    import <in_private_pkcs8> <algorithm> <out_key_blob>" << std::endl
        << "        Imports a PKCS#8 DER-encoded ECDSA or RSA private key <in_private_pkcs8> " <<
            "into the device's keymaster, writing the resulting key blob to <out_key_blob>."
            << std::endl
        << "        <algorithm> must be either \"ec\" or \"rsa\", " <<
            "in accordance to the content of <in_private_pkcs8>."
            << std::endl
        << std::endl
        << "    export <in_keyblob> <out_public_x509>" << std::endl
        << "        Exports the given keymaster key blob <in_keyblob>'s public key " <<
            "to a DER-encoded X.509 certificate <out_public_x509>" << std::endl
        << std::endl
        << "    sign <in_keyblob> <in_message> <out_signature>" << std::endl
        << "        Signs <in_message> with <in_keyblob>, saving the signature to <out_signature>"
        << std::endl
        << std::endl
        << "    mkkeybox <out_keybox> <cmdline1> <cmdline2>" << std::endl
        << "        Creates a new suskeymaster binary keybox file <out_keybox> " <<
            "from the two command lines (for EC and RSA)." << std::endl
        << "        The command lines have the following format:" << std::endl
        << "            <alg> <n_certs> <cert_1> ... <cert_n> <wrapped_key>" << std::endl
        << "        Where:" << std::endl
        << "            <alg> must be either \"ec\" or \"rsa\", depening on which key type " <<
            "the given command line corresponds to." << std::endl
        << "            <n_certs> is the number of certificates in the keybox" << std::endl
        << "            <cert_1> ... <cert_n> are the file paths of the individual " <<
            "DER-encoded X.509 certificate files. They may be quoted if they contain spaces."
        << std::endl
        << "            <wrapped_key> is the file path of the wrapped keymaster key blob " <<
            "which contains the private leaf cert signing key of the given keybox" << std::endl
        << std::endl
        << "        Note: The command lines have to be supplied in quotes if written in a shell."
        << std::endl
        << std::endl
        << "    dumpkeybox <in_keybox> <out_dir_path>" << std::endl
        << "        Dumps the suskeymaster binary keybox file <in_keybox> " <<
            "to the directory <out_dir_path>" << std::endl
        << std::endl
        << std::endl
        << "Examples:" << std::endl
        << "    To generate an ECDSA key and attest it:" << std::endl
        << "    $ " << progname << " attest generated ec" << std::endl
        << std::endl
        << "    To import an RSA private key:" << std::endl
        << "    $ " << progname << " import rsa rsa-private-pkcs8.der keyblob-rsa.bin" << std::endl
        << std::endl
        << "    To generate and save an ECDSA KeyMaster key:" << std::endl
        << "    $ " << progname << " generate ec keyblob-ec.bin" << std::endl
        << std::endl
        << "    To export the public part of an EC key:" << std::endl
        << "    $ " << progname << " export keyblob-ec.bin pubkey.x509" << std::endl
        << std::endl
        << "    To sign a message with a KeyMaster key:" << std::endl
        << "    $ " << progname << " sign keyblob.bin message.txt signature.bin" << std::endl
        << std::endl
        << "    To generate a binary suskeymaster keybox file from certificates and key blobs:"
        << std::endl
        << "    $ " << progname << " mkkeybox keybox.bin " <<
            "'ec 3 cert1-ec.der cert2-ec.der cert3-ec.der key-ec.bin' " <<
            "'rsa 3 cert1-rsa.der cert2-rsa.der cert3-rsa.der key-rsa.der'" << std::endl
        << std::endl
        << "    To dump a binary keybox file to the current working directory:" << std::endl
        << "    $ " << progname << " dumpkeybox keybox.bin ." << std::endl
        << std::endl;
}

static void print_not_enough_args_for_cmd(const char *cmd)
{
    std::cerr << "Not enough arguments for command \"" << cmd << "\"" << std::endl;
    print_usage();
}

static int read_file(const char *path, hidl_vec<uint8_t>& out, const char *name)
{
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        std::cerr << "Failed to open " << name << " \"" << path << "\": "
            << errno << " (" << std::strerror(errno) << ")" << std::endl;
        return 1;
    }

    file.seekg(0, std::ios::end);
    if (file.fail()) {
        std::cerr << "Failed to set the position in " << name << " \"" << path
            << "\" to the end: " << errno << " (" << std::strerror(errno) << ")"
            << std::endl;
        return 1;
    }

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

    std::cout << "Successfully read " << name << " \"" << path << "\"" << std::endl;
    return 0;
}

static int write_file(const char *path, const hidl_vec<uint8_t>& in, const char *name)
{
    std::ofstream file(path, std::ios::binary | std::ios::ate);
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

        if (suskeymaster::generate_key(g_hal, alg, keyblob)) {
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

    return suskeymaster::attest_key(g_hal, keyblob);
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

    if (suskeymaster::import_key(g_hal, priv_key_pkcs8, alg, out_key_blob)) {
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

    if (suskeymaster::export_key(g_hal, key_blob, out_pubkey_x509)) {
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

    if (suskeymaster::sign(g_hal, message, keyblob, signature)) {
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

    if (suskeymaster::generate_key(g_hal, alg, keyblob)) {
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

    return suskeymaster::make_keybox(ec_cert_paths, ec_key_path,
            rsa_cert_paths, rsa_key_path,
            std::string(out)
    );
}

static int handle_cmd_dumpkeybox(const char *in_keybox_path,
        const char *out_dir_path)
{
    return suskeymaster::dump_keybox(in_keybox_path, out_dir_path);
}

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
    } else {
        return -1;
    }
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

static int init_g_hal(void)
{
    g_hal = ::android::hardware::keymaster::V4_0::IKeymasterDevice::tryGetService();
    if (g_hal == nullptr || !g_hal->ping().isOk()) {
        std::cerr << "Couldn't obtain handle to KeyMaster HAL service" << std::endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
