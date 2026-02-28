#include "suskeymaster.hpp"
#include <android/hardware/keymaster/4.0/types.h>
#include <android/hardware/keymaster/4.0/IKeymasterDevice.h>
#include <utils/StrongPointer.h>
#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <ostream>
#include <iostream>

using namespace ::android::hardware::keymaster::V4_0;
using namespace ::android::hardware;

static void print_usage(const char *argv0);
static void print_not_enough_args_for_cmd(const char *argv0, const char *cmd);

static int read_file(const char *path, hidl_vec<uint8_t>& out, const char *name);
static int write_file(const char *path, const hidl_vec<uint8_t>& in, const char *name);

int main(int argc, char **argv)
{
    if (argc < 2) {
        std::cerr << "Not enough arguments!" << std::endl;
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }

    if (!strcmp(argv[1], "help")) {
        print_usage(argv[0]);
        return EXIT_SUCCESS;
    }
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
            print_usage(argv[0]);
            return EXIT_SUCCESS;
        }
    }

    ::android::sp<IKeymasterDevice> hal = IKeymasterDevice::tryGetService();
    if (hal == nullptr || !hal->ping().isOk()) {
        std::cerr << "Couldn't obtain handle to KeyMaster HAL service" << std::endl;
        return EXIT_FAILURE;
    }

    const char *const cmd = argv[1];

    if (!strcmp(cmd, "attest")) {
        if (argc < 4) {
            print_not_enough_args_for_cmd(argv[0], cmd);
            return EXIT_FAILURE;
        }
        const char *const key_source = argv[2];
        const char *const key_specific = argv[3];

        hidl_vec<uint8_t> keyblob;

        if (!strcmp(key_source, "generated")) {
            Algorithm alg;
            if (!strcmp(key_specific, "ec")) {
                alg = Algorithm::EC;
            } else if (!strcmp(key_specific, "rsa")) {
                alg = Algorithm::RSA;
            } else {
                std::cerr << "Invalid key algorithm: " << key_specific << std::endl;
                print_usage(argv[0]);
                return EXIT_FAILURE;
            }

            if (suskeymaster::generate_key(hal, alg, keyblob)) {
                std::cerr << "Failed to generate an " << toString(alg) << " key" << std::endl;
                return EXIT_FAILURE;
            }
        } else if (!strcmp(key_source, "file")) {
            if (read_file(key_specific, keyblob, "keymaster key blob")) {
                std::cerr << "Failed to read the keymaster key blob!" << std::endl;
                return EXIT_FAILURE;
            }
        } else {
            std::cerr << "Invalid key source: " << key_source << std::endl;
            return EXIT_FAILURE;
        }

        return suskeymaster::attest_key(hal, keyblob);

    } else if (!strcmp(cmd, "import")) {
        if (argc < 5) {
            print_not_enough_args_for_cmd(argv[0], cmd);
            return EXIT_FAILURE;
        }

        const char *const alg_str = argv[2];
        const char *const in_priv_key_path = argv[3];
        const char *const out_keyblob_path = argv[4];

        Algorithm alg;
        hidl_vec<uint8_t> priv_key_pkcs8;
        hidl_vec<uint8_t> out_key_blob;

        if (!strcmp(alg_str, "ec"))
            alg = Algorithm::EC;
        else if (!strcmp(alg_str, "rsa"))
            alg = Algorithm::RSA;
        else {
            std::cerr << "Unsupported key algorithm: " << alg_str << std::endl;
            return EXIT_FAILURE;
        }

        if (read_file(in_priv_key_path, priv_key_pkcs8, "PKCS8 private key file")) {
            std::cerr << "Failed to read the PKCS8 private key file!" << std::endl;
            return EXIT_FAILURE;
        }

        if (suskeymaster::import_key(hal, priv_key_pkcs8, out_key_blob, alg)) {
            std::cerr << "Couldn't import private key!" << std::endl;
            return EXIT_FAILURE;
        }

        if (write_file(out_keyblob_path, out_key_blob, "keymaster key blob")) {
            std::cerr << "Failed to write the keymaster key blob!" << std::endl;
            return EXIT_FAILURE;
        }

        return EXIT_SUCCESS;

    } else if (!strcmp(cmd, "export")) {
        if (argc < 4) {
            print_not_enough_args_for_cmd(argv[0], cmd);
            return EXIT_FAILURE;
        }

        const char *const in_keyblob_path = argv[2];
        const char *const out_pubkey_x509_path = argv[3];

        hidl_vec<uint8_t> key_blob;
        hidl_vec<uint8_t> out_pubkey_x509;

        if (read_file(in_keyblob_path, key_blob, "keymaster key blob")) {
            std::cerr << "Failed to read the keymaster key blob!" << std::endl;
            return EXIT_FAILURE;
        }

        if (suskeymaster::export_key(hal, key_blob, out_pubkey_x509)) {
            std::cerr << "Couldn't export keymaster key!" << std::endl;
            return EXIT_FAILURE;
        }

        if (write_file(out_pubkey_x509_path, out_pubkey_x509, "X.509 public key")) {
            std::cerr << "Failed to write the X.509 public key!" << std::endl;
            return EXIT_FAILURE;
        }

        return EXIT_SUCCESS;

    } else if (!strcmp(cmd, "sign")) {
        if (argc < 5) {
            print_not_enough_args_for_cmd(argv[0], cmd);
            return EXIT_FAILURE;
        }

        const char *const in_keyblob_path = argv[2];
        const char *const in_message_path = argv[3];
        const char *const out_signature_path = argv[4];

        hidl_vec<uint8_t> keyblob;
        hidl_vec<uint8_t> message;
        hidl_vec<uint8_t> signature;

        if (read_file(in_message_path, message, "message file")) {
            std::cerr << "Failed to read the message!" << std::endl;
            return EXIT_FAILURE;
        }
        if (read_file(in_keyblob_path, keyblob, "keymaster key blob")) {
            std::cerr << "Failed to read the keymaster key blob!" << std::endl;
            return EXIT_FAILURE;
        }

        if (suskeymaster::sign(hal, message, keyblob, signature)) {
            std::cerr << "Signing operation failed!" << std::endl;
            return EXIT_FAILURE;
        }

        if (write_file(out_signature_path, signature, "signature file")) {
            std::cerr << "Failed to write the signature!" << std::endl;
            return EXIT_FAILURE;
        }

        return EXIT_SUCCESS;

    } else if (!strcmp(cmd, "generate")) {
        if (argc < 4) {
            print_not_enough_args_for_cmd(argv[0], cmd);
            return EXIT_FAILURE;
        }

        const char *const alg_str = argv[2];
        const char *const out_keyblob_path = argv[3];

        Algorithm alg;
        hidl_vec<uint8_t> keyblob;

        if (!strcmp(alg_str, "ec"))
            alg = Algorithm::EC;
        else if (!strcmp(alg_str, "rsa"))
            alg = Algorithm::RSA;
        else {
            std::cerr << "Unsupported key algorithm: " << alg_str << std::endl;
            return EXIT_FAILURE;
        }

        if (suskeymaster::generate_key(hal, alg, keyblob)) {
            std::cerr << "Failed to generate key!" << std::endl;
            return EXIT_FAILURE;
        }

        if (write_file(out_keyblob_path, keyblob, "new KeyMaster key blob")) {
            std::cerr << "Failed to write the new KeyMaster key blob!" << std::endl;
            return EXIT_FAILURE;
        }

        return EXIT_SUCCESS;
    }

    std::cerr << "Unknown command: " << cmd << std::endl;
    print_usage(argv[0]);
    return EXIT_FAILURE;
}

static void print_usage(const char *argv0)
{
    const char *progname = argv0 ? argv0 : "suskeymaster";

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
        << "    import <in_private_pkcs8> <out_key_blob>" << std::endl
        << "        Imports a PKCS#8 DER-encoded ECDSA or RSA private key <in_private_pkcs8> " <<
            "into the device's keymaster, writing the resulting key blob to <out_key_blob>."
            << std::endl
        << std::endl
        << "    export <in_keyblob> <out_public_x509>" << std::endl
        << "        Exports the given keymaster key blob <in_keyblob>'s public key " <<
            "to a DER-encoded X.509 certificate <out_public_x509>" << std::endl
        << std::endl
        << "Examples:" << std::endl
        << "    To generate an ECDSA key and attest it:" << std::endl
        << "    $ " << progname << " attest generated ec" << std::endl
        << std::endl
        << "    To import an RSA private key:" << std::endl
        << "    $ " << progname << " import rsa rsa-private-pkcs8.der keyblob-rsa.bin" << std::endl
        << std::endl
        << "    To generate and save an ECDSA KeyMaster key:" << std::endl
        << "    $ " << progname << " generate rsa keyblob-ec.bin" << std::endl
        << std::endl
        << "    To export a private key:" << std::endl
        << "    $ " << progname << " export key keyblob-ec.bin pubkey.x509" << std::endl
        << std::endl
        << "    To sign a message with a KeyMaster key:" << std::endl
        << "    $ " << progname << " sign message.txt keyblob.bin signature.bin" << std::endl
        << std::endl;
}

static void print_not_enough_args_for_cmd(const char *argv0, const char *cmd)
{
    std::cerr << "Not enough arguments for command \"" << cmd << "\"" << std::endl;
    print_usage(argv0);
}

static int read_file(const char *path, hidl_vec<uint8_t>& out, const char *name)
{
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        std::cerr << "Failed to open " << name << " \"" << path << "\": "
            << errno << " (" << std::strerror(errno) << ")" << std::endl;
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

    std::cout << "Successfully wrote " << name << " \"" << path << "\"" << std::endl;
    return 0;
}
