# suskeymaster

A toolkit for interacting with and subverting Android KeyMaster/KeyMint HALs. Consists of a runtime HAL hook that intercepts and replaces attestation certificate chains on the fly, and a CLI for general-purpose Keymaster/KeyMint operations.

> **Disclaimer:** This software is intended for security research, firmware development, and forensic/data recovery purposes on devices you own or have explicit authorization to modify. Spoofing hardware attestation may violate terms of service of applications that rely on it. Use responsibly.

This project is licensed under the [Apache 2.0 license](LICENSE), except for files under libsuscertmod/external and any files explicitly stating a different license.

---

## Components

### `libsuscertmod`
Core library shared by the hook and CLI. Handles X.509 leaf cert parsing, leaf cert generation and signing, and keybox management. Depends on OpenSSL - for the android (aarch64) target it's linked with a static `libcrypto.a` prebuilt, which can be found under `libsuscertmod/external/`.
The library is OpenSSL's `libcrypto` implementation, version 4.0, compiled with `aarch64-linux-android34-clang` from the Android NDK r27c, configured using the command line in `openssl-config-cmdline.txt`.
On host targets it just links to the system `libcrypto`.

### `libsuskmhal`
KeyMaster/KeyMint HAL abstraction layer. Supports both HIDL (KeyMaster 3.0, 4.0, 4.1) and AIDL (KeyMint 1.0, 2.0, 3.0) transports. Implements its own binder/parcel serialization down to the `ioctl` level - no dependency on `libbinder` or any AOSP compnents.

### `libsuskeymaster` - the HAL hook
A shared library injected into the KeyMaster/KeyMint HAL process. Hooks the attestation callback to intercept outgoing certificate chains and replace them with ones signed by keys from a user-supplied keybox. See [Installation](#installation) below.

### `cli` - `suskeymaster` binary
Standalone command-line tool exposing KeyMaster/KeyMint operations and keybox utilities. Some commands require an on-device HAL connection; others (keybox manipulation, cert wrapping, attestation verification) run on a host Linux/Windows build.
The CLI, apart from strictly Keymaster/KeyMint operations, also includes utilities for decrypting Android userdata encryption keys (DE and CE), as well as some other tools. Only Gatekeeper authentication is supported for now, but Weaver support is coming soon. Note that this feature is only really tested on older devices running Keymaster (Android 9, Samsung's Android 14) - it might not fully work yet on newer devices with KeyMint.

---

## Architecture

```
                    ┌──────────────────────────────────────┐
                    │        Keymaster HAL process         │
                    │                                      │
  attestation  ───► │ attestKey callback ──► sus_attest_cb │ (patched branch)
  response          │                              │       │
                    └──────────────────────────────┼───────┘
                                                   │
                                          libsuskeymaster.so
                                                   │
                                          libsuscertmod
                                          (parse leaf, resign,
                                           swap chain from keybox)
                                                   │
                                           modified cert chain
                                           returned to caller
```

```
  suskeymaster CLI
        │
        ├── libsuskmhal  (HIDL/AIDL transport, binder ioctls)
        │       └── talks directly to /dev/hwbinder or /dev/binder
        │
        └── libsuscertmod  (keybox, cert ops - no HAL needed)
```

---

## Keybox

A keybox is a binary file containing two signing key entries (EC and RSA), each paired with a certificate chain. The hook loads the active keybox at attestation time and uses it to sign the generated leaf cert and assemble the replacement chain.

Keybox commands run on both host and device.

```
suskeymaster mkkeybox <out_keybox> \
    "ec <n_certs> <cert_1.der> ... <cert_n.der> <ec_keyblob>" \
    "rsa <n_certs> <cert_1.der> ... <cert_n.der> <rsa_keyblob>"

suskeymaster dumpkeybox <in_keybox> <out_dir>
```

Key blobs referenced in the keybox are KeyMaster-wrapped blobs (output of `suskeymaster generate` or `suskeymaster import`).

---

## Building
The Android NDK is required to compile the android binaries. For the host target, gcc and clang are tested on linux and x86_64-w64-mingw32-gcc is tested for windows.
The Build environment is obviously Linux, though you might have some luck with MSYS2 on Windows or other UNIX-like OSes, such as MacOS.

### Android target - full CLI and libsuskeymaster hook
```sh
export CC=/path/to/android-ndk/bin/clang
export CXX=/path/to/android-ndk/bin/clang++
export STRIP=/path/to/android-ndk/bin/llvm-strip
make -f Makefile.android clean

make -f Makefile.android -j$(nproc) # Debug build (ASAN, debug symbols)
make -f Makefile.android -j$(nproc) release # Release build (-O3, LTO, stripped)
```

### Host target (linux) - limited CLI
```sh
export CC=gcc
export CXX=g++
export PLATFORM=linux
make -f Makefile.host clean

make -f Makefile.host -j$(nproc) # Debug build
make -f Makefile.host -j$(nproc) release # Release build
```

### Host target (windows) - even more limited CLI
Note: A static version of `libcrypto` and all the mingw tools need to be installed on your system
```sh
export CC=x86_64-w64-mingw32-gcc
export CXX=x86_64-w64-mingw32-g++
export STRIP=x86_64-w64-mingw32-strip
export PLATFORM=windows
make -f Makefile.host clean

make -f Makefile.host -j$(nproc) # Debug build
make -f Makefile.host -j$(nproc) release # Release build
```

## Installation

### Hook (`libsuskeymaster`)

Installation is manual and device-specific. The high-level process:

1. **Build** `libsuskeymaster.so` for the target device's architecture.

2. **Push** the library to the device, e.g. `/vendor/lib64/libsuskeymaster.so`.

3. **Add the library as a dependency** of the KeyMaster/KeyMint HAL binary using `patchelf`:
   ```sh
   patchelf --add-needed libsuskeymaster.so <hal_binary>
   ```

4. **Patch the attestation callback branch** in the HAL binary. Find the call site that invokes the HIDL user callback after attestation and redirect it to `sus_attest_cb` (exported by `libsuskeymaster.so`). This requires disassembly of the HAL binary and manual instruction patching - the exact location is vendor- and version-specific. Also, for now it's only supported/working on my own device configuration - Samsung SKeymaster4device HIDL HAL on Android 14. Integration on other systems and HAL versions is definetly possible but probably requires modifications to the `libsuskeymaster/handler.cpp` hook. The rest of the code is generic and works on any modern device configuration.

5. **Place a keybox** at the path expected by `libsuskeymaster` (`/data/vendor/suskeybox.bin`) and restart the HAL, preferably by rebooting. A "fallback" keybox may also be built into the `libsuskeymaster` library directly, by placing a C hexdump of the binary keybox (`xxd -i`) in `libsuskeymaster/builtin-keybox.c`.

`sus_attest_cb` has the same signature as the original HIDL callback and calls the original after modifying the cert chain, so non-attestation operations are unaffected.

### CLI

Push the `suskeymaster` binary to the device and run it via ADB shell, or run the host build directly on Linux for commands that don't require a HAL connection.
Note: Keymaster/KeyMint HAL operations require root; normally basically only the `keystore2` process has the ability to talk to the Keymaster/KeyMint HAL.

---

## CLI Usage

```
suskeymaster <command> [args]
```

Arguments in `<angle brackets>` are mandatory; `[square brackets]` are optional.

Key parameters (`KEY_PARAMETERS`) are passed as space-separated `TAG=VALUE` pairs, e.g. `ALGORITHM=AES KEY_SIZE=256` or without any `=` for boolean tags (e.g. `NO_AUTH_REQUIRED`).
Blob tags are passed in using base64: `"APPLICATION_ID=$(printf 'app-id' | base64 -w0)"`

`suskeymaster help` will print all the available sub-commands, along with some examples (like the ones below).
Run `suskeymaster help <subcommand>` for more detailed usage info about a given subcommand.

### Key management (on-device)

```sh
# Generate a key
suskeymaster generate <params> <out_key_blob> [out_cert_chain]

# Import a raw or PKCS#8 private key
suskeymaster import <in_private_key> <out_key_blob> [params]

# Export public key (asymmetric) or raw bytes - KeyMaster ≤ 4.1 only
suskeymaster export <in_keyblob> <out_exported> [deserialization_params]

# Print key characteristics
suskeymaster get-characteristics <key_blob> [deserialization_params]

# Upgrade a key blob from an older OS/patch level
suskeymaster upgrade <in_keyblob_to_upgrade> <out_upgraded_keyblob> [upgrade_params]
```

### Attestation (on-device)

```sh
# Generate an ephemeral key and attest it
suskeymaster attest generated [generate_params] [attest_params] [attestation]

# Attest an existing key blob - KeyMaster only
suskeymaster attest file <keyblob> [attest_params] [attestation]
```

### Crypto operations (on-device)

```sh
suskeymaster crypto encrypt <in_key_blob> <in_plaintext> <out_ciphertext> [params] [out_aes_nonce]
suskeymaster crypto decrypt <in_key_blob> <in_ciphertext> <out_plaintext> [params]
suskeymaster crypto sign    <in_key_blob> <in_message>   <out_signature>  [params]
suskeymaster crypto verify  <in_key_blob> <in_message>   <in_signature>   [params]
```

### Secure import / wrapping transaction (KeyMaster >= 4.0)

A two-party protocol for importing a key without it ever appearing in the clear on the device, utilizing the `importWrappedKey` Keymaster/KeyMint method.

```sh
# Client (on-device): generate wrapping key
suskeymaster secure-import target generate <out_keyblob> <out_pubkey> [key_params] [out_attestation]

# Server (host): verify attestation, wrap the key to import
suskeymaster secure-import host verify <attestation>
suskeymaster secure-import host wrap <in_private_key> <in_wrapping_pubkey> \
    <out_wrapped_data> <out_masking_key> [key_params]

# Client (on-device): finalize the import
suskeymaster secure-import target import-wrapped-key <in_wrapped_data> <in_masking_key> \
    <in_wrapping_keyblob> <out_keyblob> [unwrapping_params]
```

### Keybox utilities (host or device)

```sh
suskeymaster mkkeybox <out_keybox> "<ec N cert1 ... certN keyblob>" "<rsa N cert1 ... certN keyblob>"
suskeymaster dumpkeybox <in_keybox> <out_dir>
```

### vold / FBE key recovery (on-device)

```sh
# Derive APPLICATION_ID for a vold key directory
suskeymaster vold gen-appid <in_secdiscardable> [out_appid] [in_auth_secret]

# Decrypt a Device Encrypted (DE) key
suskeymaster vold decrypt-de-key <in_vold_encrypted_key> <in_keyblob> \
    <in_secdiscardable> <out_decrypted_key>

# Decrypt a Credential Encrypted (CE) key from an unwrapped synthetic password blob (See `gatekeeper unwrap-sp-blob`)
suskeymaster vold decrypt-ce-key <in_synthetic_password> <sp_blob_ver> \
    <in_encrypted_key> <out_decrypted_key> [in_secdiscardable]

```
### Install a raw fscrypt key into the kernel keyring; for old devices that don't support the fscrypt ioctls needed by `fscryptctl`  (on-device or linux host)
```suskeymaster vold fscrypt-legacy install-key <in_fscrypt_key>```

### Gatekeeper authentication / Synthetic Password (on-device)

```sh
# Dump a synthetic password data (.pwd) file
suskeymaster gatekeeper dump-pwd-data <in_pwd_file>

# Verify a user credential via Gatekeeper
suskeymaster gatekeeper verify <user_id> <in_pwd_file> [credential_base64]

# Unwrap a synthetic password blob using lockscreen credentials
suskeymaster gatekeeper unwrap-sp-blob <user_id> <in_keystore_key_blob> \
    <in_pwd_file> <in_secdiscardable> <in_spblob> <in_null_handle> \
    <out_decrypted_blob> [credential_base64]

# Unwrap a synthetic password blob for a user with no lockscreen set
suskeymaster noauth unwrap-sp-blob <in_keystore_key_blob> \
    <in_secdiscardable> <in_spblob> <out_decrypted_blob>
```

### Samsung-specific

```sh
# Inspect/modify tags on a Samsung encrypted key blob
suskeymaster samsung ekey list-tags <in_keyblob>
suskeymaster samsung ekey add-tags  <in_keyblob> <out_keyblob> <tags>
suskeymaster samsung ekey del-tags  <in_keyblob> <out_keyblob> <tags>
```

---

## HAL version support

| HAL | Transport | Support |
|-----|-----------|-----------|
| Keymaster 2.0 and below | Passthrough | No |
| Keymaster 3.0 | HIDL | Yes |
| Keymaster 4.0 | HIDL | Yes |
| Keymaster 4.1 | HIDL | Yes |
| KeyMint 1.0 | AIDL | Yes |
| KeyMint 2.0 | AIDL | Yes |
| KeyMint 3.0 | AIDL | Yes |
| KeyMint 4.0 | AIDL | Yes |

Note: Some CLI commands are restricted by HAL version (e.g. `export` and `attest file` don't exist on KeyMint; `secure-import` (`importWrappedKey`) requires KeyMint or KeyMaster >= 4.0).

StrongBox support is coming soon.

### Authentication HALs

| HAL | Transport | Support |
|:-----|-----------|---------|
| Gatekeeper | HIDL | Yes |
|            | AIDL | No |
| Weaver | HIDL | No |
|        | AIDL | No |

---

## Dependencies

- **The Android NDK compiler** for android build, or standard Clang/GCC for host build
- **`make`**
- **OpenSSL** - used by `libsuscertmod` for cert parsing and signing; prebuilt in `libsuscertmod/external`
- A disassembler (e.g. Ghidra, IDA, Binary Ninja) for locating the attestation callback call site in the HAL binary
- patchelf (or other ELF .so patching tools) - for hook installation
