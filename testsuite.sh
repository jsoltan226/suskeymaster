#!/bin/sh

SUSKEYMASTER="$(realpath "$1")"
TESTDIR="$2"

run() {
    echo "$*"
    eval "$@" || exit 1
}

getb64() {
    printf $@ | base64 -w0
}

cd "$TESTDIR"

# get-characteristics
echo
echo
echo '>>> get-characteristics'
echo
run '"$SUSKEYMASTER" generate "ALGORITHM=HMAC PURPOSE=SIGN APPLICATION_DATA=$(getb64 "application-data")" hmac-keyblob.bin' || exit 1
run '"$SUSKEYMASTER" get-characteristics hmac-keyblob.bin "APPLICATION_DATA=$(getb64 "application-data")"' || exit 1
run rm hmac-keyblob.bin

# generate
echo
echo
echo '>>> generate'
echo
run '"$SUSKEYMASTER" generate "ALGORITHM=EC PURPOSE=SIGN PURPOSE=VERIFY" rsa-keyblob.bin' || exit 1

# attest file
echo
echo
echo '>>> attest file'
echo '(skip; not supported on KeyMint)'
echo
#run '"$SUSKEYMASTER" attest file rsa-keyblob.bin' # Not supported on KeyMint
#run rm rsa-keyblob.bin

# attest generated
echo
echo
echo '>>> attest generated'
echo
run '"$SUSKEYMASTER" attest generated "ALGORITHM=RSA PURPOSE=SIGN APPLICATION_ID=$(getb64 "application-id")" "APPLICATION_ID=$(getb64 "application-id")"' || exit 1

# import
echo
echo
echo '>>> import'
echo
run 'dd if=/dev/urandom bs=1 count=32 of=aes-key.bin' || exit 1
run '"$SUSKEYMASTER" import aes-key.bin aes-keyblob.bin "ALGORITHM=AES APPLICATION_ID=$(getb64 "aes") PURPOSE=ENCRYPT PURPOSE=DECRYPT"' || exit 1
run '"$SUSKEYMASTER" get-characteristics aes-keyblob.bin "APPLICATION_ID=$(getb64 "aes")"' || exit 1
run rm aes-key.bin

# export
echo
echo
echo '>>> export'
echo '(skip; not supported on KeyMint)'
echo
#run '"$SUSKEYMASTER" generate "ALGORITHM=EC" ec-keyblob.bin' || exit 1
#run '"$SUSKEYMASTER" export ec-keyblob.bin ec-pubkey.x509' || exit 1

# upgrade
echo
echo
echo '>>> upgrade'
echo
run '"$SUSKEYMASTER" generate "ALGORITHM=EC" ec-keyblob.bin' || exit 1
run '"$SUSKEYMASTER" upgrade ec-keyblob.bin ec-keyblob-upgraded.bin # || exit 1'

run rm -f ec-keyblob-upgraded.bin
#run rm ec-pubkey.x509
run rm ec-keyblob.bin

# crypto encrypt & decrypt
echo
echo
echo '>>> crypto encrypt & decrypt'
echo
echo "message.txt" > message.txt
run '"$SUSKEYMASTER" crypto encrypt aes-keyblob.bin message.txt message-encrypted.bin "APPLICATION_ID=$(getb64 "aes") BLOCK_MODE=GCM" message-iv.bin' || exit 1
echo
run '"$SUSKEYMASTER" crypto decrypt aes-keyblob.bin message-encrypted.bin message-decrypted.txt "APPLICATION_ID=$(getb64 "aes") BLOCK_MODE=GCM NONCE=$(base64 -w0 message-iv.bin)"' || exit 1
run 'diff message.txt message-decrypted.txt' || exit 1
run rm message-decrypted.txt message-iv.bin message-encrypted.bin
run rm aes-keyblob.bin

# crypto sign & verify
echo
echo
echo '>>> crypto sign & verify'
echo
run '"$SUSKEYMASTER" generate "ALGORITHM=EC PURPOSE=SIGN PURPOSE=VERIFY DIGEST=SHA_2_256" ec-keyblob.bin' || exit 1
echo
run '"$SUSKEYMASTER" crypto sign ec-keyblob.bin message.txt signature.bin "DIGEST=SHA_2_256"' || exit 1
echo
run '"$SUSKEYMASTER" crypto verify ec-keyblob.bin message.txt signature.bin "DIGEST=SHA_2_256"' || exit 1

run rm message.txt signature.bin
run rm ec-keyblob.bin


echo
echo
echo 'OK'
echo
cd -
