#!/usr/bin/env bash

set -euo pipefail
shopt -s nullglob globstar

export PKCS11PROXY_CKBI_TARGET=/usr/lib64/pkcs11/libsofthsm2.so

echo "===== init slot 0 ====="

SLOT_ID=$(softhsm2-util --init-token --slot 0 --label softhsm --so-pin 1234 --pin 1234 | grep -oE '[^ ]+$')

echo "===== test-all slot 0 (default) ====="

pkcs11-testing --module "$PKCS11PROXY_CKBI_TARGET" --slot "$SLOT_ID" --pin 1234 --test-all | tee test-all-default.txt || true

echo "===== test-all slot 0 (via pkcs11proxy) ====="

pkcs11-testing --module ./libpkcs11proxy.so --slot "$SLOT_ID" --pin 1234 --test-all | tee test-all-pkcs11proxy.txt || true

echo "===== test-all slot 0 (diff) ====="

diff -I '^Modulus: [0-9A-F]\+$' test-all-default.txt test-all-pkcs11proxy.txt

echo "===== init slot 1 ====="

SLOT_ID=$(softhsm2-util --init-token --slot 1 --label softhsm --so-pin 1234 --pin 1234 | grep -oE '[^ ]+$')

echo "===== test-stability slot 1 (default) ====="

pkcs11-testing --module "$PKCS11PROXY_CKBI_TARGET" --slot "$SLOT_ID" --pin 1234 --test-stability | tee test-stability-default.txt

echo "===== test-stability slot 1 (via pkcs11proxy) ====="

pkcs11-testing --module ./libpkcs11proxy.so --slot "$SLOT_ID" --pin 1234 --test-stability | tee test-stability-pkcs11proxy.txt

echo "===== test-stability slot 1 (diff) ====="

diff test-stability-default.txt test-stability-pkcs11proxy.txt
