#!/usr/bin/env bash

set -euo pipefail
shopt -s nullglob globstar

export PKCS11PROXY_CKBI_TARGET=/usr/lib64/pkcs11/libsofthsm2.so
export P11PROXY_CKBI_TARGET=$PKCS11PROXY_CKBI_TARGET

echo "===== init slot 0 ====="

SLOT_ID=$(softhsm2-util --init-token --slot 0 --label softhsm --so-pin 1234 --pin 1234 | grep -oE '[^ ]+$')

echo "===== test-all slot 0 (default) ====="

pkcs11-testing --module "$PKCS11PROXY_CKBI_TARGET" --slot "$SLOT_ID" --pin 1234 --test-all | tee test-all-default.txt || true

echo "===== test-all slot 0 (via pkcs11proxy) ====="

pkcs11-testing --module ./libpkcs11proxy.so --slot "$SLOT_ID" --pin 1234 --test-all | tee test-all-pkcs11proxy.txt || true

echo "===== test-all slot 0 (diff via pkcs11proxy) ====="

diff -I '^Modulus: [0-9A-F]\+$' test-all-default.txt test-all-pkcs11proxy.txt || testdata/dump-proxy-log-fail.bash

echo "===== test-rsaimport slot 0 (default) ====="

pkcs11-testing --module "$PKCS11PROXY_CKBI_TARGET" --slot "$SLOT_ID" --pin 1234 --test-rsaimport | tee test-rsaimport-default.txt || true

echo "===== test-rsaimport slot 0 (via p11proxy) ====="

pkcs11-testing --module ./libp11proxy.so --slot "$SLOT_ID" --pin 1234 --test-rsaimport | tee test-rsaimport-p11proxy.txt || true

echo "===== test-rsaimport slot 0 (diff via p11proxy) ====="

diff -I '^Modulus: [0-9A-F]\+$' test-rsaimport-default.txt test-rsaimport-p11proxy.txt || testdata/dump-proxy-log-fail.bash

echo "===== test-rsapub slot 0 (default) ====="

pkcs11-testing --module "$PKCS11PROXY_CKBI_TARGET" --slot "$SLOT_ID" --pin 1234 --test-rsapub | tee test-rsapub-default.txt || true

echo "===== test-rsapub slot 0 (via p11proxy) ====="

pkcs11-testing --module ./libp11proxy.so --slot "$SLOT_ID" --pin 1234 --test-rsapub | tee test-rsapub-p11proxy.txt || true

echo "===== test-rsapub slot 0 (diff via p11proxy) ====="

diff -I '^Modulus: [0-9A-F]\+$' test-rsapub-default.txt test-rsapub-p11proxy.txt || testdata/dump-proxy-log-fail.bash

echo "===== init slot 1 ====="

SLOT_ID=$(softhsm2-util --init-token --slot 1 --label softhsm --so-pin 1234 --pin 1234 | grep -oE '[^ ]+$')

echo "===== test-stability slot 1 (default) ====="

pkcs11-testing --module "$PKCS11PROXY_CKBI_TARGET" --slot "$SLOT_ID" --pin 1234 --test-stability | tee test-stability-default.txt

echo "===== test-stability slot 1 (via pkcs11proxy) ====="

pkcs11-testing --module ./libpkcs11proxy.so --slot "$SLOT_ID" --pin 1234 --test-stability | tee test-stability-pkcs11proxy.txt

echo "===== test-stability slot 1 (diff) ====="

diff test-stability-default.txt test-stability-pkcs11proxy.txt || testdata/dump-proxy-log-fail.bash
