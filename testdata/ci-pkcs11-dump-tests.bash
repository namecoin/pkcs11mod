#!/usr/bin/env bash

set -euo pipefail
shopt -s nullglob globstar

echo "===== Default p11-kit-trust CKBI ====="

export PKCS11PROXY_CKBI_TARGET=/usr/lib64/pkcs11/p11-kit-trust.so

pkcs11-dump info "$PKCS11PROXY_CKBI_TARGET" > orig-info.txt
pkcs11-dump slotlist "$PKCS11PROXY_CKBI_TARGET" > orig-slotlist.txt
pkcs11-dump dump "$PKCS11PROXY_CKBI_TARGET" 18 "" > orig-dump-18.txt || true
pkcs11-dump dump "$PKCS11PROXY_CKBI_TARGET" 19 "" > orig-dump-19.txt || true

echo "===== p11-kit-trust CKBI via pkcs11proxy ====="

# Note: pkcs11-dump paths must have a slash in them, otherwise only the
# standard library paths will be searched.
pkcs11-dump info "./libpkcs11proxy.so" > proxy-info.txt
pkcs11-dump slotlist "./libpkcs11proxy.so" > proxy-slotlist.txt
pkcs11-dump dump "./libpkcs11proxy.so" 18 "" > proxy-dump-18.txt || true
pkcs11-dump dump "./libpkcs11proxy.so" 19 "" > proxy-dump-19.txt || true

echo "===== p11-kit-trust CKBI diff ====="

diff orig-info.txt proxy-info.txt
diff orig-slotlist.txt proxy-slotlist.txt
diff orig-dump-18.txt proxy-dump-18.txt
diff orig-dump-19.txt proxy-dump-19.txt
