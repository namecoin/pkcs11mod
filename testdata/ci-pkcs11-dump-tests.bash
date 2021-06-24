#!/usr/bin/env bash

set -euo pipefail
shopt -s nullglob globstar

echo "===== Default p11-kit-trust CKBI ====="

export PKCS11PROXY_CKBI_TARGET=/usr/lib64/pkcs11/p11-kit-trust.so
export P11PROXY_CKBI_TARGET=/usr/lib64/pkcs11/p11-kit-trust.so

pkcs11-dump info "$PKCS11PROXY_CKBI_TARGET" | tee orig-info.txt
pkcs11-dump slotlist "$PKCS11PROXY_CKBI_TARGET" | tee orig-slotlist.txt
pkcs11-dump dump "$PKCS11PROXY_CKBI_TARGET" 18 "" | tee orig-dump-18.txt || true
pkcs11-dump dump "$PKCS11PROXY_CKBI_TARGET" 19 "" | tee orig-dump-19.txt || true

echo "===== p11-kit-trust CKBI via pkcs11proxy ====="

# Note: pkcs11-dump paths must have a slash in them, otherwise only the
# standard library paths will be searched.
pkcs11-dump info "./libpkcs11proxy.so" | tee pkcs11proxy-info.txt
pkcs11-dump slotlist "./libpkcs11proxy.so" | tee pkcs11proxy-slotlist.txt
pkcs11-dump dump "./libpkcs11proxy.so" 18 "" | tee pkcs11proxy-dump-18.txt || true
pkcs11-dump dump "./libpkcs11proxy.so" 19 "" | tee pkcs11proxy-dump-19.txt || true

echo "===== p11-kit-trust CKBI pkcs11proxy diff ====="

echo "===== info ====="
diff orig-info.txt pkcs11proxy-info.txt
echo "===== slotlist ====="
diff orig-slotlist.txt pkcs11proxy-slotlist.txt
echo "===== dump-18 ====="
diff orig-dump-18.txt pkcs11proxy-dump-18.txt
echo "===== dump-19 ====="
diff orig-dump-19.txt pkcs11proxy-dump-19.txt

echo "===== p11-kit-trust CKBI via p11proxy ====="

# Note: pkcs11-dump paths must have a slash in them, otherwise only the
# standard library paths will be searched.
pkcs11-dump info "./libp11proxy.so" | tee p11proxy-info.txt
pkcs11-dump slotlist "./libp11proxy.so" | tee p11proxy-slotlist.txt
pkcs11-dump dump "./libp11proxy.so" 18 "" | tee p11proxy-dump-18.txt || true
pkcs11-dump dump "./libp11proxy.so" 19 "" | tee p11proxy-dump-19.txt || true

echo "===== p11-kit-trust CKBI p11proxy diff ====="

echo "===== info ====="
diff orig-info.txt p11proxy-info.txt
echo "===== slotlist ====="
diff orig-slotlist.txt p11proxy-slotlist.txt
echo "===== dump-18 ====="
diff orig-dump-18.txt p11proxy-dump-18.txt
echo "===== dump-19 ====="
diff orig-dump-19.txt p11proxy-dump-19.txt
