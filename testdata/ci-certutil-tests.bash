#!/usr/bin/env bash

set -euo pipefail
shopt -s nullglob globstar

export PKCS11PROXY_CKBI_TARGET="$CI_BAK_MODULE"
export P11PROXY_CKBI_TARGET=$PKCS11PROXY_CKBI_TARGET

echo "===== init DB ====="

ln -s -T "$CI_MAIN_MODULE" ./libnssckbi.so
certutil -N -d . --empty-password

echo "===== list all (default) ====="

certutil -L -d . -h all | tee list-all-default.txt || true
grep -q ",C," list-all-default.txt

testdata/assert-proxy-log.bash missing

echo "===== list all (via pkcs11proxy) ====="

mv "$CI_MAIN_MODULE" "$CI_BAK_MODULE"
cp libpkcs11proxy.so "$CI_MAIN_MODULE"

certutil -L -d . -h all | tee list-all-pkcs11proxy.txt || true
grep -q ",C," list-all-pkcs11proxy.txt

echo "===== list all (diff via pkcs11proxy) ====="

diff list-all-default.txt list-all-pkcs11proxy.txt || testdata/dump-proxy-log-fail.bash
testdata/assert-proxy-log.bash present

echo "===== list all (via p11proxy) ====="

cp libp11proxy.so "$CI_MAIN_MODULE"

certutil -L -d . -h all | tee list-all-p11proxy.txt || true
grep -q ",C," list-all-p11proxy.txt

echo "===== list all (diff via p11proxy) ====="

diff list-all-default.txt list-all-p11proxy.txt || testdata/dump-proxy-log-fail.bash
testdata/assert-proxy-log.bash present
