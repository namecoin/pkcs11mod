#!/usr/bin/env bash

set -euo pipefail
shopt -s nullglob globstar

echo "===== Default System CKBI ====="

testdata/try-tstclnt-connect.bash www.namecoin.org success "" || testdata/dump-proxy-log-fail.bash
testdata/assert-proxy-log.bash missing

testdata/try-tstclnt-connect.bash untrusted-root.badssl.com fail "SEC_ERROR_UNTRUSTED_ISSUER" || testdata/dump-proxy-log-fail.bash
testdata/assert-proxy-log.bash missing

echo "===== Deleted System CKBI ====="

mv "$CI_MAIN_MODULE" "$CI_BAK_MODULE"

testdata/try-tstclnt-connect.bash www.namecoin.org fail "SEC_ERROR_UNKNOWN_ISSUER" || testdata/dump-proxy-log-fail.bash
testdata/assert-proxy-log.bash missing

testdata/try-tstclnt-connect.bash untrusted-root.badssl.com fail "SEC_ERROR_UNTRUSTED_ISSUER" || testdata/dump-proxy-log-fail.bash
testdata/assert-proxy-log.bash missing

# TODO: No env var, missing default target

# TODO: Env var pointing to missing target

echo "===== Nonexistent System CKBI via pkcs11proxy ====="

export PKCS11PROXY_CKBI_TARGET=/usr/lib64/pkcs11/p11-kit-trust.missing.so
cp libpkcs11proxy.so "$CI_MAIN_MODULE"

testdata/try-tstclnt-connect.bash www.namecoin.org fail "SEC_ERROR_UNKNOWN_ISSUER" || testdata/dump-proxy-log-fail.bash
testdata/assert-proxy-log.bash present

testdata/try-tstclnt-connect.bash untrusted-root.badssl.com fail "SEC_ERROR_UNTRUSTED_ISSUER" || testdata/dump-proxy-log-fail.bash
testdata/assert-proxy-log.bash present

echo "===== System CKBI via pkcs11proxy ====="

export PKCS11PROXY_CKBI_TARGET="$CI_BAK_MODULE"
cp libpkcs11proxy.so "$CI_MAIN_MODULE"

testdata/try-tstclnt-connect.bash www.namecoin.org success "" || testdata/dump-proxy-log-fail.bash
testdata/assert-proxy-log.bash present

testdata/try-tstclnt-connect.bash untrusted-root.badssl.com fail "SEC_ERROR_UNTRUSTED_ISSUER" || testdata/dump-proxy-log-fail.bash
testdata/assert-proxy-log.bash present

echo "===== Nonexistent System CKBI via p11proxy ====="

export P11PROXY_CKBI_TARGET=/usr/lib64/pkcs11/p11-kit-trust.missing.so
cp libp11proxy.so "$CI_MAIN_MODULE"

testdata/try-tstclnt-connect.bash www.namecoin.org fail "SEC_ERROR_UNKNOWN_ISSUER" || testdata/dump-proxy-log-fail.bash
testdata/assert-proxy-log.bash present

testdata/try-tstclnt-connect.bash untrusted-root.badssl.com fail "SEC_ERROR_UNTRUSTED_ISSUER" || testdata/dump-proxy-log-fail.bash
testdata/assert-proxy-log.bash present

echo "===== System CKBI via p11proxy ====="

export P11PROXY_CKBI_TARGET="$CI_BAK_MODULE"
cp libp11proxy.so "$CI_MAIN_MODULE"

testdata/try-tstclnt-connect.bash www.namecoin.org success "" || testdata/dump-proxy-log-fail.bash
testdata/assert-proxy-log.bash present

testdata/try-tstclnt-connect.bash untrusted-root.badssl.com fail "SEC_ERROR_UNTRUSTED_ISSUER" || testdata/dump-proxy-log-fail.bash
testdata/assert-proxy-log.bash present
