#!/usr/bin/env bash

set -euo pipefail
shopt -s nullglob globstar

echo "===== Default p11-kit-trust CKBI ====="

testdata/try-chromium-connect.bash www.namecoin.org success ""
testdata/assert-proxy-log.bash missing

testdata/try-chromium-connect.bash untrusted-root.badssl.com fail ""
testdata/assert-proxy-log.bash missing

echo "===== Deleted p11-kit-trust CKBI ====="

mv /usr/lib64/pkcs11/p11-kit-trust.so /usr/lib64/pkcs11/p11-kit-trust.orig.so

testdata/try-chromium-connect.bash www.namecoin.org fail ""
testdata/assert-proxy-log.bash missing

testdata/try-chromium-connect.bash untrusted-root.badssl.com fail ""
testdata/assert-proxy-log.bash missing

# TODO: No env var, missing default target

# TODO: Env var pointing to missing target

echo "===== p11-kit-trust CKBI via pkcs11proxy ====="

export PKCS11PROXY_CKBI_TARGET=/usr/lib64/pkcs11/p11-kit-trust.orig.so
cp libpkcs11proxy.so /usr/lib64/pkcs11/p11-kit-trust.so

testdata/try-chromium-connect.bash www.namecoin.org success ""
testdata/assert-proxy-log.bash present

testdata/try-chromium-connect.bash untrusted-root.badssl.com fail ""
testdata/assert-proxy-log.bash present
