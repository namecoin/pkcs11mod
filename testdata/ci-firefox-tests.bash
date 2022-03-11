#!/usr/bin/env bash

set -euo pipefail
shopt -s nullglob globstar

echo "===== Default System CKBI ====="

testdata/try-firefox-connect.bash www.namecoin.org success ""
testdata/assert-proxy-log.bash missing

testdata/try-firefox-connect.bash untrusted-root.badssl.com fail "Certificate error was not overridden"
testdata/assert-proxy-log.bash missing

echo "===== Deleted System CKBI ====="

mv "$CI_MAIN_MODULE" "$CI_BAK_MODULE"

testdata/try-firefox-connect.bash www.namecoin.org fail "Certificate error was not overridden"
testdata/assert-proxy-log.bash missing

testdata/try-firefox-connect.bash untrusted-root.badssl.com fail "Certificate error was not overridden"
testdata/assert-proxy-log.bash missing

# TODO: No env var, missing default target

# TODO: Env var pointing to missing target

echo "===== System CKBI via pkcs11proxy ====="

export PKCS11PROXY_CKBI_TARGET="$CI_BAK_MODULE"
cp libpkcs11proxy.so "$CI_MAIN_MODULE"

testdata/try-firefox-connect.bash www.namecoin.org success ""
testdata/assert-proxy-log.bash present

testdata/try-firefox-connect.bash untrusted-root.badssl.com fail "Certificate error was not overridden"
testdata/assert-proxy-log.bash present

echo "===== System CKBI via p11proxy ====="

export P11PROXY_CKBI_TARGET="$CI_BAK_MODULE"
cp libp11proxy.so "$CI_MAIN_MODULE"

testdata/try-firefox-connect.bash www.namecoin.org success ""
testdata/assert-proxy-log.bash present

testdata/try-firefox-connect.bash untrusted-root.badssl.com fail "Certificate error was not overridden"
testdata/assert-proxy-log.bash present
