#!/usr/bin/env bash

set -euo pipefail
shopt -s nullglob globstar

echo ""
echo "!!!!! Test failed, dumping proxy log... !!!!!"
echo ""

cat "$HOME/.config/pkcs11proxy.log" || true
cat "./pkcs11proxy.log" || true
cat "$HOME/.config/p11mod.log" || true
cat "./p11mod.log" || true

exit 1
