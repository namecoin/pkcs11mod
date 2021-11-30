#!/usr/bin/env bash

set -euo pipefail
shopt -s nullglob globstar

echo ""
echo "!!!!! Test failed, dumping proxy log... !!!!!"
echo ""

cat "$HOME/pkcs11mod.log"

exit 1
