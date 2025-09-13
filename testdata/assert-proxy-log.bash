#!/usr/bin/env bash

set -euo pipefail
shopt -s nullglob globstar

DESIRED="$1"

if [[ "$DESIRED" != "present" ]] && [[ "$DESIRED" != "missing" ]]
then
    echo "Invalid DESIRED value; should be present or missing"
    exit 1
fi

if [[ -e "$HOME/.config/pkcs11proxy.log" ]] || [[ -e "./pkcs11proxy.log" ]] || [[ -e "$HOME/.config/p11mod.log" ]] || [[ -e "./p11mod.log" ]]
then
    RESULT="present"
else
    RESULT="missing"
fi

rm -f "$HOME/.config/pkcs11proxy.log"
rm -f "./pkcs11proxy.log"
rm -f "$HOME/.config/p11mod.log"
rm -f "./p11mod.log"

if [[ "$RESULT" != "$DESIRED" ]]
then
    echo "Log test failed"
    echo "Got $RESULT, wanted $DESIRED"
    exit 1
fi

exit 0
