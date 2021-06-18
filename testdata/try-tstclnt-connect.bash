#!/usr/bin/env bash

set -euo pipefail
shopt -s nullglob globstar

SERVER_HOST="$1"
DESIRED="$2"
TEXTMATCH="$3"

echo "$SERVER_HOST"

if [[ "$DESIRED" != "success" ]] && [[ "$DESIRED" != "fail" ]]
then
    echo "Invalid DESIRED value; should be success or fail"
    exit 1
fi

if TEXTOUT=$(tstclnt -b -D -h "$SERVER_HOST" -Q 2>&1)
then
    RESULT="success"
else
    RESULT="fail"
fi

if [[ "$RESULT" != "$DESIRED" ]]
then
    echo "TLS test failed"
    echo "Got $RESULT, wanted $DESIRED"
    echo "$TEXTOUT"
    exit 1
fi

if ! echo "$TEXTOUT" | grep -q "$TEXTMATCH"
then
    echo "TLS test failed"
    echo "Missing output: $TEXTMATCH"
    echo "$TEXTOUT"
    exit 1
fi

exit 0
