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

# Nuke whatever cached state might exist...
rm -rf ~/.mozilla

if timeout 10 firefox --screenshot "https://$SERVER_HOST" && [[ -e "screenshot.png" ]]
then
    RESULT="success"
    TEXTOUT=""
else
    RESULT="fail"
    # TODO: detect this for real
    TEXTOUT="Certificate error was not overridden"
fi

rm -f screenshot.png

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
