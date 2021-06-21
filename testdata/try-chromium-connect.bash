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

# TODO: Nuke whatever cached state might exist...

rm -f screenshot.png

# Disable sandbox because Chromium doesn't support running the sandbox as root,
# and the Cirrus container runs as root.
chromium-browser --no-sandbox --headless --screenshot=./screenshot.png "https://$SERVER_HOST" 2>&1 | tee log.txt
TEXTOUT=$(cat log.txt)

if echo "$TEXTOUT" | grep -q "SSL error"
then
    RESULT=fail
else
    RESULT=success
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
