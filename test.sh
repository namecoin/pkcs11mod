#!/bin/sh

echo "Namecoin PKCS#11 Module Test"
so=./libnamecoin.so

printf '\n\nModule information\n\n'
pkcs11-dump info $so 2>>/dev/null

printf '\n\nTrying to make a key with module\n\n'
ssh-keygen -D $so
#https://docs.fedoraproject.org/en-US/Fedora/26/html/System_Administrators_Guide/sec-SSH_Certificate_PKCS_11_Token.html
