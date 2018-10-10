#!/bin/sh
so=./libnamecoin.so
pkcs11-dump info $so
ssh-keygen -D $so
#https://docs.fedoraproject.org/en-US/Fedora/26/html/System_Administrators_Guide/sec-SSH_Certificate_PKCS_11_Token.html
