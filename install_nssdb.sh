#!/bin/sh

# TODO: could use modutil for this instead, which is probably safer.
echo "library=/usr/local/namecoin/libnamecoin.so
name=Namecoin TLS Certificate Trust
NSS=trustOrder=50

" >> "$1/pkcs11.txt"
