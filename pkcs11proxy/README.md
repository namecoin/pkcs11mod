# pkcs11proxy

pkcs11proxy is a usage example for pkcs11mod.  It simply passes through all PKCS#11 calls to the Mozilla NSS CKBI PKCS#11 module.  In the real world, you would set `backend` to a struct of your own creation that implements the same API as `pkcs11.Ctx`.

## Building

1. Build pkcs11mod (see parent directory).
2. `CGO_ENABLED=1 go build -buildmode c-shared -o libpkcs11proxy.so`
