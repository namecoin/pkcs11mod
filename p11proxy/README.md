# p11proxy

p11proxy is a usage example for p11mod.  It simply passes through all PKCS#11 calls to another PKCS#11 module.  In the real world, you would set `backend` to a struct of your own creation that implements the same API as `p11.Module`.

## Building

1. Build pkcs11mod (see parent directory).
2. `CGO_ENABLED=1 go build -buildmode c-shared -o libp11proxy.so`
    * If building for a Windows target, replace `libp11proxy.so` with `p11proxy.dll`

## Usage

Set the `P11PROXY_CKBI_TARGET` environment variable to the PKCS#11 module that will be proxied to.  If this variable is unset or empty, the default is `/usr/lib64/nss/libnssckbi.so` (the Mozilla NSS CKBI PKCS#11 module).
