# p11proxy

p11proxy is a usage example for p11mod.  It simply passes through all PKCS#11 calls to another PKCS#11 module.  You might find it useful for tracing PKCS#11 calls to a log file.  In the real world, you would set `backend` to a struct of your own creation that implements the same API as `p11.Module`.

## Building

1. Build pkcs11mod (see parent directory).
2. `CGO_ENABLED=1 go build -buildmode c-shared -o libp11proxy.so`
    * If building for a Windows target, replace `libp11proxy.so` with `p11proxy.dll`

## Usage

Set the `P11PROXY_CKBI_TARGET` environment variable to the PKCS#11 module that will be proxied to.  If this variable is unset or empty, the default is `/usr/lib64/nss/libnssckbi.so` (the Mozilla NSS CKBI PKCS#11 module).

### Example Usage with Firefox

1. Find the CKBI PKCS#11 module that Firefox ships with.  Depending on your OS, it is probably called `libnssckbi.so`, `libnssckbi.dylib`, or `nssckbi.dll`.
2. Rename the Firefox CKBI module, e.g. rename `libnssckbi.so` to `libnssckbi.orig.so`.
3. Place the p11proxy module where the Firefox CKBI module was, e.g. rename `libp11proxy.so` to `libnssckbi.so` and put it in the directory where the original module was.
4. Set `P11PROXY_CKBI_TARGET` to the renamed Firefox CKBI module, e.g. `export P11PROXY_CKBI_TARGET=/usr/lib64/nss/libnssckbi.orig.so`.
5. Run Firefox.  If you did it right, certificate validation will work as it did before, but you'll see a log file from p11proxy.
