# p11mod: high-level Go library for creating PKCS#11 modules

p11mod allows you to create PKCS#11 modules in Go, and is easier to use and more idiomatic to Go than pkcs11mod.  You implement your PKCS#11 functions by providing a struct that implements the same API as `p11.Module` from [Miek Gieben's p11 package](https://github.com/miekg/pkcs11/tree/master/p11); p11mod takes care of exposing this as a C ABI library (using pkcs11mod under the hood).

## Building

Prerequisites:

1. Ensure you have the Go tools installed.
2. Build pkcs11mod (see parent directory).
3. You can `import "github.com/namecoin/pkcs11mod/p11mod"` from your Go PKCS#11 module.

## Example usage

See the `p11proxy` sibling directory for an example of how to use p11mod.

## Tracing

Set the environment variable `P11MOD_TRACE=1` to enable debug tracing.  The trace will be outputted to the log file.
