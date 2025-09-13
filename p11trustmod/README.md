# p11trustmod: high-level Go library for creating PKCS#11 trust databases

p11trustmod allows you to create PKCS#11 trust databases in Go, and is easier to use than p11mod.  You implement your trust database functions by providing a struct that implements the `p11trustmod.Backend` interface; p11trustmod takes care of exposing this as a PKCS#11 module (using p11mod under the hood).

## Building

Prerequisites:

1. Ensure you have the Go tools installed.
2. Build pkcs11mod (see parent directory).
3. You can `import "github.com/namecoin/pkcs11mod/p11trustmod"` from your Go PKCS#11 module.

## Example usage

TODO.

## Tracing

Set the environment variable `P11TRUSTMOD_TRACE=1` to enable debug tracing. To include sensitive data that might be a privacy leak, also set `P11TRUSTMOD_TRACE_SENSITIVE=1`. The trace will be outputted to the log file. Also see the [p11mod tracing](../p11mod/#tracing) documentation.
