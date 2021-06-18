# pkcs11mod: Go library for creating PKCS#11 modules

pkcs11mod allows you to create PKCS#11 modules in Go.  You implement your PKCS#11 functions by providing a struct that implements the same API as `pkcs11.Ctx` from Miek Gieben's pkcs11 package; pkcs11mod takes care of exposing this as a C ABI library.

## Building

Prerequisites:

1. Ensure you have the Go tools installed.

Option A: Using Go build commands without Go modules (works on any platform with Bash; will not work on Go 1.17+):

1. Ensure you have the GOPATH environment variable set. (For those not
   familar with Go, setting it to the path to an empty directory will suffice.
   The directory will be filled with build files.)

2. Run `export GO111MODULE=off` to disable Go modules.

3. Run `go get -d -t -u github.com/namecoin/pkcs11mod`. The pkcs11mod source code will be
   retrieved automatically.

4. Run `go generate github.com/namecoin/pkcs11mod`.  Some source code will be generated.

5. Run `go get -t -u github.com/namecoin/pkcs11mod`.  pkcs11mod will build.

6. You can now `import "github.com/namecoin/pkcs11mod"` from your Go PKCS#11 module.

Option B: Using Go build commands with Go modules (works on any platform with Bash:

1. Run the following in the `pkcs11mod` directory to set up Go modules:
   
   ~~~
   go mod init github.com/namecoin/pkcs11mod
   go mod tidy
   go generate ./...
   go mod tidy
   ~~~

2. Place your application's directory as a sibling of the `pkcs11mod` directory.

3. Run the following in your application's directory:
   
   ~~~
   go mod edit -replace github.com/namecoin/pkcs11mod=../pkcs11mod
   go mod tidy
   ~~~

4. You can now `import "github.com/namecoin/pkcs11mod"` from your Go PKCS#11 module.

## Example usage

See the `pkcs11proxy` subdirectory for an example of how to use pkcs11mod.

## Development focus/status

pkcs11mod is primarily motivated by the use cases that Namecoin has; as such, the PKCS#11 features we've implemented so far are mostly the features used by applications such as NSS's certificate verifier and PKCS#11 modules such as NSS's CKBI (built-in certificates).  We don't have any objection to implementing the rest of the PKCS#11 spec (and we'd happily accept pull requests to this end), but it's unlikely that we'll spend much of our free time on features that aren't relevant to Namecoin.

While we do plan to use pkcs11mod in production in the future, it is not yet used in production, and any horrifying bugs in pkcs11mod probably haven't been noticed by us yet.

## Credits / License

Original code Copyright Namecoin Developers 2018.  Licensed under LGPLv3+.

Based on:

* https://github.com/miekg/pkcs11
    * BSD 3-Clause License
* https://github.com/Pkcs11Interop/pkcs11-mock
    * Apache 2.0 License
