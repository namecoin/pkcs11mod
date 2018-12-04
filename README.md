# pkcs11mod: Go library for creating PKCS#11 modules

pkcs11mod allows you to create PKCS#11 modules in Go.  You implement your PKCS#11 functions by providing a struct that implements the same API as `pkcs11.Ctx` from Miek Gieben's pkcs11 package; pkcs11mod takes care of exposing this as a C ABI library.

## Example usage

First, build pkcs11mod:

~~~
go get -d github.com/namecoin/pkcs11mod
go generate github.com/namecoin/pkcs11mod
go get github.com/namecoin/pkcs11mod
~~~

Then, create a Go program like this:

~~~
package main

import (
	"github.com/miekg/pkcs11"
	"github.com/namecoin/pkcs11mod"
)

func init() {
	backend := pkcs11.New("/usr/lib64/nss/libnssckbi.so")

	pkcs11mod.SetBackend(backend)
}

func main() {}
~~~

In this case, we're simply passing through all PKCS#11 calls to the Mozilla NSS CKBI PKCS#11 module, but you can set `backend` to any struct that implements the same API as `pkcs11.Ctx`.

Then, build your program like this:

~~~
CGO_ENABLED=1 go build -buildmode c-shared -o libmypkcs11module.so
~~~

In this example, your PKCS#11 module will be named `libmypkcs11module.so`.

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
