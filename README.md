# pkcs11mod: Go library for creating PKCS#11 modules

pkcs11mod allows you to create PKCS#11 modules in Go.  You implement your PKCS#11 functions by providing a struct that implements the same API as `pkcs11.Ctx` from [Miek Gieben's pkcs11 package](https://github.com/miekg/pkcs11); pkcs11mod takes care of exposing this as a C ABI library.

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

Option B: Using Go build commands with Go modules (works on any platform with Bash):

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

See the `pkcs11proxy` subdirectory for an example of how to use pkcs11mod.  Also consider using the higher-level p11mod library (see subdirectory) instead of using pkcs11mod directly (see [this section](#should-i-use-pkcs11mod-or-p11mod)).

## Tracing

Set the environment variable `PKCS11MOD_TRACE=1` to enable debug tracing.  To include sensitive data that might be a privacy leak, also set `PKCS11MOD_TRACE_SENSITIVE=1`.  The trace will be outputted to the log file.

## What's the difference between pkcs11 and pkcs11mod?

Miek Gieben's [pkcs11](https://github.com/miekg/pkcs11) and [p11](https://github.com/miekg/pkcs11/blob/master/p11) packages are for implementing applications that open PKCS#11 modules (e.g. you'd use pkcs11 or p11 if you're creating a web browser that will open a certificate database); pkcs11mod and p11mod are for implementing PKCS#11 modules that are opened by an application (e.g. you'd use pkcs11mod or p11mod if you're creating a certificate database that will be opened by a web browser).

## Should I use pkcs11mod or p11mod?

p11mod is much easier to use and more idiomatic to Go.  However, p11mod implements less of the PKCS#11 specification than pkcs11mod.  If you only need functionality that p11mod has, you will probably find p11mod more pleasant to work with.  On the other hand, p11mod is much newer and less battle-tested, so you may find pkcs11mod more reliable.

## Development focus/status

pkcs11mod is primarily motivated by the use cases that Namecoin has; as such, the PKCS#11 features we've implemented so far are mostly the features used by applications such as NSS's certificate verifier and PKCS#11 modules such as NSS's CKBI (built-in certificates).  We don't have any objection to implementing the rest of the PKCS#11 spec (and we'd happily accept pull requests to this end), but it's unlikely that we'll spend much of our free time on features that aren't relevant to Namecoin.

While we do plan to use pkcs11mod in production in the future, it is not yet used in production, and any horrifying bugs in pkcs11mod probably haven't been noticed by us yet.

## Credits / License

Copyright (C) 2018-2022  Namecoin Developers

pkcs11mod is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 2.1 of the License, or (at your option) any later version.

pkcs11mod is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public
License along with pkcs11mod; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

pkcs11mod is based on:

* https://github.com/miekg/pkcs11
    * BSD 3-Clause License
* https://github.com/Pkcs11Interop/pkcs11-mock
    * Apache 2.0 License
* https://github.com/pipelined/vst2
    * MIT License
