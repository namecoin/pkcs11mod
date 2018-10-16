// Copyright 2018 Namecoin Developers GPLv3+

package main

// Backend is an interface compatible with pkcs11.Ctx.
type Backend interface {
	Initialize() error
	Finalize() error
}
