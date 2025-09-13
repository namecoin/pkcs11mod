// pkcs11mod
// Copyright (C) 2021-2025 Namecoin Developers
//
// pkcs11mod is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 2.1 of the License, or (at your option) any later version.
//
// pkcs11mod is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with pkcs11mod; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

package main

import (
	"io"
	"log"
	"os"

	"github.com/miekg/pkcs11"

	"github.com/namecoin/pkcs11mod"
)

var logfile io.Closer

func init() {
	dir, err := os.UserConfigDir()
	if err != nil {
		log.Printf("error reading config dir (will try fallback): %v", err)

		dir = "."
	}

	f, err := os.OpenFile(dir+"/pkcs11proxy.log", os.O_RDWR|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		log.Printf("error opening file (will try fallback): %v", err)

		dir = "."
		f, err = os.OpenFile(dir+"/pkcs11proxy.log", os.O_RDWR|os.O_CREATE|os.O_APPEND, 0o600)
	}

	if err != nil {
		log.Printf("error opening file (will fallback to console logging): %v", err)
	}

	if err == nil {
		log.SetOutput(f)
		logfile = f
	}

	log.Println("pkcs11proxy: module loading")

	backendPath := os.Getenv("PKCS11PROXY_CKBI_TARGET")
	if backendPath == "" {
		backendPath = "/usr/lib64/nss/libnssckbi.so"
	}

	log.Printf("pkcs11proxy: backend path: %s\n", backendPath)

	backend := pkcs11.New(backendPath)
	if backend == nil {
		return
	}

	pkcs11mod.SetBackend(backend)
}

func main() {}
