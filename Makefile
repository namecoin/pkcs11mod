.PHONY: clean

libpkcs11_exported.a: pkcs11_exported.o
	ar cru libpkcs11_exported.a pkcs11_exported.o
pkcs11_exported.o: spec2
	${CC} ${CFLAGS} ${PACKED_CFLAGS} -c pkcs11_exported.c

spec_modules_off:
	mkdir -p spec/
	cp $(shell go env GOPATH)/src/github.com/miekg/pkcs11/*.h spec/
	cp $(shell go env GOPATH)/src/github.com/miekg/pkcs11/vendor.go spec/vendor.go_

spec_modules_on:
	mkdir -p spec/
	go mod vendor
	cp ./vendor/github.com/miekg/pkcs11/*.h spec/
	cp ./vendor/github.com/miekg/pkcs11/vendor.go spec/vendor.go_
	rm -rf ./vendor/

ifeq ($(shell go env GO111MODULE),off)
spec: spec_modules_off
else
spec: spec_modules_on
endif

spec2: spec
	echo 'package pkcs11mod' > strings.go
	echo '' >> strings.go
	echo 'import "github.com/miekg/pkcs11"' >> strings.go
	echo '' >> strings.go
	echo 'var strCKA = map[uint]string{' >> strings.go
	awk '/#define CKA_/{ print "pkcs11."$$2":\""$$2"\"," }' spec/pkcs11t.h | grep -v CKA_SUB_PRIME_BITS | grep -v CKA_EC_PARAMS >> strings.go
	awk '/CKA_/{ print "pkcs11."$$1":\""$$1"\"," }' spec/vendor.go_ >> strings.go
	echo '}' >> strings.go
	echo '' >> strings.go
	echo 'var strCKO = map[uint]string{' >> strings.go
	awk '/#define CKO_/{ print "pkcs11."$$2":\""$$2"\"," }' spec/pkcs11t.h >> strings.go
	awk '/CKO_/{ print "pkcs11."$$1":\""$$1"\"," }' spec/vendor.go_ >> strings.go
	echo '}' >> strings.go
	echo '' >> strings.go
	echo 'var strCKT = map[uint]string{' >> strings.go
	awk '/CKT_/{ print "pkcs11."$$1":\""$$1"\"," }' spec/vendor.go_ >> strings.go
	echo '}' >> strings.go
	gofmt -s -w strings.go

clean:
	rm -vf libpkcs11_exported.a pkcs11_exported.o spec/*.h spec/*.go_ strings.go
	rmdir spec || true

all: clean libpkcs11_exported.a
