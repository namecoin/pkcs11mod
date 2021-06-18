.PHONY: clean

libpkcs11_exported.a: pkcs11_exported.o
	ar cru libpkcs11_exported.a pkcs11_exported.o
pkcs11_exported.o: spec
	${CC} ${CFLAGS} ${PACKED_CFLAGS} -c pkcs11_exported.c

spec_modules_off:
	mkdir -p spec/
	cp $(shell go env GOPATH)/src/github.com/miekg/pkcs11/*.h spec/

spec_modules_on:
	mkdir -p spec/
	go mod vendor
	cp ./vendor/github.com/miekg/pkcs11/*.h spec/
	rm -rf ./vendor/

ifeq ($(shell go env GO111MODULE),off)
spec: spec_modules_off
else
spec: spec_modules_on
endif

clean:
	rm -vf libpkcs11_exported.a pkcs11_exported.o spec/*.h
	rmdir spec || true

all: clean libpkcs11_exported.a
