.PHONY: clean

libpkcs11_exported.a: pkcs11_exported.o
	ar cru libpkcs11_exported.a pkcs11_exported.o
pkcs11_exported.o:
	${CC} -c pkcs11_exported.c

clean:
	rm -vf libpkcs11_exported.a pkcs11_exported.o

all: clean libpkcs11_exported.a
