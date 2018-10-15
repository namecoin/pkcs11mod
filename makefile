NAME ?= 'libnamecoin.so'
.PHONY: ${NAME}
${NAME}: pkcs11_exported.a
	CGO_ENABLED=1 go build -buildmode c-shared -o ${NAME}
pkcs11_exported.a: pkcs11_exported.o
	ar cru libpkcs11_exported.a pkcs11_exported.o
pkcs11_exported.o:
	gcc -c pkcs11_exported.c
clean:
	rm libnamecoin.h libnamecoin.so pkcs11_exported.a pkcs11_exported.o
