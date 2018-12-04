NAME ?= 'libckbiproxy.so'
.PHONY: ${NAME} clean cleanmoz

# build the shared object
${NAME}:
	go generate github.com/namecoin/ncp11/pkcs11mod
	go get github.com/namecoin/ncp11/pkcs11mod
	CGO_ENABLED=1 go build -buildmode c-shared -o ${NAME}

# install libnamecoin.h and libnamecoin.so to /usr/local/namecoin/
install:
	mkdir -p /usr/local/namecoin
	install libnamecoin.h /usr/local/namecoin/
	install libnamecoin.so /usr/local/namecoin/

clean: cleanmoz
	rm -vf libnamecoin.h libnamecoin.so
cleanmoz:
	rm -rvf moz/web-ext-artifacts

# build extension
moz-ext: cleanmoz
	cd moz && web-ext build


# test-run sandbox firefox
moz-run: cleanmoz
	cd moz && web-ext run --verbose


# install pkcs11 module to mozilla directory (not extension)
moz-install:
	mkdir -p /usr/lib/mozilla/pkcs11-modules/ 
	install moz/namecoin_module.json /usr/lib/mozilla/pkcs11-modules/


all: clean ${NAME} moz-ext
	@echo now run "${MAKE} all-install" to install all (requires root)

# install all the things
install-all: install moz-install
	@echo now the mozilla extension zip file is ready to install on this machine
