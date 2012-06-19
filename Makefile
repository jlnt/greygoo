# === Tweak stuff here ===

# Use OpenSSL crypto implementation in server or embedded crypto lib?
#OPENSSL_IN_SERVER=1

# Compile in debug mode ?
#ENABLE_DEBUG=1

# Set below to disable private key encryption
#OSSL_NOCRYPT=-n

CFLAGS=-I. -Wall -Wextra -Wno-type-limits -O2
#CFLAGS+=-Wno-error -Wshorten-64-to-32 -Wsign-conversion -Wconversion \
#        -Wno-missing-prototypes -Wno-padded

CC=gcc

LD=ld

OPENSSL=openssl

#FORCE32BITS=1

# Compile statically ?
# Modern libc don't work well when compiled statically.
# COMPILE_STATICALLY=1

# === END of Makefile tweaks ===

#LIBS=

.PHONY: all dhparams genrsa tests install clean rmkeys rmrsa rmdh distclean

CLIENT_LIBS:=$(LIBS) -lcrypto

# -static ?
ifdef COMPILE_STATICALLY
CFLAGS+=-static
CLIENT_LIBS+=-ldl
endif

# OpenSSL ?
ifdef OPENSSL_IN_SERVER
CFLAGS+=-DGG_USE_OPENSSL
SERVER_LIBS:=$(LIBS) -lcrypto
endif

# DEBUG ?
ifdef ENABLE_DEBUG
CFLAGS+=-DGG_DEBUG
endif

ifdef FORCE32BITS
CFLAGS+=-m32
GG_LDFLAGS+=--oformat=elf32-i386
endif

all: ggd ggc tests

PUBKEYS=public_keys
PRIVKEYS=private_keys

# Real ("root") keys
RSAPUB_PEM=$(PUBKEYS)/rsa_public_root.pem
RSAPUB_O=$(PUBKEYS)/rsa_public_root.o
RSAPUB_PRECOMP_C=$(PUBKEYS)/rsa_public_precomp_root.c
RSAPUB_PRECOMP_O=$(PUBKEYS)/rsa_public_precomp_root.o

RSAPRIV_PEM=$(PRIVKEYS)/rsa_private_root.pem
RSAPRIV_O=$(PRIVKEYS)/rsa_private_root.o

# Test keys
RSAPUB_TEST_PEM=$(PUBKEYS)/rsa_public_test.pem
RSAPUB_TEST_O=$(PUBKEYS)/rsa_public_test.o
RSAPUB_PRECOMP_TEST_C=$(PUBKEYS)/rsa_public_precomp_test.c
RSAPUB_PRECOMP_TEST_O=$(PUBKEYS)/rsa_public_precomp_test.o

RSAPRIV_TEST_PEM=$(PRIVKEYS)/rsa_private_test.pem
RSAPRIV_TEST_O=$(PRIVKEYS)/rsa_private_test.o

# Diffie-Hellman

DHPARAMS_DER=$(PUBKEYS)/dh_parameters.der
DHPARAMS_O=$(PUBKEYS)/dh_parameters.o

DHPARAMS_PRECOMP_C=$(PUBKEYS)/dh_params_precomp.c
DHPARAMS_PRECOMP_O=$(PUBKEYS)/dh_params_precomp.o

sources := $(wildcard *.c) \
           $(wildcard tools/*.c) \
           $(wildcard ucryptolib/*.c)
objects := $(patsubst %.c,%.o,$(sources))
headers := $(wildcard *.h)

# Compile -tests files with GG_TESTS define. That way we can conditionally
# define functions in headers.
%-tests.o : %-tests.c $(headers) Makefile
	$(CC) -c -DGG_TESTS $(CFLAGS) $< -o $@

# We depend on all headers, not ideal but safe
%.o : %.c $(headers) Makefile
	$(CC) -c $(CFLAGS) $< -o $@

ggc: $(DHPARAMS_O) $(RSAPRIV_O) $(RSAPRIV_TEST_O) ggc.o report.o gg-packet.o \
     gg-crypto-openssl.o gg-utils.o gg-protocol.o gg-protocol-client.o \
     gg-password.o gg-syslog.o
	$(CC) $(CFLAGS) $^ -o $@ $(CLIENT_LIBS)

GGD_OBJECTS=ggd.o report.o gg-packet.o gg-utils.o gg-server.o gg-protocol.o \
            gg-protocol-server.o gg-syslog.o

ifdef OPENSSL_IN_SERVER
GGD_OBJECTS+=gg-crypto-openssl.o gg-password.o $(DHPARAMS_O) \
             $(RSAPUB_O) $(RSAPUB_TEST_O)
else
GGD_OBJECTS+=$(RSAPUB_PRECOMP_O) $(RSAPUB_PRECOMP_TEST_O) \
             $(DHPARAMS_PRECOMP_O) gg-crypto-ucryptolib.o ucryptolib/cryptolib.o
endif

ggd: $(GGD_OBJECTS)
	$(CC) $(CFLAGS) $^ -o $@ $(SERVER_LIBS)

tools/cl-precompute: tools/cl-precompute.o
	$(CC) $(CFLAGS) $^ -o $@ $(CLIENT_LIBS)

tools/gg-keygen: tools/gg-keygen.o gg-password.o gg-utils.o report.o gg-syslog.o
	$(CC) $(CFLAGS) $^ -o $@ -lcrypto

tools/gg-tests: tools/gg-tests.o report.o gg-password.o gg-password-tests.o \
                gg-utils.o gg-utils-tests.o report.o gg-syslog.o
	$(CC) $(CFLAGS) $^ -o $@ -lcrypto

# Key material generation
# This is a serious operation, we make sure that it can't happen automagically
# during a build process

$(DHPARAMS_DER):
	@echo "No DH parameters. Use 'make dhparams' to generate them."
	@false

dhparams:
	$(OPENSSL) dhparam -outform DER -out $(DHPARAMS_DER) -2 1024

$(RSAPUB_PEM): $(RSAPRIV_PEM)

$(RSAPRIV_PEM):
	@echo "No RSA keys. Use 'make genrsa' to generate them."
	@false

$(RSAPUB_TEST_PEM): $(RSAPRIV_TEST_PEM)

$(RSAPRIV_TEST_PEM):
	@echo "No test RSA keys. Use 'make genrsatest' to generate them."
	@false

genrsa: tools/gg-keygen
	@echo "Generating the real (root) Grey Goo key."
	tools/gg-keygen $(OSSL_NOCRYPT) $(RSAPRIV_PEM) $(RSAPUB_PEM)

genrsatest: tools/gg-keygen
	@echo "Generating the testing Grey Goo key."
	tools/gg-keygen $(OSSL_NOCRYPT) $(RSAPRIV_TEST_PEM) $(RSAPUB_TEST_PEM)

# Generate .o files for OpenSSL crypto

$(RSAPRIV_O): $(RSAPRIV_PEM)
	$(LD) $(GG_LDFLAGS) -r -b binary $< -o $@

$(RSAPUB_O): $(RSAPUB_PEM)
	$(LD) $(GG_LDFLAGS) -r -b binary $< -o $@

$(RSAPRIV_TEST_O): $(RSAPRIV_TEST_PEM)
	$(LD) $(GG_LDFLAGS) -r -b binary $< -o $@

$(RSAPUB_TEST_O): $(RSAPUB_TEST_PEM)
	$(LD) $(GG_LDFLAGS) -r -b binary $< -o $@

$(DHPARAMS_O): $(DHPARAMS_DER)
	$(LD) $(GG_LDFLAGS) -r -b binary $< -o $@

# Generate precomputed files for cryptolib (public keys only)

$(RSAPUB_PRECOMP_C): tools/cl-precompute $(RSAPUB_PEM)
	tools/cl-precompute -r $@ $(RSAPUB_PEM) precomputed_rsa_root

$(RSAPUB_PRECOMP_TEST_C): tools/cl-precompute $(RSAPUB_TEST_PEM)
	tools/cl-precompute -r $@ $(RSAPUB_TEST_PEM) precomputed_rsa_test

$(DHPARAMS_PRECOMP_C): tools/cl-precompute $(DHPARAMS_DER)
	tools/cl-precompute -d $@ $(DHPARAMS_DER) precomputed_dh

# tests

tests: tools/gg-tests
	$<

# Clean / install

install:
	install -m755 ggd $(DESTDIR)/usr/sbin
	# Make sure ggc is not readable so that it starts undumpable
	install -m711 ggc $(DESTDIR)/usr/sbin

clean:
	rm -f $(objects) ggd ggc $(DHPARAMS_O) $(RSAPRIV_O) $(RSAPRIV_TEST_O) \
	      $(RSAPUB_O) $(RSAPUB_TEST_O) $(RSAPUB_PRECOMP_C) \
	      $(RSAPUB_PRECOMP_TEST_C) $(RSAPUB_PRECOMP_O) \
	      $(RSAPUB_PRECOMP_TEST_O) $(DHPARAMS_PRECOMP_C) \
	      $(DHPARAMS_PRECOMP_O) tools/cl-precompute \
	      tools/gg-keygen tools/gg-tests

rmrsa: clean
	rm -f $(RSAPRIV_PEM) $(RSAPUB_PEM)

rmrsatest: clean
	rm -f $(RSAPRIV_TEST_PEM) $(RSAPUB_TEST_PEM)

rmdh: clean
	rm -f $(DHPARAMS_DER)

rmkeys: rmrsa rmdh

distclean: clean

