###############################################################################
#                  /!\ YOU SHOULD NOT MODIFY THIS FILE! /!\                   #
###############################################################################

BIN = client server mitm

CFLAGS = -Wall -Wno-unused -Wextra -pedantic -std=c99 -g

KEY  = key.pem
CERT = cert.pem
PEM  = $(KEY) $(CERT)

KEYLEN  = 1024
DAYS    = 90
SUBJECT = "/CN=localhost/"


.PHONY: all keys clean clean-all

all: $(BIN) $(PEM)


# Only client and server binaries require OpenSSL library.
client server: %: %.c common.h
	$(CC) $(CFLAGS) $(CPPFLAGS) $< -lssl -lcrypto -o $@

%: %.c common.h
	$(CC) $(CFLAGS) $(CPPFLAGS) $< -o $@


keys $(PEM):
	openssl genrsa -out $(KEY) $(KEYLEN)
	openssl req    -x509 -new -key $(KEY) -out $(CERT) -days $(DAYS) -subj $(SUBJECT)


clean:
	rm -f $(BIN)

clean-all: clean
	rm -f $(PEM)
