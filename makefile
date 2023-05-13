CC=gcc
CFLAGS=-Wall -Wextra
LDFLAGS=-lssl -lcrypto

main: enc.c
	$(CC) $(CFLAGS) enc.c -o enc $(LDFLAGS)

clean:
	rm -f enc
