all: test

test: test.c cryptolib.c cryptolib.h Makefile
	gcc -m32 -Wall -o test test.c cryptolib.c -lcrypto
