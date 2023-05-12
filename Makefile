QJSPATH=../../quickjs-2021-03-27

CC=gcc
LD=ld
CFLAGS=-I$(QJSPATH) $(shell pkg-config --cflags wolfssl)
LDFLAGS=$(QJSPATH)/libquickjs.a $(shell pkg-config --libs wolfssl) -lm -ldl

quickjs-wolfssl.so: quickjs-wolfssl.o
	$(LD) $(LDFLAGS) -shared -soname quickjs-wolfssl -o quickjs-wolfssl.so quickjs-wolfssl.o
	ln -s quickjs-wolfssl.so libquickjs-wolfssl.so

quickjs-wolfssl.o: quickjs-wolfssl.c
	$(CC) $(CFLAGS) -g -c -o quickjs-wolfssl.o quickjs-wolfssl.c

clean:
	rm quickjs-wolfssl.so quickjs-wolfssl.o libquickjs-wolfssl.so

all: quickjs-wolfssl.so
