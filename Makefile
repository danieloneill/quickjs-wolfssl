QJSPATH=../../quickjs-2021-03-27

CC:=gcc
LD:=ld

#STAGING_DIR=/home/doneill/wndr3700/openwrt/staging_dir
#TARGET_DIR=$(STAGING_DIR)//target-mips_24kc_musl
#TOOLCHAIN_DIR=$(STAGING_DIR)/toolchain-mips_24kc_gcc-12.3.0_musl

#CROSS_CC=$(CROSS_PREFIX)$(CC)
#CROSS_LD=$(CROSS_PREFIX)$(LD)

# Cross compile:
#CFLAGS=-I$(QJSPATH)
#LDFLAGS=$(QJSPATH)/libquickjs.a -lm -ldl -L$(TOOLCHAIN_DIR)/lib -L$(TARGET_DIR)/usr/lib -lwolfssl

# Host compile:
CROSS_CC=$(CC)
CROSS_LD=$(LD)
CFLAGS=-I$(QJSPATH) $(shell pkg-config --cflags wolfssl)
LDFLAGS=$(QJSPATH)/libquickjs.a $(shell pkg-config --libs wolfssl) -lm -ldl

quickjs-wolfssl.so: quickjs-wolfssl.o
	$(CROSS_LD) $(LDFLAGS) -shared -soname quickjs-wolfssl -o quickjs-wolfssl.so quickjs-wolfssl.o
	ln -s quickjs-wolfssl.so libquickjs-wolfssl.so

quickjs-wolfssl.o: quickjs-wolfssl.c
	$(CROSS_CC) $(CFLAGS) -g -c -o quickjs-wolfssl.o quickjs-wolfssl.c

clean:
	rm quickjs-wolfssl.so quickjs-wolfssl.o libquickjs-wolfssl.so

all: quickjs-wolfssl.so
