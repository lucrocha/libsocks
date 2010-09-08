CC = gcc
CFLAGS = -O2 -Wall -ggdb3 -std=gnu99 -fPIC
LDFLAGS = -nostdlib -shared
LDLIBS = -ldl -lc

all: libsocks.so

libsocks.so: socks.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

clean:
	$(RM) socks.o libsocks.so

