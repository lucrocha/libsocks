libsocks
========

Hijacks tcp/ip connect requests and forwards them through a SOCKS4 proxy.

How to use:

SOCKS_SERVER=localhost SOCKS_PORT=8888 LD_PRELOAD=$PWD/libsocks.so executable
