/*
 * The MIT License
 *
 * Copyright (c) 2010 Luciano Rocha
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#define _GNU_SOURCE 1

#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <dlfcn.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>

/* SOCKS v4 client request message */
struct __attribute__ ((__packed__)) socks4_request {
	uint8_t s4_version;
	uint8_t s4_command;
	uint16_t s4_port;
	uint32_t s4_addr;
	uint8_t s4_user;
};

/* SOCKS v4 connect template */
const struct socks4_request template = {
	.s4_version = 0x04, /* version 4 */
	.s4_command = 0x01, /* establish TCP connection */
	.s4_user = 0x00, /* null-terminated user ID */
};

/* SOCKS v4 server response message */
struct __attribute__ ((__packed__)) socks4_response {
	uint8_t s4_null1;
	uint8_t s4_status;
	uint16_t s4_null2;
	uint32_t s4_null4;
};

#define SOCKS4_REQUEST_GRANTED 0x5a

/* list of addresses to try for the socks server; won't interfere if empty */
static struct addrinfo *socks_server;

/* pointer to real connect(2) function, initialized at library loading time, at
 * _init() */
static int (*real_connect)(int, const struct sockaddr *, socklen_t);

void _init(void)
{
	/* get real connect(2)'s address */
	real_connect = dlsym(RTLD_NEXT, "connect");

	/* NULL can be the real address for a symbol, and dlerror() should
	 * be used for proper error checking, but if connect is NULL then
	 * we can't proceed anyway
	 */

	if (!real_connect)
		abort();

	const char *socks_host = getenv("SOCKS_SERVER");
	if (!socks_host)
		return;

	const char *socks_port = getenv("SOCKS_PORT");
	if (!socks_port)
		socks_port = "socks";

	struct addrinfo hints = {
		.ai_family = AF_INET,
		.ai_socktype = SOCK_STREAM,
	};

	getaddrinfo(socks_host, socks_port, &hints, &socks_server);
}

static int do_complete_send(int s, const void *data, int len)
{
	while (len > 0) {
		int r = send(s, data, len, 0);

		if (r < 0 && errno != EINTR && errno != EAGAIN)
			return -1;

		if (r > 0) {
			len -= r;
			data += r;
		}
	}

	return 0;
}

static int do_complete_recv(int s, void *data, int len)
{
	while (len > 0) {
		int r = recv(s, data, len, 0);

		if (r < 0 && errno != EINTR && errno != EAGAIN)
			return -1;

		if (r == 0)
			break;

		if (r > 0) {
			len -= r;
			data += r;
		}
	}

	return len != 0;
}

int connect(int s, const struct sockaddr *_in, socklen_t len)
{
	int saved_errno = errno;

	if (	!socks_server
		/* invalid socket? */
		|| s < 0
		/* no sockaddr structure? */
		|| !_in
		/* empty or invalid sockaddr? */
		|| len < sizeof(struct sockaddr)
		/* wrong protocol? */
		|| _in->sa_family != AF_INET
		)
		goto pass;

	const struct sockaddr_in *sa = (const struct sockaddr_in *) _in;

	/* ignore if connecting to broadcast, multicast, localhost, ... */
	in_addr_t ip = sa->sin_addr.s_addr;

	if (ip == INADDR_ANY
		|| ip == INADDR_BROADCAST
		|| IN_MULTICAST(ip)
		|| ( (ntohl(ip) >> 24) == 127 )
	   )
		goto pass;

	/* check domain and type of socket, only ipv4/tcp is supported */
	int opt = -1;
	socklen_t optlen = sizeof(opt);

	if (getsockopt(s, SOL_SOCKET, SO_TYPE, &opt, &optlen) < 0
		|| optlen != sizeof(opt)
		|| opt != SOCK_STREAM)
		goto pass;

	opt = -1;
	optlen = sizeof(opt);

	if (getsockopt(s, SOL_SOCKET, SO_DOMAIN, &opt, &optlen) < 0
		|| optlen != sizeof(opt)
		|| opt != AF_INET)
		goto pass;

	/* use socks proxy */

	/* store current flags */
	long flags = fcntl(s, F_GETFL);
	/* and disable non-blocking behaviour */
	fcntl(s, F_SETFL, flags & ~O_NONBLOCK);

	struct addrinfo *server = socks_server;
	while (server && real_connect(s, server->ai_addr, server->ai_addrlen))
		server = server->ai_next;

	if (!server)
		/* failed */
		goto error;

	/* connected, ask SOCKS server for connection */
	struct socks4_request message = template;
	message.s4_port = sa->sin_port;
	message.s4_addr = ip;

	if (do_complete_send(s, &message, sizeof(message)))
		goto error;

	struct socks4_response response;
	if (do_complete_recv(s, &response, sizeof(response)))
		goto error;

	/* negotiation OK, check if allowed */
	if (response.s4_status != SOCKS4_REQUEST_GRANTED)
		goto error;

	/* OK: restore flags and return OK */
	fcntl(s, F_SETFL, flags);
	return 0;

error:

	saved_errno = errno ? errno : ECONNREFUSED;

	fcntl(s, F_SETFL, flags);
	shutdown(s, SHUT_RDWR);

	errno = saved_errno;
	return -1;

pass:
	errno = saved_errno;
	return real_connect(s, _in, len);
}
