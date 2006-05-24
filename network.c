/* $Id: network.c,v 1.2 2006-05-24 00:07:05 niallo Exp $ */
/*
 * Copyright (c) 2006 Niall O'Higgins <niallo@unworkable.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <err.h>
#include <event.h>
#include <netdb.h>
#include <string.h>

#include "network.h"

int
network_announce(const char *url, const char *infohash, const char *peerid,
    const char *myport, const char *uploaded, const char *downloaded,
    const char *left, const char *compact, const char *event, const char *ip,
    const char *numwant, const char *key, const char *trackerid)
{
	int connfd;
	size_t n, ret;
	char host[MAXHOSTNAMELEN], port[6], *path, *p, *c;

#define HTTPLEN 7
	c = strstr(url, "http://");
	c += HTTPLEN;
	n = strcspn(c, ":/") + 1;
	if (n > sizeof(host))
		return (-1);
	strlcpy(host, c, n);
	printf("hostname: %s\n", host);

	c += n;
	if (*c != '/') {
		n = strcspn(c, "/") + 1;
		if (n > sizeof(port))
			return (-1);

		strlcpy(port, c, n);
	} else {
		strlcpy(port, "80", sizeof(port));
	}
	printf("port: %s\n", port);

	if ((connfd = network_connect(host, port)) == -1)
		exit(1);
	return (0);
}

int
network_connect(const char *host, const char *port)
{
	struct addrinfo hints, *res, *res0;
	int error, sockfd;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	error = getaddrinfo(host, port, &hints, &res0);
	if (error) {
		warnx("%s", gai_strerror(error));
		return (-1);
	}
	/* assume first address is ok */
	res = res0;
	sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
	if (sockfd == -1) {
		warn("network_tracker_announce: socket");
		return (-1);
	}
	
	if (connect(sockfd, res->ai_addr, res->ai_addrlen) == -1) {
		warn("network_tracker_announce: connect");
		return (-1);
	}

	freeaddrinfo(res0);

	return (sockfd);
}

void
network_loop()
{

	event_init();


}
