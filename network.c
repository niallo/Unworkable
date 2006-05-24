/* $Id: network.c,v 1.5 2006-05-24 01:24:15 niallo Exp $ */
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "buf.h"
#include "network.h"

int
network_announce(const char *url, const char *infohash, const char *peerid,
    const char *myport, const char *uploaded, const char *downloaded,
    const char *left, const char *compact, const char *event, const char *ip,
    const char *numwant, const char *key, const char *trackerid)
{
	int connfd, l;
	size_t n;
	ssize_t nr;
	char host[MAXHOSTNAMELEN], port[6], path[MAXPATHLEN], *c;
	char params[1024], request[1024], buf[128];
	BUF *res;

	if ((res = buf_alloc(128, BUF_AUTOEXT)) == NULL) {
		warnx("network_announce: could not allocate response buffer");
		return (-1);
	}
#define HTTPLEN 7
	c = strstr(url, "http://");
	c += HTTPLEN;
	n = strcspn(c, ":/") + 1;
	if (n > sizeof(host) - 1)
		goto err;

	strlcpy(host, c, n);
	printf("hostname: %s\n", host);

	c += n;
	if (*c != '/') {
		n = strcspn(c, "/") + 1;
		if (n > sizeof(port) - 1)
			goto err;

		strlcpy(port, c, n);
	} else {
		strlcpy(port, "80", sizeof(port));
	}
	printf("port: %s\n", port);
	c += n - 1;

	strlcpy(path, c, sizeof(path));
	/* strip trailing slash */
	if (path[strlen(path) - 1] == '/')
		path[strlen(path) - 1] = '\0';

	printf("path: %s\n", path);

	if ((connfd = network_connect(host, port)) == -1)
		exit(1);
	
	/* build params string */
	if (strlcpy(params, "?info_hash=", sizeof(params)) >= sizeof(params)
	    || strlcat(params, infohash, sizeof(params)) >= sizeof(params)
	    || strlcat(params, "?peer_id=", sizeof(params)) >= sizeof(params)
	    || strlcat(params, peerid, sizeof(params)) >= sizeof(params)
	    || strlcat(params, "?port=", sizeof(params)) >= sizeof(params)
	    || strlcat(params, myport, sizeof(params)) >= sizeof(params)
	    || strlcat(params, "?uploaded=", sizeof(params)) >= sizeof(params)
	    || strlcat(params, uploaded, sizeof(params)) >= sizeof(params)
	    || strlcat(params, "?downloaded=", sizeof(params)) >= sizeof(params)
	    || strlcat(params, downloaded, sizeof(params)) >= sizeof(params)
	    || strlcat(params, "?left=", sizeof(params)) >= sizeof(params)
	    || strlcat(params, left, sizeof(params)) >= sizeof(params)
	    || strlcat(params, "?compact=", sizeof(params)) >= sizeof(params)
	    || strlcat(params, compact, sizeof(params)) >= sizeof(params))
		errx(1, "network_announce: string truncation detected");
	/* these parts are optional */
	if (event != NULL) {
		if (strlcat(params, "?event=", sizeof(params)) >= sizeof(params)
		    || strlcat(params, event, sizeof(params)) >= sizeof(params))
			errx(1, "network_announce: string truncation detected");
	}
	if (ip != NULL) {
		if (strlcat(params, "?ip=", sizeof(params)) >= sizeof(params)
		    || strlcat(params, ip, sizeof(params)) >= sizeof(params))
			errx(1, "network_announce: string truncation detected");
	}
	if (numwant != NULL) {
		if (strlcat(params, "?numwant=", sizeof(params)) >= sizeof(params)
		    || strlcat(params, numwant, sizeof(params)) >= sizeof(params))
			errx(1, "network_announce: string truncation detected");
	}
	if (numwant != NULL) {
		if (strlcat(params, "?key=", sizeof(params)) >= sizeof(params)
		    || strlcat(params, key, sizeof(params)) >= sizeof(params))
			errx(1, "network_announce: string truncation detected");
	}
	if (trackerid != NULL) {
		if (strlcat(params, "?trackerid=", sizeof(params)) >= sizeof(params)
		    || strlcat(params, trackerid, sizeof(params)) >= sizeof(params))
			errx(1, "network_announce: string truncation detected");
	}
	l = snprintf(request, sizeof(params),
	    "GET %s%s HTTP/1.1\r\nHost: %s\r\n\r\n", path, params, host);
	if (l == -1 || l >= (int)sizeof(request))
		errx(1, "network_announce: snprintf error");
	

	if ((nr = write(connfd, request, strlen(request) + 1)) == -1)
		err(1, "network_announce: write");

	nr = read(connfd, buf, sizeof(buf));
	buf_append(res, &buf, nr);

	/*
	while ((nr = read(connfd, buf, sizeof(buf))) != -1 && nr !=0)
		buf_append(res, buf, nr);
	*/
	buf_write_fd(res, STDOUT_FILENO);

	return (0);

err:
	buf_free(res);
	return (-1);
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
