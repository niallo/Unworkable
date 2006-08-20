/* $Id: network.c,v 1.13 2006-08-20 21:11:42 niallo Exp $ */
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

#include <ctype.h>
#include <err.h>
#include <event.h>
#include <netdb.h>
#include <sha1.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "bencode.h"
#include "buf.h"
#include "network.h"
#include "parse.h"

char *
network_announce(const char *url, const u_int8_t *infohash, const char *peerid,
    const char *myport, const char *uploaded, const char *downloaded,
    const char *left, const char *compact, const char *event, const char *ip,
    const char *numwant, const char *key, const char *trackerid)
{
	int connfd, i, l;
	size_t n;
	ssize_t nr;
	char host[MAXHOSTNAMELEN], port[6], path[MAXPATHLEN], *c;
	char params[1024], request[1024], buf[128];
	char tbuf[3*SHA1_DIGEST_LENGTH+1];
	BUF *res;

	if ((res = buf_alloc(128, BUF_AUTOEXT)) == NULL) {
		warnx("network_announce: could not allocate response buffer");
		return (NULL);
	}

	/* convert binary info hash to url encoded format */
	for (i = 0; i < SHA1_DIGEST_LENGTH; i++) {
		l = snprintf(&tbuf[3*i], sizeof(tbuf), "%%%02x", infohash[i]);
		if (l == -1 || l >= (int)sizeof(tbuf))
			goto trunc;
	}
#define HTTPLEN 7
	/* separate out hostname, port and path */
	c = strstr(url, "http://");
	c += HTTPLEN;
	n = strcspn(c, ":/") + 1;
	if (n > sizeof(host) - 1)
		goto err;

	if (strlcpy(host, c, n) >= n)
		goto trunc;

	c += n;
	if (*c != '/') {
		n = strcspn(c, "/") + 1;
		if (n > sizeof(port) - 1)
			goto err;

		if (strlcpy(port, c, n) >= n)
			goto trunc;
	} else {
		if (strlcpy(port, "80", sizeof(port)) >= sizeof(port))
			goto trunc;
	}
	c += n - 1;

	if (strlcpy(path, c, sizeof(path)) >= sizeof(path))
		goto trunc;
	/* strip trailing slash */
	if (path[strlen(path) - 1] == '/')
		path[strlen(path) - 1] = '\0';

	/* build params string */
	l = snprintf(params, sizeof(params),
	    "?info_hash=%s"
	    "&peer_id=%s"
	    "&port=%s"
	    "&uploaded=%s"
	    "&downloaded=%s"
	    "&left=%s"
	    "&compact=%s",
	    tbuf,
	    peerid,
	    myport,
	    uploaded,
	    downloaded,
	    left,
	    compact);
	if (l == -1 || l >= (int)sizeof(params))
		goto trunc;
	/* these parts are optional */
	if (event != NULL) {
		l = snprintf(params, sizeof(params), "%s&event=%s\n", params,
		    event);
		if (l == -1 || l >= (int)sizeof(params))
			goto trunc;
	}
	if (ip != NULL) {
		l = snprintf(params, sizeof(params), "%s&ip=%s\n", params,
		    ip);
		if (l == -1 || l >= (int)sizeof(params))
			goto trunc;
	}
	if (numwant != NULL) {
		l = snprintf(params, sizeof(params), "%s&numwant=%s\n", params,
		    numwant);
		if (l == -1 || l >= (int)sizeof(params))
			goto trunc;
	}
	if (key != NULL) {
		l = snprintf(params, sizeof(params), "%s&key=%s\n", params,
		    key);
		if (l == -1 || l >= (int)sizeof(params))
			goto trunc;
	}
	if (trackerid != NULL) {
		l = snprintf(params, sizeof(params), "%s&trackerid=%s\n",
		    params, trackerid);
		if (l == -1 || l >= (int)sizeof(params))
			goto trunc;
	}

	l = snprintf(request, sizeof(request),
	    "GET %s%s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", path,
	    params, host);
	if (l == -1 || l >= (int)sizeof(request))
		goto trunc;

	if ((connfd = network_connect(host, port)) == -1)
		exit(1);
	
	if ((nr = write(connfd, request, strlen(request) + 1)) == -1) {
		warn("network_announce: write");
		goto err;
	}

	while ((nr = read(connfd, buf, sizeof(buf))) != -1 && nr !=0)
		buf_append(res, &buf, nr);

	buf_putc(res, '\0');
	(void) close(connfd);

	return (buf_release(res));

trunc:
	warnx("network_announce: string truncation detected");
err:
	buf_free(res);
	return (NULL);
}

int
network_handle_response(struct torrent *tp, char *res)
{
	struct benc_node *troot;
	char *c;
	BUF *buf;

	if ((buf = buf_alloc(128, BUF_AUTOEXT)) == NULL) {
		warnx("network_handle_response: could not allocate buffer");
		return (-1);
	}
	buf_set(buf, res, strlen(res), 0);

	c = res;
	if (strncmp(c, "HTTP/1.0", 8) != 0 && strncmp(c, "HTTP/1.1", 8)) {
		warnx("network_handle_response: not a valid HTTP response");
		return (-1);
	}
	c += 9;
	if (strncmp(c, "200", 3) != 0) {
		warnx("network_handle_response: HTTP response indicates error");
		return (-1);
	}
	c = strstr(c, "\r\n\r\n");
	if (c == NULL) {
		warnx("network_handle_response: HTTP response had no content");
		return (-1);
	}
	c += 4;
	if ((troot = benc_parse_buf(buf)) == NULL) {
		warnx("network_handle_response: HTTP response parsing failed");
		buf_free(buf);
		return (-1);
	}

	return (0);
}

int
network_connect(const char *host, const char *port)
{
	struct addrinfo hints, *res, *res0;
	int error, sockfd;

	memset(&hints, 0, sizeof(hints));
	/* IPv4-only for now */
	hints.ai_family = PF_INET;
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
