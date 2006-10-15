/* $Id: network.c,v 1.19 2006-10-15 06:36:40 niallo Exp $ */
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
#include "xmalloc.h"

int
network_announce(struct torrent *tp, const char *url, const u_int8_t *infohash,
    const char *peerid, const char *myport, const char *uploaded,
    const char *downloaded, const char *left, const char *compact,
    const char *event, const char *ip, const char *numwant, const char *key,
    const char *trackerid)
{
	int connfd, i, l;
	size_t n;
	ssize_t nr;
	char host[MAXHOSTNAMELEN], port[6], path[MAXPATHLEN], *c;
	char params[2048], request[2048];
	char tbuf[3*SHA1_DIGEST_LENGTH+1];
	struct bufferevent *bufev;

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

	memcpy(host, c, n - 1);
	host[n - 1] = '\0';

	c += n;
	if (*c != '/') {
		n = strcspn(c, "/") + 1;
		if (n > sizeof(port) - 1)
			goto err;

		memcpy(port, c, n - 1);
		port[n - 1] = '\0';
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
		l = snprintf(params, sizeof(params), "%s&event=%s", params,
		    event);
		if (l == -1 || l >= (int)sizeof(params))
			goto trunc;
	}
	if (ip != NULL) {
		l = snprintf(params, sizeof(params), "%s&ip=%s", params,
		    ip);
		if (l == -1 || l >= (int)sizeof(params))
			goto trunc;
	}
	if (numwant != NULL) {
		l = snprintf(params, sizeof(params), "%s&numwant=%s", params,
		    numwant);
		if (l == -1 || l >= (int)sizeof(params))
			goto trunc;
	}
	if (key != NULL) {
		l = snprintf(params, sizeof(params), "%s&key=%s", params,
		    key);
		if (l == -1 || l >= (int)sizeof(params))
			goto trunc;
	}
	if (trackerid != NULL) {
		l = snprintf(params, sizeof(params), "%s&trackerid=%s",
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
	
	bufev = bufferevent_new(connfd, network_handle_response,
	    network_handle_write, network_handle_error, tp);
	bufferevent_enable(bufev, EV_READ);

	if ((nr = write(connfd, request, strlen(request) + 1)) == -1) {
		warn("network_announce: write");
		goto err;
	}
	event_dispatch();

	return (0);

trunc:
	warnx("network_announce: string truncation detected");
err:
	return (-1);
}

void
network_handle_response(struct bufferevent *bufev, void *arg)
{
#define RESBUFLEN 1024
	struct torrent *tp;
	struct benc_node *troot;
	u_char *c, *res;
	BUF *buf;
	size_t len;

	res = xmalloc(RESBUFLEN);
	memset(res, '\0', RESBUFLEN);
	len = bufferevent_read(bufev, res, RESBUFLEN);

	tp = arg;

	troot = benc_node_create();
	troot->flags = BLIST;

	if ((buf = buf_alloc(128, BUF_AUTOEXT)) == NULL) {
		warnx("network_handle_response: could not allocate buffer");
		xfree(res);
		return;
	}

	c = res;
	if (strncmp(c, "HTTP/1.0", 8) != 0 && strncmp(c, "HTTP/1.1", 8)) {
		warnx("network_handle_response: not a valid HTTP response");
		goto err;
	}
	c += 9;
	if (strncmp(c, "200", 3) != 0) {
		warnx("network_handle_response: HTTP response indicates error");
		goto err;
	}
	c = strstr(c, "\r\n\r\n");
	if (c == NULL) {
		warnx("network_handle_response: HTTP response had no content");
		goto err;
	}
	c += 4;
	buf_set(buf, c, len - (c - res), 0);
	troot = benc_root_create();
	if ((troot = benc_parse_buf(buf, troot)) == NULL) {
		warnx("network_handle_response: HTTP response parsing failed");
		goto err;
	}
	benc_node_print(troot, 0);
err:
	xfree(res);
	buf_free(buf);
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
		warnx("network_connect: %s", gai_strerror(error));
		return (-1);
	}
	/* assume first address is ok */
	res = res0;
	sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
	if (sockfd == -1) {
		warn("network_connect: socket");
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
network_handle_error(struct bufferevent *bufev, short what, void *data)
{


}

void
network_handle_write(struct bufferevent *bufev, void *data)
{

}

void
network_init()
{

	event_init();


}
