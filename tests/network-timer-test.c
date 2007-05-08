/* $Id: network-timer-test.c,v 1.2 2007-05-08 19:42:07 niallo Exp $ */
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
#include <sys/queue.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <ctype.h>
#include <err.h>
#include <event.h>
#include <fcntl.h>
#include <netdb.h>
#include <sha1.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "includes.h"

/* data associated with a bittorrent session */
struct session {
	/* don't expect to have huge numbers of peers, or be searching very often, so linked list
	 * should be fine for storage */
	TAILQ_HEAD(peers, peer) peers;
	int connfd;
	char *key;
	char *ip;
	char *numwant;
	char *peerid;
	char *port;
	char *trackerid;
	char *request;
	struct event announce_event;

	struct torrent *tp;
};

static int	network_announce(struct session *, const char *);
static void	network_announce_update(int, short, void *);
static void	network_handle_announce_response(struct bufferevent *, void *);
static void	network_handle_announce_error(struct bufferevent *, short, void *);
static void	network_handle_write(struct bufferevent *, void *);
static int	network_connect(int, int, int, const struct sockaddr *,
		    socklen_t);
static int	network_connect_tracker(const char *, const char *);

static int
network_announce(struct session *sc, const char *event)
{
	struct bufferevent *bufev;
	char *host = "localhost";
	char *port = "8080";
	char *request = "GET /announce?info_hash=%c6%7d%02%e7%3f%e6%cb%8e%31%c3%43%6c%70%60%8c%bf%f3%fd%71%7d&peer_id=U1234567891234567890&port=6668&uploaded=0&downloaded=0&left=0&compact=1 HTTP/1.1\r\nHost: localhost\t\nConnection: close\r\n\r\n";
	/* non blocking connect ? */
	if ((sc->connfd = network_connect_tracker(host, port)) == -1)
		exit(1);
	
	bufev = bufferevent_new(sc->connfd, network_handle_announce_response,
	    network_handle_write, network_handle_announce_error, sc);
	bufferevent_enable(bufev, EV_READ);
	bufferevent_write(bufev, request, strlen(request) + 1);
	return (0);
}

static void
network_handle_announce_response(struct bufferevent *bufev, void *arg)
{
#define RESBUFLEN 1024
	u_char *res;
	size_t len;
	struct session *sc;
	struct timeval tv;

	printf("network_handle_announce_response\n");
	/* XXX need to handle case where full response is not yet buffered */
	res = xmalloc(RESBUFLEN);
	memset(res, '\0', RESBUFLEN);
	len = bufferevent_read(bufev, res, RESBUFLEN);
	sc = arg;
	printf("tracker announce completed, sending next one in 5 seconds\n");
	timerclear(&tv);
	tv.tv_sec = 5;
	evtimer_set(&sc->announce_event, network_announce_update, sc);
	evtimer_add(&sc->announce_event, &tv);
	xfree(res);
}

static int
network_connect(int domain, int type, int protocol, const struct sockaddr *name, socklen_t namelen)
{
	int sockfd;

	sockfd = socket(domain, type, protocol);
	if (sockfd == -1) {
		warn("network_connect: socket");
		return (-1);
	}
	if (fcntl(sockfd, F_SETFL, O_NONBLOCK) == -1)
		err(1, "network_connect");
	if (connect(sockfd, name, namelen) == -1) {
		warn("network_connect: connect");
		return (-1);
	}


	return (sockfd);

}
static int
network_connect_tracker(const char *host, const char *port)
{
	struct addrinfo hints, *res, *res0;
	int error, sockfd;

	printf("network_connect_tracker\n");
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
	sockfd = network_connect(res->ai_family, res->ai_socktype,
	    res->ai_protocol, res->ai_addr, res->ai_addrlen);
	freeaddrinfo(res0);

	return (sockfd);
}

static void
network_handle_announce_error(struct bufferevent *bufev, short error, void *data)
{
	struct session *sc = data;

	printf("network error\n");
	if (error & EVBUFFER_TIMEOUT) {
		printf("buffer event timeout");
		bufferevent_free(bufev);
	}
	if (error & EVBUFFER_EOF) {
		printf("EOF on fd %d\n", sc->connfd);
		bufferevent_disable(bufev, EV_READ|EV_WRITE);
		bufferevent_free(bufev);
		close(sc->connfd);
	}
}

static void
network_handle_write(struct bufferevent *bufev, void *data)
{
	struct session *sc = data;

	printf("network_handle_write\n");
}

static void
network_announce_update(int fd, short type, void *arg)
{
	struct session *sc = arg;
	struct timeval tv;

	printf("network_announce_update\n");
	network_announce(sc, NULL);
	timerclear(&tv);
	tv.tv_sec = 5;
	evtimer_set(&sc->announce_event, network_announce_update, sc);
	evtimer_add(&sc->announce_event, &tv);
}

int
main(int argc, char **argv)
{
	int ret;
	struct session *sc;
	struct timeval tv;

	event_init();

	sc = xmalloc(sizeof(*sc));
	memset(sc, 0, sizeof(*sc));

	TAILQ_INIT(&sc->peers);
	sc->port = xstrdup("6668");
	sc->peerid = xstrdup("U1234567891234567890");

	network_announce(sc, "started");
	event_dispatch();

	return (ret);
}

