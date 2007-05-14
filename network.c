/* $Id: network.c,v 1.85 2007-05-14 00:06:22 niallo Exp $ */
/*
 * Copyright (c) 2006, 2007 Niall O'Higgins <niallo@unworkable.org>
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
#include <errno.h>
#include <event.h>
#include <fcntl.h>
#include <netdb.h>
#include <sha1.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "includes.h"

#define PEER_STATE_HANDSHAKE		(1<<0)
#define PEER_STATE_BITFIELD		(1<<1)
#define PEER_STATE_ESTABLISHED		(1<<2)
#define PEER_STATE_AMCHOKING		(1<<3)
#define PEER_STATE_CHOKED		(1<<4)
#define PEER_STATE_AMINTERESTED		(1<<5)
#define PEER_STATE_INTERESTED		(1<<6)
#define PEER_STATE_ISTRANSFERRING	(1<<7)

#define PEER_MSG_ID_CHOKE		0
#define PEER_MSG_ID_UNCHOKE		1
#define PEER_MSG_ID_INTERESTED		2
#define PEER_MSG_ID_NOTINTERESTED	3
#define PEER_MSG_ID_HAVE		4
#define PEER_MSG_ID_BITFIELD		5
#define PEER_MSG_ID_REQUEST		6
#define PEER_MSG_ID_PIECE		7
#define PEER_MSG_ID_CANCEL		8

#define BLOCK_SIZE			16384 /* 16KB */
#define MAX_BACKLOG			65536 /* 64KB */

#define BIT_SET(a,i)			((a)[(i)/8] |= 1<<(7-((i)%8)))
#define BIT_CLR(a,i)			((a)[(i)/8] &= ~(1<<(7-((i)%8))))
#define BIT_ISSET(a,i)			((a)[(i)/8] & (1<<(7-((i)%8))))
#define BIT_ISCLR(a,i)			(((a)[(i)/8] & (1<<(7-((i)%8)))) == 0)

/* bittorrent peer */
struct peer {
	TAILQ_ENTRY(peer) peer_list;
	struct sockaddr_in sa;
	int connfd;
	int state;
	u_int32_t rxpending;
	u_int32_t txpending;
	struct bufferevent *bufev;
	u_int32_t rxmsglen, piece, block;
	u_int8_t *txmsg, *rxmsg;
	u_int8_t *bitfield;
	/* from peer's handshake message */
	u_int8_t pstrlen;
	u_int8_t id[20];
	u_int8_t info_hash[20];

	struct session *sc;
};

/* data associated with a bittorrent session */
struct session {
	/* don't expect to have huge numbers of peers, or be searching very often, so linked list
	 * should be fine for storage */
	TAILQ_HEAD(peers, peer) peers;
	int connfd;
	int servfd;
	char *key;
	char *ip;
	char *numwant;
	char *peerid;
	char *port;
	char *trackerid;
	char *request;
	struct event announce_event;
	struct event scheduler_event;

	struct torrent *tp;
};

struct piececounter {
	u_int32_t count;
	u_int32_t idx;
};

static int	network_announce(struct session *, const char *);
static void	network_announce_update(int, short, void *);
static void	network_handle_announce_response(struct bufferevent *, void *);
static void	network_handle_announce_error(struct bufferevent *, short, void *);
static void	network_handle_write(struct bufferevent *, void *);
static int	network_connect(int, int, int, const struct sockaddr *,
		    socklen_t);
static int	network_connect_tracker(const char *, const char *);
static int	network_connect_peer(struct peer *);
static void	network_peerlist_update(struct session *, struct benc_node *);
static void	network_peer_handshake(struct session *, struct peer *);
static void	network_peer_write_piece(struct peer *, u_int32_t, off_t, u_int32_t);
static void	network_peer_read_piece(struct peer *, u_int32_t, off_t, u_int32_t, void *);
static void	network_peer_write_bitfield(struct peer *);
static void	network_peer_write_interested(struct peer *);
static void	network_peer_free(struct peer *);
static void	network_handle_peer_connect(struct bufferevent *, short, void *);
static void	network_handle_peer_response(struct bufferevent *, void *);
static void	network_handle_peer_write(struct bufferevent *, void *);
static void	network_handle_peer_error(struct bufferevent *, short, void *);
static void	network_scheduler(int, short, void *);
static struct piececounter *network_session_sorted_pieces(struct session *);
static int	network_session_sorted_pieces_cmp(const void *, const void *);
static int	network_listen(char *, char *);
static void	network_peer_request_piece(struct peer *, u_int32_t, u_int32_t);

static int
network_announce(struct session *sc, const char *event)
{
	int i, l;
	size_t n;
	char host[MAXHOSTNAMELEN], port[6], path[MAXPATHLEN], *c;
#define GETSTRINGLEN 2048
	char *params, *request;
	char tbuf[3*SHA1_DIGEST_LENGTH+1];
	struct bufferevent *bufev;

	params = xmalloc(GETSTRINGLEN);
	request = xmalloc(GETSTRINGLEN);
	memset(params, '\0', GETSTRINGLEN);
	memset(request, '\0', GETSTRINGLEN);

	/* convert binary info hash to url encoded format */
	for (i = 0; i < SHA1_DIGEST_LENGTH; i++) {
		l = snprintf(&tbuf[3*i], sizeof(tbuf), "%%%02x", sc->tp->info_hash[i]);
		if (l == -1 || l >= (int)sizeof(tbuf))
			goto trunc;
	}
#define HTTPLEN 7
	/* separate out hostname, port and path */
	c = strstr(sc->tp->announce, "http://");
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
	l = snprintf(params, GETSTRINGLEN,
	    "?info_hash=%s"
	    "&peer_id=%s"
	    "&port=%s"
	    "&uploaded=%llu"
	    "&downloaded=%llu"
	    "&left=%llu"
	    "&compact=1",
	    tbuf,
	    sc->peerid,
	    sc->port,
	    sc->tp->uploaded,
	    sc->tp->downloaded,
	    sc->tp->left);
	if (l == -1 || l >= GETSTRINGLEN)
		goto trunc;
	/* these parts are optional */
	if (event != NULL) {
		l = snprintf(params, GETSTRINGLEN, "%s&event=%s", params,
		    event);
		if (l == -1 || l >= GETSTRINGLEN)
			goto trunc;
	}
	if (sc->ip != NULL) {
		l = snprintf(params, GETSTRINGLEN, "%s&ip=%s", params,
		    sc->ip);
		if (l == -1 || l >= GETSTRINGLEN)
			goto trunc;
	}
	if (sc->numwant != NULL) {
		l = snprintf(params, GETSTRINGLEN, "%s&numwant=%s", params,
		    sc->numwant);
		if (l == -1 || l >= GETSTRINGLEN)
			goto trunc;
	}
	if (sc->key != NULL) {
		l = snprintf(params, GETSTRINGLEN, "%s&key=%s", params,
		    sc->key);
		if (l == -1 || l >= GETSTRINGLEN)
			goto trunc;
	}
	if (sc->trackerid != NULL) {
		l = snprintf(params, GETSTRINGLEN, "%s&trackerid=%s",
		    params, sc->trackerid);
		if (l == -1 || l >= GETSTRINGLEN)
			goto trunc;
	}

	l = snprintf(request, GETSTRINGLEN,
	    "GET %s%s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", path,
	    params, host);
	if (l == -1 || l >= GETSTRINGLEN)
		goto trunc;

	/* non blocking connect ? */
	if ((sc->connfd = network_connect_tracker(host, port)) == -1)
		exit(1);
	
	sc->request = request;
	bufev = bufferevent_new(sc->connfd, network_handle_announce_response,
	    network_handle_write, network_handle_announce_error, sc);
	bufferevent_enable(bufev, EV_READ);
	if (bufferevent_write(bufev, request, strlen(request) + 1) != 0)
		errx(1, "network_announce: bufferevent_write failure");
	xfree(params);
	return (0);

trunc:
	warnx("network_announce: string truncation detected");
err:
	xfree(params);
	xfree(request);
	return (-1);
}

static void
network_handle_announce_response(struct bufferevent *bufev, void *arg)
{
#define RESBUFLEN 1024
	BUF *buf;
	u_char *c, *res;
	size_t len;
	struct benc_node *node, *troot;
	struct session *sc;
	struct torrent *tp;
	struct timeval tv;
	struct bufferevent *bev;

	printf("network_handle_announce_response\n");
	buf = NULL;
	troot = node = NULL;
	/* XXX need to handle case where full response is not yet buffered */
	res = xmalloc(RESBUFLEN);
	memset(res, '\0', RESBUFLEN);
	len = bufferevent_read(bufev, res, RESBUFLEN);

	sc = arg;
	tp = sc->tp;

	c = res;
	if (strncmp(c, "HTTP/1.0", 8) != 0 && strncmp(c, "HTTP/1.1", 8)) {
		warnx("network_handle_announce_response: not a valid HTTP response");
		goto err;
	}
	c += 9;
	if (strncmp(c, "200", 3) != 0) {
		warnx("network_handle_announce_response: HTTP response indicates error");
		goto err;
	}
	c = strstr(c, "\r\n\r\n");
	if (c == NULL) {
		warnx("network_handle_announce_response: HTTP response had no content");
		goto err;
	}
	c += 4;

	if ((buf = buf_alloc(128, BUF_AUTOEXT)) == NULL) {
		warnx("network_handle_announce_response: could not allocate buffer");
		xfree(res);
		return;
	}
	buf_set(buf, c, len - (c - res), 0);

	troot = benc_root_create();
	if ((troot = benc_parse_buf(buf, troot)) == NULL)
		errx(1,"network_handle_announce_response: HTTP response parsing failed");

	benc_node_print(troot, 0);
	if ((node = benc_node_find(troot, "interval")) == NULL)
		errx(1, "no interval field");

	if (!(node->flags & BINT))
		errx(1, "interval is not a number");

	tp->interval = node->body.number;

	if ((node = benc_node_find(troot, "peers")) == NULL)
		errx(1, "no peers field");
	network_peerlist_update(sc, node);
	benc_node_freeall(troot);

	printf("tracker announce completed, sending next one in %zd seconds\n",
	    tp->interval);
	timerclear(&tv);
	tv.tv_sec = tp->interval;
	evtimer_del(&sc->announce_event);
	evtimer_set(&sc->announce_event, network_announce_update, sc);
	evtimer_add(&sc->announce_event, &tv);
	/* time to set up the server socket */
	sc->servfd = network_listen(NULL, sc->port);
	bev = bufferevent_new(sc->servfd, NULL,
	    NULL, network_handle_peer_connect, sc);
	bufferevent_enable(bev, EV_READ);
	/* now that we've announced, kick off the scheduler */
	timerclear(&tv);
	tv.tv_sec = 1;
	evtimer_set(&sc->scheduler_event, network_scheduler, sc);
	evtimer_add(&sc->scheduler_event, &tv);
err:
	bufferevent_free(bufev);
	buf_free(buf);
	xfree(res);
	(void) close(sc->connfd);
}

static void
network_handle_peer_connect(struct bufferevent *bufev, short error, void *data)
{
	struct session *sc;
	struct peer *p;
	socklen_t addrlen;

	sc = data;
	p = xmalloc(sizeof(*p));
	memset(p, 0, sizeof(*p));

	printf("received an incoming peer connection\n");
	if ((p->connfd = accept(sc->servfd, (struct sockaddr *) &p->sa, &addrlen)) == -1)
		err(1, "network_handle_peer_connect: accept");

	p->bufev = bufferevent_new(p->connfd, network_handle_peer_response,
	    network_handle_peer_write, network_handle_peer_error, p);
	bufferevent_enable(p->bufev, EV_READ|EV_WRITE);
	network_peer_handshake(sc, p);
}

static int
network_listen(char *host, char *port)
{
	int error = 0;
	int fd;
	int option_value = 1;
	struct addrinfo hints, *res;

	if ((fd = socket(PF_INET, SOCK_STREAM, 0)) == -1)
		err(1, "could not create server socket");
	if (fcntl(fd, F_SETFL, O_NONBLOCK) == -1)
		err(1, "network_listen: fcntl");
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_INET;
	hints.ai_socktype = SOCK_STREAM;
	error = getaddrinfo(host, port, &hints, &res);
	if (error != 0)
		errx(1, "\"%s\" - %s", host, gai_strerror(error));
	if (bind(fd, res->ai_addr, res->ai_addrlen) == -1)
		err(1, "could not bind to port %s", port);
	if (listen(fd, MAX_BACKLOG) == -1)
		err(1, "could not listen on server socket");
	freeaddrinfo(res);
	error = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR,
		    &option_value, sizeof(option_value));
	if (error == -1)
		err(1, "could not set socket options");
	return fd;
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
network_connect_peer(struct peer *p)
{
	printf("network_connect_peer\n");
	p->state |= PEER_STATE_HANDSHAKE;
	return (network_connect(PF_INET, SOCK_STREAM, 0,
	    (const struct sockaddr *) &p->sa, sizeof(p->sa)));
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

	if (error & EVBUFFER_TIMEOUT) {
		printf("buffer event timeout");
		bufferevent_free(bufev);
	}
	if (error & EVBUFFER_EOF) {
		bufferevent_free(bufev);
		(void) close(sc->connfd);
	}
}

static void
network_handle_write(struct bufferevent *bufev, void *data)
{
	struct session *sc = data;

	printf("network_handle_write\n");
	xfree(sc->request);
}

static void
network_announce_update(int fd, short type, void *arg)
{
	struct session *sc = arg;
	struct timeval tv;

	printf("network_announce_update\n");
	network_announce(sc, NULL);
	timerclear(&tv);
	tv.tv_sec = sc->tp->interval;
	evtimer_set(&sc->announce_event, network_announce_update, sc);
	evtimer_add(&sc->announce_event, &tv);
}

/* Yes, this is slow.  But peer lists should not be too long, and we shouldn't be running it
   often at all (once per announce, interval is often thousands of seconds).
   So O(n2) should be acceptable worst case. */
static void
network_peerlist_update(struct session *sc, struct benc_node *peers)
{
	char *peerlist;
	size_t len, i;
	struct peer *p, *ep, *nxt;
	int found = 0;

	/* XXX */
	if (!(peers->flags & BSTRING))
		errx(1, "long peer lists not supported yet");

	len = peers->body.string.len;
	peerlist = peers->body.string.value;
	p = NULL;

	printf("network_peerlist_update\n");
	/* check for peers to add */
	for (i = 0; i < len; i++) {
		if (i % 6 == 0) {
			p = xmalloc(sizeof(*p));
			memset(p, 0, sizeof(*p));
			p->sc = sc;
			p->sa.sin_family = AF_INET;
			memcpy(&p->sa.sin_addr, peerlist + i, 4);
			memcpy(&p->sa.sin_port, peerlist + i + 4, 2);
			/* Is this peer already in the list? */
			found = 0;
			TAILQ_FOREACH(ep, &sc->peers, peer_list) {
				/* XXX check for ourselves */
				if (memcmp(&ep->sa.sin_addr, &p->sa.sin_addr, sizeof(ep->sa.sin_addr)) == 0
				    && memcmp(&ep->sa.sin_port, &p->sa.sin_port, sizeof(ep->sa.sin_port)) == 0) {
					found = 1;
					break;
				}
			}
			if (!found)
				TAILQ_INSERT_TAIL(&sc->peers, p, peer_list);
			continue;
		}
	}

	/* check for peers to remove */
	peerlist = peers->body.string.value;
	for (ep = TAILQ_FIRST(&sc->peers); ep != TAILQ_END(&sc->peers); ep = nxt) {
		nxt = TAILQ_NEXT(ep, peer_list);
		for (i = 0; i < len; i++ ) {
			if (i % 6 == 0) {
				p = xmalloc(sizeof(*p));
				memset(p, 0, sizeof(*p));
				memcpy(&p->sa.sin_addr, peerlist + i, 4);
				memcpy(&p->sa.sin_port, peerlist + i + 4, 2);
				/* Is this peer in the new list? */
				found = 0;
				if (memcmp(&ep->sa.sin_addr, &p->sa.sin_addr, sizeof(p->sa.sin_addr)) == 0
				    && memcmp(&ep->sa.sin_port, &p->sa.sin_port, sizeof(p->sa.sin_addr)) == 0) {
					found = 1;
					xfree(p);
					break;
				}
				xfree(p);
			}
		}
		/* if not, remove from list and free memory */
		if (!found) {
			TAILQ_REMOVE(&sc->peers, ep, peer_list);
			if (ep->connfd != 0)
				(void) close(ep->connfd);
			xfree(ep);
		}
	}
	printf("peer list for url %s: \n", sc->tp->announce);
	TAILQ_FOREACH(ep, &sc->peers, peer_list) {
		printf("host=%s, port=%d - ", inet_ntoa(ep->sa.sin_addr),
		    ntohs(ep->sa.sin_port));
		if (ep->connfd != 0) {
			/* XXX */
		} else {
			/* XXX non-blocking connect? */
			ep->connfd = network_connect_peer(ep);
			ep->bufev = bufferevent_new(ep->connfd, network_handle_peer_response,
			    network_handle_peer_write, network_handle_peer_error, ep);
			bufferevent_enable(ep->bufev, EV_READ|EV_WRITE);
			network_peer_handshake(sc, ep);
		}
	}
}
static void
network_peer_handshake(struct session *sc, struct peer *p)
{
	printf("network_peer_handshake for peer on fd %d\n", p->connfd);
	/*
	* handshake: <pstrlen><pstr><reserved><info_hash><peer_id>
	* pstrlen: string length of <pstr>, as a single raw byte
	* pstr: string identifier of the protocol
	* reserved: eight (8) reserved bytes. All current implementations use all zeroes. Each bit in
	* these bytes can be used to change the behavior of the protocol.
	* An email from Bram suggests that trailing bits should be used first, so that leading bits
	* may be used to change the meaning of trailing bits.
	* info_hash: 20-byte SHA1 hash of the info key in the metainfo file. This is the same
	* info_hash that is transmitted in tracker requests.
	* peer_id: 20-byte string used as a unique ID for the client. This is the same peer_id that is
	* transmitted in tracker requests.
	*
	* In version 1.0 of the BitTorrent protocol, pstrlen = 19, and pstr = "BitTorrent protocol".
	*/
	#define HANDSHAKELEN (1 + 19 + 8 + 20 + 20)
	p->txmsg = xmalloc(HANDSHAKELEN);
	memset(p->txmsg, 0, HANDSHAKELEN);
	p->txmsg[0] = 19;
	memcpy(p->txmsg + 1, "BitTorrent protocol", 19);
	memcpy(p->txmsg + 28, sc->tp->info_hash, 20);
	memcpy(p->txmsg + 48, sc->peerid, 20);

	if (bufferevent_write(p->bufev, p->txmsg, HANDSHAKELEN) != 0)
		errx(1, "network_peer_handshake() failure");
}


static void
network_handle_peer_error(struct bufferevent *bufev, short error, void *data)
{
	struct peer *p;

	p = data;
	if (error & EVBUFFER_TIMEOUT) {
		printf("buffer event timeout\n");
	}
	if (error & EVBUFFER_EOF) {
		printf("buffer event EOF\n");
		network_peer_free(p);
	}
	else
		printf("peer buffer error\n");
}

static void
network_handle_peer_write(struct bufferevent *bufev, void *data)
{
	struct peer *p = data;

	printf("network_peer_write for peer on fd %d\n", p->connfd);
	xfree(p->txmsg);
}

static void
network_handle_peer_response(struct bufferevent *bufev, void *data)
{
	struct peer *p = data;
	/* should always be 19, but just in case... */
	size_t len, i;
	u_int32_t msglen, bitfieldlen, idx, blocklen, off;
	u_int8_t *base, id = 0;

	if (p->state & PEER_STATE_HANDSHAKE) {
		printf("handshake response\n");
		if (p->rxpending == 0) {
			/* this should be a handshake response, minimum of 1 byte read, which is length
			 * field, so we always know how much data to expect */
			p->rxmsg = xmalloc(1);
			len = bufferevent_read(bufev, p->rxmsg, 1);
			if (len != 1)
				errx(1, "len should be 1 here!");
			memcpy(&p->pstrlen, p->rxmsg, 1);
			if (p->pstrlen != 19)
				errx(1, "pstrlen is %d not 19!", p->pstrlen);
			xfree(p->rxmsg);
			/* now we can allocate full data buffer, and know when we're done reading... */
			p->rxmsglen = p->pstrlen + 8 + 20 + 20;
			p->rxmsg = xmalloc(p->rxmsglen);
			p->rxpending = p->rxmsglen;
			goto read;
		} else {
		read:
			base = p->rxmsg + (p->rxmsglen - p->rxpending);
			len = bufferevent_read(bufev, p->rxmsg, p->rxmsglen);
			if (len < p->rxmsglen) {
				p->rxpending = p->rxmsglen - len;
				return;
			}
			/* if we get this far, means we have got the full handshake */
			memcpy(&p->info_hash, base + 1 + p->pstrlen + 8, 20);
			memcpy(&p->id, base + 1 + p->pstrlen + 8 + 20, 20);

			xfree(p->rxmsg);
			p->rxmsg = NULL;
			printf("parsed incoming handshake\n");
			printf("peer hash:\t0x");
			for (i = 0; i < SHA1_DIGEST_LENGTH; i++)
				printf("%02x", p->info_hash[i]);
			printf("\n");
			p->state |= PEER_STATE_BITFIELD;
			p->state &= ~PEER_STATE_HANDSHAKE;
			/* if we have some pieces, send our bitfield */
			if (!torrent_empty(p->sc->tp))
				network_peer_write_bitfield(p);
			p->rxpending = 0;
			return;
		}
	} else {
		if (p->rxpending == 0) {
			/* this is a new message */
			len = bufferevent_read(bufev, &msglen, 4);
			if (len != 4)
				errx(1, "len should be 4 here!");
			p->rxmsglen = ntohl(msglen);
			printf("message length: %u\n", p->rxmsglen);
			/* keep-alive: do nothing */
			if (p->rxmsglen == 0)
				return;
			p->rxmsg = xmalloc(p->rxmsglen);
			memset(p->rxmsg, 0, p->rxmsglen);
			p->rxpending = p->rxmsglen;
			goto read2;
		} else {
		read2:
			/* continuing a large message */
			printf("pending: %u\n", p->rxpending);
			base = p->rxmsg + (p->rxmsglen - p->rxpending);
			len = bufferevent_read(bufev, base, p->rxpending);
			printf("read: %zd\n", len);
			p->rxpending -= len;
			if (p->rxpending > 0)
				return;
		}
		/* if we get this far, means we have the entire message */
		memcpy(&id, p->rxmsg, 1);
		/* XXX: safety-check for correct message lengths */
		switch (id) {
			case PEER_MSG_ID_CHOKE:
				printf("peer sez choke\n");
				p->state |= PEER_STATE_CHOKED;
				break;
			case PEER_MSG_ID_UNCHOKE:
				printf("peer sez unchoke\n");
				p->state &= ~PEER_STATE_CHOKED;
				network_peer_request_piece(p, p->piece, p->block);
				break;
			case PEER_MSG_ID_INTERESTED:
				p->state |= PEER_STATE_INTERESTED;
				printf("peer sez interested\n");
				break;
			case PEER_MSG_ID_NOTINTERESTED:
				p->state &= ~PEER_STATE_INTERESTED;
				printf("peer sez notinterested\n");
				break;
			case PEER_MSG_ID_HAVE:
				printf("peer sez have\n");
				memcpy(&idx, p->rxmsg+sizeof(id), sizeof(idx));
				idx = ntohl(idx);
				if (idx > p->sc->tp->num_pieces - 1) {
					printf("have index overflow, ignoring\n");
					return;
				}
				setbit(p->bitfield, idx);
				break;
			case PEER_MSG_ID_BITFIELD:
				printf("peer sez bitfield\n");
				if (!(p->state & PEER_STATE_BITFIELD)) {
					printf("not expecting bitfield!\n");
					return;
				}
				bitfieldlen = p->rxmsglen - 1;
				printf("pieces: %u bitfield: %d\n", p->sc->tp->num_pieces, bitfieldlen * 8);
				if (bitfieldlen * 8 > p->sc->tp->num_pieces + 7
				    || bitfieldlen * 8 < p->sc->tp->num_pieces - 7) {
					printf("bitfield is wrong size! killing peer connection\n");
					network_peer_free(p);
					return;
				}
				p->bitfield = xmalloc(bitfieldlen);
				memcpy(p->bitfield, p->rxmsg+sizeof(id), bitfieldlen);
				p->state &= ~PEER_STATE_BITFIELD;
				p->state |= PEER_STATE_ESTABLISHED;
				break;
			case PEER_MSG_ID_REQUEST:
				memcpy(&idx, p->rxmsg+sizeof(id), sizeof(idx));
				idx = ntohl(idx);
				memcpy(&off, p->rxmsg+sizeof(idx), sizeof(off));
				off = ntohl(off);
				memcpy(&blocklen, p->rxmsg+sizeof(id)+sizeof(idx)+sizeof(off), sizeof(blocklen));
				blocklen = ntohl(blocklen);
				printf("peer REQUEST idx: %d offset: %d blocklen: %d\n", idx, off, blocklen);
				network_peer_write_piece(p, idx, off, blocklen);
				break;
			case PEER_MSG_ID_PIECE:
				printf("peer sez piece\n");
				memcpy(&idx, p->rxmsg+sizeof(id), sizeof(idx));
				idx = ntohl(idx);
				memcpy(&off, p->rxmsg+sizeof(id)+sizeof(idx), sizeof(off));
				off = ntohl(off);
				printf("peer PIECE idx: %d offset: %d\n", idx, off);
				network_peer_read_piece(p, idx, off, p->rxmsglen - 13, p->rxmsg+sizeof(id)+sizeof(off)+sizeof(idx));
				break;
			case PEER_MSG_ID_CANCEL:
				printf("peer sez cancel\n");
				/* XXX: not sure how to cancel a write */
				break;
			default:
				printf("unknown message id: %u\n", id);
				break;
		}
	}
}

static void
network_peer_write_piece(struct peer *p, u_int32_t idx, off_t offset, u_int32_t len)
{
	struct torrent_piece *tpp;
	void *data;
	int hint;

	if ((tpp = torrent_piece_find(p->sc->tp, idx)) == NULL) {
		printf("REQUEST for piece %u - failed at torrent_piece_find(), returning\n", idx);
		return;
	}
	if ((data = torrent_block_read(tpp, offset, len, &hint)) == NULL) {
		printf("REQUEST for piece %u - failed at torrent_block_read(), returning\n", idx);
		return;
	}
	if (bufferevent_write(p->bufev, data, len) != 0)
		errx(1, "network_peer_write_piece: bufferevent_write failure");
}

static void
network_peer_read_piece(struct peer *p, u_int32_t idx, off_t offset, u_int32_t len, void *data)
{
	struct torrent_piece *tpp;

	if ((tpp = torrent_piece_find(p->sc->tp, idx)) == NULL) {
		printf("REQUEST for piece %u - failed at torrent_piece_find(), returning\n", idx);
		return;
	}
	torrent_block_write(tpp, offset, len, data);
	p->block += len;
	p->state &= ~PEER_STATE_ISTRANSFERRING;
}

static void
network_peer_write_interested(struct peer *p)
{
	u_int8_t id;
	u_int32_t len;

	len = htonl(sizeof(id));
	id = PEER_MSG_ID_INTERESTED;

	p->txmsg = xmalloc(sizeof(len) + sizeof(id));
	memcpy(p->txmsg, &len, sizeof(len));
	memcpy(p->txmsg+sizeof(len), &id, sizeof(id));

	if (bufferevent_write(p->bufev, p->txmsg, sizeof(len) + sizeof(id)) != 0)
		errx(1, "network_peer_write_interested: bufferevent_write failure");
	p->state |= PEER_STATE_AMINTERESTED;

}
static void
network_peer_write_bitfield(struct peer *p)
{
	u_int8_t *bitfield, id;
	u_int32_t msglen, msglen2;

	id = PEER_MSG_ID_BITFIELD;
	bitfield = torrent_bitfield_get(p->sc->tp);

	msglen = sizeof(msglen) + sizeof(id) + (p->sc->tp->num_pieces / 8);
	p->txmsg = xmalloc(msglen);
	memset(p->txmsg, 0, msglen);
	msglen2 = htonl(msglen);
	memcpy(p->txmsg, &msglen2, sizeof(msglen2));
	memcpy(p->txmsg+sizeof(msglen), &id, sizeof(id));
	memcpy(p->txmsg+sizeof(msglen)+sizeof(id), bitfield, p->sc->tp->num_pieces / 8);

	if (bufferevent_write(p->bufev, p->txmsg, msglen) != 0)
		errx(1, "network_peer_write_bitfield: bufferevent_write failure");
	
	xfree(bitfield);
}

static void
network_peer_free(struct peer *p)
{
	printf("freeing peer\n");
	struct session *sc = p->sc;
	TAILQ_REMOVE(&sc->peers, p, peer_list);
	if (p->bufev != NULL)
		bufferevent_free(p->bufev);
	if (p->rxmsg != NULL)
		xfree(p->rxmsg);
	if (p->txmsg != NULL)
		xfree(p->txmsg);
	if (p->bitfield != NULL)
		xfree(p->bitfield);
	if (p->connfd != 0)
		(void)  close(p->connfd);

	xfree(p);
}

/* network subsystem init, needs to be called before doing anything */
void
network_init()
{
	event_init();
}

/* bulk of decision making happens here.  run every second, once announce is complete. */
static void
network_scheduler(int fd, short type, void *arg)
{
	struct peer *p;
	struct session *sc = arg;
	struct timeval tv;
	/* piece rarity array */
	struct piececounter *pieces;

	timerclear(&tv);
	tv.tv_sec = 1;
	evtimer_set(&sc->scheduler_event, network_scheduler, sc);
	evtimer_add(&sc->scheduler_event, &tv);
	
	/* XXX: probably this should be some sane threshold like 10 */
	if (!TAILQ_EMPTY(&sc->peers)) {
		pieces = network_session_sorted_pieces(sc);
		TAILQ_FOREACH(p, &sc->peers, peer_list)
			if (!(p->state & PEER_STATE_ISTRANSFERRING)
			    &&!(p->state & PEER_STATE_AMINTERESTED)) {
				network_peer_write_interested(p);
				p->piece = pieces[0].idx;
			}
		xfree(pieces);
	} else {
		/* XXX: try to connect some more peers */
	}
}

static void
network_peer_request_piece(struct peer *p, u_int32_t idx, u_int32_t off)
{
	u_int32_t msglen, msglen2, blocklen;
	u_int8_t  *msg, id;

	msglen = sizeof(msglen) + sizeof(id) + sizeof(idx) + sizeof(off) + sizeof(blocklen);
	msg = xmalloc(msglen);
	msglen2 = htonl(msglen - sizeof(msglen));
	id = PEER_MSG_ID_REQUEST;
	idx = htonl(idx);
	off = htonl(off);
	blocklen = htonl(BLOCK_SIZE);

	memcpy(msg, &msglen2, sizeof(msglen2));
	memcpy(msg+sizeof(msglen2), &id, sizeof(id));
	memcpy(msg+sizeof(msglen2)+sizeof(id), &idx, sizeof(idx));
	memcpy(msg+sizeof(msglen2)+sizeof(id)+sizeof(idx), &off, sizeof(off));
	memcpy(msg+sizeof(msglen2)+sizeof(id)+sizeof(idx)+sizeof(off), &blocklen, sizeof(blocklen));

	p->txmsg = msg;
	p->state |= PEER_STATE_ISTRANSFERRING;
	if (bufferevent_write(p->bufev, msg, msglen) != 0)
		errx(1, "network_peer_request_piece: bufferevent_write failure");
}

static int
network_session_sorted_pieces_cmp(const void *a, const void *b)
{
	const struct piececounter *x, *y;

	x = a;
	y = b;

	return (x->count - y->count);

}

/* for a given session return sorted array of piece counts*/
static struct piececounter *
network_session_sorted_pieces(struct session *sc)
{
	struct torrent_piece *tpp;
	struct piececounter *pieces;
	struct peer *p;
	u_int32_t i, count;

	pieces = xcalloc(sc->tp->num_pieces, sizeof(*pieces));

	/* counts for each piece */
	for (i = 0; i < sc->tp->num_pieces; i++) {
		/* if we have this piece, eliminate it from the array */
		tpp = torrent_piece_find(sc->tp, i);
		if (tpp->flags & TORRENT_PIECE_CKSUMOK)
			continue;
		count = 0;
		/* otherwise count it */
		TAILQ_FOREACH(p, &sc->peers, peer_list) {
			if (!(p->state & PEER_STATE_ESTABLISHED))
				continue;
			if (BIT_ISSET(p->bitfield, i))
				count++;
		}
		pieces[i].count = count;
		pieces[i].idx = i;
	}
	/* sort the rarity array */
	qsort(pieces, sc->tp->num_pieces, sizeof(*pieces),
	    network_session_sorted_pieces_cmp);

	return (pieces);
}

/* start handling network stuff for a new torrent */
int
network_start_torrent(struct torrent *tp)
{
	int ret;
	struct session *sc;

	sc = xmalloc(sizeof(*sc));
	memset(sc, 0, sizeof(*sc));

	TAILQ_INIT(&sc->peers);
	sc->tp = tp;
	sc->port = xstrdup("6668");
	sc->peerid = xstrdup("U1234567891234567890");

	ret = network_announce(sc, "started");

	event_dispatch();

	printf("returning\n");
	return (ret);
}

