/* $Id: network.c,v 1.158 2007-10-29 05:11:57 niallo Exp $ */
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
#include <sys/param.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <openssl/bn.h>
#include <openssl/dh.h>
#include <openssl/engine.h>

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

#define PEER_STATE_HANDSHAKE1		(1<<0)
#define PEER_STATE_BITFIELD		(1<<1)
#define PEER_STATE_ESTABLISHED		(1<<2)
#define PEER_STATE_AMCHOKING		(1<<3)
#define PEER_STATE_CHOKED		(1<<4)
#define PEER_STATE_AMINTERESTED		(1<<5)
#define PEER_STATE_INTERESTED		(1<<6)
#define PEER_STATE_ISTRANSFERRING	(1<<7)
#define PEER_STATE_DEAD			(1<<8)
#define PEER_STATE_GOTLEN		(1<<9)
#define PEER_STATE_CRYPTED		(1<<10)
#define PEER_STATE_HANDSHAKE2		(1<<11)

#define PEER_MSG_ID_CHOKE		0
#define PEER_MSG_ID_UNCHOKE		1
#define PEER_MSG_ID_INTERESTED		2
#define PEER_MSG_ID_NOTINTERESTED	3
#define PEER_MSG_ID_HAVE		4
#define PEER_MSG_ID_BITFIELD		5
#define PEER_MSG_ID_REQUEST		6
#define PEER_MSG_ID_PIECE		7
#define PEER_MSG_ID_CANCEL		8

#define PEER_COMMS_THRESHOLD		60 /* 60 seconds */

#define BLOCK_SIZE			16384 /* 16KB */
#define MAX_BACKLOG			65536 /* 64KB */
#define LENGTH_FIELD 			4 /* peer messages use a 4byte len field */
#define MAX_MESSAGE_LEN 		0xffffff /* 16M */
#define DEFAULT_ANNOUNCE_INTERVAL	1800/* */
#define MAX_REQUESTS			100 /* max request queue length per peer */

/* MSE defines
 * see http://www.azureuswiki.com/index.php/Message_Stream_Encryption */
#define CRYPTO_PRIME				0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A63A36210000000000090563
#define CRYPTO_GENERATOR			2
#define CRYPTO_PLAINTEXT			0x01
#define CRYPTO_RC4				0x02
#define CRYPTO_INT_LEN				160
#define CRYPTO_MAX_BYTES1			608
#define CRYPTO_MIN_BYTES1			96

#define BT_PROTOCOL				"BitTorrent protocol"
#define BT_PSTRLEN				19
#define BT_INITIAL_LEN 				20

#define BIT_SET(a,i)			((a)[(i)/8] |= 1<<(7-((i)%8)))
#define BIT_CLR(a,i)			((a)[(i)/8] &= ~(1<<(7-((i)%8))))
#define BIT_ISSET(a,i)			((a)[(i)/8] & (1<<(7-((i)%8))))
#define BIT_ISCLR(a,i)			(((a)[(i)/8] & (1<<(7-((i)%8)))) == 0)

/* try to keep this many peer connections at all times */
#define PEERS_WANTED				10

/* when trying to fetch more peers, make sure we don't announce
 * more often than this interval allows */
#define MIN_ANNOUNCE_INTERVAL			60

#define PEER_ID_LEN				20

/* data for a http response */
struct http_response {
	/* response buffer */
	u_int8_t *rxmsg;
	/* size of buffer so far */
	u_int32_t rxread,rxmsglen;
};


/* bittorrent peer */
struct peer {
	TAILQ_ENTRY(peer) peer_list;
	RB_ENTRY(peer_idxnode) entry;
	TAILQ_HEAD(peer_piece_dls, piece_dl) peer_piece_dls;
	struct sockaddr_in sa;
	int connfd;
	int state;
	u_int32_t rxpending;
	u_int32_t txpending;
	struct bufferevent *bufev;
	u_int32_t rxmsglen;
	u_int8_t *txmsg, *rxmsg;
	u_int8_t *bitfield;
	/* from peer's handshake message */
	u_int8_t pstrlen;
	u_int8_t id[PEER_ID_LEN];
	u_int8_t info_hash[20];

	struct session *sc;
	/* last time we rx'd something from this peer */
	struct timeval lastrecv;
	/* time we connected this peer (ie start of its life) */
	struct timeval connected;
	/* how many bytes have we rx'd from the peer since it was connected */
	u_int64_t totalrx;
	/* block request queue length*/
	u_int16_t queue_len;
};

/* piece download transaction */
struct piece_dl {
	TAILQ_ENTRY(piece_dl) peer_piece_dl_list;
	TAILQ_ENTRY(piece_dl) idxnode_piece_dl_list;
	struct peer *pc; /* peer we're requesting from */
	u_int32_t idx; /* piece index */
	u_int32_t off; /* offset within this piece */
	u_int32_t len; /* length of this request (=> buf size) */
	u_int32_t bytes; /* how many bytes have we read so far */
};

/* For the binary tree which does lookups based on piece dl index and offset,
 * we do not guarantee that key to be unique - ie there may be multiple piece_dls
 * in progress for the same block.  Instead, we have a list of piece_dls. */
struct piece_dl_idxnode {
	RB_ENTRY(piece_dl_idxnode) entry;
	u_int32_t idx; /* piece index */
	u_int32_t off; /* offset within this piece */
	TAILQ_HEAD(idxnode_piece_dls, piece_dl) idxnode_piece_dls;
};

/* data associated with a bittorrent session */
struct session {
	/* don't expect to have huge numbers of peers, or be searching very often, so linked list
	 * should be fine for storage */
	TAILQ_HEAD(peers, peer) peers;
	/* index piece_dls by block index / offset */
	RB_HEAD(piece_dl_by_idxoff, piece_dl_idxnode) piece_dl_by_idxoff;
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
	struct sockaddr_in sa;
	struct torrent *tp;
	struct http_response *res;
	u_int8_t num_peers;
	rlim_t maxfds;
	int announce_underway;
	u_int32_t tracker_num_peers;
	struct timeval last_announce;
};

struct piececounter {
	u_int32_t count;
	u_int32_t idx;
};


char *user_port = NULL;

static int	network_announce(struct session *, const char *);
static void	network_announce_update(int, short, void *);
static void	network_handle_announce_response(struct bufferevent *, void *);
static void	network_handle_announce_error(struct bufferevent *, short, void *);
static void	network_handle_write(struct bufferevent *, void *);
static int	network_connect(int, int, int, const struct sockaddr *,
		    socklen_t);
static int	network_connect_tracker(const char *, const char *);
static int	network_connect_peer(struct peer *);
static void	network_peerlist_connect(struct session *);
static void	network_peerlist_update(struct session *, struct benc_node *);
static void	network_peerlist_update_dict(struct session *, struct benc_node *);
static void	network_peerlist_update_string(struct session *, struct benc_node *);
static void	network_peer_handshake(struct session *, struct peer *);
static void	network_peer_write_piece(struct peer *, u_int32_t, off_t, u_int32_t);
static void	network_peer_read_piece(struct peer *, u_int32_t, off_t, u_int32_t, void *);
static void	network_peer_write_bitfield(struct peer *);
static void	network_peer_write_interested(struct peer *);
static void	network_peer_free(struct peer *);
static struct peer * network_peer_create(void);
static void	network_handle_peer_connect(struct bufferevent *, short, void *);
static void	network_handle_peer_response(struct bufferevent *, void *);
static void	network_handle_peer_write(struct bufferevent *, void *);
static void	network_handle_peer_error(struct bufferevent *, short, void *);
static void	network_scheduler(int, short, void *);
static int	network_listen(struct session *, char *, char *);
static void	network_peer_request_block(struct peer *, u_int32_t, u_int32_t,
    u_int32_t);
static void	network_peer_write_unchoke(struct peer *);
static struct piece_dl *network_piece_gimme(struct peer *);
static void	network_peer_cancel_piece(struct piece_dl *);
static void	network_peer_write_have(struct peer *, u_int32_t);
static void	network_peer_process_message(u_int8_t, struct peer *);

static DH	*network_crypto_dh(void);
static long	network_peer_lastcomms(struct peer *);
static u_int64_t network_peer_rate(struct peer *);
static int network_piece_inqueue(struct session *, struct torrent_piece *);
static u_int32_t network_piece_find_rarest(struct session *, int, int *);
static struct piece_dl * network_piece_dl_create(struct peer *, u_int32_t,
    u_int32_t, u_int32_t);
static void	network_piece_dl_free(struct piece_dl *);
static struct piece_dl *network_piece_dl_find(struct session *, u_int32_t, u_int32_t);
static void	network_peer_piece_dl(struct piece_dl *);
static int network_piece_cmp(const void *, const void *);
static struct piececounter *network_piece_rarityarray(struct session *);

static int	piece_dl_idxnode_cmp(struct piece_dl_idxnode *, struct piece_dl_idxnode *);

/* index of piece dls by block index and offset */
RB_PROTOTYPE(piece_dl_by_idxoff, piece_dl_idxnode, entry, piece_dl_idxnode_cmp)
RB_GENERATE(piece_dl_by_idxoff, piece_dl_idxnode, entry, piece_dl_idxnode_cmp)

static int
piece_dl_idxnode_cmp(struct piece_dl_idxnode *p1, struct piece_dl_idxnode *p2)
{
	int64_t idxdiff;

	idxdiff = p1->idx - p2->idx;

	if (idxdiff == 0)
		return (p1->off - p2->off);
	else
		return (idxdiff);
}


static int
network_announce(struct session *sc, const char *event)
{
	int i, l;
	size_t n;
	char host[MAXHOSTNAMELEN], port[6], path[MAXPATHLEN], *c;
#define GETSTRINGLEN 2048
	char *params, *tparams, *request;
	char tbuf[3*SHA1_DIGEST_LENGTH+1];
	struct bufferevent *bufev;

	trace("network_announce");
	if (gettimeofday(&sc->last_announce, NULL) == -1)
		err(1, "network_announce: gettimeofday");
	params = xmalloc(GETSTRINGLEN);
	tparams = xmalloc(GETSTRINGLEN);
	request = xmalloc(GETSTRINGLEN);
	memset(params, '\0', GETSTRINGLEN);
	memset(tparams, '\0', GETSTRINGLEN);
	memset(request, '\0', GETSTRINGLEN);

	/* convert binary info hash to url encoded format */
	for (i = 0; i < SHA1_DIGEST_LENGTH; i++) {
		l = snprintf(&tbuf[3*i], sizeof(tbuf), "%%%02x", sc->tp->info_hash[i]);
		if (l == -1 || l >= (int)sizeof(tbuf))
			goto trunc;
	}
#define HTTPLEN 7
	/* XXX: need support for announce-list */
	/* separate out hostname, port and path */
	c = strstr(sc->tp->announce, "http://");
	c += HTTPLEN;
	n = strcspn(c, ":/");
	if (n > sizeof(host) - 1)
		errx(1, "n is greater than sizeof(host) - 1");

	memcpy(host, c, n);
	host[n] = '\0';

	c += n;
	if (*c == ':') {
		c++;
		n = strcspn(c, "/");
		if (n > sizeof(port)) {
			errx(1, "n is greater than sizeof(port)");
		}
		memcpy(port, c, n);
		port[n] = '\0';
	} else {
		if (strlcpy(port, "80", sizeof(port)) >= sizeof(port))
			errx(1, "string truncation");
		n = 0;
	}
	c += n;
	if (strlcpy(path, c, sizeof(path)) >= sizeof(path))
		errx(1, "string truncation");
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
		strlcpy(tparams, params, GETSTRINGLEN);
		l = snprintf(params, GETSTRINGLEN, "%s&event=%s", tparams,
		    event);
		if (l == -1 || l >= GETSTRINGLEN)
			goto trunc;
	}
	/* while OpenBSD's snprintf doesn't mind snprintf(X, len, "%sblah", X) others
	 * don't like this, so I do the strlcpy and use the temporary buffer tparams. */
	if (sc->ip != NULL) {
		strlcpy(tparams, params, GETSTRINGLEN);
		l = snprintf(params, GETSTRINGLEN, "%s&ip=%s", tparams,
		    sc->ip);
		if (l == -1 || l >= GETSTRINGLEN)
			goto trunc;
	}
	if (sc->numwant != NULL) {
		strlcpy(tparams, params, GETSTRINGLEN);
		l = snprintf(params, GETSTRINGLEN, "%s&numwant=%s", params,
		    sc->numwant);
		if (l == -1 || l >= GETSTRINGLEN)
			goto trunc;
	}
	if (sc->key != NULL) {
		strlcpy(tparams, params, GETSTRINGLEN);
		l = snprintf(params, GETSTRINGLEN, "%s&key=%s", params,
		    sc->key);
		if (l == -1 || l >= GETSTRINGLEN)
			goto trunc;
	}
	if (sc->trackerid != NULL) {
		strlcpy(tparams, params, GETSTRINGLEN);
		l = snprintf(params, GETSTRINGLEN, "%s&trackerid=%s",
		    params, sc->trackerid);
		if (l == -1 || l >= GETSTRINGLEN)
			goto trunc;
	}

	l = snprintf(request, GETSTRINGLEN,
	    "GET %s%s HTTP/1.0\r\nHost: %s\r\nUser-agent: Unworkable/%s\r\n\r\n", path,
	    params, host, UNWORKABLE_VERSION);
	if (l == -1 || l >= GETSTRINGLEN)
		goto trunc;

	trace("network_announce() to host: %s on port: %s", host, port);
	trace("network_announce() request: %s", request);
	/* non blocking connect ? */
	if ((sc->connfd = network_connect_tracker(host, port)) == -1)
		exit(1);

	sc->request = request;
	sc->res = xmalloc(sizeof *sc->res);
	memset(sc->res, 0, sizeof *sc->res);
#define RESBUFLEN 1024
	sc->res->rxmsg = xmalloc(RESBUFLEN);
	sc->res->rxmsglen = RESBUFLEN;
	sc->announce_underway = 1;
	bufev = bufferevent_new(sc->connfd, network_handle_announce_response,
	    network_handle_write, network_handle_announce_error, sc);
	if (bufev == NULL)
		errx(1, "network_announce: bufferevent_new failure");
	bufferevent_enable(bufev, EV_READ);
	trace("network_announce() writing to socket");
	if (bufferevent_write(bufev, request, strlen(request) + 1) != 0)
		errx(1, "network_announce: bufferevent_write failure");
	trace("freeing params");
	xfree(params);
	trace("network_announce() done");
	return (0);

trunc:
	warnx("network_announce: string truncation detected");
	xfree(params);
	xfree(request);
	xfree(tparams);
	return (-1);
}

static void
network_handle_announce_response(struct bufferevent *bufev, void *arg)
{
	size_t len;
	struct session *sc;

	sc = arg;
	trace("network_handle_announce_response() reading buffer");
	/* within 256 bytes of filling up our buffer - grow it */
	if (sc->res->rxmsglen <= sc->res->rxread + 256) {
		sc->res->rxmsglen += RESBUFLEN;
		sc->res->rxmsg = xrealloc(sc->res->rxmsg, sc->res->rxmsglen);
	}
	len = bufferevent_read(bufev, sc->res->rxmsg + sc->res->rxread, 256);
	sc->res->rxread += len;
	trace("network_handle_announce_response() read %u", len);
}

static void
network_handle_announce_error(struct bufferevent *bufev, short error, void *data)
{
	struct session *sc = data;
	struct benc_node *node, *troot;
	struct torrent *tp;
	struct timeval tv;
	struct bufferevent *bev;
	BUF *buf = NULL;
	u_int32_t l;
	u_char *c;

	trace("network_handle_announce_error() called");
	/* shouldn't have to worry about this case */
	if (sc->res == NULL)
		return;
	/* still could be data left for reading */
	do {
		l = sc->res->rxread;
		network_handle_announce_response(bufev, sc);
	}
	while (sc->res->rxread - l > 0);

	tp = sc->tp;

	if (error & EVBUFFER_TIMEOUT)
		errx(1, "network_handle_announce_error() TIMOUT (unexpected)");

	c = sc->res->rxmsg;
	/* XXX: need HTTP/1.1 support - tricky part is chunked encoding I think */
#define HTTP_1_0 "HTTP/1.0"
#define HTTP_1_1 "HTTP/1.1"
	if (strncmp(c, HTTP_1_0, strlen(HTTP_1_0)) != 0 && strncmp(c, HTTP_1_1, strlen(HTTP_1_1))) {
		warnx("network_handle_announce_error: server did not send a valid HTTP/1.0 response");
		goto err;
	}
	c += strlen(HTTP_1_0) + 1;
#define HTTP_OK "200"
	if (strncmp(c, HTTP_OK, strlen(HTTP_OK)) != 0) {
		*(c + strlen(HTTP_OK)) = '\0';
		warnx("network_handle_announce_error: HTTP response indicates error (code: %s)", c);
		goto err;
	}
#define HTTP_END "\r\n\r\n"
	c = strstr(c, HTTP_END);
	if (c == NULL) {
		warnx("network_handle_announce_error: HTTP response had no content");
		goto err;
	}
	c += strlen(HTTP_END);

	if ((buf = buf_alloc(128, BUF_AUTOEXT)) == NULL)
		errx(1,"network_handle_announce_error: could not allocate buffer");
	buf_set(buf, c, sc->res->rxread - (c - sc->res->rxmsg), 0);

	trace("network_handle_announce_error() bencode parsing buffer");
	troot = benc_root_create();
	if ((troot = benc_parse_buf(buf, troot)) == NULL)
		errx(1,"network_handle_announce_error: HTTP response parsing failed (no peers?)");

	if ((node = benc_node_find(troot, "interval")) == NULL) {
		tp->interval = DEFAULT_ANNOUNCE_INTERVAL;
	} else {
		if (!(node->flags & BINT))
			errx(1, "interval is not a number");
		tp->interval = node->body.number;
	}

	if ((node = benc_node_find(troot, "complete")) != NULL) {
		if (!(node->flags & BINT))
			errx(1, "complete is not a number");
		tp->complete = node->body.number;
	}

	if ((node = benc_node_find(troot, "incomplete")) != NULL) {
		if (!(node->flags & BINT))
			errx(1, "incomplete is not a number");
		tp->incomplete = node->body.number;
	}

	if ((node = benc_node_find(troot, "peers")) == NULL)
		errx(1, "no peers field");
	trace("network_handle_announce_error() updating peerlist");
	network_peerlist_update(sc, node);
	benc_node_freeall(troot);
	troot = NULL;

	trace("network_handle_announce_error() setting announce timer");
	timerclear(&tv);
	tv.tv_sec = tp->interval;
	evtimer_del(&sc->announce_event);
	evtimer_set(&sc->announce_event, network_announce_update, sc);
	evtimer_add(&sc->announce_event, &tv);
	if (sc->servfd == 0) {
		trace("network_handle_announce_error() setting up server socket");
		/* time to set up the server socket */
		sc->servfd = network_listen(sc, "0.0.0.0", sc->port);
		bev = bufferevent_new(sc->servfd, NULL,
		    NULL, network_handle_peer_connect, sc);
		if (bufev == NULL)
			errx(1, "network_handle_announce_error: bufferevent_new failure");
		bufferevent_enable(bev, EV_PERSIST|EV_READ);
		/* now that we've announced, kick off the scheduler */
		trace("network_handle_announce_error() setting up scheduler");
		timerclear(&tv);
		tv.tv_sec = 1;
		evtimer_set(&sc->scheduler_event, network_scheduler, sc);
		evtimer_add(&sc->scheduler_event, &tv);
	}
err:
	bufferevent_free(bufev);
	bufev = NULL;
	if (buf != NULL)
		buf_free(buf);
	trace("network_handle_announce_error() freeing res2");
	if (sc->res != NULL) {
		xfree(sc->res->rxmsg);
		xfree(sc->res);
		sc->res = NULL;
	}
	(void) close(sc->connfd);
	trace("network_handle_announce_error() done");
	sc->announce_underway = 0;
}

static void
network_handle_peer_connect(struct bufferevent *bufev, short error, void *data)
{
	struct session *sc;
	struct peer *p;
	socklen_t addrlen;

	trace("network_handle_peer_connect() called");
	if (error & EVBUFFER_TIMEOUT)
		errx(1, "timeout");
	if (error & EVBUFFER_EOF)
		errx(1, "eof");
	sc = data;
	p = network_peer_create();
	p->sc = sc;
	addrlen = sizeof(p->sa);

	trace("network_handle_peer_connect() accepting connection");
	if ((p->connfd = accept(sc->servfd, (struct sockaddr *) &p->sa, &addrlen)) == -1) {
		trace("network_handle_peer_connect() accept error");
		network_peer_free(p);
		return;
	}
	trace("network_handle_peer_connect() accepted peer: %s:%d",
	    inet_ntoa(p->sa.sin_addr), ntohs(p->sa.sin_port));

	p->state |= PEER_STATE_HANDSHAKE1;
	p->bufev = bufferevent_new(p->connfd, network_handle_peer_response,
	    network_handle_peer_write, network_handle_peer_error, p);
	if (p->bufev == NULL)
		errx(1, "network_announce: bufferevent_new failure");
	bufferevent_enable(p->bufev, EV_READ|EV_WRITE);
	trace("network_handle_peer_connect() initiating handshake");
	TAILQ_INSERT_TAIL(&sc->peers, p, peer_list);
	sc->num_peers++;
	network_peer_handshake(sc, p);

}

static int
network_listen(struct session *sc, char *host, char *port)
{
	int error = 0;
	int fd;
	int option_value = 1;
	struct addrinfo hints, *res;

	trace("network_listen() creating socket");
	if ((fd = socket(PF_INET, SOCK_STREAM, 0)) == -1)
		err(1, "could not create server socket");
	trace("network_listen() setting socket non-blocking");
	if (fcntl(fd, F_SETFL, O_NONBLOCK) == -1)
		err(1, "network_listen: fcntl");
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_INET;
	hints.ai_socktype = SOCK_STREAM;
	trace("network_listen() calling getaddrinfo()");
	error = getaddrinfo(host, port, &hints, &res);
	if (error != 0)
		errx(1, "\"%s\" - %s", host, gai_strerror(error));
	trace("network_listen() settings socket options");
	error = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR,
		    &option_value, sizeof(option_value));
	if (error == -1)
		err(1, "could not set socket options");
	trace("network_listen() binding socket to address");
	if (bind(fd, res->ai_addr, res->ai_addrlen) == -1)
		err(1, "could not bind to port %s", port);
	trace("network_listen() listening on socket");
	memcpy(&sc->sa, res->ai_addr, res->ai_addrlen);
	if (listen(fd, MAX_BACKLOG) == -1)
		err(1, "could not listen on server socket");
	freeaddrinfo(res);
	trace("network_listen() done");
	return fd;
}

static int
network_connect(int domain, int type, int protocol, const struct sockaddr *name, socklen_t namelen)
{
	int sockfd;

	trace("network_connect() making socket");
	sockfd = socket(domain, type, protocol);
	if (sockfd == -1) {
		trace("network_connect(): socket");
		return (-1);
	}
	trace("network_connect() setting socket non-blocking");
	if (fcntl(sockfd, F_SETFL, O_NONBLOCK) == -1)
		err(1, "network_connect");

	trace("network_connect() calling connect() on fd");
	if (connect(sockfd, name, namelen) == -1) {
		if (errno != EINPROGRESS) {
			trace("network_connect() connect(): %s", strerror(errno));
			return (-1);
		}
	}
	trace("network_connect() connect() returned");

	return (sockfd);

}

static int
network_connect_peer(struct peer *p)
{
	p->state |= PEER_STATE_HANDSHAKE1;
	return (network_connect(PF_INET, SOCK_STREAM, 0,
	    (const struct sockaddr *) &p->sa, sizeof(p->sa)));
}

static int
network_connect_tracker(const char *host, const char *port)
{
	struct addrinfo hints, *res, *res0;
	int error, sockfd;

	memset(&hints, 0, sizeof(hints));
	/* I think that this is the only place where we should actually
	 * have to resolve host names.  The getaddrinfo() calls elsewhere
	 * should be very fast. */
	hints.ai_family = PF_INET;
	hints.ai_socktype = SOCK_STREAM;
	trace("network_connect_tracker() calling getaddrinfo()");
	error = getaddrinfo(host, port, &hints, &res0);
	if (error) {
		trace("network_connect_tracker(): %s", gai_strerror(error));
		return (-1);
	}
	/* assume first address is ok */
	res = res0;
	trace("network_connect_tracker() calling network_connect()");
	sockfd = network_connect(res->ai_family, res->ai_socktype,
	    res->ai_protocol, res->ai_addr, res->ai_addrlen);
	freeaddrinfo(res0);

	return (sockfd);
}

static void
network_handle_write(struct bufferevent *bufev, void *data)
{
	struct session *sc = data;

	trace("network_handle_write() called");
	xfree(sc->request);
}

static void
network_announce_update(int fd, short type, void *arg)
{
	struct session *sc = arg;
	struct timeval tv;

	trace("network_announce_update() called");
	if (!sc->announce_underway)
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
network_peerlist_update_string(struct session *sc, struct benc_node *peers)
{
	char *peerlist;
	size_t len, i;
	struct peer *p, *ep, *nxt;
	int found = 0;

	len = peers->body.string.len;
	peerlist = peers->body.string.value;
	p = NULL;

	if (len == 0)
		trace("network_peerlist_update() peer list is zero in length");

	/* check for peers to add */
	for (i = 0; i < len; i++) {
		if (i % 6 == 0) {
			p = network_peer_create();
			p->sc = sc;
			p->sa.sin_family = AF_INET;
			memcpy(&p->sa.sin_addr, peerlist + i, 4);
			memcpy(&p->sa.sin_port, peerlist + i + 4, 2);
			/* Check if this peer is us */
			if (memcmp(&p->sa.sin_addr, &sc->sa.sin_addr, sizeof(ep->sa.sin_addr)) == 0
			    && memcmp(&p->sa.sin_port, &sc->sa.sin_port, sizeof(ep->sa.sin_port)) == 0) {
				trace("network_peerlist_update() peer is ourselves");
				continue;
			}
			/* Is this peer already in the list? */
			found = 0;
			TAILQ_FOREACH(ep, &sc->peers, peer_list) {
				if (memcmp(&ep->sa.sin_addr, &p->sa.sin_addr, sizeof(ep->sa.sin_addr)) == 0
				    && memcmp(&ep->sa.sin_port, &p->sa.sin_port, sizeof(ep->sa.sin_port)) == 0) {
					found = 1;
					break;
				}
			}
			if (found == 0) {
				trace("network_peerlist_update() adding peer to list");
				TAILQ_INSERT_TAIL(&sc->peers, p, peer_list);
				sc->num_peers++;
			} else {
				network_peer_free(p);
			}
			continue;
		}
	}

	/* check for peers to remove */
	peerlist = peers->body.string.value;
	for (ep = TAILQ_FIRST(&sc->peers); ep != TAILQ_END(&sc->peers); ep = nxt) {
		nxt = TAILQ_NEXT(ep, peer_list);
		for (i = 0; i < len; i++ ) {
			if (i % 6 == 0) {
				p = network_peer_create();
				p->sc = sc;
				memcpy(&p->sa.sin_addr, peerlist + i, 4);
				memcpy(&p->sa.sin_port, peerlist + i + 4, 2);
				/* Is this peer in the new list? */
				found = 0;
				if (memcmp(&ep->sa.sin_addr, &p->sa.sin_addr, sizeof(p->sa.sin_addr)) == 0
				    && memcmp(&ep->sa.sin_port, &p->sa.sin_port, sizeof(p->sa.sin_addr)) == 0) {
					found = 1;
					network_peer_free(p);
					break;
				}
				network_peer_free(p);
			}
		}
		/* if not, remove from list and free memory */
		if (!found) {
			trace("network_peerlist_update() expired peer: %s:%d - removing",
			    inet_ntoa(ep->sa.sin_addr), ntohs(ep->sa.sin_port));
			TAILQ_REMOVE(&sc->peers, ep, peer_list);
			network_peer_free(ep);
			sc->num_peers--;
		}
	}
	network_peerlist_connect(sc);
}

static void
network_peerlist_update_dict(struct session *sc, struct benc_node *peers)
{

	struct benc_node *dict, *n;
	struct peer *ep, *p = NULL;
	struct addrinfo hints, *res;
	struct sockaddr_in sa;
	int port, error, l;
	char *ip, portstr[6];

	if (!(peers->flags & BLIST))
		errx(1, "peers object is not a list");
	/* iterate over a blist of bdicts each with three keys */
	TAILQ_FOREACH(dict, &peers->children, benc_nodes) {
		int found;
		p = network_peer_create();
		p->sc = sc;

		n = benc_node_find(dict, "ip");
		if (!(n->flags & BSTRING))
			errx(1, "node is not a string");
		ip = n->body.string.value;
		n = benc_node_find(dict, "port");
		if (!(n->flags & BINT))
			errx(1, "node is not an integer");
		port = n->body.number;
		l = snprintf(portstr, sizeof(portstr), "%d", port);
		if (l == -1 || l >= (int)sizeof(portstr))
			errx(1, "network_peerlist_update_dict() string truncations");

		if ((n = benc_node_find(dict, "peer id")) == NULL)
			errx(1, "couldn't find peer id field");
		if (!(n->flags & BSTRING))
			errx(1, "node is not a string");
		memcpy(&p->id, n->body.string.value, sizeof(p->id));

		memset(&hints, 0, sizeof(hints));
		hints.ai_family = PF_INET;
		hints.ai_socktype = SOCK_STREAM;
		trace("network_peerlist_update_dict() calling getaddrinfo()");
		error = getaddrinfo(ip, portstr, &hints, &res);
		if (error != 0)
			errx(1, "\"%s\" - %s", ip, gai_strerror(error));

		p->sa.sin_family = AF_INET;
		sa.sin_addr = ((struct sockaddr_in *)res->ai_addr)->sin_addr;
		sa.sin_port = ((struct sockaddr_in *)res->ai_addr)->sin_port;
		memcpy(&p->sa.sin_addr, &sa.sin_addr, 4);
		memcpy(&p->sa.sin_port, &sa.sin_port, 2);
		freeaddrinfo(res);
		/* Is this peer already in the list? */
		found = 0;
		TAILQ_FOREACH(ep, &sc->peers, peer_list) {
			if (memcmp(&ep->sa.sin_addr, &p->sa.sin_addr, sizeof(ep->sa.sin_addr)) == 0
			    && memcmp(&ep->sa.sin_port, &p->sa.sin_port, sizeof(ep->sa.sin_port)) == 0) {
				found = 1;
				break;
			}
		}
		if (found == 0) {
			trace("network_peerlist_update_dict() adding peer to list");
			TAILQ_INSERT_TAIL(&sc->peers, p, peer_list);
			sc->num_peers++;
		} else {
			network_peer_free(p);
		}
	}

	network_peerlist_connect(sc);
}

static void
network_peerlist_connect(struct session *sc)
{
	struct peer *ep, *nxt;

	for (ep = TAILQ_FIRST(&sc->peers); ep != TAILQ_END(&sc->peers) ; ep = nxt) {
		nxt = TAILQ_NEXT(ep, peer_list);
		/* stay within our limits */
		if (sc->num_peers >= sc->maxfds - 5) {
				network_peer_free(ep);
				sc->num_peers--;
				continue;
		}
		trace("network_peerlist_update() we have a peer: %s:%d", inet_ntoa(ep->sa.sin_addr),
		    ntohs(ep->sa.sin_port));
		if (ep->connfd != 0) {
			/* XXX */
		} else {
			trace("network_peerlist_update() connecting to peer: %s:%d",
			    inet_ntoa(ep->sa.sin_addr), ntohs(ep->sa.sin_port));
			/* XXX does this failure case do anything worthwhile? */
			if ((ep->connfd = network_connect_peer(ep)) == -1) {
				trace("network_peerlist_update() failure connecting to peer: %s:%d - removing",
				    inet_ntoa(ep->sa.sin_addr), ntohs(ep->sa.sin_port));
				TAILQ_REMOVE(&sc->peers, ep, peer_list);
				network_peer_free(ep);
				sc->num_peers--;
				continue;
			}
			trace("network_peerlist_update() connected fd %d to peer: %s:%d",
			    ep->connfd, inet_ntoa(ep->sa.sin_addr), ntohs(ep->sa.sin_port));
			ep->bufev = bufferevent_new(ep->connfd, network_handle_peer_response,
			    network_handle_peer_write, network_handle_peer_error, ep);
			if (ep->bufev == NULL)
				errx(1, "network_peerlist_update: bufferevent_new failure");
			bufferevent_enable(ep->bufev, EV_READ|EV_WRITE);
			trace("network_peerlist_update() initiating handshake");
			network_peer_handshake(sc, ep);
		}
	}
}

static void
network_peerlist_update(struct session *sc, struct benc_node *peers)
{
	if (peers->flags & BSTRING) {
		network_peerlist_update_string(sc, peers);
	} else {
		network_peerlist_update_dict(sc, peers);
	}
}

static struct peer *
network_peer_create(void)
{
	struct peer *p;
	p = xmalloc(sizeof(*p));
	memset(p, 0, sizeof(*p));
	TAILQ_INIT(&p->peer_piece_dls);
	/* peers start in choked state */
	p->state |= PEER_STATE_CHOKED;

	return (p);
}

static void
network_peer_free(struct peer *p)
{
	struct piece_dl *pd, *nxtpd;
	/* search the piece dl list for any dls associated with this peer */
	for (pd = TAILQ_FIRST(&p->peer_piece_dls); pd; pd = nxtpd) {
		nxtpd = TAILQ_NEXT(pd, peer_piece_dl_list);
		network_piece_dl_free(pd);
	}
	if (p->bufev != NULL && p->bufev->enabled & EV_WRITE) {
		bufferevent_disable(p->bufev, EV_WRITE|EV_READ);
		bufferevent_free(p->bufev);
		p->bufev = NULL;
	}
	if (p->rxmsg != NULL)
		xfree(p->rxmsg);
	if (p->txmsg != NULL)
		xfree(p->txmsg);
	if (p->bitfield != NULL)
		xfree(p->bitfield);
	if (p->connfd != 0) {
		(void)  close(p->connfd);
		p->connfd = 0;
	}

	xfree(p);
	p = NULL;
}

static void
network_peer_handshake(struct session *sc, struct peer *p)
{
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
	if (gettimeofday(&p->connected, NULL) == -1)
		err(1, "network_peer_handshake: gettimeofday");
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
		trace("network_handle_peer_error() TIMEOUT for peer %s:%d", inet_ntoa(p->sa.sin_addr), ntohs(p->sa.sin_port));
	}
	if (error & EVBUFFER_EOF) {
		p->state = 0;
		p->state |= PEER_STATE_DEAD;
		trace("network_handle_peer_error() EOF for peer %s:%d", inet_ntoa(p->sa.sin_addr), ntohs(p->sa.sin_port));
	} else {
		trace("network_handle_peer_error() error for peer %s:%d", inet_ntoa(p->sa.sin_addr), ntohs(p->sa.sin_port));
		p->state = 0;
		p->state |= PEER_STATE_DEAD;
	}
}

static void
network_handle_peer_write(struct bufferevent *bufev, void *data)
{
	struct peer *p = data;
	/* XXX: may be insufficient to prevent leaks, as
	 * what if the peer write event never fires? do we need to keep a list of writes for each peer?
	 * */
	if (p->txmsg != NULL) {
		xfree(p->txmsg);
		p->txmsg = NULL;
	}
}

static void
network_handle_peer_response(struct bufferevent *bufev, void *data)
{
	struct peer *p = data;
	size_t len;
	u_int32_t msglen;
	u_int8_t *base, id = 0;

	if (p == NULL)
		errx(1, "network_handle_peer_response() NULL peer!");

	/* the complicated thing here is the non-blocking IO, which
	 * means we have to be prepared to come back later and add more
	 * data */

	if (p->state & PEER_STATE_HANDSHAKE1 && p->rxpending == 0) {
		p->rxmsg = xmalloc(BT_INITIAL_LEN);
		p->rxmsglen = BT_INITIAL_LEN;
		p->rxpending = p->rxmsglen;
		goto read;
	} else {
		if (p->rxpending == 0) {
			/* this is a new message */
			p->state &= ~PEER_STATE_GOTLEN;
			p->rxmsg = xmalloc(LENGTH_FIELD);
			p->rxmsglen = LENGTH_FIELD;
			p->rxpending = p->rxmsglen;

			goto read;
		} else {
		read:
			base = p->rxmsg + (p->rxmsglen - p->rxpending);
			len = bufferevent_read(bufev, base, p->rxpending);
			p->totalrx += len;
			p->rxpending -= len;
			/* more rx data pending, come back later */
			if (p->rxpending > 0)
				goto out;
			if (p->state & PEER_STATE_HANDSHAKE1) {
				memcpy(&p->pstrlen, p->rxmsg,
				    sizeof(p->pstrlen));
				/* test for plain handshake */
				if (p->pstrlen == BT_PSTRLEN
				    && memcmp(p->rxmsg+1, BT_PROTOCOL, BT_PSTRLEN) == 0) {
					xfree(p->rxmsg);
					p->rxmsg = NULL;
					/* see comment above network_peer_handshake() for explanation of these numbers */
					p->rxpending = 8 + 20 + 20;
					p->rxmsglen = p->rxpending;
					p->rxmsg = xmalloc(p->rxmsglen);
					p->state &= ~PEER_STATE_HANDSHAKE1;
					p->state |= PEER_STATE_HANDSHAKE2;
					goto out;

				} else {
				/* XXX: try D-H key exchange */
					trace("network_handle_peer_response: crypto, killing peer for now");
					p->state = 0;
					p->state |= PEER_STATE_DEAD;
					goto out;
				}

			}
			if (p->state & PEER_STATE_HANDSHAKE2) {
				/* see comment above network_peer_handshake() for explanation of these numbers */
				memcpy(&p->info_hash, p->rxmsg + 8, 20);
				memcpy(&p->id, p->rxmsg + 8 + 20, 20);
				if (memcmp(p->info_hash, p->sc->tp->info_hash, 20) != 0) {
					trace("network_handle_peer_response() info hash mismatch for peer %s:%d", inet_ntoa(p->sa.sin_addr), ntohs(p->sa.sin_port));
					p->state = 0;
					p->state |= PEER_STATE_DEAD;
					goto out;
				}

				xfree(p->rxmsg);
				p->rxmsg = NULL;
				p->state |= PEER_STATE_BITFIELD;
				p->state &= ~PEER_STATE_HANDSHAKE2;
				/* XXX if we have some pieces, we probably want to send our bitfield
				network_peer_write_bitfield(p);
				*/
				p->rxpending = 0;
				goto out;
			}
			if (!(p->state & PEER_STATE_GOTLEN)) {
				/* got the length field */
				memcpy(&msglen, p->rxmsg, sizeof(msglen));
				p->rxmsglen = ntohl(msglen);
				if (p->rxmsglen > MAX_MESSAGE_LEN) {
					trace("network_handle_peer_response() got a message %u bytes long, longer than %u bytes, assuming its malicious and killing peer %s:%d", p->rxmsglen, MAX_MESSAGE_LEN, inet_ntoa(p->sa.sin_addr), ntohs(p->sa.sin_port));
					p->state = 0;
					p->state |= PEER_STATE_DEAD;
					goto out;
				}
				if (p->rxmsg != NULL) {
					xfree(p->rxmsg);
					p->rxmsg = NULL;
				}
				p->state |= PEER_STATE_GOTLEN;
				/* keep-alive: do nothing */
				if (p->rxmsglen == 0)
					goto out;
				p->rxmsg = xmalloc(p->rxmsglen);
				memset(p->rxmsg, 0, p->rxmsglen);
				p->rxpending = p->rxmsglen;
				goto out;
			}
		}

		/* if we get this far, means we have the entire message */
		memcpy(&id, p->rxmsg, 1);
		network_peer_process_message(id, p);
		if (p->rxmsg != NULL) {
			xfree(p->rxmsg);
			p->rxmsg = NULL;
		}
	}
out:
	if (gettimeofday(&p->lastrecv, NULL) == -1)
		err(1, "network_handle_peer_response: gettimeofday");
	if (EVBUFFER_LENGTH(EVBUFFER_INPUT(bufev)))
		bufev->readcb(bufev, data);
}

static void
network_peer_process_message(u_int8_t id, struct peer *p)
{
	struct torrent_piece *tpp;
	struct peer *tp;
	struct piece_dl *pd, *nxtpd;
	u_int32_t bitfieldlen, idx, blocklen, off;
	int res = 0;
	int found = 0;

	/* XXX: safety-check for correct message lengths */
	switch (id) {
		case PEER_MSG_ID_CHOKE:
			trace("CHOKE message from peer %s:%d", inet_ntoa(p->sa.sin_addr), ntohs(p->sa.sin_port));
			p->state |= PEER_STATE_CHOKED;
			for (pd = TAILQ_FIRST(&p->peer_piece_dls); pd; pd = nxtpd) {
				nxtpd = TAILQ_NEXT(pd, peer_piece_dl_list);
				network_piece_dl_free(pd);
			}
			break;
		case PEER_MSG_ID_UNCHOKE:
			trace("UNCHOKE message from peer %s:%d", inet_ntoa(p->sa.sin_addr), ntohs(p->sa.sin_port));
			p->state &= ~PEER_STATE_CHOKED;
			break;
		case PEER_MSG_ID_INTERESTED:
			trace("INTERESTED message from peer %s:%d", inet_ntoa(p->sa.sin_addr), ntohs(p->sa.sin_port));
			p->state |= PEER_STATE_INTERESTED;
			break;
		case PEER_MSG_ID_NOTINTERESTED:
			trace("NOTINTERESTED message from peer %s:%d", inet_ntoa(p->sa.sin_addr), ntohs(p->sa.sin_port));
			p->state &= ~PEER_STATE_INTERESTED;
			break;
		case PEER_MSG_ID_HAVE:
			memcpy(&idx, p->rxmsg+sizeof(id), sizeof(idx));
			idx = ntohl(idx);
			trace("HAVE message from peer %s:%d (idx=%u)", inet_ntoa(p->sa.sin_addr), ntohs(p->sa.sin_port), idx);
			if (idx > p->sc->tp->num_pieces - 1) {
				trace("have index overflow, ignoring");
				break;
			}
			if (p->bitfield == NULL) {
				bitfieldlen = (p->sc->tp->num_pieces + 7) / 8;
				p->bitfield = xmalloc(bitfieldlen);
				memset(p->bitfield, 0, bitfieldlen);
				p->state &= ~PEER_STATE_BITFIELD;
				p->state |= PEER_STATE_ESTABLISHED;
			}
			setbit(p->bitfield, idx);
			break;
		case PEER_MSG_ID_BITFIELD:
			trace("BITFIELD message from peer %s:%d", inet_ntoa(p->sa.sin_addr), ntohs(p->sa.sin_port));
			if (!(p->state & PEER_STATE_BITFIELD)) {
				trace("not expecting bitfield!");
				break;
			}
			bitfieldlen = p->rxmsglen - sizeof(id);
			if (bitfieldlen != (p->sc->tp->num_pieces + 7) / 8) {
				trace("bitfield is wrong size! killing peer connection (is: %u should be: %u)", bitfieldlen*8, p->sc->tp->num_pieces + 7);
				p->state = 0;
				p->state |= PEER_STATE_DEAD;
				break;
			}
			p->bitfield = xmalloc(bitfieldlen);
			memset(p->bitfield, 0, bitfieldlen);
			memcpy(p->bitfield, p->rxmsg+sizeof(id), bitfieldlen);
			p->state &= ~PEER_STATE_BITFIELD;
			p->state |= PEER_STATE_ESTABLISHED;
			network_peer_write_interested(p);
			break;
		case PEER_MSG_ID_REQUEST:
			trace("REQUEST message from peer %s:%d", inet_ntoa(p->sa.sin_addr), ntohs(p->sa.sin_port));
			memcpy(&idx, p->rxmsg+sizeof(id), sizeof(idx));
			idx = ntohl(idx);
			if (idx > p->sc->tp->num_pieces - 1) {
				trace("PIECE index out of bounds");
				break;
			}
			memcpy(&off, p->rxmsg+sizeof(idx), sizeof(off));
			off = ntohl(off);
			tpp = torrent_piece_find(p->sc->tp, idx);
			if (off > tpp->len) {
				trace("PIECE offset out of bounds");
				break;
			}
			memcpy(&blocklen, p->rxmsg+sizeof(id)+sizeof(idx)+sizeof(off), sizeof(blocklen));
			blocklen = ntohl(blocklen);
			network_peer_write_piece(p, idx, off, blocklen);
			break;
		case PEER_MSG_ID_PIECE:
			p->state |= PEER_STATE_ISTRANSFERRING;
			memcpy(&idx, p->rxmsg+sizeof(id), sizeof(idx));
			idx = ntohl(idx);
			memcpy(&off, p->rxmsg+sizeof(id)+sizeof(idx), sizeof(off));
			off = ntohl(off);
			trace("PIECE message (idx=%u off=%u len=%u) from peer %s:%d", idx,
			    off, p->rxmsglen, inet_ntoa(p->sa.sin_addr), ntohs(p->sa.sin_port));
			if (idx > p->sc->tp->num_pieces - 1) {
				trace("PIECE index out of bounds");
				break;
			}
			tpp = torrent_piece_find(p->sc->tp, idx);
			if (off > tpp->len) {
				trace("PIECE offset out of bounds");
				break;
			}
			/* Only read if we don't already have it */
			if (!(tpp->flags & TORRENT_PIECE_CKSUMOK)) {
				p->queue_len--;
				if (!(tpp->flags & TORRENT_PIECE_MAPPED))
					torrent_piece_map(tpp);
				network_peer_read_piece(p, idx, off,
				    p->rxmsglen-(sizeof(id)+sizeof(off)+sizeof(idx)),
				    p->rxmsg+sizeof(id)+sizeof(off)+sizeof(idx));
				/* only checksum if we think we have every block of this piece */
				found = 1;
				for (off = 0; off < tpp->len; off += BLOCK_SIZE) {
					if ((pd = network_piece_dl_find(p->sc, idx, off)) == NULL) {
						found = 0;
						break;
					}
				}
				if (found) {
					res = torrent_piece_checkhash(p->sc->tp, tpp);
					torrent_piece_unmap(tpp);
					if (res == 0) {
						trace("hash check success for piece %d", idx);
						p->sc->tp->good_pieces++;
						p->sc->tp->left -= tpp->len;
						if (p->sc->tp->good_pieces == p->sc->tp->num_pieces) {
							refresh_progress_meter();
							exit(0);
						}
						/* send HAVE messages to all peers */
						TAILQ_FOREACH(tp, &p->sc->peers, peer_list)
							network_peer_write_have(tp, idx);
						/* clean up all the piece dls for this now that its done */
						for (off = 0; off < tpp->len; off += BLOCK_SIZE) {
							if ((pd = network_piece_dl_find(p->sc, idx, off)) != NULL) {
								network_piece_dl_free(pd);
							}
						}
					} else {
						trace("hash check failure for piece %d", idx);
					}
				}
			} else {
				/* XXX hash check failed, try re-downloading this piece? */
				/* clean up this piece dl, although its not fully the correct thing to do */
				if ((pd = network_piece_dl_find(p->sc, idx, off)) != NULL) {
					network_piece_dl_free(pd);
					p->queue_len--;
				}
			}
			break;
		case PEER_MSG_ID_CANCEL:
			/* XXX: not sure how to cancel a write */
			trace("CANCEL message from peer %s:%d", inet_ntoa(p->sa.sin_addr), ntohs(p->sa.sin_port));
			break;
		default:
			trace("Unknown message from peer %s:%d", inet_ntoa(p->sa.sin_addr), ntohs(p->sa.sin_port));
			break;
	}
}

static void
network_peer_write_have(struct peer *p, u_int32_t idx)
{
	u_int32_t msglen, msglen2;
	u_int8_t  *msg, id;

	msglen = sizeof(msglen) + sizeof(id) + sizeof(idx);
	msg = xmalloc(msglen);

	msglen2 = htonl(msglen - sizeof(msglen));
	id = PEER_MSG_ID_HAVE;
	idx = htonl(idx);

	memcpy(msg, &msglen2, sizeof(msglen2));
	memcpy(msg+sizeof(msglen2), &id, sizeof(id));
	memcpy(msg+sizeof(msglen2)+sizeof(id), &idx, sizeof(idx));

	p->txmsg = msg;
	if (bufferevent_write(p->bufev, msg, msglen) != 0)
		errx(1, "network_peer_request_block: bufferevent_write failure");

}

static void
network_peer_write_piece(struct peer *p, u_int32_t idx, off_t offset, u_int32_t len)
{
	struct torrent_piece *tpp;
	void *data;
	int hint;

	trace("network_peer_write_piece() at index %u offset %u length %u to peer %s:%d",
	      idx, offset, len, inet_ntoa(p->sa.sin_addr), ntohs(p->sa.sin_port));
	if ((tpp = torrent_piece_find(p->sc->tp, idx)) == NULL) {
		trace("network_peer_write_piece() piece %u - failed at torrent_piece_find(), returning", idx);
		return;
	}
	if (!(tpp->flags & TORRENT_PIECE_MAPPED))
		torrent_piece_map(tpp);
	if ((data = torrent_block_read(tpp, offset, len, &hint)) == NULL) {
		trace("network_peer_write_piece() piece %u - failed at torrent_block_read(), returning", idx);
		return;
	}
	torrent_piece_unmap(tpp);
	if (bufferevent_write(p->bufev, data, len) != 0)
		errx(1, "network_peer_write_piece: bufferevent_write failure");
}

static void
network_peer_read_piece(struct peer *p, u_int32_t idx, off_t offset, u_int32_t len, void *data)
{
	struct torrent_piece *tpp;
	struct piece_dl *pd;

	if ((tpp = torrent_piece_find(p->sc->tp, idx)) == NULL) {
		trace("network_peer_read_piece: piece %u - failed at torrent_piece_find(), returning", idx);
		return;
	}
	trace("network_peer_read_piece() at index %u offset %u length %u", idx, offset, len);
	if ((pd = network_piece_dl_find(p->sc, idx, offset)) == NULL)
		errx(1, "network_peer_read_piece: no piece_dl for idx %u", idx);
	torrent_block_write(tpp, offset, len, data);
	pd->bytes += len;
	/* XXX not really accurate measure of progress since the data could be bad */
	p->sc->tp->downloaded += len;
	p->state &= ~PEER_STATE_ISTRANSFERRING;
	p->totalrx += len;
}

static void
network_peer_piece_dl(struct piece_dl *pd)
{
	network_peer_request_block(pd->pc, pd->idx, pd->off, pd->len);
}

static void
network_peer_request_block(struct peer *p, u_int32_t idx, u_int32_t off, u_int32_t len)
{
	u_int32_t msglen, msglen2, blocklen;
	u_int8_t  *msg, id;

	trace("network_peer_request_block, index: %u offset: %u len: %u to peer %s:%d", idx, off, len,
	    inet_ntoa(p->sa.sin_addr), ntohs(p->sa.sin_port));
	msglen = sizeof(msglen) + sizeof(id) + sizeof(idx) + sizeof(off) + sizeof(blocklen);
	msg = xmalloc(msglen);

	msglen2 = htonl(msglen - sizeof(msglen));
	id = PEER_MSG_ID_REQUEST;
	idx = htonl(idx);
	off = htonl(off);
	blocklen = htonl(len);

	memcpy(msg, &msglen2, sizeof(msglen2));
	memcpy(msg+sizeof(msglen2), &id, sizeof(id));
	memcpy(msg+sizeof(msglen2)+sizeof(id), &idx, sizeof(idx));
	memcpy(msg+sizeof(msglen2)+sizeof(id)+sizeof(idx), &off, sizeof(off));
	memcpy(msg+sizeof(msglen2)+sizeof(id)+sizeof(idx)+sizeof(off), &blocklen, sizeof(blocklen));

	p->txmsg = msg;
	if (bufferevent_write(p->bufev, msg, msglen) != 0)
		errx(1, "network_peer_request_block: bufferevent_write failure");
	p->state |= PEER_STATE_ISTRANSFERRING;
}

static void
network_peer_cancel_piece(struct piece_dl *pd)
{
	u_int32_t msglen, msglen2, blocklen, off, idx;
	u_int8_t  *msg, id;

	trace("network_peer_cancel_piece, index: %u offset: %u to peer %s:%d",
	     pd->idx, pd->off,
	    inet_ntoa(pd->pc->sa.sin_addr), ntohs(pd->pc->sa.sin_port));
	msglen = sizeof(msglen) + sizeof(id) + sizeof(idx) + sizeof(off) + sizeof(blocklen);
	msg = xmalloc(msglen);
	msglen2 = htonl(msglen - sizeof(msglen));
	id = PEER_MSG_ID_CANCEL;
	idx = htonl(pd->idx);
	off = htonl(pd->off);
	blocklen = htonl(pd->len);

	memcpy(msg, &msglen2, sizeof(msglen2));
	memcpy(msg+sizeof(msglen2), &id, sizeof(id));
	memcpy(msg+sizeof(msglen2)+sizeof(id), &idx, sizeof(idx));
	memcpy(msg+sizeof(msglen2)+sizeof(id)+sizeof(idx), &off, sizeof(off));
	memcpy(msg+sizeof(msglen2)+sizeof(id)+sizeof(idx)+sizeof(off), &blocklen, sizeof(blocklen));

	pd->pc->txmsg = msg;
	if (bufferevent_write(pd->pc->bufev, msg, msglen) != 0)
		errx(1, "network_peer_request_piece: bufferevent_write failure");
	pd->pc->state |= PEER_STATE_ISTRANSFERRING;
}

static void
network_peer_write_interested(struct peer *p)
{
	u_int8_t id;
	u_int32_t len;

	trace("network_peer_write_interested() to peer %s:%d", inet_ntoa(p->sa.sin_addr), ntohs(p->sa.sin_port));
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
	u_int32_t bitfieldlen, msglen, msglen2;

	bitfieldlen = (p->sc->tp->num_pieces + 7) / 8;

	trace("network_peer_write_bitfield() to peer %s:%d", inet_ntoa(p->sa.sin_addr), ntohs(p->sa.sin_port));
	id = PEER_MSG_ID_BITFIELD;
	bitfield = torrent_bitfield_get(p->sc->tp);

	msglen = sizeof(id) + bitfieldlen;
	p->txmsg = xmalloc(msglen);
	memset(p->txmsg, 0, msglen);
	msglen2 = htonl(msglen);
	memcpy(p->txmsg, &msglen2, sizeof(msglen2));
	memcpy(p->txmsg+sizeof(msglen), &id, sizeof(id));
	memcpy(p->txmsg+sizeof(msglen)+sizeof(id), bitfield, bitfieldlen);

	if (bufferevent_write(p->bufev, p->txmsg, msglen) != 0)
		errx(1, "network_peer_write_bitfield: bufferevent_write failure");

	trace("network_peer_write_bitfield() freeing bitfield");
	xfree(bitfield);
}
static void
network_peer_write_unchoke(struct peer *p)
{
	u_int8_t id;
	u_int32_t len;

	trace("network_peer_write_unchoke() to peer %s:%d", inet_ntoa(p->sa.sin_addr), ntohs(p->sa.sin_port));
	len = htonl(sizeof(id));
	id = PEER_MSG_ID_UNCHOKE;

	p->txmsg = xmalloc(sizeof(len) + sizeof(id));
	memcpy(p->txmsg, &len, sizeof(len));
	memcpy(p->txmsg+sizeof(len), &id, sizeof(id));

	if (bufferevent_write(p->bufev, p->txmsg, sizeof(len) + sizeof(id)) != 0)
		errx(1, "network_peer_write_unchoke: bufferevent_write failure");
}

/*
 * Are all this piece's blocks in the download queue?
 * Returns 1 on success, 0 on failure
 */
static int
network_piece_inqueue(struct session *sc, struct torrent_piece *tpp)
{
	u_int32_t off;

	/* if this piece and all its blocks are already in our download queue, skip it */
	for (off = 0; ; off += BLOCK_SIZE) {
		if (off >= tpp->len)
			return (1);
		if (network_piece_dl_find(sc, tpp->index, off) == NULL)
			return (0);
	}
}

static int
network_piece_cmp(const void *a, const void *b)
{
	const struct piececounter *x, *y;

	x = a;
	y = b;

	return (x->count - y->count);

}

/* for a given session return sorted array of piece counts*/
static struct piececounter *
network_piece_rarityarray(struct session *sc)
{
	struct piececounter *pieces;
	struct peer *p;
	u_int32_t i, count, pos, len;

	pos = 0;
	len = sc->tp->num_pieces;
	pieces = xcalloc(len, sizeof(*pieces));

	/* counts for each piece */
	for (i = 0; i < len; i++) {
		count = 0;
		/* otherwise count it */
		TAILQ_FOREACH(p, &sc->peers, peer_list) {
			if (!(p->state & PEER_STATE_ESTABLISHED))
				continue;
			if (BIT_ISSET(p->bitfield, i))
				count++;
		}
		if (pos > len)
			errx(1, "network_piece_rarityarray: pos is %u should be %u\n", pos, (sc->tp->num_pieces - sc->tp->good_pieces - 1));

		pieces[pos].count = count;
		pieces[pos].idx = i;
		pos++;
	}
	/* sort the rarity array */
	qsort(pieces, len, sizeof(*pieces),
	    network_piece_cmp);

	return (pieces);
}

#define FIND_RAREST_IGNORE_INQUEUE	0
#define FIND_RAREST_ABSOLUTE		1
static u_int32_t
network_piece_find_rarest(struct session *sc, int flag, int *res)
{
	struct torrent_piece *tpp;
	struct piececounter *pieces;
	u_int32_t i;
	int found = 0;

	tpp = NULL;
	*res = 1;

	pieces = network_piece_rarityarray(sc);
	/* find the rarest piece amongst our peers */
	for (i = 0; i < sc->tp->num_pieces; i++) {
		tpp = torrent_piece_find(sc->tp, pieces[i].idx);
		/* if we have this piece, skip it */
		if (tpp->flags & TORRENT_PIECE_CKSUMOK) {
			continue;
		}
		if (flag == FIND_RAREST_IGNORE_INQUEUE) {
			/* if this piece and all its blocks are already in our download queue, skip it */
			if (network_piece_inqueue(sc, tpp)) {
				continue;
			} else {
				found = 1;
				break;
			}
		} else {
			found = 1;
			break;
		}
	}

	*res = found;
	xfree(pieces);
	return (tpp->index);
}


/* hand me something to download */
static struct piece_dl *
network_piece_gimme(struct peer *peer)
{
	struct torrent_piece *tpp;
	struct piece_dl *pd;
	struct piece_dl_idxnode *pdin;
	u_int32_t idx, len, off;
	int res;

	res = 0;
	idx = off = 0;
	tpp = NULL;

	/* XXX: prioritise incomplete pieces for which we have some blocks */
	RB_FOREACH(pdin, piece_dl_by_idxoff, &peer->sc->piece_dl_by_idxoff) {
		tpp = torrent_piece_find(peer->sc->tp, pdin->idx);
		if (!(tpp->flags & TORRENT_PIECE_CKSUMOK)) {
			/* if not all this piece's blocks are in the download queue */
			if (!network_piece_inqueue(peer->sc, tpp)) {
				idx = pdin->idx;
				goto get_block;
			}
		}
	}
	/* XXX: first 4 pieces should be chosen at random */
	if (peer->sc->tp->good_pieces < 4 && peer->sc->tp->num_pieces > 4) {
		for (;;) {
			idx = random() % (peer->sc->tp->num_pieces - 1);
			tpp = torrent_piece_find(peer->sc->tp, idx);
			/* do we already have this piece? */
			if (tpp->flags & TORRENT_PIECE_CKSUMOK)
				continue;
			/* is it already in our download queue? */
			if (network_piece_inqueue(peer->sc, tpp))
				continue;
			/* if not, run with it */
			break;
		}
	} else {
		/* find the rarest piece that does not have all its blocks already in the download queue */
		idx = network_piece_find_rarest(peer->sc, FIND_RAREST_IGNORE_INQUEUE, &res);
		/* there are no more pieces */
		if (!res)
			return (NULL);
		tpp = torrent_piece_find(peer->sc->tp, idx);
	}
get_block:
	/* find the next block (by offset) in the piece, which is not already in the download queue */
	for (off = 0; ; off += BLOCK_SIZE) {
		if (off >= tpp->len)
			errx(1, "gone to a bad offset %u in idx %u, len %u", off, idx, tpp->len);
		if (network_piece_dl_find(peer->sc, idx, off) == NULL) {
			break;
		}
	}
	if (BLOCK_SIZE > tpp->len - off)
		len = tpp->len - off;
	else
		len = BLOCK_SIZE;
	pd = network_piece_dl_create(peer, idx, off, len);

	trace("choosing next dl (tpp->len %u) len %u idx %u off %u", tpp->len, len, idx, off);
	return (pd);
}

/* bulk of decision making happens here.  run every second, once announce is complete. */
static void
network_scheduler(int fd, short type, void *arg)
{
	struct torrent_piece *tpp;
	struct peer *p, *nxt;
	struct session *sc = arg;
	struct timeval tv, now;
	/* piece rarity array */
	struct piece_dl *pd;
	struct piece_dl_idxnode *pdin;
	u_int32_t pieces_left, reqs;
	u_int64_t peer_rate;
	u_int8_t queue_len, i, choked, unchoked;

	reqs = choked = unchoked = 0;
	p = NULL;
	timerclear(&tv);
	tv.tv_sec = 1;
	evtimer_set(&sc->scheduler_event, network_scheduler, sc);
	evtimer_add(&sc->scheduler_event, &tv);

	/* XXX: need choke algorithm */
	/* XXX: try to keep a decent number of peers connected */

	pieces_left = sc->tp->num_pieces - sc->tp->good_pieces;
	if (!TAILQ_EMPTY(&sc->peers)) {
		for (p = TAILQ_FIRST(&sc->peers); p; p = nxt) {
			nxt = TAILQ_NEXT(p, peer_list);
			if (p->state & PEER_STATE_CHOKED)
				choked++;
			else
				unchoked++;
			/* if peer is marked dead, free it */
			if (p->state & PEER_STATE_DEAD) {
				TAILQ_REMOVE(&sc->peers, p, peer_list);
				network_peer_free(p);
				pd = NULL;
				sc->num_peers--;
				continue;
			}
			/* if we have not received data in PEER_COMMS_THRESHOLD,
			 * remove the block requests from our list and kill the peer */
			if ((p->state & PEER_STATE_BITFIELD || p->state & PEER_STATE_ESTABLISHED)
			    && network_peer_lastcomms(p) >= PEER_COMMS_THRESHOLD) {
				trace("comms threshold exceeded for peer %s:%d",
				    inet_ntoa(p->sa.sin_addr), ntohs(p->sa.sin_port));
				p->state = 0;
				p->state |= PEER_STATE_DEAD;
				continue;
			}
			/* if we are not transferring to/from this peer */
			if (!(p->state & PEER_STATE_ISTRANSFERRING)) {
				if (!(p->state & PEER_STATE_CHOKED)) {
					peer_rate = network_peer_rate(p);
					/* for each 10k/sec on this peer, add a request. */
					/* minimum queue length is 2, max is MAX_REQUESTS */
					queue_len = peer_rate / 10240;
					if (queue_len < 2)
						queue_len = 2;
					else if (queue_len > MAX_REQUESTS)
						queue_len = MAX_REQUESTS;
					/* queue_len is what the peer's queue length should be */
					queue_len -= p->queue_len;

					for (i = 0; i < queue_len; i++) {
						pd = network_piece_gimme(p);
						/* probably means no bitfield from this peer yet, or all requests are in transit. give it some time. */
						if (pd == NULL) {
							continue;
						}
						network_peer_piece_dl(pd);
						p->queue_len++;
					}
				}
			}
		}
	}
	if (gettimeofday(&now, NULL) == -1)
		err(1, "network_scheduler: gettimeofday");
	/* try to get some more peers */
	if (sc->num_peers < PEERS_WANTED
	    && (now.tv_sec - sc->last_announce.tv_sec) > MIN_ANNOUNCE_INTERVAL) {
		/* XXX: But what if the tracker really only has a small number of peers?
		 * We will keep asking over and over, wasting resources.
		 * This should be fixed */
		network_announce(sc, NULL);
	}
	RB_FOREACH(pdin, piece_dl_by_idxoff, &sc->piece_dl_by_idxoff) {
		tpp = torrent_piece_find(sc->tp, pdin->idx);
		if (!(tpp->flags & TORRENT_PIECE_CKSUMOK))
			reqs++;
	}
	trace("Peers: %u Good pieces: %u/%u Reqs in flight: %u Choked: %u Unchoked: %u",
	      sc->num_peers, sc->tp->good_pieces, sc->tp->num_pieces, reqs, choked, unchoked);

	/* every 30 seconds, print out all the piece dls and their peers */
	if ((now.tv_sec % 30) == 0) {
		RB_FOREACH(pdin, piece_dl_by_idxoff, &sc->piece_dl_by_idxoff) {
			tpp = torrent_piece_find(sc->tp, pdin->idx);
			if (!(tpp->flags & TORRENT_PIECE_CKSUMOK))
				reqs++;
			trace("Piece dl idx: %u off %u",  pdin->idx, pdin->off);
		}
	}
}
/* start handling network stuff for a new torrent */
int
network_start_torrent(struct torrent *tp, rlim_t maxfds)
{
	int ret;
	struct session *sc;
	off_t len;

	sc = xmalloc(sizeof(*sc));
	memset(sc, 0, sizeof(*sc));

	TAILQ_INIT(&sc->peers);
	sc->tp = tp;
	sc->maxfds = maxfds;
	if (user_port == NULL) {
		sc->port = xstrdup("6668");
	} else {
		sc->port = xstrdup(user_port);
		trace("using port %s instead of default", user_port);
	}
	/* XXX: this needs to be randomly generated */
	sc->peerid = xstrdup("U1234567891234567890");

	if (tp->type == SINGLEFILE)
		len = tp->body.singlefile.tfp.file_length;
	else
		len = tp->body.multifile.total_length;

	start_progress_meter(tp->name, len, &tp->downloaded);
	ret = network_announce(sc, "started");

	event_dispatch();
	trace("network_start_torrent() returning");

	return (ret);
}

static DH *
network_crypto_dh()
{
	DH *dhp;

	if ((dhp = DH_new()) == NULL)
		errx(1, "network_crypto_pubkey: DH_new() failure");
	if ((dhp->p = BN_bin2bn(mse_P, CRYPTO_INT_LEN, NULL)) == NULL)
		errx(1, "network_crypto_pubkey: BN_bin2bn(P) failure");
	if ((dhp->g = BN_bin2bn(mse_G, CRYPTO_INT_LEN, NULL)) == NULL)
		errx(1, "network_crypto_pubkey: BN_bin2bn(G) failure");
	if (DH_generate_key(dhp) == 0)
		errx(1, "network_crypto_pubkey: DH_generate_key() failure");

	return (dhp);
}

/* return how long in seconds since last communication on this peer */
static long
network_peer_lastcomms(struct peer *p)
{
	struct timeval now;

	if (gettimeofday(&now, NULL) != 0)
		err(1, "network_peer_lastcomms: gettimeofday");

	return (now.tv_sec - p->lastrecv.tv_sec);
}

/* return the instantaneous transfer rate of a given peer */
static u_int64_t
network_peer_rate(struct peer *p)
{
	struct timeval now;
	u_int64_t rate;

	if (gettimeofday(&now, NULL) != 0)
		err(1, "network_peer_rate: gettimeofday");
	rate = now.tv_sec - p->connected.tv_sec;
	/* prevent divide by zero */
	if (rate == 0)
		return (0);
	return (p->totalrx / rate);

}

static struct piece_dl *
network_piece_dl_create(struct peer *p, u_int32_t idx, u_int32_t off,
    u_int32_t len)
{
	struct piece_dl *pd;
	struct piece_dl_idxnode find, *res;

	pd = xmalloc(sizeof(*pd));
	memset(pd, 0, sizeof(*pd));
	pd->pc = p;
	pd->idx = idx;
	pd->off = off;
	pd->len = len;

	/* check for an existing piece_dl_idxnode */
	find.off = off;
	find.idx = idx;
	if ((res = RB_FIND(piece_dl_by_idxoff, &p->sc->piece_dl_by_idxoff, &find)) == NULL) {
		/* need to create one */
		res = xmalloc(sizeof(*res));
		memset(res, 0, sizeof(*res));
		res->off = off;
		res->idx = idx;
		TAILQ_INIT(&res->idxnode_piece_dls);
		TAILQ_INSERT_TAIL(&res->idxnode_piece_dls, pd, idxnode_piece_dl_list);
		RB_INSERT(piece_dl_by_idxoff, &p->sc->piece_dl_by_idxoff, res);
	} else {
		/* found a pre-existing one, just append this to its list */
		TAILQ_INSERT_TAIL(&res->idxnode_piece_dls, pd, idxnode_piece_dl_list);
	}
	TAILQ_INSERT_TAIL(&p->peer_piece_dls, pd, peer_piece_dl_list);

	return (pd);
}

static void
network_piece_dl_free(struct piece_dl *pd)
{
	struct piece_dl_idxnode find, *res;
	find.off = pd->off;
	find.idx = pd->idx;
	/* remove from index/offset btree */
	if ((res = RB_FIND(piece_dl_by_idxoff, &pd->pc->sc->piece_dl_by_idxoff, &find)) == NULL) {
		errx(1, "network_piece_dl_free: could not find idxoff node in tree");
	} else {
		trace("found idxnode idx %u off %u", res->idx, res->off);
		TAILQ_REMOVE(&res->idxnode_piece_dls, pd, idxnode_piece_dl_list);

	}
	/* remove from per-peer list */
	TAILQ_REMOVE(&pd->pc->peer_piece_dls, pd, peer_piece_dl_list);
	/* RB_REMOVE(piece_dl_by_idxoff, &pd->pc->sc->piece_dl_by_idxoff, pd); */
	xfree(pd);
	pd = NULL;
}

static struct piece_dl *
network_piece_dl_find(struct session *sc, u_int32_t idx, u_int32_t off)
{
	struct piece_dl_idxnode find, *res;

	find.off = off;
	find.idx = idx;
	if ((res = RB_FIND(piece_dl_by_idxoff, &sc->piece_dl_by_idxoff, &find)) == NULL)
		return (NULL);
	
	/* XXX: for now, return the first piece_dl in the peice_dl_idxnode's list.
	 * later, uniqueness of piece_dl by their index and offset will not be
	 * assumed and we will have to mroe properly handle this */
	if (TAILQ_EMPTY(&res->idxnode_piece_dls))
		return (NULL);


	return (TAILQ_FIRST(&res->idxnode_piece_dls));
}

/* network subsystem init, needs to be called before doing anything */
void
network_init()
{
	event_init();
}

