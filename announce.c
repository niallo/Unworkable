/* $Id: announce.c,v 1.12 2008-10-02 17:19:56 niallo Exp $ */
/*
 * Copyright (c) 2006, 2007, 2008 Niall O'Higgins <niallo@p2presearch.com>
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
/* solaris 10 */
#if defined(__SVR4) && defined(__sun)
#include <utility.h>
#endif

#include <netinet/in.h>
#include <arpa/inet.h>

#include <openssl/bn.h>
#include <openssl/dh.h>
#include <openssl/engine.h>

#include <ctype.h>
#include <errno.h>
#include <event.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>
#include <sha1.h>

#include "includes.h"


static void	announce_update(int, short, void *);
static void	handle_announce_response(struct bufferevent *, void *);
static void	handle_announce_error(struct bufferevent *, short, void *);
static void	handle_announce_write(struct bufferevent *, void *);
/*
 * announce()
 *
 * This sends an announce request to a tracker over HTTP.
 */
int
announce(struct session *sc, const char *event)
{
	int i, l;
	size_t n;
	char host[MAXHOSTNAMELEN], port[6], path[MAXPATHLEN], *c;
	char *params, *tparams, *request;
	char tbuf[3*SHA1_DIGEST_LENGTH+1];
	char pbuf[3*PEER_ID_LEN+1];
	struct bufferevent *bufev;

	trace("announce");
	sc->last_announce = time(NULL);
	params = xmalloc(GETSTRINGLEN);
	tparams = xmalloc(GETSTRINGLEN);
	request = xmalloc(GETSTRINGLEN);
	memset(params, '\0', GETSTRINGLEN);
	memset(tparams, '\0', GETSTRINGLEN);
	memset(request, '\0', GETSTRINGLEN);

	/* convert binary info hash to url encoded format */
	for (i = 0; i < SHA1_DIGEST_LENGTH; i++) {
		l = snprintf(&tbuf[3*i], sizeof(tbuf), "%%%02x",
		    sc->tp->info_hash[i]);
		if (l == -1 || l >= (int)sizeof(tbuf))
			goto trunc;
	}
	/* convert peer id to url encoded format */
	for (i = 0; i < PEER_ID_LEN; i++) {
		l = snprintf(&pbuf[3*i], sizeof(pbuf), "%%%02x", sc->peerid[i]);
		if (l == -1 || l >= (int)sizeof(pbuf))
			goto trunc;
	}
	/* XXX: need support for announce-list */
	/* separate out hostname, port and path */
	if ((c = strstr(sc->tp->announce, "http://")) == NULL)
		errx(1, "unsupported announce protocol: %s", sc->tp->announce);
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
	    "&uploaded=%jd"
	    "&downloaded=%jd"
	    "&left=%jd"
	    "&compact=1",
	    tbuf,
	    pbuf,
	    sc->port,
	    (intmax_t)sc->tp->uploaded,
	    (intmax_t)sc->tp->downloaded,
	    (intmax_t)sc->tp->left);
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

	/* While OpenBSD's snprintf doesn't mind snprintf(X, len, "%sblah", X)
	 * others don't like this, so I do the strlcpy and use the temporary
	 * buffer tparams. */
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

	trace("announce() to host: %s on port: %s", host, port);
	trace("announce() request: %s", request);
	/* non blocking connect ? */
	if ((sc->connfd = network_connect_tracker(host, port)) == -1)
		err(1, "tracker announce");

	sc->request = request;
	sc->res = xmalloc(sizeof *sc->res);
	memset(sc->res, 0, sizeof *sc->res);
	sc->res->rxmsg = xmalloc(RESBUFLEN);
	sc->res->rxmsglen = RESBUFLEN;
	sc->announce_underway = 1;
	bufev = bufferevent_new(sc->connfd, handle_announce_response,
	    handle_announce_write, handle_announce_error, sc);
	if (bufev == NULL)
		errx(1, "announce: bufferevent_new failure");
	bufferevent_enable(bufev, EV_READ);
	trace("announce() writing to socket");
	if (bufferevent_write(bufev, request, strlen(request) + 1) != 0)
		errx(1, "announce: bufferevent_write failure");
	xfree(params);
	xfree(request);
	trace("announce() done");
	return (0);

trunc:
	trace("announce: string truncation detected");
	xfree(params);
	xfree(request);
	xfree(tparams);
	return (-1);
}

/*
 * handle_announce_response()
 *
 * When data is ready on the announce socket, this is called to buffer it up.
 */
static void
handle_announce_response(struct bufferevent *bufev, void *arg)
{
	size_t len;
	struct session *sc;

	sc = arg;
	trace("handle_announce_response() reading buffer");
	/* within 256 bytes of filling up our buffer - grow it */
	if (sc->res->rxmsglen <= sc->res->rxread + 256) {
		sc->res->rxmsglen += RESBUFLEN;
		sc->res->rxmsg = xrealloc(sc->res->rxmsg, sc->res->rxmsglen);
	}
	len = bufferevent_read(bufev, sc->res->rxmsg + sc->res->rxread, 256);
	sc->res->rxread += len;
	trace("handle_announce_response() read %u", len);
}

/*
 * handle_announce_error()
 *
 * Called when the announce request socket is closed by the other
 * side - ie when the HTTP request has completed.  Handles all the announce
 * response parsing.
 */
static void
handle_announce_error(struct bufferevent *bufev, short error, void *data)
{
	struct session *sc = data;
	struct benc_node *node, *troot;
	struct torrent *tp;
	struct bufferevent *bev;
	struct timeval tv;
	BUF *buf = NULL;
	u_int32_t l;
	size_t len;
	u_int8_t *c, *dump;

	trace("handle_announce_error() called");
	/* shouldn't have to worry about this case */
	if (sc->res == NULL) {
		sc->announce_underway = 0;
		return;
	}
	/* still could be data left for reading */
	do {
		l = sc->res->rxread;
		handle_announce_response(bufev, sc);
	}
	while (sc->res->rxread - l > 0);

	/* XXX: this shouldn't happen - need to look into why it does */
	if (sc->res->rxread == 0) {
		sc->announce_underway = 0;
		return;
	}

	tp = sc->tp;

	if (error & EVBUFFER_TIMEOUT)
		errx(1, "handle_announce_error() TIMEOUT (unexpected)");

	c = sc->res->rxmsg;
	/* XXX: need HTTP/1.1 support - tricky part is chunked encoding I think */
	if (strncmp(c, HTTP_1_0, strlen(HTTP_1_0)) != 0 && strncmp(c, HTTP_1_1, strlen(HTTP_1_1))) {
		warnx("handle_announce_error: server did not send a valid HTTP/1.0 response");
		goto err;
	}
	c += strlen(HTTP_1_0) + 1;
	if (strncmp(c, HTTP_OK, strlen(HTTP_OK)) != 0) {
		*(c + strlen(HTTP_OK)) = '\0';
		warnx("handle_announce_error: HTTP response indicates error (code: %s)", c);
		goto err;
	}
	c = strstr(c, HTTP_END);
	if (c == NULL) {
		warnx("handle_announce_error: HTTP response had no content");
		goto err;
	}
	c += strlen(HTTP_END);

	if ((buf = buf_alloc(128, BUF_AUTOEXT)) == NULL)
		errx(1,"handle_announce_error: could not allocate buffer");
	len = sc->res->rxread - (c - sc->res->rxmsg);
	buf_set(buf, c, len, 0);
	dump = xmalloc(len + 1);
	memcpy(dump, c, len);
	dump[len] = '\0';
	trace("announce response: %s", dump);
	xfree(dump);

	trace("handle_announce_error() bencode parsing buffer");
	troot = benc_root_create();
	if ((troot = benc_parse_buf(buf, troot)) == NULL)
		errx(1,"handle_announce_error: HTTP response parsing failed (no peers?)");

	/* check for a b-encoded failure response */
	if ((node = benc_node_find(troot, "failure reason")) != NULL) {
		if (!(node->flags & BSTRING))
			trace("unspecified tracker failure");
		trace("tracker failure: %s", node->body.string.value);
		goto err;
	}
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

	if ((node = benc_node_find(troot, "peers")) == NULL) {
		trace("no peers field");
		goto err;
	}
	trace("handle_announce_error() updating peerlist");
	network_peerlist_update(sc, node);
	benc_node_freeall(troot);
	troot = NULL;

	trace("handle_announce_error() setting announce timer");
	timerclear(&tv);
	tv.tv_sec = tp->interval;
	evtimer_del(&sc->announce_event);
	evtimer_set(&sc->announce_event, announce_update, sc);
	evtimer_add(&sc->announce_event, &tv);
	if (sc->servfd == 0) {
		trace("handle_announce_error() setting up server socket");
		/* time to set up the server socket */
		if (sc->port != NULL) {
			sc->servfd = network_listen("0.0.0.0", sc->port);
			bev = bufferevent_new(sc->servfd, NULL,
			    NULL, network_handle_peer_connect, sc);
			if (bufev == NULL)
				errx(1,
				     "handle_announce_error: bufferevent_new failure");
			bufferevent_enable(bev, EV_PERSIST|EV_READ);
		}
		/* now that we've announced, kick off the scheduler */
		trace("handle_announce_error() setting up scheduler");
		timerclear(&tv);
		tv.tv_sec = 1;
		evtimer_set(&sc->scheduler_event, scheduler, sc);
		evtimer_add(&sc->scheduler_event, &tv);
	}
err:
	bufferevent_free(bufev);
	bufev = NULL;
	if (buf != NULL)
		buf_free(buf);
	if (sc->res != NULL) {
		xfree(sc->res->rxmsg);
		xfree(sc->res);
		sc->res = NULL;
	}
	(void) close(sc->connfd);
	trace("handle_announce_error() done");
	sc->announce_underway = 0;
}

/*
 * announce_update()
 *
 * Called at announce interval to send a fresh announce
 * to tracker if necessary.
 */
static void
announce_update(int fd, short type, void *arg)
{
	struct session *sc = arg;
	struct timeval tv;

	trace("announce_update() called");
	if (!sc->announce_underway)
		announce(sc, NULL);
	else
		trace("announce_update() announce already underway");
	timerclear(&tv);
	tv.tv_sec = sc->tp->interval;
	evtimer_set(&sc->announce_event, announce_update, sc);
	evtimer_add(&sc->announce_event, &tv);
}

/*
 * announce_handle_write()
 *
 * Write handler for announce http request socket.
 */
static void
handle_announce_write(struct bufferevent *bufev, void *data)
{
	trace("handle_announce_write() called");
}


