/* $Id: ctl_server.c,v 1.2 2007-12-10 04:06:41 niallo Exp $ */
/*
 * Copyright (c) 2007 Niall O'Higgins <niallo@unworkable.org>
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
#include <sys/queue.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <ctype.h>
#include <errno.h>
#include <event.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "includes.h"

char *gui_port;

static void ctl_server_handle_connect(struct bufferevent *, short, void *);
static void ctl_server_conn_bootstrap(struct ctl_server_conn *);
static struct ctl_server_conn * ctl_server_conn_create(struct ctl_server *);
static void ctl_server_conn_free(struct ctl_server_conn *);
static void ctl_server_handle_conn_message(struct bufferevent *, void *);
static void ctl_server_handle_conn_error(struct bufferevent *, short, void *);
static void ctl_server_broadcast_message(struct ctl_server *, char *);
static void ctl_server_write_message(struct ctl_server_conn *, char *);
static char * ctl_server_pieces(struct session *);
static char * ctl_server_peers(struct session *);

/*
 * ctl_server_start()
 *
 * Start a new control server for the specified session on the specified port.
 */
void
ctl_server_start(struct session *sc, char *port, off_t started)
{
	struct ctl_server *cs;

	cs = xmalloc(sizeof(*cs));
	memset(cs, 0, sizeof(*cs));
	TAILQ_INIT(&cs->conns);

	sc->ctl_server = cs;
	cs->started = started;
	cs->sc = sc;
	cs->fd = network_listen("0.0.0.0", port);
	cs->bev = bufferevent_new(cs->fd, NULL, NULL, ctl_server_handle_connect, cs);
	if (cs->bev == NULL)
		errx(1, "ctl_server_start: bufferevent_new failure");
	bufferevent_enable(cs->bev, EV_PERSIST|EV_READ);
}

/*
 * ctl_server_notify_bytes()
 *
 * Notify control connections of number of bytes received.
 */
void
ctl_server_notify_bytes(struct session *sc, off_t bytes)
{
	char *msg;
	int l;

	if (sc->ctl_server == NULL)
		return;

	msg = xmalloc(CTL_MESSAGE_LEN);
	memset(msg, '\0', CTL_MESSAGE_LEN);

	l = snprintf(msg, CTL_MESSAGE_LEN, "bytes:%ld\r\n", bytes);
	if (l == -1 || l >= (int)CTL_MESSAGE_LEN)
		errx(1, "ctl_server_notify_bytes() string truncation");
	ctl_server_broadcast_message(sc->ctl_server, msg);
	xfree(msg);
}

/*
 * ctl_server_notify_pieces()
 *
 * Notify control connections of pieces received.
 */
void
ctl_server_notify_pieces(struct session *sc)
{
	char *msg;

	if (sc->ctl_server == NULL)
		return;
	msg = ctl_server_pieces(sc);
	ctl_server_broadcast_message(sc->ctl_server, msg);
	xfree(msg);
}

/*
 * ctl_server_notify_peers()
 *
 * Notify control connections of connected peers.
 */
void
ctl_server_notify_peers(struct session *sc)
{
	char *msg;

	if (sc->ctl_server == NULL)
		return;
	msg = ctl_server_peers(sc);
	ctl_server_broadcast_message(sc->ctl_server, msg);
	xfree(msg);
}

/*
 * ctl_server_handle_connect()
 *
 * Handle incoming connections to the control server.
 */
static void
ctl_server_handle_connect(struct bufferevent *bufev, short error, void *data)
{
	struct ctl_server *cs;
	struct ctl_server_conn *csc;
	socklen_t addrlen;

	trace("ctl_server_handle_connect() called");
	if (error & EVBUFFER_TIMEOUT)
		errx(1, "timeout");
	if (error & EVBUFFER_EOF)
		errx(1, "eof");
	cs = data;
	csc = ctl_server_conn_create(cs);
	addrlen = sizeof(csc->sa);

	trace("ctl_server_handle_connect() accepting connection");
	if ((csc->fd = accept(cs->fd, (struct sockaddr *) &csc->sa, &addrlen)) == -1) {
		trace("ctl_server_handle_connect() accept error");
		ctl_server_conn_free(csc);
		return;
	}
	trace("ctl_server_handle_connectt() accepted connection: %s:%d",
	    inet_ntoa(csc->sa.sin_addr), ntohs(csc->sa.sin_port));

	csc->bev = bufferevent_new(csc->fd, ctl_server_handle_conn_message,
	    NULL, ctl_server_handle_conn_error, csc);
	if (csc->bev == NULL)
		errx(1, "ctl_server_handle_connect(): bufferevent_new failure");
	bufferevent_enable(csc->bev, EV_READ|EV_WRITE);
	cs->bev = bufferevent_new(cs->fd, NULL, NULL, ctl_server_handle_connect, cs);
	if (cs->bev == NULL)
		errx(1, "ctl_server_start: bufferevent_new failure");
	bufferevent_enable(cs->bev, EV_PERSIST|EV_READ);
	TAILQ_INSERT_TAIL(&cs->conns, csc, conn_list);
	ctl_server_conn_bootstrap(csc);
}

/*
 * ctl_server_conn_create()
 *
 * Create a connection to the control server.
 */
static struct ctl_server_conn *
ctl_server_conn_create(struct ctl_server *cs)
{
	struct ctl_server_conn *csc;

	csc = xmalloc(sizeof(*csc));
	memset(csc, 0, sizeof(*csc));
	csc->cs = cs;

	return (csc);
}

/*
 * ctl_server_conn_free()
 *
 * Free a connection to the control server.
 */
static void
ctl_server_conn_free(struct ctl_server_conn *csc)
{
	(void)  close(csc->fd);
	xfree(csc);
}

/*
 * ctl_server_conn_bootstrap()
 *
 * Send initial state data to this new connection.
 */
static void
ctl_server_conn_bootstrap(struct ctl_server_conn *csc)
{
	off_t len;
	char *msg;
	int l;

	trace("bootstrapping");
#define BOOTSTRAP_LEN 1024
	if (csc->cs->sc->tp->type == SINGLEFILE) {
		len = csc->cs->sc->tp->body.singlefile.tfp.file_length;
	} else {
		len = csc->cs->sc->tp->body.multifile.total_length;
	}
	msg = xmalloc(BOOTSTRAP_LEN);
	memset(msg, '\0', BOOTSTRAP_LEN);
	l = snprintf(msg, BOOTSTRAP_LEN, "num_peers:%u\r\nnum_pieces:%u\r\ntorrent_size:%ld\r\ntorrent_bytes:%ld\r\n",
	     csc->cs->sc->num_peers, csc->cs->sc->tp->num_pieces, len, csc->cs->started);
	if (l == -1 || l >= (int)BOOTSTRAP_LEN)
		errx(1, "ctl_server_conn_bootstrap() string truncation");
	ctl_server_write_message(csc, msg);
	xfree(msg);
	msg = ctl_server_pieces(csc->cs->sc);
	ctl_server_write_message(csc, msg);
	xfree(msg);
	msg = ctl_server_peers(csc->cs->sc);
	ctl_server_write_message(csc, msg);
	xfree(msg);
	trace("bootstrapped");
}

/*
 * ctl_server_handle_conn_message()
 *
 * Handle a message from a connection to the control server.
 */
static void
ctl_server_handle_conn_message(struct bufferevent *bufev, void *data)
{
	/* TODO */
}

/*
 * ctl_server_handle_conn_error()
 *
 * Handle a message from a connection to the control server.
 */
static void
ctl_server_handle_conn_error(struct bufferevent *bufev, short error, void *data)
{
	struct ctl_server_conn *csc;

	csc = data;

	trace("ctl_server_handle_conn_error() freeing connection");
	TAILQ_REMOVE(&csc->cs->conns, csc, conn_list);
	ctl_server_conn_free(csc);
}

/*
 * ctl_server_write_message()
 *
 * Write a message to a connection.
 */
static void
ctl_server_write_message(struct ctl_server_conn *csc, char *msg)
{
	if (bufferevent_write(csc->bev, msg, strlen(msg)) != 0)
		errx(1, "ctl_server_write_message() failure");
}

/*
 * ctl_server_broadcast_message()
 *
 * Broadcast a message to all connections.
 */
static void
ctl_server_broadcast_message(struct ctl_server *cs, char *msg)
{
	struct ctl_server_conn *csc;

	TAILQ_FOREACH(csc, &cs->conns, conn_list)
		ctl_server_write_message(csc, msg);
}

/*
 * ctl_server_pieces()
 *
 * Allocate and return string containing pieces message.
 */
static char *
ctl_server_pieces(struct session *sc)
{
	struct torrent_piece *tpp;
	u_int32_t count, i, msglen;
	char *msg, piece[8];

	/* almost certainly too much space, but who cares */
	msglen = CTL_MESSAGE_LEN + (5 * sc->tp->good_pieces);
	msg = xmalloc(msglen);
	memset(msg, '\0', msglen);
	snprintf(msg, msglen, "pieces:");

	count = 0;
	for (i = 0; i < sc->tp->num_pieces; i++) {
		tpp = torrent_piece_find(sc->tp, i);
		if (tpp->flags & TORRENT_PIECE_CKSUMOK) {
			count++;
			if (count == sc->tp->good_pieces) {
				snprintf(piece, sizeof(piece), "%u\r\n", i);
			} else {
				snprintf(piece, sizeof(piece), "%u,", i);
			}
			if (strlcat(msg, piece, msglen) >= msglen)
				errx(1, "ctl_server_pieces() string truncation");
		}
	}

	return (msg);
}

/*
 * ctl_server_peers()
 *
 * Allocate and return string containing peers message.
 */
static char *
ctl_server_peers(struct session *sc)
{
	struct peer *p;
	u_int32_t count, msglen;
	char *msg, peer[32];

	/* almost certainly too much space, but who cares */
	msglen = CTL_MESSAGE_LEN + (32 * sc->num_peers);
	msg = xmalloc(msglen);
	memset(msg, '\0', msglen);
	snprintf(msg, msglen, "peers:");

	count = 0;
	TAILQ_FOREACH(p, &sc->peers, peer_list) {
			count++;
			if (count == sc->num_peers) {
				snprintf(peer, sizeof(peer), "%s:%d\r\n",
				    inet_ntoa(p->sa.sin_addr), ntohs(p->sa.sin_port));
			} else {
				snprintf(peer, sizeof(peer), "%s:%d,",
				    inet_ntoa(p->sa.sin_addr), ntohs(p->sa.sin_port));
			}
			if (strlcat(msg, peer, msglen) >= msglen)
				errx(1, "ctl_server_peers() string truncation");
	}

	return (msg);
}
