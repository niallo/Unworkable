/* $Id: network.c,v 1.225 2008-10-06 17:04:18 niallo Exp $ */
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
#include <sys/queue.h>
#include <sys/param.h>
#include <sys/socket.h>
/* cygwin */
#if defined(NO_GETADDRINFO)
#include "openbsd-compat/getaddrinfo.h"
#endif

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
#include <sha1.h>

#include "includes.h"


char *user_port = NULL;
int   seed = 0;

static void network_peer_write(struct peer *, u_int8_t *, u_int32_t);
static void network_peerlist_update_dict(struct session *, struct benc_node *);
static void network_peerlist_update_string(struct session *, struct benc_node *);
static char *network_peer_id_create(void);
static int network_connect(int, int, int, const struct sockaddr *, socklen_t);
static int network_connect_peer(struct peer *);
static void network_handle_peer_response(struct bufferevent *, void *);
static void network_peer_process_message(u_int8_t, struct peer *);
static void network_peer_handshake(struct session *, struct peer *);
static void network_peer_keepalive(int, short, void *);

/* index of piece dls by block index and offset */
RB_PROTOTYPE(piece_dl_by_idxoff, piece_dl_idxnode, entry, piece_dl_idxnode_cmp)
RB_GENERATE(piece_dl_by_idxoff, piece_dl_idxnode, entry, piece_dl_idxnode_cmp)

int
piece_dl_idxnode_cmp(struct piece_dl_idxnode *p1, struct piece_dl_idxnode *p2)
{
	int64_t idxdiff;

	idxdiff = p1->idx - p2->idx;

	if (idxdiff == 0) {
		return (p1->off - p2->off);
	} else {
		return (idxdiff);
	}
}

/*
 * network_peer_id_create()
 *
 * Generate a random peer id string for us to use
 */
static char *
network_peer_id_create()
{
	long r;
	char *id;

	r = random();
	id = xmalloc(PEER_ID_LEN+1);
	memset(id, 1, PEER_ID_LEN+1);
	/* we don't care about truncation  here */
	(void) snprintf(id, PEER_ID_LEN+1, "-UL-0001-0%010ld", r);

	return (id);
}

/*
 * network_peer_write()
 *
 * Write data to a peer.
 */
static void
network_peer_write(struct peer *p, u_int8_t *msg, u_int32_t len)
{
	if (bufferevent_write(p->bufev, msg, len) != 0)
		errx(1, "network_peer_write() failure");
	xfree(msg);
	p->lastsend = time(NULL);
}

/*
 * network_connect()
 *
 * Generic TCP/IP socket connection routine, used by other functions.
 */
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

/*
 * network_connect_peer()
 *
 * Connects socket to a peer.
 */
static int
network_connect_peer(struct peer *p)
{
	p->state |= PEER_STATE_HANDSHAKE1;
	return (network_connect(PF_INET, SOCK_STREAM, 0,
	    (const struct sockaddr *) &p->sa, sizeof(p->sa)));
}

/*
 * network_peerlist_connect()
 *
 * Connect any new peers in our peer list.
 */
void
network_peerlist_connect(struct session *sc)
{
	struct peer *ep, *nxt;
	struct timeval tv;

	for (ep = TAILQ_FIRST(&sc->peers); ep != TAILQ_END(&sc->peers) ; ep = nxt) {
		nxt = TAILQ_NEXT(ep, peer_list);
		/* stay within our limits */
		if (sc->num_peers >= sc->maxfds - 5) {
				network_peer_free(ep);
				sc->num_peers--;
				TAILQ_REMOVE(&sc->peers, ep, peer_list);
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
			/* set up keep-alive timer */
			timerclear(&tv);
			tv.tv_sec = 1;
			evtimer_set(&ep->keepalive_event, network_peer_keepalive, ep);
			evtimer_add(&ep->keepalive_event, &tv);
			trace("network_peerlist_update() initiating handshake");
			network_peer_handshake(sc, ep);
		}
	}
}

/*
 * Adds a prepared struct peer to the peer list if it isn't already there
 *
 */
void
network_peerlist_add_peer(struct session *sc, struct peer *p)
{
	struct peer *ep;

	/* Is this peer already in the list? */
	int found = 0;
	TAILQ_FOREACH(ep, &sc->peers, peer_list) {
		if (memcmp(&ep->sa.sin_addr, &p->sa.sin_addr, sizeof(ep->sa.sin_addr)) == 0
		    && memcmp(&ep->sa.sin_port, &p->sa.sin_port, sizeof(ep->sa.sin_port)) == 0) {
			found = 1;
			break;
		}
	}
	if (found == 0) {
		trace("network_peerlist_add_peer() adding peer to list: %s:%d",
		    inet_ntoa(p->sa.sin_addr), ntohs(p->sa.sin_port));
		TAILQ_INSERT_TAIL(&sc->peers, p, peer_list);
		sc->num_peers++;
	} else {
		network_peer_free(p);
	}
}

/*
 * network_peerlist_update_string()
 *
 * Handle string format peerlist parsing.
 */

static void
network_peerlist_update_string(struct session *sc, struct benc_node *peers)
{
	char *peerlist;
	size_t len, i;
	struct peer *p;

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
			network_peerlist_add_peer(sc, p);
			continue;
		}
	}

	network_peerlist_connect(sc);
}

/*
 * network_peerlist_update_dict()
 *
 * Handle dictionary format peerlist parsing.
 */
static void
network_peerlist_update_dict(struct session *sc, struct benc_node *peers)
{

	struct benc_node *dict, *n;
	struct peer *p = NULL;
	struct addrinfo hints, *res;
	struct sockaddr_in sa;
	int port, error, l;
	char *ip, portstr[6];

	if (!(peers->flags & BLIST))
		errx(1, "peers object is not a list");
	/* iterate over a blist of bdicts each with three keys */
	TAILQ_FOREACH(dict, &peers->children, benc_nodes) {
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

		network_peerlist_add_peer(sc, p);
	}

	network_peerlist_connect(sc);
}



/*
 * network_peer_handshake()
 *
 * Build and write a handshake message to remote peer.
 */
static void
network_peer_handshake(struct session *sc, struct peer *p)
{
	u_int8_t *msg;
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
	p->connected = time(NULL);
	#define HANDSHAKELEN (1 + 19 + 8 + 20 + 20)
	msg = xmalloc(HANDSHAKELEN);
	memset(msg, 0, HANDSHAKELEN);
	msg[0] = 19;
	memcpy(msg + 1, "BitTorrent protocol", 19);
	/* set reserved bit to indicate we support the fast extension */
	msg[27] |= 0x04;
	memcpy(msg + 28, sc->tp->info_hash, 20);
	memcpy(msg + 48, sc->peerid, 20);

	network_peer_write(p, msg, HANDSHAKELEN);
}

/*
 * network_handle_peer_response()
 *
 * Handle any input from peer, managing handshakes,
 * encryption requests and so on.  Also handle ensuring the message is
 * complete before passing it to the message processor.
 */
static void
network_handle_peer_response(struct bufferevent *bufev, void *data)
{
	struct peer *p = data;
	size_t len;
	u_int32_t msglen;
	u_int8_t *base, id = 0;

	/* the complicated thing here is the non-blocking IO, which
	 * means we have to be prepared to come back later and add more
	 * data */

	if (p->state & PEER_STATE_HANDSHAKE1 && p->rxpending == 0) {
		p->lastrecv = time(NULL);
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
				/* does this peer support fast extension? */
				if (p->rxmsg[27] & 0x04) {
					p->state |= PEER_STATE_FAST;
					trace("network_handle_peer_response() fast peer %s:%d", inet_ntoa(p->sa.sin_addr), ntohs(p->sa.sin_port));
				} else {
					trace("network_handle_peer_response() slow peer %s:%d", inet_ntoa(p->sa.sin_addr), ntohs(p->sa.sin_port));
				}

				if (memcmp(p->info_hash, p->sc->tp->info_hash, 20) != 0) {
					trace("network_handle_peer_response() info hash mismatch for peer %s:%d", inet_ntoa(p->sa.sin_addr), ntohs(p->sa.sin_port));
					p->state = 0;
					p->state |= PEER_STATE_DEAD;
					goto out;
				}

				xfree(p->rxmsg);
				p->rxmsg = NULL;
				p->state |= PEER_STATE_BITFIELD;
				p->state |= PEER_STATE_SENDBITFIELD;
				p->state &= ~PEER_STATE_HANDSHAKE2;
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
	/*
	 * if its time to send the bitfield, and we actually have some pieces,
	 * send the bitfield.
	 */
	if (p->state & PEER_STATE_SENDBITFIELD) {
		/* fast extension gives us a couple more options */
		if (p->state & PEER_STATE_FAST) {
			if (torrent_empty(p->sc->tp)) {
				network_peer_write_havenone(p);
			} else if (p->sc->tp->good_pieces == p->sc->tp->num_pieces) {
				network_peer_write_haveall(p);
			} else {
				network_peer_write_bitfield(p);
			}
		} else if (!torrent_empty(p->sc->tp)) {
			network_peer_write_bitfield(p);
		}
		p->state &= ~PEER_STATE_SENDBITFIELD;
	}
	if (EVBUFFER_LENGTH(EVBUFFER_INPUT(bufev)))
		bufev->readcb(bufev, data);
}

/*
 * network_peer_process_message()
 *
 * Now that we actually have the full message in our
 * buffers, process it.
 */
static void
network_peer_process_message(u_int8_t id, struct peer *p)
{
	struct torrent_piece *tpp;
	struct peer *tp;
	struct piece_dl *pd, *nxtpd;
	struct piece_ul *pu, *nxtpu;
	int res = 0;
	int found = 0;
	u_int32_t bitfieldlen, idx, blocklen, off;

	/* XXX: safety-check for correct message lengths */
	switch (id) {
		case PEER_MSG_ID_CHOKE:
			trace("CHOKE message from peer %s:%d",
			    inet_ntoa(p->sa.sin_addr), ntohs(p->sa.sin_port));
			p->state |= PEER_STATE_CHOKED;
			if (!(p->state & PEER_STATE_FAST)) {
				for (pd = TAILQ_FIRST(&p->peer_piece_dls); pd; pd = nxtpd) {
					nxtpd = TAILQ_NEXT(pd, peer_piece_dl_list);
					pd->pc = NULL;
					TAILQ_REMOVE(&p->peer_piece_dls, pd, peer_piece_dl_list);
					p->dl_queue_len--;
				}
			}
			break;
		case PEER_MSG_ID_UNCHOKE:
			trace("UNCHOKE message from peer %s:%d",
			    inet_ntoa(p->sa.sin_addr), ntohs(p->sa.sin_port));
			p->state &= ~PEER_STATE_CHOKED;
			break;
		case PEER_MSG_ID_INTERESTED:
			trace("INTERESTED message from peer %s:%d",
			    inet_ntoa(p->sa.sin_addr), ntohs(p->sa.sin_port));
			p->state |= PEER_STATE_INTERESTED;
			break;
		case PEER_MSG_ID_NOTINTERESTED:
			trace("NOTINTERESTED message from peer %s:%d",
			    inet_ntoa(p->sa.sin_addr), ntohs(p->sa.sin_port));
			p->state &= ~PEER_STATE_INTERESTED;
			break;
		case PEER_MSG_ID_HAVE:
			memcpy(&idx, p->rxmsg+sizeof(id), sizeof(idx));
			idx = ntohl(idx);
			trace("HAVE message from peer %s:%d (idx=%u)",
			    inet_ntoa(p->sa.sin_addr), ntohs(p->sa.sin_port), idx);
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
			util_setbit(p->bitfield, idx);
			/* does this peer have anything we want? */
			scheduler_piece_gimme(p, PIECE_GIMME_NOCREATE, &res);
			if (res && !(p->state & PEER_STATE_AMINTERESTED))
				network_peer_write_interested(p);
			break;
		case PEER_MSG_ID_BITFIELD:
			trace("BITFIELD message from peer %s:%d",
			    inet_ntoa(p->sa.sin_addr), ntohs(p->sa.sin_port));
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
			/* does this peer have anything we want? */
			scheduler_piece_gimme(p, PIECE_GIMME_NOCREATE, &res);
			if (res && !(p->state & PEER_STATE_AMINTERESTED))
				network_peer_write_interested(p);
			break;
		case PEER_MSG_ID_REQUEST:
			memcpy(&idx, p->rxmsg+sizeof(id), sizeof(idx));
			idx = ntohl(idx);
			if (idx > p->sc->tp->num_pieces - 1) {
				trace("REQUEST index out of bounds (%u)", idx);
				break;
			}
			memcpy(&off, p->rxmsg+sizeof(id)+sizeof(idx), sizeof(off));
			off = ntohl(off);
			tpp = torrent_piece_find(p->sc->tp, idx);
			if (off > tpp->len) {
				trace("REQUEST offset out of bounds (%u)"), off;
				break;
			}
			memcpy(&blocklen, p->rxmsg+sizeof(id)+sizeof(idx)+sizeof(off), sizeof(blocklen));
			blocklen = ntohl(blocklen);
			if (!(tpp->flags & TORRENT_PIECE_CKSUMOK)) {
				trace("REQUEST for data we don't have from peer %s:%d idx=%u off=%u len=%u", inet_ntoa(p->sa.sin_addr), ntohs(p->sa.sin_port), idx, off, blocklen);
				if (p->state & PEER_STATE_FAST)
					network_peer_reject_block(p, idx, off, blocklen);
				break;
			}
			trace("REQUEST message from peer %s:%d idx=%u off=%u len=%u", inet_ntoa(p->sa.sin_addr), ntohs(p->sa.sin_port), idx, off, blocklen);
			/* network_peer_write_piece(p, idx, off, blocklen); */
			network_piece_ul_enqueue(p, idx, off, blocklen);
			break;
		case PEER_MSG_ID_PIECE:
			memcpy(&idx, p->rxmsg+sizeof(id), sizeof(idx));
			idx = ntohl(idx);
			memcpy(&off, p->rxmsg+sizeof(id)+sizeof(idx), sizeof(off));
			off = ntohl(off);
			trace("PIECE message (idx=%u off=%u len=%u) from peer %s:%d", idx,
			    off, p->rxmsglen - (sizeof(id)+sizeof(off)+sizeof(idx)), inet_ntoa(p->sa.sin_addr), ntohs(p->sa.sin_port));
			if (idx > p->sc->tp->num_pieces - 1) {
				trace("PIECE index out of bounds");
				break;
			}
			tpp = torrent_piece_find(p->sc->tp, idx);
			if (off > tpp->len) {
				trace("PIECE offset out of bounds");
				break;
			}
			pd = network_piece_dl_find(p->sc, p, idx, off);
			if (pd != NULL
			    && p->rxmsglen-(sizeof(id)+sizeof(off)+sizeof(idx)) != pd->len) {
				trace("PIECE len incorrect, should be %u", pd->len);
				break;
			}
			if (pd == NULL) {
				trace("PIECE message for data we didn't request - killing peer");
				p->state = 0;
				p->state |= PEER_STATE_DEAD;
				break;
			}
			/* Only read if we don't already have it */
			if (!(tpp->flags & TORRENT_PIECE_CKSUMOK)) {
				p->dl_queue_len--;
				if (!(tpp->flags & TORRENT_PIECE_MAPPED))
					torrent_piece_map(tpp);
				network_peer_read_piece(p, idx, off,
				    p->rxmsglen-(sizeof(id)+sizeof(off)+sizeof(idx)),
				    p->rxmsg+sizeof(id)+sizeof(off)+sizeof(idx));
				/* only checksum if we think we have every block of this piece */
				found = 1;
				for (off = 0; off < tpp->len; off += BLOCK_SIZE) {
					if ((pd = network_piece_dl_find(p->sc, p, idx, off)) == NULL) {
						found = 0;
						break;
					}
					if (pd->len != pd->bytes) {
						found = 0;
						break;
					}
				}
				if (found) {
					res = torrent_piece_checkhash(p->sc->tp, tpp);
					torrent_piece_unmap(tpp);
					if (res == 0) {
						trace("hash check success for piece %d", idx);
						/* dump fastresume data  */
						torrent_fastresume_dump(p->sc->tp);
						p->sc->tp->good_pieces++;
						p->sc->tp->left -= tpp->len;
						if (p->sc->tp->good_pieces == p->sc->tp->num_pieces) {
							if (!seed) {
								refresh_progress_meter();
								exit(0);
							} else if (!p->sc->announce_underway) {
								/* tell tracker we're done */
								announce(p->sc, "completed");
							}
						}
						/* send HAVE messages to all peers */
						TAILQ_FOREACH(tp, &p->sc->peers, peer_list)
							network_peer_write_have(tp, idx);
						/* notify control server */
						ctl_server_notify_pieces(p->sc);
						/* clean up all the piece dls for this now that its done */
						for (off = 0; off < tpp->len; off += BLOCK_SIZE) {
							if ((pd = network_piece_dl_find(p->sc, NULL, idx, off)) != NULL) {
								network_piece_dl_free(p->sc, pd);
							}
						}
					} else {
						trace("hash check failure for piece %d", idx);
						for (off = 0; off < tpp->len; off += BLOCK_SIZE) {
							if ((pd = network_piece_dl_find(p->sc, NULL, idx, off)) != NULL) {
								network_piece_dl_free(p->sc, pd);
							}
						}
					}
				}
			} else {
				/* this code is wrong */
				#if 0
				/* XXX hash check failed, try re-downloading this piece? */
				/* clean up this piece dl, although its not fully the correct thing to do */
				if ((pd = network_piece_dl_find(p->sc, idx, off)) != NULL) {
					pd->pc = NULL;
					p->dl_queue_len--;
				}
				#endif
			}
			p->lastrecv = time(NULL);
			break;
		case PEER_MSG_ID_CANCEL:
			memcpy(&idx, p->rxmsg+sizeof(id), sizeof(idx));
			idx = ntohl(idx);
			if (idx > p->sc->tp->num_pieces - 1) {
				trace("CANCEL index out of bounds (%u)", idx);
				break;
			}
			memcpy(&off, p->rxmsg+sizeof(id)+sizeof(idx), sizeof(off));
			off = ntohl(off);
			memcpy(&blocklen, p->rxmsg+sizeof(id)+sizeof(idx)+sizeof(off), sizeof(blocklen));
			blocklen = ntohl(blocklen);
			trace("CANCEL message idx=%u off=%u len=%u from peer %s:%d", idx, off, blocklen, 
			    inet_ntoa(p->sa.sin_addr), ntohs(p->sa.sin_port));
			for (pu = TAILQ_FIRST(&p->peer_piece_uls); pu; pu = nxtpu) {
				nxtpu = TAILQ_NEXT(pu, peer_piece_ul_list);
				if (pu->idx == idx
				    && pu->off == off
				    && pu->len == blocklen) {
					TAILQ_REMOVE(&p->peer_piece_uls, pu, peer_piece_ul_list);
					xfree(pu);
				}
			}
			break;
		case PEER_MSG_ID_REJECT:
			trace("REJECT message from peer %s:%d",
			    inet_ntoa(p->sa.sin_addr), ntohs(p->sa.sin_port));
			if (!(p->state & PEER_STATE_FAST)) {
				trace("peer %s:%d does not support fast extension, closing",
				    inet_ntoa(p->sa.sin_addr), ntohs(p->sa.sin_port));
				p->state = 0;
				p->state |= PEER_STATE_DEAD;
				break;
			}
			memcpy(&idx, p->rxmsg+sizeof(id), sizeof(idx));
			idx = ntohl(idx);
			if (idx > p->sc->tp->num_pieces - 1) {
				trace("REJECT index out of bounds (%u)", idx);
				break;
			}
			memcpy(&off, p->rxmsg+sizeof(id)+sizeof(idx), sizeof(off));
			off = ntohl(off);
			memcpy(&blocklen, p->rxmsg+sizeof(id)+sizeof(idx)+sizeof(off), sizeof(blocklen));
			blocklen = ntohl(blocklen);
			trace("REJECT message from peer %s:%d idx=%u off=%u len=%u", inet_ntoa(p->sa.sin_addr), ntohs(p->sa.sin_port), idx, off, blocklen);
			if ((pd = network_piece_dl_find(p->sc, p, idx, off)) == NULL) {
				trace("could not find piece dl for reject from peer %s:%d idx=%u off=%u len=%u", inet_ntoa(p->sa.sin_addr), ntohs(p->sa.sin_port), idx, off, blocklen);
				break;
			}
			network_piece_dl_free(p->sc, pd);
			p->dl_queue_len--;
			break;
		case PEER_MSG_ID_HAVENONE:
			trace("HAVENONE message from peer %s:%d",
			    inet_ntoa(p->sa.sin_addr), ntohs(p->sa.sin_port));
			if (!(p->state & PEER_STATE_BITFIELD)) {
				trace("not expecting HAVENONE!");
				break;
			}
			bitfieldlen = (p->sc->tp->num_pieces + 7) / 8;
			p->bitfield = xmalloc(bitfieldlen);
			memset(p->bitfield, 0, bitfieldlen);
			p->state &= ~PEER_STATE_BITFIELD;
			p->state |= PEER_STATE_ESTABLISHED;
			/* does this peer have anything we want? */
			scheduler_piece_gimme(p, PIECE_GIMME_NOCREATE, &res);
			if (res && !(p->state & PEER_STATE_AMINTERESTED))
				network_peer_write_interested(p);
			break;
		case PEER_MSG_ID_HAVEALL:
			trace("HAVEALL message from peer %s:%d",
			    inet_ntoa(p->sa.sin_addr), ntohs(p->sa.sin_port));
			if (!(p->state & PEER_STATE_BITFIELD)) {
				trace("not expecting HAVEALL");
				break;
			}
			bitfieldlen = (p->sc->tp->num_pieces + 7) / 8;
			p->bitfield = xmalloc(bitfieldlen);
			memset(p->bitfield, 0xFF, bitfieldlen);
			p->state &= ~PEER_STATE_BITFIELD;
			p->state |= PEER_STATE_ESTABLISHED;
			/* does this peer have anything we want? */
			scheduler_piece_gimme(p, PIECE_GIMME_NOCREATE, &res);
			if (res && !(p->state & PEER_STATE_AMINTERESTED))
				network_peer_write_interested(p);
			break;
		case PEER_MSG_ID_ALLOWEDFAST:
			memcpy(&idx, p->rxmsg+sizeof(id), sizeof(idx));
			idx = ntohl(idx);
			trace("ALLOWEDFAST message (idx=%u) from peer %s:%d", idx,
			    inet_ntoa(p->sa.sin_addr), ntohs(p->sa.sin_port));
			if (idx > p->sc->tp->num_pieces - 1) {
				trace("ALLOWEDFAST index out of bounds");
				break;
			}
			/* ignore these for now */

		case PEER_MSG_ID_SUGGEST:
			memcpy(&idx, p->rxmsg+sizeof(id), sizeof(idx));
			idx = ntohl(idx);
			trace("SUGGEST message (idx=%u) from peer %s:%d", idx,
			    inet_ntoa(p->sa.sin_addr), ntohs(p->sa.sin_port));
			if (idx > p->sc->tp->num_pieces - 1) {
				trace("SUGGEST index out of bounds");
				break;
			}
			/* ignore these for now */

		default:
			trace("Unknown message from peer %s:%d",
			    inet_ntoa(p->sa.sin_addr), ntohs(p->sa.sin_port));
			break;
	}
}

/*
 * network_handle_peer_error()
 *
 * Handle errors on peer sockets.  Typically we mark things as dead
 * and let the scheduler handle cleanup.
 */
void
network_handle_peer_error(struct bufferevent *bufev, short error, void *data)
{
	struct peer *p;

	p = data;
	if (error & EVBUFFER_TIMEOUT) {
		trace("network_handle_peer_error() TIMEOUT for peer %s:%d",
		    inet_ntoa(p->sa.sin_addr), ntohs(p->sa.sin_port));
	}
	if (error & EVBUFFER_EOF) {
		p->state = 0;
		p->state |= PEER_STATE_DEAD;
		trace("network_handle_peer_error() EOF for peer %s:%d",
		    inet_ntoa(p->sa.sin_addr), ntohs(p->sa.sin_port));
	} else {
		trace("network_handle_peer_error() error for peer %s:%d",
		    inet_ntoa(p->sa.sin_addr), ntohs(p->sa.sin_port));
		p->state = 0;
		p->state |= PEER_STATE_DEAD;
	}
}

/*
 * network_peer_keepalive()
 *
 * Periodically send keep-alive messages to peers if necessary.
 */
static void
network_peer_keepalive(int fd, short type, void *arg)
{
	struct peer *p;
	struct timeval tv;

	p = arg;

	if (time(NULL) - p->lastsend >= PEER_KEEPALIVE_SECONDS)
		network_peer_write_keepalive(p);
	timerclear(&tv);
	tv.tv_sec = 1;
	evtimer_set(&p->keepalive_event, network_peer_keepalive, p);
	evtimer_add(&p->keepalive_event, &tv);
}

/*
 * network_handle_peer_write()
 *
 * Handle write events.  Mostly involves cleanup.
 */
void
network_handle_peer_write(struct bufferevent *bufev, void *data)
{
	/* do nothing */
}

/*
 * network_peer_write_have()
 *
 * Send HAVE message to peer.
 */
void
network_peer_write_have(struct peer *p, u_int32_t idx)
{
	u_int32_t msglen, msglen2;
	u_int8_t *msg, id;

	msglen = sizeof(msglen) + sizeof(id) + sizeof(idx);
	msg = xmalloc(msglen);

	msglen2 = htonl(msglen - sizeof(msglen));
	id = PEER_MSG_ID_HAVE;
	idx = htonl(idx);

	memcpy(msg, &msglen2, sizeof(msglen2));
	memcpy(msg+sizeof(msglen2), &id, sizeof(id));
	memcpy(msg+sizeof(msglen2)+sizeof(id), &idx, sizeof(idx));

	network_peer_write(p, msg, msglen);
}

/*
 * network_peer_write_piece()
 *
 * Write a PIECE message to a remote peer,
 * filling the buffer from our local torrent data store.
 */
void
network_peer_write_piece(struct peer *p, u_int32_t idx, u_int32_t offset, u_int32_t len)
{
	struct torrent_piece *tpp;
	u_int32_t msglen, msglen2;
	u_int8_t *data, *msg, id;
	int hint = 0;

	trace("network_peer_write_piece() idx=%u off=%u len=%u for peer %s:%d",
	    idx, offset, len, inet_ntoa(p->sa.sin_addr),
	    ntohs(p->sa.sin_port));

	if ((tpp = torrent_piece_find(p->sc->tp, idx)) == NULL) {
		trace("network_peer_write_piece() piece %u - failed at torrent_piece_find(), returning",
		    idx);
		return;
	}
	if (!(tpp->flags & TORRENT_PIECE_MAPPED))
		torrent_piece_map(tpp);
	if ((data = torrent_block_read(tpp, offset, len, &hint)) == NULL) {
		trace("network_peer_write_piece() piece %u - failed at torrent_block_read(), returning",
		    idx);
		return;
	}
	/* construct PIECE message response */
	msglen = sizeof(msglen) + sizeof(id) + sizeof(idx) + sizeof(offset) + len;
	msglen2 = htonl((msglen - sizeof(msglen)));
	msg = xmalloc(msglen);
	memset(msg, 0, msglen);
	id = PEER_MSG_ID_PIECE;
	idx = htonl(idx);
	offset = htonl(offset);
	memcpy(msg, &msglen2, sizeof(msglen2));
	memcpy(msg+sizeof(msglen2), &id, sizeof(id));
	memcpy(msg+sizeof(msglen2)+sizeof(id), &idx, sizeof(idx));
	memcpy(msg+sizeof(msglen2)+sizeof(id)+sizeof(idx), &offset, sizeof(offset));
	memcpy(msg+sizeof(msglen2)+sizeof(id)+sizeof(idx)+sizeof(offset), data, len);

	network_peer_write(p, msg, msglen);
	if (hint == 1)
		xfree(data);
	p->totaltx += msglen;
}

/*
 * network_peer_read_piece()
 *
 * Taking a buffer and the pre-parsed parameters, read a PIECE request
 * into our torrent data store.
 */
void
network_peer_read_piece(struct peer *p, u_int32_t idx, off_t offset, u_int32_t len, void *data)
{
	struct torrent_piece *tpp;
	struct piece_dl *pd;

	if ((tpp = torrent_piece_find(p->sc->tp, idx)) == NULL) {
		trace("network_peer_read_piece: piece %u - failed at torrent_piece_find(), returning",
		    idx);
		return;
	}
	trace("network_peer_read_piece() at index %u offset %u length %u", idx, offset, len);
	if ((pd = network_piece_dl_find(p->sc, p, idx, offset)) == NULL)
		return;
	torrent_block_write(tpp, offset, len, data);
	pd->bytes += len;
	/* XXX not really accurate measure of progress since the data could be bad */
	p->sc->tp->downloaded += len;
	p->totalrx += len;
	ctl_server_notify_bytes(p->sc, p->sc->tp->downloaded);
}

/* network_peer_request_block()
 *
 * Send a REQUEST message to remote peer.
 */
void
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

	network_peer_write(p, msg, msglen);
}

/*
 * network_peer_cancel_piece()
 *
 * Send a CANCEL message to remote peer.
 */
void
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

	network_peer_write(pd->pc, msg, msglen);
}

/*
 * network_peer_write_interested()
 *
 * Send an INTERESTED message to remote peer.
 */
void
network_peer_write_interested(struct peer *p)
{
	u_int32_t len;
	u_int8_t *msg, id;

	trace("network_peer_write_interested() to peer %s:%d", inet_ntoa(p->sa.sin_addr), ntohs(p->sa.sin_port));
	len = htonl(sizeof(id));
	id = PEER_MSG_ID_INTERESTED;

	msg = xmalloc(sizeof(len) + sizeof(id));
	memcpy(msg, &len, sizeof(len));
	memcpy(msg+sizeof(len), &id, sizeof(id));

	p->state |= PEER_STATE_AMINTERESTED;

	network_peer_write(p, msg, sizeof(len) + sizeof(id));
}

/*
 * network_peer_write_bitfield()
 *
 * Send a BITFIELD message to remote peer.
 */
void
network_peer_write_bitfield(struct peer *p)
{
	u_int32_t bitfieldlen, msglen, msglen2;
	u_int8_t *bitfield, *msg, id;

	bitfieldlen = (p->sc->tp->num_pieces + 7) / 8;

	trace("network_peer_write_bitfield() to peer %s:%d len: %u", inet_ntoa(p->sa.sin_addr), ntohs(p->sa.sin_port), bitfieldlen);
	id = PEER_MSG_ID_BITFIELD;
	bitfield = torrent_bitfield_get(p->sc->tp);

	msglen = sizeof(msglen) + sizeof(id) + bitfieldlen;
	msg = xmalloc(msglen);
	msglen2 = htonl(msglen - sizeof(msglen));
	memcpy(msg, &msglen2, sizeof(msglen2));
	memcpy(msg+sizeof(msglen), &id, sizeof(id));
	memcpy(msg+sizeof(msglen)+sizeof(id), bitfield, bitfieldlen);

	network_peer_write(p, msg, msglen);
	xfree(bitfield);
}

/*
 * network_peer_write_unchoke()
 *
 * Send an UNCHOKE message to remote peer.
 */
void
network_peer_write_unchoke(struct peer *p)
{
	u_int32_t len;
	u_int8_t *msg, id;

	trace("network_peer_write_unchoke() to peer %s:%d", inet_ntoa(p->sa.sin_addr), ntohs(p->sa.sin_port));
	len = htonl(sizeof(id));
	id = PEER_MSG_ID_UNCHOKE;

	msg = xmalloc(sizeof(len) + sizeof(id));
	memcpy(msg, &len, sizeof(len));
	memcpy(msg+sizeof(len), &id, sizeof(id));

	p->state &= ~PEER_STATE_AMCHOKING;

	network_peer_write(p, msg, sizeof(len) + sizeof(id));
}

/*
 * network_peer_write_choke()
 *
 * Send a CHOKE message to remote peer.
 */
void
network_peer_write_choke(struct peer *p)
{
	u_int32_t len;
	u_int8_t *msg, id;

	trace("network_peer_write_choke() to peer %s:%d", inet_ntoa(p->sa.sin_addr), ntohs(p->sa.sin_port));
	len = htonl(sizeof(id));
	id = PEER_MSG_ID_CHOKE;

	msg = xmalloc(sizeof(len) + sizeof(id));
	memcpy(msg, &len, sizeof(len));
	memcpy(msg+sizeof(len), &id, sizeof(id));

	p->state |= PEER_STATE_AMCHOKING;
	network_peer_write(p, msg, sizeof(len) + sizeof(id));
}

/*
 * network_peer_write_keepalive()
 *
 * Send a keep-alive message to remote peer.
 */
void
network_peer_write_keepalive(struct peer *p)
{
	u_int32_t len;
	u_int8_t *msg;

	trace("network_peer_write_keepalive() to peer %s:%d", inet_ntoa(p->sa.sin_addr), ntohs(p->sa.sin_port));

	msg = xmalloc(sizeof(len));
	memset(msg, 0, sizeof(len));

	network_peer_write(p, msg, sizeof(len));
}

/*
 * network_peer_write_haveall()
 *
 * Send a HAVEALL message to remote peer.
 */
void
network_peer_write_haveall(struct peer *p)
{
	u_int32_t len;
	u_int8_t *msg, id;

	trace("network_peer_write_haveall() to peer %s:%d", inet_ntoa(p->sa.sin_addr), ntohs(p->sa.sin_port));
	len = htonl(sizeof(id));
	id = PEER_MSG_ID_HAVEALL;

	msg = xmalloc(sizeof(len) + sizeof(id));
	memcpy(msg, &len, sizeof(len));
	memcpy(msg+sizeof(len), &id, sizeof(id));

	network_peer_write(p, msg, sizeof(len) + sizeof(id));
}

/*
 * network_peer_write_havenone()
 *
 * Send a HAVENONE message to remote peer.
 */
void
network_peer_write_havenone(struct peer *p)
{
	u_int32_t len;
	u_int8_t *msg, id;

	trace("network_peer_write_havenone() to peer %s:%d", inet_ntoa(p->sa.sin_addr), ntohs(p->sa.sin_port));
	len = htonl(sizeof(id));
	id = PEER_MSG_ID_HAVENONE;

	msg = xmalloc(sizeof(len) + sizeof(id));
	memcpy(msg, &len, sizeof(len));
	memcpy(msg+sizeof(len), &id, sizeof(id));

	network_peer_write(p, msg, sizeof(len) + sizeof(id));
}

/* network_peer_reject_block()
 *
 * Send a REJECT message to remote peer.
 */
void
network_peer_reject_block(struct peer *p, u_int32_t idx, u_int32_t off, u_int32_t len)
{
	u_int32_t msglen, msglen2, blocklen;
	u_int8_t  *msg, id;

	trace("network_peer_reject_block, index: %u offset: %u len: %u to peer %s:%d", idx, off, len,
	    inet_ntoa(p->sa.sin_addr), ntohs(p->sa.sin_port));
	msglen = sizeof(msglen) + sizeof(id) + sizeof(idx) + sizeof(off) + sizeof(blocklen);
	msg = xmalloc(msglen);

	msglen2 = htonl(msglen - sizeof(msglen));
	id = PEER_MSG_ID_REJECT;
	idx = htonl(idx);
	off = htonl(off);
	blocklen = htonl(len);

	memcpy(msg, &msglen2, sizeof(msglen2));
	memcpy(msg+sizeof(msglen2), &id, sizeof(id));
	memcpy(msg+sizeof(msglen2)+sizeof(id), &idx, sizeof(idx));
	memcpy(msg+sizeof(msglen2)+sizeof(id)+sizeof(idx), &off, sizeof(off));
	memcpy(msg+sizeof(msglen2)+sizeof(id)+sizeof(idx)+sizeof(off), &blocklen, sizeof(blocklen));

	network_peer_write(p, msg, msglen);
}

/*
 * network_crypto_dh()
 *
 * Generate a DH key object.
 */
DH *
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

/*
 * network_peer_lastcomms()
 *
 * Return how long in seconds since last communication on this peer.
 */
long
network_peer_lastcomms(struct peer *p)
{
	return (time(NULL) - p->lastrecv);
}

/*
 * network_peer_rxrate()
 *
 * Return the average rx transfer rate of a given peer.
 */
u_int64_t
network_peer_rxrate(struct peer *p)
{
	u_int64_t rate;

	rate = time(NULL) - p->connected;
	/* prevent divide by zero */
	if (rate == 0)
		return (0);
	return (p->totalrx / rate);

}

/*
 * network_peer_txrate()
 *
 * Return the average tx transfer rate of a given peer.
 */
u_int64_t
network_peer_txrate(struct peer *p)
{
	u_int64_t rate;

	rate = time(NULL) - p->connected;
	/* prevent divide by zero */
	if (rate == 0)
		return (0);
	return (p->totaltx / rate);

}

/*
 * network_piece_dl_create()
 *
 * Create a piece dl, and also insert into the per-peer list and global
 * btree index.
 */
struct piece_dl *
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

/*
 * network_piece_dl_free()
 *
 * Free piece dls in a clean manner.
 */
void
network_piece_dl_free(struct session *sc, struct piece_dl *pd)
{
	struct piece_dl_idxnode find, *res;
	find.off = pd->off;
	find.idx = pd->idx;
	/* remove from index/offset btree */
	if ((res = RB_FIND(piece_dl_by_idxoff, &sc->piece_dl_by_idxoff, &find)) != NULL)
		TAILQ_REMOVE(&res->idxnode_piece_dls, pd, idxnode_piece_dl_list);
	if (pd->pc != NULL) {
		/* remove from per-peer list */
		TAILQ_REMOVE(&pd->pc->peer_piece_dls, pd, peer_piece_dl_list);
	}
	if (res != NULL
	    && TAILQ_EMPTY(&res->idxnode_piece_dls))
		RB_REMOVE(piece_dl_by_idxoff, &sc->piece_dl_by_idxoff, res);
	xfree(pd);
	pd = NULL;
}

/* public functions */

/*
 * network_init()
 *
 * Network subsystem init, needs to be called before doing anything.
 */
void
network_init()
{
	event_init();
}

/*
 * network_listen()
 *
 * Create a listening server socket.
 */
int
network_listen(char *host, char *port)
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
	if (listen(fd, MAX_BACKLOG) == -1)
		err(1, "could not listen on server socket");
	freeaddrinfo(res);
	trace("network_listen() done");
	return fd;
}

/*
 * network_start_torrent()
 *
 * Start handling network stuff for a new torrent.
 */
int
network_start_torrent(struct torrent *tp, rlim_t maxfds)
{
	int ret;
	struct session *sc;
	off_t len, started;

	sc = xmalloc(sizeof(*sc));
	memset(sc, 0, sizeof(*sc));

	TAILQ_INIT(&sc->peers);
	sc->tp = tp;
	sc->maxfds = maxfds;
	if (tp->good_pieces == tp->num_pieces)
		tp->left = 0;
	if (user_port == NULL) {
		sc->port = xstrdup(DEFAULT_PORT);
	} else {
		sc->port = xstrdup(user_port);
		trace("using port %s instead of default", user_port);
	}
	sc->peerid = network_peer_id_create();
	trace("my peer id: %s", sc->peerid);
	/* an ugly way to find out how much data we started with. */
	started = tp->downloaded;
	tp->downloaded = 0;
	if (gui_port != NULL)
		ctl_server_start(sc, gui_port, started);

	if (tp->type == SINGLEFILE) {
		len = tp->body.singlefile.tfp.file_length;
	} else {
		len = tp->body.multifile.total_length;
	}

	start_progress_meter(tp->name, len, &tp->downloaded, &tp->good_pieces, tp->num_pieces, started);
	ret = announce(sc, "started");

	event_dispatch();
	trace("network_start_torrent() returning name %s good pieces %u", tp->name, tp->good_pieces);

	return (ret);
}

/*
 * network_peerlist_update()
 *
 * When given a bencode node, decide which kind of peer list format
 * its in, and fire off the relevant parsing routine.
 */
void
network_peerlist_update(struct session *sc, struct benc_node *peers)
{
	if (peers->flags & BSTRING) {
		network_peerlist_update_string(sc, peers);
	} else {
		network_peerlist_update_dict(sc, peers);
	}
	ctl_server_notify_peers(sc);
}

/*
 * network_handle_peer_connect()
 *
 * Handle incoming peer connections.
 */
void
network_handle_peer_connect(struct bufferevent *bufev, short error, void *data)
{
	struct session *sc;
	struct peer *p;
	struct timeval tv;
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
	/* set up keep-alive timer */
	timerclear(&tv);
	tv.tv_sec = 1;
	evtimer_set(&p->keepalive_event, network_peer_keepalive, p);
	evtimer_add(&p->keepalive_event, &tv);
	trace("network_handle_peer_connect() initiating handshake");
	TAILQ_INSERT_TAIL(&sc->peers, p, peer_list);
	sc->num_peers++;
	network_peer_handshake(sc, p);

	bufferevent_enable(bufev, EV_READ);
}

/*
 * network_connect_tracker()
 *
 * Connects socket to a tracker.
 */
int
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
	trace("network_connect_tracker() calling getaddrinfo() for host: %s port: %s", host, port);
	/* XXX cache thiS, OR PERhaps use evdns */
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

/*
 * network_piece_dl_find()
 *
 * Search our binary tree for the correct index and offset of the piece dl,
 * and return the result.
 */
struct piece_dl *
network_piece_dl_find(struct session *sc, struct peer *p, u_int32_t idx, u_int32_t off)
{
	struct piece_dl *pd;
	struct piece_dl_idxnode find, *res;

	/* if a peer has been supplied, we should simply search its list for this piece. */
	if (p != NULL) {
		TAILQ_FOREACH(pd, &p->peer_piece_dls, peer_piece_dl_list) {
			if (pd->off == off && pd->idx == idx) {
				return (pd);
			}
		}
	}

	find.off = off;
	find.idx = idx;
	if ((res = RB_FIND(piece_dl_by_idxoff, &sc->piece_dl_by_idxoff, &find)) == NULL)
		return (NULL);

	if (TAILQ_EMPTY(&res->idxnode_piece_dls))
		return (NULL);

	/* XXX: for now, return the first piece_dl in the peice_dl_idxnode's list.
	 * later, uniqueness of piece_dl by their index and offset will not be
	 * assumed and we will have to mroe properly handle this */
	return (TAILQ_FIRST(&res->idxnode_piece_dls));
}

/*
 * network_peer_create()
 *
 * Creates a fresh peer object, initialising state and
 * data structures.
 */
struct peer *
network_peer_create(void)
{
	struct peer *p;
	p = xmalloc(sizeof(*p));
	memset(p, 0, sizeof(*p));
	TAILQ_INIT(&p->peer_piece_dls);
	TAILQ_INIT(&p->peer_piece_uls);
	/* peers start in choked state */
	p->state |= PEER_STATE_CHOKED;
	p->state |= PEER_STATE_AMCHOKING;

	return (p);
}

/*
 * network_peer_free()
 *
 * Single function to free a peer correctly.  Includes walking
 * its piece dl list and marking any entries as 'orphaned'.
 */
void
network_peer_free(struct peer *p)
{
	struct piece_dl *pd, *nxtpd;
	struct piece_ul *pu, *nxtpu;
	/* search the piece dl list for any dls associated with this peer */
	for (pd = TAILQ_FIRST(&p->peer_piece_dls); pd; pd = nxtpd) {
		nxtpd = TAILQ_NEXT(pd, peer_piece_dl_list);
		pd->pc = NULL;
		TAILQ_REMOVE(&p->peer_piece_dls, pd, peer_piece_dl_list);
		/* unless this is completed, remove it from the btree */
		if (pd->len != pd->bytes)
			network_piece_dl_free(p->sc, pd);
	}
	/* search the piece ul list for any uls associated with this peer */
	for (pu = TAILQ_FIRST(&p->peer_piece_uls); pu; pu = nxtpu) {
		nxtpu = TAILQ_NEXT(pu, peer_piece_ul_list);
		pu->pc = NULL;
		TAILQ_REMOVE(&p->peer_piece_uls, pu, peer_piece_ul_list);
		xfree(pu);
	}
	if (p->bufev != NULL && p->bufev->enabled & EV_WRITE) {
		bufferevent_disable(p->bufev, EV_WRITE|EV_READ);
		bufferevent_free(p->bufev);
		p->bufev = NULL;
	}
	if (p->rxmsg != NULL)
		xfree(p->rxmsg);
	if (p->bitfield != NULL)
		xfree(p->bitfield);
	if (p->connfd != 0) {
		(void)  close(p->connfd);
		p->connfd = 0;
	}

	evtimer_del(&p->keepalive_event);
	xfree(p);
	p = NULL;
}

/*
 * network_peer_piece_ul_enqueue()
 *
 * This function creates an enqueues a piece request for a peer.
 */
struct piece_ul *
network_piece_ul_enqueue(struct peer *p, u_int32_t idx, u_int32_t off,
    u_int32_t len)
{
	struct piece_ul *pu;

	pu = xmalloc(sizeof(*pu));
	memset(pu, 0, sizeof(*pu));
	pu->pc = p;
	pu->idx = idx;
	pu->off = off;
	pu->len = len;

	TAILQ_INSERT_TAIL(&p->peer_piece_uls, pu, peer_piece_ul_list);

	return (pu);
}

/*
 * network_peer_piece_ul_dequeue()
 *
 * This function dequeues and removes a piece request from a peer.
 */
struct piece_ul *
network_piece_ul_dequeue(struct peer *p)
{
	struct piece_ul *pu;

	if ((pu = TAILQ_FIRST(&p->peer_piece_uls)) != NULL) {
		TAILQ_REMOVE(&p->peer_piece_uls, pu, peer_piece_ul_list);
		return (pu);
	}
	return (NULL);
}
