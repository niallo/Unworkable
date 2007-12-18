/* $Id: includes.h,v 1.37 2007-12-18 06:10:35 niallo Exp $ */
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

#ifndef INCLUDES_H
#define INCLUDES_H

#include <sys/queue.h>
#include <sys/tree.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <sys/types.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <openssl/bn.h>
#include <openssl/dh.h>
#include <openssl/engine.h>

#include <event.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>

#define UNWORKABLE_VERSION "0.2"

#define BSTRING		(1 << 0)
#define BINT		(1 << 1)
#define BDICT		(1 << 2)
#define BLIST		(1 << 3)
#define BDICT_ENTRY	(1 << 4)

#define PEER_STATE_HANDSHAKE1		(1<<0)
#define PEER_STATE_BITFIELD		(1<<1)
#define PEER_STATE_ESTABLISHED		(1<<2)
#define PEER_STATE_AMCHOKING		(1<<3)
#define PEER_STATE_CHOKED		(1<<4)
#define PEER_STATE_AMINTERESTED		(1<<5)
#define PEER_STATE_INTERESTED		(1<<6)
#define PEER_STATE_DEAD			(1<<7)
#define PEER_STATE_GOTLEN		(1<<8)
#define PEER_STATE_CRYPTED		(1<<9)
#define PEER_STATE_HANDSHAKE2		(1<<10)

#define PEER_MSG_ID_CHOKE		0
#define PEER_MSG_ID_UNCHOKE		1
#define PEER_MSG_ID_INTERESTED		2
#define PEER_MSG_ID_NOTINTERESTED	3
#define PEER_MSG_ID_HAVE		4
#define PEER_MSG_ID_BITFIELD		5
#define PEER_MSG_ID_REQUEST		6
#define PEER_MSG_ID_PIECE		7
#define PEER_MSG_ID_CANCEL		8

#define PEER_COMMS_THRESHOLD		120 /* 120 seconds */

#define BLOCK_SIZE			16384 /* 16KB */
#define MAX_BACKLOG			65536 /* 64KB */
#define LENGTH_FIELD 			4 /* peer messages use a 4byte len field */
#define MAX_MESSAGE_LEN 		0xffffff /* 16M */
#define DEFAULT_ANNOUNCE_INTERVAL	1800/* */
#define MAX_REQUESTS			100 /* max request queue length per peer */

/* MSE defines
 * see http://www.azureuswiki.com/index.php/Message_Stream_Encryption */
#define CRYPTO_PRIME			0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A63A36210000000000090563
#define CRYPTO_GENERATOR		2
#define CRYPTO_PLAINTEXT		0x01
#define CRYPTO_RC4			0x02
#define CRYPTO_INT_LEN			160
#define CRYPTO_MAX_BYTES1		608
#define CRYPTO_MIN_BYTES1		96

#define BT_PROTOCOL			"BitTorrent protocol"
#define BT_PSTRLEN			19
#define BT_INITIAL_LEN 			20

/* try to keep this many peer connections at all times */
#define PEERS_WANTED			10

/* when trying to fetch more peers, make sure we don't announce
 * more often than this interval allows */
#define MIN_ANNOUNCE_INTERVAL		60

#define PEER_ID_LEN			20
/* these are used in the HTTP client */
#define GETSTRINGLEN			2048
#define HTTPLEN				7
#define RESBUFLEN			1024
#define HTTP_1_0			"HTTP/1.0"
#define HTTP_1_1			"HTTP/1.1"
#define HTTP_OK				"200"
#define HTTP_END			"\r\n\r\n"

/* what percentage remaining to be considered endgame? */
#define ENDGAME_PERCENTAGE		5

#define DEFAULT_PORT			"6668"

#define PIECE_GIMME_NOCREATE		(1<<0)

#define CTL_MESSAGE_LEN			64

struct benc_node {
	/*
	 *  Having this HEAD in every node is slightly wasteful of memory,
	 *  but I can't figure out how to put it in the union.
	 */
	TAILQ_HEAD(children, benc_node)		children;

	TAILQ_ENTRY(benc_node)			benc_nodes;
	unsigned int				flags;
	union {
		long long			number;
		struct {
			char *value;
			size_t len;
		}				string;
		struct {
			char *key;
			struct benc_node *value;
		}				dict_entry;
	} body;
	/* in dictionaries, absolute offset of dict end from start of input buffer */
	size_t end;
};

enum type { MULTIFILE, SINGLEFILE };

struct torrent_mmap {
	u_int8_t			*addr;
	u_int8_t			*aligned_addr;
	u_int32_t			len;
	struct torrent_file		*tfp;
	TAILQ_ENTRY(torrent_mmap)	mmaps;
};


#define TORRENT_PIECE_CKSUMOK		(1<<0)
#define TORRENT_PIECE_MAPPED		(1<<1)

struct torrent_piece {
	/* misc info about the piece */
	int				flags;
	/* how many blocks we currently have */
	u_int32_t                          blocks;
	/* how long the piece actually is */
	u_int32_t                          len;
	/* index of this piece in the torrent */
	u_int32_t                          index;
	/* list of low-level mmaps containing the blocks */
	TAILQ_HEAD(mmaps, torrent_mmap)	mmaps;
	/* pointer to containing torrent */
	struct torrent			*tp;
};

struct torrent_file {
	TAILQ_ENTRY(torrent_file)		files;
	off_t					file_length;
	char					*md5sum;
	char					*path;
	int					fd;
	size_t					refs;
};

struct torrent {
	union {
		struct {
			char			*pieces;
			struct torrent_file	tfp;
		} singlefile;

		struct {
			TAILQ_HEAD(files, torrent_file) files;
			char			*name;
			char			*pieces;
			off_t			total_length;
		} multifile;
	} body;
	char					*announce;
	time_t					creation_date;
	char					*comment;
	char					*created_by;
	u_int8_t				*info_hash;
	u_int32_t				num_pieces;
	u_int32_t				piece_length;
	u_int32_t				good_pieces;
	enum type				type;
	off_t					uploaded;
	off_t					downloaded;
	off_t					left;
	struct benc_node			*broot;
	u_int32_t				interval;
	char					*trackerid;
	char					*name;
	short					isnew;
	u_int32_t				complete;
	u_int32_t				incomplete;
};

/* Control server */
struct ctl_server {
	struct session *sc;
	struct bufferevent *bev;
	off_t started;
	int fd;
	TAILQ_HEAD(ctl_server_conns, ctl_server_conn) conns;
};

/* Connections to control server */
struct ctl_server_conn {
	struct bufferevent *bev;
	struct sockaddr_in sa;
	struct ctl_server *cs;
	int fd;
	TAILQ_ENTRY(ctl_server_conn) conn_list;
};

/* data for a http response */
struct http_response {
	/* response buffer */
	u_int8_t *rxmsg;
	/* size of buffer so far */
	u_int32_t rxread, rxmsglen;
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
	u_int8_t *rxmsg;
	u_int8_t *bitfield;
	/* from peer's handshake message */
	u_int8_t pstrlen;
	u_int8_t id[PEER_ID_LEN];
	u_int8_t info_hash[20];

	struct session *sc;
	/* last time we rx'd something from this peer */
	time_t  lastrecv;
	/* time we connected this peer (ie start of its life) */
	time_t connected;
	/* how many bytes have we rx'd from the peer since it was connected */
	u_int64_t totalrx;
	/* block request queue length*/
	u_int32_t queue_len;
};

/* piece download transaction */
struct piece_dl {
	TAILQ_ENTRY(piece_dl) peer_piece_dl_list;
	TAILQ_ENTRY(piece_dl) idxnode_piece_dl_list;
	struct peer *pc; /* peer we're requesting from */
	u_int32_t idx; /* piece index */
	u_int32_t off; /* offset within this piece */
	u_int32_t len; /* length of this request */
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

struct piececounter {
	u_int32_t count;
	u_int32_t idx;
};

struct peercounter {
	u_int64_t rate;
	struct peer *peer;
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
	struct torrent *tp;
	struct http_response *res;
	rlim_t maxfds;
	int announce_underway;
	u_int32_t tracker_num_peers;
	u_int32_t num_peers;
	time_t last_announce;
	struct piececounter *rarity_array;
	time_t last_rarity;
	struct ctl_server *ctl_server;
};

void			 benc_node_add(struct benc_node *, struct benc_node *);
void			 benc_node_add_head(struct benc_node *,
			    struct benc_node *);
struct benc_node	*benc_node_create(void);
struct benc_node	*benc_node_find(struct benc_node *node, char *);
void			 benc_node_print(struct benc_node *, int);
struct benc_node	*benc_root_create(void);
void			 benc_node_freeall(struct benc_node *);

extern struct benc_node	*root;

/* flags */
#define BUF_AUTOEXT	1	/* autoextend on append */

typedef struct buf BUF;

BUF		*buf_alloc(size_t, u_int);
BUF		*buf_load(const char *, u_int);
void		 buf_free(BUF *);
void		*buf_release(BUF *);
int		 buf_getc(BUF *);
void		 buf_empty(BUF *);
ssize_t		 buf_set(BUF *, const void *, size_t, size_t);
ssize_t		 buf_append(BUF *, const void *, size_t);
void		 buf_putc(BUF *, int);
size_t		 buf_len(BUF *);
int		 buf_write_fd(BUF *, int);
int		 buf_write(BUF *, const char *, mode_t);
void		 buf_write_stmp(BUF *, char *, mode_t);
void		 buf_ungetc(BUF *);
size_t		 buf_pos(BUF *);

int		 mkpath(const char *, mode_t);
void		 network_init(void);
int		 network_start_torrent(struct torrent *, rlim_t);
int				yyerror(const char *, ...);
int				yyparse(void);
int				yylex(void);
struct benc_node		*benc_parse_buf(BUF *b, struct benc_node *);

extern BUF			*in;
void			*torrent_block_read(struct torrent_piece *, off_t,
			    u_int32_t, int *);
void			 torrent_block_write(struct torrent_piece *, off_t,
			    u_int32_t, void *);
struct torrent_mmap	*torrent_mmap_create(struct torrent *,
			    struct torrent_file *, off_t, u_int32_t);
struct torrent		*torrent_parse_file(const char *);
u_int8_t		*torrent_parse_infohash(const char *, size_t);
int			 torrent_piece_checkhash(struct torrent *,
			    struct torrent_piece *);
struct torrent_piece	*torrent_piece_find(struct torrent *, u_int32_t);
struct torrent_piece	*torrent_pieces_create(struct torrent *);
int			 torrent_piece_map(struct torrent_piece *);
void			 torrent_piece_unmap(struct torrent_piece *);
void			 torrent_print(struct torrent *);
int			 torrent_intcmp(struct torrent_piece *,
			    struct torrent_piece *);
u_int8_t		*torrent_bitfield_get(struct torrent *);
int			 torrent_empty(struct torrent *);
void			 torrent_piece_sync(struct torrent *, u_int32_t);
/*
 * Support for Boehm's garbage collector, useful for finding leaks.
 */
#if defined(USE_BOEHM_GC)
#include <gc.h>
#define xmalloc(n) GC_MALLOC(n)
#define xcalloc(m,n) GC_MALLOC((m)*(n))
#define xfree(p) GC_FREE(p)
#define xrealloc(p,n) GC_REALLOC((p),(n))
#define xstrdup(n) gc_strdup(n)
#define CHECK_LEAKS() GC_gcollect()
char *gc_strdup(const char *);
#else
void *xmalloc(size_t);
void *xrealloc(void *, size_t);
void *xcalloc(size_t, size_t);
void  xfree(void *);
char *xstrdup(const char *);
#endif /* USE_BOEHM_GC */
#endif /* INCLUDES_H */
/*
 * Ensure all of data on socket comes through. f==read || f==vwrite
 */
size_t	atomicio(ssize_t (*)(int, void *, size_t), int, void *, size_t);

#define vwrite (ssize_t (*)(int, void *, size_t))write
void	refresh_progress_meter(void);
void	start_progress_meter(char *, off_t, off_t *, u_int32_t *, u_int32_t, off_t);
void	stop_progress_meter(void);

void	trace(const char *, ...);

void	sighandler(int);
void	print_len(void *, size_t);


extern char *unworkable_trace;
extern char *user_port;
extern char *gui_port;
extern int seed;


static const u_int8_t mse_P[] = {
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC9, 0x0F, 0xDA, 0xA2,
	0x21, 0x68, 0xC2, 0x34, 0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1,
	0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74, 0x02, 0x0B, 0xBE, 0xA6,
	0x3B, 0x13, 0x9B, 0x22, 0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
	0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B, 0x30, 0x2B, 0x0A, 0x6D,
	0xF2, 0x5F, 0x14, 0x37, 0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45,
	0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6, 0xF4, 0x4C, 0x42, 0xE9,
	0xA6, 0x3A, 0x36, 0x21, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09, 0x05, 0x63
};

static const u_int8_t mse_G[] = { 2 };
static const u_int8_t mse_VC[] = { 0, 0, 0, 0, 0, 0, 0, 0 };
#ifdef NO_STRLCPY
size_t		strlcpy(char *, const char *, size_t);
#endif
#ifdef NO_STRLCAT
size_t		strlcat(char *, const char *, size_t);
#endif
#ifdef NO_STRTONUM
long long	strtonum(const char *, long long, long long, const char **);
#endif
#ifdef NO_ERR
void     err(int, const char *, ...);
void     verr(int, const char *, __va_list);
void     errx(int, const char *, ...);
void     verrx(int, const char *, __va_list);
void     warn(const char *, ...);
void     vwarn(const char *, __va_list);
void     warnx(const char *, ...);
void     vwarnx(const char *, __va_list);
#else
#include <err.h>
#endif

#define BIT_SET(a,i)	((a)[(i)>>3] |= 1<<((i)&(8-1)))
#define BIT_CLR(a,i)	((a)[(i)>>3] &= ~(1<<((i)&(8-1))))
#define BIT_ISSET(a,i)	((a)[(i)>>3] & (1<<((i)&(8-1))))
#define BIT_ISCLR(a,i)	(((a)[(i)>>3] & (1<<((i)&(8-1)))) == 0)

/* solaris 10 specific */
#if defined(__SVR4) && defined(__sun)
char *__progname;
#endif

int	announce(struct session *, const char *);
int	network_listen(char *, char *);
void	network_peerlist_update(struct session *, struct benc_node *);
struct piece_dl *network_piece_dl_find(struct session *, struct peer *, u_int32_t, u_int32_t);
int	network_connect_tracker(const char *, const char *);
void	network_peer_write_piece(struct peer *, u_int32_t, off_t, u_int32_t);
void	network_peer_read_piece(struct peer *, u_int32_t, off_t, u_int32_t, void *);
void	network_peer_write_bitfield(struct peer *);
void	network_peer_write_interested(struct peer *);
void	network_peer_free(struct peer *);
struct peer * network_peer_create(void);
void	network_handle_peer_write(struct bufferevent *, void *);
void	network_handle_peer_error(struct bufferevent *, short, void *);
void	network_handle_peer_connect(struct bufferevent *, short, void *);
void	network_peer_request_block(struct peer *, u_int32_t, u_int32_t, u_int32_t);
void	network_peer_write_choke(struct peer *);
void	network_peer_write_unchoke(struct peer *);
void	network_peer_cancel_piece(struct piece_dl *);
void	network_peer_write_have(struct peer *, u_int32_t);
DH	*network_crypto_dh(void);
long	network_peer_lastcomms(struct peer *);
u_int64_t network_peer_rate(struct peer *);
struct piece_dl * network_piece_dl_create(struct peer *, u_int32_t,
    u_int32_t, u_int32_t);
void	network_piece_dl_free(struct session *, struct piece_dl *);
int	piece_dl_idxnode_cmp(struct piece_dl_idxnode *, struct piece_dl_idxnode *);
/* index of piece dls by block index and offset */
RB_PROTOTYPE(piece_dl_by_idxoff, piece_dl_idxnode, entry, piece_dl_idxnode_cmp)

void	scheduler(int, short, void *);
struct piece_dl * scheduler_piece_gimme(struct peer *, int, int *);

void ctl_server_start(struct session *, char *, off_t);
void ctl_server_notify_bytes(struct session *, off_t);
void ctl_server_notify_pieces(struct session *);
void ctl_server_notify_peers(struct session *);
