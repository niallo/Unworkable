/* $Id: includes.h,v 1.25 2007-11-16 06:17:16 niallo Exp $ */
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

#include <signal.h>
#include <stdarg.h>
#include <stdio.h>

#define UNWORKABLE_VERSION "0.1"

#define BSTRING		(1 << 0)
#define BINT		(1 << 1)
#define BDICT		(1 << 2)
#define BLIST		(1 << 3)
#define BDICT_ENTRY	(1 << 4)


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
	void				*addr;
	void				*aligned_addr;
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
