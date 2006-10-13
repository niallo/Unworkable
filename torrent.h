/* $Id: torrent.h,v 1.20 2006-10-13 23:56:06 niallo Exp $ */
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

#ifndef TORRENT_H
#define TORRENT_H

#include <sys/queue.h>
#include <sys/tree.h>

#include "bencode.h"

enum type { MULTIFILE, SINGLEFILE };

struct torrent_mmap {
	void				*addr;
	size_t				len;
	struct torrent_file		*tfp;
	TAILQ_ENTRY(torrent_mmap)	mmaps;
};

struct torrent_piece {
	int				flags;
	size_t				len;
	int				index;
	TAILQ_HEAD(mmaps, torrent_mmap)	mmaps;
	RB_ENTRY(torrent_piece)		entry;
};

struct torrent_file {
	TAILQ_ENTRY(torrent_file)		files;
	off_t					file_length;
	char					*md5sum;
	char					*path;
	int					fd;
	int					refs;
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
	int					num_pieces;
	int					piece_length;
	RB_HEAD(pieces, torrent_piece)		pieces;
	enum type				type;
	unsigned long long			uploaded;
	unsigned long long			downloaded;
	unsigned long long			left;
	struct benc_node			*broot;
};

void			*torrent_block_read(struct torrent_piece *, off_t,
			    size_t, int *);
void			 torrent_block_write(struct torrent_piece *, off_t,
			    size_t, void *);
struct torrent_mmap	*torrent_mmap_create(struct torrent *,
			    struct torrent_file *, off_t, size_t);
struct torrent		*torrent_parse_file(const char *);
u_int8_t		*torrent_parse_infohash(const char *);
int			 torrent_piece_checkhash(struct torrent *,
			    struct torrent_piece *);
struct torrent_piece	*torrent_piece_find(struct torrent *, int);
struct torrent_piece	*torrent_piece_map(struct torrent *, int);
void			 torrent_piece_unmap(struct torrent *, int);
void			 torrent_print(struct torrent *);
int			 torrent_intcmp(struct torrent_piece *,
			    struct torrent_piece *);

/* TORRENT_H */
#endif
