/* $Id: torrent.h,v 1.8 2006-05-15 16:26:39 niallo Exp $ */
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

#include "file.h"

enum type { MULTIFILE, SINGLEFILE };

struct torrent_file {
	SLIST_ENTRY(torrent_file)		files;
	long long				length;
	char					*md5sum;
	char					*path;
	struct file				*file;
};

struct torrent {
	union {
		struct {
			long long		length;
			char			*name;
			long			piece_length;
			char			*pieces;
			char			*md5sum;
		} singlefile;

		struct {
			SLIST_HEAD(files, torrent_file) files;
			char			*name;
			long long		piece_length;
			char			*pieces;
		} multifile;
	} body;
	char					*announce;
	time_t					creation_date;
	char					*comment;
	char					*created_by;
	enum type				type;
};

struct torrent		*torrent_parse_file(const char *);
void 			torrent_print(struct torrent *);

/* TORRENT_H */
#endif
