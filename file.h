/* $Id: file.h,v 1.2 2006-05-15 16:24:38 niallo Exp $ */
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
#ifndef FILE_H
#define FILE_H

#include <sys/queue.h>

#define COMPLETE	(1 << 0)

struct piece {
	int				flags;
	char				*sha1;
	size_t				len;
	off_t				offset;
	SLIST_ENTRY(piece)		pieces;
};

struct file {
	int				fd;
	void				*addr;
	SLIST_HEAD(pieces, piece)	pieces;
};

struct file				*file_open(const char *path);

/* FILE_H */
#endif
