/* $Id: bencode.h,v 1.8 2006-05-01 01:34:07 niallo Exp $ */
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

#ifndef BENCODE_H
#define BENCODE_H

#include <sys/queue.h>

enum btype { BSTRING, BINT, BDICT, BLIST };

#define BSTRING		(1 << 0)
#define BINT		(1 << 1)
#define BDICT		(1 << 2)
#define BLIST		(1 << 3)
#define BDICT_ENTRY	(1 << 4)


struct benc_node {
	struct benc_node			*parent;
	/*
	 *  Having this HEAD in every node is slightly wasteful of memory,
	 *  but I can't figure out how to put it in the union.
	 */
	SLIST_HEAD(children, benc_node)		children;

	SLIST_ENTRY(benc_node)			benc_nodes;
	unsigned int				flags;
	union {
		long				number;
		struct {
			char *value;
			long len;
		}				string;
		struct {
			char *key;
			struct benc_node *value;
		}				dict_entry;
	} body;
};

void			benc_node_add(struct benc_node *, struct benc_node *);
struct benc_node	*benc_node_create(void);
void			benc_node_free(struct benc_node *);


void			print_tree(struct benc_node *, int level);

extern struct benc_node	*root;
#endif /* BENCODE_H */
