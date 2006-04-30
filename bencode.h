/* $Id: bencode.h,v 1.6 2006-04-30 01:56:58 niallo Exp $ */
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

struct b_node {
	struct b_node				*parent;
	/*
	 *  Having this HEAD in every node is slightly wasteful of memory,
	 *  but I can't figure out how to put it in the union.
	 */
	SLIST_HEAD(children, b_node)		children;

	SLIST_ENTRY(b_node)			b_nodes;
	enum btype				type;
	union {
		long				number;
		struct {
			char *value;
			long len;
		}				string;
		struct {
			char *key;
			struct b_node *value;
		}				dict_entry;
	} body;
};

struct b_node		*add_node(struct b_node *, struct b_node *);
struct b_node		*create_node(void);

void			print_tree(struct b_node *, int level);

extern struct b_node	*root;
#endif /* BENCODE_H */
