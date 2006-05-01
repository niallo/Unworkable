/* $Id: bencode.c,v 1.7 2006-05-01 00:56:32 niallo Exp $ */
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

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bencode.h"

struct benc_node *root;

/* add new node as child of old and return new node */
void
benc_node_add(struct benc_node *node, struct benc_node *new)
{
#define IS_CONTAINER_TYPE(x) \
	(x->flags & BDICT || x->flags & BLIST)

	//printf("adding node of type %s\n", type2string(new));
	if (IS_CONTAINER_TYPE(node)) {
		/*
		printf("inserting as child of node 0x%x\n",
		    (unsigned int) node);
		*/
		SLIST_INSERT_HEAD(&(node->children), new, benc_nodes);
		new->parent = node;
	}
	else if (node->parent == NULL) {
		printf("adding to root\n");
		benc_node_add(root, new);
		new->parent = root;
	}
	else {
		printf("adding to grandparent\n");
		benc_node_add(node->parent, new);
		new->parent = node->parent;
	}
}

/* create and initialise a benc_node */
struct benc_node *
benc_node_create(void)
{
	struct benc_node *node;

	if ((node = malloc(sizeof(*node))) == NULL)
		err(1, "benc_create_node: malloc");

	memset(node, 0, sizeof(*node));

	SLIST_INIT(&(node->children));

	return (node);
}

void
print_tree(struct benc_node *node, int level)
{
	struct benc_node *cnode;
	int i;
	/* 64 levels */

	for (i = 0; i < level; i++)
		printf("\t");

	if (node->parent != NULL && node->parent->flags & BDICT) {
		printf("key: %s", node->body.dict_entry.key);
		print_tree(node->body.dict_entry.value, level);
	} else if (node->flags & BSTRING) {
		printf("string len: %ld value: %s\n", node->body.string.len,
		    node->body.string.value);
	} else if (node->flags & BINT) {
		printf("int value: %ld\n", node->body.number);
	} else if (node->flags & BLIST) {
		printf("blist\n");
		SLIST_FOREACH(cnode, &(node->children), benc_nodes)
			print_tree(cnode, level + 1);
	} else if (node->flags & BDICT) {
		printf("bdict\n");
		SLIST_FOREACH(cnode, &(node->children), benc_nodes)
			print_tree(cnode, level + 1);
	}
}
