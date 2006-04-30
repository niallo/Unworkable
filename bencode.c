/* $Id: bencode.c,v 1.6 2006-04-30 01:56:58 niallo Exp $ */
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

struct b_node *root;

/* add new node as child of old and return new node */
struct b_node *
add_node(struct b_node *node, struct b_node *new)
{
#define IS_CONTAINER_TYPE(x) \
	(x->type == BDICT || x->type == BLIST)

	if (IS_CONTAINER_TYPE(node)) {
		printf("adding node to children\n");
		SLIST_INSERT_HEAD(&(node->children), new, b_nodes);
	}
	else if (node->parent == NULL) {
		printf("adding node to root\n");
		add_node(root, new);
	}
	else {
		printf("adding node to parent\n");
		add_node(node->parent, new);
	}

	return (new);
}

/* create and initialise a b_node */
struct b_node *
create_node(void)
{
	struct b_node *node;

	if ((node = malloc(sizeof(*node))) == NULL)
		err(1, "create_node: malloc");

	memset(node, 0, sizeof(*node));

	SLIST_INIT(&(node->children));

	return (node);
}


void
print_tree(struct b_node *node, int level)
{
	struct b_node *cnode;
	int i;
	/* 64 levels */

	for (i = 0; i < level; i++)
		printf("\t");

	if (node->parent != NULL && node->parent->type == BDICT) {
		printf("key: %s", node->body.dict_entry.key);
		print_tree(node->body.dict_entry.value, level);
	}

	if (node->type == BSTRING) {
		printf("string len: %ld value: %s\n", node->body.string.len,
		    node->body.string.value);
	} else if (node->type == BINT) {
		printf("int value: %ld\n", node->body.number);
	} else if (node->type == BLIST) {
		printf("blist\n");
		SLIST_FOREACH(cnode, &(node->children), b_nodes)
			print_tree(cnode, level + 1);
	} else if (node->type == BDICT) {
		printf("bdict\n");
		SLIST_FOREACH(cnode, &(node->children), b_nodes)
			print_tree(cnode, level + 1);
	}
}
