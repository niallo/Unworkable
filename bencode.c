/* $Id: bencode.c,v 1.31 2006-10-17 19:24:38 niallo Exp $ */
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
#include "xmalloc.h"

#define IS_CONTAINER_TYPE(x) \
	(x->flags & BDICT || x->flags & BLIST)

struct benc_node *root;

/* add new node to tail of node's child queue */
void
benc_node_add(struct benc_node *node, struct benc_node *new)
{
	TAILQ_INSERT_TAIL(&node->children, new, benc_nodes);
}

/* add new node to head of node's child queue */
void
benc_node_add_head(struct benc_node *node, struct benc_node *new)
{
	TAILQ_INSERT_HEAD(&node->children, new, benc_nodes);
}

/* create and initialise a benc_node */
struct benc_node *
benc_node_create(void)
{
	struct benc_node *node;

	node = xmalloc(sizeof(*node));

	memset(node, 0, sizeof(*node));

	TAILQ_INIT(&(node->children));

	return (node);
}

/* find BDICT_ENTRY node with specified key */
struct benc_node *
benc_node_find(struct benc_node *node, char *key)
{
	struct benc_node *childnode, *ret;

	if (node->flags & BDICT_ENTRY
	    && strcmp(key, node->body.dict_entry.key) == 0)
		return (node->body.dict_entry.value);

	if (node->flags & BDICT_ENTRY
	    && IS_CONTAINER_TYPE(node))
		TAILQ_FOREACH(childnode,
		    &node->body.dict_entry.value->children, benc_nodes)
			if ((ret = benc_node_find(childnode, key)) != NULL)
				return (ret);

	if (IS_CONTAINER_TYPE(node))
		TAILQ_FOREACH(childnode, &node->children, benc_nodes)
			if ((ret = benc_node_find(childnode, key)) != NULL)
				return (ret);

	return (NULL);
}

void
benc_node_print(struct benc_node *node, int level)
{
	struct benc_node *childnode;
	int i;

	for (i = 0; i < level; i++)
		printf("\t");

	if (node->flags & BDICT_ENTRY) {
		printf("key: %s", node->body.dict_entry.key);
		benc_node_print(node->body.dict_entry.value, level);
	} else if (node->flags & BSTRING) {
		printf("string len: %ld value: %s\n", node->body.string.len,
		    node->body.string.value);
	} else if (node->flags & BINT) {
		printf("int value: %lld\n", node->body.number);
	}
	if (node->flags & BLIST) {
		printf("blist\n");
		TAILQ_FOREACH(childnode, &node->children, benc_nodes)
			benc_node_print(childnode, level + 1);
	}
	if (node->flags & BDICT) {
		printf("bdict\n");
		TAILQ_FOREACH(childnode, &node->children, benc_nodes)
			benc_node_print(childnode, level + 1);
	}
}

void
benc_node_freeall(struct benc_node *node)
{
	struct benc_node *childnode;

	if (node->flags & BDICT_ENTRY) {
		xfree(node->body.dict_entry.key);
		benc_node_freeall(node->body.dict_entry.value);
	} else if (node->flags & BSTRING) {
		xfree(node->body.string.value);
	}

	if (IS_CONTAINER_TYPE(node)) {
		while ((childnode = TAILQ_FIRST(&node->children)) != NULL) {
			TAILQ_REMOVE(&node->children, childnode, benc_nodes);
			benc_node_freeall(childnode);
		}
	}

	xfree(node);
}

/* create a root node, which parser needs to be passed during init */
struct benc_node *
benc_root_create(void)
{
	struct benc_node *n = benc_node_create();
	n->flags = BLIST;

	return (n);
}
