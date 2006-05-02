/* $Id: bencode.c,v 1.21 2006-05-02 14:05:31 niallo Exp $ */
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

#define IS_CONTAINER_TYPE(x) \
	(x->flags & BDICT || x->flags & BLIST)

struct benc_node *root;

/* add new node as child of old and return new node */
void
benc_node_add(struct benc_node *node, struct benc_node *new)
{
	SLIST_INSERT_HEAD(&(node->children), new, benc_nodes);
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
		SLIST_FOREACH(childnode,
		    &(node->body.dict_entry.value->children), benc_nodes)
			if ((ret = benc_node_find(childnode, key)) != NULL)
				return (ret);

	if (IS_CONTAINER_TYPE(node))
		SLIST_FOREACH(childnode, &(node->children), benc_nodes)
			if ((ret = benc_node_find(childnode, key)) != NULL)
				return (ret);

	return (NULL);
}

/* recursively free a node tree */
void
benc_node_free(struct benc_node *node)
{
	struct benc_node *childnode;

	if (node->flags & BDICT_ENTRY) {
		free(node->body.dict_entry.key);
		free(node->body.dict_entry.value);
	}

	if (node->flags & BSTRING && !(node->flags & BDICT_ENTRY))
		free(node->body.string.value);
	
	if (IS_CONTAINER_TYPE(node)) {
		SLIST_FOREACH(childnode, &(node->children), benc_nodes)
			benc_node_free(childnode);
		while (!SLIST_EMPTY(&(node->children)))
			SLIST_REMOVE_HEAD(&(node->children), benc_nodes);
	}
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
		printf("int value: %ld\n", node->body.number);
	} else if (node->flags & BLIST) {
		printf("blist\n");
		SLIST_FOREACH(childnode, &(node->children), benc_nodes)
			benc_node_print(childnode, level + 1);
	} else if (node->flags & BDICT) {
		printf("bdict\n");
		SLIST_FOREACH(childnode, &(node->children), benc_nodes)
			benc_node_print(childnode, level + 1);
	}
}
