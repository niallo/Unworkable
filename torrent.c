/* $Id: torrent.c,v 1.8 2006-05-02 14:15:29 niallo Exp $ */
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
#include "parse.h"
#include "torrent.h"

struct torrent *
torrent_parse_file(const char *file)
{
	struct torrent		*torrent;
	struct benc_node	*node;
	FILE			*fp;

	if ((torrent = malloc(sizeof(*torrent))) == NULL)
		err(1, "torrent_parse_file: malloc");

	memset(torrent, 0, sizeof(*torrent));

	if ((fp = fopen(file, "r")) == NULL)
		err(1, "torrent_parse_file: fopen");

	fin = fp;
	if (yyparse() > 0) {
		fclose(fin);
		errx(1, "torrent_parse_file: yyparse");
	}

	fclose(fin);

	if ((node = benc_node_find(root, "announce")) == NULL)
		errx(1, "no announce data found in torrent");

	if (node->flags & BSTRING)
		torrent->announce = node->body.string.value;
	else
		errx(1, "announce value is not a string");

	if ((node = benc_node_find(root, "comment")) != NULL
	    && node->flags & BSTRING)
		torrent->comment = node->body.string.value;

	if ((node = benc_node_find(root, "files")) == NULL)
		torrent->type = SINGLEFILE;
	else
		torrent->type = MULTIFILE;

	return (torrent);
}

void
torrent_print(struct torrent *torrent)
{

	printf("announce url: %s\n", torrent->announce);
	printf("comment: ");
	if (torrent->comment == NULL)
		printf("NONE\n");
	else
		printf("%s\n", torrent->comment);
	printf("type: ");
	if (torrent->type == SINGLEFILE)
		printf("single file\n");
	else
		printf("multi file\n");
}
