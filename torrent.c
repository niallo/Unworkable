/* $Id: torrent.c,v 1.20 2006-05-16 01:28:36 niallo Exp $ */
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

#include <sys/param.h>

#include <err.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "bencode.h"
#include "parse.h"
#include "torrent.h"

struct torrent *
torrent_parse_file(const char *file)
{
	struct torrent_file		*multi_file;
	struct torrent			*torrent;
	struct benc_node		*node, *lnode, *tnode;
	struct benc_node		*filenode, *childnode;
	FILE				*fp;
	int				l;
	size_t				ret;

	if ((torrent = malloc(sizeof(*torrent))) == NULL)
		err(1, "torrent_parse_file: malloc");

	memset(torrent, 0, sizeof(*torrent));

	if ((fp = fopen(file, "r")) == NULL)
		err(1, "torrent_parse_file: fopen");

	fin = fp;
	if (yyparse() != 0) {
		fclose(fin);
		errx(1, "torrent_parse_file: yyparse of %s", file);
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

	if ((filenode = benc_node_find(root, "files")) == NULL) {
		torrent->type = SINGLEFILE;
		if ((node = benc_node_find(root, "length")) == NULL)
			errx(1, "no length field");

		if (!(node->flags & BINT))
			errx(1, "length is not a number");

		torrent->body.singlefile.length = node->body.number;

		if ((node = benc_node_find(root, "name")) == NULL)
			errx(1, "no name field");

		if (!(node->flags & BSTRING))
			errx(1, "name is not a string");

		torrent->body.singlefile.name = node->body.string.value;

		if ((node = benc_node_find(root, "piece length")) == NULL)
			errx(1, "no piece length field");

		if (!(node->flags & BINT))
			errx(1, "piece length is not a number");

		torrent->body.singlefile.piece_length = node->body.number;

		if ((node = benc_node_find(root, "pieces")) == NULL)
			errx(1, "no pieces field");

		if (!(node->flags & BSTRING))
			errx(1, "pieces is not a string");

		torrent->body.singlefile.pieces = node->body.string.value;

		if ((node = benc_node_find(root, "md5sum")) != NULL) {
			if (!(node->flags & BSTRING))
				errx(1, "md5sum is not a string");
			else
				torrent->body.singlefile.md5sum =
				    node->body.string.value;
		}
	} else {
		torrent->type = MULTIFILE;
		if ((node = benc_node_find(root, "name")) == NULL)
			errx(1, "no name field");

		if (!(node->flags & BSTRING))
			errx(1, "name is not a string");

		torrent->body.multifile.name = node->body.string.value;

		if ((node = benc_node_find(root, "piece length")) == NULL)
			errx(1, "no piece length field");

		if (!(node->flags & BINT))
			errx(1, "piece length is not a number");

		torrent->body.multifile.piece_length = node->body.number;

		if ((node = benc_node_find(root, "pieces")) == NULL)
			errx(1, "no pieces field");

		if (!(node->flags & BSTRING))
			errx(1, "pieces is not a string");

		torrent->body.multifile.pieces = node->body.string.value;

		SLIST_INIT(&(torrent->body.multifile.files));

		/* iterate through sub-dictionaries */
		SLIST_FOREACH(childnode, &(filenode->children), benc_nodes) {
			if ((multi_file = malloc(sizeof(*multi_file))) == NULL)
				err(1, "torrent_parse_file: malloc");

			memset(multi_file, 0, sizeof(*multi_file));
			if ((tnode = benc_node_find(childnode, "length")) == NULL)
				errx(1, "no length field");
			if (!(tnode->flags & BINT))
				errx(1, "length is not a number");
			multi_file->length = tnode->body.number;
			if ((tnode = benc_node_find(childnode, "md5sum")) != NULL
			    && tnode->flags & BSTRING)
				multi_file->md5sum = tnode->body.string.value;

			if ((tnode = benc_node_find(childnode, "path")) == NULL)
				errx(1, "no path field");
			if (!(tnode->flags & BLIST))
				errx(1, "path is not a list");

			if ((multi_file->path = malloc(MAXPATHLEN)) == NULL)
				err(1, "torrent_parse_file: malloc");

			memset(multi_file->path, '\0', MAXPATHLEN);

			SLIST_FOREACH(lnode, &(tnode->children), benc_nodes) {
				printf("p: %s\n", lnode->body.string.value);
				if (!(lnode->flags & BSTRING))
					errx(1, "path element is not a string");
				if (*multi_file->path == '\0') {
					ret = strlcpy(multi_file->path,
					    lnode->body.string.value,
					    MAXPATHLEN);
					if (ret >= MAXPATHLEN)
						errx(1, "path too large");
				} else {
					l = snprintf(multi_file->path,
					    MAXPATHLEN, "%s/%s",
					    multi_file->path,
					    lnode->body.string.value);
					if (l == -1 || l >= MAXPATHLEN)
						errx(1, "path too large");
				}
			}

			SLIST_INSERT_HEAD(&(torrent->body.multifile.files),
			    multi_file, files);
		}
	}

	if ((node = benc_node_find(root, "created by")) != NULL
	    && node->flags & BSTRING)
		torrent->created_by = node->body.string.value;

	if ((node = benc_node_find(root, "creation date")) != NULL
	    && node->flags & BINT)
		torrent->creation_date = node->body.number;

	return (torrent);
}

void
torrent_print(struct torrent *torrent)
{
	struct torrent_file *tfile;

	printf("announce url:\t%s\n", torrent->announce);
	printf("created by:\t");
	if (torrent->created_by == NULL)
		printf("NONE\n");
	else
		printf("%s\n", torrent->created_by);
	printf("creation date:\t");
	if (torrent->creation_date == NULL)
		printf("NONE\n");
	else
		printf("%s", ctime(&torrent->creation_date));
	printf("comment:\t");
	if (torrent->comment == NULL)
		printf("NONE\n");
	else
		printf("%s\n", torrent->comment);
	printf("type:\t\t");
	if (torrent->type == SINGLEFILE) {
		printf("single file\n");
		printf("length:\t\t%lld bytes\n",
		    torrent->body.singlefile.length);
		printf("file name:\t%s\n",
		    torrent->body.singlefile.name);
		printf("piece length:\t%ld bytes\n",
		    torrent->body.singlefile.piece_length);
		printf("md5sum:\t\t");
		if (torrent->body.singlefile.md5sum == NULL)
			printf("NONE\n");
		else
			printf("%s\n", torrent->body.singlefile.md5sum);
	} else {
		printf("multi file\n");
		printf("base path:\t%s\n",
		    torrent->body.multifile.name);
		printf("piece length:\t%lld bytes\n",
		    torrent->body.multifile.piece_length);
		printf("--files--\n");
		SLIST_FOREACH(tfile, &(torrent->body.multifile.files), files) {
			printf("file name:\t%s\n", tfile->path);
			printf("length:\t\t%lld bytes\n", tfile->length);
			printf("md5sum:\t\t");
			if (tfile->md5sum == NULL)
				printf("NONE\n");
			else
				printf("%s\n", tfile->md5sum);
		}
	}
}
