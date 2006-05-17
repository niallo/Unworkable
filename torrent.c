/* $Id: torrent.c,v 1.21 2006-05-17 16:32:29 niallo Exp $ */
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

#include <sys/types.h>
#include <sys/mman.h>
#include <sys/param.h>

#include <err.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "bencode.h"
#include "parse.h"
#include "torrent.h"

RB_PROTOTYPE(pieces, torrent_piece, entry, torrent_intcmp)
RB_GENERATE(pieces, torrent_piece, entry, torrent_intcmp)

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

		torrent->body.singlefile.file_length = node->body.number;

		if ((node = benc_node_find(root, "name")) == NULL)
			errx(1, "no name field");

		if (!(node->flags & BSTRING))
			errx(1, "name is not a string");

		torrent->body.singlefile.name = node->body.string.value;

		if ((node = benc_node_find(root, "piece length")) == NULL)
			errx(1, "no piece length field");

		if (!(node->flags & BINT))
			errx(1, "piece length is not a number");

		torrent->piece_length = node->body.number;

		if ((node = benc_node_find(root, "pieces")) == NULL)
			errx(1, "no pieces field");

		if (!(node->flags & BSTRING))
			errx(1, "pieces is not a string");

		torrent->body.singlefile.pieces = node->body.string.value;
		torrent->num_pieces = node->body.string.len / 20;

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

		torrent->piece_length = node->body.number;

		if ((node = benc_node_find(root, "pieces")) == NULL)
			errx(1, "no pieces field");

		if (!(node->flags & BSTRING))
			errx(1, "pieces is not a string");

		torrent->body.multifile.pieces = node->body.string.value;
		torrent->body.singlefile.pieces = node->body.string.value;
		torrent->num_pieces = node->body.string.len / 20;

		TAILQ_INIT(&(torrent->body.multifile.files));

		/* iterate through sub-dictionaries */
		SLIST_FOREACH(childnode, &(filenode->children), benc_nodes) {
			if ((multi_file = malloc(sizeof(*multi_file))) == NULL)
				err(1, "torrent_parse_file: malloc");

			memset(multi_file, 0, sizeof(*multi_file));
			if ((tnode = benc_node_find(childnode, "length")) == NULL)
				errx(1, "no length field");
			if (!(tnode->flags & BINT))
				errx(1, "length is not a number");
			multi_file->file_length = tnode->body.number;
			torrent->body.multifile.total_length +=
			    tnode->body.number;
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

			TAILQ_INSERT_TAIL(&(torrent->body.multifile.files),
			    multi_file, files);
		}
	}

	if ((node = benc_node_find(root, "created by")) != NULL
	    && node->flags & BSTRING)
		torrent->created_by = node->body.string.value;

	if ((node = benc_node_find(root, "creation date")) != NULL
	    && node->flags & BINT)
		torrent->creation_date = node->body.number;

	RB_INIT(&(torrent->pieces));

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
	printf("pieces:\t\t%d\n", torrent->num_pieces);
	printf("type:\t\t");
	if (torrent->type == SINGLEFILE) {
		printf("single file\n");
		printf("length:\t\t%lld bytes\n",
		    torrent->body.singlefile.file_length);
		printf("file name:\t%s\n",
		    torrent->body.singlefile.name);
		printf("piece length:\t%d bytes\n",
		    torrent->piece_length);
		printf("md5sum:\t\t");
		if (torrent->body.singlefile.md5sum == NULL)
			printf("NONE\n");
		else
			printf("%s\n", torrent->body.singlefile.md5sum);
	} else {
		printf("multi file\n");
		printf("base path:\t%s\n",
		    torrent->body.multifile.name);
		printf("piece length:\t%d bytes\n",
		    torrent->piece_length);
		printf("--files--\n");
		TAILQ_FOREACH(tfile, &(torrent->body.multifile.files), files) {
			printf("file name:\t%s\n", tfile->path);
			printf("length:\t\t%lld bytes\n", tfile->file_length);
			printf("md5sum:\t\t");
			if (tfile->md5sum == NULL)
				printf("NONE\n");
			else
				printf("%s\n", tfile->md5sum);
		}
	}
}

int
torrent_intcmp(struct torrent_piece *p1, struct torrent_piece *p2)
{
	return (p1->index - p2->index);
}

void
torrent_block_write(struct torrent_piece *tpp, off_t off, size_t len, void *d)
{
	void *block;
	char *aptr, *bptr;
	struct torrent_mmap *tmmp;
	size_t cntlen = 0, tlen = len;

	block = NULL;
	bptr = NULL;

	TAILQ_FOREACH(tmmp, &(tpp->mmaps), mmaps) {
		cntlen += tmmp->len;
		if (tmmp->len < off) {
			continue;
		} else {
			aptr = (char *)tmmp->addr;
			for (; cntlen < off; cntlen++) {
				aptr++;
			}
			if (tmmp->len < len) {
				memcpy(bptr, aptr, tmmp->len);
				bptr += tmmp->len;
				tlen = len - tmmp->len;
			} else {
				memcpy(bptr, aptr, tlen);
			}
		}
	}
}

/* hint will be set to 1 if the return value needs to be freed */
void *
torrent_block_read(struct torrent_piece *tpp, off_t off, size_t len, int *hint)
{
	void *block;
	char *aptr, *bptr;
	struct torrent_mmap *tmmp;
	size_t cntlen = 0, cntbase = 0, tlen = len;

	*hint = 0;
	block = NULL;
	bptr = NULL;

	TAILQ_FOREACH(tmmp, &(tpp->mmaps), mmaps) {
		/* sum the lengths of the mappings we visit. if the offset is
		   greater than the current sum, then the requested data is
		   not within this mapping so continue to next mapping */
		cntlen += tmmp->len;
		if (cntlen < off) {
			/* we need to maintain a base length so that we
			   know how far we need to move the pointer to reach
			   the offset */
			cntbase += tmmp->len;
			continue;
		} else {
			/* our offset is within this mapping, but we still
			   might need to bring the pointer up to it */
			aptr = tmmp->addr;
			for(; cntbase < off; cntbase++)
				aptr++;

			/* this mapping might not contain as many bytes as
			   we requested.  in that case, copy as many as
			   possible and continue to next mapping */
			if (tmmp->len  < tlen) {
				/* make sure we only malloc once */
				if (*hint == 0) {
					if ((block = malloc(len)) == NULL)
						err(1,
						    "torrent_block_read: malloc");
					bptr = block;
					*hint = 1;
				}
				memcpy(bptr, aptr, tmmp->len);
				bptr += tmmp->len;
				tlen -= tmmp->len;
			} else {
				/* if possible, do not do a buffer copy,
				 * but return the mmaped base address directly
				 */
				if (*hint == 0)
					return (aptr);

				memcpy(bptr, aptr, tlen);
				return (block);
			}
		}
	}
	if (*hint == 1)
		return (block);

	return (NULL);
}

struct torrent_piece *
torrent_piece_find(struct torrent *tp, int idx)
{
	struct torrent_piece find, *res;
	find.index = idx;
	res = RB_FIND(pieces, &(tp->pieces), &find);

	return (res);
}

struct torrent_mmap *
torrent_mmap_create(int fd, off_t off, size_t len)
{
	struct torrent_mmap *tmmp;

#define MMAP_FLAGS PROT_READ|PROT_WRITE
	if ((tmmp = malloc(sizeof(*tmmp))) == NULL)
		err(1, "torrent_mmap_create: malloc");
	memset(tmmp, 0, sizeof(*tmmp));
	
	printf("mmap: len %d off: %d fd: %d\n", (int)len, (int)off, fd);
	tmmp->addr = mmap(0, len, MMAP_FLAGS, 0, fd, off);
	if (tmmp->addr == MAP_FAILED)
		err(1, "torrent_mmap_create: mmap");
	tmmp->len = len;

	return (tmmp);
}

struct torrent_piece *
torrent_piece_map(struct torrent *tp, int idx)
{
	struct torrent_piece *tpp;
	struct torrent_file  *nxttfp, *tfp, *lasttfp;
	struct torrent_mmap  *tmmp;
	off_t off;
	size_t len;
	int fd;

	if ((tpp = malloc(sizeof(*tpp))) == NULL)
		err(1, "torrent_piece_map: malloc");
	
	memset(tpp, 0, sizeof(*tpp));
	tpp->index = idx;
	TAILQ_INIT(&(tpp->mmaps));

	/* nice and simple */
	if (tp->type == SINGLEFILE) {
		off = tp->piece_length * idx;
		/* last piece is irregular */
		if (idx == tp->num_pieces - 1) {
			len = tp->body.singlefile.file_length - off;
		} else {
			len = tp->piece_length;
		}
		fd = tp->body.singlefile.fd;
		tmmp = torrent_mmap_create(fd, off, len);
		TAILQ_INSERT_TAIL(&(tpp->mmaps), tmmp, mmaps);
		RB_INSERT(pieces, &(tp->pieces), tpp);

		return (tpp);
	} else {
		/*
		 * From: http://wiki.theory.org/BitTorrentSpecification
		 *
		 * "For the purposes of piece boundaries in the multi-file case,
		 * consider the file data as one long continuous stream,
		 * composed of the concatenation of each file in the order
		 * listed in the files list. The number of pieces and their
		 * boundaries are then determined in the same manner as the
		 * case of a single file. Pieces may overlap file boundaries."
		 *
		 * So, find which file(s) this piece should be mapped within.
		 * Or, if files are too small to make up a whole piece, which
		 * files should be mapped within the piece.
		 * This is kind of complicated.
		 */

		off = tp->piece_length * idx;
		/* last piece is irregular */
		if (idx == tp->num_pieces - 1) {
			lasttfp = TAILQ_LAST(&(tp->body.multifile.files),
			    files);
			len = tp->body.multifile.total_length
			    - ((tp->num_pieces - 1) * tp->piece_length);
		} else {
			len = tp->piece_length;
		}
		TAILQ_FOREACH(tfp, &(tp->body.multifile.files), files) {
			/* piece offset puts it outside the current
			   file, may be mapped to next file */
			if (off > tfp->file_length) {
				off -= tfp->file_length;
				continue;
			}
			/* file is too small for one piece
			   and this piece is not yet full */
			if (tfp->file_length < len
			    && tpp->len < len) {
				tmmp = torrent_mmap_create(tfp->fd, 0,
				    tfp->file_length);
				TAILQ_INSERT_TAIL(&(tpp->mmaps), tmmp, mmaps);
				tpp->len += tfp->file_length;
				len -= tfp->file_length;
				continue;
			}
			/* piece overlaps this file and the next one */
			if (off + len > tfp->file_length) {
				tmmp = torrent_mmap_create(tfp->fd, off,
				    tfp->file_length - off);
				tpp->len += tmmp->len;
				TAILQ_INSERT_TAIL(&(tpp->mmaps), tmmp, mmaps);
				nxttfp = TAILQ_NEXT(tfp, files);
				len = tfp->file_length - off;
				off++;
				if (idx == tp->num_pieces - 1) {
					tmmp = torrent_mmap_create(nxttfp->fd,
					    0, nxttfp->file_length);
				} else {
					tmmp = torrent_mmap_create(nxttfp->fd,
					    0, tp->piece_length - len);
				}
				tpp->len += tmmp->len;
				TAILQ_INSERT_TAIL(&(tpp->mmaps), tmmp, mmaps);
				off++;
				break;
			} else if (off < tfp->file_length) {
				/* piece lies within this file */
				fd = tfp->fd;
				tmmp = torrent_mmap_create(fd, off, len);
				off++;
				TAILQ_INSERT_TAIL(&(tpp->mmaps), tmmp, mmaps);
				tpp->len += len;
				break;
			}
		}
		RB_INSERT(pieces, &(tp->pieces), tpp);
		printf("piece length: %d\n", (int)tpp->len);

		return (tpp);
	}
	return (NULL);
}

void
torrent_piece_unmap(struct torrent *tp, int idx)
{
	struct torrent_piece *tpp;

	tpp = torrent_piece_find(tp, idx);

	if (tpp == NULL)
		errx(1, "torrent_piece_unmap: NULL piece");

	#if 0
	if (munmap(tpp->addr, tpp->len) < 0)
		err(1, "torrent_piece_unmap: munmap");
	#endif

}

void
torrent_data_open(struct torrent *tp)
{
	struct torrent_file *tfp;
	char buf[MAXPATHLEN];
	int fd, l;

#define OPEN_FLAGS O_RDWR|O_CREAT
	if (tp->type == SINGLEFILE) {
		if ((fd = open(tp->body.singlefile.name, OPEN_FLAGS, 0600)) < 0)
			err(1, "torrent_data_open: open `%s'",
			    tp->body.singlefile.name);
		tp->body.singlefile.fd = fd;
	} else {
		TAILQ_FOREACH(tfp, &(tp->body.multifile.files), files) {
			memset(buf, '\0', sizeof(buf));
			l = snprintf(buf, sizeof(buf), "%s/",
			    tp->body.multifile.name);
			if (l == -1 || l >= (int)sizeof(buf))
				errx(1, "torrent_data_open: path too long");
			if (strlcat(buf, tfp->path, sizeof(buf)) >= sizeof(buf))
				errx(1, "torrent_data_open: path too long");
			if ((fd = open(buf, OPEN_FLAGS, 0600)) < 0)
				err(1, "torrent_data_open: open `%s'", buf);
			tfp->fd = fd;
		}
	}
}

void
torrent_data_close(struct torrent *tp)
{
	struct torrent_file *tfp;

	if (tp->type == SINGLEFILE) {
		(void) close(tp->body.singlefile.fd);
	} else {
		TAILQ_FOREACH(tfp, &(tp->body.multifile.files), files) {
			(void) close(tfp->fd);
		}
	}
}

