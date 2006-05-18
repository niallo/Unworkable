/* $Id: torrent.c,v 1.36 2006-05-18 18:03:34 niallo Exp $ */
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
#include <sys/stat.h>

#include <err.h>
#include <fcntl.h>
#include <limits.h>
#include <sha1.h>
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

/* dedicated function which computes the torrent info hash */
u_int8_t *
torrent_parse_infohash(const char *file)
{
	int fd;
	SHA1_CTX sha;
	u_int8_t result[SHA1_DIGEST_LENGTH], *ret;
	struct stat sb;
	size_t len;
	ssize_t n;
	char *buf, *p;

	if ((fd = open(file, O_RDONLY, 0)) == -1)
		err(1, "torrent_parse_infohash: open `%s'", file);
	
	if (fstat(fd, &sb) == -1)
		err(1, "torrent_parse_infohash: fstat");

	len = sb.st_size;

	if ((buf = malloc(len+1)) == NULL)
		err(1, "torrent_parse_infohash: malloc");
	
	n = read(fd, buf, len);
	if (n == -1)
		err(1, "torrent_parse_infohash: read");
	(void) close(fd);

	buf[len] = '\0';
	p = strstr(buf, "4:info");
	if (p == NULL)
		errx(1, "torrent_parse_infohash: no info key found");
	p += 6;

	SHA1Init(&sha);
	SHA1Update(&sha, p, (len - (p - buf)) - 1);
	SHA1Final(result, &sha);

	if ((ret = malloc(SHA1_DIGEST_LENGTH)) == NULL)
		err(1, "torrent_parse_infohash: malloc");
	memcpy(ret, result, SHA1_DIGEST_LENGTH);
	free(buf);

	return (ret);
}

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
	torrent->info_hash = torrent_parse_infohash(file);

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

		torrent->body.singlefile.tfp.file_length = node->body.number;

		if ((node = benc_node_find(root, "name")) == NULL)
			errx(1, "no name field");

		if (!(node->flags & BSTRING))
			errx(1, "name is not a string");

		torrent->body.singlefile.tfp.path = node->body.string.value;

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
				torrent->body.singlefile.tfp.md5sum =
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
		torrent->num_pieces = node->body.string.len / SHA1_DIGEST_LENGTH;

		TAILQ_INIT(&(torrent->body.multifile.files));

		/* iterate through sub-dictionaries */
		TAILQ_FOREACH(childnode, &(filenode->children), benc_nodes) {
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

			TAILQ_FOREACH(lnode, &(tnode->children), benc_nodes) {
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
	int i;

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
	printf("info hash:\t0x");
	for (i = 0; i < SHA1_DIGEST_LENGTH; i++)
		printf("%02x", torrent->info_hash[i]);
	putchar('\n');
	printf("pieces:\t\t%d\n", torrent->num_pieces);
	printf("type:\t\t");
	if (torrent->type == SINGLEFILE) {
		tfile = &torrent->body.singlefile.tfp;
		printf("single file\n");
		printf("length:\t\t%lld bytes\n", tfile->file_length);
		printf("file name:\t%s\n", tfile->path);
		printf("piece length:\t%d bytes\n",
		    torrent->piece_length);
		printf("md5sum:\t\t");
		if (tfile->md5sum == NULL)
			printf("NONE\n");
		else
			printf("%s\n", tfile->md5sum);
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
torrent_block_write(struct torrent_piece *tpp, size_t off, size_t len, void *d)
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
torrent_block_read(struct torrent_piece *tpp, size_t off, size_t len, int *hint)
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
				if (*hint == 0) {
					return (aptr);
                }

				memcpy(bptr, aptr, tlen);
				return (block);
			}
		}
	}
	if (*hint == 1) {
		return (block);
    }

	return (NULL);
}

struct torrent_piece *
torrent_piece_find(struct torrent *tp, int idx)
{
	struct torrent_piece find, *res;
	find.index = idx;
	res = RB_FIND(pieces, &(tp->pieces), &find);
	if (res == NULL)
		errx(1, "torrent_piece_find: no such piece `%d'", idx);
	return (res);
}

struct torrent_mmap *
torrent_mmap_create(struct torrent *tp, struct torrent_file *tfp, size_t off,
    size_t len)
{
	struct torrent_mmap *tmmp;
	struct stat sb;
	char buf[MAXPATHLEN];
	int fd = 0, l;
	
#define OPEN_FLAGS O_RDONLY
	if (tfp->fd == 0) {
		if (tp->type == SINGLEFILE)
			l = snprintf(buf, sizeof(buf), "%s", tfp->path);
		else
			l = snprintf(buf, sizeof(buf), "%s/%s",
			    tp->body.multifile.name, tfp->path);
		if (l == -1 || l >= (int)sizeof(buf))
			errx(1, "torrent_data_open: path too long");
		if ((fd = open(buf, OPEN_FLAGS, 0600)) == -1)
			err(1, "torrent_data_open: open `%s'", buf);
		tfp->fd = fd;
	}
	//printf("mmap: len: %d off: %d fd: %d\n", (int)len, (int)off, tfp->fd);
	if (fstat(tfp->fd, &sb) == -1)
		err(1, "torrent_mmap_create: fstat `%d'", tfp->fd);
	if (sb.st_size < (len + off))
		errx(1, "torrent_mmap_create: insufficient data in file");
#define MMAP_FLAGS PROT_READ|PROT_WRITE
	if ((tmmp = malloc(sizeof(*tmmp))) == NULL)
		err(1, "torrent_mmap_create: malloc");
	memset(tmmp, 0, sizeof(*tmmp));
	
	tmmp->addr = mmap(0, len, MMAP_FLAGS, 0, tfp->fd, off);
	if (tmmp->addr == MAP_FAILED)
		err(1, "torrent_mmap_create: mmap");
	tmmp->len = len;

	tmmp->tfp = tfp;
	tfp->refs++;
	return (tmmp);
}

struct torrent_piece *
torrent_piece_map(struct torrent *tp, int idx)
{
	struct torrent_piece *tpp;
	struct torrent_file  *nxttfp, *tfp, *lasttfp;
	struct torrent_mmap  *tmmp;
	size_t len, off;

	if ((tpp = malloc(sizeof(*tpp))) == NULL)
		err(1, "torrent_piece_map: malloc");
	
	memset(tpp, 0, sizeof(*tpp));
	tpp->index = idx;
	TAILQ_INIT(&(tpp->mmaps));

	/* nice and simple */
	if (tp->type == SINGLEFILE) {
		off = tp->piece_length * idx;
		/* last piece is irregular */
		tfp = &tp->body.singlefile.tfp;
		if (idx == tp->num_pieces - 1) {
			len = tfp->file_length - off;
		} else {
			len = tp->piece_length;
		}
		tpp->len = len;
		tmmp = torrent_mmap_create(tp, tfp, off, len);
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
			if (off > (size_t)tfp->file_length) {
				off -= tfp->file_length;
				continue;
			}
			/* file is too small for one piece
			   and this piece is not yet full */
			if ((size_t)tfp->file_length < len
			    && tpp->len < len) {
				tmmp = torrent_mmap_create(tp, tfp, off,
				    tfp->file_length - off);
				TAILQ_INSERT_TAIL(&(tpp->mmaps), tmmp, mmaps);
				tpp->len += tfp->file_length - off;
				len -= tfp->file_length - off;
				off = 0;
				continue;
			}
			if (off + len > (size_t)tfp->file_length) {
				if (tfp->file_length == off) {
					off = 0;
					continue;
				}
				tmmp = torrent_mmap_create(tp, tfp, off,
				    tfp->file_length - off);
				tpp->len += tmmp->len;
				TAILQ_INSERT_TAIL(&(tpp->mmaps), tmmp, mmaps);
				nxttfp = TAILQ_NEXT(tfp, files);
				len -= tmmp->len;
				off++;
				#if 0
				if (idx == tp->num_pieces - 1) {
					tmmp = torrent_mmap_create(tp, nxttfp,
					    0, nxttfp->file_length);
				} else if (nxttfp->file_length < len) {
				#endif
				if (nxttfp->file_length < len) {
					tmmp = torrent_mmap_create(tp, nxttfp,
					    0, nxttfp->file_length);
					tpp->len += tmmp->len;
					TAILQ_INSERT_TAIL(&(tpp->mmaps), tmmp,
					    mmaps);
					off++;
					len -= tmmp->len;
					tfp = nxttfp;
					off = 0;
					continue;
				} else {
					tmmp = torrent_mmap_create(tp, nxttfp,
					    0, len);
				}
				tpp->len += tmmp->len;
				TAILQ_INSERT_TAIL(&(tpp->mmaps), tmmp, mmaps);
				off++;
				break;
			} else if (off < (size_t)tfp->file_length) {
				/* piece lies within this file */
				tmmp = torrent_mmap_create(tp, tfp, off, len);
				off++;
				TAILQ_INSERT_TAIL(&(tpp->mmaps), tmmp, mmaps);
				tpp->len += len;
				break;
			}
		}
		RB_INSERT(pieces, &(tp->pieces), tpp);

		return (tpp);
	}
	return (NULL);
}

int
torrent_piece_checkhash(struct torrent *tp, struct torrent_piece *tpp)
{
	SHA1_CTX sha;
	u_int8_t *d, *s, results[SHA1_DIGEST_LENGTH];
	int hint, i;

	d = torrent_block_read(tpp, 0, tpp->len, &hint);
	if (d == NULL)
		return (-1);

	SHA1Init(&sha);
	SHA1Update(&sha, d, tpp->len);
	SHA1Final(results, &sha);

	if (hint == 1)
		free(d);
	if (tp->type == MULTIFILE) {
		s = tp->body.multifile.pieces
		    + (SHA1_DIGEST_LENGTH * tpp->index);
	} else {
		s = tp->body.singlefile.pieces
		    + (SHA1_DIGEST_LENGTH * tpp->index);
	}

	#if 0
	printf("actual hash: 0x");
	for (i = 0; i < SHA1_DIGEST_LENGTH; i++)
		printf("%02x", s[i]);
	printf("\n");
	printf("genera hash: 0x");
	for (i = 0; i < SHA1_DIGEST_LENGTH; i++)
		printf("%02x", results[i]);
	printf("\n");
	#endif
	
	return (memcmp(results, s, SHA1_DIGEST_LENGTH));
}

void
torrent_piece_unmap(struct torrent *tp, int idx)
{
	struct torrent_piece *tpp;
	struct torrent_mmap *tmmp;

	tpp = torrent_piece_find(tp, idx);

	if (tpp == NULL)
		errx(1, "torrent_piece_unmap: NULL piece");

	TAILQ_FOREACH(tmmp, &(tpp->mmaps), mmaps) {
		if (munmap(tmmp->addr, tmmp->len) == -1)
			err(1, "torrent_piece_unmap: munmap");
		tmmp->tfp->refs--;
		if (tmmp->tfp->refs == 0) {
			(void) close(tmmp->tfp->fd);
			tmmp->tfp->fd = 0;
		}
	}
	while ((tmmp = TAILQ_FIRST(&tpp->mmaps))) {
		TAILQ_REMOVE(&tpp->mmaps, tmmp, mmaps);
		free(tmmp);
	}

	RB_REMOVE(pieces, &tp->pieces, tpp);
	free(tpp);
}

void
torrent_data_open(struct torrent *tp)
{
	#if 0
	struct torrent_file *tfp;
	char buf[MAXPATHLEN];
	int fd, l;

	if (tp->type == SINGLEFILE) {
		fd = open(tp->body.singlefile.name, OPEN_FLAGS, 0600);
		if (fd == -1)
			err(1, "torrent_data_open: open `%s'",
			    tp->body.singlefile.name);
		tp->body.singlefile.tfp.fd = fd;
	} else {
		TAILQ_FOREACH(tfp, &(tp->body.multifile.files), files) {
			memset(buf, '\0', sizeof(buf));
			l = snprintf(buf, sizeof(buf), "%s/%s",
			    tp->body.multifile.name, tfp->path);
			if (l == -1 || l >= (int)sizeof(buf))
				errx(1, "torrent_data_open: path too long");
			if ((fd = open(buf, OPEN_FLAGS, 0600)) == -1)
				err(1, "torrent_data_open: open `%s'", buf);
			tfp->fd = fd;
		}
	}
	#endif
}

void
torrent_data_close(struct torrent *tp)
{
	#if 0
	struct torrent_file *tfp;

	if (tp->type == SINGLEFILE) {
		(void) close(tp->body.singlefile.fd);
	} else {
		TAILQ_FOREACH(tfp, &(tp->body.multifile.files), files) {
			(void) close(tfp->fd);
		}
	}
	#endif
}

