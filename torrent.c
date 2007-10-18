/* $Id: torrent.c,v 1.84 2007-10-18 01:21:05 niallo Exp $ */
/*
 * Copyright (c) 2006, 2007 Niall O'Higgins <niallo@unworkable.org>
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
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <limits.h>
#include <sha1.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "includes.h"

RB_PROTOTYPE(pieces, torrent_piece, entry, torrent_intcmp)
RB_GENERATE(pieces, torrent_piece, entry, torrent_intcmp)

/* dedicated function which computes the torrent info hash */
u_int8_t *
torrent_parse_infohash(const char *file, size_t infoend)
{
	SHA1_CTX sha;
	u_int8_t result[SHA1_DIGEST_LENGTH], *ret;
	char *p, *buf;
	BUF *b;
	size_t len;

	if ((b = buf_load(file, BUF_AUTOEXT)) == NULL)
		exit(1);

	len = buf_len(b);
	buf = buf_release(b);
	p = buf;
#define INFOLEN 6
	p = strstr(buf, "4:info");
	if (p == NULL)
		errx(1, "torrent_parse_infohash: no info key found");
	p += INFOLEN;

	SHA1Init(&sha);
	SHA1Update(&sha, p, (infoend - (p - buf)));
	SHA1Final(result, &sha);

	len = SHA1_DIGEST_LENGTH;
	ret = xmalloc(len);
	memcpy(ret, result, SHA1_DIGEST_LENGTH);
	xfree(buf);

	return (ret);
}

struct torrent *
torrent_parse_file(const char *file)
{
	struct torrent_file		*multi_file;
	struct torrent			*torrent;
	struct benc_node		*troot, *node, *lnode, *tnode;
	struct benc_node		*filenode, *childnode;
	BUF				*buf;
	int				l;
	size_t				ret;

	torrent = xmalloc(sizeof(*torrent));

	memset(torrent, 0, sizeof(*torrent));
	torrent->name = xstrdup(file);

	/* XXX need a way to free torrents and their node trees */
	torrent->broot = benc_root_create();

	if ((buf = buf_load(file, 0)) == NULL)
		err(1, "torrent_parse_file: buf_load");

	if ((troot = benc_parse_buf(buf, torrent->broot)) == NULL)
		errx(1, "torrent_parse_file: yyparse of %s", file);

	buf_free(in);
	if ((node = benc_node_find(troot, "info")) == NULL)
		errx(1, "no info data found in torrent");
	torrent->info_hash = torrent_parse_infohash(file, node->end);

	if ((node = benc_node_find(troot, "announce")) == NULL)
		errx(1, "no announce data found in torrent");

	if (node->flags & BSTRING)
		torrent->announce = node->body.string.value;
	else
		errx(1, "announce value is not a string");

	if ((node = benc_node_find(troot, "comment")) != NULL
	    && node->flags & BSTRING)
		torrent->comment = node->body.string.value;

	if ((filenode = benc_node_find(troot, "files")) == NULL) {
		torrent->type = SINGLEFILE;
		if ((node = benc_node_find(troot, "length")) == NULL)
			errx(1, "no length field");

		if (!(node->flags & BINT))
			errx(1, "length is not a number");

		torrent->body.singlefile.tfp.file_length = node->body.number;
		torrent->left = torrent->body.singlefile.tfp.file_length;

		if ((node = benc_node_find(troot, "name")) == NULL)
			errx(1, "no name field");

		if (!(node->flags & BSTRING))
			errx(1, "name is not a string");

		torrent->body.singlefile.tfp.path = node->body.string.value;

		if ((node = benc_node_find(troot, "piece length")) == NULL)
			errx(1, "no piece length field");

		if (!(node->flags & BINT))
			errx(1, "piece length is not a number");

		torrent->piece_length = node->body.number;

		if ((node = benc_node_find(troot, "pieces")) == NULL)
			errx(1, "no pieces field");

		if (!(node->flags & BSTRING))
			errx(1, "pieces is not a string");

		torrent->body.singlefile.pieces = node->body.string.value;
		torrent->num_pieces = node->body.string.len / SHA1_DIGEST_LENGTH;

		if ((node = benc_node_find(troot, "md5sum")) != NULL) {
			if (!(node->flags & BSTRING))
				errx(1, "md5sum is not a string");
			else
				torrent->body.singlefile.tfp.md5sum =
				    node->body.string.value;
		}
	} else {
		torrent->type = MULTIFILE;
		if ((node = benc_node_find(troot, "name")) == NULL)
			errx(1, "no name field");

		if (!(node->flags & BSTRING))
			errx(1, "name is not a string");

		torrent->body.multifile.name = node->body.string.value;

		if ((node = benc_node_find(troot, "piece length")) == NULL)
			errx(1, "no piece length field");

		if (!(node->flags & BINT))
			errx(1, "piece length is not a number");

		torrent->piece_length = node->body.number;

		if ((node = benc_node_find(troot, "pieces")) == NULL)
			errx(1, "no pieces field");

		if (!(node->flags & BSTRING))
			errx(1, "pieces is not a string");

		torrent->body.multifile.pieces = node->body.string.value;
		torrent->body.singlefile.pieces = node->body.string.value;
		torrent->num_pieces = node->body.string.len / SHA1_DIGEST_LENGTH;

		TAILQ_INIT(&torrent->body.multifile.files);

		/* iterate through sub-dictionaries */
		TAILQ_FOREACH(childnode, &filenode->children, benc_nodes) {
			multi_file = xmalloc(sizeof(*multi_file));

			memset(multi_file, 0, sizeof(*multi_file));
			if ((tnode = benc_node_find(childnode, "length")) == NULL)
				errx(1, "no length field");
			if (!(tnode->flags & BINT))
				errx(1, "length is not a number");
			multi_file->file_length = tnode->body.number;
			torrent->body.multifile.total_length +=
			    tnode->body.number;
			torrent->left = torrent->body.multifile.total_length;
			if ((tnode = benc_node_find(childnode, "md5sum")) != NULL
			    && tnode->flags & BSTRING)
				multi_file->md5sum = tnode->body.string.value;

			if ((tnode = benc_node_find(childnode, "path")) == NULL)
				errx(1, "no path field");
			if (!(tnode->flags & BLIST))
				errx(1, "path is not a list");

			multi_file->path = xmalloc(MAXPATHLEN);

			memset(multi_file->path, '\0', MAXPATHLEN);

			TAILQ_FOREACH(lnode, &tnode->children, benc_nodes) {
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

			TAILQ_INSERT_TAIL(&torrent->body.multifile.files,
			    multi_file, files);
		}
	}

	if ((node = benc_node_find(troot, "created by")) != NULL
	    && node->flags & BSTRING)
		torrent->created_by = node->body.string.value;

	if ((node = benc_node_find(troot, "creation date")) != NULL
	    && node->flags & BINT)
		torrent->creation_date = node->body.number;

	RB_INIT(&torrent->pieces);

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
	printf("pieces:\t\t%u\n", torrent->num_pieces);
	printf("type:\t\t");
	if (torrent->type == SINGLEFILE) {
		tfile = &torrent->body.singlefile.tfp;
		printf("single file\n");
		printf("length:\t\t%lld bytes\n", tfile->file_length);
		printf("file name:\t%s\n", tfile->path);
		printf("piece length:\t%u bytes\n",
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
		printf("piece length:\t%u bytes\n",
		    torrent->piece_length);
		printf("--files--\n");
		TAILQ_FOREACH(tfile, &torrent->body.multifile.files, files) {
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
torrent_block_write(struct torrent_piece *tpp, off_t off, u_int32_t len, void *d)
{
	struct torrent_mmap *tmmp;
	off_t cntlen = 0, cntbase = 0;
	u_char *aptr;
	u_int32_t tlen, bytesleft = len, diff = 0;

	TAILQ_FOREACH(tmmp, &tpp->mmaps, mmaps) {
		if (bytesleft < len) {
			diff = len - bytesleft;
			/* write as much as we can here and jump to next
			 * mapping if required*/
			if (bytesleft > tmmp->len) {
				memcpy(tmmp->addr, (u_char *)d + diff,
				    tmmp->len);
				bytesleft -= tmmp->len;
				continue;
			}
			/* done once we make it here */
			memcpy(tmmp->addr, (u_char *)d + diff, bytesleft);
			return;

		}
		cntlen += tmmp->len;
		if (cntlen < off) {
			cntbase += tmmp->len;
			continue;
		} else {
			aptr = tmmp->addr;
			for (; cntbase < off; cntbase++)
				aptr++;
			tlen = tmmp->len - (aptr - (u_char *)tmmp->addr);
			/* its possible that we are writing more bytes than
			 * remain in this single mapping.  in this case,
			 * we need to write the remainder to the next
			 * mapping(s)*/
			if (len > tlen) {
				trace("continuing buffer");
				memcpy(aptr, d, tlen);
				bytesleft -= tlen;
				continue;
			}
			memcpy(aptr, d, len);
		}
	}
}

/* hint will be set to 1 if the return value needs to be freed */
void *
torrent_block_read(struct torrent_piece *tpp, off_t off, u_int32_t len, int *hint)
{
	void *block;
	u_char *aptr, *bptr;
	struct torrent_mmap *tmmp;
	off_t cntlen = 0, cntbase = 0;
	u_int32_t tlen = len;

	*hint = 0;
	block = NULL;
	bptr = NULL;

	TAILQ_FOREACH(tmmp, &tpp->mmaps, mmaps) {
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
					block = xmalloc(len);
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
torrent_piece_find(struct torrent *tp, u_int32_t idx)
{
	struct torrent_piece find, *res;
	find.index = idx;
	if ((res = RB_FIND(pieces, &tp->pieces, &find)) == NULL) {
		/* piece not already mapped, try to map it */
		if ((res = torrent_piece_map(tp, idx)) == NULL)
			warnx("could not map piece at index: %u", idx);
	}

	return (res);
}

struct torrent_mmap *
torrent_mmap_create(struct torrent *tp, struct torrent_file *tfp, off_t off,
    u_int32_t len)
{
	struct torrent_mmap *tmmp;
	struct stat sb;
	char buf[MAXPATHLEN], zero = 0x00, *basedir;
	int fd = 0, l;
	trace("torrent_mmap_create:  off: %llu len: %u", off, len);
	open:
	if (tfp->fd == 0) {
		if (tp->type == SINGLEFILE)
			l = snprintf(buf, sizeof(buf), "%s", tfp->path);
		else {
			l = snprintf(buf, sizeof(buf), "%s/%s",
			    tp->body.multifile.name, tfp->path);
			if (l == -1 || l >= (int)sizeof(buf))
				errx(1, "torrent_mmap_create: path too long");
			if ((basedir = dirname(buf)) == NULL)
				err(1, "torrent_mmap_create: basename");
			if (mkpath(basedir, 0755) == -1)
				if (errno != EEXIST)
					err(1, "torrent_mmap_create \"%s\": mkdir", basedir);


		}
		if ((fd = open(buf, O_RDWR|O_CREAT, 0600)) == -1)
			err(1, "torrent_mmap_create: open `%s'", buf);

		if (flock(fd, LOCK_EX | LOCK_NB) == -1)
			err(1, "torrent_mmap_create: flock()");
		tfp->fd = fd;
	}
	if (fstat(tfp->fd, &sb) == -1)
		err(1, "torrent_mmap_create: fstat `%d'", tfp->fd);
	/* trace("size: %llu vs. len+off: %llu", sb.st_size, (off_t)len + off); */
	if (sb.st_size < ((off_t)len + off)) {
		trace("%llu offset zeroed, len %u, size: %u", off, len, sb.st_size);
		tp->isnew = 1;
		/* seek to the expected size of file ... */
		if (lseek(tfp->fd, (off_t)len + off - 1, SEEK_SET) == -1)
			err(1, "torrent_mmap_create: lseek() failure");
		/* and write a byte there */
		if (write(tfp->fd, &zero, 1) < 1)
			err(1, "torrent_mmap_create: write() failure");
		close(tfp->fd);
		tfp->fd = 0;
		goto open;
	}
	/* printf("mmap: len: %u off: %llu sbsiz: %llu fd: %d\n", len, off, sb.st_size, tfp->fd); */
	tmmp = xmalloc(sizeof(*tmmp));
	memset(tmmp, 0, sizeof(*tmmp));

	tmmp->tfp = tfp;
	tmmp->addr = mmap(0, len, PROT_READ|PROT_WRITE, MAP_SHARED, tfp->fd, off);
	if (tmmp->addr == MAP_FAILED)
		err(1, "torrent_mmap_create: mmap");
	if (madvise(tmmp->addr, len, MADV_SEQUENTIAL|MADV_WILLNEED) == -1)
		err(1, "torrent_mmap_create: madvise");
	tmmp->len = len;

	tfp->refs++;
	return (tmmp);
}

struct torrent_piece *
torrent_piece_map(struct torrent *tp, u_int32_t idx)
{
	struct torrent_piece *tpp;
	struct torrent_file  *nxttfp, *tfp, *lasttfp;
	struct torrent_mmap  *tmmp;
	u_int32_t len;
	off_t off;

	tpp = xmalloc(sizeof(*tpp));

	memset(tpp, 0, sizeof(*tpp));
	tpp->index = idx;
	TAILQ_INIT(&tpp->mmaps);

	off = tp->piece_length * (off_t)idx;
	/* nice and simple */
	if (tp->type == SINGLEFILE) {
		/* last piece is irregular */
		tfp = &tp->body.singlefile.tfp;
		if (idx == tp->num_pieces - 1) {
			len = tfp->file_length - off;
		} else {
			len = tp->piece_length;
		}
		tpp->len = len;
		tmmp = torrent_mmap_create(tp, tfp, off, len);
		TAILQ_INSERT_TAIL(&tpp->mmaps, tmmp, mmaps);
		RB_INSERT(pieces, &tp->pieces, tpp);

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

		/* last piece is irregular */
		if (idx == tp->num_pieces - 1) {
			lasttfp = TAILQ_LAST(&tp->body.multifile.files,
			    files);
			len = tp->body.multifile.total_length
			    - ((tp->num_pieces - 1) * tp->piece_length);
		} else {
			len = tp->piece_length;
		}
		TAILQ_FOREACH(tfp, &tp->body.multifile.files, files) {
			/* piece offset puts it outside the current
			   file, may be mapped to next file */
			if (off > tfp->file_length) {
				off -= tfp->file_length;
				continue;
			}
			/* file is too small for one piece
			   and this piece is not yet full */
			if (tfp->file_length < (off_t)len
			    && tpp->len < len) {
				tmmp = torrent_mmap_create(tp, tfp, off,
				    tfp->file_length - off);
				TAILQ_INSERT_TAIL(&tpp->mmaps, tmmp, mmaps);
				tpp->len += tfp->file_length - off;
				len -= tfp->file_length - off;
				off = 0;
				continue;
			}
			if (off + (off_t)len > tfp->file_length) {
				if (tfp->file_length == off) {
					off = 0;
					continue;
				}
				tmmp = torrent_mmap_create(tp, tfp, off,
				    tfp->file_length - off);
				tpp->len += tmmp->len;
				TAILQ_INSERT_TAIL(&tpp->mmaps, tmmp, mmaps);
				nxttfp = TAILQ_NEXT(tfp, files);
				len -= tmmp->len;
				off++;
				if (nxttfp->file_length < (off_t)len) {
					tmmp = torrent_mmap_create(tp, nxttfp,
					    0, nxttfp->file_length);
					tpp->len += tmmp->len;
					TAILQ_INSERT_TAIL(&tpp->mmaps, tmmp,
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
				TAILQ_INSERT_TAIL(&tpp->mmaps, tmmp, mmaps);
				off++;
				break;
			} else if (off < tfp->file_length) {
				/* piece lies within this file */
				tmmp = torrent_mmap_create(tp, tfp, off, len);
				off++;
				TAILQ_INSERT_TAIL(&tpp->mmaps, tmmp, mmaps);
				tpp->len += len;
				break;
			}
		}
		RB_INSERT(pieces, &tp->pieces, tpp);

		return (tpp);
	}
	return (NULL);
}

int
torrent_piece_checkhash(struct torrent *tp, struct torrent_piece *tpp)
{
	SHA1_CTX sha;
	u_int8_t *d, *s, results[SHA1_DIGEST_LENGTH];
	int hint, res;

	d = torrent_block_read(tpp, 0, tpp->len, &hint);
	if (d == NULL)
		return (-1);

	SHA1Init(&sha);
	SHA1Update(&sha, d, tpp->len);
	SHA1Final(results, &sha);

	if (hint == 1)
		xfree(d);
	if (tp->type == MULTIFILE) {
		s = tp->body.multifile.pieces
		    + (SHA1_DIGEST_LENGTH * tpp->index);
	} else {
		s = tp->body.singlefile.pieces
		    + (SHA1_DIGEST_LENGTH * tpp->index);
	}
	res = memcmp(results, s, SHA1_DIGEST_LENGTH);
	if (res == 0)
		tpp->flags |= TORRENT_PIECE_CKSUMOK;


	return (res);
}

void
torrent_piece_sync(struct torrent *tp, u_int32_t idx)
{
	struct torrent_piece *tpp;
	struct torrent_mmap *tmmp;

	tpp = torrent_piece_find(tp, idx);

	if (tpp == NULL)
		errx(1, "torrent_piece_sync: NULL piece");

	TAILQ_FOREACH(tmmp, &tpp->mmaps, mmaps)
		if (msync(tmmp->addr, tmmp->len, MS_SYNC) == -1)
			err(1, "torrent_piece_sync: msync");

}

void
torrent_piece_unmap(struct torrent *tp, u_int32_t idx)
{
	struct torrent_piece *tpp;
	struct torrent_mmap *tmmp;

	tpp = torrent_piece_find(tp, idx);

	if (tpp == NULL)
		errx(1, "torrent_piece_unmap: NULL piece");

	TAILQ_FOREACH(tmmp, &tpp->mmaps, mmaps) {
		tmmp->tfp->refs--;
		if (tmmp->tfp->refs == 0) {
			flock(tmmp->tfp->fd, LOCK_UN);
			(void)  close(tmmp->tfp->fd);
			tmmp->tfp->fd = 0;
		}
		if (msync(tmmp->addr, tmmp->len, MS_SYNC) == -1)
			err(1, "torrent_piece_unmape: msync");
		if (munmap(tmmp->addr, tmmp->len) == -1)
			err(1, "torrent_piece_unmap: munmap");
	}
	while ((tmmp = TAILQ_FIRST(&tpp->mmaps))) {
		TAILQ_REMOVE(&tpp->mmaps, tmmp, mmaps);
		xfree(tmmp);
	}

	RB_REMOVE(pieces, &tp->pieces, tpp);
	xfree(tpp);
}

u_int8_t *
torrent_bitfield_get(struct torrent *tp)
{
	struct torrent_piece find, *res;
	u_int32_t i, len;
	u_int8_t *bitfield;

	len = (tp->num_pieces + 7) / 8;
	bitfield = xmalloc(len);
	memset(bitfield, 0, len);
	for (i = 0; i < tp->num_pieces - 1; i++) {
		find.index = i;
		if ((res = RB_FIND(pieces, &tp->pieces, &find)) != NULL
		    && (res->flags & TORRENT_PIECE_CKSUMOK))
			setbit(bitfield, i);
	}
	return (bitfield);
}

int
torrent_empty(struct torrent *tp)
{
	struct torrent_piece *tpp;

	RB_FOREACH(tpp, pieces, &tp->pieces) {
		if (tpp->flags & TORRENT_PIECE_CKSUMOK)
			return (1);
	}
	return (0);
}

