/* $Id: main.c,v 1.7 2006-05-17 22:32:26 niallo Exp $ */
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
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "bencode.h"
#include "torrent.h"

void usage(void);

extern char *optarg;
extern int  optind;

void
usage(void)
{
	fprintf(stderr, "unworkable: [-i] file\n");
	exit(1);
}

int
main(int argc, char **argv)
{
	int ch, fd, i, iflag, hint;
	struct torrent *torrent;
	struct torrent_piece *tpp;
	char *p;

	root = benc_node_create();
	root->flags = BLIST;

	while ((ch = getopt(argc, argv, "i")) != -1) {
		switch (ch) {
		case 'i':
			iflag = 1;
			break;
		default:
			usage();
		}
	}

	argc -= optind;
	argv += optind;

	if (argc == 0)
		usage();

	torrent = torrent_parse_file(argv[0]);
	torrent_print(torrent);
	torrent_data_open(torrent);

	if ((fd = open("/tmp/out", O_WRONLY|O_CREAT|O_TRUNC, 0600)) == -1)
		err(1, "open");
	for (i = 0; i < torrent->num_pieces; i++) {
		torrent_piece_map(torrent, i);
		tpp = torrent_piece_find(torrent, i);
		if (tpp == NULL)
			printf("bad!\n");
		p = (char *)torrent_block_read(tpp, 0, tpp->len, &hint);
		//printf("%d len is %d\n", i, (int)tpp->len);
		write(fd, p, tpp->len);
		if (hint == 1)
			free(p);
	}
	close(fd);

	tpp = torrent_piece_find(torrent, 0);
	i = torrent_piece_checkhash(torrent, tpp);
	if (i != 0)
		printf("hash mismatch\n");
	else
		printf("hash match\n");

	exit(0);

}
