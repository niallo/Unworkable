/* $Id: main.c,v 1.50 2007-12-03 21:07:31 niallo Exp $ */
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
#include <sys/time.h>
#include <sys/resource.h>

#include <sys/time.h>

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#if defined(USE_BOEHM_GC)
#include <gc.h>
#endif

#include "includes.h"

void usage(void);

extern char *optarg;
extern int  optind;

void
usage(void)
{
	fprintf(stderr, "usage: unworkable [-s] [-p port] [-t tracefile] torrent\n");
	exit(1);
}

int
main(int argc, char **argv)
{
	struct torrent *torrent;
	struct rlimit rlp;
	struct torrent_piece *tpp;
	u_int32_t i;
	int ch, j;

	#if defined(USE_BOEHM_GC)
	GC_INIT();
	#endif

	signal(SIGHUP, sighandler);
	signal(SIGABRT, sighandler);
	signal(SIGINT, sighandler);
	signal(SIGQUIT, sighandler);
	/* don't die on sigpipe */
	signal(SIGPIPE, SIG_IGN);
	#if defined(__SVR4) && defined(__sun)
	__progname = argv[0];
	#endif

	while ((ch = getopt(argc, argv, "st:p:")) != -1) {
		switch (ch) {
		case 't':
			unworkable_trace = xstrdup(optarg);
			break;
		case 'p':
			user_port = xstrdup(optarg);
			break;
		case 's':
			seed = 1;
			break;
		default:
			usage();
		}
	}

	argc -= optind;
	argv += optind;

	if (argc == 0)
		usage();


	if (getrlimit(RLIMIT_NOFILE, &rlp) == -1)
		err(1, "getrlimit");
	torrent = torrent_parse_file(argv[0]);
	torrent_pieces_create(torrent);
	/* a little extra info? torrent_print(torrent); */
	printf("checking data, this could take a while\n");
	for (i = 0; i < torrent->num_pieces; i++) {
		tpp = torrent_piece_find(torrent, i);
		if (tpp->index != i)
			errx(1, "main: something went wrong, index is %u, should be %u", tpp->index, i);
		torrent_piece_map(tpp);
		if (!torrent->isnew) {
			j = torrent_piece_checkhash(torrent, tpp);
			if (j == 0) {
				torrent->good_pieces++;
				torrent->downloaded += tpp->len;
			}
		}
		torrent_piece_unmap(tpp);
	}
	/* do we already have everything? */
	if (!seed && torrent->good_pieces == torrent->num_pieces) {
		printf("download already complete!\n");
		exit(0);
	}

	srandom(time(NULL));
	network_init();
	network_start_torrent(torrent, rlp.rlim_cur);

	exit(0);
}
