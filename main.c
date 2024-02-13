/* $Id: main.c,v 1.58 2008-09-27 20:35:43 niallo Exp $ */
/*
 * Copyright (c) 2006, 2007, 2008 Niall O'Higgins <niallo@p2presearch.com>
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
#include <sys/ioctl.h>
#include <sys/uio.h>
#include <sys/termios.h>

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

#define DEFAULT_WINSIZE 80
#define MAX_WINSIZE 512
#define MESSAGE "hash check"
#define METER "|/-\\"

static void sighandler(int, short, void *);
void usage(void);

extern char *optarg;
extern int  optind;

void
usage(void)
{
	fprintf(stderr, "usage: unworkable [-s] [-g port] [-p port] [-t tracefile] torrent\n");
	exit(1);
}

void
sighandler(int sig, short event, void *arg)
{
	switch (sig) {
	case SIGTERM:
	case SIGINT:
		(void)event_loopexit(NULL);
        terminate_handler();
	}
}

int
main(int argc, char **argv)
{
	struct rlimit rlp;
	struct torrent *torrent;
	struct torrent_piece *tpp;
	struct winsize winsize;
	struct event	 ev_sigint;
	struct event	 ev_sigterm;
	u_int32_t i;
	int ch, j, win_size, percent;
	char blurb[MAX_WINSIZE+1];

	#if defined(USE_BOEHM_GC)
	GC_INIT();
	#endif

	network_init();
	signal_set(&ev_sigint, SIGINT, sighandler, NULL);
	signal_set(&ev_sigterm, SIGTERM, sighandler, NULL);
	signal_add(&ev_sigint, NULL);
	signal_add(&ev_sigterm, NULL);
	/* don't die on sigpipe */
	signal(SIGPIPE, SIG_IGN);
	#if defined(__SVR4) && defined(__sun)
	__progname = argv[0];
	#endif

	while ((ch = getopt(argc, argv, "sg:t:p:")) != -1) {
		switch (ch) {
		case 't':
			unworkable_trace = xstrdup(optarg);
			break;
		case 'g':
			gui_port = xstrdup(optarg);
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

	if (argc != 1)
		usage();


	if (getrlimit(RLIMIT_NOFILE, &rlp) == -1)
		err(1, "getrlimit");

	if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &winsize) != -1 &&
	    winsize.ws_col != 0) {
		if (winsize.ws_col > MAX_WINSIZE)
			win_size = MAX_WINSIZE;
		else
			win_size = winsize.ws_col;
	} else
		win_size = DEFAULT_WINSIZE;
	win_size += 1;					/* trailing \0 */
	torrent = torrent_parse_file(argv[0]);
	mytorrent = torrent;
	torrent_pieces_create(torrent);
	/* a little extra info? torrent_print(torrent); */
	memset(&blurb, '\0', sizeof(blurb));
	snprintf(blurb, sizeof(blurb), "%s ", MESSAGE);
	atomicio(vwrite, STDOUT_FILENO, blurb, win_size - 1);
	if (torrent_fastresume_load(torrent) == -1) {
		for (i = 0; i < torrent->num_pieces; i++) {
			tpp = torrent_piece_find(torrent, i);
			if (tpp->index != i)
				errx(1,
				     "main: something went wrong, index is %u, should be %u", tpp->index, i);
			torrent_piece_map(tpp);
			if (!torrent->isnew) {
				j = torrent_piece_checkhash(torrent, tpp);
				if (j == 0) {
					torrent->good_pieces++;
					torrent->downloaded += tpp->len;
				}
			}
			torrent_piece_unmap(tpp);
			percent = (float)i / torrent->num_pieces * 100;
			snprintf(blurb, sizeof(blurb), "\r%s [%3d%%] %c",
			    MESSAGE, percent, METER[i % 3]);
			atomicio(vwrite, STDOUT_FILENO, blurb, win_size - 1);
		}
	}
	/* do we already have everything? */
	if (!seed && torrent->good_pieces == torrent->num_pieces) {
		printf("\rdownload already complete!\n");
		exit(0);
	}

	srandom(time(NULL));
	network_start_torrent(torrent, rlp.rlim_cur);

	exit(0);
}
