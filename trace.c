/* $Id: trace.c,v 1.7 2008-09-19 23:30:33 niallo Exp $ */
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

#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

#include "includes.h"

char *unworkable_trace = NULL;
FILE *out = NULL;
struct torrent *mytorrent = NULL;

static void vtrace(const char *, va_list);

void
trace(const char *fmt, ...)
{
	va_list vap;

	va_start(vap, fmt);
	vtrace(fmt, vap);
	va_end(vap);
}

static void
vtrace(const char *fmt, va_list vap)
{
	time_t t;
	char tbuf[32];

	if (unworkable_trace == NULL)
		return;

	if (out == NULL)
		if ((out = fopen(unworkable_trace, "w")) == NULL)
			err(1, "vtrace: fopen failure");

	t = time(NULL);

	strftime(tbuf, sizeof(tbuf), "[%Y-%m-%d %T] ", gmtime(&t));
	(void)fputs(tbuf, out);
	(void)fputs("-> ", out);
	(void)vfprintf(out, fmt, vap);
	fputc('\n', out);
	fflush(out);
}

void
sighandler(int sig)
{
	if (mytorrent != NULL)
		torrent_fastresume_dump(mytorrent);
	if (out != NULL)
		fclose(out);

	exit(1);
}
