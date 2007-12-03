/* $Id: trace.c,v 1.4 2007-12-03 21:07:31 niallo Exp $ */
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

#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>

#include "includes.h"

char *unworkable_trace = NULL;
FILE *out = NULL;

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
	if (unworkable_trace == NULL)
		return;

	if (out == NULL)
		if ((out = fopen(unworkable_trace, "w")) == NULL)
			err(1, "vtrace: fopen failure");


	(void)fputs("-> ", out);
	(void)vfprintf(out, fmt, vap);
	fputc('\n', out);
	fflush(out);
}

void
sighandler(int sig)
{
	if (out != NULL)
		fclose(out);
	exit(1);
}
