/* $Id: xmalloc.c,v 1.5 2006-10-17 20:54:54 niallo Exp $ */
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

#include <err.h>
#include <stdlib.h>
#include <string.h>

#include "xmalloc.h"

#define	OOM_MSG	"Out of memory"

#if !defined (USE_BOEHM_GC)
void *
xmalloc(size_t size)
{
	void *ptr;

	if ((ptr = malloc(size)) == NULL)
		err(1, OOM_MSG);
	return (ptr);
}

void *
xrealloc(void *ptr, size_t size)
{
	void *nptr;

	if ((nptr = realloc(ptr, size)) == NULL)
		err(1, OOM_MSG);
	return (nptr);
}

void *
xcalloc(size_t nmemb, size_t size)
{
	void *ptr;

	ptr = calloc(nmemb, size);
	if (ptr == NULL)
		err(1, OOM_MSG);
	return ptr;
}

void
xfree(void *ptr)
{
	if (ptr == NULL)
		errx(1, "xfree: NULL pointer given as argument");
	free(ptr);
}

char *
xstrdup(const char *str)
{
	size_t len;
	char *cp;

	len = strlen(str) + 1;
	cp = xmalloc(len);
	if (strlcpy(cp, str, len) >= len)
		errx(1, "xstrdup: string truncated");
	return cp;
}

#else

/* Special for compiling with Boehm's GC. See Makefile and xmalloc.h  */
char *
gc_strdup(const char *x)
{
	char *y = malloc(strlen(x) + 1);
	/* XXX ja ja, should check return value... */
	strlcpy(y, x, strlen(x) + 1);
	return (y);
}

#endif /* WITH_BOEHM_GC */
