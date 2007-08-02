/* $Id: util.c,v 1.1 2007-08-02 23:18:45 niallo Exp $ */
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
#include <sys/stat.h>

#include <errno.h>
#include <libgen.h>
#include <stdio.h>
#include <string.h>

#include "includes.h"

int
mkpath(const char *s, mode_t mode){
	char *q, *path = NULL, *up = NULL;
	int rv;

	rv = -1;
	if (strcmp(s, ".") == 0)
		return 0;

	path = xstrdup(s);
	if ((q = dirname(s)) == NULL)
		goto out;
	up = xstrdup(q);

	if ((mkpath(up, mode) == -1) && (errno != EEXIST))
		goto out;
	
	if ((mkdir(path, mode) == -1) && (errno != EEXIST))
		rv = -1;
	else
		rv = 0;

out:	xfree(up);
	xfree(path);
	return (rv);
}

void
print_len(void *ptr, size_t len)
{
	char *out, *p;
	size_t i;

	out = xmalloc(len + 3);
	memset(out, '\0', len + 3);
	p = (char *)ptr;
	
	for (i = 0; i < len; i++) {
		snprintf(out, len+3, "%s%c", out, *p);
		p++;
	}
	printf("print_len: %s\n", out);
}
