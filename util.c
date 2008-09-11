/* $Id: util.c,v 1.6 2008-09-11 00:14:18 niallo Exp $ */
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
#include <sys/stat.h>

#include <errno.h>
#include <libgen.h>
#include <stdio.h>
#include <string.h>

#include "includes.h"

int
mkpath(const char *s, mode_t mode){
	char *q, *r = NULL, *path = NULL, *up = NULL;
	int rv;

	rv = -1;
	if (strcmp(s, ".") == 0)
		return 0;

	path = xstrdup(s);
	q = xstrdup(s);
	if ((r = dirname(q)) == NULL)
		goto out;
	up = xstrdup(r);

	if ((mkpath(up, mode) == -1) && (errno != EEXIST))
		goto out;

	if ((mkdir(path, mode) == -1) && (errno != EEXIST))
		rv = -1;
	else
		rv = 0;

out:
	if (up != NULL)
		xfree(up);
	xfree(q);
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

/* $OpenBSD: progressmeter.c,v 1.5 2007/12/03 21:07:31 niallo Exp $ */
/*
 * Copyright (c) 2006 Damien Miller. All rights reserved.
 * Copyright (c) 2005 Anil Madhavapeddy. All rights reserved.
 * Copyright (c) 1995,1999 Theo de Raadt.  All rights reserved.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * ensure all of data on socket comes through. f==read || f==vwrite
 */
size_t
atomicio(ssize_t (*f) (int, void *, size_t), int fd, void *_s, size_t n)
{
	char *s = _s;
	size_t pos = 0;
	ssize_t res;

	while (n > pos) {
		res = (f) (fd, s + pos, n - pos);
		switch (res) {
		case -1:
			if (errno == EINTR || errno == EAGAIN)
				continue;
			return 0;
		case 0:
			errno = EPIPE;
			return pos;
		default:
			pos += (size_t)res;
		}
	}
	return (pos);
}

void
util_setbit(u_int8_t *bitfield, u_int32_t bit)
{
	u_int32_t byte;

	/* which byte is this bit in (divide by 8) */
	byte = bit >> 3u;

	bitfield[byte] |= 1 << (7u - (bit & 7u));

}

int
util_getbit(u_int8_t *bitfield, u_int32_t bit)
{
	u_int32_t byte;

	/* which byte is this bit in (divide by 8) */
	byte = bit >> 3u;

	return (bitfield[byte] & (1u << (7u - (bit & 7u))));
}
