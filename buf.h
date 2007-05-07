/*$Id#*/
/*
 * Copyright (c) 2003 Jean-Francois Brousseau <jfb@openbsd.org>
 * Copyright (c) 2006, 2007 Niall O'Higgins <niallo@unworkable.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
 * THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL  DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#ifndef BUF_H
#define BUF_H

/* flags */
#define BUF_AUTOEXT	1	/* autoextend on append */

typedef struct buf BUF;

BUF		*buf_alloc(size_t, u_int);
BUF		*buf_load(const char *, u_int);
void		 buf_free(BUF *);
void		*buf_release(BUF *);
int		 buf_getc(BUF *);
void		 buf_empty(BUF *);
ssize_t		 buf_set(BUF *, const void *, size_t, size_t);
ssize_t		 buf_append(BUF *, const void *, size_t);
ssize_t		 buf_fappend(BUF *, const char *, ...)
		     __attribute__((format(printf, 2, 3)));
void		 buf_putc(BUF *, int);
size_t		 buf_len(BUF *);
int		 buf_write_fd(BUF *, int);
int		 buf_write(BUF *, const char *, mode_t);
void		 buf_write_stmp(BUF *, char *, mode_t);
void		 buf_ungetc(BUF *);

#define buf_get(b)	buf_peek(b, 0)

#endif	/* BUF_H */
