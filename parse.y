/* $Id: parse.y,v 1.5 2006-04-26 13:43:23 niallo Exp $ */
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
%{

#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int yyerror(const char *, ...);
int yyparse(void);
int yylex(void);

static FILE	*fin     = NULL;
static u_long	bstrlen  = 0;
static int	bstrflag = 0;
static int	bdone    = 0;

%}

%union {
	int number;
	char *string;
}

%token COLON
%token END
%token INT_START DICT_START LIST_START
%token <string> STRING
%type  <string> bstring
%type  <number> number
%type  <string> bdict_entries
%type  <string> blist_entries

%%


bencode		: /* empty */
		| bencode bstring
		| bencode bint
		| bencode bdict
		| bencode blist
		;

bstrflag	: { bstrflag = 1; }
		;

bstring		: bstrflag number COLON STRING			{
			printf("string %s len %d\n", $4, $2);
		}
		;

bdict_entries	: bdict_entries STRING COLON STRING		{
			printf("key: %s val: %s\n", $2, $4);
		}
		;

bdict		: DICT_START number COLON bdict_entries END	{

			printf("bdict string %s len %d\n", $4, $2);
		}
		;


blist		: LIST_START number COLON blist_entries END	{
			printf("string %s len %d\n", $4, $2);
		}
		;

blist_entries	: blist_entries STRING COLON			{
			printf("entry: %s\n", $2);
		}
		;

bint		: INT_START number END				{
			printf("number: %d\n", $2);
		}
		;


number		: STRING					{
			long lval;
			const char *errstr;
			lval = strtonum($1, LONG_MIN, LONG_MAX, &errstr);
			if (errstr) {
				yyerror("%s is %s", $1, errstr);
				free($1);
				YYERROR;
			} else {
				$$ = lval;
				if (bstrflag == 1)
					bstrlen = lval;
			}
			free($1);
		}
		;

%%

int
yylex(void)
{
	char	*buf, *p;
	int	c, i = 0, token = 0;
	size_t	buflen = 128;

	if ((buf = malloc(buflen)) == NULL)
		err(1, "yylex: malloc");

	p = buf;
	memset(buf, '\0', buflen);

	for (;;) {
		if (i == buflen) {
			size_t p_offset = p - buf;
			buflen += 20480;
			if ((buf = realloc(buf, buflen)) == NULL)
				err(1, "yylex: realloc");
			/* ensure pointers are not invalidated after realloc */
			p = buf + p_offset;
			printf("b\n");
			/* NUL-fill the new memory */
			memset(p, '\0', 20480);
		}

		c = fgetc(fin);
		/* assume STRING if we hit EOF */
		if (c == EOF) {
			yyval.string = buf;
			return (STRING);
		}
		if (c == '\n') {
			free(buf);
			return (0);
		}

		switch (c) {
		case ':':
			if (bdone == 0) {
				yylval.string = buf;
				bdone = 1;
				(void)ungetc(c, fin);
				return (STRING);
			} else {
				bdone = 0;
				free(buf);
				return (COLON);
			}
			break;
		case 'e':
			if (bdone == 0) {
				yylval.string = buf;
				bdone = 1;
				(void)ungetc(c, fin);
				return (STRING);
			} else {
				bdone = 0;
				free(buf);
				return (END);
			}
			break;
		case 'i':
			free(buf);
			return (INT_START);
			break;
		case 'd':
			free(buf);
			return (DICT_START);
			break;
		case 'l':
			free(buf);
			return (LIST_START);
			break;
		default:
			*p = c;
			i++;
			yylval.string = buf;
			token = STRING;
			break;
		}

		if (i == bstrlen && bstrflag == 1) {
			yylval.string = buf;
			bstrlen = bstrflag = 0;
			return (STRING);
		}

		p++;
	}
}

int
yyerror(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	fprintf(stderr, "\n");
	va_end(ap);

	return (0);
}

int
main(int argc, char **argv) {
	fin = stdin;
	yyparse();

	exit(0);
}
