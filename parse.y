/* $Id: parse.y,v 1.10 2006-04-29 19:55:07 niallo Exp $ */
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

#include "bencode.h"

int yyerror(const char *, ...);
int yyparse(void);
int yylex(void);

static FILE	*fin     = NULL;
static size_t	bstrlen  = 0;
static int	bstrflag = 0;
static int	bdone    = 0;
static int	bcdone   = 0;

%}

%union {
	int number;
	char *string;
}

%token COLON
%token END
%token INT_START
%token DICT_START
%token LIST_START
%token <string> STRING
%type  <string> bstring
%type  <number> bint
%type  <number> number
%type  <string> bdict_entries
%type  <string> blist_entries

%start bencode

%%


bencode		: /* empty */
		| bencode bstring
		| bencode bint
		| bencode bdict
		| bencode blist
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

/* special hack for bstrings */
bstrflag	:						{
			bstrflag = 1;
		}
		;

bstring		: bstrflag number COLON STRING			{
			printf("string %s len %d\n", $4, $2);
			$$ = $4;
		}
		;

bint		: INT_START number END				{
			printf("number: %d\n", $2);
			$$ = $2;
		}
		;

blist_entries	: blist_entries bint
		| blist_entries bstring
		| blist_entries blist
		| blist_entries bdict
		| bint						{ }
		| bstring					{ }
		| blist						{ }
		| bdict						{ }
		;

blist		: LIST_START blist_entries END			{
			printf("blist found\n");
		}
		;


bdict_entries	: bdict_entries bstring bint		{ }
		| bdict_entries bstring bstring		{ }
		| bdict_entries bstring blist		{ }
		| bdict_entries bstring bdict		{ }
		| bstring bint				{ }
		| bstring bstring			{ }
		| bstring blist				{ }
		| bstring bdict				{ }
		;

bdict		: DICT_START bdict_entries END			{
			printf("bdict found\n");
		}
		;
%%

int
yylex(void)
{
	char	*buf, *p;
	int	c, token = 0;
	size_t	buflen = 128, i = 0;;

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
			/* NUL-fill the new memory */
			memset(p, '\0', 20480);
		}

		c = fgetc(fin);
		/* assume STRING if we hit EOF */
		if (c == EOF) {
			yyval.string = buf;
			printf("EOF\n");
			return (STRING);
		}
		if (c == '\n') {
			free(buf);
			printf("c is dash n\n");
			return (0);
		}


		switch (c) {
		case ':':
			/* special handling for bstrings */
			if (bdone == 0 && bcdone == 1) {
				*p = c;
				i++;
				break;
			}
			if (bdone == 0 && i > 0) {
				yylval.string = buf;
				bdone = 1;
				bcdone = 0;
				(void)ungetc(c, fin);
				printf("pre-COLON STRING %s\n", buf);
				return (STRING);
			} else {
				bdone = 0;
				bcdone = 1;
				free(buf);
				printf("COLON\n");
				return (COLON);
			}
			break;
		case 'e':
			/* special handling for bstrings */
			if (bstrflag == 1) {
				*p = c;
				i++;
				break;
			}
			/* in other contexts, e is END */
			if (bdone == 0 && i > 0) {
				yylval.string = buf;
				bdone = 1;
				(void)ungetc(c, fin);
				printf("pre-END i is %d %s\n", (int)i, buf);
				return (STRING);
			} else {
				bdone = 0;
				free(buf);
				printf("END\n");
				return (END);
			}
			break;
		case 'i':
			/* special handling for bstrings */
			if (bstrflag == 1) {
				*p = c;
				i++;
				break;
			}
			free(buf);
			printf("INT_START\n");
			return (INT_START);
			break;
		case 'd':
			/* special handling for bstrings */
			if (bstrflag == 1) {
				*p = c;
				i++;
				break;
			}
			free(buf);
			printf("DICT_START\n");
			return (DICT_START);
			break;
		case 'l':
			/* special handling for bstrings */
			if (bstrflag == 1) {
				*p = c;
				i++;
				break;
			}
			free(buf);
			printf("LIST_START\n");
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
			bstrlen = bstrflag = bcdone = 0;
			printf("STRING %s\n", buf);
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
	int ret = 0;

	fin = stdin;
	ret = yyparse();

	exit(ret);
}
