/* $Id: parse.y,v 1.1 2006-04-26 00:49:54 niallo Exp $ */
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

int atoul(char *, u_long *);

int yyerror(const char *, ...);
int yyparse(void);
int yylex(void);


static FILE	*fin = NULL;
static u_long	bstrlen = 0;
static int	bstrflag = 0;

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
			u_long ulval;
			
			if (atoul($1, &ulval) == -1) {
				yyerror("%s is not a number", $1);
				free($1);
				YYERROR;
			} else {
				$$ = ulval;
				if (bstrflag == 1)
					bstrlen = ulval;
			}
			free($1);
		}
		;

%%

int
atoul(char *s, u_long *ulvalp)
{
        u_long   ulval;
        char    *ep;

        errno = 0;
        ulval = strtoul(s, &ep, 0);
        if (s[0] == '\0' || *ep != '\0')
                return (-1);
        if (errno == ERANGE && ulval == ULONG_MAX)
                return (-1);
        *ulvalp = ulval;
        return (0);
}


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

		*p = c;
		i++;

		/* short circuit for byte string lexical tie-in */
		if (*p == ':') {
			free(buf);
			return (COLON);
		}

		if (bstrflag == 1) {
			if (i == bstrlen) {
				yylval.string = buf;
				bstrlen = bstrflag = 0;
				return (STRING);
			} else if (bstrlen > 0) {
				p++;
				continue;
			}
		}

		switch (*p) {
		case 'e':
			token = END;
			break;
		case 'i':
			token = INT_START;
			break;
		case 'd':
			token = DICT_START;
			break;
		case 'l':
			token = LIST_START;
			break;
		default:
			yylval.string = buf;
			return (STRING);
			break;
		}

		if (token != 0) {
			free(buf);
			return (token);
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
