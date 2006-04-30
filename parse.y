/* $Id: parse.y,v 1.15 2006-04-30 01:56:58 niallo Exp $ */
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
static long	bstrlen  = 0;
static int	bstrflag = 0;
static int	bdone    = 0;
static int	bcdone   = 0;

%}

%union {
	long		number;
	char		*string;
	struct b_node	*b_node;
}

%token COLON
%token END
%token INT_START
%token DICT_START
%token LIST_START
%token <string>		STRING
%type  <b_node>		bstring
%type  <b_node>		bint
%type  <number>		number
%type  <b_node>		bdict_entries
%type  <b_node>		blist_entries
%type  <b_node>		bdict
%type  <b_node>		blist

%start bencode

%%


bencode		: /* empty */
		| bencode bstring				{
			add_node(root, $2);
		}
		| bencode bint					{
			add_node(root, $2);
		}
		| bencode bdict					{
			add_node(root, $2);
		}
		| bencode blist					{
			add_node(root, $2);
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

/* special hack for bstrings */
bstrflag	:						{
			bstrflag = 1;
		}
		;

bstring		: bstrflag number COLON STRING			{
			struct b_node *node;
			
			node = create_node();
			node->body.string.len = $2;
			node->body.string.value = $4;
			node->type = BSTRING;

			$$ = node;
		}
		;

bint		: INT_START number END				{
			struct b_node *node;

			node = create_node();
			node->body.number = $2;
			node->type = BINT;

			$$ = node;
		}
		;

blist_entries	: blist_entries bint				{
			add_node($1, $2);
		}
		| blist_entries bstring				{
			add_node($1, $2);
		}
		| blist_entries blist				{
			add_node($1, $2);
		}
		| blist_entries bdict				{
			add_node($1, $2);
		}
		| bint						{
			$$ = $1;
		}
		| bstring					{
			$$ = $1;
		}
		| blist						{
			$$ = $1;
		}
		| bdict						{
			$$ = $1;
		}
		;

blist		: LIST_START blist_entries END			{
			struct b_node *node;

			node = create_node();
			node->type = BLIST;
			

			add_node(node, $2);

			$$ = node;
		}
		;


bdict_entries	: bdict_entries bstring bint			{

		}
		| bdict_entries bstring bstring			{
		
		}
		| bdict_entries bstring blist			{
		
		}
		| bdict_entries bstring bdict			{
		
		}
		| bstring bint					{
		
		}
		| bstring bstring				{
		
		}
		| bstring blist					{
		
		}
		| bstring bdict					{
		
		}
		;

bdict		: DICT_START bdict_entries END			{
			struct b_node *node;

			node = create_node();
			node->type = BDICT;

			add_node(node, $2);

			$$ = node;
		}
		;
%%

int
yylex(void)
{
	char	*buf, *p;
	int	c;
	long	buflen = 128, i = 0;

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

		/* if we are in string context, ignore special chars */
		if ((c == ':' && bdone == 0 && bcdone == 1)
		    || (c != ':' && bstrflag == 1))
			goto skip;

		switch (c) {
		case ':':
			if (bdone == 0 && i > 0) {
				yylval.string = buf;
				bdone = 1;
				bcdone = 0;
				(void)ungetc(c, fin);
				return (STRING);
			} else {
				bdone = 0;
				bcdone = 1;
				free(buf);
				return (COLON);
			}
		case 'e':
			/* in other contexts, e is END */
			if (bdone == 0 && i > 0) {
				yylval.string = buf;
				bdone = 1;
				(void)ungetc(c, fin);
				return (STRING);
			} else {
				bdone = 0;
				free(buf);
				return (END);
			}
		case 'i':
			free(buf);
			return (INT_START);
		case 'd':
			free(buf);
			return (DICT_START);
		case 'l':
			free(buf);
			return (LIST_START);
		}
skip:
		/* add this character to the buffer */
		*p = c;
		i++;

		if (i == bstrlen && bstrflag == 1) {
			yylval.string = buf;
			bstrlen = bstrflag = bcdone = 0;
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
main(int argc, char **argv)
{
	int ret = 0;

	root = create_node();
	root->parent = NULL;
	root->type = BLIST;
	SLIST_INIT(&(root->children));

	fin = stdin;
	ret = yyparse();

	print_tree(root, 0);

	exit(ret);
}
