/* $Id: parse.y,v 1.22 2006-05-01 01:16:18 niallo Exp $ */
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

/* Assume no more than 16 nested dictionaries/lists. */
#define  STACK_SIZE 		16

int				yyerror(const char *, ...);
int				yyparse(void);
int				yylex(void);

/* Internal node-stack functions */
static struct benc_node		*benc_stack_pop(void);
static struct benc_node		*benc_stack_peek(void);
static void			benc_stack_push(struct benc_node *);

static FILE			*fin     = NULL;
static long			bstrlen  = 0;
static int			bstrflag = 0;
static int			bdone    = 0;
static int			bcdone   = 0;

static struct benc_node		*bstack[STACK_SIZE];
static int			bstackidx = 0;

%}

%union {
	long			number;
	char			*string;
	struct benc_node	*benc_node;
}

%token				COLON
%token				END
%token				INT_START
%token				DICT_START
%token <benc_node>		LIST_START
%token <string>			STRING
%type  <benc_node>		bstring
%type  <benc_node>		bint
%type  <number>			number
%type  <benc_node>		bdict_entries
%type  <benc_node>		bdict_entry
%type  <benc_node>		blist_entries
%type  <benc_node>		bdict
%type  <benc_node>		blist

%start bencode

%%


bencode		: /* empty */
		| bencode bstring				{
			benc_node_add(root, $2);
		}
		| bencode bint					{
			benc_node_add(root, $2);
		}
		| bencode bdict					{
			benc_node_add(root, $2);
		}
		| bencode blist					{
			benc_node_add(root, $2);
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

/*
 * Special hack for bstrings.
 */
bstrflag	:						{
			bstrflag = 1;
		}
		;

bstring		: bstrflag number COLON STRING			{
			struct benc_node *node;
			
			node = benc_node_create();
			node->body.string.len = $2;
			node->body.string.value = $4;
			node->flags = BSTRING;
			$$ = node;
		}
		;

bint		: INT_START number END				{
			struct benc_node *node;

			node = benc_node_create();
			node->body.number = $2;
			node->flags = BINT;

			$$ = node;
		}
		;

blist		: LIST_START					{
			/*
			 * Push the list node onto the stack before continuing
			 * so that sub-elements can add themselves to it.
			 */
			struct benc_node *node;

			node = benc_node_create();
			node->flags = BLIST;
			benc_stack_push(node);
		}
		blist_entries END				{
			/*
			 * Pop list node and link the remaining sub-element.
			 */
			struct benc_node *node;

			node = benc_stack_pop();
			benc_node_add(node, $3);
			$$ = node;
		}
		;

blist_entries	: bint						{
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
		| blist_entries bint				{
			benc_node_add(benc_stack_peek(), $2);
		}
		| blist_entries bstring				{
			benc_node_add(benc_stack_peek(), $2);
		}
		| blist_entries blist				{
			benc_node_add(benc_stack_peek(), $2);
		}
		| blist_entries bdict				{
			benc_node_add(benc_stack_peek(), $2);
		}
		;

bdict_entry	: bstring bint					{
			struct benc_node *node;

			node = benc_node_create();
			node->flags = BINT|BDICT_ENTRY;
			node->body.dict_entry.key = $1->body.string.value;
			node->body.dict_entry.value = $2;

			$$ = node;
		}
		| bstring bstring				{
			struct benc_node *node;

			node = benc_node_create();
			node->flags = BSTRING|BDICT_ENTRY;
			node->body.dict_entry.key = $1->body.string.value;
			node->body.dict_entry.value = $2;

			$$ = node;
		}
		| bstring blist					{
			struct benc_node *node;

			node = benc_node_create();
			node->flags = BLIST|BDICT_ENTRY;
			node->body.dict_entry.key = $1->body.string.value;
			node->body.dict_entry.value = $2;

			$$ = node;
		}
		| bstring bdict					{
			struct benc_node *node;

			node = benc_node_create();
			node->flags = BDICT|BDICT_ENTRY;
			node->body.dict_entry.key = $1->body.string.value;
			node->body.dict_entry.value = $2;

			$$ = node;
		}


bdict_entries	: bdict_entry					{
			$$ = $1;
		}
		| bdict_entries bdict_entry			{
			benc_node_add(benc_stack_peek(), $2);
		}
		;

bdict		: DICT_START					{
			/*
			 * Push the dict node onto the stack before continuing
			 * so that sub-elements can add themselves to it.
			 */
			struct benc_node *node;

			node = benc_node_create();
			node->flags = BDICT;
			
			benc_stack_push(node);
		}
		bdict_entries END				{
			/*
			 * Pop dict node and link the remaining sub-element.
			 */
			struct benc_node *node;

			node = benc_stack_pop();
			benc_node_add(node, $3);

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
			printf("realloc\n");
		}

		c = fgetc(fin);
		if (c == EOF) {
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

static struct benc_node*
benc_stack_pop(void)
{
	struct benc_node *node;

	bstackidx--;
	node = bstack[bstackidx];

	return (node);
}

static struct benc_node*
benc_stack_peek(void)
{
	struct benc_node *node;

	node = bstack[bstackidx - 1];

	return (node);
}

static void
benc_stack_push(struct benc_node *node)
{
	bstack[bstackidx] = node;
	bstackidx++;
}


int
main(int argc, char **argv)
{
	int ret = 0;

	root = benc_node_create();
	root->parent = NULL;
	root->flags = BLIST;
	SLIST_INIT(&(root->children));

	fin = stdin;
	ret = yyparse();

	if (ret == 0)
		print_tree(root, 0);

	exit(ret);
}
