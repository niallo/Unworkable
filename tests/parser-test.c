#include <err.h>
#include <stdio.h>
#include <stdlib.h>

#include "includes.h"

int
main(int argc, char **argv)
{
	BUF *b;
	int i;
	struct benc_node *troot;

	if (argc < 2)
		errx(2, "must supply at least one input file");
	
	for (i = 1; i < argc; i++) {
		if ((b = buf_load(argv[i], 0)) == NULL)
			err(1, "invalid input file");

		troot = benc_root_create();
		if ((troot = benc_parse_buf(b, troot)) == NULL)
			err(1, "could not parse file: %s", argv[i]);

		benc_node_print(troot, 0);
		benc_node_freeall(troot);
		buf_free(b);
	}

	exit(0);
}
