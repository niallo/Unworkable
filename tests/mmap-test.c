#include <sys/types.h>
#include <sys/mman.h>
#include <err.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>

int
main(int argc, char **argv)
{
	int fd;
	size_t len;
	off_t off;
	void *addr;
	char *test;

	if ((test = malloc(128)) == NULL)
		err(1, "malloc() failure");

	if ((fd = open("./test_file", O_RDWR|O_CREAT|O_TRUNC, 0600)) == -1)
		err(1,"open() failure");
	
	len = 200000;
	off = 0;
	addr = mmap(0, len, PROT_WRITE|PROT_READ, 0, fd, off);
	if (addr == MAP_FAILED)
		err(1, "mmap() failure");

	memset(test, 'b', 128);
	write(fd, test, 128);
	memcpy(addr, test, 128);

	exit(0);
}
