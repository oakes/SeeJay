#include <stdio.h>
#include <stdlib.h>

#include "util.h"

/*
 * Reads the file into memory and returns a pointer.
 */

int read_file(char *name, char *buffer)
{
	/* open the file */

	FILE *file = fopen(name, "r");
	if (!file) {
		return -1;
	}

	/* get the file length */

	fseek(file, 0, SEEK_END);
	unsigned long len = ftell(file);
	fseek(file, 0, SEEK_SET);

	/* read and return the contents */

	if (!(buffer = (char *)malloc(len+1))) {
		fclose(file);
		return -1;
	}
	fread(buffer, len, 1, file);
	fclose(file);

	return 0;
}

/*
 * Determines if the file exists.
 */

int file_exists(char *name)
{
	FILE *file = fopen(name, "r");
	if (file == NULL) {
		return 0;
	}

	fclose(file);
	return 1;
}
