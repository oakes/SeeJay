#include <stdio.h>
#include <stdlib.h>

#include "util.h"

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
