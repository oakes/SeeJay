#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "util.h"

/*
 * Determines if the file exists.
 */

int file_exists(char *name)
{
	FILE *file = fopen(name, "r");
	if (file == NULL) {
		return -1;
	}

	fclose(file);
	return 0;
}

/*
 * Reads the value for a given key in the config file.
 */

int read_config(char *name, char *key, char *value)
{
	FILE *file = fopen(name, "r");
	if (file == NULL) {
		return -1;
	}

	char buffer[100];
	char delims[] = " \t\n";
	char *temp;

	while (fgets(buffer, sizeof(buffer), file) != NULL) {
		temp = strtok(buffer, delims);
		if (temp != NULL && strcmp(temp, key) == 0) {
			if ((temp = strtok(NULL, delims)) != NULL) {
				strcpy(value, temp);
			}
			break;
		}
	}

	fclose(file);
	return 0;
}
