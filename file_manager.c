#ifndef FILE_MANAGER_H
#define FILE_MANAGER_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void trim(char **str)
{
	int len = strlen(*str);
	if (len == 0)
		return;

	while ((*str)[len - 1] == '\n' || (*str)[len - 1] == ' ') {
		(*str)[len - 1] = 0;
		--len;
	}
}

void load_file(FILE **file, char *location, char *modes)
{
	*file = fopen(location, modes);
	if (!file) {
		printf("Failed to open file at location: %s\n", location);
		return;
	}
}

void read_all_file(FILE *file, char ***destination, int list_size,
				   int element_size)
{
	*destination = (char **)malloc(list_size * sizeof(char *));
	if (!destination) {
		printf("Failed to malloc 'destination' (file_manager.c -> "
			   "read_all_file)\n");
		return;
	}
	for (int i = 0; i < list_size; ++i) {
		(*destination)[i] = (char *)calloc(element_size, sizeof(char));
		if (!destination) {
			printf("Failed to malloc 'destination' (file_manager.c -> "
				   "read_all_file)\n");
			return;
		}

		fscanf(file, "%s", (*destination)[i]);
		trim(&(*destination)[i]);
	}
}

#endif // FILE_MANAGER_H
