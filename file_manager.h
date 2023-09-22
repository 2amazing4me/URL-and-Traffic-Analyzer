#include <stdio.h>

void trim(char **str);

void load_file(FILE **file, char *location, char *modes);

void read_all_file(FILE *file, char ***destination, int list_size,
				   int element_size);
