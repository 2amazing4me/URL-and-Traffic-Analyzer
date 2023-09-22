// Copyright Baldovin Razvan-Mihai-Marian 312CA 2023
#ifndef URL_CHECK_H
#define URL_CHECK_H

#include <ctype.h>
#define MAX_URL_SIZE 400
#define MALWARE_URLS 41
#define TLD_CNT 3211
#define MAX_TLD_SIZE 30
#define NUM_OF_EXECUTABLES 5
#define KEYWORDS_CNT 1

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "file_manager.h"

int check_dictionary(char *url, char **known_malware)
{
	for (int i = 0; i < MALWARE_URLS; ++i) {
		if (strstr(url, known_malware[i]))
			return 1;
	}

	return 0;
}

int check_extension(char *url)
{
	char *executables[NUM_OF_EXECUTABLES] = {".exe", ".bin", ".sh", ".dat",
											 ".doc"};

	for (int i = 0; i < NUM_OF_EXECUTABLES; ++i)
		if (strstr(url, executables[i]))
			return 1;

	return 0;
}

int check_number_proportion(char *url)
{
	char *copy = (char *)calloc(MAX_URL_SIZE, sizeof(char));
	if (!copy) {
		printf("Failed to calloc 'copy' (url_check.c -> "
			   "check_number_proportion)\n");
		return -1;
	}
	strcpy(copy, url);

	char *domain = strtok(copy, "/");
	if (strstr(domain, "http")) {
		domain = strtok(NULL, "/");
		domain = strtok(NULL, "/");
	}

	int domain_len = strlen(domain);
	int numbers_in_domain = 0;

	for (int i = 0; i < domain_len; ++i) {
		if (domain[i] >= '0' && domain[i] <= '9')
			++numbers_in_domain;
	}

	free(copy);

	if (numbers_in_domain > domain_len / 5 && numbers_in_domain)
		return 1;

	return 0;
}

int check_subdomain(char *url)
{
	char *copy = (char *)calloc(MAX_URL_SIZE, sizeof(char));
	if (!copy) {
		printf("Failed to calloc 'copy' (url_check.c -> check_tld)\n");
		return -1;
	}
	strcpy(copy, url);

	char *domain = strtok(copy, "/");
	if (strstr(domain, "http")) {
		domain = strtok(NULL, "/");
		domain = strtok(NULL, "/");
	}

	int check = 0;
	char *p = strtok(domain, ".");
	if (strstr(p, "www"))
		if (p[3])
			check = 1;

	free(copy);
	return check;
}

int check_tld(char *url, char **known_tlds)
{
	char *copy = (char *)calloc(MAX_URL_SIZE, sizeof(char));
	if (!copy) {
		printf("Failed to calloc 'copy' (url_check.c -> check_tld)\n");
		return -1;
	}
	strcpy(copy, url);

	char *domain = strtok(copy, "/");
	if (strstr(domain, "http")) {
		domain = strtok(NULL, "/");
		domain = strtok(NULL, "/");
	}

	int check = 1;
	for (int i = 0; i < TLD_CNT && check; ++i) {
		char *p = strstr(domain, known_tlds[i]);
		if (p) {
			if (strlen(p) > strlen(known_tlds[i]))
				if (!isalpha(p[strlen(known_tlds[i])])) {
					check = 1;
					break;
				}
			if (strcmp(p, known_tlds[i]) == 0)
				check = 0;
		}
	}

	free(copy);
	return check;
}

int check_suspicious_keywords(char *url)
{
	char *keyword[KEYWORDS_CNT] = {"cmd", };

	for (int i = 0; i < KEYWORDS_CNT; ++i)
		if (strstr(url, keyword[i]))
			return 1;

	return 0;
}

int check_url(char *url, char **known_malware, char **known_tlds)
{
	if (check_dictionary(url, known_malware))
		return 1;
	if (check_extension(url))
		return 1;
	if (check_number_proportion(url))
		return 1;
	if (check_subdomain(url))
		return 1;
	if (check_tld(url, known_tlds))
		return 1;
	if (check_suspicious_keywords(url))
		return 1;

	return 0;
}

void url_av(void)
{
	FILE *url_list, *output, *malware, *tld_list;
	load_file(&url_list, "data/urls/urls.in", "r");
	load_file(&output, "urls-predictions.out", "w");
	load_file(&malware, "data/urls/domains_database", "r");
	load_file(&tld_list, "resources/tld_list.txt", "r");

	char **known_malware, **known_tlds;
	read_all_file(malware, &known_malware, MALWARE_URLS, MAX_URL_SIZE);
	read_all_file(tld_list, &known_tlds, TLD_CNT, MAX_TLD_SIZE);

	while (!feof(url_list)) {
		char *url = (char *)calloc(MAX_URL_SIZE, sizeof(char));

		fscanf(url_list, "%s", url);
		trim(&url);

		if (url[0])
			fprintf(output, "%d\n", check_url(url, known_malware, known_tlds));

		free(url);
	}

	for (int i = 0; i < MALWARE_URLS; ++i)
		free(known_malware[i]);
	free(known_malware);

	for (int i = 0; i < TLD_CNT; ++i)
		free(known_tlds[i]);
	free(known_tlds);

	fclose(url_list);
	fclose(malware);
	fclose(output);
	fclose(tld_list);
}

#endif // URL_CHECK_H
