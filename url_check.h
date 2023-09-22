// Copyright Baldovin Razvan-Mihai-Marian 312CA 2023
int check_dictionary(char *url, char **known_malware);

int check_extension(char *url);

int check_number_proportion(char *url);

int check_domain(char *url);

int check_tld(char *url, char **known_tlds);

int check_suspicious_keywords(char *url);

int check_url(char *url, char **known_malware);

void url_av(void);
