// Copyright Baldovin Razvan-Mihai-Marian 312CA 2023
typedef struct __request request;

void assign_request_values(char *str, request *traffic);

void free_traffic(request *traffic);

int to_seconds(char *time);

int check_traffic(request traffic);

void traffic_av(void);
