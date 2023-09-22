// Copyright Baldovin Razvan-Mihai-Marian 312CA 2023
#ifndef TRAFFIC_CHECK_H
#define TRAFFIC_CHECK_H

#define TRAFFIC_SIZE 1000
#define REQUEST_SIZE 150

#define MINUTE 60
#define HOUR (60 * MINUTE)
#define DAY (24 * HOUR)

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "file_manager.h"

typedef struct __request {
	char *origin_ip, *origin_port, *response_ip, *response_port, *flow_duration,
		*fwd_pkts_tot, *bwd_pkts_tot, *fwd_header_size_tot,
		*bwd_header_size_tot, *flow_FIN_flag_count, *flow_SYN_flag_count,
		*flow_ACK_flag_count, *fwd_pkts_payload_avg, *bwd_pkts_payload_avg,
		*fwd_iat_avg, *bwd_iat_avg, *flow_pkts_payload_avg;
} request;

void assign_request_values(char *str, request *traffic)
{
	char *p = strtok(str, ",");
	(*traffic).origin_ip = strdup(p);

	p = strtok(NULL, ",");
	(*traffic).origin_port = strdup(p);

	p = strtok(NULL, ",");
	(*traffic).response_ip = strdup(p);

	p = strtok(NULL, ",");
	(*traffic).response_port = strdup(p);

	p = strtok(NULL, ",");
	(*traffic).flow_duration = strdup(p);

	p = strtok(NULL, ",");
	(*traffic).fwd_pkts_tot = strdup(p);

	p = strtok(NULL, ",");
	(*traffic).bwd_pkts_tot = strdup(p);

	p = strtok(NULL, ",");
	(*traffic).fwd_header_size_tot = strdup(p);

	p = strtok(NULL, ",");
	(*traffic).bwd_header_size_tot = strdup(p);

	p = strtok(NULL, ",");
	(*traffic).flow_FIN_flag_count = strdup(p);

	p = strtok(NULL, ",");
	(*traffic).flow_SYN_flag_count = strdup(p);

	p = strtok(NULL, ",");
	(*traffic).flow_ACK_flag_count = strdup(p);

	p = strtok(NULL, ",");
	(*traffic).fwd_pkts_payload_avg = strdup(p);

	p = strtok(NULL, ",");
	(*traffic).bwd_pkts_payload_avg = strdup(p);

	p = strtok(NULL, ",");
	(*traffic).fwd_iat_avg = strdup(p);

	p = strtok(NULL, ",");
	(*traffic).bwd_iat_avg = strdup(p);

	p = strtok(NULL, ",");
	(*traffic).flow_pkts_payload_avg = strdup(p);
}

void free_traffic(request *traffic)
{
	free((*traffic).origin_ip);
	free((*traffic).origin_port);
	free((*traffic).response_ip);
	free((*traffic).response_port);
	free((*traffic).flow_duration);
	free((*traffic).fwd_pkts_tot);
	free((*traffic).bwd_pkts_tot);
	free((*traffic).fwd_header_size_tot);
	free((*traffic).bwd_header_size_tot);
	free((*traffic).flow_FIN_flag_count);
	free((*traffic).flow_SYN_flag_count);
	free((*traffic).flow_ACK_flag_count);
	free((*traffic).fwd_pkts_payload_avg);
	free((*traffic).bwd_pkts_payload_avg);
	free((*traffic).fwd_iat_avg);
	free((*traffic).bwd_iat_avg);
	free((*traffic).flow_pkts_payload_avg);
}

int to_seconds(char *time)
{
	char *aux = strdup(time);
	int seconds = 0;

	char *p = strtok(aux, " ");
	seconds += atol(p) * DAY;

	// skips the word "days"
	p = strtok(NULL, " ");
	p = strtok(NULL, " :");
	seconds += atol(p) * HOUR;

	p = strtok(NULL, " :");
	seconds += atol(p) * MINUTE;

	p = strtok(NULL, " :");
	seconds += atol(p);

	free(aux);

	return seconds;
}

int check_traffic(request traffic)
{
	// Safe
	if (strcmp(traffic.response_ip, "255.255.255.255") == 0)
		return 0;

	// Brute force
	if (to_seconds(traffic.flow_duration) >= 1 &&
		atof(traffic.flow_pkts_payload_avg) > 500)
		return 1;

	// Cryptominer
	if (atol(traffic.flow_ACK_flag_count) == 0 &&
		atol(traffic.flow_FIN_flag_count) == 0 &&
		atol(traffic.flow_SYN_flag_count) == 0)
		return 1;

	return 0;
}

void traffic_av(void)
{
	FILE *traffic_list, *output;
	load_file(&traffic_list, "data/traffic/traffic.in", "r");
	load_file(&output, "traffic-predictions.out", "w");

	fseek(traffic_list, 276, SEEK_SET);
	while (!feof(traffic_list)) {
		request traffic;

		char *str = (char *)calloc(REQUEST_SIZE, sizeof(char));
		fgets(str, REQUEST_SIZE, traffic_list);

		if (str[0]) {
			assign_request_values(str, &traffic);

			fprintf(output, "%d\n", check_traffic(traffic));

			free_traffic(&traffic);
		}

		free(str);
	}

	fclose(traffic_list);
	fclose(output);
}

#endif // TRAFFIC_CHECK_H
