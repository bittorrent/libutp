#include <stdio.h>
#include <string.h>

#include "utp.h"

// shared conf file parsing--should be called with a default conf already set
// (i.e. this only overrides values)
bool parse_conf_file(const char * const file_name, UTPConf *conf)
{
	if (file_name == NULL || conf == NULL) return false;

	FILE *fp = fopen(file_name, "r");
	if (fp == NULL) return false;

	char name[100];
	int value;
	while (fscanf(fp, "%s%d\n", name, &value) == 2) {
		if (strcmp(name, "ccontrol_target") == 0)
			conf->ccontrol_target = (uint32)value;
		else if (strcmp(name, "max_cwnd_increase_bytes_per_rtt") == 0)
			conf->max_cwnd_increase_bytes_per_rtt = (uint16)(value & 0xffff);
		else if (strcmp(name, "min_window_size") == 0)
			conf->min_window_size = (uint32)(value & 0xffff);
		else fprintf(stderr, "unknown conf name: %s\n", name);
	}

	fclose(fp);

	return true;
}

const char *conf_to_str(const char * const prefix, UTPConf *conf)
{
	static char str[4096];
	snprintf(str, sizeof(str),
		 "%sccontrol_target=%d\n"
		 "%smax_cwnd_increase_bytes_per_rtt=%d\n"
		 "%smin_window_size=%d\n",
		 prefix, conf->ccontrol_target,
		 prefix, conf->max_cwnd_increase_bytes_per_rtt,
		 prefix, conf->min_window_size);
	return str;
}
