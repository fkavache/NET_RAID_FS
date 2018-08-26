#ifndef PARSER_H
#define PARSER_H

struct Disk_Config
{
	char* diskname;
	char* mountpoint;
	int raid;
	char** servers;
	char* hotswap;
	int num_servers;
};

struct Config{
	char* errorlog;
	char* cache_size;
	char* cache_replacement;
	int timeout;
	struct Disk_Config * disk_configs;
	int num_storages;
};

int config_parser(char* file, struct Config * config_st);

#endif