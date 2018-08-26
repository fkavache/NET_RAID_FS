#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "parser.h"

int main_config_parser(FILE* fid, struct Config * config_st);
int disk_config_parser(FILE* fid, struct Config * config_st);
int scanf_errs(FILE* fid, int err_code, int arg_num);
int parse_servers(char* servers,  struct Config * config_st, int disk_i);

/*
	Configuration file parser, uses two parser
	1 - main configuration parser 
		i. error log file path
		ii. cache size
		iii. cache replacement algorithm
		iv. timeout for hotswap
	2 - disk configuration parser
		i. diskname
		ii. mountpoint
		iii. raid
		iv. servers (for raid implementations)
		v. hotswap server
*/
int config_parser(char* file, struct Config * config_st){

	FILE* fid;
	fpos_t pos;
	int pos_init = 0;

	fid = fopen(file,"rw+");

	if(!fid)
		printf("Can't open file\n");

	////////////////////////////////

	main_config_parser(fid, config_st);

	////////////////////////////////

	disk_config_parser(fid, config_st);

	////////////////////////////////

  return 0;
}

/*
	Main configuration parser - uses fscanf and fills ო given config_st structure with data
*/
int main_config_parser(FILE* fid, struct Config * config_st){
	config_st->errorlog = malloc(256);
  config_st->cache_size = malloc(256);
  config_st->cache_replacement = malloc(256);

  int res = fscanf(fid, "errorlog = %s cache_size = %s cache_replacement = %s timeout = %d", 
		config_st->errorlog, config_st->cache_size, config_st->cache_replacement, &(config_st->timeout));
 	
 	int err = scanf_errs(fid, res, 4);
	if(err == -1 || err == 0)
		return -1;
	return 1;
}

/*
	Disk configuration parser - uses fscanf and fills given config_st structure with data
*/
int disk_config_parser(FILE* fid, struct Config * config_st){
	char servers[256];

	int diskstorage = 0;
	while (!feof(fid))
	{

		config_st->disk_configs = realloc(config_st->disk_configs, (diskstorage + 1) * sizeof(struct Disk_Config));

		config_st->disk_configs[diskstorage].diskname = malloc(256);
		config_st->disk_configs[diskstorage].mountpoint = malloc(256);
		config_st->disk_configs[diskstorage].hotswap = malloc(256);

		int res = fscanf(fid, " diskname = %s mountpoint = %s raid = %d servers = %[^\n] hotswap = %s", 
			config_st->disk_configs[diskstorage].diskname, config_st->disk_configs[diskstorage].mountpoint, 
			&(config_st->disk_configs[diskstorage].raid), servers, config_st->disk_configs[diskstorage].hotswap);

		parse_servers(servers, config_st, diskstorage);
		
		int err = scanf_errs(fid, res, 5);
		if(err == -1 || err == 0){
			if (diskstorage == 0)
				return -1; 
			fclose(fid);
			memcpy(&config_st->num_storages, &diskstorage, sizeof(int));
			return err;	
		}

		diskstorage ++;
	}

	fclose(fid);
	memcpy(&config_st->num_storages, &diskstorage, sizeof(int));
}

int scanf_errs(FILE* fid, int err_code, int arg_num){
	if (err_code == EOF) {
		if (ferror(fid))
		  return -1;
		else
		  return 0;
		return -1;
	}
	else if (err_code != arg_num)
		return -1;
	return 1;
}

int parse_servers(char* servers,  struct Config * config_st, int disk_i){
	char seps[] = ", ";
	char* token;
	char var[256];

	int i = 0;
	token = strtok (servers, seps);
	while (token != NULL)
	{
	  sscanf (token, "%s", var);

	  config_st->disk_configs[disk_i].servers = realloc(config_st->disk_configs[disk_i].servers, (i+1) * sizeof(char*));
	  config_st->disk_configs[disk_i].servers[i] = malloc(256);
	  strcpy(config_st->disk_configs[disk_i].servers[i], var);

	  token = strtok (NULL, seps);	
	  i++;
	}

	memcpy(&config_st->disk_configs[disk_i].num_servers, &i, sizeof(int));
}