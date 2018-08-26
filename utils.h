#ifndef UTILS_H
#define UTILS_H

enum syscall {
	X,
	GETATTR,
	MKNOD,
	MKDIR,
	UNLINK,
	RMDIR,
	RENAME,
	TRUNCATE,
	OPEN,
	READ,
	WRITE,
	RELEASE,
	OPENDIR,
	READDIR,
	RELEASEDIR,
	HOTSWAP,
};

enum write_state{
	DEFAULT,
	BU_FIRST_CHUNK,
	BU_REST,
};

struct Metadata{
	enum syscall func_num;
	//mknod
	char path[256];
	mode_t mode;
	//write
	size_t size;
	off_t offset;
	off_t new_size;
	int xvar;
	//rename
	char new_path[256];
	//open
	int flags;
	//
	int write_fd;
	int read_fd;
	DIR* readdir_fd;
};

struct Server
{
	char server[256];
	int sfd;
};

struct srtw_file
{
	char file_name[256];
	int fd;	
};

struct cache_file
{
	char name[256];
	int fd_serv1;
	int size;
	int offset;
	time_t access;
	char * data;
};

struct cache_info
{
	char name[256];
	time_t access;
	int retstat;
	struct stat * statbuf;
};

struct Cache
{
	int cache_size;
	int used_size;
	int num_files;
	int num_infos;
	struct cache_file ** files;
	struct cache_info ** infos;
};

struct NRF_Data
{
	struct Cache * cache;
	char diskname[256];
	struct Server servers[3];
	FILE* logfile;
	int srtw_idx;
	struct srtw_file ** srtw_files;
	pthread_mutex_t *lock;
	int timeout;
};

//RETURN STRUCTS

struct getattr_ret
{
	struct stat st;
	int ret;
};

struct opendir_ret
{
	DIR* dp;
	int ret;
};

struct readdir_ret
{
	int strlen;
	int ret;
};

struct hotswap_ret
{
	int regdir;
	char path[256];
};

//hotswap
struct hotswap_data
{
	int sfd0;
	int sfd1;
	pthread_t tid;
	pthread_t stid;
	struct NRF_Data * nrf_data;
	int * status;
};

#endif