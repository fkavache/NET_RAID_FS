#define FUSE_USE_VERSION 30

#include <fuse.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <limits.h>
#include <unistd.h>
#include <time.h>

#include "parser.h"

// for socket api
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h> /* superset of previous */
#include <arpa/inet.h>
#include <openssl/md5.h>
#include <pthread.h>

#include "utils.h"

int client(char* server, int i, struct NRF_Data * nrf_data);
int log_msg(FILE* logfile, char* msg, char* diskname, char* server);
int ressurect(int sfd_from, int sfd_to, int fd_from, int fd_to, const char* path, int read_flag);
int corunlink(struct NRF_Data * nrf_data, const char* path);
int update_caches(struct Cache * cache, struct NRF_Data * nrf_data, const char * path);

///////////////////////////////////////////////////////////

/** Get file attributes */
int nrf_getattr(const char *path, struct stat *statbuf)
{
  struct NRF_Data * nrf_data = (struct NRF_Data *) fuse_get_context()->private_data;
  pthread_mutex_lock(nrf_data->lock);

  printf("----  getattr : %s\n", path);

 struct Cache * cache = nrf_data->cache;
  int contains = 0;
  int i=0;
  int num_infos = cache->num_infos;
  struct cache_info * info;
  for(; i<num_infos; i++){
    info = cache->infos[i];
    if(strcmp(info->name, path) == 0){
      int ret = info->retstat;
      memcpy(statbuf, info->statbuf, sizeof(struct stat));
      pthread_mutex_unlock(nrf_data->lock);
      return ret;      
    }
  }


  struct Metadata * metadata = malloc(sizeof(struct Metadata));
  strcpy(metadata->path, path);

  metadata->func_num =  GETATTR;


  //send struct metadata 
  int struct_res = write(nrf_data->servers[0].sfd, metadata, sizeof(struct Metadata));

  struct getattr_ret retst;
  int ret_read = read(nrf_data->servers[0].sfd, &retst, sizeof(struct getattr_ret));


  memcpy(statbuf, &(retst.st), sizeof(struct stat));
 if(retst.ret >= 0){
    if(cache->cache_size - cache->used_size < sizeof(struct stat)){
      struct cache_info * info;
      struct cache_info * evict_info = NULL;
      int j = 0;
      double diff;
      double max_diff = 0;
      for(; j<cache->num_infos; j++){
        info = cache->infos[j];
        time_t now;
        time(&now);
        diff = difftime(now, info->access);
        if(diff > max_diff){
          max_diff = diff;
          evict_info = info;
        }
      }
      if(evict_info != NULL){
        log_msg(nrf_data->logfile, "info cache eviction", nrf_data->diskname, nrf_data->servers[0].server);
        strcpy(evict_info->name, path);
        free(evict_info->statbuf);
        evict_info->statbuf = malloc(sizeof(struct stat));
        memcpy(evict_info->statbuf, &(retst.st), sizeof(struct stat));
        evict_info->retstat = retst.ret;
      }

    }else{

      cache->infos = realloc(cache->infos, (cache->num_infos + 1) * sizeof(struct cache_info *));
      cache->infos[cache->num_infos] = malloc(sizeof(struct cache_info));
      strcpy(cache->infos[cache->num_infos]->name, path);

      cache->infos[cache->num_infos]->statbuf = malloc(sizeof(struct stat));
      memcpy(cache->infos[cache->num_infos]->statbuf, &(retst.st), sizeof(struct stat));
      cache->infos[cache->num_infos]->retstat = retst.ret;

      cache->used_size += sizeof(struct stat);
      cache->num_infos ++;
    }
  }
  pthread_mutex_unlock(nrf_data->lock);
  return retst.ret;
}


/** Create a file node */
int nrf_mknod(const char *path, mode_t mode, dev_t dev)
{
  struct NRF_Data * nrf_data = (struct NRF_Data *) fuse_get_context()->private_data;
  pthread_mutex_lock(nrf_data->lock);


  printf("----  mknod : %s\n", path);

  struct Metadata * metadata = malloc(sizeof(struct Metadata));
  strcpy(metadata->path, path);

  metadata->func_num =  MKNOD;
  metadata->mode = mode;
  int struct_res, ret_read;
  struct_res = write(nrf_data->servers[0].sfd, metadata, sizeof(struct Metadata));

  //return value;
  int retstat;
  ret_read = read(nrf_data->servers[0].sfd, &retstat,  sizeof(int));

  //created on server 1
  if(retstat >= 0 && nrf_data->servers[1].sfd != -1){
    int struct_res, ret_read;
    struct_res = write(nrf_data->servers[1].sfd, metadata, sizeof(struct Metadata));

    //return value;
    int retstat;
    ret_read = read(nrf_data->servers[1].sfd, &retstat,  sizeof(int));

  }

  pthread_mutex_unlock(nrf_data->lock);
  return retstat;
}

/** Create a directory */
int nrf_mkdir(const char *path, mode_t mode)
{
  struct NRF_Data * nrf_data = (struct NRF_Data *) fuse_get_context()->private_data;
  pthread_mutex_lock(nrf_data->lock);

  printf("----  mkdir : %s\n", path);

  //send metadata
  struct Metadata * metadata = malloc(sizeof(struct Metadata));
  strcpy(metadata->path, path);

  metadata->func_num =  MKDIR;
  metadata->mode = mode;
  int struct_res, ret_read;
  struct_res = write(nrf_data->servers[0].sfd, metadata, sizeof(struct Metadata));

  int retstat;
  ret_read = read(nrf_data->servers[0].sfd, &retstat,  sizeof(int));

  if(retstat >= 0 && nrf_data->servers[1].sfd != -1) {
    int struct_res, ret_read;
    struct_res = write(nrf_data->servers[1].sfd, metadata, sizeof(struct Metadata));

    int retstat;
    ret_read = read(nrf_data->servers[1].sfd, &retstat,  sizeof(int));

  }

  pthread_mutex_unlock(nrf_data->lock);
  return retstat;
}

/** Remove a file */
int nrf_unlink(const char *path)
{
  struct NRF_Data * nrf_data = (struct NRF_Data *) fuse_get_context()->private_data;
  pthread_mutex_lock(nrf_data->lock);

  struct Cache * cache = nrf_data->cache;

  printf("----  unlink : %s\n", path);

  //send metadata
  struct Metadata * metadata = malloc(sizeof(struct Metadata));
  strcpy(metadata->path, path);

  metadata->func_num =  UNLINK;
  int struct_res, ret_read;
  struct_res = write(nrf_data->servers[0].sfd, metadata, sizeof(struct Metadata));

  int retstat;
  ret_read = read(nrf_data->servers[0].sfd, &retstat,  sizeof(int));

  if(retstat >= 0 && nrf_data->servers[1].sfd != -1){
    int struct_res, ret_read;
    struct_res = write(nrf_data->servers[1].sfd, metadata, sizeof(struct Metadata));

    int retstat;
    ret_read = read(nrf_data->servers[1].sfd, &retstat,  sizeof(int));
  }

  if(retstat >= 0){
    update_caches(cache, nrf_data, path);
  }

  pthread_mutex_unlock(nrf_data->lock);
  return retstat;
}

/** Remove a directory */
int nrf_rmdir(const char *path)
{
  struct NRF_Data * nrf_data = (struct NRF_Data *) fuse_get_context()->private_data;
  pthread_mutex_lock(nrf_data->lock);
  struct Cache * cache = nrf_data->cache;

  printf("----  rmdir : %s\n", path);

  //send metadata
  struct Metadata * metadata = malloc(sizeof(struct Metadata));
  strcpy(metadata->path, path);

  metadata->func_num =  RMDIR;
  int struct_res, ret_read;
  struct_res = write(nrf_data->servers[0].sfd, metadata, sizeof(struct Metadata));

  //receive return value
  int retstat;
  ret_read = read(nrf_data->servers[0].sfd, &retstat,  sizeof(int));

  if(retstat >= 0 && nrf_data->servers[1].sfd != -1){
    int struct_res, ret_read;
    struct_res = write(nrf_data->servers[1].sfd, metadata, sizeof(struct Metadata));

    //receive return value
    int retstat;
    ret_read = read(nrf_data->servers[1].sfd, &retstat,  sizeof(int));
  }

  if(retstat >= 0){
    int j=0;
    struct cache_info * info;
    for(; j<cache->num_infos; j++){
      info = cache->infos[j];
      if(strcmp(info->name, path) == 0){
        strcpy(info->name, "///");
      } 
    }
  }

  pthread_mutex_unlock(nrf_data->lock);
  return retstat;
}

/** Rename a file */
// both path and newpath are fs-relative
int nrf_rename(const char *path, const char *newpath)
{
  struct NRF_Data * nrf_data = (struct NRF_Data *) fuse_get_context()->private_data;
  pthread_mutex_lock(nrf_data->lock);
  struct Cache * cache = nrf_data->cache;

  printf("----  rename : %s\n", path);

  //send metadata
  struct Metadata * metadata = malloc(sizeof(struct Metadata));
  strcpy(metadata->path, path);
  strcpy(metadata->new_path, newpath);

  metadata->func_num =  RENAME;
  int struct_res, ret_read;
  struct_res = write(nrf_data->servers[0].sfd, metadata, sizeof(struct Metadata));

  int retstat;
  ret_read = read(nrf_data->servers[0].sfd, &retstat,  sizeof(int));

  if(retstat >= 0 && nrf_data->servers[1].sfd != -1){
    int struct_res, ret_read;
    struct_res = write(nrf_data->servers[1].sfd, metadata, sizeof(struct Metadata));

    int retstat;
    ret_read = read(nrf_data->servers[1].sfd, &retstat,  sizeof(int));
  }


  if(retstat >= 0){
    update_caches(cache, nrf_data, path);
  }

  pthread_mutex_unlock(nrf_data->lock);
  return retstat;
}

/** Change the size of a file */
int nrf_truncate(const char *path, off_t newsize)
{
  struct NRF_Data * nrf_data = (struct NRF_Data *) fuse_get_context()->private_data;
  pthread_mutex_lock(nrf_data->lock);

  struct Cache * cache = nrf_data->cache;

  printf("----  truncate : %s\n", path);

  //send metadata
  struct Metadata * metadata = malloc(sizeof(struct Metadata));
  strcpy(metadata->path, path);

  metadata->func_num =  TRUNCATE;
  metadata->new_size = newsize;
  int struct_res, ret_read;
  struct_res = write(nrf_data->servers[0].sfd, metadata, sizeof(struct Metadata));

  //receive return value
  int retstat;
  ret_read = read(nrf_data->servers[0].sfd, &retstat,  sizeof(int));

  if(retstat >= 0 && nrf_data->servers[1].sfd != -1){
    int struct_res, ret_read;
    struct_res = write(nrf_data->servers[1].sfd, metadata, sizeof(struct Metadata));

    //receive return value
    int retstat;
    ret_read = read(nrf_data->servers[1].sfd, &retstat,  sizeof(int));
  }

  pthread_mutex_unlock(nrf_data->lock);
  return retstat;
}


/** File open operation */
int nrf_open(const char *path, struct fuse_file_info *fi)
{

  struct NRF_Data * nrf_data = (struct NRF_Data *) fuse_get_context()->private_data;
  pthread_mutex_lock(nrf_data->lock);


  printf("----  open : %s\n", path);

  //send metadata
  struct Metadata * metadata = malloc(sizeof(struct Metadata));
  strcpy(metadata->path, path);

  metadata->func_num =  OPEN;
  metadata->flags = fi->flags;
  int struct_res, ret_read;
  struct_res = write(nrf_data->servers[0].sfd, metadata, sizeof(struct Metadata));


  char file_hash[33];
  char sys_file_hash[33];
  read(nrf_data->servers[0].sfd, file_hash, 33);
  read(nrf_data->servers[0].sfd, sys_file_hash, 33);

  //receive return value
  int retstat;
  ret_read = read(nrf_data->servers[0].sfd, &retstat,  sizeof(int));
  fi->fh = retstat;

  if(retstat > 0){
    retstat = 0;
  }

  if(retstat >= 0 && nrf_data->servers[1].sfd != -1){
    int struct_res, ret_read;
    struct_res = write(nrf_data->servers[1].sfd, metadata, sizeof(struct Metadata));



    char file_hash_srv2[33];
    char sys_file_hash_srv2[33];
    read(nrf_data->servers[1].sfd, file_hash_srv2, 33);
    read(nrf_data->servers[1].sfd, sys_file_hash_srv2, 33);



    //receive return value
    int retstat;
    ret_read = read(nrf_data->servers[1].sfd, &retstat,  sizeof(int));

    //instead of saving second server fd into fi->fh ill save it in srtw_files
    //fi->fh = retstat;

    struct srtw_file * srtw_f = malloc(sizeof(struct srtw_file));
    strcpy(srtw_f->file_name, path);
    srtw_f->fd = retstat;
    
    nrf_data->srtw_files = realloc(nrf_data->srtw_files, (nrf_data->srtw_idx + 1) * sizeof(struct srtw_file *));

    nrf_data->srtw_files[nrf_data->srtw_idx] = malloc(sizeof(struct srtw_file));
    memcpy(nrf_data->srtw_files[nrf_data->srtw_idx], srtw_f, sizeof(struct srtw_file));
    nrf_data->srtw_idx ++;


    if(retstat >= 0){

      if(strcmp(file_hash, sys_file_hash) != 0 && strcmp(file_hash_srv2, sys_file_hash_srv2) == 0){
        log_msg(nrf_data->logfile, "about to restore data from server2 to server1", nrf_data->diskname, nrf_data->servers[0].server);
        ressurect(nrf_data->servers[1].sfd, nrf_data->servers[0].sfd, retstat, fi->fh, path, 0);
      }
      if(strcmp(file_hash_srv2, sys_file_hash_srv2) != 0 || strcmp(sys_file_hash, sys_file_hash_srv2) != 0){
        log_msg(nrf_data->logfile, "about to restore data from server1 to server2", nrf_data->diskname, nrf_data->servers[1].server);
        ressurect(nrf_data->servers[0].sfd, nrf_data->servers[1].sfd, fi->fh, retstat, path, 0);
      }
      if(strcmp(file_hash, sys_file_hash) != 0 && strcmp(file_hash_srv2, sys_file_hash_srv2) != 0){
        log_msg(nrf_data->logfile, "file corrupted on both server, deleting file from server1 and server2", nrf_data->diskname, nrf_data->servers[0].server);
        corunlink(nrf_data, path);
      }

      retstat = 0;
    }
  }

  pthread_mutex_unlock(nrf_data->lock);
  return retstat;
}

/** Read data from an open file */
int nrf_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
{
  struct NRF_Data * nrf_data = (struct NRF_Data *) fuse_get_context()->private_data;
  pthread_mutex_lock(nrf_data->lock);


  printf("----  read\n");

  struct Cache * cache = nrf_data->cache;

  int contains = 0;

  int i=0;
  int num_files = cache->num_files;

  struct cache_file * file;
  for(; i<num_files; i++){
    file = cache->files[i];
    if(file->size == size && file->offset == offset && strcmp(file->name, path) == 0){
      log_msg(nrf_data->logfile, "reading data from cache", nrf_data->diskname, nrf_data->servers[0].server);
      memcpy(buf, file->data, size);
      time(&file->access);
      pthread_mutex_unlock(nrf_data->lock);
      return size;
    }
  }


  struct Metadata * metadata = malloc(sizeof(struct Metadata));
  strcpy(metadata->path, path);

  metadata->func_num = READ;
  metadata->size =  size;
  metadata->offset = offset;
  metadata->read_fd = fi->fh;
  metadata->xvar = 0;

  int struct_res, res, ret_read; 
  struct_res = write(nrf_data->servers[0].sfd, metadata, sizeof(struct Metadata));
 
  res = read(nrf_data->servers[0].sfd, buf, size);  

  if(size < (cache->cache_size * 2) / 3){
    while(size > cache->cache_size - cache->used_size){
      struct cache_file * file;
      struct cache_file * evict_file = NULL;
      int j = 0;
      double diff;
      double max_diff = 0;
      for(; j<cache->num_files; j++){
        file = cache->files[j];
        time_t now;
        time(&now);
        diff = difftime(now, file->access);
        if(diff >= max_diff && strcmp(file->name, "///") != 0){
          max_diff = diff;
          evict_file = file;
        }
      }
      if(evict_file != NULL){
        cache->used_size -= evict_file->size;
        strcpy(evict_file->name, "///");
        free(evict_file->data);
      }else{
        break;
      }
    }
  }

  cache->files = realloc(cache->files, (cache->num_files + 1) * sizeof(struct cache_file *));

  struct cache_file * new_file = malloc(sizeof(struct cache_file));
  strcpy(new_file->name, path);
  new_file->size = size;
  new_file->offset = offset;

  time(&(new_file->access));

  new_file->data = malloc(size);
  memcpy(new_file->data, buf, size); 

  cache->files[cache->num_files] = malloc(sizeof(struct cache_file));
  memcpy(cache->files[cache->num_files], new_file, sizeof(struct cache_file));
  cache->used_size += size;
  cache->num_files++;
 
  int retstat = 0;
  ret_read = read(nrf_data->servers[0].sfd, &retstat,  sizeof(int));
  pthread_mutex_unlock(nrf_data->lock);
  return retstat;
}
  
/** Write data to an open file */
int nrf_write(const char *path, const char *buf, size_t size, off_t offset,
       struct fuse_file_info *fi)
{
  struct NRF_Data * nrf_data = (struct NRF_Data *) fuse_get_context()->private_data;
  pthread_mutex_lock(nrf_data->lock);
  struct Cache * cache = nrf_data->cache;


  //printf("----  write : %s\n", path);

  struct Metadata * metadata = malloc(sizeof(struct Metadata));
  strcpy(metadata->path, path);

  metadata->func_num = WRITE;
  metadata->size =  size;
  metadata->offset = offset;
  metadata->write_fd = fi->fh;
  metadata->xvar = DEFAULT;

  int struct_res, ret_read, res; 
  struct_res = write(nrf_data->servers[0].sfd, metadata, sizeof(struct Metadata));

  res = write(nrf_data->servers[0].sfd, buf, size);

  int retstat;
  ret_read = read(nrf_data->servers[0].sfd, &retstat,  sizeof(int));

  if(retstat >= 0  && nrf_data->servers[1].sfd != -1){
    int i;
    for(i=0; i<nrf_data->srtw_idx; i++){
      if(strcmp(nrf_data->srtw_files[i]->file_name, path) == 0){
        metadata->write_fd = nrf_data->srtw_files[i]->fd;
        break;
      } 
    }

   
    int struct_res, ret_read, res; 
    struct_res = write(nrf_data->servers[1].sfd, metadata, sizeof(struct Metadata));

    res = write(nrf_data->servers[1].sfd, buf, size);

    int retstat;
    ret_read = read(nrf_data->servers[1].sfd, &retstat,  sizeof(int));
  }

  if(retstat >= 0){
    int i=0;
    struct cache_file * file;
    for(; i<cache->num_files; i++){
      file = cache->files[i];
      if(strcmp(file->name, path) == 0){// && (size + offset) <= file->size + file->offset){
        //memcpy(file->data + offset, buf, size);
        //time(&(file->access));
        strcpy(file->name, "///");
        free(file->data);
      }
    }
    int j=0;
    struct cache_info * info;
    for(; j<cache->num_infos; j++){
      info = cache->infos[j];
      if(strcmp(info->name, path) == 0){
        info->statbuf->st_size = size + offset;
      } 
    }
  }

  pthread_mutex_unlock(nrf_data->lock);
  return retstat;
}


/** Release an open file */
int nrf_release(const char *path, struct fuse_file_info *fi)
{
  struct NRF_Data * nrf_data = (struct NRF_Data *) fuse_get_context()->private_data;
  pthread_mutex_lock(nrf_data->lock);


  printf("----  release : %s\n", path);

  struct Metadata * metadata = malloc(sizeof(struct Metadata));
  strcpy(metadata->path, path);

  metadata->func_num = RELEASE;
  metadata->read_fd = fi->fh;
  int struct_res, ret_read;
  struct_res = write(nrf_data->servers[0].sfd, metadata, sizeof(struct Metadata));

  int retstat = 0;
  ret_read = read(nrf_data->servers[0].sfd, &retstat,  sizeof(int));

  if(retstat >=0  && nrf_data->servers[1].sfd != -1){
    int i;
    for(i=0; i<nrf_data->srtw_idx; i++){
      if(strcmp(nrf_data->srtw_files[i]->file_name, path) == 0){
        metadata->read_fd = nrf_data->srtw_files[i]->fd;
        //strcpy(nrf_data->srtw_files[i]->file_name, "///");
        break;
     } 
    }

    int struct_res, ret_read;
    struct_res = write(nrf_data->servers[1].sfd, metadata, sizeof(struct Metadata));

    int retstat = 0;
    ret_read = read(nrf_data->servers[1].sfd, &retstat,  sizeof(int));
  }

  pthread_mutex_unlock(nrf_data->lock);
  return retstat;
}

/** Open directory */
int nrf_opendir(const char *path, struct fuse_file_info *fi)
{
  struct NRF_Data * nrf_data = (struct NRF_Data *) fuse_get_context()->private_data;
  pthread_mutex_lock(nrf_data->lock);


  printf("----  opendir : %s\n", path);

  struct Metadata * metadata = malloc(sizeof(struct Metadata));
  strcpy(metadata->path, path);

  metadata->func_num = OPENDIR;
  int struct_res, ret_read, struct_read;
  struct_res = write(nrf_data->servers[0].sfd, metadata, sizeof(struct Metadata));

  struct opendir_ret opendirr;

  struct_read = read (nrf_data->servers[0].sfd, &opendirr, sizeof(struct opendir_ret));

  fi->fh = (intptr_t)opendirr.dp;
  int ret = opendirr.ret;
  
  pthread_mutex_unlock(nrf_data->lock);
  return ret;
}

/** Read directory */
int nrf_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset,
         struct fuse_file_info *fi)
{
  struct NRF_Data * nrf_data = (struct NRF_Data *) fuse_get_context()->private_data; 
  pthread_mutex_lock(nrf_data->lock);


  printf("----  readdir : %s\n", path);

  struct Metadata * metadata = malloc(sizeof(struct Metadata));
  strcpy(metadata->path, path);

  metadata->func_num = READDIR;
  metadata->readdir_fd = (DIR *) (uintptr_t)fi->fh; 
  int struct_res, ret_read;
  struct_res = write(nrf_data->servers[0].sfd, metadata, sizeof(struct Metadata));


  struct readdir_ret readdirr;
  int struct_read = read (nrf_data->servers[0].sfd, &readdirr, sizeof(struct readdir_ret));

  char readdir[readdirr.strlen];
  int ress = read(nrf_data->servers[0].sfd, readdir, readdirr.strlen);  


  const char s[] = "/";
  char *token;

  token = strtok(readdir, s);

  while( token != NULL ) {
    if (filler(buf, token, NULL, 0) != 0) {

    //  int retstat;
      readdirr.ret = -ENOMEM;
    }

    token = strtok(NULL, s);
  }

  pthread_mutex_unlock(nrf_data->lock);
  return readdirr.ret;
}

/** Release directory */
int nrf_releasedir(const char *path, struct fuse_file_info *fi)
{
  struct NRF_Data * nrf_data = (struct NRF_Data *) fuse_get_context()->private_data; 
  pthread_mutex_lock(nrf_data->lock);


  printf("----  releasedir : %s\n", path);

  struct Metadata * metadata = malloc(sizeof(struct Metadata));

  metadata->func_num = RELEASEDIR;
  metadata->readdir_fd = (DIR *) (uintptr_t) fi->fh;
  int struct_res, ret_read;
  struct_res = write(nrf_data->servers[0].sfd, metadata, sizeof(struct Metadata));
  
/*
  int retstat;
  ret_read = read(sfds[0], &retstat,  sizeof(int));
*/

  pthread_mutex_unlock(nrf_data->lock);
  return 0;
}

struct fuse_operations nrf_oper = {
  .getattr = nrf_getattr,
  .mknod = nrf_mknod,
  .mkdir = nrf_mkdir,
  .unlink = nrf_unlink,
  .rmdir = nrf_rmdir,
  .rename = nrf_rename,
  .truncate = nrf_truncate,
  .open = nrf_open,
  .read = nrf_read,
  .write = nrf_write,
  .release = nrf_release,
  .opendir = nrf_opendir,
  .readdir = nrf_readdir,
  .releasedir = nrf_releasedir,
};

int client(char* server, int i, struct NRF_Data * nrf_data){
	printf("SERVER  %s\n", server);
  char server_tmp[256];
  strcpy(server_tmp, server);
  char* token;
  token = strtok (server, ":"); //IP

  struct sockaddr_in addr;
  int ip;
  int sfd = socket(AF_INET, SOCK_STREAM, 0);
  inet_pton(AF_INET, token, &ip);

  
  token = strtok (NULL, ":");  //PORT

  int port = atoi (token);

  addr.sin_family = AF_INET;  
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = ip;

  struct Server * srv = malloc(sizeof(struct Server));
  strcpy(srv->server, server_tmp);
  srv->sfd = sfd;
  memcpy(&nrf_data->servers[i], srv, sizeof(struct Server));  

  connect(sfd, (struct sockaddr *) &addr, sizeof(struct sockaddr_in));
  log_msg(nrf_data->logfile, "open connection", nrf_data->diskname, server_tmp);
 // close(sfd);
}

int log_msg(FILE* logfile, char* msg, char* diskname, char* server){
  time_t rawtime;
  struct tm * timeinfo;
  time ( &rawtime );
  timeinfo = localtime ( &rawtime );
  char res_time[256];
  strcpy(res_time, asctime (timeinfo));
  res_time[strlen(res_time)-1] = '\0';

  char res_msg[1024];
  strcpy(res_msg, "[");
  strcat(res_msg, res_time);
  strcat(res_msg, "] ");
  strcat(res_msg, diskname);
  strcat(res_msg, "  ");
  strcat(res_msg, server);
  strcat(res_msg, "  ");

  strcat(res_msg, msg);
  fprintf(logfile, "%s\n", res_msg);
  fflush(logfile);
}

int ressurect(int sfd_from, int sfd_to, int fd_from, int fd_to, const char* path, int read_flag){

  //printf("SFD_FROM   /   SFD_TO   /   FD_FROM   /   FD_TO  /   PATH  %d / %d /  %d  /  %d  / %s\n",
    //     sfd_from, sfd_to, fd_from, fd_to, path);

  size_t size = 4096;
  off_t offset = 0;
  struct Metadata * metadata = malloc(sizeof(struct Metadata));
  while(1){
    strcpy(metadata->path, path);

    metadata->func_num = READ;
    metadata->size =  size;
    metadata->offset = offset;
    metadata->read_fd = fd_from;
    metadata->xvar = read_flag;

    int struct_res, res, ret_read; 
    struct_res = write(sfd_from, metadata, sizeof(struct Metadata));

    char buf[size];
    res = read(sfd_from, buf, size);  

    int retstat = 0;
    ret_read = read(sfd_from, &retstat,  sizeof(int));

    if(retstat <= 0) break;

    strcpy(metadata->path, path);

    metadata->func_num = WRITE;
    metadata->size =  retstat;
    metadata->offset = offset;
    metadata->write_fd = fd_to;
    metadata->xvar = BU_REST;
    if(offset == 0)
      metadata->xvar = BU_FIRST_CHUNK;

    struct_res = write(sfd_to, metadata, sizeof(struct Metadata));

    res = write(sfd_to, buf, retstat);

    retstat;
    ret_read = read(sfd_to, &retstat,  sizeof(int));


    offset += retstat;

  }
}

int corunlink(struct NRF_Data * nrf_data, const char* path){
  struct Metadata * metadata = malloc(sizeof(struct Metadata));
  strcpy(metadata->path, path);

  metadata->func_num =  UNLINK;
  int struct_res, ret_read;
  struct_res = write(nrf_data->servers[0].sfd, metadata, sizeof(struct Metadata));

  int retstat;
  ret_read = read(nrf_data->servers[0].sfd, &retstat,  sizeof(int));

  if(retstat >= 0){
    int struct_res, ret_read;
    struct_res = write(nrf_data->servers[1].sfd, metadata, sizeof(struct Metadata));

    int retstat;
    ret_read = read(nrf_data->servers[1].sfd, &retstat,  sizeof(int));
  }

  return retstat;
}

int cache_init(struct Config * config, struct NRF_Data * nrf_data){
  char cache_size[64];
  strcpy(cache_size, config->cache_size);
  char gmkb = cache_size[strlen(cache_size)-1];
  cache_size[strlen(cache_size)-1] = '\0';

  struct Cache * cache = malloc(sizeof(struct Cache));

  int cache_size_int = atoi(cache_size);
  if(gmkb == 'B')
    cache_size_int = cache_size_int * 1;
  else if(gmkb == 'K')
    cache_size_int = cache_size_int * 1024;  
  else if(gmkb == 'M')
    cache_size_int = cache_size_int * 1024 * 1024;
  else if(gmkb == 'G')
    cache_size_int = cache_size_int * 1024 * 1024 * 1024;
  else{
    printf("%s\n", "Invalid cache size format");
    exit(-1);
  }

  cache->cache_size = cache_size_int;
  cache->used_size = 0;
  cache->num_files = 0;
  cache->num_infos = 0;

  nrf_data->cache = malloc(sizeof(struct Cache));
  memcpy(nrf_data->cache, cache, sizeof(struct Cache));
  log_msg(nrf_data->logfile, "cache init", nrf_data->diskname, nrf_data->servers[0].server);
}

int hotswap(int sfd, int hotswap_sfd, pthread_t tid, struct NRF_Data * nrf_data){
  struct Metadata * metadata = malloc(sizeof(struct Metadata));
  metadata->func_num = HOTSWAP;
  write(sfd, metadata, sizeof(struct Metadata));

  struct hotswap_ret ** regdir_arr = malloc(0);
  int arr_length = 0;
  while(1){
    struct hotswap_ret * retst = malloc(sizeof(struct hotswap_ret));
    read(sfd, retst, sizeof(struct hotswap_ret));
    if(retst->regdir == -1)
      break;

    regdir_arr = realloc(regdir_arr, (arr_length + 1) * sizeof(struct hotswap_ret * ));
    regdir_arr[arr_length] = malloc(sizeof(struct hotswap_ret));
    memcpy(regdir_arr[arr_length], retst, sizeof(struct hotswap_ret));
    arr_length ++;
    
    //printf("DIR REG | %d\n", retst.regdir);
    //printf("PATH    | %s\n", retst.path);
  }

  int i=0;
  for(; i < arr_length; i++){
    if(regdir_arr[i]->regdir == 0){//dir

      strcpy(metadata->path, regdir_arr[i]->path);
      metadata->func_num =  MKDIR;
      metadata->mode = 0000777;
      write(hotswap_sfd, metadata, sizeof(struct Metadata));
      int retstat;
      read(hotswap_sfd, &retstat,  sizeof(int));

    }else{//file

      strcpy(metadata->path, regdir_arr[i]->path);
      metadata->func_num =  MKNOD;
      metadata->mode = 0000777;
      write(hotswap_sfd, metadata, sizeof(struct Metadata));
      int retstat;
      read(hotswap_sfd, &retstat,  sizeof(int));
      //int ressurect(int sfd_from, int sfd_to, int fd_from, int fd_to, const char* path, int read_flag);
      ressurect(sfd, hotswap_sfd, -1, -1, regdir_arr[i]->path, 1);

    }
  }

  //actual hotswap
  nrf_data->servers[tid] = nrf_data->servers[2];

  printf("%s\n", "--------------------------------------------");
  printf("DONE%s\n", " HOTSWAP");
  printf("%s\n", "--------------------------------------------");
}

void *thread_f(void *data)
{
  struct hotswap_data * htd = (struct hotswap_data *)data;

  char server[256];
  if(htd->tid == 0)
    strcpy(server, htd->nrf_data->servers[0].server);
  else 
    strcpy(server, htd->nrf_data->servers[1].server);

  int x = -1;
  int res = 100;
  time_t t;
  int flag = 0;
  int flag1 = 0;
  struct Metadata * metadata = malloc(sizeof(struct Metadata));

  while(1){
    if(*htd->status != 500){
      pthread_mutex_lock(htd->nrf_data->lock);

      metadata->func_num = -1;
      write(htd->sfd0, metadata, sizeof(struct Metadata));

      read(htd->sfd0, &res, sizeof(int));

      if(*htd->status == 200 && res == 100){
        if(flag1 == 0){
          flag1 = 1;
          time(&t);
        }else{
          time_t now;
          time(&now);
          double diff = difftime(now, t);
          log_msg(htd->nrf_data->logfile, "waiting for connection ... ", htd->nrf_data->diskname, htd->nrf_data->servers[htd->tid].server);
          printf("#########  WAITING...  %f\n", diff);
          if(diff >= htd->nrf_data->timeout){
            printf("%s\n", "--------------------------------------------");
            printf("%s%s\n", "LOST CONNECTION AFTER HOTSWAP | server - ", htd->nrf_data->servers[htd->tid].server);
            printf("%s\n", "--------------------------------------------");
            if(htd->tid == 0){
              log_msg(htd->nrf_data->logfile, "server declared as lost", htd->nrf_data->diskname, htd->nrf_data->servers[htd->tid].server);
              htd->nrf_data->servers[0] = htd->nrf_data->servers[1];
              htd->nrf_data->servers[1].sfd = -1;
              //pthread_exit(0);
            }else{
              htd->nrf_data->servers[1].sfd = -1;
            }
            *htd->status = 500;
          }
        }
      }

      if(*htd->status != 200 && *htd->status != 500){
        if(res == 100 && flag == 0){
          flag = 1;
          time(&t);
        }
        else if(res == 100 && flag == 1){
          time_t now;
          time(&now);
          double diff;
          diff = difftime(now, t);
          char buf[256];
          log_msg(htd->nrf_data->logfile, "waiting for connection ... ", htd->nrf_data->diskname, server);
          printf("#########  WAITING...  %f\n", diff);
          if(diff >= htd->nrf_data->timeout){
            log_msg(htd->nrf_data->logfile, "server declared as lost", htd->nrf_data->diskname, server);
            hotswap(htd->sfd1, htd->nrf_data->servers[2].sfd, htd->tid, htd->nrf_data);
            *htd->status = 200;
            htd->sfd0 = htd->nrf_data->servers[2].sfd;
          }
        }
        if(res == -1 && flag == 1){
          log_msg(htd->nrf_data->logfile, "the connection was restored", htd->nrf_data->diskname, server);
          flag = 0;
        }else if(res == -1 && flag1 == 1){
          log_msg(htd->nrf_data->logfile, "the connection was restored", htd->nrf_data->diskname, server);
          flag = 0;
        }
      }
      res = 100;
      pthread_mutex_unlock(htd->nrf_data->lock);
      sleep(1);
    }
  }

  return NULL;
}

int update_caches(struct Cache * cache, struct NRF_Data * nrf_data, const char * path){
  int i=0;
  struct cache_file * file;
  for(; i<cache->num_files; i++){
    file = cache->files[i];
    if(strcmp(file->name, path) == 0){
      strcpy(file->name, "///");
      cache->used_size -= file->size;
      free(file->data);
    }
  }

  int j=0;
  struct cache_info * info;
  for(; j<cache->num_infos; j++){
    info = cache->infos[j];
    if(strcmp(info->name, path) == 0){
      strcpy(info->name, "///");
      cache->used_size -= sizeof(struct stat);
      free(info->statbuf);
    } 
  }

  int k=0;
  for(; k<nrf_data->srtw_idx; k++){
    if(strcmp(nrf_data->srtw_files[k]->file_name, path) == 0){
      strcpy(nrf_data->srtw_files[k]->file_name, "///");
    } 
  }
}

int main(int argc, char *argv[])
{

  struct Config * config = malloc(sizeof(struct Config));

  int res = config_parser(argv[1], config);

  if(res == -1){
    printf("%s\n", "Invalid config file format");
    return -1;
  }


  int status = 0;
  pid_t wpid;
  pthread_mutex_t lock;
  pthread_mutex_init(&lock, NULL);

  FILE* logfile = fopen(config->errorlog, "a+");
  int storage_num = config->num_storages;
  int j;
  for(j = 0; j<storage_num; j++){
    pid_t pid = fork();
    if(pid == 0){ //child
      struct NRF_Data * nrf_data = malloc(sizeof(struct NRF_Data));
      //basic data init
      strcpy(nrf_data->diskname, config->disk_configs[j].diskname);
      nrf_data->logfile = logfile;
      nrf_data->srtw_idx = 0;
      nrf_data->lock = &lock;
      nrf_data->timeout = config->timeout;


      //client init
      int num_servers = config->disk_configs[j].num_servers;
      num_servers = 2; //raid 1
      int i;
      for(i = 0; i < num_servers; i++)
        client(config->disk_configs[j].servers[i], i, nrf_data);

      client(config->disk_configs[j].hotswap, 2, nrf_data); 

      pthread_t tid0 = 0;
      pthread_t tid1 = 1;
      int status = -1;
      struct hotswap_data htd0;
      struct hotswap_data htd1;
      htd0.sfd0 = nrf_data->servers[0].sfd;
      htd0.sfd1 = nrf_data->servers[1].sfd;
      htd0.tid = tid0;
      htd0.stid = tid1;
      htd0.nrf_data = nrf_data;
      htd0.status = &status;

      htd1.sfd0 = nrf_data->servers[1].sfd;
      htd1.sfd1 = nrf_data->servers[0].sfd;
      htd1.tid = tid1;
      htd1.stid = tid0;
      htd1.nrf_data = nrf_data;
      htd1.status = &status;

      pthread_create(&tid0, NULL, thread_f, &htd0);
      pthread_create(&tid1, NULL, thread_f, &htd1);

/*      pthread_join(tid0, NULL);
      pthread_join(tid1, NULL);*/

      //cache init
      cache_init(config, nrf_data);

      char* n_argv[3];
      n_argv[0] = malloc(256);
      strcpy(n_argv[0], argv[0]);
      n_argv[1] = malloc(256);
      strcpy(n_argv[1], "-f");
      n_argv[2] = malloc(256);
      strcpy(n_argv[2], config->disk_configs[j].mountpoint);

      exit(fuse_main( 3, n_argv, &nrf_oper, nrf_data ));
    }
  }

  while((wpid = wait(&status)) > 0);
 
}
