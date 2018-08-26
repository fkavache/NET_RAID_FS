#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h> /* superset of previous */
#include <unistd.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <utime.h>
#include <dirent.h>
#include "../utils.h"
#include <stdint.h>
#include <openssl/md5.h>
#include <sys/types.h> 
#include <sys/xattr.h>
#include <sys/epoll.h>
#include <fts.h>

#define BACKLOG 10

int socket_handler (struct Metadata * metadata, int cfd, char* storagedir);

int getattr_socket (struct Metadata * metadata, int cfd, char* storagedir);
int mknod_socket   (struct Metadata * metadata, int cfd, char* storagedir);
int mkdir_socket   (struct Metadata * metadata, int cfd, char* storagedir);
int unlink_socket  (struct Metadata * metadata, int cfd, char* storagedir);
int rmdir_socket   (struct Metadata * metadata, int cfd, char* storagedir);
int rename_socket  (struct Metadata * metadata, int cfd, char* storagedir);
int truncate_socket(struct Metadata * metadata, int cfd, char* storagedir);
int open_socket    (struct Metadata * metadata, int cfd, char* storagedir);
int read_socket    (struct Metadata * metadata, int cfd, char* storagedir);
int write_socket   (struct Metadata * metadata, int cfd, char* storagedir);
int release_socket (struct Metadata * metadata, int cfd, char* storagedir);
int opendir_socket (struct Metadata * metadata, int cfd, char* storagedir);
int readdir_socket (struct Metadata * metadata, int cfd, char* storagedir);
int release_socket (struct Metadata * metadata, int cfd, char* storagedir);
int hotswap_socket (struct Metadata * metadata, int cfd, char* storagedir);

char* file_fpath(char* file_name, char* storagedir);

//stackoverflow code
int hash(char * filename, char* hash){
    int MD_DIGEST_LENGTH = 16;
    unsigned char c[MD_DIGEST_LENGTH];

    int i;
    FILE *inFile = fopen (filename, "rb");
    MD5_CTX mdContext;
    int bytes;
    unsigned char data[1024];

    if (inFile == NULL) {
        printf ("%s can't be opened.\n", filename);
        return 0;
    }

    MD5_Init (&mdContext);
    while ((bytes = fread (data, 1, 1024, inFile)) != 0)
        MD5_Update (&mdContext, data, bytes);

    MD5_Final (c,&mdContext);

    char md5string[33];
    for(int i = 0; i < 16; ++i)
      sprintf(&md5string[i*2], "%02x", (unsigned int)c[i]);

    strcpy(hash, md5string);
    fclose (inFile);

    return 0;
}

int main(int argc, char* argv[]){

  int sfd, cfd;
  struct sockaddr_in addr;
  struct sockaddr_in peer_addr;
  int port = atoi(argv[2]);

  sfd = socket(AF_INET, SOCK_STREAM, 0);
  int optval = 1;
  setsockopt(sfd, SOL_SOCKET,(SO_REUSEPORT | SO_REUSEADDR),(char*)&optval,sizeof(optval));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = htonl(INADDR_ANY);
  bind(sfd, (struct sockaddr *) &addr, sizeof(struct sockaddr_in));
  listen(sfd, BACKLOG);
  int peer_addr_size = sizeof(struct sockaddr_in);

  printf("%s\n", "Waiting   ---------------------------------   ");
  cfd = accept(sfd, (struct sockaddr *) &peer_addr, &peer_addr_size);
  printf("%s\n", "Connected ---------------------------------   ");



  int epoll_fd = epoll_create(1);
  struct epoll_event e;
  struct epoll_event es[1];
  e.events = EPOLLIN;
  e.data.fd = cfd;
  epoll_ctl(epoll_fd, EPOLL_CTL_ADD, cfd, &e);

  while(1){
    int ready = epoll_wait(epoll_fd, es, 1, -1);
    int i = 0;
    for(; i < ready; i++){
      int curr_fd = es[i].data.fd;
      struct Metadata * metadata = malloc(sizeof(struct Metadata));
      int read_res = read (curr_fd, metadata, sizeof(struct Metadata));
      socket_handler(metadata, curr_fd, argv[3]);
    }
  }

  close(cfd);
  close(sfd);
}

int getattr_socket(struct Metadata * metadata, int cfd, char* storagedir){

  char file_name[256];
  strcpy(file_name, metadata->path);

  char* file_path = file_fpath(file_name, storagedir);

  struct getattr_ret retst;

  int retstat = 0;
  retstat = lstat(file_path, &(retst.st));
  if(retstat < 0)
    retstat = -errno;

  retst.ret = retstat;

/*  printf("\n################## SOCKET GETATTR INFO ##################\n");
  printf("# FILE NAME ---  %s\n# FILE PATH ---  %s\n# RETVAL --- %d\n", file_name, file_path, retstat);
  printf("################## SOCKET GETATTR INFO ##################\n");*/

  int struct_res;
  struct_res = write(cfd, &retst, sizeof(struct getattr_ret));
  return retstat;
}

int mknod_socket(struct Metadata * metadata, int cfd, char* storagedir){

  char file_name[256];
  strcpy(file_name, metadata->path);
  char* file_path = file_fpath(file_name, storagedir);

  int retstat = open(file_path, O_CREAT | O_EXCL | O_WRONLY, metadata->mode);

  //---------------------------------------------

  char file_hash[33];
  hash(file_path, file_hash);

  setxattr(file_path, "user.hash", file_hash, 33, 0);

  //---------------------------------------------

  if (retstat >= 0)
      retstat = close(retstat);

  if(retstat < 0)
   retstat = -errno;

  int write_res = write(cfd, &retstat, sizeof(int));
/*
  printf("\n################## SOCKET MKNOD INFO ##################\n");
  printf("# FILE NAME --- %s\n# FILE PATH --- %s\n# RETVALUE --- %d\n", file_name, file_path, retstat);
  printf("################## SOCKET MKNOD INFO ##################\n");*/

  return retstat;
}


int mkdir_socket(struct Metadata * metadata, int cfd, char* storagedir){
  char file_name[256];
  strcpy(file_name, metadata->path);

  char* file_path = file_fpath(file_name, storagedir);

  int retstat = mkdir(file_path, metadata->mode);
  if(retstat < 0)
    retstat = -errno;

/*  printf("\n################## SOCKET MKDIR INFO ##################\n");
  printf("# FILE NAME --- %s\n# FILE PATH --- %s\n# RETVALUE --- %d\n", file_name, file_path, retstat);
  printf("################## SOCKET MKDIR INFO ##################\n");*/

  int write_res = write(cfd, &retstat, sizeof(int));

  return retstat;
}


int unlink_socket(struct Metadata * metadata, int cfd, char* storagedir){
  char file_name[256];
  strcpy(file_name, metadata->path);

  char* file_path = file_fpath(file_name, storagedir);

  int retstat = unlink(file_path);
  if(retstat < 0)
    retstat = -errno;
/*
  printf("\n################## SOCKET UNLINK INFO ##################\n");
  printf("# FILE NAME --- %s\n# FILE PATH --- %s\n# RETVALUE --- %d\n", file_name, file_path, retstat);
  printf("################## SOCKET UNLINK INFO ##################\n");*/

  int write_res = write(cfd, &retstat, sizeof(int));

  return retstat;
}


int rmdir_socket(struct Metadata * metadata, int cfd, char* storagedir){
  char file_name[256];
  strcpy(file_name, metadata->path);

  char* file_path = file_fpath(file_name, storagedir);

  int retstat = rmdir(file_path);
  if(retstat < 0)
    retstat = -errno;

/*  printf("\n################## SOCKET UNLINK INFO ##################\n");
  printf("# FILE NAME --- %s\n# FILE PATH --- %s\n# RETVALUE --- %d\n", file_name, file_path, retstat);
  printf("################## SOCKET UNLINK INFO ##################\n");*/

  int write_res = write(cfd, &retstat, sizeof(int));
  
  return retstat;
}

int rename_socket(struct Metadata * metadata, int cfd, char* storagedir){
  char file_name[256];
  strcpy(file_name, metadata->path);

  char file_new_name[256];
  strcpy(file_new_name, metadata->new_path);

  char* file_path = file_fpath(file_name, storagedir);
  char* file_new_path = file_fpath(file_new_name, storagedir);
  
  int retstat = rename(file_path, file_new_path);
  if(retstat < 0)
    retstat = -errno;
/*
  printf("\n################## SOCKET RENAME INFO ##################\n");
  printf("# FILE NAME --- %s\n# FILE PATH --- %s\n# FILE NEW NAME --- %s\n# FILE NEW PATH --- %s\n# RETVALUE --- %d\n", 
    file_name, file_path, file_new_name, file_new_path, retstat);
  printf("################## SOCKET RENAME INFO ##################\n");*/

  int write_res = write(cfd, &retstat, sizeof(int));

  return retstat;
}

int truncate_socket(struct Metadata * metadata, int cfd, char* storagedir){
  char file_name[256];
  strcpy(file_name, metadata->path);

  char* file_path = file_fpath(file_name, storagedir);

  int retstat = truncate(file_path, metadata->new_size);
  if(retstat < 0)
    retstat = -errno;

/*  printf("\n################## SOCKET TRUNCATE INFO ##################\n");
  printf("# FILE NAME --- %s\n# FILE PATH --- %s\n# NEW SIZE --- %ld\n# RETVALUE --- %d\n", file_name, file_path, metadata->new_size, retstat);
  printf("################## SOCKET TRUNCATE INFO ##################\n");*/

  int write_res = write(cfd, &retstat, sizeof(int));

  return retstat;
}

int open_socket(struct Metadata * metadata, int cfd, char* storagedir){
  char file_name[256];
  strcpy(file_name, metadata->path);

  char* file_path = file_fpath(file_name, storagedir);

  int retstat = 0;

  retstat = open(file_path, metadata->flags);
  if (retstat < 0)
    retstat = -errno;

  char file_hash[33];
  hash(file_path, file_hash);

  char sys_file_hash[33];
  getxattr(file_path, "user.hash", sys_file_hash, 33);

  write(cfd, file_hash, 33);
  write(cfd, sys_file_hash, 33);

/*  printf("\n################## SOCKET OPEN INFO ##################\n");
  printf("# FILE NAME --- %s\n# FILE PATH --- %s\n# FLAGS --- %d\n# RETVALUE --- %d\n", file_name, file_path, metadata->flags, retstat);
  printf("################## SOCKET OPEN INFO ##################\n");*/

  int write_res = write(cfd, &retstat, sizeof(int));

  return retstat;
}

int read_socket(struct Metadata * metadata, int cfd, char* storagedir){
  int res;

  char file_name[256];
  strcpy(file_name, metadata->path);

  char* file_path = file_fpath(file_name, storagedir);
  size_t size = metadata->size;
  off_t offset = metadata->offset;



  int retstat;
  FILE * f; 
  char buf[size]; 
  if(metadata->xvar == 1){
    f = fopen(file_path, "r");
    retstat = pread(fileno(f), buf, size, offset);
    res = write(cfd, buf, size);

    fclose(f);
  }else{
    retstat = pread(metadata->read_fd, buf, size, offset);
    res = write(cfd, buf, size);
  }


/*  retstat = pread(metadata->read_fd, buf, size, offset);
  res = write(cfd, buf, size);*/

  if(retstat < 0)
    retstat = -errno;
  

  int write_res = send(cfd, &retstat, sizeof(int), 0);

 /* printf("\n################## SOCKET READ INFO ##################\n");
  printf("# FILENAME ---  %s\n# SIZE --- %ld\n# OFFSET--- %ld\n# RETVALUE --- %d\n", file_name, size, offset, retstat);
  printf("################## SOCKET READ INFO ##################\n");*/


  return retstat;
}

int write_socket(struct Metadata * metadata, int cfd, char* storagedir){
  char file_name[256];
  strcpy(file_name, metadata->path);

  char* file_path = file_fpath(file_name, storagedir);

  char buf[metadata->size];
  int res = read(cfd, buf, metadata->size);  

  int retstat;
  FILE * f; 
  char* open_str = "w";
  if(metadata->xvar == BU_REST)
    open_str = "a";

  if(metadata->xvar == DEFAULT)
    retstat = pwrite(metadata->write_fd, buf, metadata->size, metadata->offset);
  else{
    f = fopen(file_path, open_str);
    retstat = pwrite(fileno(f), buf, metadata->size, metadata->offset);
    fclose(f);
  }

  if(retstat < 0)
    retstat = -errno;
  char file_hash[33];
  hash(file_path, file_hash);

  setxattr(file_path, "user.hash", file_hash, 33, 0);



/*  printf("\n################## SOCKET WRITE INFO ##################\n");
  printf("# SIZE --- %ld\n# OFFSET--- %ld\n# RETVALUE --- %d\n", metadata->size, metadata->offset, retstat);
  printf("################## SOCKET WRITE INFO ##################\n");*/

  int write_res = write(cfd, &retstat, sizeof(int));

  return retstat;
}

int release_socket(struct Metadata * metadata, int cfd, char* storagedir){
  char file_name[256];
  strcpy(file_name, metadata->path);

  int retstat = close(metadata->read_fd);
  if(retstat < 0)
    retstat = -errno;

/*  printf("\n################## SOCKET RELEASE INFO ##################\n");
  printf("# FILENAME ---  %s\n# RETVALUE --- %d\n", file_name, retstat);
  printf("################## SOCKET RELEASE INFO ##################\n");*/

  int write_res = write(cfd, &retstat, sizeof(int));

  return retstat;
}

int opendir_socket(struct Metadata * metadata, int cfd, char* storagedir){
  char file_name[256];
  strcpy(file_name, metadata->path);

  char* file_path = file_fpath(file_name, storagedir);

  int retstat = 0;
  DIR * dp = opendir(file_path);

  if (dp == NULL)
    retstat = -errno;
  //else
    //retstat = dirfd(dp);
  struct opendir_ret opendirr;
  opendirr.ret = retstat;
  opendirr.dp = dp;

  int struct_res;
  struct_res = write(cfd, &opendirr, sizeof(struct opendir_ret));

/*  printf("\n################## SOCKET OPENDIR INFO ##################\n");
  printf("# PATH ---  %s\n# RETVALUE --- %d\n", file_path, retstat);
  printf("################## SOCKET OPENDIR INFO ##################\n");
*/

  return retstat;
}

int readdir_socket(struct Metadata * metadata, int cfd, char* storagedir){

  char file_name[256];
  strcpy(file_name, metadata->path);
  int retstat = 0;

  DIR * dp = metadata->readdir_fd;

  struct dirent *de;
  de = readdir(dp);


  char buf[10000];
 // char * buf = strdup("/");
  strcpy(buf, "/");
  do {
    strcat(buf, "/");
    strcat(buf, de->d_name);
  } while ((de = readdir(dp)) != NULL); 
  
  int len = strlen(buf);
  //int res_len = write(cfd, &len, sizeof(int));
  struct readdir_ret readdirr;
  readdirr.ret = retstat;
  readdirr.strlen = len+1;

  int struct_res = write(cfd, &readdirr, sizeof(struct readdir_ret));
//  printf("SOCKET READDIR BUFF     =====  %s\n", buf);
  //int len = strlen(buf) + 1;
  //int len_res = write(cfd, &len, sizeof(int));
  int res = write(cfd, buf, len+1);
 


/*  printf("\n################## SOCKET READDIR INFO ##################\n");
  printf("# FILENAME ---  %s\n# RETVALUE --- %d\n", file_name, retstat);
  printf("################## SOCKET READDIR INFO ##################\n");*/

  //int write_res = write(cfd, &retstat, sizeof(int));
//  printf("PPPPPPPPPPPPPPPPPPPPPp    %d\n", retstat);

  return retstat;
}

int releasedir_socket(struct Metadata * metadata, int cfd, char* storagedir){
/*
  printf("\n################## SOCKET RELEASEDIR INFO ##################\n");
  printf("# RETVALUE --- %d\n", 0);
  printf("################## SOCKET RELEASEDIR INFO ##################\n");*/

  int retstat = closedir(metadata->readdir_fd);
/*  if(retstat < 0)
    retstat = -errno;
*/
 // int write_res = write(cfd, &retstat, sizeof(int));

  return 0;
}

int hotswap_socket(struct Metadata * metadata, int cfd, char* storagedir){
//  printf("%s\n", "HOTSWAPPPPPPPPPPPPPPPPPPPPPPPPP");
  char * dir = malloc(strlen(storagedir) + 1);
  strcpy(dir, storagedir);
  char * path[] = {dir, NULL};

  FTS *ftsp;

  FTSENT *p, *chp;
  if ((ftsp = fts_open(path, FTS_COMFOLLOW | FTS_LOGICAL | FTS_NOCHDIR, NULL)) == NULL) {
    printf("%s%s\n", "FTS : can't open ", *path);
    exit(-1);
  }

  struct hotswap_ret retst;
  chp = fts_children(ftsp, 0);
  if (chp == NULL) {
    retst.regdir = -1;
    write(cfd, &retst, sizeof(struct hotswap_ret));              
    return 0;
  }

  while ((p = fts_read(ftsp)) != NULL) {
    if(p->fts_info == FTS_D){
       retst.regdir = 0;
        strcpy(retst.path, p->fts_path + strlen(storagedir));
        write(cfd, &retst, sizeof(struct hotswap_ret));
    }
    else if(p->fts_info == FTS_F){
      retst.regdir = 1;
      strcpy(retst.path, p->fts_path + strlen(storagedir));
      write(cfd, &retst, sizeof(struct hotswap_ret));
    }
  }

  retst.regdir = -1;
  write(cfd, &retst, sizeof(struct hotswap_ret));

  fts_close(ftsp);
  return 0;
}

char* file_fpath(char* file_name, char* storagedir){
  char* file_path = malloc(256);
  strcpy(file_path, storagedir);
  strcat(file_path, (char*)file_name); 
  return file_path;
}

int socket_handler(struct Metadata * metadata, int cfd, char* storagedir){
  if(storagedir[strlen(storagedir)-1] == '/')
    storagedir[strlen(storagedir)-1] = '\0';

  int ret = 0;
  switch(metadata->func_num) {
    case -1 :
      ret = -1;
      int x = -1;
      write(cfd, &x, sizeof(int));
      break;
    case GETATTR  : 
      ret = getattr_socket(metadata, cfd, storagedir);
      break;

    case MKNOD  :
      ret = mknod_socket(metadata, cfd, storagedir);
      break;

    case MKDIR :
      ret = mkdir_socket(metadata, cfd, storagedir);
      break;

    case UNLINK :
      ret = unlink_socket(metadata, cfd, storagedir);
      break;

    case RMDIR :
      ret = rmdir_socket(metadata, cfd, storagedir);
      break;

    case RENAME :
      ret = rename_socket(metadata, cfd, storagedir);
      break;

    case TRUNCATE :
      ret = truncate_socket(metadata, cfd, storagedir);
      break;

    case OPEN :
      ret = open_socket(metadata, cfd, storagedir);
      break;
    
    case READ :
      ret = read_socket(metadata, cfd, storagedir);
      break; 

    case WRITE  : 
      ret = write_socket(metadata, cfd, storagedir);
      break;

    case RELEASE  : 
      ret = release_socket(metadata, cfd, storagedir);
      break;

    case OPENDIR  : 
      ret = opendir_socket(metadata, cfd, storagedir);
      break;

    case READDIR  : 
      ret = readdir_socket(metadata, cfd, storagedir);
      break;

    case RELEASEDIR  : 
      ret = releasedir_socket(metadata, cfd, storagedir);
      break;

    case HOTSWAP  : 
      ret = hotswap_socket(metadata, cfd, storagedir);
      break;
  }
}
