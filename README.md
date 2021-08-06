## NET_RAID_FS 

### Final Project for Freeuni / Macs / OS

--------------------------------------------

### Introduction

**NET_RAID_FS** is a network filesystem implemented with standard raid level 1 algorithm. 

1. Filesystem uses stable storage which guarantees atomicity for any given write operation and allows software to be written that is robust against some hardware and power failures. 
2. In case of server loss, filesystem uses hot swapping which allows replacement of server to a system without stopping, shutting down, or rebooting it.
3. Also filesystem has caching and epoll mechanisms for efficiency purposes.

### Project Structure

```
.
|-- server
|   |-- MakeFile
|   |-- net_raid_server.c
|
|-- Makefile
|-- net_raid_client.c
|-- parser.c
|-- parser.h
|-- README.md
|-- DOC
|-- utils.h
.

``` 

There are separate entry points and therefore separate makefile files for server and client,
there is additional parser.c/h in client side to parse configuration file, also in client side
there is utils.h which is common for both server and client and where there is described all the
data structures that is needed to send and receive data.

### How to Use

To run the program you need to have valid configuration file, which looks like this:

```
errorlog = /path/to/error.log
cache_size = 1024M
cache_replacement = lru
timeout = 10

diskname = STORAGE1
mountpoint = /path/to/mountpoint1
raid = 1
servers = 127.0.0.1:10001, 127.0.0.1:10002
hotswap = 127.0.0.1:11111 

diskname = STORAGE2
mountpoint = /path/to/mountpoint2
raid = 5
servers = 127.0.0.1:10011, 127.0.0.1:10012, 127.0.0.1:10013
hotswap = 127.0.0.1:22222

```
Where:
1. **errorlog**          - the file path where you want to log system activities.
2. **cache_size**        - size of cache, which has B/K/M/G.
3. **cache_replacement** - replacement algorithm (system has only lru support).
4. **timeout**           - second, which system is waiting after server loss, in this time
                       system might recover the lost server and continue working, after this time
                       servers is declared missing.

Beside of these general configurations, there can be multiple disk configurations:
1. **diskname**   - used only in logging.
2. **mountpoint** - main mount directory for this disk, where client will read and write data.
3. **raid**       - level of raid algorithm (system has only level 1 support).
4. **servers**    - list of servers, which should be registered before client, there is only 2 servers
                in raid 1.
5. **hotswap**    - hotswap server for replacing lost server. After server loss data will be copied
                from healthy server, in case of another server loss system will continue working
                with only one server.

After creating the configuration file, libssl must be installed to run the hashing mechanisms
command - $ sudo apt-get install libpcap-dev libssl-dev

After installing this package, it is now possible to run the program, first running the server:

1. From the terminal which is opened from /NET_RAID_FS/server directory run make command first to compile code.
2. To run the server itself run the following command ./net_raid_server [ip] [port] [storagedir]
   **(e.g. ./net_raid_server 127.0.0.1 10001 /home/kobi/Desktop/storagedir1)**
3. First all the servers that was specified in the configuration file must register and wait for their connections. 

After registering all the servers, the client runs

1. From the terminal which is opened from /NET_RAID_FS directory run make command first to compile code.
2. To run the server itself run the following command ./net_raid_client [config file]
   **(e.g. ./net_raid_client /home/kobi/Desktop/config_file.txt)**

After launching the program, the mount points specified in the configuration file will be mounted.
Data will be stored on the server side, in the storage specified during the registration.
