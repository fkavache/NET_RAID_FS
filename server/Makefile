COMPILER = gcc
FILESYSTEM_FILES = net_raid_server.c

build: $(FILESYSTEM_FILES)
	$(COMPILER) $(FILESYSTEM_FILES) -o net_raid_server -lssl -lcrypto
	@echo 'run: ./net_raid_server [server port storagedir]'

clean:
	rm net_raid_server
