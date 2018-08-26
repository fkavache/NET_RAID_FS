COMPILER = gcc -g 
FILESYSTEM_FILES = net_raid_client.c parser.c

build: $(FILESYSTEM_FILES)
	$(COMPILER) $(FILESYSTEM_FILES) -o net_raid_client `pkg-config fuse --cflags --libs`
	@echo 'run: ./net_raid_client -f [config file]'

clean:
	rm net_raid_client
