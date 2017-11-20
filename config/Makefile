lowfat-config: lowfat-config.c
	$(CC) -o lowfat-config lowfat-config.c -lm -lpthread -O2

lowfat-check-config: lowfat-check-config.c
	$(CC) -o lowfat-check-config lowfat-check-config.c -lm -lpthread -O2

lowfat-ptr-info: lowfat-ptr-info.c
	$(CC) -o lowfat-ptr-info lowfat-ptr-info.c -lm -lpthread -O2

clean:
	rm -f lowfat-config lowfat-check-config lowfat-ptr-info *.o *.i *.s *.ii \
        lowfat.ld lowfat2.ld lowfat_config.c lowfat_config2.c

