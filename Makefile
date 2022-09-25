all: IDS.c IDS.h
	gcc -o IDS IDS.c -lpcap