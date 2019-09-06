CC = gcc
CFLAGS = -O9 -DFFCSR16_EVALUATE

test: ecrypt-portable.h ffcsr16-sync.h ecrypt-sync.h ffcsr16.c
	$(CC) $(CFLAGS) ffcsr16.c -o test

