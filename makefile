# M. Thaler 2/2016
# MPC project

CC    = gcc
#CFLGS = -std=gnu99 -g -fopenmp
CFLGS = -std=gnu99 -O2 -fopenmp

OBJS  = main.o aes128.o cbc.o utils.o

main:	$(OBJS)
	$(CC) $(CFLGS) $(OBJS) $(LIBS) -o main.e -lm

.c.o:
	$(CC) -c $(CFLGS) $<

clean:
	rm -f *.o *.e

all:
	make clean
	make
