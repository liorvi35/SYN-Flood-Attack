# This file contains the `Make` file for DDos Attack in C\
since: 17/05/2023\
authors Lior Vinman & Yoad Tamar

CC = gcc
FLAGS = -Wall -g
TARGETS = Attack Monitor

.PHONY: default all clean

default: all

all: $(TARGETS)

Attack: Attack.c Attack.h
	$(CC) $(FLAGS) -c $^
	$(CC) $(FLAGS) -o $@ $@.o


Monitor: Monitor.c Monitor.h
	$(CC) $(FLAGS) -c $^
	$(CC) $(FLAGS) -o $@ $@.o

clean:
	rm -f *.o *.h.gch $(TARGETS)
