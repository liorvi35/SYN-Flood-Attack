CC = gcc
FLAGS = -Wall -g
TARGETS = Attack

.PHONY: all clean

all: $(TARGETS)

Attack: Attack.c Attack.h
	$(CC) $(FLAGS) -c $^
	$(CC) $(FLAGS) -o $@ $@.o

clean:
	rm -f *.o *.h.gch $(TARGETS)
