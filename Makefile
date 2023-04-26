CC = gcc
FLAGS = -Wall -g
TARGETS = attack

.PHONY: all clean

all: $(TARGETS)

attack: attack.c attack.h
	$(CC) $(FLAGS) -c $^
	$(CC) $(FLAGS) -o $@ attack.o

clean:
	rm -f *.o *.h.gch $(TARGETS)