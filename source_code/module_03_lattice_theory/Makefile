# Module 03: Lattice Theory
CC = gcc
CFLAGS = -Wall -Wextra -Wshadow -O2 -std=c11
LDFLAGS = -lm

SOURCES = $(wildcard *.c)
TARGETS = $(SOURCES:.c=)

.PHONY: all clean test

all: $(TARGETS)

%: %.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(TARGETS)

test: all
	@echo "Testing Module 03 examples..."
	@for prog in $(TARGETS); do \
		echo "Running $$prog..."; \
		./$$prog && echo "  PASSED" || echo "  FAILED"; \
	done
