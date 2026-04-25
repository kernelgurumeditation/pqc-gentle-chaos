# Module 11: Migration Planning
CC = gcc
CFLAGS = -Wall -Wextra -Wshadow -O2 -std=c11
LDFLAGS = -lm
LDFLAGS_SSL = -lssl -lcrypto

# Separate source files by dependency requirements
SOURCES = $(wildcard *.c)

# Files requiring OpenSSL
SSL_SOURCES = unit_11_2_x25519_key_exchange.c unit_11_3_sha3_shake_hashing.c unit_11_6_lamport_signatures.c unit_11_7_merkle_tree_auth.c

# Standalone files
STANDALONE_SOURCES = $(filter-out $(SSL_SOURCES),$(SOURCES))
STANDALONE_TARGETS = $(STANDALONE_SOURCES:.c=)

# Optional SSL targets
SSL_TARGETS = $(SSL_SOURCES:.c=)

.PHONY: all clean test info build-ssl

all: $(STANDALONE_TARGETS) info

# Build standalone programs
$(STANDALONE_TARGETS): %: %.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

# Build SSL-dependent programs (requires OpenSSL)
build-ssl: $(SSL_TARGETS)

$(SSL_TARGETS): %: %.c
	@echo "Building $@ (requires OpenSSL)..."
	@$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS) $(LDFLAGS_SSL) 2>/dev/null && echo "  -> $@ built successfully" || echo "  -> $@ requires OpenSSL (skipped)"

clean:
	rm -f $(STANDALONE_TARGETS) $(SSL_TARGETS)

test: all
	@echo "Testing Module 11 examples..."
	@for prog in $(STANDALONE_TARGETS); do \
		echo "Running $$prog..."; \
		./$$prog && echo "  PASSED" || echo "  FAILED"; \
	done

info:
	@echo ""
	@echo "Note: Some files require OpenSSL:"
	@echo "  $(SSL_SOURCES)"
	@echo "Run 'make build-ssl' to build them if OpenSSL is installed."
