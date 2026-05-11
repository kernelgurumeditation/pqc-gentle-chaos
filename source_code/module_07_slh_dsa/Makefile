# Module 07: SLH-DSA (Hash-Based Signatures)
CC = gcc
CFLAGS = -Wall -Wextra -Wshadow -O2 -std=c11
LDFLAGS = -lm

# Files with their own main() that build as standalone (no extra deps).
RUNNABLE_SOURCES = unit_7_1_lamport_signatures.c \
                   unit_7_2_merkle_tree_tests.c \
                   unit_7_3_wots_key_reuse_attack.c \
                   unit_7_3_wots_tests.c \
                   unit_7_5_fors_tests.c \
                   unit_7_7_integration_tests.c
RUNNABLE_TARGETS = $(RUNNABLE_SOURCES:.c=)

# unit_7_6_slh_dsa_full.c requires OpenSSL (-lcrypto). Built only via
# `make build-ssl`. Syntax-checked by `make check` regardless.
SSL_SOURCES = unit_7_6_slh_dsa_full.c
SSL_TARGETS = $(SSL_SOURCES:.c=)
SSL_LDFLAGS = -lm -lcrypto

.PHONY: all clean test check build-ssl

all: $(RUNNABLE_TARGETS)

%: %.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

# Build the OpenSSL-dependent target only when explicitly requested.
build-ssl: $(SSL_TARGETS)

$(SSL_TARGETS): $(SSL_SOURCES)
	$(CC) $(CFLAGS) -o $@ $< $(SSL_LDFLAGS)

# Syntax-only check for all sources (no link step).
check: $(RUNNABLE_TARGETS)
	@echo "Syntax-checking OpenSSL-dependent sources..."
	@for src in $(SSL_SOURCES); do \
		echo "  $$src"; \
		$(CC) $(CFLAGS) -fsyntax-only $$src || exit 1; \
	done
	@echo "All sources syntax-clean."

clean:
	rm -f $(RUNNABLE_TARGETS) $(SSL_TARGETS)

test: all
	@echo "Testing Module 07 examples..."
	@for prog in $(RUNNABLE_TARGETS); do \
		echo "Running $$prog..."; \
		./$$prog && echo "  PASSED" || echo "  FAILED"; \
	done
