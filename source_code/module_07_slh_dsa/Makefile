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

# unit_7_6_slh_dsa_full.c is OpenSSL-backed SLH-DSA code with its own main()
# self-test. It requires linking with -lcrypto, so it is built by `make
# build-ssl` into a standalone executable. If OpenSSL development headers are
# absent, use `make check` which only syntax-checks it (-fsyntax-only).
SSL_SOURCES = unit_7_6_slh_dsa_full.c
SSL_TARGETS = $(SSL_SOURCES:.c=)
SSL_LDFLAGS = -lcrypto

.PHONY: all clean test check build-ssl

all: $(RUNNABLE_TARGETS)

%: %.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

# Build the OpenSSL-dependent self-test into a standalone executable.
# Requires OpenSSL development headers + libcrypto.
build-ssl: $(SSL_TARGETS)

$(SSL_TARGETS): %: %.c
	$(CC) $(CFLAGS) -o $@ $< $(SSL_LDFLAGS)

# Syntax-only check for the OpenSSL-dependent source (no link step). Use this
# when libcrypto/headers are unavailable.
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
