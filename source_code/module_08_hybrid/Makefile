# Module 08: Hybrid Cryptography
CC = gcc
CFLAGS = -Wall -Wextra -Wshadow -O2 -std=c11
LDFLAGS = -lm

# Files with their own main() that build as standalone programs.
# composite_keys.c is a library (no main); unit_8_5_integration_test_full.c
# depends on a hybrid_crypto implementation not shipped here. Both are
# syntax-checked by the `check` target instead.
RUNNABLE_SOURCES = unit_8_2_xwing_test_suite.c \
                   unit_8_3_hybrid_signature_test.c \
                   unit_8_5_hybrid_crypto_test_suite.c \
                   unit_8_5_integration_test_suite.c
RUNNABLE_TARGETS = $(RUNNABLE_SOURCES:.c=)

LIBRARY_SOURCES = composite_keys.c \
                  unit_8_5_integration_test_full.c

.PHONY: all clean test check

all: $(RUNNABLE_TARGETS)

%: %.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

# Syntax-only check for library sources and full reference impls
check: $(RUNNABLE_TARGETS)
	@echo "Syntax-checking library sources (composite_keys.c, *_full.c)..."
	@for src in $(LIBRARY_SOURCES); do \
		echo "  $$src"; \
		$(CC) $(CFLAGS) -fsyntax-only $$src || exit 1; \
	done
	@echo "All sources syntax-clean."

clean:
	rm -f $(RUNNABLE_TARGETS) *.o

test: all
	@echo "Testing Module 08 examples..."
	@for prog in $(RUNNABLE_TARGETS); do \
		echo "Running $$prog..."; \
		./$$prog && echo "  PASSED" || echo "  FAILED"; \
	done
