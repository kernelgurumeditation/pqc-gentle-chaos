# Module 01: Prerequisites - Development Environment Test
# IMPORTANT: This module requires external libraries:
#   - OpenSSL (libssl-dev on Ubuntu)
#   - liboqs (Open Quantum Safe library)
#
# Install liboqs: https://github.com/open-quantum-safe/liboqs
# Most systems won't have liboqs pre-installed.
# This module is optional - other modules use standalone demos.

CC = gcc
CFLAGS = -Wall -Wextra -Wshadow -O2 -std=c11
LDFLAGS = -loqs -lssl -lcrypto

# Source files (requires external libraries)
EXTERNAL_DEPS_SOURCES = test_setup.c unit_1_2_test_setup.c

# Targets
EXTERNAL_TARGETS = $(EXTERNAL_DEPS_SOURCES:.c=)

.PHONY: all clean test info

# Default: just show info since external deps may not be available
all: info

# Build if you have dependencies installed
build: $(EXTERNAL_TARGETS)

$(EXTERNAL_TARGETS): %: %.c
	@echo "Building $@ (requires liboqs + OpenSSL)..."
	@$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS) 2>/dev/null && echo "  -> $@ built successfully" || echo "  -> $@ requires liboqs and OpenSSL (skipped)"

clean:
	rm -f $(EXTERNAL_TARGETS)

test: build
	@for prog in $(EXTERNAL_TARGETS); do \
		if [ -x $$prog ]; then \
			echo "Running $$prog..."; \
			./$$prog; \
		fi \
	done

info:
	@echo "Module 01: Prerequisites"
	@echo "========================"
	@echo "This module tests the development environment."
	@echo ""
	@echo "Required external libraries:"
	@echo "  - OpenSSL (libssl-dev)"
	@echo "  - liboqs (Open Quantum Safe library)"
	@echo ""
	@echo "To build: make build"
	@echo "To test:  make test"
	@echo ""
	@echo "Note: Most other modules use standalone demos"
	@echo "      that don't require external dependencies."
