# Module 11: Migration Planning
CC = gcc
CXX = g++
CFLAGS = -Wall -Wextra -Wshadow -O2 -std=c11
CXXFLAGS = -Wall -Wextra -Wshadow -O2 -std=c++17
LDFLAGS = -lm
LDFLAGS_SSL = -lssl -lcrypto

# All C sources
SOURCES = $(wildcard *.c)

# Files requiring OpenSSL
SSL_SOURCES = unit_11_2_x25519_key_exchange.c unit_11_3_sha3_shake_hashing.c unit_11_6_lamport_signatures.c unit_11_7_merkle_tree_auth.c

# Template sources NOT built by default: unit_11_8_timing_test.c is a timing
# harness template that references an externally-provided function_under_test()
# and intentionally does not link on its own (see README).
TEMPLATE_SOURCES = unit_11_8_timing_test.c

# C++ sources (built with g++)
CPP_SOURCES = $(wildcard *.cpp)
CPP_TARGETS = $(CPP_SOURCES:.cpp=)

# Standalone C files (exclude OpenSSL- and template-only sources)
STANDALONE_SOURCES = $(filter-out $(SSL_SOURCES) $(TEMPLATE_SOURCES),$(SOURCES))
STANDALONE_TARGETS = $(STANDALONE_SOURCES:.c=)

# Optional SSL targets
SSL_TARGETS = $(SSL_SOURCES:.c=)

.PHONY: all clean test info build-ssl

all: $(STANDALONE_TARGETS) $(CPP_TARGETS) info

# Build standalone C programs
$(STANDALONE_TARGETS): %: %.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

# Build C++ programs
$(CPP_TARGETS): %: %.cpp
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDFLAGS)

# Build SSL-dependent programs (requires OpenSSL)
build-ssl: $(SSL_TARGETS)

$(SSL_TARGETS): %: %.c
	@echo "Building $@ (requires OpenSSL)..."
	@$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS) $(LDFLAGS_SSL) 2>/dev/null && echo "  -> $@ built successfully" || echo "  -> $@ requires OpenSSL (skipped)"

clean:
	rm -f $(STANDALONE_TARGETS) $(CPP_TARGETS) $(SSL_TARGETS) $(TEMPLATE_SOURCES:.c=)

test: all
	@echo "Testing Module 11 examples..."
	@for prog in $(STANDALONE_TARGETS) $(CPP_TARGETS); do \
		echo "Running $$prog..."; \
		./$$prog && echo "  PASSED" || echo "  FAILED"; \
	done

info:
	@echo ""
	@echo "Note: Some files require OpenSSL:"
	@echo "  $(SSL_SOURCES)"
	@echo "Run 'make build-ssl' to build them if OpenSSL is installed."
	@echo ""
	@echo "Template (not built by default): $(TEMPLATE_SOURCES)"
	@echo "  Provide function_under_test() and compile manually to use it."
