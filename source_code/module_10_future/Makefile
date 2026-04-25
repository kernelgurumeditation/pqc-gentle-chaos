# Makefile for Module 10: Future Algorithms
#
# unit_10_1 is self-contained (framework pattern, no crypto).
# unit_10_2, 10_3, 10_4 require liboqs for real algorithm access.

CFLAGS = -Wall -Wextra -Wshadow -O2 -std=c11

SELF_CONTAINED = unit_10_1_crypto_agility
LIBOQS_DEPENDENT = unit_10_2_falcon_wrapper unit_10_3_hqc_demo unit_10_4_bike_demo

.PHONY: all info self-contained liboqs clean test

all: self-contained

info:
	@echo "Module 10: Future Algorithms"
	@echo ""
	@echo "Targets:"
	@echo "  make self-contained   Build framework-pattern demos"
	@echo "  make liboqs           Build liboqs-backed algorithm demos"
	@echo "  make clean            Remove binaries"
	@echo "  make test             Run self-contained demos"

self-contained: $(SELF_CONTAINED)

$(SELF_CONTAINED): %: %.c
	$(CC) $(CFLAGS) -o $@ $<

liboqs:
	@for t in $(LIBOQS_DEPENDENT); do \
		echo "Building $$t with liboqs..."; \
		$(CC) $(CFLAGS) -DHAVE_LIBOQS -o $$t $$t.c -loqs || exit 1; \
	done

clean:
	rm -f $(SELF_CONTAINED) $(LIBOQS_DEPENDENT)

test: self-contained
	@echo "=== unit_10_1_crypto_agility ==="
	@./unit_10_1_crypto_agility
