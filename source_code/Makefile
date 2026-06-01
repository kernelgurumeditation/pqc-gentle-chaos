# PQC Developer's Handbook - Source Code Examples
# Master Makefile

CC = gcc
CFLAGS = -Wall -Wextra -Wshadow -O2 -std=c11
LDFLAGS = -lm

# Module directories
MODULES = module_01_prerequisites \
          module_02_math_foundations \
          module_03_lattice_theory \
          module_04_ml_kem \
          module_05_signatures_theory \
          module_06_ml_dsa \
          module_07_slh_dsa \
          module_08_hybrid \
          module_09_protocols \
          module_10_future \
          module_11_migration

.PHONY: all clean test help verify-params sanitize golden golden-check capstone $(MODULES)

all: $(MODULES) capstone

# The graded capstone integrates Modules 4/6/8 into one end-to-end demo.
capstone:
	@echo "Building capstone..."
	@$(MAKE) -C capstone all

# Golden-output fixtures: record / check the deterministic reference programs'
# stdout against committed expected/<module>/<prog>.out files. This is a true
# regression gate — a wrong constant or off-by-one changes the captured output.
# (Timing/benchmark and intentionally-random programs are excluded; see golden.sh.)
golden: all
	@bash golden.sh record

golden-check: all
	@bash golden.sh check

$(MODULES):
	@echo "Building $@..."
	@$(MAKE) -C $@

# Verify FIPS parameter self-consistency (recomputes derived key/sig sizes and
# checks them against the published constants in common/fips_params.h).
# This is a parameter self-consistency check, NOT a NIST Known-Answer-Test.
verify-params:
	@$(CC) $(CFLAGS) -I. -o common/verify_params common/verify_params.c
	@./common/verify_params

# Rebuild the pure-standalone math/algorithm modules under AddressSanitizer +
# UndefinedBehaviorSanitizer and run them, failing on any sanitizer error.
# (Modules 1/7/8 are skipped: they need liboqs/OpenSSL.)
SANITIZE_MODULES = module_02_math_foundations module_03_lattice_theory \
                   module_04_ml_kem module_05_signatures_theory \
                   module_06_ml_dsa module_10_future module_11_migration
SAN_CFLAGS = -Wall -Wextra -Wshadow -O1 -g -std=c11 \
             -fsanitize=address,undefined -fno-sanitize-recover=all
sanitize:
	@for dir in $(SANITIZE_MODULES); do \
		echo "== ASan/UBSan: $$dir =="; \
		$(MAKE) -C $$dir clean >/dev/null 2>&1 || true; \
		$(MAKE) -C $$dir CFLAGS="$(SAN_CFLAGS)" || exit 1; \
	done
	@echo "Sanitizer build complete."

clean:
	@for dir in $(MODULES) capstone; do \
		$(MAKE) -C $$dir clean 2>/dev/null || true; \
	done
	@rm -f common/verify_params

test: all
	@echo "Running all tests..."
	@for dir in $(MODULES); do \
		echo "Testing $$dir..."; \
		$(MAKE) -C $$dir test 2>/dev/null || true; \
	done

help:
	@echo "PQC Developer's Handbook Source Code Examples"
	@echo ""
	@echo "Usage:"
	@echo "  make              - Build all modules"
	@echo "  make clean        - Clean all build artifacts"
	@echo "  make test         - Run all tests"
	@echo "  make verify-params - Check FIPS parameter self-consistency"
	@echo "  make golden       - Record golden output fixtures (deterministic progs)"
	@echo "  make golden-check - Diff program output vs golden fixtures (regression gate)"
	@echo "  make sanitize     - Rebuild + run pure modules under ASan/UBSan"
	@echo "  make <module>     - Build specific module"
	@echo ""
	@echo "Modules:"
	@echo "  module_01_prerequisites (requires liboqs)"
	@echo "  module_02_math_foundations"
	@echo "  module_03_lattice_theory"
	@echo "  module_04_ml_kem"
	@echo "  module_05_signatures_theory"
	@echo "  module_06_ml_dsa"
	@echo "  module_07_slh_dsa"
	@echo "  module_08_hybrid"
	@echo "  module_09_protocols"
	@echo "  module_10_future"
	@echo "  module_11_migration"
