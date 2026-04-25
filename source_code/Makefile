# PQC Developer's Handbook - Source Code Examples
# Master Makefile

CC = gcc
CFLAGS = -Wall -Wextra -O2 -std=c11
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

.PHONY: all clean $(MODULES)

all: $(MODULES)

$(MODULES):
	@echo "Building $@..."
	@$(MAKE) -C $@ || true

clean:
	@for dir in $(MODULES); do \
		$(MAKE) -C $$dir clean 2>/dev/null || true; \
	done

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
	@echo "  make          - Build all modules"
	@echo "  make clean    - Clean all build artifacts"
	@echo "  make test     - Run all tests"
	@echo "  make <module> - Build specific module"
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
