# ============================================================================
#  GRADED CAPSTONE - Hybrid Secure Channel (Modules 4 / 6 / 8)
#  Educational / toy implementation. Pure C11 + libm; no liboqs, no OpenSSL.
# ============================================================================

CC      = gcc
CFLAGS  = -Wall -Wextra -Wshadow -O2 -std=c11
LDFLAGS = -lm

TARGET  = capstone_hybrid_channel
SRC     = $(TARGET).c

EXPECTED_DIR = expected
EXPECTED     = $(EXPECTED_DIR)/$(TARGET).out

# Fixed seed for reproducible golden output / check.
DEMO_SEED ?= 1234567

.PHONY: all clean test record check

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

# Build and run the demo (must print CAPSTONE: PASS and exit 0).
test: all
	@echo "Running $(TARGET) (PQC_DEMO_SEED=$(DEMO_SEED))..."
	@PQC_DEMO_SEED=$(DEMO_SEED) ./$(TARGET)

# Regenerate the golden output from a fixed-seed run.
record: all
	@mkdir -p $(EXPECTED_DIR)
	@PQC_DEMO_SEED=$(DEMO_SEED) ./$(TARGET) > $(EXPECTED) ; \
	status=$$? ; \
	if [ $$status -ne 0 ]; then \
		echo "record: FAILED - program exited $$status (expected 0)"; \
		rm -f $(EXPECTED); \
		exit 1; \
	fi
	@echo "record: wrote golden output to $(EXPECTED)"

# Diff current fixed-seed output against the golden file; fail on mismatch.
check: all
	@if [ ! -f $(EXPECTED) ]; then \
		echo "check: FAILED - $(EXPECTED) missing; run 'make record' first"; \
		exit 1; \
	fi
	@PQC_DEMO_SEED=$(DEMO_SEED) ./$(TARGET) > .check.out 2>&1 ; \
	run_status=$$? ; \
	if [ $$run_status -ne 0 ]; then \
		echo "check: FAILED - program exited $$run_status (expected 0)"; \
		rm -f .check.out; \
		exit 1; \
	fi ; \
	if diff -u $(EXPECTED) .check.out > .check.diff 2>&1; then \
		rm -f .check.out .check.diff; \
		echo "check: PASSED - output matches $(EXPECTED)"; \
	else \
		echo "check: FAILED - output differs from $(EXPECTED):"; \
		cat .check.diff; \
		rm -f .check.out .check.diff; \
		exit 1; \
	fi

clean:
	rm -f $(TARGET) .check.out .check.diff
