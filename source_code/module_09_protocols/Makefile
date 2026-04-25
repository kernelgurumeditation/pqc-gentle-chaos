# Makefile for Module 9: Protocol Integration
#
# Most files require OpenSSL 3.5+ for native PQC support.
# SSH demo is self-contained (no external libs).

CFLAGS = -Wall -Wextra -Wshadow -O2 -std=c11

# Self-contained demos (compile without external libs)
SELF_CONTAINED = \
	unit_9_2_ssh_kex_demo \
	unit_9_4_ipsec_ike_mlkem \
	unit_9_5_hybrid_code_signing

# OpenSSL-dependent demos (require -DHAVE_OPENSSL -lssl -lcrypto)
OPENSSL_DEPENDENT = \
	unit_9_1_tls13_hybrid_kex \
	unit_9_1_tls13_cert_chain \
	unit_9_3_smime_hybrid

.PHONY: all self-contained openssl clean info test

all: self-contained

info:
	@echo "Module 9: Protocol Integration"
	@echo ""
	@echo "Targets:"
	@echo "  make self-contained   Build stubs that don't need external libs"
	@echo "  make openssl          Build demos that require OpenSSL 3.5+ (with HAVE_OPENSSL)"
	@echo "  make clean            Remove all binaries"
	@echo "  make test             Run self-contained demos"
	@echo ""
	@echo "Self-contained demos: $(SELF_CONTAINED)"
	@echo "OpenSSL-dependent:    $(OPENSSL_DEPENDENT)"

self-contained: $(SELF_CONTAINED)

$(SELF_CONTAINED): %: %.c
	$(CC) $(CFLAGS) -o $@ $<

openssl:
	@for t in $(OPENSSL_DEPENDENT); do \
		echo "Building $$t with OpenSSL..."; \
		$(CC) $(CFLAGS) -DHAVE_OPENSSL -o $$t $$t.c -lssl -lcrypto || exit 1; \
	done

clean:
	rm -f $(SELF_CONTAINED) $(OPENSSL_DEPENDENT)

test: self-contained
	@echo "=== unit_9_2_ssh_kex_demo ==="
	@./unit_9_2_ssh_kex_demo
	@echo ""
	@echo "=== unit_9_4_ipsec_ike_mlkem ==="
	@./unit_9_4_ipsec_ike_mlkem
	@echo ""
	@echo "=== unit_9_5_hybrid_code_signing ==="
	@./unit_9_5_hybrid_code_signing
