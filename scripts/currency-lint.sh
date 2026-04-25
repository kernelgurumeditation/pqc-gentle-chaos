#!/usr/bin/env bash
# currency-lint.sh — flag stale-by-design tokens in pqc-developers-handbook.md
#
# Scans for:
#   • Hard-dated phrases (e.g., "April 2026", "as of Jan 2025")
#   • Ecosystem version numbers (OpenSSL/JDK/Go/OpenSSH/liboqs/oqs-provider)
#   • Statistical figures that change over time (Cloudflare %, etc.)
#   • Vendor-roadmap dates (FIPS, CA/B, BSI, ANSSI, NCSC, EU CRA)
#
# Output: grouped by category, with line numbers. Run quarterly; review each
# section against the source-of-truth URL listed.
#
# Exit code: 0 always (informational tool, not a CI gate).

set -u

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DOC="${REPO_ROOT}/pqc-developers-handbook.md"

if [[ ! -f "$DOC" ]]; then
  echo "ERROR: handbook not found at $DOC" >&2
  exit 1
fi

# Today's date — the lint is useful only when run periodically, so emit it
# in the header for log retention.
TODAY="$(date -u +%Y-%m-%d)"
TOTAL_LINES="$(wc -l < "$DOC")"

cat <<EOF
================================================================
PQC Handbook Currency Lint — run $TODAY
Document: $DOC ($TOTAL_LINES lines)
================================================================
EOF

# ---- Helper -----------------------------------------------------------------
section() {
  echo
  echo "▶ $1"
  echo "  ($2)"
  echo "  --------------------------------------------------------------"
}

count() {
  local n
  n="$(wc -l < "$1")"
  if [[ "$n" -eq 0 ]]; then
    echo "  (no matches)"
  else
    cat "$1"
    echo "  --- $n match(es) ---"
  fi
}

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# ---- 1. Hard-dated phrases --------------------------------------------------
section "Hard-dated phrases (month + year)" \
        "review against current state; treat as 'last verified' markers"
grep -nE '\b(January|February|March|April|May|June|July|August|September|October|November|December|Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) [12][0-9]{3}\b' "$DOC" \
  | sed 's/^/  /' > "$TMP/dates"
count "$TMP/dates"

# ---- 2. "As of <date>" / "current to <date>" / "verified <date>" -----------
section "'As of / current to / verified' anchors" \
        "ensure the date matches latest review pass"
grep -nE '(as of|current to|verified|Last verified|today)[^.]*\b[12][0-9]{3}' "$DOC" \
  | sed 's/^/  /' > "$TMP/asof"
count "$TMP/asof"

# ---- 3. Ecosystem version numbers ------------------------------------------
section "Ecosystem version numbers" \
        "compare to latest releases — OpenSSL/Go/JDK/OpenSSH/liboqs/oqs-provider"
grep -nE '(OpenSSL [0-9]+\.[0-9]+(\.[0-9]+)?|Go (stdlib )?[0-9]+\.[0-9]+|JDK [0-9]+|OpenSSH [0-9]+\.[0-9]+|liboqs [0-9]+\.[0-9]+|oqs-provider [0-9]+\.[0-9]+|Bouncy Castle [0-9]+\.[0-9]+|aws-lc-rs|AWS-LC-FIPS [0-9]+\.[0-9]+|\.NET (10|11)|RHEL [0-9]+\.[0-9]+|Caddy [0-9]+\.[0-9]+|nginx [0-9]+\.[0-9]+|HAProxy [0-9]+\.[0-9]+|Envoy [0-9]+\.[0-9]+|Chrome [0-9]+|Firefox [0-9]+|Safari [0-9]+|sigstore cosign [0-9]+|Vault Enterprise [0-9]+\.[0-9]+|Luna HSM \(fw [0-9]+\.[0-9]+\)|Apple iOS [0-9]+|macOS Tahoe [0-9]+|Windows 11 [0-9]+H[12])' "$DOC" \
  | sed 's/^/  /' > "$TMP/versions"
count "$TMP/versions"

# ---- 4. Statistical figures (% / cycle counts) -----------------------------
section "Statistical figures (%, cycle counts)" \
        "Cloudflare/Akamai adoption %, AVX cycle counts, microbenchmark numbers"
grep -nE '~[0-9]+(\.[0-9]+)?%|~[0-9]+(k|M|G)?( cycles| QPS| ops/s)|[0-9]+\.[0-9]+%' "$DOC" \
  | sed 's/^/  /' > "$TMP/stats"
count "$TMP/stats"

# ---- 5. Roadmap dates (FIPS / CA/B / BSI / ANSSI / NCSC / EU CRA) ----------
section "Roadmap dates (regulatory / standards bodies)" \
        "FIPS 140-3 transition, CA/B Forum ballots, BSI/ANSSI/NCSC deadlines, EU CRA, NIST IR 8547"
grep -nE '(FIPS 140-3|FIPS 203|FIPS 204|FIPS 205|FIPS 206|FIPS 207|CA/B Forum|CA/Browser|BSI TR-02102|ANSSI|NCSC|CRA|G7|CRYPTREC|ASD ISM|NIST IR 8547|NIST SP 800-57|RFC 9794|RFC 9882|draft-ietf-(tls|lamps|ipsecme|hpke|cose|jose|plants))' "$DOC" \
  | sed 's/^/  /' > "$TMP/roadmap"
count "$TMP/roadmap"

# ---- 6. CVE references -----------------------------------------------------
section "CVE references" \
        "verify each is still the latest disclosure and severity hasn't been re-rated"
grep -nE 'CVE-[12][0-9]{3}-[0-9]+' "$DOC" | sort -k2 -t: -u \
  | sed 's/^/  /' > "$TMP/cves"
count "$TMP/cves"

# ---- 7. Document version & changelog freshness -----------------------------
section "Document version markers" \
        "internal v10.x references — confirm changelog is up-to-date"
grep -nE 'v(10|11)\.[0-9]+|(Apr|May|Jun) 2026' "$DOC" | head -10 \
  | sed 's/^/  /' > "$TMP/ver"
count "$TMP/ver"

# ---- Summary ---------------------------------------------------------------
echo
echo "================================================================"
echo "Run this quarterly. Each section is informational — review the"
echo "matches against the upstream source (regulator, vendor, RFC) and"
echo "update as needed. Tracked artifacts to keep current:"
echo "  • Unit 11.9.6 Regulatory Compliance Matrix"
echo "  • Unit 11.9 Vendor Landscape Snapshot"
echo "  • Unit 11.9 Ecosystem Snapshot"
echo "  • Unit 11.10 PQC CVE Registry"
echo "  • Algorithm Decision Table FIPS 140-3 column"
echo "================================================================"
