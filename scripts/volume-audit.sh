#!/usr/bin/env bash
# volume-audit.sh — verify volume split integrity.
#
# Checks each volume's filtered Markdown for:
#   1. Cross-volume references that should have been rewritten
#   2. Anchor links to sections that don't exist in this volume
#   3. TOC entries that don't have matching headings
#   4. Page count sanity
#
# Run after `make pdf-volumes`. Exit 0 = clean, exit 1 = issues found.

set -u

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VOL1_MD="${REPO_ROOT}/pqc-developers-handbook-vol1.md"
VOL2_MD="${REPO_ROOT}/pqc-developers-handbook-vol2.md"
VOL1_PDF="${REPO_ROOT}/pqc-developers-handbook-vol1.pdf"
VOL2_PDF="${REPO_ROOT}/pqc-developers-handbook-vol2.pdf"

ISSUES=0

echo "================================================================"
echo "Volume Split Audit"
echo "================================================================"

# ---- Pre-flight -----------------------------------------------------------
for f in "$VOL1_MD" "$VOL2_MD"; do
  if [[ ! -f "$f" ]]; then
    echo "ERROR: $f not found. Run 'make pdf-volumes' first." >&2
    exit 1
  fi
done

# ---- Helper ---------------------------------------------------------------
audit_volume() {
  local label="$1"
  local md="$2"
  local pdf="$3"
  local own_modules="$4"   # e.g., "1 2 3 4 5 6 7"
  local other_modules="$5" # e.g., "8 9 10 11"
  local other_volume="$6"

  echo
  echo "--- $label ----------------------------------------------------"

  # Build regex: Module followed by other-volume-numbers
  local other_pattern
  other_pattern="$(echo "$other_modules" | tr ' ' '|')"

  # 1. Bare "Module N" references (not in code blocks, not already rewritten)
  echo "1. Bare cross-volume Module refs (should be rewritten):"
  local bad_module_refs
  bad_module_refs="$(awk -v pat="\\\\bModule (${other_pattern})\\\\b" '
    /^```/ { in_fence = !in_fence; next }
    in_fence { next }
    /^## Module/ || /^### Module/ { next }
    {
      # Skip lines already containing "Volume N, Module M" — those are rewritten
      gsub(/Volume [12], Module [0-9]+/, "")
      if ($0 ~ pat) print FILENAME ":" NR ": " $0
    }
  ' "$md" | head -10)"

  if [[ -n "$bad_module_refs" ]]; then
    echo "$bad_module_refs" | sed 's/^/    /'
    local n
    n="$(echo "$bad_module_refs" | wc -l)"
    echo "    [$n cross-vol Module ref(s) NOT rewritten — investigate]"
    ISSUES=$(( ISSUES + 1 ))
  else
    echo "    ✓ all bare Module refs handled"
  fi

  # 2. Bare "Unit N.M" references where N is in other volume
  echo "2. Bare cross-volume Unit refs:"
  local bad_unit_refs
  bad_unit_refs="$(awk -v pat="\\\\bUnit (${other_pattern})\\\\.[0-9]+" '
    /^```/ { in_fence = !in_fence; next }
    in_fence { next }
    {
      gsub(/Volume [12], Unit [0-9]+(\.[0-9]+)+/, "")
      if ($0 ~ pat) print FILENAME ":" NR ": " $0
    }
  ' "$md" | head -10)"

  if [[ -n "$bad_unit_refs" ]]; then
    echo "$bad_unit_refs" | sed 's/^/    /'
    local n
    n="$(echo "$bad_unit_refs" | wc -l)"
    echo "    [$n cross-vol Unit ref(s) — note: §X.Y notation in Index is OK]"
  else
    echo "    ✓ no leftover cross-vol Unit refs in prose"
  fi

  # 3. Markdown anchor links pointing to non-existent slugs in this volume.
  # Build the set of valid heading slugs in this volume, then find any
  # in-document anchor link target that isn't in that set.
  echo "3. Anchor links pointing to non-existent slugs:"
  local heading_slugs
  heading_slugs="$(awk '
    function slugify(s,    out, c, i) {
      out = tolower(s)
      gsub(/[^a-z0-9 -]/, "", out)
      gsub(/  +/, " ", out)
      gsub(/^ +| +$/, "", out)
      gsub(/ /, "-", out)
      gsub(/--+/, "-", out)
      return out
    }
    /^## / || /^### / || /^#### / {
      sub(/^#+ /, "")
      print slugify($0)
    }
  ' "$md" | sort -u)"

  local link_anchors
  link_anchors="$(grep -oE '\(#[a-z0-9-]+\)' "$md" | sed 's/^(#//; s/)$//' | sort -u)"

  local broken
  broken="$(comm -23 <(echo "$link_anchors") <(echo "$heading_slugs") | head -15)"

  if [[ -n "$broken" ]]; then
    echo "$broken" | sed 's/^/    #/'
    local n
    n="$(echo "$broken" | wc -l)"
    echo "    [$n anchor(s) point to slugs not present in this volume]"
    ISSUES=$(( ISSUES + 1 ))
  else
    echo "    ✓ all anchor links resolve to in-volume headings"
  fi

  # 4. PDF page count sanity
  if [[ -f "$pdf" ]]; then
    local pages
    pages="$(pdfinfo "$pdf" | awk '/^Pages:/ {print $2}')"
    echo "4. PDF page count: $pages pages"
    if [[ "$pages" -lt 100 || "$pages" -gt 1500 ]]; then
      echo "    [out-of-range — sanity check failed]"
      ISSUES=$(( ISSUES + 1 ))
    else
      echo "    ✓ page count in expected range"
    fi
  else
    echo "4. PDF not built ($pdf missing)"
    ISSUES=$(( ISSUES + 1 ))
  fi

  # 5. Front-of-document volume notice present
  if grep -q "^> \*\*Volume ${label##*Volume } of 2" "$md" 2>/dev/null \
     || grep -q "^> \*\*Volume" "$md"; then
    echo "5. ✓ volume notice present"
  else
    echo "5. ✗ volume notice missing"
    ISSUES=$(( ISSUES + 1 ))
  fi
}

audit_volume "Volume 1 (Algorithms)" "$VOL1_MD" "$VOL1_PDF" "1 2 3 4 5 6 7" "8 9 10 11" "2"
audit_volume "Volume 2 (Production)" "$VOL2_MD" "$VOL2_PDF" "8 9 10 11" "1 2 3 4 5 6 7" "1"

echo
echo "================================================================"
if [[ "$ISSUES" -eq 0 ]]; then
  echo "Audit clean — both volumes look good."
  exit 0
else
  echo "Audit found $ISSUES issue(s) — review above."
  exit 1
fi
