#!/usr/bin/env bash
# check-links.sh — verify external URLs in pqc-developers-handbook.md are reachable.
#
# Extracts every http(s) URL from the Markdown source, deduplicates, then
# probes each with HEAD (falling back to GET on 405). Reports broken URLs
# (4xx / 5xx / connection failure / timeout) — informational, not a CI gate.
#
# Usage:
#   scripts/check-links.sh                  # check all URLs (~80 in v10.7)
#   scripts/check-links.sh --quiet          # only print failures
#   scripts/check-links.sh --bibliography   # only Bibliography section URLs
#
# Run quarterly. Cache is stored at .link-check-cache.txt — successful URLs
# checked within the last 30 days are skipped to be polite to rate-limited
# servers (NIST, IETF datatracker). Delete cache to force a full re-check.

set -u

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DOC="${REPO_ROOT}/pqc-developers-handbook.md"
CACHE="${REPO_ROOT}/.link-check-cache.txt"
CACHE_TTL_DAYS=30
PARALLEL=8
TIMEOUT=15
MODE_QUIET=0
MODE_BIB=0

for arg in "$@"; do
  case "$arg" in
    --quiet) MODE_QUIET=1 ;;
    --bibliography) MODE_BIB=1 ;;
    --help|-h)
      sed -n '2,/^$/p' "$0" | sed 's/^# \?//'
      exit 0
      ;;
    *)
      echo "Unknown argument: $arg" >&2
      exit 1
      ;;
  esac
done

[[ -f "$DOC" ]] || { echo "ERROR: $DOC not found" >&2; exit 1; }
command -v curl >/dev/null || { echo "ERROR: curl required" >&2; exit 1; }

# ---- Extract URLs ----------------------------------------------------------
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

if [[ $MODE_BIB -eq 1 ]]; then
  # Awk flag pattern (range expression breaks when start regex also matches end)
  awk '/^## Bibliography/{f=1; print; next} f && /^## /{f=0} f' "$DOC" > "$TMP/scope.md"
else
  cp "$DOC" "$TMP/scope.md"
fi

# Extract URLs from markdown links: [text](url) AND bare https://... in prose.
# Strip trailing markdown noise (closing parens, asterisks, punctuation) that
# the URL char class would otherwise greedily capture.
grep -oE 'https?://[A-Za-z0-9._~:/?#@!$&'"'"'()*+,;=%-]+' "$TMP/scope.md" \
  | sed -E 's/[)]+\*+\.?$//; s/[)]\.\?$//; s/[.,;:]+$//; s/[)]+$//; s/\*+$//' \
  | grep -vE '^https?://?$' \
  | grep -vE '^https?://(legacy-backend|internal-legacy|alerts\.internal|prometheus|new-vendor|hooks\.slack\.com/services/xxx)' \
  | grep -vE '^https?://[A-Za-z0-9._~:/?#@!$&'"'"'()*+,;=%-]*\$\{' \
  | sort -u > "$TMP/urls.txt"

TOTAL_URLS="$(wc -l < "$TMP/urls.txt")"

# ---- Cache filtering -------------------------------------------------------
touch "$CACHE"
NOW="$(date -u +%s)"
TTL_SECS=$(( CACHE_TTL_DAYS * 86400 ))

while IFS= read -r url; do
  [[ -z "$url" ]] && continue
  cached_line="$(grep -F "$url|" "$CACHE" 2>/dev/null | head -1 || true)"
  if [[ -n "$cached_line" ]]; then
    cached_ts="$(echo "$cached_line" | cut -d'|' -f2)"
    cached_status="$(echo "$cached_line" | cut -d'|' -f3)"
    age=$(( NOW - cached_ts ))
    if [[ "$age" -lt "$TTL_SECS" && "$cached_status" == "OK" ]]; then
      continue   # cached success within TTL → skip
    fi
  fi
  echo "$url" >> "$TMP/to-check.txt"
done < "$TMP/urls.txt"

TO_CHECK="$(wc -l < "$TMP/to-check.txt" 2>/dev/null || echo 0)"
SKIPPED=$(( TOTAL_URLS - TO_CHECK ))

if [[ $MODE_QUIET -eq 0 ]]; then
  echo "================================================================"
  echo "PQC Handbook Link Check"
  echo "  Total URLs found:    $TOTAL_URLS"
  echo "  Cached (skipping):   $SKIPPED  (TTL ${CACHE_TTL_DAYS}d)"
  echo "  To probe:            $TO_CHECK"
  echo "  Parallelism:         $PARALLEL"
  echo "  Timeout per probe:   ${TIMEOUT}s"
  echo "================================================================"
fi

[[ "$TO_CHECK" -eq 0 ]] && { echo "All URLs cached as OK. Done."; exit 0; }

# ---- Probe ------------------------------------------------------------------
probe() {
  local url="$1"
  local status

  # Hosts known to bot-block but always serve to humans — skip with HUMAN status.
  # Adding a host here means the URL is no longer probed; the bibliography
  # entry must be human-verified instead.
  case "$url" in
    https://doi.org/10.1137/*|\
    https://doi.org/10.1145/*|\
    https://doi.org/10.1561/*|\
    https://media.defense.gov/*)
      echo "HUMAN|$url"
      return
      ;;
  esac

  # HEAD first (cheaper). Many CDNs/origins reject HEAD with 403/404/405 even
  # though GET succeeds — fall back to GET (range-limited) on any non-2xx/3xx.
  status="$(curl -sS --max-time "$TIMEOUT" -o /dev/null -w '%{http_code}' \
            -L --user-agent 'Mozilla/5.0 (compatible; pqc-handbook-linkcheck/1.0)' \
            -I "$url" 2>/dev/null || echo "000")"
  case "$status" in
    2*|3*) ;;  # success — keep HEAD result
    *)
      # GET fallback with Range to fetch only first 1KB; honors most servers
      status="$(curl -sS --max-time "$TIMEOUT" -o /dev/null -w '%{http_code}' \
                -L --user-agent 'Mozilla/5.0 (compatible; pqc-handbook-linkcheck/1.0)' \
                -H 'Range: bytes=0-1024' \
                "$url" 2>/dev/null || echo "000")"
      # Range responses come back as 206 Partial Content — that's success
      [[ "$status" == "206" ]] && status="200"
      ;;
  esac
  echo "$status|$url"
}

export -f probe
export TIMEOUT

xargs -a "$TMP/to-check.txt" -P "$PARALLEL" -I {} bash -c 'probe "$@"' _ {} \
  > "$TMP/results.txt"

# ---- Summarize -------------------------------------------------------------
FAILS=0
PASSES=0
SKIPPED_HUMAN=0
while IFS='|' read -r code url; do
  case "$code" in
    HUMAN)  # bot-blocked host on allowlist
      SKIPPED_HUMAN=$(( SKIPPED_HUMAN + 1 ))
      [[ $MODE_QUIET -eq 0 ]] && echo "  [skip] $url  (host bot-blocks; human-verify)"
      # Don't cache HUMAN — re-show on every run as a reminder
      ;;
    2*|3*)  # 200, 301, 302, etc. all good
      PASSES=$(( PASSES + 1 ))
      [[ $MODE_QUIET -eq 0 ]] && echo "  [$code] $url"
      # Update cache: replace existing line or append
      grep -vF "$url|" "$CACHE" > "$CACHE.tmp" 2>/dev/null || true
      echo "$url|$NOW|OK|$code" >> "$CACHE.tmp"
      mv "$CACHE.tmp" "$CACHE"
      ;;
    *)
      FAILS=$(( FAILS + 1 ))
      echo "  [FAIL $code] $url"
      grep -vF "$url|" "$CACHE" > "$CACHE.tmp" 2>/dev/null || true
      echo "$url|$NOW|FAIL|$code" >> "$CACHE.tmp"
      mv "$CACHE.tmp" "$CACHE"
      ;;
  esac
done < "$TMP/results.txt"

echo
echo "================================================================"
echo "Results: $PASSES OK, $FAILS broken, $SKIPPED_HUMAN bot-blocked (human-verify)"
if [[ "$FAILS" -gt 0 ]]; then
  echo "Action: review broken URLs and update or remove."
fi
echo "Cache: $CACHE (delete to force full re-check)"
echo "================================================================"
exit 0
