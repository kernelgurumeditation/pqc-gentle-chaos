#!/usr/bin/env bash
# check-structure.sh — validate structural invariants of the MASTER handbook
# BEFORE the volume/essentials filters run on it.
#
# HARD GATE: code-fence balance. An unbalanced fence does NOT error in
# WeasyPrint — it silently swallows content and corrupts the derived volume /
# essentials PDFs (this exact bug shipped once). Nothing else catches it, so it
# fails the build.
#
# ADVISORY: internal-anchor resolution. This is a best-effort heuristic (its
# slugify mirrors md2pdf.js but its fence tracking can diverge on indented
# fences, so it may over-report). The WeasyPrint build step that follows is the
# AUTHORITATIVE anchor validator — it hard-fails on any genuinely broken
# `href="#x"`. So anchor findings here are printed as warnings, not failures.
#
# Usage: bash scripts/check-structure.sh [file.md]
# Exit:  0 = fences balanced, non-zero = unbalanced fences.
set -uo pipefail

FILE="${1:-pqc-developers-handbook.md}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
FILE_PATH="$ROOT/$FILE"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
fail=0

if [[ ! -f "$FILE_PATH" ]]; then
  echo -e "${RED}ERROR:${NC} $FILE_PATH not found"
  exit 2
fi

echo "Checking structure of $FILE ..."

# ---------------------------------------------------------------------------
# 1. HARD GATE — code-fence balance: lines starting with ``` must be EVEN.
# ---------------------------------------------------------------------------
fences=$(grep -cE '^```' "$FILE_PATH")
if (( fences % 2 != 0 )); then
  echo -e "${RED}[FAIL]${NC} Unbalanced code fences: $fences \`\`\` markers (odd). An unclosed fence will corrupt the volume/essentials filters."
  fail=1
else
  echo -e "${GREEN}[OK]${NC}   Code fences balanced ($fences markers)."
fi

# ---------------------------------------------------------------------------
# 2. ADVISORY — internal anchor resolution (warning only; WeasyPrint is the
#    authoritative validator in the build step that follows).
# ---------------------------------------------------------------------------
node - "$FILE_PATH" <<'NODE'
const fs = require('fs');
const lines = fs.readFileSync(process.argv[2], 'utf-8').split('\n');

// Mirror md2pdf.js renderer.heading slugify.
function slugify(text) {
  return text.toLowerCase()
    .replace(/[^\w\s-]/g, '')
    .replace(/\s+/g, '-')
    .replace(/^-+|-+$/g, '');
}

const ids = new Set();
let inFence = false;
for (const line of lines) {
  if (/^(```|~~~)/.test(line)) { inFence = !inFence; continue; }
  if (inFence) continue;
  const m = line.match(/^(#{1,6})\s+(.*)$/);
  if (m) ids.add(slugify(m[2].replace(/<[^>]*>/g, '').trim()));
}

const targets = [];
inFence = false;
let lineNo = 0;
for (const line of lines) {
  lineNo++;
  if (/^(```|~~~)/.test(line)) { inFence = !inFence; continue; }
  if (inFence) continue;
  const re = /\]\(#([^)]+)\)/g;
  let mm;
  while ((mm = re.exec(line)) !== null) targets.push({ slug: mm[1], lineNo });
}

const broken = targets.filter(t => !ids.has(t.slug));
if (broken.length === 0) {
  console.log(`\x1b[0;32m[OK]\x1b[0m   All ${targets.length} internal anchors resolve.`);
} else {
  console.log(`\x1b[1;33m[WARN]\x1b[0m ${broken.length} of ${targets.length} internal anchors did not resolve in this heuristic check (the WeasyPrint build verifies anchors authoritatively):`);
  for (const b of broken.slice(0, 25)) console.log(`         line ${b.lineNo}: #${b.slug}`);
  if (broken.length > 25) console.log(`         ... and ${broken.length - 25} more`);
}
// Advisory only — never fails the script.
NODE

echo ""
if (( fail == 0 )); then
  echo -e "${GREEN}Structure OK${NC} (fences balanced)."
  exit 0
else
  echo -e "${RED}Structure check failed${NC} (unbalanced fences)."
  exit 1
fi
