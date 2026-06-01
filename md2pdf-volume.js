#!/usr/bin/env node
/**
 * md2pdf-volume.js
 *
 * Generate volume-specific Markdown from the unified PQC handbook source.
 * Driven by volume-config.js.
 *
 * Usage:
 *   node md2pdf-volume.js <volumeNum> <input.md> <output.md>
 *
 * Example:
 *   node md2pdf-volume.js 1 pqc-developers-handbook.md pqc-developers-handbook-vol1.md
 *
 * Behavior:
 *   - Includes only H2 sections listed in VOLUMES[volumeNum].includeH2
 *   - Front matter (before first H2) is always included
 *   - Embedded sample-doc H2s (SKIP_H2_INLINE) are suppressed but preserve
 *     surrounding parent unit/module state (matches md2pdf-essentials.js)
 *   - Generates fresh Table of Contents matching only included sections
 *   - Rewrites cross-references that target a unit in the OTHER volume so
 *     they read "Volume N, Unit X.Y" instead of being broken anchors
 *   - Prepends a per-volume notice block right after the title page
 */

const fs = require('fs');
const path = require('path');
const {
  VOLUMES,
  MODULE_TO_VOLUME,
  SKIP_H2_INLINE,
  SKIP_H2_ALWAYS,
} = require('./volume-config.js');

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------
const volumeNum = parseInt(process.argv[2], 10);
const inputFile = process.argv[3];
const outputFile = process.argv[4];

if (!volumeNum || !inputFile || !outputFile) {
  console.error('Usage: node md2pdf-volume.js <volumeNum> <input.md> <output.md>');
  process.exit(1);
}

const volume = VOLUMES[volumeNum];
if (!volume) {
  console.error(`Unknown volume: ${volumeNum}. Valid: ${Object.keys(VOLUMES).join(', ')}`);
  process.exit(1);
}

// ---------------------------------------------------------------------------
// Filter pass — produce volume-specific markdown
// ---------------------------------------------------------------------------
const lines = fs.readFileSync(inputFile, 'utf-8').split('\n');
const output = [];

let inFrontMatter = true;       // Before first H2
let currentH2 = null;            // Current H2 heading text
let includeCurrentH2 = false;    // Whether to emit lines from this H2
let inInlineSkip = false;        // Inside an embedded sample-doc section
let inFence = false;             // Inside a ``` / ~~~ fenced code block

for (let i = 0; i < lines.length; i++) {
  const line = lines[i];

  // Track fenced code blocks FIRST. Inside a fence, lines beginning with
  // "## "/"### " are CODE (e.g. a sample document shown inside ```markdown),
  // NOT real headings — running heading/skip detection on them corrupts the
  // block and leaves an unbalanced fence in the filtered output (which then
  // swallows later real headings). Emit the fence marker per current state.
  if (/^\s*(```|~~~)/.test(line)) {
    inFence = !inFence;
    if (inFrontMatter) { output.push(line); continue; }
    if (inInlineSkip) continue;
    if (includeCurrentH2) output.push(line);
    continue;
  }

  // H2 heading detection (only OUTSIDE code fences)
  if (!inFence && line.startsWith('## ') && !line.startsWith('### ')) {
    inFrontMatter = false;
    const h2Text = line.slice(3).trim();

    // Embedded sample-doc H2: enter inline-skip mode (preserve parent state)
    if (SKIP_H2_INLINE.has(h2Text)) {
      inInlineSkip = true;
      continue;
    }

    // Real H2 — exit inline-skip if we were in it
    inInlineSkip = false;
    currentH2 = h2Text;

    // Always-skipped H2 (TOC etc.)
    if (SKIP_H2_ALWAYS.has(h2Text)) {
      includeCurrentH2 = false;
      continue;
    }

    // Volume include / exclude
    if (volume.includeH2.has(h2Text)) {
      includeCurrentH2 = true;
      output.push(line);
      continue;
    }

    includeCurrentH2 = false;
    continue;
  }

  // Front matter: always include
  if (inFrontMatter) {
    output.push(line);
    continue;
  }

  // Inline-skip persists through ALL H3s — only an H2 boundary can end it
  // (handled in the H2 branch above). The embedded Risk Acceptance Statement
  // sample doc inside Unit 11.6 contains H3s like "### Phase 2: Hybrid
  // Deployment" that must remain suppressed even though they sit inside the
  // kept Module 11 H2.
  if (inInlineSkip) {
    continue;
  }

  // Inside a kept H2: emit
  if (includeCurrentH2) {
    output.push(line);
  }
}

// ---------------------------------------------------------------------------
// Cross-reference rewriting pass
// ---------------------------------------------------------------------------
// Strategy:
//   • Detect references to "Unit X.Y" or "Module N" where the target's module
//     belongs to a DIFFERENT volume.
//   • Rewrite them to "Volume N, Unit X.Y" (drops broken anchor).
//   • Same-volume references are left alone — anchors still resolve.

function moduleOfUnit(unitDotted) {
  // "11.9.7" → 11; "4.2" → 4; "3" → 3
  const m = String(unitDotted).match(/^(\d+)/);
  return m ? parseInt(m[1], 10) : null;
}

function isCrossVolume(targetModule) {
  if (!targetModule || !MODULE_TO_VOLUME[targetModule]) return false;
  return MODULE_TO_VOLUME[targetModule] !== volume.num;
}

function targetVolumeNum(targetModule) {
  return MODULE_TO_VOLUME[targetModule];
}

let rewriteStats = {
  proseUnitRefs: 0,
  proseModuleRefs: 0,
  anchorUnitRefs: 0,
  anchorModuleRefs: 0,
};

let result = output.join('\n');

// ---- Pattern 1: markdown anchor links to units --------------------------
// Examples:
//   [Unit 4.2](#unit-42)
//   [Unit 11.9.7](#unit-1197)
//   [Unit 11.10: PQC CVE Registry](#unit-1110-pqc-cve-registry)
//   [Module 4](#module-4)
//   [Module 4: ML-KEM Deep Dive](#module-4-ml-kem-deep-dive)
result = result.replace(
  /\[(Unit|Module) (\d+(?:\.\d+)*)([^\]]*)\]\(#[a-z0-9-]+\)/g,
  (m, kind, num, suffix) => {
    const mod = moduleOfUnit(num);
    if (!isCrossVolume(mod)) return m;       // same-volume → keep anchor
    const tgtVol = targetVolumeNum(mod);
    if (kind === 'Unit') rewriteStats.anchorUnitRefs++;
    else rewriteStats.anchorModuleRefs++;
    return `*Volume ${tgtVol}, ${kind} ${num}${suffix}*`;
  }
);

// ---- Patterns 2–5: prose cross-references (fence-aware) -----------------
// Patterns 2–4 (prose "see Unit/Module N") and Pattern 5 (bare "Module N"
// catch-all) all rewrite PROSE only and must NOT touch fenced code — otherwise
// comments like `// see Module 4` inside a C listing get mangled. We run them
// in a single line-by-line pass that tracks ``` / ~~~ (incl. indented) fences.
{
  const linesArr = result.split('\n');
  let inFence = false;
  for (let i = 0; i < linesArr.length; i++) {
    // Toggle on a fence marker (```... or ~~~..., optionally indented).
    if (/^\s*(```|~~~)/.test(linesArr[i])) {
      inFence = !inFence;
      continue;
    }
    if (inFence) continue;

    // Pattern 2: prose "see/in/from Unit X.Y" (skip markdown link text via
    // the negative lookbehind on `[`).
    linesArr[i] = linesArr[i].replace(
      /(?<![\[])(\b(?:see|See|in|from|of|per|via|using|consult|cf\.)\s+)Unit\s+(\d+(?:\.\d+)*)/g,
      (m, prefix, num) => {
        const mod = moduleOfUnit(num);
        if (!isCrossVolume(mod)) return m;
        const tgtVol = targetVolumeNum(mod);
        rewriteStats.proseUnitRefs++;
        return `${prefix}Volume ${tgtVol}, Unit ${num}`;
      }
    );

    // Pattern 3: prose "see/in/from Module N"
    linesArr[i] = linesArr[i].replace(
      /(?<![\[])(\b(?:see|See|in|from|of|per|via|using|consult)\s+)Module\s+(\d+)/g,
      (m, prefix, num) => {
        const mod = parseInt(num, 10);
        if (!isCrossVolume(mod)) return m;
        const tgtVol = targetVolumeNum(mod);
        rewriteStats.proseModuleRefs++;
        return `${prefix}Volume ${tgtVol}, Module ${num}`;
      }
    );

    // Pattern 4: parenthetical "(see Module N)" / "(see Unit X.Y)"
    linesArr[i] = linesArr[i].replace(
      /\(see (Unit|Module) (\d+(?:\.\d+)*)\)/g,
      (m, kind, num) => {
        const mod = kind === 'Module' ? parseInt(num, 10) : moduleOfUnit(num);
        if (!isCrossVolume(mod)) return m;
        const tgtVol = targetVolumeNum(mod);
        if (kind === 'Unit') rewriteStats.proseUnitRefs++;
        else rewriteStats.proseModuleRefs++;
        return `(see Volume ${tgtVol}, ${kind} ${num})`;
      }
    );

    // Skip real module H2/H3 headings before the broad Pattern 5 catch-all —
    // these headings belong to the volume; cross-vol H2s were already filtered.
    if (linesArr[i].startsWith('## Module ') || linesArr[i].startsWith('### Module ')) continue;

    // Pattern 5: bare "Module N" anywhere (broadest catch-all)
    linesArr[i] = linesArr[i].replace(
      /\bModule (\d+)\b(?![,.] Volume)/g,
      (m, num) => {
        const mod = parseInt(num, 10);
        if (!isCrossVolume(mod)) return m;
        const tgtVol = targetVolumeNum(mod);
        rewriteStats.proseModuleRefs++;
        return `Volume ${tgtVol}, Module ${num}`;
      }
    );

    // Also "Modules N-M" ranges (e.g., "Modules 8-11")
    linesArr[i] = linesArr[i].replace(
      /\bModules (\d+)[-–](\d+)\b/g,
      (m, lo, hi) => {
        const loN = parseInt(lo, 10), hiN = parseInt(hi, 10);
        const loVol = MODULE_TO_VOLUME[loN];
        const hiVol = MODULE_TO_VOLUME[hiN];
        if (loVol === volume.num && hiVol === volume.num) return m;
        if (loVol !== volume.num && hiVol !== volume.num) {
          // Whole range is in other volume
          rewriteStats.proseModuleRefs++;
          return `Volume ${loVol}, Modules ${lo}–${hi}`;
        }
        // Range straddles volumes — annotate
        rewriteStats.proseModuleRefs++;
        return `Modules ${lo}–${hi} (Volume ${loVol} for ${lo}, Volume ${hiVol} for ${hi})`;
      }
    );
  }
  result = linesArr.join('\n');
}

// ---------------------------------------------------------------------------
// Generate fresh TOC from filtered output
// ---------------------------------------------------------------------------
function slugify(text) {
  return text.toLowerCase()
    .replace(/[^\w\s-]/g, '')
    .replace(/\s+/g, '-')
    .replace(/^-+|-+$/g, '');
}

function generateTOC(markdown) {
  const tocLines = ['## Table of Contents', ''];
  const skipBefore = 'The Post-Quantum Transition at a Glance';
  let started = false;
  let inFence = false;
  for (const line of markdown.split('\n')) {
    // Skip headings inside fenced code blocks (e.g. sample-document "## ..."
    // lines), otherwise the TOC links to anchors that have no heading element.
    if (/^\s*(```|~~~)/.test(line)) { inFence = !inFence; continue; }
    if (inFence) continue;
    if (line.startsWith('## ') && !line.startsWith('### ')) {
      const text = line.slice(3).trim();
      if (text === skipBefore) started = true;
      if (!started) continue;
      const anchor = slugify(text);
      tocLines.push(`- [${text}](#${anchor})`);
    } else if (line.startsWith('### ') && started) {
      const text = line.slice(4).trim();
      const anchor = slugify(text);
      tocLines.push(`  - [${text}](#${anchor})`);
    }
  }
  tocLines.push('', '---', '');
  return tocLines.join('\n');
}

const generatedTOC = generateTOC(result);

// ---------------------------------------------------------------------------
// Inject volume notice + fresh TOC after the title page (first '---')
// ---------------------------------------------------------------------------
const titleEndIdx = result.indexOf('\n---\n');
let finalResult;
if (titleEndIdx > 0) {
  finalResult =
    result.slice(0, titleEndIdx + 5) +
    volume.notice +
    generatedTOC +
    result.slice(titleEndIdx + 5);
} else {
  finalResult = volume.notice + generatedTOC + result;
}

fs.writeFileSync(outputFile, finalResult);

// ---------------------------------------------------------------------------
// Report
// ---------------------------------------------------------------------------
const inputLines = lines.length;
const outputLineCount = finalResult.split('\n').length;
const pctRetained = (outputLineCount / inputLines * 100).toFixed(1);

console.error(`Volume ${volume.num} filter:`);
console.error(`  ${inputLines} → ${outputLineCount} lines (${pctRetained}% retained)`);
console.error(`  Cross-references rewritten:`);
console.error(`    Prose Unit refs:    ${rewriteStats.proseUnitRefs}`);
console.error(`    Prose Module refs:  ${rewriteStats.proseModuleRefs}`);
console.error(`    Anchor Unit refs:   ${rewriteStats.anchorUnitRefs}`);
console.error(`    Anchor Module refs: ${rewriteStats.anchorModuleRefs}`);
console.error(`  Output: ${outputFile}`);
