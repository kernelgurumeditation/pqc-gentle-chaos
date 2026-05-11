#!/usr/bin/env node
/**
 * md2pdf-essentials.js
 *
 * Generate the "Essentials Edition" filtered Markdown from the full
 * PQC Developer's Handbook. Target: ~300 pages.
 *
 * Usage:
 *   node md2pdf-essentials.js <input.md> <output.md>
 *
 * Then feed output.md into md2pdf.js for HTML+PDF generation.
 *
 * Inclusion strategy:
 *   - Always include front matter (title, intro)
 *   - Always include TOC, Glossary, Alphabetical Index, Quick Reference
 *   - Include selected H2 sections in full
 *   - For some H2 sections, include only specified H3 units
 *   - Skip everything else
 */

const fs = require('fs');

const inputFile = process.argv[2];
const outputFile = process.argv[3];

if (!inputFile || !outputFile) {
    console.error('Usage: node md2pdf-essentials.js <input.md> <output.md>');
    process.exit(1);
}

// ============================================================
// INCLUSION CONFIGURATION
// ============================================================

// H2 sections to INCLUDE in full (text match on heading after "## ").
// Section is included entirely from its H2 heading until the next H2.
// NOTE: 'Table of Contents' is intentionally EXCLUDED — we generate a fresh
// one from the filtered output to avoid TOC entries pointing to skipped sections.
const INCLUDE_H2_FULL = new Set([
    'The Post-Quantum Transition at a Glance',
    'How to Use This Document',
    'Glossary of Terms',
    'Course Conclusion',
    'Alphabetical Index',
    'Appendix: Quick Reference Cards',
    'Bibliography',
]);

// H2 sections to INCLUDE BUT FILTER to specified H3 units only.
// Maps H2 heading text → set of H3 unit identifiers (text after "### ").
// Use unit prefix like "Unit 4.1:" to match.
const INCLUDE_H2_FILTERED = new Map([
    // Modules 1-3: skip foundational math (assumed prerequisite for essentials reader)
    // Module 4: KEM concepts only
    ['Module 4: ML-KEM Deep Dive', new Set([
        'Unit 4.1: KEM Concepts and Security Definitions',
    ])],
    ['Module 4 Summary: ML-KEM Deep Dive', null],  // null = include H2 only, no H3 filter
    // Module 5: skip — theory covered enough by Module 6
    ['Module 5 Summary: Digital Signatures Theory', null],
    // Module 6: structural overview only
    ['Module 6: ML-DSA Deep Dive', new Set([
        'Unit 6.1: ML-DSA Structure and Security Model',
    ])],
    ['Module 6 Summary: ML-DSA Deep Dive', null],
    // Module 7: structural overview only
    ['Module 7: SLH-DSA (Hash-Based Digital Signatures)', new Set([
        'Unit 7.1: Hash-Based Signature Foundations',
    ])],
    ['Module 7 Summary: SLH-DSA (Hash-Based Signatures)', null],
    // Module 8: hybrid intro + X-Wing + MTC
    ['Module 8: Hybrid Cryptography', new Set([
        'Unit 8.1: Introduction to Hybrid Cryptography',
        'Unit 8.2: Hybrid Key Exchange',
        'Unit 8.6: Merkle Tree Certificates (MTCs) and the PLANTS Working Group',
    ])],
    ['Module 8 Summary: Hybrid Cryptography', null],
    // Module 9 summary only (protocol details too long for essentials)
    ['Module 9 Summary: Protocol Integration', null],
    // Module 10: agility + Round 2 + threshold (the "what's coming next")
    ['Module 10: Future Algorithms and Research', new Set([
        'Unit 10.3: Cryptographic Agility',
        'Unit 10.5: NIST Additional Signatures — Round 2 Status',
        'Unit 10.6: Post-Quantum Threshold Cryptography',
    ])],
    ['Module 10 Summary: Future Algorithms and Research', null],
    // Module 11 — operational essentials (the most reference-critical content)
    ['Module 11: Migrating Legacy Codebases to Post-Quantum Cryptography', new Set([
        'Unit 11.1: Understanding the Migration Imperative',
        'Unit 11.2: Cryptographic Inventory and Discovery',
        'Unit 11.4: PQC Library Selection and Integration',
        'Unit 11.8: Production Deployment Checklist',
        'Unit 11.9: Cloud KMS Integration for Post-Quantum Cryptography',
        'Unit 11.10: PQC CVE Registry and Implementation Pitfalls',
        'Unit 11.11: Formal Verification Lessons — "Verification Theatre"',
    ])],
    ['Module 11 Summary: Migrating Legacy Codebases to PQC', null],
]);

// H2 headings that EXIT the current section (real module H2s — drop content).
const SKIP_H2_EXIT = new Set([
    'Table of Contents',  // replaced by auto-generated mini-TOC below
    'Resources Summary',
    'Document History',
    'Module 1: Prerequisites and Environment Setup',
    'Module 1 Summary: Prerequisites and Environment Setup',
    'Module 2: Mathematical Foundations',
    'Module 2 Summary: Mathematical Foundations',
    'Module 3: Lattice Cryptography Theory',
    'Module 3 Summary: Lattice Cryptography Theory',
    'Module 5: Digital Signatures Theory',
    'Module 9: Protocol Integration',
    'Performance Benchmarks',
    'Memory Usage Analysis',
    'Hardware Acceleration for PQC',
    'Study Schedules',
    'C/C++ Implementation Projects',
    'Debugging and Testing Cryptographic Code',
    'Appendix: Security Analysis & Advanced Topics',
]);

// H2 headings that are EMBEDDED sample-doc content within an included unit.
// These should be SKIPPED for output but MUST PRESERVE the surrounding
// includeCurrentH2/h3FilterSet state so subsequent H3 units within the
// real parent (e.g., Module 11) continue to be processed correctly.
const SKIP_H2_INLINE = new Set([
    'Version 1.0 | Target: 2030 NIST Compliance',  // sample-doc within Unit 11.6
    'Document Control',
    '1. System Description',
    '2. Current Cryptographic Profile',
    '3. Technical Constraints Preventing Migration',
    '4. Compensating Controls Implemented',
    '5. Residual Risk Assessment',
    '6. Risk Acceptance Statement',
    '7. Approval Signatures',
    '8. Review Schedule',
    'Appendix A: Supporting Evidence',
]);

// ============================================================
// FILTER LOGIC
// ============================================================

const lines = fs.readFileSync(inputFile, 'utf-8').split('\n');
const output = [];

let inFrontMatter = true;       // Before first H2
let currentH2 = null;            // Current H2 heading text (null if not in any)
let includeCurrentH2 = false;    // Whether to emit lines from this H2
let h3FilterSet = null;          // Set of H3 unit prefixes to include (null = include all)
let currentH3 = null;            // Current H3 heading text
let includeCurrentH3 = false;    // Whether current H3 should be emitted
let inInlineSkip = false;        // True while inside an embedded sample-doc section
                                  // (skip everything until next H3 or qualifying H2)

function matchesH3Filter(h3text, filterSet) {
    if (!filterSet) return true;
    for (const prefix of filterSet) {
        if (h3text.startsWith(prefix)) return true;
    }
    return false;
}

for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    // H2 heading
    if (line.startsWith('## ') && !line.startsWith('### ')) {
        inFrontMatter = false;
        const h2Text = line.slice(3).trim();

        // Embedded sample-doc H2: enter inline-skip mode. Preserve
        // outer state (we're still logically inside parent unit/module).
        // Inline-skip exits when we hit the next real H3 or H2.
        if (SKIP_H2_INLINE.has(h2Text)) {
            inInlineSkip = true;
            currentH3 = null;
            includeCurrentH3 = false;
            continue;
        }

        // Real H2 — exit inline-skip if we were in it.
        inInlineSkip = false;
        currentH2 = h2Text;
        currentH3 = null;

        if (SKIP_H2_EXIT.has(h2Text)) {
            includeCurrentH2 = false;
            h3FilterSet = null;
            continue;
        }

        if (INCLUDE_H2_FULL.has(h2Text)) {
            includeCurrentH2 = true;
            h3FilterSet = null;
            output.push(line);
            continue;
        }

        if (INCLUDE_H2_FILTERED.has(h2Text)) {
            includeCurrentH2 = true;
            h3FilterSet = INCLUDE_H2_FILTERED.get(h2Text);
            output.push(line);
            continue;
        }

        // Default: skip unknown H2 sections
        includeCurrentH2 = false;
        h3FilterSet = null;
        continue;
    }

    // H3 heading inside a kept H2
    if (line.startsWith('### ') && includeCurrentH2) {
        // Reaching an H3 ends any embedded inline-skip.
        inInlineSkip = false;

        const h3Text = line.slice(4).trim();
        currentH3 = h3Text;

        if (h3FilterSet === null) {
            // No H3 filter: include all H3 sections
            includeCurrentH3 = true;
            output.push(line);
            continue;
        }

        if (matchesH3Filter(h3Text, h3FilterSet)) {
            includeCurrentH3 = true;
            output.push(line);
            continue;
        }

        includeCurrentH3 = false;
        continue;
    }

    // Front matter: always include
    if (inFrontMatter) {
        output.push(line);
        continue;
    }

    // Suppress all output while in inline-skip (embedded sample-doc body).
    if (inInlineSkip) {
        continue;
    }

    // Inside an H2: emit only if H2 is included AND (no H3 filter OR current H3 included)
    if (includeCurrentH2) {
        if (h3FilterSet === null || currentH3 === null || includeCurrentH3) {
            output.push(line);
        }
    }
}

// ============================================================
// GENERATE FRESH TOC FROM FILTERED OUTPUT
// ============================================================

function slugify(text) {
    return text.toLowerCase()
        .replace(/[^\w\s-]/g, '')
        .replace(/\s+/g, '-')
        .replace(/^-+|-+$/g, '');
}

function generateTOC(filteredLines) {
    const tocLines = ['## Table of Contents', ''];
    const skipBefore = 'The Post-Quantum Transition at a Glance';
    let started = false;
    for (const line of filteredLines) {
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

const generatedTOC = generateTOC(output);

// ============================================================
// PREPEND ESSENTIALS NOTICE + GENERATED TOC
// ============================================================

const essentialsNotice = `
> **Essentials Edition.** This is a curated subset of the full PQC Developer's Handbook (1,220+ pages). It includes the introduction, glossary, key algorithm overviews (ML-KEM, ML-DSA, SLH-DSA, X-Wing), and the operational/migration material (cloud KMS integration, CVE registry, formal verification lessons, production deployment checklist). For mathematical foundations, deep algorithm internals, and full source code references, see the [full edition](pqc-developers-handbook.pdf).
>
> *Generated from \`pqc-developers-handbook.md\` v1.0 — see Document History in the full edition for change log.*

`;

// Find the title page end (first occurrence of "---" after H1) and inject notice + TOC after it
const result = output.join('\n');
const titleEndIdx = result.indexOf('\n---\n');
let finalResult;
if (titleEndIdx > 0) {
    finalResult = result.slice(0, titleEndIdx + 5) + essentialsNotice + generatedTOC + result.slice(titleEndIdx + 5);
} else {
    finalResult = essentialsNotice + generatedTOC + result;
}

fs.writeFileSync(outputFile, finalResult);

const inputLines = lines.length;
const outputLines = finalResult.split('\n').length;
console.error(`Essentials filter: ${inputLines} → ${outputLines} lines (${(outputLines / inputLines * 100).toFixed(1)}%)`);
