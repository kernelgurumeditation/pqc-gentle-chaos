/**
 * volume-config.js — defines the two-volume split for the PQC handbook.
 *
 * Volume 1 ("Algorithms"): Modules 1–7 — math foundations, lattice theory,
 * and the three NIST FIPS algorithms (ML-KEM/ML-DSA/SLH-DSA) in depth.
 * Audience: library implementers, researchers, students.
 *
 * Volume 2 ("Production"): Modules 8–11 + operational appendices — hybrid
 * crypto, protocol integration, future algorithms, migration, KMS, CVEs,
 * deployment. Audience: SREs, security architects, compliance.
 *
 * Both volumes share: Glossary, Bibliography, Quick Start Gateway (filtered
 * to volume-relevant personas), front matter, Document History.
 */

// ---------------------------------------------------------------------------
// Unit → Volume mapping (drives cross-reference rewriting)
// ---------------------------------------------------------------------------
// Maps a Module N → Volume number. Cross-refs to a unit whose module is in
// a different volume get rewritten to "Volume N, Unit X.Y".
const MODULE_TO_VOLUME = {
  1: 1, 2: 1, 3: 1, 4: 1, 5: 1, 6: 1, 7: 1,
  8: 2, 9: 2, 10: 2, 11: 2,
};

const VOLUME_TITLES = {
  1: 'Post-Quantum Cryptography — Algorithms (Theory and Implementation)',
  2: 'Post-Quantum Cryptography — Production (Migration and Operations)',
};

const VOLUME_FILENAMES = {
  1: 'pqc-developers-handbook-vol1',
  2: 'pqc-developers-handbook-vol2',
};

// ---------------------------------------------------------------------------
// H2 sections to skip as embedded sample-doc content (within Unit 11.6 RAS).
// Same behavior as md2pdf-essentials.js: preserves outer parent state but
// suppresses output until next real H3 or qualifying H2.
// ---------------------------------------------------------------------------
const SKIP_H2_INLINE = new Set([
  'Version 1.0 | Target: 2030 NIST Compliance',
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

// Always skipped (replaced or not relevant per-volume)
const SKIP_H2_ALWAYS = new Set([
  'Table of Contents',  // regenerated per volume
]);

// ---------------------------------------------------------------------------
// Volume 1 H2 inclusions
// ---------------------------------------------------------------------------
const VOL1_INCLUDE_H2 = new Set([
  'The Post-Quantum Transition at a Glance',
  'How to Use This Document',
  'Quick Start Gateway — Pick Your Path',
  'Glossary of Terms',
  'Module 1: Prerequisites and Environment Setup',
  'Module 1 Summary: Prerequisites and Environment Setup',
  'Module 2: Mathematical Foundations',
  'Module 2 Summary: Mathematical Foundations',
  'Module 3: Lattice Cryptography Theory',
  'Module 3 Summary: Lattice Cryptography Theory',
  'Module 4: ML-KEM Deep Dive',
  'Module 4 Summary: ML-KEM Deep Dive',
  'Module 5: Digital Signatures Theory',
  'Module 5 Summary: Digital Signatures Theory',
  'Module 6: ML-DSA Deep Dive',
  'Module 6 Summary: ML-DSA Deep Dive',
  'Module 7: SLH-DSA (Hash-Based Digital Signatures)',
  'Module 7 Summary: SLH-DSA (Hash-Based Signatures)',
  'Appendix: Security Analysis & Advanced Topics',  // theory-heavy, fits V1
  'Study Schedules',  // shared (theory portion)
  'Bibliography',
  'Alphabetical Index',
  'Document History',
]);

// ---------------------------------------------------------------------------
// Volume 2 H2 inclusions
// ---------------------------------------------------------------------------
const VOL2_INCLUDE_H2 = new Set([
  'The Post-Quantum Transition at a Glance',
  'How to Use This Document',
  'Quick Start Gateway — Pick Your Path',
  'Glossary of Terms',
  'Module 8: Hybrid Cryptography',
  'Module 8 Summary: Hybrid Cryptography',
  'Module 9: Protocol Integration',
  'Module 9 Summary: Protocol Integration',
  'Module 10: Future Algorithms and Research',
  'Module 10 Summary: Future Algorithms and Research',
  'Module 11: Migrating Legacy Codebases to Post-Quantum Cryptography',
  'Module 11 Summary: Migrating Legacy Codebases to PQC',
  'Course Conclusion',
  'Performance Benchmarks',
  'Memory Usage Analysis',
  'Hardware Acceleration for PQC',
  'C/C++ Implementation Projects',
  'Debugging and Testing Cryptographic Code',
  'Resources Summary',
  'Appendix: Quick Reference Cards',
  'Bibliography',
  'Alphabetical Index',
  'Document History',
]);

// ---------------------------------------------------------------------------
// Per-volume notice prepended to the document
// ---------------------------------------------------------------------------
const VOL1_NOTICE = `
> **Volume 1 of 2 — Algorithms.** This volume covers the mathematical foundations of post-quantum cryptography (Modules 1–3) and the internal structure of the three NIST FIPS PQC standards: **ML-KEM** (FIPS 203), **ML-DSA** (FIPS 204), and **SLH-DSA** (FIPS 205), plus the digital-signature theory underpinning them. Aimed at library implementers, security researchers, and students who need to understand how the algorithms work, not just how to deploy them.
>
> **Volume 2 — Production** ([\`pqc-developers-handbook-vol2.pdf\`](pqc-developers-handbook-vol2.pdf)) covers the operational side: hybrid cryptography (X-Wing), protocol integration (TLS/SSH/S-MIME), Cloud KMS/HSM landscape, the PQC CVE registry, formal-verification lessons, regulatory compliance, and a 12-scenario migration cookbook.
>
> Cross-volume references in this PDF appear as *Volume 2, Unit X.Y* — they are not clickable but resolve when both PDFs are open.
>
> *Generated from the unified master \`pqc-developers-handbook.md\`. Both volumes track the same version (see Document History).*

`;

const VOL2_NOTICE = `
> **Volume 2 of 2 — Production.** This volume covers the operational side of PQC: hybrid cryptography (X-Wing, composite signatures), protocol integration (TLS/SSH/S-MIME/IPsec), Cloud KMS and HSM landscape (AWS/GCP/Azure), the PQC CVE registry and "Verification Theatre" formal-verification lessons, regulatory compliance across 10 jurisdictions, and 12 migration cookbook scenarios. Aimed at SREs, security architects, platform engineers, and compliance officers running production systems through the PQC transition.
>
> **Volume 1 — Algorithms** ([\`pqc-developers-handbook-vol1.pdf\`](pqc-developers-handbook-vol1.pdf)) covers the mathematical foundations and internal structure of ML-KEM (FIPS 203), ML-DSA (FIPS 204), and SLH-DSA (FIPS 205). Read it if you need to understand *how* the algorithms work, not just how to deploy them.
>
> Cross-volume references in this PDF appear as *Volume 1, Unit X.Y* — they are not clickable but resolve when both PDFs are open.
>
> *Generated from the unified master \`pqc-developers-handbook.md\`. Both volumes track the same version (see Document History).*

`;

// ---------------------------------------------------------------------------
// Export configs
// ---------------------------------------------------------------------------
const VOLUMES = {
  1: {
    num: 1,
    title: VOLUME_TITLES[1],
    outputBase: VOLUME_FILENAMES[1],
    includeH2: VOL1_INCLUDE_H2,
    notice: VOL1_NOTICE,
    otherVolumeNum: 2,
    otherVolumeFile: VOLUME_FILENAMES[2] + '.pdf',
  },
  2: {
    num: 2,
    title: VOLUME_TITLES[2],
    outputBase: VOLUME_FILENAMES[2],
    includeH2: VOL2_INCLUDE_H2,
    notice: VOL2_NOTICE,
    otherVolumeNum: 1,
    otherVolumeFile: VOLUME_FILENAMES[1] + '.pdf',
  },
};

module.exports = {
  VOLUMES,
  MODULE_TO_VOLUME,
  SKIP_H2_INLINE,
  SKIP_H2_ALWAYS,
};
