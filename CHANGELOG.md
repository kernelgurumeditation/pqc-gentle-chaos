# Changelog

All notable changes to the PQC Developer's Handbook are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project tracks the handbook edition in the document footer (currently v10.x).

## [Unreleased]

### Added
- Project meta-docs: `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `CITATION.cff`,
  `.editorconfig`, and this `CHANGELOG.md`.
- `scripts/check-structure.sh` — validates balanced code fences and resolvable
  internal anchors in the master handbook before the volume/essentials split.
- `source_code/common/fips_params.h` — single-source FIPS 203/204/205 parameter
  reference, plus a `make verify-params` self-consistency checker.
- Unit→program coverage matrix in `source_code/README.md`.
- Reproducible-RNG seam (`PQC_DEMO_SEED`) across runnable demos so their output
  is deterministic and testable.
- End-to-end ML-KEM-768 round-trip demo and an ML-DSA-65 parameter self-test.
- "Common Misconception" callouts at the four hardest topics (incomplete NTT,
  rejection sampling, few-time FORS, hybrid combiners).
- "Run it:" companion-code callouts linking handbook units to `source_code/`.
- `CITATION.cff` for Zenodo/Scholar citability.

### Changed
- Two-volume split rebalanced (Module 7 moved to Volume 2) for more even page counts.
- Currency refresh: OpenSSH 10.0 default (`mlkem768x25519-sha256`), NIST IR 8610
  (Round-2 additional-signatures status), FN-DSA/FIPS 206 "use ML-DSA now" guidance.
- CI now runs the source test suite, a sanitizer (ASan/UBSan) matrix, and the
  structure check; builds fail loudly (removed failure-masking `|| true`).

### Fixed
- See the deep-audit pass below; PDF filters made fence-aware; `unit_6_7`
  reference ML-DSA implementation now self-verifies VALID.

## [10.0] - 2026-04-25 — Deep Audit Pass

### Changed
- Switched PDF pipeline from Chromium/md-to-pdf to WeasyPrint (CSS Paged Media).

### Fixed
- Clean build (`-Wall -Wextra -Wshadow`, zero warnings) across all source files.
- 35+ FIPS parameters verified; reference additions (master parameter sheet,
  protocol overhead cheat sheet, alphabetical index, production checklist).

## [9.0] - 2026-03

### Changed
- FALCON/FN-DSA status corrected to FIPS 206 draft (IPD August 2025).
- OpenSSL API modernized (`EVP_Digest`); `sprintf`→`snprintf` in PEM encoding.

### Added
- New content on constant-time PQC, formal verification, ACVP/CAVP, hardware
  side-channel attacks, and benchmarking methodology.

[Unreleased]: https://github.com/kernelgurumeditation/pqc-gentle-chaos/compare/v10.0...HEAD
[10.0]: https://github.com/kernelgurumeditation/pqc-gentle-chaos/releases/tag/v10.0
[9.0]: https://github.com/kernelgurumeditation/pqc-gentle-chaos/releases/tag/v9.0
