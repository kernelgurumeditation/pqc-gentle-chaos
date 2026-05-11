# PQC Developer's Handbook

This is my notebook for learning post-quantum cryptography.

After about 25 years building secure systems (payment rails, control systems, the usual mix of symmetric and asymmetric crypto under everyone-uses-it standards), it became clear that the ground under classical PKI is shifting. I figured I needed to actually understand the new primitives, instead of just filing them under "lattice math, look at it later." So I started writing things down.

What you're looking at is the result. A collection of materials, experiments, exercises, code snippets that compile, and the occasional rant. All of it built up while reading FIPS 203 / 204 / 205 and the surrounding ecosystem. It's a live document. I update it when I have time and when something I read makes me realise a previous explanation was wrong or unclear.

I'm also curious about the stranger corners of cryptography that don't fit the FIPS world: homomorphic encryption, format-preserving encryption (FF1, FF3-1), threshold schemes, and similar. Some of that creeps into the later modules. Most of it is on a "when I get to it" list.

This isn't a polished textbook. It's a working notebook. Expect rough edges in places, very dense reference material in others, and the odd half-finished section. The C code does compile clean and the PDFs do build.

## What's in here

- **`pqc-developers-handbook.md`**: the master document (~55,000 lines, 11 modules, ~226 exercises with solutions). Source of truth. Everything else is generated from this.
- **`source_code/`**: 85 C files across 11 module directories. Standalone files build with `-Wall -Wextra -Wshadow`. A few (Module 1, parts of 7 and 11) use liboqs / OpenSSL conditionally (`make build-ssl` per module).
- **`md2pdf.js`, `md2pdf-essentials.js`, `md2pdf-volume.js`, `volume-config.js`**: the Markdown → HTML → PDF pipeline (WeasyPrint).
- **`scripts/`**: small maintenance helpers (currency lint, link check, volume audit).

## Build it

Requirements:

| Dep | Version | What for |
|-----|---------|----------|
| Node.js   | ≥ 20   | Markdown → HTML (`marked`) |
| Python 3  | ≥ 3.8  | PDF rendering (WeasyPrint) |
| gcc/clang | C11+   | Compiling the C examples |
| liboqs    | latest | Optional. Used by units that wrap reference PQC implementations |
| OpenSSL   | 3.5+   | Optional. Needed for SHAKE/SHA-3 and the more "production" examples |

```bash
npm install                       # installs marked
pip3 install -r requirements.txt  # installs WeasyPrint

make pdf-everything               # builds all four PDFs
```

Or pick one:

```bash
make pdf             # full unified edition
make pdf-essentials  # curated subset
make pdf-volumes     # two-volume split (Algorithms + Production)
```

Source code:

```bash
cd source_code
make all             # compile every standalone module
make test            # run per-module test programs
```

## What it produces, and who each output is for

Four PDFs, all built from the same Markdown source. Pick the one that matches how you're reading.

| File | Pages | Best for |
|------|-------|----------|
| `pqc-developers-handbook.pdf` | ~1,160 | The completist. Everything in one place. Heavy. |
| `pqc-developers-handbook-essentials.pdf` | ~240 | Quick reference. Skips the math foundations and protocol deep-dives; keeps the algorithm overviews and the operational / migration content (Cloud KMS, CVE registry, deployment checklist, regulatory matrix). |
| `pqc-developers-handbook-vol1.pdf` | ~700 | **Algorithms** (Modules 1–7). For somebody implementing or studying the primitives: math foundations, lattice theory, ML-KEM / ML-DSA / SLH-DSA internals. Researchers, library implementers, students. |
| `pqc-developers-handbook-vol2.pdf` | ~420 | **Production** (Modules 8–11 + ops appendices). Hybrid crypto, protocol integration, KMS landscape, the PQC CVE registry, migration cookbook, regulatory deadlines. For SREs, security architects, anyone running real systems through this transition. |

Cross-volume references in V1 and V2 are rewritten automatically ("see Volume 2, Unit 11.10") so each volume reads coherently on its own without dangling links.

The two-volume split is the better choice if you have a single audience. The unified PDF is for the rare reader who actually wants the full thing on one PDF.

## What's covered

Eleven modules, roughly bottom-up:

1. **Prerequisites**: environment, building liboqs / OpenSSL
2. **Math Foundations**: modular arithmetic, polynomial rings, NTT, CBD sampling
3. **Lattice Theory**: LWE, Ring-LWE, Module-LWE, K-PKE
4. **ML-KEM** (FIPS 203): K-PKE, Fujisaki–Okamoto, parameter sets
5. **Digital Signatures Theory**: Fiat–Shamir, lattice signatures
6. **ML-DSA** (FIPS 204): rejection sampling, hints, keygen, signing, verification
7. **SLH-DSA** (FIPS 205): WOTS+, FORS, Merkle trees, XMSS, hypertree
8. **Hybrid Cryptography**: X-Wing, composite signatures, Merkle Tree Certificates
9. **Protocol Integration**: TLS 1.3, SSH, S/MIME, IPsec
10. **Future Algorithms**: FALCON / FN-DSA, BIKE, HQC, crypto-agility, threshold PQC
11. **Migration**: inventory (CBOM), legacy systems, phased rollout, KMS, CVE registry, regulatory matrix

## Maintenance

Anything tied to deadlines, library versions, regulatory dates, or CVE catalogues decays fast. There's a quarterly workflow:

```bash
make maintenance   # currency-lint + check-links
```

`lint-currency` flags 7 categories of stale-by-design tokens (regulator dates, ecosystem versions, statistical figures, CVE references, etc.) for review. `check-links` probes the external URLs with a 30-day cache and a small allowlist for hosts that block bots but serve humans (DOI links, defense.gov, etc.).

## Make targets

| Target | Does |
|--------|------|
| `make pdf` | Full PDF |
| `make pdf-essentials` | Curated ~240pp |
| `make pdf-vol1` / `pdf-vol2` | Single volume |
| `make pdf-volumes` | Both volumes |
| `make pdf-everything` | All four |
| `make lint-currency` | Flag stale tokens |
| `make check-links` | Probe URLs |
| `make maintenance` | Lint + link check |
| `make clean` | Remove generated artefacts |
| `make watch` | Auto-rebuild (needs `entr`) |
| `make help` | Show all targets |

## Sources

Anything authoritative is cited inline in the handbook. The load-bearing references are FIPS 203 / 204 / 205 (and the FIPS 206 IPD for FN-DSA), the IETF drafts for the hybrid constructions (`draft-connolly-cfrg-xwing-kem`, `draft-ietf-tls-ecdhe-mlkem`, `draft-ietf-lamps-pq-composite-sigs`), NIST SP 800-227 and IR 8547, and the CA/B Forum / BSI / ANSSI / NCSC / EU CRA guidance for the operational side.

## License

Apache 2.0. See [LICENSE](LICENSE).

---

If you spot something wrong, please open an issue. Pull requests for corrections welcome. When citing, please reference the version footer in the handbook (the document tracks its own changelog).
