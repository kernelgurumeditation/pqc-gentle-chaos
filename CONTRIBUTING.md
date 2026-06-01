# Contributing to the PQC Developer's Handbook

Thanks for your interest in improving this handbook. It is an educational
reference covering the NIST post-quantum standards (FIPS 203/204/205, draft
206), hybrid cryptography, protocol integration, and migration. Contributions
that improve **correctness**, **clarity**, and **currency** are very welcome.

## Ground rules

- **Educational code, clearly labeled.** The programs under `source_code/` are
  teaching implementations. Toy/simplified parameters and the use of `rand()`
  for non-secret demo values are acceptable **only when clearly labeled** as
  non-production. Never present a simplified construction as secure.
- **Cite primary sources.** Cryptographic constants, sizes, and algorithm steps
  must match the relevant FIPS standard or RFC. When you change a numeric value,
  reference the source in the PR description.
- **Keep it reproducible.** Demos must not depend on wall-clock randomness for
  their printed output — use the `PQC_DEMO_SEED` seam (see existing demos) so
  output can be captured and tested.

## Repository layout

| Path | What it is |
|------|------------|
| `pqc-developers-handbook.md` | The single source of truth (~55k lines, 11 modules). |
| `source_code/module_NN_*/` | Runnable C reference programs, one directory per module. |
| `source_code/common/` | Shared headers (e.g. FIPS parameter reference) and verifiers. |
| `md2pdf*.js`, `volume-config.js` | Markdown → HTML filters that drive the four PDF editions. |
| `scripts/` | Maintenance linters (links, currency, structure, volume audit). |
| `Makefile` | PDF build targets. `source_code/Makefile` builds all modules. |

The variant Markdown files (`-essentials`, `-vol1`, `-vol2`) and the PDFs are
**generated** — edit `pqc-developers-handbook.md`, not the derived files.

## Before you open a PR

Run the local checks that CI runs:

```bash
# 1. Structure: balanced code fences + resolvable internal anchors
bash scripts/check-structure.sh

# 2. Source code builds clean (-Wall -Wextra -Wshadow) and tests pass
make -C source_code all
make -C source_code test        # or: bash source_code/run_tests.sh

# 3. FIPS parameter self-consistency
make -C source_code verify-params

# 4. (If you touched the PDF pipeline) rebuild and eyeball
make pdf-everything
```

### Editing the handbook

- **Anchor edits to text, not line numbers** — the file is large and numbers drift.
- **Keep code fences balanced.** An odd number of ` ``` ` markers silently
  corrupts the volume/essentials filters. `scripts/check-structure.sh` enforces this.
- Sample documents that themselves contain `## ` headings must stay inside a
  fenced block; the filters are fence-aware and will skip them.

### Adding a reference program

1. Place it in the matching `source_code/module_NN_*/` directory using the
   `unit_X_Y_description.c` naming convention.
2. Make sure the module `Makefile` builds it and `-Wall -Wextra -Wshadow` is clean.
3. Add a golden-output fixture (see `make record`) if the output is deterministic.
4. Add a row to the unit→program matrix in `source_code/README.md`.
5. Add a **Run it:** callout in the corresponding handbook unit.

## Style

A `.editorconfig` is provided (4-space C, 2-space JS, tabs in Makefiles). Match
the surrounding code's naming and comment density.

## Conduct

Participation is governed by the [Code of Conduct](CODE_OF_CONDUCT.md).

## License

By contributing you agree your contributions are licensed under the project's
[Apache 2.0](LICENSE) license.
