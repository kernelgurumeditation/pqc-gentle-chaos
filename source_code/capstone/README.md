# Graded Capstone: Hybrid Secure Channel

A single, self-contained, **deterministic** C program that stitches together
the three pillars of the PQC Developer's Handbook into one end-to-end
"hybrid secure channel" handshake:

- **Module 4 (ML-KEM)** — post-quantum key encapsulation + an HKDF-style KDF
- **Module 6 (ML-DSA)** — a Fiat-Shamir lattice signature over the transcript
- **Module 8 (Hybrid Cryptography)** — the X-Wing combiner (X25519 + ML-KEM-768)

It builds with the same flags as the rest of `source_code/`, runs to a clear
`CAPSTONE: PASS` / `CAPSTONE: FAIL` verdict, and is byte-for-byte reproducible
under a fixed seed.

> ### EDUCATIONAL, NOT PRODUCTION
> Like every other example in `source_code/`, this uses **toy primitives**:
> the "hash" is a small deterministic mixing function (NOT SHA-3/SHAKE),
> "X25519" is a DH-shaped hash construction (NOT Curve25519), "ML-KEM" is a
> hash-shaped KEM (NOT a real lattice KEM), and the signature runs at a tiny
> dimension. The **data flow and algorithm shapes are faithful** to the real
> constructions, but **none of it is cryptographically secure**. For anything
> real, use a FIPS-validated library (e.g. liboqs). No `liboqs`, no `OpenSSL`,
> no external deps — pure **C11 + libm**.

---

## The five milestones (mapped to Modules 4 / 6 / 8)

| # | Milestone | Stage in code | Module(s) | What it proves |
|---|-----------|---------------|-----------|----------------|
| 1 | **Hybrid KEM** | Stage A | 8 (combiner) + 4 (KEM) | A toy X25519 + ML-KEM-768 X-Wing combiner — `ss = H(ss_pq ‖ ss_classical ‖ ct ‖ pk ‖ label)` — lets **both** client and server derive the **same** hybrid shared secret. |
| 2 | **KDF** | Stage B | 4 | HKDF-style **extract → expand** turns the shared secret into a 32-byte session key. |
| 3 | **Sign / Verify** | Stage C | 6 | A toy ML-DSA-65-style Fiat-Shamir signature (`commit w=A·y`, `challenge c=H(w‖m)`, `response z=y+c·s`, verify `A·z − c·t == w`) over the **transcript hash**. Verify **accepts** the valid signature and **rejects** a 1-bit-flipped transcript. |
| 4 | **Self-test / KAT** | Stage D | all | Fixed known-answer values (hybrid shared secret + derived session key) are asserted, so a default-seed run is reproducible. |
| 5 | **Constant-time compare** | Stage E | all | Every secret comparison uses a branch-free `ct_memcmp()` that never early-exits, so its run time does not leak how many leading bytes matched. |

### Why the signature challenge is a scalar (design note)

Real ML-DSA multiplies the challenge polynomial `c` and the matrix `A` in the
**same polynomial ring** `R_q`, so `A·(c·s) = c·(A·s)` for free. This toy uses
an arbitrary integer matrix `A`, where only **scalar** multiplication commutes
with `A`. So the sparse ±1 challenge (TAU entries, exactly as ML-DSA derives it
from `c_tilde`) is folded into a single small scalar before multiplying. This
keeps the Fiat-Shamir `z = y + c·s` / verify `A·z − c·t == w` shape **and** the
rejection bound `β = τ·η` meaningful, while staying mathematically correct at
toy scale.

---

## Grading rubric

| Criterion | Weight | How it is checked |
|-----------|:------:|-------------------|
| **Correctness** | 40% | Stage A shared secrets match; Stage C verify accepts the valid signature and rejects the tampered transcript; final line is `CAPSTONE: PASS` with exit code 0. |
| **Constant-time** | 20% | All secret comparisons route through `ct_memcmp()` (Stage E self-checks the helper). |
| **KAT pass / reproducibility** | 20% | Stage D matches fixed known-answer values; `make check` diffs a fresh fixed-seed run against the golden output and must match exactly. |
| **Clean build** | 20% | Compiles with `-Wall -Wextra -Wshadow -O2 -std=c11` and **zero warnings**. |

A submission scores full marks when `make check` passes (which implies a clean
build, exit 0, `CAPSTONE: PASS`, all KATs, and reproducible output).

---

## Build / run / check

```bash
# Build (exact handbook flags: -Wall -Wextra -Wshadow -O2 -std=c11 -lm)
make

# Build and run the demo (prints CAPSTONE: PASS, exits 0)
make test

# Regenerate the golden output from a fixed-seed run
make record        # writes expected/capstone_hybrid_channel.out

# Verify current output matches the golden file (fails on any mismatch)
make check

# Remove the built binary and scratch files
make clean
```

Run the binary directly if you prefer:

```bash
./capstone_hybrid_channel               # default seed 1234567
PQC_DEMO_SEED=42 ./capstone_hybrid_channel   # any other seed (KAT auto-skips)
```

### Determinism

All randomness comes from a fixed-seed LCG. The seed is read from the
`PQC_DEMO_SEED` environment variable, defaulting to **`1234567`** to match the
rest of the repository. Two runs with the same seed produce **identical**
output. The KAT in Stage D applies only to the default seed; for any other seed
the KAT step prints `[SKIP]` and the run still ends in `CAPSTONE: PASS`.

---

## Files

| File | Purpose |
|------|---------|
| `capstone_hybrid_channel.c` | The complete end-to-end demo (Stages A–E). |
| `Makefile` | Targets: `all`, `clean`, `test`, `record`, `check`. |
| `expected/capstone_hybrid_channel.out` | Golden fixed-seed output for `make check`. |
| `README.md` | This file. |
