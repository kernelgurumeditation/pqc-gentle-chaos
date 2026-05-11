# Security

## What this repo is, security-wise

This is a learning notebook for post-quantum cryptography. The C code in `source_code/` is **educational reference**, not production crypto. Several files are explicitly labelled as simplified or stubbed (search the source for "WARNING", "demonstration only", "Not constant-time"). Do not deploy any of this code into a system that protects real keys, real money, or real lives. If you need production PQC, use a vetted library: liboqs, OpenSSL 3.5+ with the PQ provider, BoringSSL, AWS-LC, or the relevant ML-KEM / ML-DSA / SLH-DSA reference implementations from `pq-crystals` and `sphincsplus`.

The PDFs and Markdown describe algorithms and protocols. Treat the prose the same way you'd treat any technical article: read it, verify against the FIPS specifications and IETF drafts cited in the bibliography, then make your own decisions.

## Reporting issues

For non-security issues (typos, broken examples, technical errors in the explanations, build problems), please open a GitHub issue at https://github.com/kernelgurumeditation/pqc-gentle-chaos/issues.

For issues you genuinely consider security-sensitive — for example, an exercise solution that teaches a dangerous pattern without flagging it, or an example that would be exploitable if a reader copied it into production — please email `nuno.felicio@gmail.com` directly rather than opening a public issue. Use the subject line `[pqc-gentle-chaos security]`.

You should not expect a fast response. This is a personal project worked on when there is time. If a fix is straightforward I'll handle it; if it's complex I may invite you to open a public discussion once the immediate dangerous patch is in.

## Scope

In scope:
- Educational code samples that would be exploitable if copied into production without modification.
- Prose statements that materially misrepresent the security of a standard or an implementation pattern.
- Build pipeline issues that would cause a user to ship something unintended.

Out of scope:
- The reference implementations in upstream libraries (report those to the upstream maintainers).
- Performance optimisations.
- Documentation gaps that aren't actively misleading.

## On the educational simplifications

A number of files use simplified random sources (`rand()` instead of `RAND_bytes` or `getrandom()`), reduced parameter sets, and non-constant-time helpers. These are marked at the call site. They are intentional and pedagogical. Removing or "fixing" them would defeat the teaching purpose, but if you find one that is *not* labelled, that is a real bug — please report it.

## License

Apache 2.0. See [LICENSE](LICENSE).
