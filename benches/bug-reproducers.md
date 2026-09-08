# HyperLica audit regressions on current Symbolica dev

Upstream base: `fb845d34bda8ccf1fedef6544d3aa46dc24944e3` (2026-09-08).
Commit `bd29c4704eaa4ea5754330a7c43d59d2bd50e065` incorporates the powered
denominator, leading-unit, rational-scaling, duplicate-factor, zero-denominator,
constant-map and sparse-partial-fraction fixes. It also normalizes nonzero
univariate GCD results with a zero operand, including algebraic extensions;
that was the source of the intermittent Galois-upgrade factorization panic.

The local overlay retains generic rational arithmetic and polynomial kernels,
native factored-coefficient partial fractions, extra exact-value regressions
and checked denominator multiplicities. It does not replace upstream's
constructors with the former local construction implementation.

## Retained regression coverage

The five obsolete standalone MRE examples have been removed. Their historical
sources remain recoverable from the earlier `symbolica-hyperlica.patch` series
and Git history; they are not part of the current performance patch.

Coverage remains in the native unit tests: factored constructor and arithmetic
regressions, `constants_can_grow_and_shrink_variable_maps`,
`sparse_partial_fractions_preserve_maps_and_skip_zero_terms`,
`gcd_with_zero_is_monic_over_extensions`, `galois_upgrade`, and the root-isolation
`isolate` test. No library test or production implementation was removed.

Run the native suite from this checkout:

```sh
cargo test --locked --lib -- --test-threads=1
```

Supply your normal `SYMBOLICA_LICENSE` through the environment if required;
no license value belongs in source or saved logs. Use a debug build and provide
a C++ compiler on PATH for native-code-generation tests.

The corrected upstream root-isolation test expects `[3/16, 9/32]`. The former
`[15/64, 9/32]` assertion was a test-expectation mismatch, not an incorrect root;
the refined interval remains `[1023/4096, 2049/8192]`.

Current upstream canonicalizes zero factored rationals to empty denominators
and drops removable zero-power factors before map unification. Regression
tests respect those representation choices while preserving exact-value checks.

For measured validation results and performance boundaries, consult the parent
HyperLica report. These runnable commands are not a claim that a particular
suite or benchmark has already passed.
