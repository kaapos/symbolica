# Rational polynomial kernel diagnostics

The `rational_polynomial_shapes` example measures multiplication and exact
division for five deterministic support families, three coefficient-size
parameters, and either integral coefficients or denominators from
`{1,3,5,7,11}`. It emits CSV and writes exact operands/products for an independent
FLINT `fmpq_mpoly` oracle. These diagnostics complement `flint_comparison`, whose
integer-polynomial cases do not directly measure rational-domain dispatch.

```sh
cargo run --locked --release --example rational_polynomial_shapes \
  --no-default-features --features faster_alloc,integer-gmp,float-mpfr \
  -- 20 benchmark-inputs > symbolica.csv
cc -O3 -DNDEBUG benches/support/rational_polynomial_shapes_flint.c \
  $(pkg-config --cflags --libs flint) -o rational-polynomial-shapes-flint
./rational-polynomial-shapes-flint 20 benchmark-inputs > flint.csv
```

Supply your normal Symbolica license through the environment, never in source
or committed command transcripts. FLINT is an optional external benchmark
dependency; the Symbolica and Numerica examples do not require it. Some FLINT
installations need explicit compiler include/library flags instead of pkg-config.

The Rust arguments are `rounds input-directory [shape] [bits] [domain]`. Optional
filters use the CSV names (`dense3_d20`, `127`, `Z`, for example). The C oracle
accepts `rounds input-directory [shape]` with the same shape names. The bit field is
a deterministic generator shift parameter, not an exact maximum bit count;
the additive index term can make small coefficients slightly larger. Families:

| Shape | Variables | Input terms | Product terms |
|---|---:|---:|---:|
| `sparse8_d128` | 8 | 17 × 17 | 245 |
| `dense3_d12` | 3 | 455 × 364 | 2600 |
| `dense3_d20` | 3 | 1771 × 1540 | 11480 |
| `sparse8_div127` | 8 | 17 × 17 | 245 |
| `sparse8_div128` | 8 | 17 × 17 | 245 |

The last two families isolate the checked-division exponent-packing boundary.
Both use input high degrees 64/63; the second multiplies its entire left operand
by `x`, so the actual dividend degree in the first variable is 127 versus 128.
All other variable degrees remain 127. A monomial shift preserves coefficient
values, term counts and every product collision. Merely replacing high degree
64 by 65 would change collisions and is not an isolated boundary control. The original
`sparse8_d128` uses input degrees 128/127 and therefore dividend degree 255,
not 128. The current eight-variable checked-division implementation only
uses its packed-key path when every dividend degree is at most 127.

`Q` is native rational arithmetic; `Z` clears the exact common denominator before
the timed region. Thus Z diagnoses possible coefficient-domain dispatch gains,
not the performance of converting inside an operation. Rust verifies the Q/Z
scalar relation and both quotients. The C oracle reads the same operands and
requires exact equality of products and quotients before timing. Both include
output allocation/destruction and exclude generation, parsing, and validation.

For meaningful comparisons, use the same release profile, Rust compiler,
dependency lockfile and features for baseline and candidate. Archive each full
dependency artifact directory: separate workspace copies can reuse Cargo
artifact names even when their contents differ. Record source/binary hashes and
FLINT/GMP/compiler versions. Pin all measured processes to the same otherwise
idle CPU, set `RAYON_NUM_THREADS=1`, and alternate baseline/candidate process
order over multiple pairs. Report median per-call times and dispersion; tiny
cases need substantially more rounds. CLI startup is not in the timed regions.

The Numerica-only `fraction_polynomial_kernels` example compares the optional
dense kernel with exact generic fraction accumulation, including a fallback
when the kernel declines. It covers dense inputs, a collision-free sparse
product, tiny products, and one/few/many denominators at three coefficient sizes.

```sh
cargo run --locked --release -p numerica \
  --example fraction_polynomial_kernels -- 100 > fraction-kernels.csv
cargo run --locked --release -p numerica \
  --example rational_fastpaths -- 5000 > fraction-scalars.csv
```

The bulk benchmark compares two paths within one revision; use the scalar
example with matched unchanged/patched revisions to isolate scalar changes.
The scalar fused round trip asserts cancellation inside its measured region,
so compare it only with the same source and assertion policy.
