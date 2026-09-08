//! Deterministic rational/integer polynomial multiplication and exact-division benchmark.
//! See benches/rational_polynomial_shapes.md for the matching FLINT oracle and protocol.
use std::{hint::black_box, sync::Arc, time::Instant};
use symbolica::prelude::*;

type P = MultivariatePolynomial<IntegerRing, u16>;
fn polynomial(vars: Arc<Vec<PolyVariable>>, shape: &str, bits: u32, variant: usize) -> P {
    let mut output = MultivariatePolynomial::new(&Z, None, vars.clone());
    let mut index = 0;
    let mut append = |powers: &[u16]| {
        let value = (Integer::from(((index * 17 + variant * 13) % 23 + 1) as i64)
            << bits.saturating_sub(5))
            + Integer::from((index * 3 + variant * 5 + 1) as i64);
        if shape == "sparse8_div128" && variant == 0 {
            // Multiplication by one monomial preserves every product collision.
            let mut shifted = powers.to_vec();
            shifted[0] += 1;
            output.append_monomial(value, &shifted);
        } else {
            output.append_monomial(value, powers);
        }
        index += 1;
    };
    if shape.starts_with("sparse") {
        // The boundary cases have the same support up to one monomial shift,
        // giving maximum dividend degrees 127 versus 128 with equal collisions.
        let high_degree = match shape {
            "sparse8_div127" | "sparse8_div128" => {
                if variant == 0 {
                    64
                } else {
                    63
                }
            }
            _ => 128 - variant as u16,
        };
        append(&vec![0; 8]);
        for variable in 0..8 {
            for degree in [1, high_degree] {
                let mut powers = vec![0; 8];
                powers[variable] = degree;
                append(&powers);
            }
        }
    } else {
        let degree = if shape == "dense3_d12" { 12 } else { 20 } - variant as u16;
        for x in 0..=degree {
            for y in 0..=degree - x {
                for z in 0..=degree - x - y {
                    append(&[x, y, z]);
                }
            }
        }
    }
    output
}

fn main() {
    let rounds: usize = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "8".into())
        .parse()
        .unwrap();
    let directory = std::env::args().nth(2).unwrap();
    std::fs::create_dir_all(&directory).unwrap();
    let variables: Vec<PolyVariable> = [
        symbol!("x"),
        symbol!("y"),
        symbol!("z"),
        symbol!("a"),
        symbol!("b"),
        symbol!("c"),
        symbol!("d"),
        symbol!("e"),
    ]
    .into_iter()
    .map(Into::into)
    .collect();
    println!(
        "shape,bits,rational,operation,domain,nvars,left_terms,right_terms,output_terms,rounds,elapsed_ns"
    );
    for shape in [
        "sparse8_d128",
        "dense3_d12",
        "dense3_d20",
        "sparse8_div127",
        "sparse8_div128",
    ] {
        if std::env::args()
            .nth(3)
            .is_some_and(|filter| filter != shape)
        {
            continue;
        }
        for bits in [12, 63, 127] {
            if std::env::args()
                .nth(4)
                .is_some_and(|filter| filter != bits.to_string())
            {
                continue;
            }
            for rational in [false, true] {
                let nvars = if shape.starts_with("sparse") { 8 } else { 3 };
                let vars = Arc::new(variables[..nvars].to_vec());
                let source = [
                    polynomial(vars.clone(), shape, bits, 0),
                    polynomial(vars.clone(), shape, bits, 1),
                ];
                let mut q = Vec::new();
                for p in source {
                    let mut qp = MultivariatePolynomial::new(&Q, None, vars.clone());
                    for (i, (c, e)) in p.coefficients.iter().zip(p.exponents_iter()).enumerate() {
                        let denominator = if rational { [1, 3, 5, 7, 11][i % 5] } else { 1 };
                        qp.append_monomial(
                            Q.to_element(c.clone(), Integer::from(denominator), true),
                            e,
                        );
                    }
                    q.push(qp);
                }
                let scale = Integer::from(if rational { 1155 } else { 1 });
                let z: Vec<P> = q
                    .iter()
                    .map(|p| p.map_coeff(|c| c.numerator_ref() * (&scale / c.denominator_ref()), Z))
                    .collect();
                let zp = &z[0] * &z[1];
                let qp = &q[0] * &q[1];
                assert_eq!(
                    qp,
                    zp.map_coeff(|c| Q.to_element(c.clone(), &scale * &scale, true), Q)
                );
                assert_eq!(qp.try_div_exact(&q[0]).unwrap(), q[1]);
                assert_eq!(zp.try_div_exact(&z[0]).unwrap(), z[1]);
                let name = format!("{shape}-b{bits}-q{rational}");
                for (suffix, value) in [
                    ("left", q[0].to_string()),
                    ("right", q[1].to_string()),
                    ("product", qp.to_string()),
                ] {
                    std::fs::write(format!("{directory}/{name}.{suffix}"), value).unwrap();
                }
                for operation in ["multiply", "exact_division"] {
                    for domain in ["Q", "Z"] {
                        if std::env::args()
                            .nth(5)
                            .is_some_and(|filter| filter != domain)
                        {
                            continue;
                        }
                        let start = Instant::now();
                        for _ in 0..rounds {
                            if domain == "Q" {
                                black_box(if operation == "multiply" {
                                    black_box(&q[0]) * black_box(&q[1])
                                } else {
                                    black_box(&qp).try_div_exact(black_box(&q[0])).unwrap()
                                });
                            } else {
                                black_box(if operation == "multiply" {
                                    black_box(&z[0]) * black_box(&z[1])
                                } else {
                                    black_box(&zp).try_div_exact(black_box(&z[0])).unwrap()
                                });
                            }
                        }
                        println!(
                            "{shape},{bits},{rational},{operation},{domain},{nvars},{},{},{},{rounds},{}",
                            q[0].nterms(),
                            q[1].nterms(),
                            qp.nterms(),
                            start.elapsed().as_nanos()
                        );
                    }
                }
            }
        }
    }
}
