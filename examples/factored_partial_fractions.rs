//! Matched-build native partial-fraction benchmark.
//!
//! Run with `cargo run --release --example factored_partial_fractions`.
//! Both paths use the same coefficient ring and build. The canonical baseline
//! independently implements the same truncated Taylor recurrence using ordinary
//! rational-polynomial coefficients. Factored timings include materializing all
//! final coefficients; parsing and exact coefficient verification are excluded.
//! Five alternating pairs report per-call medians. These are warmed native-call
//! timings, not cold-process CLI timings.

use std::hint::black_box;
use std::sync::Arc;
use std::time::Instant;
use symbolica::domains::SelfRing;
use symbolica::domains::factorized_rational_polynomial::FromNumeratorAndFactorizedDenominator;
use symbolica::domains::rational_polynomial::FromNumeratorAndDenominator;
use symbolica::prelude::*;
type NativeFactored = FactorizedRationalPolynomial<IntegerRing, u16>;
type NativeRational = RationalPolynomial<IntegerRing, u16>;

fn materialize(input: &NativeFactored) -> NativeRational {
    input.to_rational_polynomial()
}

fn canonical_recurrence(input: &NativeFactored) -> Vec<NativeRational> {
    fn mul(left: &NativeRational, right: &NativeRational) -> NativeRational {
        if left.is_zero() || right.is_one() {
            left.clone()
        } else if right.is_zero() || left.is_one() {
            right.clone()
        } else {
            left * right
        }
    }
    fn add(left: &NativeRational, right: &NativeRational) -> NativeRational {
        if left.is_zero() {
            right.clone()
        } else if right.is_zero() {
            left.clone()
        } else if left.denominator == right.denominator {
            NativeRational::from_num_den(
                &left.numerator + &right.numerator,
                left.denominator.clone(),
                &Z,
                true,
            )
        } else {
            left + right
        }
    }
    fn sub(left: &NativeRational, right: &NativeRational) -> NativeRational {
        if right.is_zero() {
            left.clone()
        } else if left.is_zero() {
            -right.clone()
        } else if left.denominator == right.denominator {
            NativeRational::from_num_den(
                &left.numerator - &right.numerator,
                left.denominator.clone(),
                &Z,
                true,
            )
        } else {
            left - right
        }
    }
    fn multiply_shifted(
        series: &mut [NativeRational],
        point: &NativeRational,
        degree: usize,
    ) -> usize {
        let degree = (degree + 1).min(series.len() - 1);
        for index in (1..=degree).rev() {
            series[index] = add(&mul(&series[index], point), &series[index - 1]);
        }
        series[0] = mul(&series[0], point);
        degree
    }
    let zero: NativeRational = input.numerator.zero().into();
    let one: NativeRational = input.numerator.one().into();
    assert!(input.numer_coeff.is_one() && input.denom_coeff.is_one());
    let points = input
        .denominators
        .iter()
        .map(|(base, exponent)| {
            let univariate = base.to_univariate(0);
            assert!(univariate.coefficients()[1].is_one());
            (
                NativeRational::from(-univariate.coefficients()[0].clone()),
                *exponent,
            )
        })
        .collect::<Vec<_>>();
    let numerator = input.numerator.to_univariate(0);
    let mut result = vec![];
    for (index, (point, terms)) in points.iter().enumerate() {
        let mut numerator_series = vec![zero.clone(); *terms];
        let mut degree = 0;
        for (index, coefficient) in numerator.coefficients().iter().rev().enumerate() {
            if index != 0 {
                degree = multiply_shifted(&mut numerator_series, point, degree);
            }
            numerator_series[0] = add(&numerator_series[0], &coefficient.clone().into());
        }
        let mut cofactor = vec![zero.clone(); *terms];
        cofactor[0] = one.clone();
        let mut degree = 0;
        for (other_index, (other_point, multiplicity)) in points.iter().enumerate() {
            if index == other_index {
                continue;
            }
            let difference = sub(point, other_point);
            for _ in 0..*multiplicity {
                degree = multiply_shifted(&mut cofactor, &difference, degree);
            }
        }
        let mut quotient = vec![];
        for exponent in 0..*terms {
            let mut coefficient = numerator_series[exponent].clone();
            for cofactor_exponent in 1..=exponent {
                coefficient = sub(
                    &coefficient,
                    &mul(
                        &cofactor[cofactor_exponent],
                        &quotient[exponent - cofactor_exponent],
                    ),
                );
            }
            quotient.push(&coefficient / &cofactor[0]);
        }
        result.extend(quotient);
    }
    result
}

fn main() {
    println!("poles,multiplicity,native_factored_ms,canonical_recurrence_ms,ratio");
    for multiplicity in [1usize, 3, 6] {
        for pole_count in [2usize, 3, 4] {
            let names = ["x", "a", "b", "c", "d"];
            let names = &names[..=pole_count];
            let variables = Arc::new(
                names
                    .iter()
                    .map(|name| Symbol::parse(name, "factored_pf_example").unwrap().into())
                    .collect::<Vec<PolyVariable>>(),
            );
            let poly = |text: &str| {
                Atom::parse(text, "factored_pf_example", ParseSettings::default())
                    .unwrap()
                    .to_polynomial::<_, u16>(&Z, Some(variables.clone()))
            };
            let input = NativeFactored::from_num_den(
                poly("x+a"),
                names[1..]
                    .iter()
                    .map(|name| (poly(&format!("x-{name}")), multiplicity))
                    .collect(),
                &Z,
                false,
            );
            let reference = canonical_recurrence(&input);
            let result = input.apart_factored_denominators(0);
            assert_eq!(
                result
                    .iter()
                    .map(|(coefficient, _, _)| materialize(coefficient))
                    .collect::<Vec<_>>(),
                reference
            );
            let candidate = || {
                let result = black_box(&input).apart_factored_denominators(0);
                let materialized = result
                    .iter()
                    .map(|(coefficient, _, _)| materialize(coefficient))
                    .collect::<Vec<_>>();
                black_box(materialized);
            };
            let baseline = || {
                black_box(canonical_recurrence(black_box(&input)));
            };
            let repetitions = if multiplicity == 1 {
                256
            } else if multiplicity == 3 {
                8
            } else {
                1
            };
            let mut candidate_samples = vec![];
            let mut baseline_samples = vec![];
            for pair in 0..5 {
                let mut measure = |is_candidate| {
                    let start = Instant::now();
                    for _ in 0..repetitions {
                        if is_candidate {
                            candidate();
                        } else {
                            baseline();
                        }
                    }
                    let time = start.elapsed().as_secs_f64() * 1000. / repetitions as f64;
                    if is_candidate {
                        candidate_samples.push(time);
                    } else {
                        baseline_samples.push(time);
                    }
                };
                measure(pair % 2 == 0);
                measure(pair % 2 != 0);
            }
            candidate_samples.sort_by(f64::total_cmp);
            baseline_samples.sort_by(f64::total_cmp);
            println!(
                "{pole_count},{multiplicity},{:.6},{:.6},{:.4}",
                candidate_samples[2],
                baseline_samples[2],
                candidate_samples[2] / baseline_samples[2]
            );
        }
    }
}
