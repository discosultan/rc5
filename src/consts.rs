use num_bigint::BigInt;
use num_rational::BigRational;
use num_traits::{FromPrimitive, One, ToPrimitive, Zero};

use crate::bytes::ByteInteger;

pub fn p<const WBIT: usize, const WBYTE: usize>() -> [u8; WBYTE] {
    // Number of terms to include in the series.
    const TERMS: u64 = 34;
    let e = approximate_e(TERMS);

    let result: BigRational = (e - big_rational_two()) * big_rational_two().pow(WBIT as i32);

    let result = result.to_u128().expect("Unable to represent constant p.");

    <[u8; WBYTE]>::from_slice(&odd(result).to_le_bytes())
}

pub fn q<const WBIT: usize, const WBYTE: usize>() -> [u8; WBYTE] {
    // Number of terms to include in the series.
    const TERMS: u64 = 93;
    let phi = approximate_golden_ratio(TERMS);

    let result = (phi - BigRational::one()) * big_rational_two().pow(WBIT as i32);

    let result = result.to_u128().expect("Unable to represent constant q.");

    <[u8; WBYTE]>::from_slice(&odd(result).to_le_bytes())
}

fn odd(value: u128) -> u128 {
    if value % 2 == 0 {
        value + 1
    } else {
        value
    }
}

fn big_rational_two() -> BigRational {
    // TODO: Recreate without unwrap.
    BigRational::from_u8(2).unwrap()
}

fn factorial(n: u64) -> BigInt {
    let mut result = BigInt::one();
    for idx in 1..=n {
        result *= idx;
    }
    result
}

fn approximate_e(terms: u64) -> BigRational {
    let mut e = BigRational::zero();
    for idx in 0..terms {
        let factorial_i = factorial(idx);
        let term = BigRational::from_integer(BigInt::one()) / factorial_i;
        e += term;
    }
    e
}

fn approximate_golden_ratio(terms: u64) -> BigRational {
    let mut phi = BigRational::zero();
    for _ in 0..terms {
        phi = BigRational::one() / (BigRational::one() + phi);
    }
    phi + BigRational::one()
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test cases taken from https://www.grc.com/r&d/rc5.pdf.

    #[test]
    fn p_16() {
        assert_eq!(p::<16, 2>(), [0xE1, 0xB7]);
    }

    #[test]
    fn p_32() {
        assert_eq!(p::<32, 4>(), [0x63, 0x51, 0xE1, 0xB7]);
    }

    #[test]
    fn p_64() {
        assert_eq!(
            p::<64, 8>(),
            [0x6B, 0x2A, 0xED, 0x8A, 0x62, 0x51, 0xE1, 0xb7]
        );
    }

    #[test]
    fn q_16() {
        assert_eq!(q::<16, 2>(), [0x37, 0x9E]);
    }

    #[test]
    fn q_32() {
        assert_eq!(q::<32, 4>(), [0xB9, 0x79, 0x37, 0x9E]);
    }

    #[test]
    fn q_64() {
        assert_eq!(
            q::<64, 8>(),
            [0x15, 0x7C, 0x4A, 0x7F, 0xB9, 0x79, 0x37, 0x9E]
        );
    }
}
