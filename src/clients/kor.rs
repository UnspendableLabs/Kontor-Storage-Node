//! Exact KOR amounts, and the one way they are written into a signed op.
//!
//! Kontor's `decimal` is a 256-bit magnitude with 18 fractional digits, carried
//! over WIT as four `u64` limbs and a sign (`core/numerics`: `r0` is the least
//! significant limb, scale `10^18`). The node never does arithmetic Kontor
//! would disagree with: it compares a balance against a reserve, a stake
//! against a target, and writes an `add-stake` amount into an expression the
//! Portal rebuilds byte for byte to verify the signature. All three are exact
//! here — an amount is an integer number of 10⁻¹⁸ KOR held in a `u128`, parsed
//! from the decimal string the Portal renders and never routed through `f64`.
//!
//! `u128` caps an amount at ~3.4 × 10²⁰ KOR, which is two limbs of the four.
//! That is far above any supply this network will see, and an amount that
//! does not fit is refused rather than truncated.

use anyhow::{anyhow, Result};
use std::fmt;
use std::str::FromStr;

/// Fractional digits of a Kontor `decimal`.
pub const KOR_DECIMALS: usize = 18;

/// `10^18`: how many indivisible units make one KOR.
const SCALE: u128 = 1_000_000_000_000_000_000;

/// An exact, non-negative KOR amount, in units of 10⁻¹⁸ KOR.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Kor(u128);

impl Kor {
    pub const ZERO: Kor = Kor(0);
    pub const ONE: Kor = Kor(SCALE);

    /// A whole number of KOR.
    #[must_use]
    pub const fn whole(kor: u64) -> Kor {
        Kor(kor as u128 * SCALE)
    }

    #[must_use]
    pub fn is_zero(self) -> bool {
        self.0 == 0
    }

    #[must_use]
    pub fn saturating_sub(self, other: Kor) -> Kor {
        Kor(self.0.saturating_sub(other.0))
    }

    #[must_use]
    pub fn checked_add(self, other: Kor) -> Option<Kor> {
        self.0.checked_add(other.0).map(Kor)
    }

    /// Parse a decimal string as the Portal renders `kor_balance` and the stake
    /// fields: digits, optionally a point and 1–18 fractional digits.
    ///
    /// Deliberately a little more tolerant than [`Kor::fmt`] is strict —
    /// surrounding whitespace and leading zeros are accepted — because this
    /// reads what someone else wrote. Zero is a valid reading (an empty stake is
    /// `"0"`). Exponents, signs and a 19th fractional digit are refused: each
    /// would mean rounding or guessing, and these values decide what the node
    /// signs.
    ///
    /// # Errors
    /// If the string is not such a decimal, or does not fit in a `u128`.
    pub fn parse(raw: &str) -> Result<Kor> {
        let s = raw.trim();
        let (int_part, frac_part) = match s.split_once('.') {
            Some((int_part, frac_part)) => (int_part, Some(frac_part)),
            None => (s, None),
        };

        let all_digits = |part: &str| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit());
        if !all_digits(int_part) {
            return Err(anyhow!(
                "invalid KOR amount {raw:?}: expected a plain decimal"
            ));
        }
        let frac_digits = match frac_part {
            None => "",
            Some(frac) if all_digits(frac) && frac.len() <= KOR_DECIMALS => frac,
            Some(_) => {
                return Err(anyhow!(
                    "invalid KOR amount {raw:?}: at most {KOR_DECIMALS} fractional digits"
                ))
            }
        };

        let overflow = || anyhow!("KOR amount {raw:?} is too large");
        let whole: u128 = int_part.parse().map_err(|_| overflow())?;
        let mut frac: u128 = if frac_digits.is_empty() {
            0
        } else {
            frac_digits.parse().map_err(|_| overflow())?
        };
        // Right-pad to 18 digits: "5" after the point is 5 × 10^17 units.
        for _ in frac_digits.len()..KOR_DECIMALS {
            frac *= 10;
        }

        whole
            .checked_mul(SCALE)
            .and_then(|units| units.checked_add(frac))
            .map(Kor)
            .ok_or_else(overflow)
    }

    /// Parse an amount that must be strictly positive — what an outgoing
    /// `add-stake`, a faucet request or a configured threshold has to be.
    ///
    /// # Errors
    /// As [`Kor::parse`], and if the amount is zero.
    pub fn parse_positive(raw: &str) -> Result<Kor> {
        let amount = Kor::parse(raw)?;
        if amount.is_zero() {
            return Err(anyhow!("KOR amount {raw:?} must be greater than zero"));
        }
        Ok(amount)
    }

    /// The WAVE literal for this amount as a Kontor `decimal` argument.
    ///
    /// `{r0: <low 64 bits>, r1: <high 64 bits>, r2: 0, r3: 0, sign: plus}` —
    /// exactly this spacing, base-10 limbs, `r0` least significant. The Portal
    /// rebuilds the `add-stake(...)` expression from the decimal string the node
    /// sends and verifies the node's BLS signature over it, so this must stay
    /// byte-identical to the Portal's encoder (contract §1).
    #[must_use]
    pub fn wave_literal(self) -> String {
        let low = self.0 & u128::from(u64::MAX);
        let high = self.0 >> 64;
        format!("{{r0: {low}, r1: {high}, r2: 0, r3: 0, sign: plus}}")
    }

    /// A lossy `f64` for the one wire field that is still a JSON number: the
    /// faucet request (contract §6). Never compared or encoded from.
    #[must_use]
    pub fn to_f64_lossy(self) -> f64 {
        // Through the canonical string, so an amount configured as "0.1" goes
        // out as the double nearest 0.1 rather than an accumulated product.
        self.to_string().parse().unwrap_or(f64::MAX)
    }
}

/// The canonical rendering: no leading zeros, no trailing fractional zeros, no
/// point for a whole amount — `^(0|[1-9][0-9]*)(\.[0-9]{1,18})?$`, the form the
/// contract requires on the wire.
impl fmt::Display for Kor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let whole = self.0 / SCALE;
        let frac = self.0 % SCALE;
        if frac == 0 {
            return write!(f, "{whole}");
        }
        let digits = format!("{frac:018}");
        write!(f, "{whole}.{}", digits.trim_end_matches('0'))
    }
}

/// Serialized as its canonical string, the shape every KOR amount has on the
/// wire — an admin page reading a JSON number would be back to `f64`.
impl serde::Serialize for Kor {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl FromStr for Kor {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        Kor::parse(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn literal(raw: &str) -> String {
        Kor::parse(raw).unwrap().wave_literal()
    }

    /// The vectors the Portal's encoder is pinned to as well. If either side
    /// changes one of these strings, every `add-stake` signature breaks.
    #[test]
    fn wave_literals_match_the_contract_byte_for_byte() {
        assert_eq!(
            literal("1"),
            "{r0: 1000000000000000000, r1: 0, r2: 0, r3: 0, sign: plus}"
        );
        assert_eq!(
            literal("0.5"),
            "{r0: 500000000000000000, r1: 0, r2: 0, r3: 0, sign: plus}"
        );
        assert_eq!(
            literal("250.5"),
            "{r0: 10692327041775828992, r1: 13, r2: 0, r3: 0, sign: plus}"
        );
        assert_eq!(
            literal("1000"),
            "{r0: 3875820019684212736, r1: 54, r2: 0, r3: 0, sign: plus}"
        );
        assert_eq!(
            literal("0.000000000000000001"),
            "{r0: 1, r1: 0, r2: 0, r3: 0, sign: plus}"
        );
    }

    /// 2^64 − 1 units is the last amount that fits in `r0` alone — the cap the
    /// Portal's old transfer encoder stopped at — and one unit more is the
    /// first that carries into `r1`.
    #[test]
    fn the_r0_boundary_carries_into_r1() {
        assert_eq!(
            literal("18.446744073709551615"),
            "{r0: 18446744073709551615, r1: 0, r2: 0, r3: 0, sign: plus}"
        );
        assert_eq!(
            literal("18.446744073709551616"),
            "{r0: 0, r1: 1, r2: 0, r3: 0, sign: plus}"
        );
    }

    #[test]
    fn the_largest_amount_fills_both_limbs_and_one_unit_more_is_refused() {
        let max = "340282366920938463463.374607431768211455";
        assert_eq!(
            literal(max),
            "{r0: 18446744073709551615, r1: 18446744073709551615, r2: 0, r3: 0, sign: plus}"
        );
        assert_eq!(Kor::parse(max).unwrap().to_string(), max);
        assert!(Kor::parse("340282366920938463463.374607431768211456").is_err());
        assert!(Kor::parse("340282366920938463464").is_err());
        assert!(Kor::parse("999999999999999999999999999999999999999999").is_err());
    }

    #[test]
    fn display_is_canonical() {
        for (raw, canonical) in [
            ("0", "0"),
            ("000", "0"),
            ("1", "1"),
            ("1.0", "1"),
            ("1.000000000000000000", "1"),
            ("0.5", "0.5"),
            ("0.50", "0.5"),
            ("007.25", "7.25"),
            ("12.5", "12.5"),
            (" 995 ", "995"),
            ("0.000000000000000001", "0.000000000000000001"),
        ] {
            assert_eq!(Kor::parse(raw).unwrap().to_string(), canonical, "{raw:?}");
        }
    }

    #[test]
    fn anything_that_would_need_rounding_or_guessing_is_refused() {
        for bad in [
            "",
            " ",
            ".",
            ".5",
            "5.",
            "-1",
            "+1",
            "1e3",
            "1,5",
            "1.2.3",
            "0x10",
            "NaN",
            "inf",
            "0.0000000000000000001", // 19 fractional digits
        ] {
            assert!(Kor::parse(bad).is_err(), "{bad:?} must be refused");
        }
    }

    #[test]
    fn parse_positive_refuses_zero_only() {
        assert!(Kor::parse_positive("0").is_err());
        assert!(Kor::parse_positive("0.0").is_err());
        assert_eq!(Kor::parse_positive("0.000000000000000001").unwrap(), Kor(1));
    }

    #[test]
    fn arithmetic_is_exact_and_never_wraps() {
        let balance = Kor::parse("1000").unwrap();
        let reserve = Kor::parse("5").unwrap();
        assert_eq!(balance.saturating_sub(reserve).to_string(), "995");
        assert_eq!(reserve.saturating_sub(balance), Kor::ZERO);
        assert_eq!(
            Kor::parse("0.1")
                .unwrap()
                .checked_add(Kor::parse("0.2").unwrap())
                .unwrap()
                .to_string(),
            "0.3",
            "the sum f64 famously gets wrong"
        );
        assert_eq!(Kor(u128::MAX).checked_add(Kor(1)), None);
        assert_eq!(Kor::whole(5), Kor::parse("5").unwrap());
        assert!(Kor::ONE < Kor::parse("1.000000000000000001").unwrap());
    }

    #[test]
    fn the_faucet_number_is_the_nearest_double() {
        assert_eq!(Kor::whole(1000).to_f64_lossy(), 1000.0);
        assert_eq!(Kor::parse("0.1").unwrap().to_f64_lossy(), 0.1);
    }
}
