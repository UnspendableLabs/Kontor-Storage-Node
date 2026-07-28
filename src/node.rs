//! Node management module.
//!
//! Contains onboarding and key management.

pub mod faucet;
pub mod onboarding;
pub mod registration;

pub use faucet::ensure_kor_balance;
pub use onboarding::{perform_onboarding, OnboardingConfig, OnboardingOutcome, UnregisteredNode};

#[cfg(test)]
pub use onboarding::BLS_PASSWORD_ENV;
