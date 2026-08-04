//! Node management module.
//!
//! Contains onboarding and key management.

pub mod faucet;
pub mod known_identity;
pub mod onboarding;
pub mod registration;

pub use faucet::ensure_kor_balance;
pub use onboarding::{
    open_or_migrate, perform_onboarding, KeySource, NodeKeys, OnboardingOutcome, OnboardingResult,
    SealedKeys, UnregisteredNode,
};

#[cfg(test)]
pub use onboarding::BLS_PASSWORD_ENV;
