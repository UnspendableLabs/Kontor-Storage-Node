//! Node management module.
//!
//! Contains onboarding and key management.

pub mod onboarding;

pub use onboarding::{perform_onboarding, OnboardingConfig};

#[cfg(test)]
pub use onboarding::BLS_PASSWORD_ENV;
