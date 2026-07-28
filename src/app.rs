//! Application configuration and runtime module.
//!
//! This module contains CLI parsing, configuration, daemon orchestration,
//! and runtime shutdown logic.

pub mod cli;
pub mod config;
pub mod daemon;
pub mod restart;
pub mod runtime;
pub mod tasks;

pub use cli::Cli;
pub use restart::{Outcome, RESTART_EXIT_CODE};
pub use runtime::run;
