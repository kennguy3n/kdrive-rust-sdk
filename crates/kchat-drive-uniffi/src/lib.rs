#![allow(clippy::too_many_arguments)]

uniffi::setup_scaffolding!();

pub mod error;
pub mod facade;

pub use error::*;
pub use facade::*;
