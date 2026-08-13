#![allow(clippy::too_many_arguments)]

pub mod api;
pub mod crypto;
pub mod dedup;
pub mod error;
pub mod types;

pub use api::*;
pub use crypto::*;
pub use dedup::*;

/// Initialize the panic hook for better error messages in the browser console.
/// Call this once before any other WASM function.
#[wasm_bindgen::prelude::wasm_bindgen(start)]
pub fn init_panic_hook() {
    console_error_panic_hook::set_once();
}
