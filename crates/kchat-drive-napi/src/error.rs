// Structured error types for the NAPI binding.
//
// napi-rs 3.0 uses `Error<Status>` where `Status` is the Node-API status
// enum (GenericFailure, InvalidArg, etc.). Custom application error codes
// are encoded as a `[CODE]` prefix in the error message.
//
// JS usage:
//   import { parseErrorCode } from 'kchat-drive-napi'
//   try { ... } catch (e) {
//     const code = parseErrorCode(e)
//     if (code === "NotFound") { ... }
//     else if (code === "Crypto") { ... }
//   }

use kchat_drive_types::{DriveError, error_code, error_message};
use napi::bindgen_prelude::{Error, Status};
use napi_derive::napi;

/// Convert a `DriveError` into a `napi::Error` with the error code
/// encoded as a `[CODE]` prefix in the message.
pub fn to_napi_error(e: DriveError) -> Error {
    let code = error_code(&e);
    let msg = error_message(&e);
    Error::new(Status::GenericFailure, format!("[{}] {}", code, msg))
}

/// Create a structured NAPI error with code "InvalidInput" for input
/// validation failures (hex decoding, wrong length, etc.).
pub fn invalid_input(msg: impl Into<String>) -> Error {
    Error::new(
        Status::GenericFailure,
        format!("[InvalidInput] {}", msg.into()),
    )
}

/// Parse the error code from a `[CODE]`-prefixed error message.
/// Returns "Unknown" if no prefix is found.
#[napi]
#[allow(dead_code)]
pub fn parse_error_code(message: String) -> String {
    if let Some(rest) = message.strip_prefix('[')
        && let Some(end) = rest.find(']')
    {
        return rest[..end].to_string();
    }
    "Unknown".to_string()
}
