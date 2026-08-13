// Structured error types for the WASM binding.
//
// Instead of returning `JsValue::from_str(string)`, which forces
// JS callers to parse error messages, we return a JS object with
// `code` and `message` fields.
//
// JS usage:
//   try { ... } catch (e) {
//     if (e.code === "NotFound") { ... }
//     else if (e.code === "Crypto") { ... }
//   }

use kchat_drive_types::{DriveError, error_code, error_message};
use wasm_bindgen::prelude::*;

/// Convert a `DriveError` into a `JsValue` error object with `code` and `message` fields.
pub fn to_js_error(e: DriveError) -> JsValue {
    let code = error_code(&e);
    let msg = error_message(&e);
    let obj = js_sys::Object::new();
    js_sys::Reflect::set(&obj, &"code".into(), &JsValue::from_str(code)).ok();
    js_sys::Reflect::set(&obj, &"message".into(), &JsValue::from_str(&msg)).ok();
    obj.into()
}

/// Create a JS error object from a code string and message string.
pub fn js_error(code: &str, msg: impl AsRef<str>) -> JsValue {
    let obj = js_sys::Object::new();
    js_sys::Reflect::set(&obj, &"code".into(), &JsValue::from_str(code)).ok();
    js_sys::Reflect::set(&obj, &"message".into(), &JsValue::from_str(msg.as_ref())).ok();
    obj.into()
}
