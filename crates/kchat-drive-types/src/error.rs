use thiserror::Error;

#[derive(Debug, Error)]
pub enum DriveError {
    #[error("invalid ID: {0}")]
    InvalidId(String),

    #[error("CBOR encode error: {0}")]
    CborEncode(String),

    #[error("CBOR decode error: {0}")]
    CborDecode(String),

    #[error("crypto error: {0}")]
    Crypto(String),

    #[error("key envelope error: {0}")]
    Envelope(String),

    #[error("MLS bridge error: {0}")]
    MlsBridge(String),

    #[error("not found: {0}")]
    NotFound(String),

    #[error("permission denied: {0}")]
    PermissionDenied(String),

    #[error("invalid state: {0}")]
    InvalidState(String),

    #[error("serialization error: {0}")]
    Serialize(String),

    #[error("I/O error: {0}")]
    Io(String),

    #[error("no historical grant — request re-share")]
    NoHistoricalGrant,

    #[error("epoch mismatch: expected {expected}, got {got}")]
    EpochMismatch { expected: u64, got: u64 },

    #[error("transport error: {0}")]
    Transport(String),
}

impl From<minicbor::decode::Error> for DriveError {
    fn from(e: minicbor::decode::Error) -> Self {
        DriveError::CborDecode(e.to_string())
    }
}

impl From<minicbor::encode::Error<std::convert::Infallible>> for DriveError {
    fn from(e: minicbor::encode::Error<std::convert::Infallible>) -> Self {
        DriveError::CborEncode(e.to_string())
    }
}

/// Maps a `DriveError` to a short, stable error code string suitable for
/// use across all bindings (WASM, NAPI, UniFFI). This is the single source
/// of truth for the error code taxonomy.
pub fn error_code(e: &DriveError) -> &'static str {
    match e {
        DriveError::InvalidId(_) => "InvalidId",
        DriveError::CborEncode(_) | DriveError::CborDecode(_) => "Serialize",
        DriveError::Crypto(_) => "Crypto",
        DriveError::Envelope(_) => "Envelope",
        DriveError::MlsBridge(_) => "MlsBridge",
        DriveError::NotFound(_) => "NotFound",
        DriveError::PermissionDenied(_) => "PermissionDenied",
        DriveError::InvalidState(_) => "InvalidState",
        DriveError::Serialize(_) => "Serialize",
        DriveError::Io(_) => "Io",
        DriveError::NoHistoricalGrant => "NoHistoricalGrant",
        DriveError::EpochMismatch { .. } => "EpochMismatch",
        DriveError::Transport(_) => "Transport",
    }
}

/// Extracts the human-readable message from a `DriveError`.
/// This is the single source of truth for error message formatting.
pub fn error_message(e: &DriveError) -> String {
    match e {
        DriveError::NoHistoricalGrant => "no historical grant".to_string(),
        DriveError::EpochMismatch { expected, got } => {
            format!("epoch mismatch: expected {}, got {}", expected, got)
        }
        DriveError::InvalidId(m)
        | DriveError::CborEncode(m)
        | DriveError::CborDecode(m)
        | DriveError::Crypto(m)
        | DriveError::Envelope(m)
        | DriveError::MlsBridge(m)
        | DriveError::NotFound(m)
        | DriveError::PermissionDenied(m)
        | DriveError::InvalidState(m)
        | DriveError::Serialize(m)
        | DriveError::Io(m)
        | DriveError::Transport(m) => m.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_code_all_variants() {
        assert_eq!(error_code(&DriveError::InvalidId("x".into())), "InvalidId");
        assert_eq!(error_code(&DriveError::CborEncode("x".into())), "Serialize");
        assert_eq!(error_code(&DriveError::CborDecode("x".into())), "Serialize");
        assert_eq!(error_code(&DriveError::Crypto("x".into())), "Crypto");
        assert_eq!(error_code(&DriveError::Envelope("x".into())), "Envelope");
        assert_eq!(error_code(&DriveError::MlsBridge("x".into())), "MlsBridge");
        assert_eq!(error_code(&DriveError::NotFound("x".into())), "NotFound");
        assert_eq!(
            error_code(&DriveError::PermissionDenied("x".into())),
            "PermissionDenied"
        );
        assert_eq!(
            error_code(&DriveError::InvalidState("x".into())),
            "InvalidState"
        );
        assert_eq!(error_code(&DriveError::Serialize("x".into())), "Serialize");
        assert_eq!(error_code(&DriveError::Io("x".into())), "Io");
        assert_eq!(
            error_code(&DriveError::NoHistoricalGrant),
            "NoHistoricalGrant"
        );
        assert_eq!(
            error_code(&DriveError::EpochMismatch {
                expected: 1,
                got: 2
            }),
            "EpochMismatch"
        );
        assert_eq!(error_code(&DriveError::Transport("x".into())), "Transport");
    }

    #[test]
    fn test_error_message_string_variants() {
        assert_eq!(
            error_message(&DriveError::NotFound("file not found".into())),
            "file not found"
        );
        assert_eq!(
            error_message(&DriveError::Crypto("AES-GCM failed".into())),
            "AES-GCM failed"
        );
    }

    #[test]
    fn test_error_message_special_variants() {
        assert_eq!(
            error_message(&DriveError::NoHistoricalGrant),
            "no historical grant"
        );
        assert_eq!(
            error_message(&DriveError::EpochMismatch {
                expected: 5,
                got: 3
            }),
            "epoch mismatch: expected 5, got 3"
        );
    }

    #[test]
    fn test_error_code_stability() {
        // Error codes are part of the public API — they must not change.
        // JS code checks these strings: if (e.code === "NotFound") { ... }
        let cases = [
            (DriveError::InvalidId("".into()), "InvalidId"),
            (DriveError::CborEncode("".into()), "Serialize"),
            (DriveError::CborDecode("".into()), "Serialize"),
            (DriveError::Crypto("".into()), "Crypto"),
            (DriveError::Envelope("".into()), "Envelope"),
            (DriveError::MlsBridge("".into()), "MlsBridge"),
            (DriveError::NotFound("".into()), "NotFound"),
            (DriveError::PermissionDenied("".into()), "PermissionDenied"),
            (DriveError::InvalidState("".into()), "InvalidState"),
            (DriveError::Serialize("".into()), "Serialize"),
            (DriveError::Io("".into()), "Io"),
            (DriveError::NoHistoricalGrant, "NoHistoricalGrant"),
            (
                DriveError::EpochMismatch {
                    expected: 0,
                    got: 0,
                },
                "EpochMismatch",
            ),
            (DriveError::Transport("".into()), "Transport"),
        ];
        for (err, expected_code) in cases {
            assert_eq!(error_code(&err), expected_code);
        }
    }
}
