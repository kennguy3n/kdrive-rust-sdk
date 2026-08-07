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
