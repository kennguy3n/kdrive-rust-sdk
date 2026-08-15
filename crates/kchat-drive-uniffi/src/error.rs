#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum DriveSdkError {
    #[error("crypto error: {msg}")]
    Crypto { msg: String },

    #[error("not found: {msg}")]
    NotFound { msg: String },

    #[error("invalid state: {msg}")]
    InvalidState { msg: String },

    #[error("MLS bridge error: {msg}")]
    MlsBridge { msg: String },

    #[error("envelope error: {msg}")]
    Envelope { msg: String },

    #[error("permission denied: {msg}")]
    PermissionDenied { msg: String },

    #[error("invalid input: {msg}")]
    InvalidInput { msg: String },
}

impl From<kchat_drive_types::DriveError> for DriveSdkError {
    fn from(e: kchat_drive_types::DriveError) -> Self {
        match e {
            kchat_drive_types::DriveError::Crypto(msg) => Self::Crypto { msg },
            kchat_drive_types::DriveError::NotFound(msg) => Self::NotFound { msg },
            kchat_drive_types::DriveError::InvalidState(msg) => Self::InvalidState { msg },
            kchat_drive_types::DriveError::MlsBridge(msg) => Self::MlsBridge { msg },
            kchat_drive_types::DriveError::Envelope(msg) => Self::Envelope { msg },
            kchat_drive_types::DriveError::PermissionDenied(msg) => Self::PermissionDenied { msg },
            other => Self::InvalidState {
                msg: other.to_string(),
            },
        }
    }
}
