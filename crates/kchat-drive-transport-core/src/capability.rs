use kchat_drive_types::DriveError;

/// Short-lived download capability (architecture §17).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DownloadCapability {
    pub capability_token: String,
    pub blob_key: String,
    pub expires_at: u64,
}

/// Upload session capability.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct UploadCapability {
    pub session_id: String,
    pub blob_key: String,
    pub edge_target: String,
    pub expires_at: u64,
}

/// Trait for transport backends that can issue requests.
pub trait Transport: Send + Sync {
    fn send(
        &self,
        req: super::request::DriveRequest,
    ) -> Result<super::request::DriveResponse, DriveError>;
}

/// Trait for async transport backends (e.g. browser fetch, async HTTP clients).
/// On WASM, use this trait instead of `Transport`.
/// Note: The returned future does not require `Send` because WASM is
/// single-threaded and `JsFuture` uses `Rc` (not `Send`).
pub trait AsyncTransport: Sync {
    fn send_async(
        &self,
        req: super::request::DriveRequest,
    ) -> impl std::future::Future<Output = Result<super::request::DriveResponse, DriveError>>;
}
