use kchat_drive_transport_core::{DriveRequest, DriveResponse, HttpMethod, Transport};
use kchat_drive_types::DriveError;

/// Native transport using tokio + reqwest (or platform HTTP client).
/// In production, this delegates to iOS URLSession / Android WorkManager
/// via callback contracts. For the demo scaffold, we use a stub.
pub struct NativeTransport {
    base_url: String,
}

impl NativeTransport {
    pub fn new(base_url: String) -> Self {
        Self { base_url }
    }
}

impl Transport for NativeTransport {
    fn send(&self, req: DriveRequest) -> Result<DriveResponse, DriveError> {
        let method_str = match req.method {
            HttpMethod::GET => "GET",
            HttpMethod::POST => "POST",
            HttpMethod::PUT => "PUT",
            HttpMethod::DELETE => "DELETE",
        };
        Err(DriveError::InvalidState(format!(
            "NativeTransport::send not yet implemented for {} {}",
            method_str, self.base_url
        )))
    }
}
