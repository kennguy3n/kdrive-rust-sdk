use kchat_drive_types::DriveError;
use serde::{Deserialize, Serialize};

/// HTTP method for drive API requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HttpMethod {
    GET,
    POST,
    PUT,
    DELETE,
}

/// A drive API request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriveRequest {
    pub method: HttpMethod,
    pub path: String,
    pub body: Option<Vec<u8>>,
    pub headers: Vec<(String, String)>,
}

/// A drive API response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriveResponse {
    pub status: u16,
    pub body: Vec<u8>,
    pub headers: Vec<(String, String)>,
}

impl DriveResponse {
    pub fn is_success(&self) -> bool {
        self.status >= 200 && self.status < 300
    }

    pub fn json<T: serde::de::DeserializeOwned>(&self) -> Result<T, DriveError> {
        serde_json::from_slice(&self.body).map_err(|e| DriveError::Serialize(e.to_string()))
    }
}
