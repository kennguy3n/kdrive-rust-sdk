use kchat_drive_transport_core::{AsyncTransport, DriveRequest, DriveResponse, HttpMethod};
use kchat_drive_types::DriveError;
use wasm_bindgen::JsValue;

/// Browser Fetch-based transport.
pub struct FetchTransport {
    base_url: String,
}

impl FetchTransport {
    pub fn new(base_url: String) -> Self {
        Self { base_url }
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }
}

/// Since async Fetch is hard to use through the Transport trait in WASM,
/// we expose a async-js-backed send method.
impl FetchTransport {
    pub async fn send_async(&self, req: DriveRequest) -> Result<DriveResponse, DriveError> {
        let url = format!("{}{}", self.base_url, req.path);

        let method = match req.method {
            HttpMethod::GET => "GET",
            HttpMethod::POST => "POST",
            HttpMethod::PUT => "PUT",
            HttpMethod::DELETE => "DELETE",
        };

        let init = web_sys::RequestInit::new();
        init.set_method(method);

        if let Some(body) = &req.body {
            let body_array = js_sys::Uint8Array::from(body.as_slice());
            init.set_body(&JsValue::from(body_array));
        }

        let request = web_sys::Request::new_with_str_and_init(&url, &init)
            .map_err(|e| DriveError::Io(format!("Request::new failed: {:?}", e)))?;

        // Set headers.
        let headers = request.headers();
        for (key, value) in &req.headers {
            headers
                .set(key, value)
                .map_err(|e| DriveError::Io(format!("headers.set failed: {:?}", e)))?;
        }

        let window = web_sys::window().ok_or(DriveError::Io("no window".into()))?;

        let promise = window.fetch_with_request(&request);
        let response_value = js_sys::futures::JsFuture::from(promise)
            .await
            .map_err(|e| DriveError::Io(format!("fetch failed: {:?}", e)))?;

        let response: web_sys::Response = response_value.into();
        let status = response.status();

        let array_buffer_promise = response
            .array_buffer()
            .map_err(|e| DriveError::Io(format!("array_buffer failed: {:?}", e)))?;
        let body_buf = js_sys::futures::JsFuture::from(array_buffer_promise)
            .await
            .map_err(|e| DriveError::Io(format!("array_buffer failed: {:?}", e)))?;

        let body_array = js_sys::Uint8Array::new(&body_buf);
        let body = body_array.to_vec();

        Ok(DriveResponse {
            status,
            body,
            headers: Vec::new(),
        })
    }
}

impl AsyncTransport for FetchTransport {
    fn send_async(
        &self,
        req: DriveRequest,
    ) -> impl std::future::Future<Output = Result<DriveResponse, DriveError>> {
        FetchTransport::send_async(self, req)
    }
}
