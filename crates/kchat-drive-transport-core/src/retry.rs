use kchat_drive_types::DriveError;
use std::time::Duration;

/// Retry configuration.
#[derive(Debug, Clone)]
pub struct RetryConfig {
    pub max_attempts: u32,
    pub initial_delay: Duration,
    pub max_delay: Duration,
    pub backoff_factor: f64,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            initial_delay: Duration::from_millis(500),
            max_delay: Duration::from_secs(10),
            backoff_factor: 2.0,
        }
    }
}

/// Computes the delay for a given attempt (0-indexed), with ±10% jitter.
pub fn retry_delay(config: &RetryConfig, attempt: u32) -> Duration {
    let base_ms = config.initial_delay.as_millis() as u64;
    let delay_ms = base_ms.saturating_mul(config.backoff_factor.powi(attempt as i32) as u64);
    let capped = delay_ms.min(config.max_delay.as_millis() as u64);
    // Add ±10% jitter to avoid thundering-herd retries.
    let jitter_range = capped / 10;
    let jitter = {
        // Use SystemTime nanos as a jitter source to avoid relying on
        // `rand::random`, which may not be available in WASM targets.
        let nanos = web_time::SystemTime::now()
            .duration_since(web_time::SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_nanos() as u64;
        (nanos % (jitter_range * 2 + 1)).saturating_sub(jitter_range)
    };
    Duration::from_millis(capped.saturating_add(jitter))
}

/// Retries a fallible operation according to the config.
///
/// This is the **synchronous** retry helper. It uses `std::thread::sleep`
/// to wait between attempts, which blocks the current thread. In async
/// contexts, prefer [`with_retry_async`] to avoid blocking the executor.
pub fn with_retry<F, T>(config: &RetryConfig, mut f: F) -> Result<T, DriveError>
where
    F: FnMut() -> Result<T, DriveError>,
{
    let mut last_err = None;
    for attempt in 0..config.max_attempts {
        match f() {
            Ok(v) => return Ok(v),
            Err(e) => {
                last_err = Some(e);
                if attempt + 1 < config.max_attempts {
                    // NOTE: This is a blocking sleep. In async contexts, use
                    // `with_retry_async` instead to avoid blocking the runtime.
                    #[cfg(not(target_arch = "wasm32"))]
                    std::thread::sleep(retry_delay(config, attempt));
                    #[cfg(target_arch = "wasm32")]
                    {
                        // In WASM, sleep is not available; callers should use
                        // an async retry with setTimeout instead.
                        let _ = retry_delay(config, attempt);
                    }
                }
            }
        }
    }
    Err(last_err.unwrap_or(DriveError::InvalidState("retry exhausted".into())))
}

/// Retries a fallible async operation according to the config.
///
/// Uses non-blocking async sleep between attempts:
/// - On native targets: `tokio::time::sleep`
/// - On WASM: `setTimeout` via `wasm_bindgen_futures`
pub async fn with_retry_async<F, Fut, T>(config: &RetryConfig, mut f: F) -> Result<T, DriveError>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, DriveError>>,
{
    let mut last_err = None;
    for attempt in 0..config.max_attempts {
        match f().await {
            Ok(v) => return Ok(v),
            Err(e) => {
                last_err = Some(e);
                if attempt + 1 < config.max_attempts {
                    async_sleep(retry_delay(config, attempt)).await;
                }
            }
        }
    }
    Err(last_err.unwrap_or(DriveError::InvalidState("retry exhausted".into())))
}

/// Non-blocking async sleep.
#[cfg(not(target_arch = "wasm32"))]
async fn async_sleep(duration: Duration) {
    tokio::time::sleep(duration).await;
}

/// Non-blocking async sleep for WASM (uses `setTimeout` via `wasm_bindgen_futures`).
#[cfg(target_arch = "wasm32")]
async fn async_sleep(duration: Duration) {
    use wasm_bindgen::JsCast;
    use wasm_bindgen_futures::JsFuture;

    let ms = duration.as_millis() as i32;
    let promise = js_sys::Promise::new(&mut |resolve, _| {
        let global = js_sys::global();
        // In the main thread, `global` is a `Window`; in a Web Worker, it is
        // a `WorkerGlobalScope`. Both expose `setTimeout`.
        if let Some(window) = global.dyn_ref::<web_sys::Window>() {
            let _ = window.set_timeout_with_callback_and_timeout_and_arguments_0(&resolve, ms);
        } else if let Some(worker) = global.dyn_ref::<web_sys::WorkerGlobalScope>() {
            let _ = worker.set_timeout_with_callback_and_timeout_and_arguments_0(&resolve, ms);
        }
    });
    let _ = JsFuture::from(promise).await;
}
