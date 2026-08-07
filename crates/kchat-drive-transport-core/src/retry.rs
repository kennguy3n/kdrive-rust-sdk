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

/// Computes the delay for a given attempt (0-indexed).
pub fn retry_delay(config: &RetryConfig, attempt: u32) -> Duration {
    let delay_ms =
        config.initial_delay.as_millis() as f64 * config.backoff_factor.powi(attempt as i32);
    let delay = Duration::from_millis(delay_ms as u64);
    delay.min(config.max_delay)
}

/// Retries a fallible operation according to the config.
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
