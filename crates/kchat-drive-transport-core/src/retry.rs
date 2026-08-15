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
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_nanos() as u64;
        (nanos % (jitter_range * 2 + 1)).saturating_sub(jitter_range)
    };
    Duration::from_millis(capped.saturating_add(jitter))
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
