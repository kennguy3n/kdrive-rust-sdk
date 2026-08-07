use std::sync::atomic::{AtomicU64, Ordering};

/// Fencing token: monotonically increasing per runtime instance.
/// Used to prevent stale operations from a previous lease holder.
#[derive(Debug)]
pub struct FencingToken {
    counter: AtomicU64,
}

impl FencingToken {
    pub fn new() -> Self {
        Self {
            counter: AtomicU64::new(1),
        }
    }

    pub fn current(&self) -> u64 {
        self.counter.load(Ordering::SeqCst)
    }

    pub fn next(&self) -> u64 {
        self.counter.fetch_add(1, Ordering::SeqCst) + 1
    }
}

impl Default for FencingToken {
    fn default() -> Self {
        Self::new()
    }
}
