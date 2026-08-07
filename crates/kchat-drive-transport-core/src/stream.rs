use kchat_drive_types::DriveError;

/// Streaming session handle for bounded streaming (architecture §19.1).
/// Read/write/checkpoint/cancel/progress — not whole-file Vec<u8> copies.
pub trait StreamSession: Send {
    /// Reads up to `buf.len()` bytes into buf. Returns Ok(0) at EOF.
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, DriveError>;

    /// Writes data to the stream.
    fn write(&mut self, data: &[u8]) -> Result<(), DriveError>;

    /// Checkpoints the current stream state (for resumable uploads).
    fn checkpoint(&mut self) -> Result<u64, DriveError>;

    /// Cancels the stream.
    fn cancel(&mut self) -> Result<(), DriveError>;

    /// Returns progress as (bytes_transferred, total_bytes).
    fn progress(&self) -> (u64, u64);
}
