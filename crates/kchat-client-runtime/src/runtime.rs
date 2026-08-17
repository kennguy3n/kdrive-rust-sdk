use kchat_drive_identity::DriveKeyVault;
use kchat_drive_sync_core::OperationJournal;
use kchat_drive_types::DriveError;
use std::sync::Mutex;

use crate::barrier::EpochBarrier;
use crate::lease::FencingToken;

/// The client runtime: sole owner of the MLS provider handle,
/// Drive vault, journal, and per-group mutation lock.
///
/// Invariants (architecture §19.1):
/// - Single runtime owns both MLS provider + Drive vault.
/// - Raw MLS mutations are deny-by-default for Drive-bound groups.
/// - Fencing token prevents stale operations.
/// - Epoch barrier ensures key material matches current MLS epoch.
#[derive(Debug)]
pub struct ClientRuntime {
    /// Fencing token for this runtime instance.
    fencing_token: FencingToken,
    /// Encrypted Drive key vault.
    vault: Mutex<DriveKeyVault>,
    /// Operation journal.
    journal: Mutex<OperationJournal>,
    /// Epoch barrier for key/epoch synchronization.
    barrier: Mutex<EpochBarrier>,
    /// Per-group mutation lock state.
    locked_groups: Mutex<Vec<String>>,
}

impl ClientRuntime {
    /// Creates a new runtime with a fresh vault.
    pub fn new() -> Self {
        Self {
            fencing_token: FencingToken::new(),
            vault: Mutex::new(DriveKeyVault::new()),
            journal: Mutex::new(OperationJournal::new()),
            barrier: Mutex::new(EpochBarrier::new()),
            locked_groups: Mutex::new(Vec::new()),
        }
    }

    /// Creates a runtime with an existing master key (e.g., from WebCrypto).
    pub fn with_master_key(master_key: [u8; 32]) -> Self {
        Self {
            fencing_token: FencingToken::new(),
            vault: Mutex::new(DriveKeyVault::from_master_key(master_key)),
            journal: Mutex::new(OperationJournal::new()),
            barrier: Mutex::new(EpochBarrier::new()),
            locked_groups: Mutex::new(Vec::new()),
        }
    }

    pub fn fencing_token(&self) -> u64 {
        self.fencing_token.current()
    }

    pub fn next_fencing_token(&self) -> u64 {
        self.fencing_token.next()
    }

    pub fn vault(&self) -> std::sync::MutexGuard<'_, DriveKeyVault> {
        self.vault
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }

    pub fn journal(&self) -> std::sync::MutexGuard<'_, OperationJournal> {
        self.journal
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }

    pub fn barrier(&self) -> std::sync::MutexGuard<'_, EpochBarrier> {
        self.barrier
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }

    /// Locks a group for mutation (deny-by-default for Drive-bound groups).
    pub fn lock_group(&self, group_id: &str) -> Result<(), DriveError> {
        let mut locked = self
            .locked_groups
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if locked.iter().any(|g| g == group_id) {
            return Err(DriveError::InvalidState(format!(
                "group {} is already locked",
                group_id
            )));
        }
        locked.push(group_id.to_string());
        Ok(())
    }

    /// Unlocks a group.
    pub fn unlock_group(&self, group_id: &str) {
        let mut locked = self
            .locked_groups
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        locked.retain(|g| g != group_id);
    }
}

impl Default for ClientRuntime {
    fn default() -> Self {
        Self::new()
    }
}
