use kchat_drive_types::{DomainId, DriveError, ShareGrantId};
use std::collections::{HashMap, VecDeque};

/// Maximum number of pending barriers retained before the oldest entry is
/// evicted. This prevents unbounded growth if barriers are registered faster
/// than they are satisfied.
const MAX_PENDING_BARRIERS: usize = 1000;

/// Epoch barrier: ensures that key material from a previous MLS epoch
/// is not used after a Commit that changes the group membership.
/// The barrier blocks Drive operations until the new epoch's keys are
/// derived and stored.
#[derive(Debug, Default)]
pub struct EpochBarrier {
    /// Current MLS epoch per group (identified by domain_id or grant_id).
    domain_epochs: HashMap<DomainId, u64>,
    grant_epochs: HashMap<ShareGrantId, u64>,
    /// Pending barriers: operations waiting for epoch >= target.
    pending: VecDeque<PendingBarrier>,
}

#[derive(Debug)]
struct PendingBarrier {
    domain_id: Option<DomainId>,
    grant_id: Option<ShareGrantId>,
    target_epoch: u64,
}

impl EpochBarrier {
    pub fn new() -> Self {
        Self::default()
    }

    /// Records the current epoch for a domain.
    pub fn set_domain_epoch(&mut self, domain_id: DomainId, epoch: u64) {
        self.domain_epochs.insert(domain_id.clone(), epoch);
        // Wake any pending barriers for this domain.
        self.pending.retain(|p| {
            if p.domain_id.as_ref() == Some(&domain_id) && epoch >= p.target_epoch {
                false // Remove satisfied barriers
            } else {
                true
            }
        });
    }

    /// Records the current epoch for a grant.
    pub fn set_grant_epoch(&mut self, grant_id: ShareGrantId, epoch: u64) {
        self.grant_epochs.insert(grant_id.clone(), epoch);
        self.pending
            .retain(|p| !(p.grant_id.as_ref() == Some(&grant_id) && epoch >= p.target_epoch));
    }

    /// Checks if the barrier is satisfied for a domain.
    pub fn check_domain(&self, domain_id: &DomainId, min_epoch: u64) -> Result<(), DriveError> {
        let current = self.domain_epochs.get(domain_id).copied().unwrap_or(0);
        if current >= min_epoch {
            Ok(())
        } else {
            Err(DriveError::EpochMismatch {
                expected: min_epoch,
                got: current,
            })
        }
    }

    /// Checks if the barrier is satisfied for a grant.
    pub fn check_grant(&self, grant_id: &ShareGrantId, min_epoch: u64) -> Result<(), DriveError> {
        let current = self.grant_epochs.get(grant_id).copied().unwrap_or(0);
        if current >= min_epoch {
            Ok(())
        } else {
            Err(DriveError::EpochMismatch {
                expected: min_epoch,
                got: current,
            })
        }
    }

    /// Registers a pending barrier.
    ///
    /// If the number of pending barriers has reached `MAX_PENDING_BARRIERS`,
    /// the oldest entry is evicted first to keep the buffer bounded.
    pub fn wait_for_domain(&mut self, domain_id: DomainId, target_epoch: u64) {
        if self.pending.len() >= MAX_PENDING_BARRIERS {
            self.pending.remove(0);
        }
        self.pending.push_back(PendingBarrier {
            domain_id: Some(domain_id),
            grant_id: None,
            target_epoch,
        });
    }

    /// Registers a pending barrier for a grant.
    ///
    /// If the number of pending barriers has reached `MAX_PENDING_BARRIERS`,
    /// the oldest entry is evicted first to keep the buffer bounded.
    pub fn wait_for_grant(&mut self, grant_id: ShareGrantId, target_epoch: u64) {
        if self.pending.len() >= MAX_PENDING_BARRIERS {
            self.pending.remove(0);
        }
        self.pending.push_back(PendingBarrier {
            domain_id: None,
            grant_id: Some(grant_id),
            target_epoch,
        });
    }

    /// Trims the pending list to at most `max_keep` entries, removing the
    /// oldest entries first. This is useful to periodically reclaim space from
    /// stale/satisfied barriers that were not cleaned up by an epoch update.
    pub fn trim_pending(&mut self, max_keep: usize) {
        if self.pending.len() > max_keep {
            let to_remove = self.pending.len() - max_keep;
            self.pending.drain(0..to_remove);
        }
    }

    /// Returns the number of pending barriers.
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }
}
