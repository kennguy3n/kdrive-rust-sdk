use kchat_drive_types::{DriveError, Hash256};
use sha2::{Digest, Sha256};

/// Ordering proof: validates that a staged Commit has the correct
/// winning Commit hash + tree hash + admitted roster before merge.
/// Minimal version for the demo.
#[derive(Debug, Clone)]
pub struct OrderingProof {
    /// MLS epoch after the commit.
    pub epoch: u64,
    /// Tree hash after the commit.
    pub tree_hash: Hash256,
    /// Winning Commit message hash.
    pub commit_hash: Hash256,
    /// Admitted member count.
    pub admitted_count: u64,
    /// Removed member count.
    pub removed_count: u64,
}

impl OrderingProof {
    /// Computes the commit hash from raw commit bytes.
    pub fn commit_hash_from_bytes(commit_bytes: &[u8]) -> Hash256 {
        let mut hasher = Sha256::new();
        hasher.update(b"kchat-drive/commit-hash/v1");
        hasher.update(commit_bytes);
        Hash256::from_slice(&hasher.finalize())
    }

    /// Computes the tree hash from raw tree hash bytes.
    pub fn tree_hash_from_bytes(tree_hash_bytes: &[u8]) -> Hash256 {
        Hash256::from_slice(tree_hash_bytes)
    }

    /// Validates the proof against expected values.
    pub fn validate(
        &self,
        expected_epoch: u64,
        expected_tree_hash: &Hash256,
        expected_commit_hash: &Hash256,
    ) -> Result<(), DriveError> {
        if self.epoch != expected_epoch {
            return Err(DriveError::EpochMismatch {
                expected: expected_epoch,
                got: self.epoch,
            });
        }
        if self.tree_hash != *expected_tree_hash {
            return Err(DriveError::MlsBridge(format!(
                "tree hash mismatch: expected {}, got {}",
                expected_tree_hash, self.tree_hash
            )));
        }
        if self.commit_hash != *expected_commit_hash {
            return Err(DriveError::MlsBridge(format!(
                "commit hash mismatch: expected {}, got {}",
                expected_commit_hash, self.commit_hash
            )));
        }
        Ok(())
    }
}

/// Post-merge assertion: after merging a Commit, verify the group's
/// epoch + tree hash match the ordering proof.
pub fn post_merge_assertion(
    actual_epoch: u64,
    actual_tree_hash: &Hash256,
    proof: &OrderingProof,
) -> Result<(), DriveError> {
    if actual_epoch != proof.epoch {
        return Err(DriveError::EpochMismatch {
            expected: proof.epoch,
            got: actual_epoch,
        });
    }
    if actual_tree_hash != &proof.tree_hash {
        return Err(DriveError::MlsBridge(format!(
            "post-merge tree hash mismatch: expected {}, got {}",
            proof.tree_hash, actual_tree_hash
        )));
    }
    Ok(())
}
