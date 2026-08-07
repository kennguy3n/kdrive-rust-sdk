use kchat_drive_types::{DriveError, NodeId, VersionId};

/// Conflict types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConflictType {
    /// Both local and remote have new versions.
    ConcurrentEdit,
    /// Remote deleted a node that has local changes.
    DeleteWithLocalChanges,
    /// Remote version is newer than local.
    RemoteNewer,
}

/// A sync conflict.
#[derive(Debug, Clone)]
pub struct SyncConflict {
    pub node_id: NodeId,
    pub local_version: Option<VersionId>,
    pub remote_version: Option<VersionId>,
    pub conflict_type: ConflictType,
}

/// Conflict resolution strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolutionStrategy {
    /// Keep local version, push as new version.
    KeepLocal,
    /// Accept remote version, discard local.
    AcceptRemote,
    /// Create a merge version (manual resolution required).
    Merge,
}

/// Resolves a conflict according to the given strategy.
pub fn resolve_conflict(
    conflict: &SyncConflict,
    strategy: ResolutionStrategy,
) -> Result<ResolutionResult, DriveError> {
    match strategy {
        ResolutionStrategy::KeepLocal => {
            Ok(ResolutionResult::KeepLocal(conflict.local_version.clone()))
        }
        ResolutionStrategy::AcceptRemote => Ok(ResolutionResult::AcceptRemote(
            conflict.remote_version.clone(),
        )),
        ResolutionStrategy::Merge => Ok(ResolutionResult::RequiresManualMerge),
    }
}

/// Result of conflict resolution.
#[derive(Debug, Clone)]
pub enum ResolutionResult {
    KeepLocal(Option<VersionId>),
    AcceptRemote(Option<VersionId>),
    RequiresManualMerge,
}
