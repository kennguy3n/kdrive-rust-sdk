use kchat_drive_types::{NodeId, VersionId};
use minicbor::{Decode, Encode};

/// Sync state for a node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Encode, Decode)]
#[repr(u8)]
pub enum SyncState {
    #[n(1)]
    Idle,
    #[n(2)]
    Uploading,
    #[n(3)]
    Downloading,
    #[n(4)]
    Conflicted,
    #[n(5)]
    Error,
}

/// Node sync state tracking.
#[derive(Debug, Clone, Encode, Decode)]
pub struct NodeSyncState {
    #[n(0)]
    pub node_id: NodeId,
    #[n(1)]
    pub state: SyncState,
    #[n(2)]
    pub local_version: Option<VersionId>,
    #[n(3)]
    pub remote_version: Option<VersionId>,
    #[n(4)]
    pub last_sync: u64,
}

/// Drive sync state: tracks all node sync states.
#[derive(Debug, Default)]
pub struct DriveSyncState {
    nodes: std::collections::HashMap<NodeId, NodeSyncState>,
}

impl DriveSyncState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get(&self, node_id: &NodeId) -> Option<&NodeSyncState> {
        self.nodes.get(node_id)
    }

    pub fn get_mut(&mut self, node_id: &NodeId) -> Option<&mut NodeSyncState> {
        self.nodes.get_mut(node_id)
    }

    pub fn upsert(&mut self, state: NodeSyncState) {
        self.nodes.insert(state.node_id.clone(), state);
    }

    pub fn conflicted_nodes(&self) -> Vec<&NodeSyncState> {
        self.nodes
            .values()
            .filter(|s| s.state == SyncState::Conflicted)
            .collect()
    }
}
