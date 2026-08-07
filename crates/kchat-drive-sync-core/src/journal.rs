use kchat_drive_types::{DriveError, NodeId, VersionId};
use minicbor::{Decode, Encode};

/// Operation types in the sync journal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Encode, Decode)]
#[repr(u8)]
pub enum OperationType {
    #[n(1)]
    Upload,
    #[n(2)]
    Download,
    #[n(3)]
    CreateFolder,
    #[n(4)]
    DeleteNode,
    #[n(5)]
    RenameNode,
    #[n(6)]
    ShareGrant,
    #[n(7)]
    ShareRevoke,
    #[n(8)]
    DomainKeyRotate,
}

/// Operation status in the journal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Encode, Decode)]
#[repr(u8)]
pub enum OperationStatus {
    #[n(1)]
    Pending,
    #[n(2)]
    InProgress,
    #[n(3)]
    Completed,
    #[n(4)]
    Failed,
    #[n(5)]
    Conflicted,
}

/// A single journal entry.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct JournalEntry {
    #[n(0)]
    pub seq: u64,
    #[n(1)]
    pub op_type: OperationType,
    #[n(2)]
    pub status: OperationStatus,
    #[n(3)]
    pub node_id: Option<NodeId>,
    #[n(4)]
    pub version_id: Option<VersionId>,
    #[n(5)]
    pub timestamp: u64,
    #[n(6)]
    pub error: Option<String>,
}

/// The operation journal: an ordered log of all drive operations.
#[derive(Debug, Default)]
pub struct OperationJournal {
    entries: Vec<JournalEntry>,
    next_seq: u64,
}

impl OperationJournal {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn append(
        &mut self,
        op_type: OperationType,
        node_id: Option<NodeId>,
        version_id: Option<VersionId>,
    ) -> u64 {
        let seq = self.next_seq;
        self.next_seq += 1;
        self.entries.push(JournalEntry {
            seq,
            op_type,
            status: OperationStatus::Pending,
            node_id,
            version_id,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            error: None,
        });
        seq
    }

    pub fn update_status(
        &mut self,
        seq: u64,
        status: OperationStatus,
        error: Option<String>,
    ) -> Result<(), DriveError> {
        let entry = self
            .entries
            .iter_mut()
            .find(|e| e.seq == seq)
            .ok_or(DriveError::NotFound(format!("journal entry {}", seq)))?;
        entry.status = status;
        entry.error = error;
        Ok(())
    }

    pub fn entries(&self) -> &[JournalEntry] {
        &self.entries
    }

    pub fn pending(&self) -> Vec<&JournalEntry> {
        self.entries
            .iter()
            .filter(|e| e.status == OperationStatus::Pending)
            .collect()
    }
}
