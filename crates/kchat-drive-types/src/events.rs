use crate::ids::*;
use crate::roles::*;
use minicbor::{Decode, Encode};

/// Drive lifecycle event (architecture §16).
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct DriveEvent {
    /// Event ID (unique, monotonic per drive).
    #[n(0)]
    pub event_id: u64,

    /// Drive ID.
    #[n(1)]
    pub drive_id: DriveId,

    /// Event type.
    #[n(2)]
    pub event_type: DriveEventType,

    /// Actor (user ID who initiated the event).
    #[n(3)]
    pub actor: UserId,

    /// Timestamp (Unix epoch seconds).
    #[n(4)]
    pub timestamp: u64,

    /// Event payload (CBOR-encoded, type-specific).
    #[n(5)]
    pub payload: Vec<u8>,
}

/// Drive event types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Encode, Decode)]
#[repr(u8)]
pub enum DriveEventType {
    #[n(1)]
    DriveCreated,
    #[n(2)]
    FolderCreated,
    #[n(3)]
    FileCreated,
    #[n(4)]
    VersionUploaded,
    #[n(5)]
    VersionDownloaded,
    #[n(6)]
    MemberAdded,
    #[n(7)]
    MemberRemoved,
    #[n(8)]
    DomainKeyRotated,
    #[n(9)]
    ShareGranted,
    #[n(10)]
    ShareRevoked,
    #[n(11)]
    RecoveryInitiated,
    #[n(12)]
    ReshareRequested,
}

/// Share grant event payload.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct ShareGrantedPayload {
    #[n(0)]
    pub grant_id: ShareGrantId,
    #[n(1)]
    pub node_id: NodeId,
    #[n(2)]
    pub recipient: UserId,
    #[n(3)]
    pub role: Role,
    #[n(4)]
    pub generation: u64,
}

/// Share revocation event payload.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct ShareRevokedPayload {
    #[n(0)]
    pub grant_id: ShareGrantId,
    #[n(1)]
    pub revoked_by: UserId,
    #[n(2)]
    pub timestamp: u64,
}

/// Domain key rotation event payload.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct DomainKeyRotatedPayload {
    #[n(0)]
    pub domain_id: DomainId,
    #[n(1)]
    pub old_generation: u64,
    #[n(2)]
    pub new_generation: u64,
    #[n(3)]
    pub rotated_by: UserId,
}

/// Member change event payload.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct MemberChangePayload {
    #[n(0)]
    pub user_id: UserId,
    #[n(1)]
    pub role: Role,
    #[n(2)]
    pub device_key: Ed25519PublicKey,
}
