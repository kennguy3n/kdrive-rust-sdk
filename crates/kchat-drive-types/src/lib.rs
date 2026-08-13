pub mod envelope;
pub mod error;
pub mod events;
pub mod header;
pub mod ids;
pub mod manifest;
pub mod roles;

pub use envelope::*;
pub use error::{DriveError, error_code, error_message};
pub use events::*;
pub use header::*;
pub use ids::*;
pub use manifest::*;
pub use roles::*;

/// KDRV1 protocol version.
pub const PROTOCOL_VERSION: u16 = 1;

/// KDRV1 crypto suite identifier.
pub const SUITE_KDRV1: u16 = 1;

/// KDRV protocol version (content deduplication). Same as PROTOCOL_VERSION.
pub const PROTOCOL_KDRV1: u16 = 1;

/// Protocol name strings for CBOR serialization.
pub const PROTOCOL_NAME_KDRV1: &str = "KDRV1";

/// Domain separator prefix for all KDRV1 KDF info strings.
pub const KDF_DOMAIN: &str = "kchat-drive";

/// Domain-separation tag for Merkle tree leaf nodes (chunk plan).
pub const CHUNK_PLAN_LEAF_TAG: &[u8] = b"kchat-drive/chunk-plan-leaf/v1";

/// Domain-separation tag for Merkle tree internal nodes (chunk plan).
pub const CHUNK_PLAN_NODE_TAG: &[u8] = b"kchat-drive/chunk-plan-node/v1";
