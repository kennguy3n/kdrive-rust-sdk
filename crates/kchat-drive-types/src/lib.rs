pub mod envelope;
pub mod error;
pub mod events;
pub mod header;
pub mod ids;
pub mod manifest;
pub mod roles;

pub use envelope::*;
pub use error::DriveError;
pub use events::*;
pub use header::*;
pub use ids::*;
pub use manifest::*;
pub use roles::*;

/// KDRV1 protocol version.
pub const PROTOCOL_VERSION: u16 = 1;

/// KDRV1 crypto suite identifier.
pub const SUITE_KDRV1: u16 = 1;

/// Domain separator prefix for all KDRV1 KDF info strings.
pub const KDF_DOMAIN: &str = "kchat-drive";
