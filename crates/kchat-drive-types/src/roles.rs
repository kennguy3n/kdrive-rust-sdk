use minicbor::{Decode, Encode};

/// Privacy mode for a tenant or drive (architecture §5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Encode, Decode)]
#[repr(u8)]
pub enum PrivacyMode {
    #[n(1)]
    Secured,
    #[n(2)]
    Advanced,
    #[n(3)]
    Max,
}

impl PrivacyMode {
    pub fn as_u8(&self) -> u8 {
        match self {
            Self::Secured => 1,
            Self::Advanced => 2,
            Self::Max => 3,
        }
    }

    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::Secured),
            2 => Some(Self::Advanced),
            3 => Some(Self::Max),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Secured => "secured",
            Self::Advanced => "advanced",
            Self::Max => "max",
        }
    }
}

impl std::fmt::Display for PrivacyMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Role a user can hold in a drive or folder (architecture §17).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Encode, Decode)]
#[repr(u8)]
pub enum Role {
    #[n(1)]
    Owner,
    #[n(2)]
    Editor,
    #[n(3)]
    Viewer,
    #[n(4)]
    Admin,
}

impl Role {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Owner => "owner",
            Self::Editor => "editor",
            Self::Viewer => "viewer",
            Self::Admin => "admin",
        }
    }
}

/// Node kind: file or folder.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Encode, Decode)]
#[repr(u8)]
pub enum NodeKind {
    #[n(1)]
    File,
    #[n(2)]
    Folder,
}

/// Drive kind: personal, tenant, or group.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Encode, Decode)]
#[repr(u8)]
pub enum DriveKind {
    #[n(1)]
    Personal,
    #[n(2)]
    Tenant,
    #[n(3)]
    Group,
}

/// Tenant type: B2B or B2C.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Encode, Decode)]
#[repr(u8)]
pub enum TenantType {
    #[n(1)]
    B2B,
    #[n(2)]
    B2C,
}

impl TenantType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::B2B => "b2b",
            Self::B2C => "b2c",
        }
    }
}
