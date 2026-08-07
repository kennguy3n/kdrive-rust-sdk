use ed25519_dalek::SigningKey;

use kchat_drive_types::{DeviceId, DriveError, UserId};

use crate::account::{AccountAuthorityRecord, DeviceCertificate};
use crate::device::DeviceKeyPair;

/// Enrollment result: contains the account authority record + device keypair.
pub struct EnrollmentResult {
    pub account: AccountAuthorityRecord,
    pub device_keypair: DeviceKeyPair,
    pub root_signing_key: SigningKey,
}

/// Enrolls a new user with a single device (demo: in-process key generation).
/// Generates:
/// 1. Account root keypair (Ed25519)
/// 2. Device keypair (Ed25519)
/// 3. Account authority record signed by the root key
pub fn enroll_user(user_id: UserId, device_name: Option<String>) -> Result<EnrollmentResult, DriveError> {
    // Generate account root key.
    let root_signing_key = SigningKey::generate(&mut rand::rngs::OsRng);
    let root_verifying_key = root_signing_key.verifying_key();

    // Generate device key.
    let device_id = DeviceId::random();
    let device_keypair = DeviceKeyPair::generate(device_id.clone());

    // Create device certificate.
    let device_cert = DeviceCertificate {
        device_id,
        device_public_key: device_keypair.public_key().clone(),
        device_name,
        enrolled_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        active: true,
    };

    // Create account authority record.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let mut account = AccountAuthorityRecord {
        user_id,
        root_public_key: kchat_drive_types::Ed25519PublicKey::new(root_verifying_key.to_bytes()),
        devices: vec![device_cert],
        created_at: now,
        updated_at: now,
        signature: None,
    };

    // Sign the record.
    account.sign(&root_signing_key)?;

    Ok(EnrollmentResult {
        account,
        device_keypair,
        root_signing_key,
    })
}

/// Adds a new device to an existing account.
/// Returns the updated account authority record (signed) and the new device keypair.
pub fn add_device(
    account: &AccountAuthorityRecord,
    root_signing_key: &SigningKey,
    device_name: Option<String>,
) -> Result<(AccountAuthorityRecord, DeviceKeyPair), DriveError> {
    let device_id = DeviceId::random();
    let device_keypair = DeviceKeyPair::generate(device_id.clone());

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let device_cert = DeviceCertificate {
        device_id,
        device_public_key: device_keypair.public_key().clone(),
        device_name,
        enrolled_at: now,
        active: true,
    };

    let mut updated = account.clone();
    updated.devices.push(device_cert);
    updated.updated_at = now;
    updated.sign(root_signing_key)?;

    Ok((updated, device_keypair))
}

/// Removes a device from an account (deactivation).
pub fn remove_device(
    account: &AccountAuthorityRecord,
    root_signing_key: &SigningKey,
    device_id: &DeviceId,
) -> Result<AccountAuthorityRecord, DriveError> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let mut updated = account.clone();
    for cert in &mut updated.devices {
        if cert.device_id == *device_id {
            cert.active = false;
        }
    }
    updated.updated_at = now;
    updated.sign(root_signing_key)?;

    Ok(updated)
}
