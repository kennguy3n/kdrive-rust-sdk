/// Two-slot snapshot pattern (architecture §19.5).
/// Alternates between slot A and slot B to ensure atomicity.
use kchat_drive_types::DriveError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnapshotSlot {
    A,
    B,
}

impl SnapshotSlot {
    pub fn other(&self) -> Self {
        match self {
            Self::A => Self::B,
            Self::B => Self::A,
        }
    }
}

#[derive(Debug)]
pub struct TwoSlotSnapshot {
    active_slot: SnapshotSlot,
    /// In production, these are IndexedDB object stores.
    /// For the scaffold, we use in-memory buffers.
    slot_a: Vec<u8>,
    slot_b: Vec<u8>,
}

impl TwoSlotSnapshot {
    pub fn new() -> Self {
        Self {
            active_slot: SnapshotSlot::A,
            slot_a: Vec::new(),
            slot_b: Vec::new(),
        }
    }

    pub fn active(&self) -> SnapshotSlot {
        self.active_slot
    }

    /// Writes to the inactive slot, then atomically swaps.
    pub fn commit(&mut self, data: Vec<u8>) -> Result<(), DriveError> {
        match self.active_slot {
            SnapshotSlot::A => {
                self.slot_b = data;
                self.active_slot = SnapshotSlot::B;
            }
            SnapshotSlot::B => {
                self.slot_a = data;
                self.active_slot = SnapshotSlot::A;
            }
        }
        Ok(())
    }

    pub fn read(&self) -> &[u8] {
        match self.active_slot {
            SnapshotSlot::A => &self.slot_a,
            SnapshotSlot::B => &self.slot_b,
        }
    }
}

impl Default for TwoSlotSnapshot {
    fn default() -> Self {
        Self::new()
    }
}
