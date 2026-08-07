use kchat_drive_types::DriveError;

/// IndexedDB-based Drive store for the browser.
/// Uses two-slot snapshot pattern (architecture §19.5).
pub struct IdbDriveStore {
    db_name: String,
}

impl IdbDriveStore {
    pub fn new(db_name: String) -> Self {
        Self { db_name }
    }

    pub fn db_name(&self) -> &str {
        &self.db_name
    }

    /// Opens the IndexedDB database. Returns a JsValue promise.
    /// In production, this uses web-sys IdbFactory.
    pub fn open(&self) -> Result<(), DriveError> {
        // Scaffold: actual IdbDatabase opening is async and requires
        // wasm-bindgen-futures. For the demo, we store the name and
        // implement the async open in the WASM facade.
        Ok(())
    }
}
