
#[derive(Debug, Default)]
pub struct OrderedWriteSet {
    entries: Vec<WriteEntry>,
}

#[derive(Debug, Clone)]
pub struct WriteEntry {
    pub seq: u64,
    pub key: String,
    pub value: Vec<u8>,
}

impl OrderedWriteSet {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn append(&mut self, key: String, value: Vec<u8>) -> u64 {
        let seq = self.entries.len() as u64;
        self.entries.push(WriteEntry { seq, key, value });
        seq
    }

    pub fn entries(&self) -> &[WriteEntry] {
        &self.entries
    }

    pub fn serialize(&self) -> Vec<u8> {
        // Simple serialization for the demo.
        // In production, this is encrypted CBOR.
        serde_json::to_vec(
            &self
                .entries
                .iter()
                .map(|e| (e.seq, &e.key, e.value.len()))
                .collect::<Vec<_>>(),
        )
        .unwrap_or_default()
    }
}
