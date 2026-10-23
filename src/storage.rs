//! Exclusive single-writer file log. Acknowledged appends sync data before returning.
use crate::{Checkpoint, Entry, Error, Hash, Result, hash_from, require, verify_chain, verify_log};
use ed25519_dalek::SigningKey;
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

const MAX_LOG_BYTES: u64 = 64 * 1024 * 1024;
pub const INTERVAL: usize = 64;
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Identity {
    version: u8,
    log_id: String,
    public_key: String,
}
pub struct Store {
    pub dir: PathBuf,
    pub key: SigningKey,
    pub log_id: Hash,
}
pub struct Guard(File);
impl Drop for Guard {
    fn drop(&mut self) {
        let _ = FileExt::unlock(&self.0);
    }
}
impl Store {
    pub fn create(dir: &Path, key: SigningKey, log_id: Hash) -> Result<Self> {
        fs::create_dir_all(dir)?;
        let store = Self {
            dir: dir.to_owned(),
            key,
            log_id,
        };
        let _guard = store.lock()?;
        let identity = Identity {
            version: 1,
            log_id: hex::encode(log_id),
            public_key: hex::encode(store.key.verifying_key().to_bytes()),
        };
        let path = dir.join("identity.json");
        if path.exists() {
            let current: Identity = serde_json::from_slice(&fs::read(path)?)?;
            require(
                current.version == 1
                    && current.log_id == identity.log_id
                    && current.public_key == identity.public_key,
                "store identity/key mismatch",
            )?;
        } else {
            // Never adopt existing records under a newly supplied identity.
            require(
                !dir.join("entries.jsonl").exists() && !dir.join("checkpoints.jsonl").exists(),
                "missing identity on existing log",
            )?;
            let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
            file.write_all(&serde_json::to_vec(&identity)?)?;
            file.sync_all()?;
            File::open(dir)?.sync_all()?;
        }
        Ok(store)
    }
    pub fn lock(&self) -> Result<Guard> {
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(self.dir.join("writer.lock"))?;
        file.try_lock_exclusive()
            .map_err(|_| Error("writer already active".into()))?;
        Ok(Guard(file))
    }
    pub fn read(&self) -> Result<Vec<Entry>> {
        read_entries(&self.dir.join("entries.jsonl"))
    }
    pub fn checkpoints(&self) -> Result<Vec<Checkpoint>> {
        let path = self.dir.join("checkpoints.jsonl");
        if !path.exists() {
            return Ok(vec![]);
        }
        let bytes = bounded_read(&path)?;
        if bytes.is_empty() {
            return Ok(vec![]);
        }
        require(
            bytes.is_empty() || bytes.ends_with(b"\n"),
            "incomplete checkpoint tail",
        )?;
        let mut rows: Vec<Checkpoint> = vec![];
        for line in bytes
            .strip_suffix(b"\n")
            .unwrap_or(&bytes)
            .split(|b| *b == b'\n')
        {
            let cp: Checkpoint = serde_json::from_slice(line)?;
            require(serde_json::to_vec(&cp)? == line, "noncanonical checkpoint")?;
            cp.verify(&self.key.verifying_key(), self.log_id)?;
            if let Some(old) = rows.last() {
                require(cp.size > old.size, "checkpoint order/duplicate")?;
            }
            rows.push(cp);
        }
        Ok(rows)
    }
    pub fn checked(&self) -> Result<(Vec<Entry>, Vec<Checkpoint>)> {
        let entries = self.read()?;
        let checkpoints = self.checkpoints()?;
        for cp in &checkpoints {
            require(
                cp.size <= entries.len() as u64,
                "checkpoint beyond log: possible tail removal",
            )?;
            verify_log(
                &entries[..cp.size as usize],
                cp,
                &self.key.verifying_key(),
                self.log_id,
            )?;
        }
        Ok((entries, checkpoints))
    }
    fn write_checkpoint(&self, entries: &[Entry]) -> Result<Checkpoint> {
        let cp = Checkpoint::unsigned(self.log_id, entries)?.sign(&self.key)?;
        let previous = self.checkpoints()?;
        if previous.last() == Some(&cp) {
            return Ok(cp);
        }
        if let Some(old) = previous.last() {
            require(cp.size > old.size, "cannot overwrite checkpoint")?;
        }
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.dir.join("checkpoints.jsonl"))?;
        file.write_all(&serde_json::to_vec(&cp)?)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        File::open(&self.dir)?.sync_all()?;
        Ok(cp)
    }
    pub fn checkpoint(&self) -> Result<Checkpoint> {
        let _guard = self.lock()?;
        let (entries, _) = self.checked()?;
        self.write_checkpoint(&entries)
    }
    pub fn append_many(&self, payloads: &[Vec<u8>], sync_each: bool) -> Result<Vec<Entry>> {
        let _guard = self.lock()?;
        let (mut entries, _) = self.checked()?;
        require(
            payloads.len() <= 10000 && entries.len() + payloads.len() <= 100000,
            "entry count limit",
        )?;
        let added_bytes: usize = payloads.iter().map(|p| p.len() * 2 + 250).sum();
        let existing = fs::metadata(self.dir.join("entries.jsonl"))
            .map(|m| m.len())
            .unwrap_or(0);
        require(
            existing + added_bytes as u64 <= MAX_LOG_BYTES,
            "log size limit",
        )?;
        // Validate the entire batch before writing any record.
        for payload in payloads {
            require(payload.len() <= crate::MAX_PAYLOAD, "payload limit")?;
        }
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.dir.join("entries.jsonl"))?;
        for payload in payloads {
            let previous = entries
                .last()
                .map(|e| hash_from(&e.hash))
                .transpose()?
                .unwrap_or([0; 32]);
            let entry = Entry::new(entries.len() as u64, previous, payload)?;
            let mut wire = entry.wire();
            wire.push(b'\n');
            file.write_all(&wire)?;
            if sync_each {
                file.sync_all()?;
            }
            entries.push(entry);
            if entries.len() % INTERVAL == 0 {
                file.sync_all()?;
                self.write_checkpoint(&entries)?;
            }
        }
        file.sync_all()?;
        File::open(&self.dir)?.sync_all()?;
        Ok(entries)
    }
}
fn bounded_read(path: &Path) -> Result<Vec<u8>> {
    let file = File::open(path)?;
    require(file.metadata()?.len() <= MAX_LOG_BYTES, "file size limit")?;
    let mut bytes = vec![];
    file.take(MAX_LOG_BYTES + 1).read_to_end(&mut bytes)?;
    require(bytes.len() as u64 <= MAX_LOG_BYTES, "file size limit")?;
    Ok(bytes)
}
pub fn read_entries(path: &Path) -> Result<Vec<Entry>> {
    if !path.exists() {
        return Ok(vec![]);
    }
    let bytes = bounded_read(path)?;
    if bytes.is_empty() {
        return Ok(vec![]);
    }
    require(
        bytes.is_empty() || bytes.ends_with(b"\n"),
        "incomplete entry tail",
    )?;
    let mut entries = vec![];
    for line in bytes
        .strip_suffix(b"\n")
        .unwrap_or(&bytes)
        .split(|b| *b == b'\n')
    {
        require(
            line.len() <= crate::MAX_PAYLOAD * 2 + 300,
            "record size limit",
        )?;
        let entry: Entry = serde_json::from_slice(line)?;
        require(entry.wire() == line, "noncanonical record")?;
        entries.push(entry);
        require(entries.len() <= 100000, "entry count limit")?;
    }
    verify_chain(&entries)?;
    Ok(entries)
}
