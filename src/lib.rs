//! Canonical chained records, signed Merkle heads, and trust-anchor-aware verification.
pub mod merkle;
pub mod storage;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;

pub type Hash = [u8; 32];
pub type Result<T> = std::result::Result<T, Error>;
pub const MAX_PAYLOAD: usize = 16384;
#[derive(Debug)]
pub struct Error(pub String);
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}
impl std::error::Error for Error {}
impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self(e.to_string())
    }
}
impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Self(e.to_string())
    }
}
pub fn require(ok: bool, msg: &str) -> Result<()> {
    if ok { Ok(()) } else { Err(Error(msg.into())) }
}
pub fn hash_from(s: &str) -> Result<Hash> {
    let bytes = hex::decode(s).map_err(|_| Error("invalid hex".into()))?;
    require(s == hex::encode(&bytes), "noncanonical hex")?;
    bytes
        .try_into()
        .map_err(|_| Error("hash length must be 32 bytes".into()))
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    pub seq: u64,
    pub previous: String,
    pub payload: String,
    pub hash: String,
}
impl Entry {
    pub fn new(seq: u64, previous: Hash, payload: &[u8]) -> Result<Self> {
        require(payload.len() <= MAX_PAYLOAD, "payload limit")?;
        let mut h = Sha256::new();
        h.update(b"SEAL-ENTRY-v1\0");
        h.update(seq.to_be_bytes());
        h.update(previous);
        h.update((payload.len() as u64).to_be_bytes());
        h.update(payload);
        Ok(Self {
            seq,
            previous: hex::encode(previous),
            payload: hex::encode(payload),
            hash: hex::encode(h.finalize()),
        })
    }
    pub fn validate(&self) -> Result<Hash> {
        let previous = hash_from(&self.previous)?;
        require(self.payload.len() <= MAX_PAYLOAD * 2, "payload limit")?;
        let payload = hex::decode(&self.payload).map_err(|_| Error("payload hex".into()))?;
        let rebuilt = Self::new(self.seq, previous, &payload)?;
        require(self == &rebuilt, "entry hash/canonical encoding mismatch")?;
        hash_from(&self.hash)
    }
    pub fn wire(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("Entry serializes")
    }
    pub fn leaf(&self) -> Hash {
        merkle::leaf(&self.wire())
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Checkpoint {
    pub version: u8,
    pub log_id: String,
    pub size: u64,
    pub root: String,
    pub chain_head: String,
    pub signature: String,
}
impl Checkpoint {
    pub fn unsigned(log_id: Hash, entries: &[Entry]) -> Result<Self> {
        verify_chain(entries)?;
        Ok(Self {
            version: 1,
            log_id: hex::encode(log_id),
            size: entries.len() as u64,
            root: hex::encode(merkle::root(
                &entries.iter().map(Entry::leaf).collect::<Vec<_>>(),
            )),
            chain_head: entries
                .last()
                .map(|e| e.hash.clone())
                .unwrap_or(hex::encode([0u8; 32])),
            signature: String::new(),
        })
    }
    fn message(&self) -> Result<Vec<u8>> {
        require(self.version == 1, "checkpoint version")?;
        let mut bytes = b"SEAL-CHECKPOINT-v1\0".to_vec();
        bytes.extend(hash_from(&self.log_id)?);
        bytes.extend(self.size.to_be_bytes());
        bytes.extend(hash_from(&self.root)?);
        bytes.extend(hash_from(&self.chain_head)?);
        Ok(bytes)
    }
    pub fn sign(mut self, key: &SigningKey) -> Result<Self> {
        self.signature = hex::encode(key.sign(&self.message()?).to_bytes());
        Ok(self)
    }
    pub fn verify(&self, key: &VerifyingKey, log_id: Hash) -> Result<()> {
        require(hash_from(&self.log_id)? == log_id, "log identity mismatch")?;
        require(!key.is_weak(), "weak public key")?;
        let bytes = hex::decode(&self.signature).map_err(|_| Error("signature hex".into()))?;
        require(
            self.signature == hex::encode(&bytes),
            "noncanonical signature",
        )?;
        if self.size == 0 {
            require(
                hash_from(&self.root)? == merkle::root(&[])
                    && hash_from(&self.chain_head)? == [0; 32],
                "invalid empty checkpoint",
            )?;
        }
        let signature =
            Signature::from_slice(&bytes).map_err(|_| Error("signature length".into()))?;
        key.verify_strict(&self.message()?, &signature)
            .map_err(|_| Error("signature rejected".into()))
    }
}
pub fn verify_chain(entries: &[Entry]) -> Result<()> {
    let mut previous = [0u8; 32];
    for (seq, entry) in entries.iter().enumerate() {
        require(
            entry.seq == seq as u64 && hash_from(&entry.previous)? == previous,
            "chain sequence/link mismatch",
        )?;
        previous = entry.validate()?;
    }
    Ok(())
}
pub fn verify_log(
    entries: &[Entry],
    anchor: &Checkpoint,
    key: &VerifyingKey,
    log_id: Hash,
) -> Result<()> {
    anchor.verify(key, log_id)?;
    let actual = Checkpoint::unsigned(log_id, entries)?;
    require(
        actual.size == anchor.size
            && actual.root == anchor.root
            && actual.chain_head == anchor.chain_head,
        "log differs from pinned checkpoint (including tail removal)",
    )
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Inclusion {
    pub entry: Entry,
    pub checkpoint: Checkpoint,
    pub path: Vec<String>,
}
impl Inclusion {
    pub fn create(entries: &[Entry], index: usize, checkpoint: Checkpoint) -> Result<Self> {
        require(checkpoint.size == entries.len() as u64, "checkpoint size")?;
        let leaves = entries.iter().map(Entry::leaf).collect::<Vec<_>>();
        let path = merkle::inclusion(&leaves, index)?;
        Ok(Self {
            entry: entries[index].clone(),
            checkpoint,
            path: path.iter().map(hex::encode).collect(),
        })
    }
    pub fn verify(&self, key: &VerifyingKey, log_id: Hash) -> Result<()> {
        self.checkpoint.verify(key, log_id)?;
        self.entry.validate()?;
        require(self.path.len() <= 64, "proof too long")?;
        let path = self
            .path
            .iter()
            .map(|s| hash_from(s))
            .collect::<Result<Vec<_>>>()?;
        merkle::verify_inclusion(
            self.entry.leaf(),
            self.entry.seq,
            self.checkpoint.size,
            &path,
            hash_from(&self.checkpoint.root)?,
        )
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Consistency {
    pub old: Checkpoint,
    pub new: Checkpoint,
    pub path: Vec<String>,
}
impl Consistency {
    pub fn create(entries: &[Entry], old: Checkpoint, new: Checkpoint) -> Result<Self> {
        require(
            new.size == entries.len() as u64 && old.size <= new.size,
            "checkpoint size",
        )?;
        let leaves = entries.iter().map(Entry::leaf).collect::<Vec<_>>();
        Ok(Self {
            path: merkle::consistency(&leaves, old.size as usize)?
                .iter()
                .map(hex::encode)
                .collect(),
            old,
            new,
        })
    }
    pub fn verify(&self, key: &VerifyingKey, log_id: Hash) -> Result<()> {
        self.old.verify(key, log_id)?;
        self.new.verify(key, log_id)?;
        require(self.path.len() <= 65, "proof too long")?;
        require(
            self.old.size != self.new.size || self.old.chain_head == self.new.chain_head,
            "equal-size head mismatch",
        )?;
        let proof = self
            .path
            .iter()
            .map(|s| hash_from(s))
            .collect::<Result<Vec<_>>>()?;
        merkle::verify_consistency(
            self.old.size,
            self.new.size,
            hash_from(&self.old.root)?,
            hash_from(&self.new.root)?,
            &proof,
        )
    }
}
