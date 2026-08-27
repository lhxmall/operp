//! Append-only write-ahead log for `ChainState.seen_gov_nonces`.
//!
//! The gov-withdraw nonce watermark is the only dedup structure with no
//! height window (it is a monotonic per-account watermark), so pruning never
//! shrinks it — but it lives in RAM, and a node restart from an older
//! snapshot rewinds it, re-opening a replay hole. This journal closes that
//! gap: every applied `GovWithdraw` appends one record (fsynced) BEFORE the
//! in-memory watermark advances; on restart the journal replays over the
//! snapshot with max-merge, so records are idempotent.
//!
//! Record layout (60 bytes, little-endian):
//!   seq u64 || account [u8;32] || nonce u64 || height u64 || crc32 u32
//!
//! Bounded by `|accounts| × gov-ops`; compaction rewrites the file as one
//! watermark record per account (see [`GovNonceJournal::compact`]).

use operp_types::{AccountId, Height};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

pub const JOURNAL_FILE: &str = "gov_nonces.journal";
/// seq(8) + account(32) + nonce(8) + height(8) + crc32(4).
const RECORD_LEN: usize = 8 + 32 + 8 + 8 + 4;
/// Compact when the journal exceeds this size (WAL checkpoint).
const COMPACT_THRESHOLD: u64 = 1 << 20;

/// CRC32 (IEEE) over one record's payload bytes. Hand-rolled table-driven
/// implementation: no new dependency for four checksum bytes.
fn crc32(data: &[u8]) -> u32 {
    let mut table = [0u32; 256];
    for (i, slot) in table.iter_mut().enumerate() {
        let mut c = i as u32;
        for _ in 0..8 {
            c = if c & 1 != 0 {
                0xEDB8_8320 ^ (c >> 1)
            } else {
                c >> 1
            };
        }
        *slot = c;
    }
    data.iter().fold(!0u32, |c, &b| {
        table[((c ^ b as u32) & 0xFF) as usize] ^ (c >> 8)
    }) ^ !0
}

/// Durability of directory entries (file creation/rename) needs a directory
/// fsync on unix; Windows has no equivalent API, so this is a no-op there.
#[cfg(unix)]
fn fsync_dir(dir: &Path) {
    let _ = std::fs::File::open(dir).and_then(|d| d.sync_all());
}
#[cfg(not(unix))]
fn fsync_dir(_dir: &Path) {}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GovNonceRecord {
    pub account: AccountId,
    pub nonce: u64,
    pub height: Height,
}

#[derive(Clone, Debug)]
pub struct GovNonceJournal {
    path: PathBuf,
}

impl GovNonceJournal {
    pub fn open(dir: &Path) -> io::Result<Self> {
        fs::create_dir_all(dir)?;
        Ok(Self {
            path: dir.join(JOURNAL_FILE),
        })
    }

    /// Append one record and fsync. The caller MUST invoke this before
    /// mutating the in-memory watermark so a crash between the two leaves
    /// the nonce recoverable.
    pub fn append(&self, account: AccountId, nonce: u64, height: Height) -> io::Result<()> {
        let mut rec = Vec::with_capacity(RECORD_LEN);
        rec.extend_from_slice(&0u64.to_le_bytes()); // seq placeholder; offset suffices
        rec.extend_from_slice(&account.0);
        rec.extend_from_slice(&nonce.to_le_bytes());
        rec.extend_from_slice(&height.to_le_bytes());
        let crc = crc32(&rec);
        rec.extend_from_slice(&crc.to_le_bytes());
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        f.write_all(&rec)?;
        f.sync_all()?;
        fsync_dir(self.path.parent().unwrap_or(Path::new(".")));
        Ok(())
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Read all records. A torn tail or corrupted record (bad CRC) ends the
    /// log: records up to the last good one are returned AND the physical
    /// file is truncated to that boundary, so subsequent appends stay
    /// aligned (H1: memory-only truncation left the next append misaligned).
    pub fn read_all(&self) -> io::Result<Vec<GovNonceRecord>> {
        if !self.path.exists() {
            return Ok(Vec::new());
        }
        let mut buf = Vec::new();
        File::open(&self.path)?.read_to_end(&mut buf)?;
        let file_len = buf.len();
        let mut good_len = buf.len() / RECORD_LEN * RECORD_LEN;
        for (i, rec) in buf.chunks_exact(RECORD_LEN).enumerate() {
            let body = RECORD_LEN - 4;
            if crc32(&rec[..body]) != u32::from_le_bytes(rec[body..].try_into().unwrap()) {
                good_len = i * RECORD_LEN;
                break;
            }
        }
        if good_len != file_len {
            let f = OpenOptions::new().write(true).open(&self.path)?;
            f.set_len(good_len as u64)?;
            f.sync_all()?;
        }
        buf.truncate(good_len);
        let mut out = Vec::with_capacity(buf.len() / RECORD_LEN);
        for rec in buf.chunks_exact(RECORD_LEN) {
            let mut account = [0u8; 32];
            account.copy_from_slice(&rec[8..40]);
            out.push(GovNonceRecord {
                account: AccountId(account),
                nonce: u64::from_le_bytes(rec[40..48].try_into().unwrap()),
                height: u64::from_le_bytes(rec[48..56].try_into().unwrap()),
            });
        }
        Ok(out)
    }

    /// WAL checkpoint: rewrite as exactly one record per account (the current
    /// watermark), fsync, atomic rename. Keeps the file at `|accounts| × 60B`.
    pub fn compact(
        &self,
        watermarks: &std::collections::HashMap<AccountId, u64>,
    ) -> io::Result<()> {
        let tmp = self.path.with_extension("tmp");
        {
            let mut f = File::create(&tmp)?;
            let mut seq = 0u64;
            // Sorted for deterministic on-disk layout.
            for (account, nonce) in watermarks {
                let mut rec = Vec::with_capacity(RECORD_LEN);
                rec.extend_from_slice(&seq.to_le_bytes());
                rec.extend_from_slice(&account.0);
                rec.extend_from_slice(&nonce.to_le_bytes());
                rec.extend_from_slice(&0u64.to_le_bytes()); // height unknown post-compact
                let crc = crc32(&rec);
                rec.extend_from_slice(&crc.to_le_bytes());
                f.write_all(&rec)?;
                seq += 1;
            }
            f.sync_all()?;
        }
        fs::rename(&tmp, &self.path)?;
        fsync_dir(self.path.parent().unwrap_or(Path::new(".")));
        Ok(())
    }

    pub fn should_compact(&self) -> bool {
        self.path
            .metadata()
            .map(|m| m.len() > COMPACT_THRESHOLD)
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn append_read_roundtrip_and_torn_tail() {
        let dir = std::env::temp_dir().join(format!("operp-journal-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let j = GovNonceJournal::open(&dir).unwrap();
        j.append(AccountId([1; 32]), 5, 100).unwrap();
        j.append(AccountId([2; 32]), 9, 200).unwrap();
        // Torn tail: 20 bytes of a partial third record.
        {
            let mut f = OpenOptions::new().append(true).open(j.path()).unwrap();
            f.write_all(&[0u8; 20]).unwrap();
        }
        let recs = j.read_all().unwrap();
        assert_eq!(recs.len(), 2);
        assert_eq!(
            recs[0],
            GovNonceRecord {
                account: AccountId([1; 32]),
                nonce: 5,
                height: 100
            }
        );
        assert_eq!(
            recs[1],
            GovNonceRecord {
                account: AccountId([2; 32]),
                nonce: 9,
                height: 200
            }
        );
        // H1 regression: the PHYSICAL file is truncated to the record boundary.
        assert_eq!(
            fs::metadata(j.path()).unwrap().len() as usize % RECORD_LEN,
            0
        );
        // Post-truncation appends stay aligned and are fully readable after
        // a reopen (the old memory-only truncation misaligned the next write).
        j.append(AccountId([3; 32]), 12, 300).unwrap();
        let recs = GovNonceJournal::open(&dir).unwrap().read_all().unwrap();
        assert_eq!(recs.len(), 3);
        assert_eq!(
            recs[2],
            GovNonceRecord {
                account: AccountId([3; 32]),
                nonce: 12,
                height: 300
            }
        );
        j.compact(&std::iter::once((AccountId([2; 32]), 11u64)).collect())
            .unwrap();
        let recs = j.read_all().unwrap();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].nonce, 11);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn corrupted_record_drops_it_and_everything_after() {
        let dir =
            std::env::temp_dir().join(format!("operp-journal-crc-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let j = GovNonceJournal::open(&dir).unwrap();
        j.append(AccountId([1; 32]), 5, 100).unwrap();
        j.append(AccountId([2; 32]), 9, 200).unwrap();
        j.append(AccountId([3; 32]), 15, 300).unwrap();
        // Flip one byte inside the SECOND record's nonce field.
        {
            use std::io::{Read, Seek, Write};
            let mut f = OpenOptions::new()
                .read(true)
                .write(true)
                .open(j.path())
                .unwrap();
            // Second record's nonce field: one full record + nonce offset.
            f.seek(io::SeekFrom::Start(
                RECORD_LEN as u64 + (RECORD_LEN - 4 - 8) as u64,
            ))
            .unwrap();
            let mut b = [0u8; 1];
            f.read_exact(&mut b).unwrap();
            b[0] ^= 0xFF;
            f.seek(io::SeekFrom::Current(-1)).unwrap();
            f.write_all(&b).unwrap();
        }
        // The flipped record fails its CRC: it and all later records drop,
        // and the file is physically truncated to the last good boundary.
        let recs = j.read_all().unwrap();
        assert_eq!(recs.len(), 1);
        assert_eq!(fs::metadata(j.path()).unwrap().len() as usize, RECORD_LEN);
        let _ = fs::remove_dir_all(&dir);
    }
}
