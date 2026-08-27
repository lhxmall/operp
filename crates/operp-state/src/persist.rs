//! Snapshot persistence for `ChainState` (gap 11 v1, Choice A-lite).
//!
//! Snapshots are content-addressed by height only: `chainstate.<height>.snap`
//! (bincode). They are a crash-recovery accelerator, NOT consensus state —
//! `state_root` is always recomputed by replay, and the operator replays
//! finalized `temp_data` batches on top of the latest snapshot whose height
//! is still valid. Only finalized heights are immutable, so operators must
//! snapshot at (or before) their last finalized batch.
//!
//! On restart: [`load_latest`] returns the newest snapshot; the caller then
//! replays `gov_nonces.journal` over it (see [`crate::journal`]) and any
//! batches newer than the snapshot via `Batch::validate_against`.

use crate::ChainState;
use operp_types::Height;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

pub const SNAPSHOT_PREFIX: &str = "chainstate.";
pub const SNAPSHOT_EXT: &str = "snap";
/// Default flush cadence (`Engine::maybe_flush_snapshot`).
pub const SNAPSHOT_EVERY: Height = 64;
/// Old snapshots kept beyond the newest (crash during rename safety).
const KEEP_SNAPSHOTS: usize = 2;
/// Version header prefixing every snapshot body. Old formats are not
/// migrated (mainnet is not live); unknown versions are skipped by
/// [`load_latest`].
const SNAPSHOT_FORMAT_VERSION: u32 = 1;

/// Durability of directory entries (rename) needs a directory fsync on unix;
/// Windows has no equivalent API, so this is a no-op there.
#[cfg(unix)]
fn fsync_dir(dir: &Path) {
    let _ = std::fs::File::open(dir).and_then(|d| d.sync_all());
}
#[cfg(not(unix))]
fn fsync_dir(_dir: &Path) {}

fn snapshot_name(height: Height) -> String {
    format!("{SNAPSHOT_PREFIX}{height}.{SNAPSHOT_EXT}")
}

/// Persist `state` atomically (tmp file + rename), then prune old snapshots.
/// Returns the snapshot path.
pub fn save_snapshot(dir: &Path, state: &ChainState) -> io::Result<PathBuf> {
    fs::create_dir_all(dir)?;
    let bytes =
        bincode::serialize(state).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let path = dir.join(snapshot_name(state.height));
    let tmp = dir.join(format!("{}.tmp", snapshot_name(state.height)));
    {
        use std::io::Write;
        let mut f = fs::File::create(&tmp)?;
        f.write_all(&SNAPSHOT_FORMAT_VERSION.to_le_bytes())?;
        f.write_all(&bytes)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, &path)?;
    fsync_dir(dir);
    prune_snapshots(dir, KEEP_SNAPSHOTS)?;
    Ok(path)
}

/// Load the newest readable snapshot in `dir`. Candidates are tried from
/// newest height down: an unreadable newest file falls back to the previous
/// height instead of failing startup (M2). Returns Ok(None) on a fresh dir.
pub fn load_latest(dir: &Path) -> io::Result<Option<(Height, ChainState)>> {
    let mut last_err: Option<io::Error> = None;
    for (_, path) in snapshot_candidates(dir)? {
        let parsed = (|| -> io::Result<ChainState> {
            let bytes = fs::read(&path)?;
            if bytes.len() < 4
                || u32::from_le_bytes(bytes[..4].try_into().unwrap()) != SNAPSHOT_FORMAT_VERSION
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "unknown snapshot format version",
                ));
            }
            bincode::deserialize(&bytes[4..])
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
        })();
        match parsed {
            Ok(state) => return Ok(Some((state.height, state))),
            Err(e) => last_err = Some(e),
        }
    }
    match last_err {
        Some(e) => Err(e),
        None => Ok(None),
    }
}

/// All snapshots in `dir` as (height, path), descending by height.
fn snapshot_candidates(dir: &Path) -> io::Result<Vec<(Height, PathBuf)>> {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        // Fresh store dir: genesis recovery, not an error.
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    let mut out: Vec<(Height, PathBuf)> = Vec::new();
    for entry in entries {
        let entry = entry?;
        if !entry.metadata()?.is_file() {
            continue;
        }
        let name = entry.file_name();
        let name = name.to_string_lossy();
        let Some(rest) = name.strip_prefix(SNAPSHOT_PREFIX) else {
            continue;
        };
        let Some(h) = rest.strip_suffix(&format!(".{SNAPSHOT_EXT}")) else {
            continue;
        };
        if let Ok(h) = h.parse::<Height>() {
            out.push((h, dir.join(snapshot_name(h))));
        }
    }
    out.sort_unstable_by(|a, b| b.0.cmp(&a.0));
    Ok(out)
}

pub fn latest_snapshot(dir: &Path) -> io::Result<Option<PathBuf>> {
    Ok(snapshot_candidates(dir)?.into_iter().next().map(|(_, p)| p))
}

fn prune_snapshots(dir: &Path, keep: usize) -> io::Result<()> {
    // Orphan tmp files from a crash mid-save are never valid snapshots.
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            if name.to_string_lossy().starts_with(SNAPSHOT_PREFIX)
                && name
                    .to_string_lossy()
                    .ends_with(&format!(".{SNAPSHOT_EXT}.tmp"))
            {
                let _ = fs::remove_file(entry.path());
            }
        }
    }
    let candidates = snapshot_candidates(dir)?;
    for (h, _) in candidates.iter().skip(keep) {
        let _ = fs::remove_file(dir.join(snapshot_name(*h)));
    }
    fsync_dir(dir);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_roundtrip_keeps_newest() {
        let dir = std::env::temp_dir().join(format!("operp-snap-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let s1 = ChainState::new();
        save_snapshot(&dir, &s1).unwrap();
        let mut s2 = ChainState::new();
        s2.height = 42;
        s2.perp_supply = 777;
        save_snapshot(&dir, &s2).unwrap();
        let (h, st) = load_latest(&dir).unwrap().unwrap();
        assert_eq!(h, 42);
        assert_eq!(st.perp_supply, 777);
        // Pruning caps retained snapshots at KEEP_SNAPSHOTS.
        let mut n = 0;
        for e in fs::read_dir(&dir).unwrap() {
            if e.unwrap()
                .file_name()
                .to_string_lossy()
                .ends_with(SNAPSHOT_EXT)
            {
                n += 1;
            }
        }
        assert_eq!(n, KEEP_SNAPSHOTS);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn corrupt_newest_falls_back_to_previous_and_unknown_version_skipped() {
        let dir = std::env::temp_dir().join(format!("operp-snap-fb-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let s0 = ChainState::new();
        save_snapshot(&dir, &s0).unwrap();
        let mut s1 = ChainState::new();
        s1.height = 42;
        s1.perp_supply = 777;
        save_snapshot(&dir, &s1).unwrap();
        // Corrupt the newest (height 42) body.
        {
            use std::io::{Seek, Write};
            let mut f = fs::OpenOptions::new()
                .write(true)
                .open(dir.join(snapshot_name(42)))
                .unwrap();
            f.seek(io::SeekFrom::End(-3)).unwrap();
            f.write_all(&[0xDE, 0xAD, 0xBE]).unwrap();
        }
        // M2 regression: startup falls back to the previous snapshot instead
        // of failing outright.
        let (h, st) = load_latest(&dir).unwrap().unwrap();
        assert_eq!(h, 0);
        assert_eq!(st.perp_supply, 0);

        // A file with an unknown version header is skipped, not fatal.
        std::fs::write(dir.join(snapshot_name(99)), &[9, 9, 9, 9, 1, 2, 3]).unwrap();
        let (h, _st) = load_latest(&dir).unwrap().unwrap();
        assert_eq!(h, 0);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn prune_removes_orphan_tmp_files() {
        let dir = std::env::temp_dir().join(format!("operp-snap-tmp-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let orphan = dir.join(format!("{SNAPSHOT_PREFIX}7.{SNAPSHOT_EXT}.tmp"));
        std::fs::write(&orphan, b"junk").unwrap();
        save_snapshot(&dir, &ChainState::new()).unwrap();
        assert!(!orphan.exists(), "crash-orphan .snap.tmp must be pruned");
        let _ = fs::remove_dir_all(&dir);
    }
}
