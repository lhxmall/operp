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

fn snapshot_name(height: Height) -> String {
    format!("{SNAPSHOT_PREFIX}{height}.{SNAPSHOT_EXT}")
}

/// Persist `state` atomically (tmp file + rename), then prune old snapshots.
/// Returns the snapshot path.
pub fn save_snapshot(dir: &Path, state: &ChainState) -> io::Result<PathBuf> {
    fs::create_dir_all(dir)?;
    let bytes = bincode::serialize(state)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let path = dir.join(snapshot_name(state.height));
    let tmp = dir.join(format!("{}.tmp", snapshot_name(state.height)));
    {
        use std::io::Write;
        let mut f = fs::File::create(&tmp)?;
        f.write_all(&bytes)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, &path)?;
    prune_snapshots(dir, KEEP_SNAPSHOTS)?;
    Ok(path)
}

/// Load the newest `chainstate.<height>.snap` in `dir`, if any.
pub fn load_latest(dir: &Path) -> io::Result<Option<(Height, ChainState)>> {
    let best = latest_snapshot(dir)?;
    let Some(path) = best else { return Ok(None) };
    let bytes = fs::read(&path)?;
    let state: ChainState = bincode::deserialize(&bytes)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    Ok(Some((state.height, state)))
}

pub fn latest_snapshot(dir: &Path) -> io::Result<Option<PathBuf>> {
    let mut heights: Vec<Height> = Vec::new();
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        // Fresh store dir: genesis recovery, not an error.
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    for entry in entries {
        let entry = entry?;
        if !entry.metadata()?.is_file() {
            continue;
        }
        let name = entry.file_name();
        let name = name.to_string_lossy();
        let Some(rest) = name.strip_prefix(SNAPSHOT_PREFIX) else { continue };
        let Some(h) = rest.strip_suffix(&format!(".{SNAPSHOT_EXT}")) else { continue };
        if let Ok(h) = h.parse::<Height>() {
            heights.push(h);
        }
    }
    heights.sort_unstable();
    Ok(heights.pop().map(|h| dir.join(snapshot_name(h))))
}

fn prune_snapshots(dir: &Path, keep: usize) -> io::Result<()> {
    let mut heights: Vec<Height> = Vec::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        let Some(rest) = name.strip_prefix(SNAPSHOT_PREFIX) else { continue };
        let Some(h) = rest.strip_suffix(&format!(".{SNAPSHOT_EXT}")) else { continue };
        if let Ok(h) = h.parse::<Height>() {
            heights.push(h);
        }
    }
    heights.sort_unstable();
    while heights.len() > keep {
        let h = heights.remove(0);
        let _ = fs::remove_file(dir.join(snapshot_name(h)));
    }
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
            if e.unwrap().file_name().to_string_lossy().ends_with(SNAPSHOT_EXT) {
                n += 1;
            }
        }
        assert_eq!(n, KEEP_SNAPSHOTS);
        let _ = fs::remove_dir_all(&dir);
    }
}
