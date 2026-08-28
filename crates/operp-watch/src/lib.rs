//! Independent OPERP vault-AA watcher.
//!
//! Contract (read-only except detection): reads `da_unit_<h>` from a live
//! Obyte hub, verifies the unit↔data binding, and replays the posted batch
//! through [`operp_settle::Batch::validate_against`]. Any height whose replay
//! fails is a mismatch that a watcher-owned wallet would challenge on-chain.
//!
//! This crate NEVER writes `submit`/`lock`/`finalize`. The `challenge` is the
//! only AA transaction a watcher may emit, and it is issued by the binary
//! (whose signing backend is the operator's separate deployment concern —
//! see the watcher limitation footnote in the workspace README).
//!
//! The core [`HubClient`] is abstracted so the replay/verify logic is fully
//! unit-testable without a live hub; the binary supplies an HTTP client.

use operp_dag::{Op, Unit};
use operp_exec::Engine;
use operp_settle::{Batch, Checkpoint, DepositEvidence, SettleError};
use operp_state::AA_SHARD_COUNT;
use operp_types::UnitId;

/// Challenge bond gross attached to a `challenge` trigger: 20000 gross =
/// 10000 bounce-fee headroom + 10000 net, matching the AA's bond gate
/// (`operp_vault.aa` `bond too small`).
pub const CHALLENGE_BOND_GROSS: u64 = 20_000;
/// Default poll interval in seconds.
pub const DEFAULT_POLL_INTERVAL_SECS: u64 = 30;

/// Watcher configuration.
#[derive(Clone, Debug)]
pub struct WatchConfig {
    /// Obyte vault AA address to watch.
    pub vault_address: String,
    /// Hub JSON-RPC base URL (e.g. `http://127.0.0.1:6611`).
    pub hub_url: Option<String>,
    pub poll_interval_secs: u64,
    pub challenge_bond_gross: u64,
}

impl Default for WatchConfig {
    fn default() -> Self {
        Self {
            vault_address: String::new(),
            hub_url: None,
            poll_interval_secs: DEFAULT_POLL_INTERVAL_SECS,
            challenge_bond_gross: CHALLENGE_BOND_GROSS,
        }
    }
}

/// A batch's data-availability unit as observed on-chain.
#[derive(Clone, Debug)]
pub struct DaUnit {
    /// Batch height.
    pub height: u64,
    /// The Obyte unit hash recorded in `da_unit_<h>`.
    pub unit_hash: String,
    /// The temp_data payload `data` (the batch JSON) carried by that unit.
    pub data: serde_json::Value,
    /// The raw Obyte joint fetched for `unit_hash` (for binding re-hash).
    pub joint: serde_json::Value,
}

/// Errors surfaced by the watcher core.
#[derive(Debug, thiserror::Error)]
pub enum WatchError {
    #[error("hub unavailable: {0}")]
    HubUnavailable(String),
    #[error("no da_unit at height {0}")]
    DaMissing(u64),
    #[error("binding mismatch: {0}")]
    BindingMismatch(String),
    #[error("settle: {0}")]
    Settle(#[from] SettleError),
    #[error("challenge rejected: {0}")]
    AaChallengeFailed(String),
}

/// Abstraction over the Obyte hub. Tests provide a mock; the binary provides
/// an HTTP-backed implementation (`HttpHubClient`).
pub trait HubClient {
    /// Read a single AA state variable. `Ok(Some(value))` when set,
    /// `Ok(None)` when the var is absent, `Err` on transport failure.
    fn get_aa_state_var(&self, address: &str, key: &str) -> Result<Option<serde_json::Value>, String>;
    /// Fetch a unit/joint by its hash as the hub returns it.
    fn get_joint(&self, unit_hash: &str) -> Result<serde_json::Value, String>;
}

/// Fetch the `da_unit_<height>` package from the hub, verifying the recorded
/// unit hash actually corresponds to the joint that carries the temp_data.
///
/// Returns `Ok(None)` when the height has no `da_unit_<h>` (never submitted,
/// or cleared by a failed-finalize sweep). Transport failures are
/// [`WatchError::HubUnavailable`] so the caller backs off rather than
/// mis-challenging.
pub fn fetch_da_unit<H: HubClient>(
    hub: &H,
    vault: &str,
    height: u64,
) -> Result<Option<DaUnit>, WatchError> {
    let key = format!("da_unit_{}", height);
    let val = hub
        .get_aa_state_var(vault, &key)
        .map_err(WatchError::HubUnavailable)?;
    let unit_hash = match val {
        Some(v) => v
            .as_str()
            .ok_or_else(|| WatchError::HubUnavailable("da_unit var not a string".into()))?
            .to_string(),
        None => return Ok(None),
    };
    let joint = hub
        .get_joint(&unit_hash)
        .map_err(WatchError::HubUnavailable)?;
    let data = extract_temp_data(&joint).ok_or_else(|| {
        WatchError::HubUnavailable("joint has no inline temp_data payload".into())
    })?;
    Ok(Some(DaUnit {
        height,
        unit_hash,
        data,
        joint,
    }))
}

/// Verify the DA binding: the Obyte unit whose hash the AA recorded in
/// `da_unit_<h>` must be exactly the joint we fetched (`get_unit_hash`).
/// `validate_against` separately proves the root points at this data package.
pub fn verify_da_binding(da: &DaUnit) -> Result<(), WatchError> {
    let recomputed = obyte_hash::get_unit_hash(&da.joint)
        .map_err(|e| WatchError::BindingMismatch(e))?;
    let recomputed_hex = hex::encode(recomputed);
    if recomputed_hex != da.unit_hash {
        return Err(WatchError::BindingMismatch(format!(
            "recorded unit_hash {} != recomputed {}",
            da.unit_hash, recomputed_hex
        )));
    }
    Ok(())
}

/// Replay a posted batch against the running engine and assert it reproduces
/// the committed roots. On success the engine is advanced to the batch's
/// state (so the caller can replay `h+1` with `engine.state.state_root()` as
/// its prev root). Any failure is a real root mismatch.
pub fn replay_and_check(
    da: &DaUnit,
    prev_root: [u8; 32],
    engine: &mut Engine,
) -> Result<(), SettleError> {
    let batch = batch_from_data(&da.data)?;
    batch.validate_against(prev_root, engine)
}

/// Rebuild a [`Batch`] from the temp_data payload's `data` value. The wire
/// format stores hashes as hex strings and `perp_burned` as a decimal string,
/// so `Checkpoint`'s serde representation does not match — reconstruct it.
fn batch_from_data(data: &serde_json::Value) -> Result<Batch, SettleError> {
    let chain_id = data
        .get("chain_id")
        .and_then(|v| v.as_str())
        .ok_or(SettleError::ChainMismatch)?
        .to_string();
    let checkpoint = checkpoint_from_data(data)?;
    let units = units_from_data(data)?;
    let deposit_evidences: Vec<DepositEvidence> = operp_settle::evidences_from_payload(data)?;
    Ok(Batch {
        chain_id,
        checkpoint,
        units,
        deposit_evidences,
    })
}

fn checkpoint_from_data(data: &serde_json::Value) -> Result<Checkpoint, SettleError> {
    let height = get_u64(data, "height")?;
    let prev_state_hash = get_hex32(data, "prev_state_hash")?;
    let state_root = get_hex32(data, "state_root")?;
    let aa_root = get_str(data, "aa_root")?.to_string();
    let last_unit = UnitId(get_hex32(data, "last_unit")?);
    let seq = get_u64(data, "seq")?;
    let fill_count = get_u64(data, "fill_count")? as u32;
    let fills_hash = get_hex32(data, "fills_hash")?;
    let validity_proof_hash = data
        .get("validity_proof_hash")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let perp_burned = data
        .get("perp_burned")
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse::<u128>().ok());

    let shards_json = data
        .get("aa_shard_roots")
        .and_then(|v| v.as_array())
        .ok_or(SettleError::RootMismatch)?;
    if shards_json.len() != AA_SHARD_COUNT {
        return Err(SettleError::RootMismatch);
    }
    let mut aa_shard_roots: [String; AA_SHARD_COUNT] = Default::default();
    for (i, s) in shards_json.iter().enumerate() {
        aa_shard_roots[i] = s.as_str().ok_or(SettleError::RootMismatch)?.to_string();
    }

    let unit_ids_json = data
        .get("unit_ids")
        .and_then(|v| v.as_array())
        .ok_or(SettleError::RootMismatch)?;
    let mut unit_ids = Vec::with_capacity(unit_ids_json.len());
    for u in unit_ids_json {
        unit_ids.push(UnitId(
            hex_to_32(&u.as_str().ok_or(SettleError::RootMismatch)?)
                .map_err(|_| SettleError::RootMismatch)?,
        ));
    }

    Ok(Checkpoint {
        height,
        prev_state_hash,
        state_root,
        aa_shard_roots,
        aa_root,
        last_unit,
        seq,
        unit_ids,
        fills_hash,
        fill_count,
        validity_proof_hash,
        perp_burned,
    })
}

fn units_from_data(data: &serde_json::Value) -> Result<Vec<Unit>, SettleError> {
    let units_json = data
        .get("units")
        .and_then(|v| v.as_array())
        .ok_or(SettleError::Replay)?;
    let mut units = Vec::with_capacity(units_json.len());
    for u in units_json {
        let parents_json = u
            .get("parents")
            .and_then(|v| v.as_array())
            .ok_or(SettleError::Replay)?;
        let mut parents = Vec::with_capacity(parents_json.len());
        for p in parents_json {
            parents.push(UnitId(
                hex_to_32(&p.as_str().ok_or(SettleError::Replay)?)
                    .map_err(|_| SettleError::Replay)?,
            ));
        }
        let op: Op = serde_json::from_value(u.get("op").cloned().ok_or(SettleError::Replay)?)
            .map_err(|_| SettleError::Replay)?;
        let pubkey = hex_to_32(&u.get("pubkey").and_then(|v| v.as_str()).ok_or(SettleError::Replay)?)
            .map_err(|_| SettleError::Replay)?;
        let sig = hex_to_64(&u.get("sig").and_then(|v| v.as_str()).ok_or(SettleError::Replay)?)
            .map_err(|_| SettleError::Replay)?;
        units.push(Unit {
            parents,
            op,
            pubkey,
            sig,
        });
    }
    Ok(units)
}

/// Locate the inline `temp_data` payload inside a hub-returned joint. The
/// joint shape varies (top-level `messages` vs nested under `unit.messages`),
/// so both are probed.
fn extract_temp_data(joint: &serde_json::Value) -> Option<serde_json::Value> {
    let messages = joint
        .get("messages")
        .or_else(|| joint.get("unit").and_then(|u| u.get("messages")))?;
    let arr = messages.as_array()?;
    for m in arr {
        if m.get("app").and_then(|a| a.as_str()) == Some("temp_data") {
            if let Some(data) = m.pointer("/payload/data") {
                return Some(data.clone());
            }
        }
    }
    None
}

fn get_str<'a>(data: &'a serde_json::Value, key: &str) -> Result<&'a str, SettleError> {
    data.get(key)
        .and_then(|v| v.as_str())
        .ok_or(SettleError::RootMismatch)
}

fn get_u64(data: &serde_json::Value, key: &str) -> Result<u64, SettleError> {
    data.get(key)
        .and_then(|v| v.as_u64())
        .ok_or(SettleError::RootMismatch)
}

fn get_hex32(data: &serde_json::Value, key: &str) -> Result<[u8; 32], SettleError> {
    hex_to_32(get_str(data, key)?).map_err(|_| SettleError::RootMismatch)
}

fn hex_to_32(s: &str) -> Result<[u8; 32], hex::FromHexError> {
    let v = hex::decode(s)?;
    let mut out = [0u8; 32];
    if v.len() != 32 {
        return Err(hex::FromHexError::InvalidStringLength);
    }
    out.copy_from_slice(&v);
    Ok(out)
}

fn hex_to_64(s: &str) -> Result<[u8; 64], hex::FromHexError> {
    let v = hex::decode(s)?;
    let mut out = [0u8; 64];
    if v.len() != 64 {
        return Err(hex::FromHexError::InvalidStringLength);
    }
    out.copy_from_slice(&v);
    Ok(out)
}

pub use operp_settle::obyte_hash;

#[cfg(test)]
mod tests {
    use super::*;

    // A tiny mock hub serving a fixed set of state vars + joints.
    struct MockHub {
        vars: std::collections::HashMap<String, serde_json::Value>,
        joints: std::collections::HashMap<String, serde_json::Value>,
    }

    impl HubClient for MockHub {
        fn get_aa_state_var(&self, _addr: &str, key: &str) -> Result<Option<serde_json::Value>, String> {
            Ok(self.vars.get(key).cloned())
        }
        fn get_joint(&self, unit_hash: &str) -> Result<serde_json::Value, String> {
            self.joints
                .get(unit_hash)
                .cloned()
                .ok_or_else(|| format!("404: no joint {}", unit_hash))
        }
    }

    // Build the on-chain temp_data message shape used by post_batch.js.
    fn temp_data_msg(data: &serde_json::Value) -> serde_json::Value {
        serde_json::json!({
            "app": "temp_data",
            "payload_location": "inline",
            "payload": {
                "data_length": 0,
                "data_hash": "x",
                "data": data.clone(),
            }
        })
    }

    // Encode a minimal joint wrapping a temp_data message. The exact unit hash
    // is not meaningful here; tests override the recorded hash to flip binding.
    fn joint_with(data: &serde_json::Value, unit_hash: &str) -> serde_json::Value {
        serde_json::json!({
            "unit": {
                "version": "1.0",
                "messages": [temp_data_msg(data)],
                "unit": unit_hash,
            },
            "messages": [temp_data_msg(data)],
        })
    }

    #[test]
    fn extract_temp_data_finds_inline_payload() {
        let data = serde_json::json!({"height": 1, "state_root": "aa"});
        let joint = joint_with(&data, "u1");
        let got = extract_temp_data(&joint).unwrap();
        assert_eq!(got, data);
    }

    #[test]
    fn fetch_da_unit_missing_returns_none() {
        let hub = MockHub { vars: Default::default(), joints: Default::default() };
        assert!(fetch_da_unit(&hub, "vault", 9).unwrap().is_none());
    }

    #[test]
    fn verify_da_binding_detects_tampered_recorded_hash() {
        // A joint's recomputed unit hash will not equal a bogus recorded hash.
        let data = serde_json::json!({"height": 1});
        let joint = joint_with(&data, "bogus-hash");
        let da = DaUnit { height: 1, unit_hash: "bogus-hash".to_string(), data, joint };
        // get_unit_hash over a minimal joint may error or produce a hash that
        // differs from "bogus-hash"; either way it must not return Ok.
        assert!(verify_da_binding(&da).is_err());
    }

    // ---- real-batch replay tests (mirror crates/operp-settle/examples/export_batch.rs) ----
    use ed25519_dalek::SigningKey;
    use operp_dag::{genesis_id, sign_unit, unit_id, Op};
    use operp_settle::Batch;
    use operp_types::{
        account_id_from_pubkey, BTC_USD, OrderType, PRICE_SCALE, QTY_SCALE, Side, TimeInForce,
        USD_SCALE,
    };

    fn setup_engine() -> Engine {
        let mut eng = Engine::new();
        eng.state
            .markets
            .insert(BTC_USD, operp_types::genesis_params());
        // Pre-fund the two accounts so a deposit-free Place batch passes intake.
        let mut a = operp_state::Account::new(account_id_from_pubkey(
            &SigningKey::from_bytes(&[1u8; 32]).verifying_key().to_bytes(),
        ));
        a.collateral = 10_000 * USD_SCALE as i128;
        eng.state.accounts.insert(a.id, a);
        let mut b = operp_state::Account::new(account_id_from_pubkey(
            &SigningKey::from_bytes(&[2u8; 32]).verifying_key().to_bytes(),
        ));
        b.collateral = 10_000 * USD_SCALE as i128;
        eng.state.accounts.insert(b.id, b);
        eng
    }

    fn build_batch_da(tamper_root: bool) -> DaUnit {
        let mut eng = setup_engine();
        let prev = eng.state.clone();
        let g = genesis_id();
        let alice = [1u8; 32];
        let bob = [2u8; 32];
        let alice_id = account_id_from_pubkey(&SigningKey::from_bytes(&alice).verifying_key().to_bytes());
        let bob_id = account_id_from_pubkey(&SigningKey::from_bytes(&bob).verifying_key().to_bytes());
        let mut applied = Vec::new();
        let mut tip = g;

        let px = 100_000 * PRICE_SCALE;
        let qty = QTY_SCALE;
        let ask = sign_unit(
            vec![tip],
            Op::Place { account: bob_id, market: BTC_USD, side: Side::Ask, typ: OrderType::Limit, tif: TimeInForce::Gtc, price: px, qty, client_seq: 1 },
            &bob,
        );
        tip = unit_id(&ask);
        applied.push(tip);
        eng.ingest(ask).unwrap();

        let bid = sign_unit(
            vec![tip],
            Op::Place { account: alice_id, market: BTC_USD, side: Side::Bid, typ: OrderType::Limit, tif: TimeInForce::Gtc, price: px, qty, client_seq: 1 },
            &alice,
        );
        tip = unit_id(&bid);
        applied.push(tip);
        eng.ingest(bid).unwrap();

        let batch = Batch::from_applied(&prev, &mut eng, &applied).expect("batch");
        let payload = batch.temp_data_payload();
        let mut data = payload.data.clone();
        if tamper_root {
            data["state_root"] = serde_json::json!(hex::encode([0xAAu8; 32]));
        }
        DaUnit { height: batch.checkpoint.height, unit_hash: String::new(), data, joint: serde_json::Value::Null }
    }

    #[test]
    fn replay_and_check_accepts_good_batch() {
        let da = build_batch_da(false);
        let mut replay = setup_engine();
        let prev_root = replay.state.state_root();
        assert!(
            replay_and_check(&da, prev_root, &mut replay).is_ok(),
            "good batch must replay cleanly"
        );
    }

    #[test]
    fn replay_and_check_rejects_tampered_root() {
        let da = build_batch_da(true);
        let mut replay = setup_engine();
        let prev_root = replay.state.state_root();
        assert!(
            replay_and_check(&da, prev_root, &mut replay).is_err(),
            "tampered batch must not replay"
        );
    }
}
