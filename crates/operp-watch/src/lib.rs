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

pub mod prove;
use operp_exec::Engine;
use operp_settle::{Batch, SettleError};

/// Challenge bond gross attached to a `challenge` trigger.
/// mirrors operp_types::CHALLENGE_BOND_NET + BOUNCE_FEE_BASE
pub const CHALLENGE_BOND_GROSS: u64 = 1_000_000_010_000;
/// Default poll interval in seconds.
pub const DEFAULT_POLL_INTERVAL_SECS: u64 = 30;

/// Watcher configuration.
#[derive(Clone, Debug)]
pub struct WatchConfig {
    /// Obyte rollup AA address to watch.
    pub rollup_address: String,
    /// Obyte vault AA address (deposit evidence payee).
    pub vault_address: String,
    /// Optional dispute AA address (challenge posting target).
    pub dispute_address: Option<String>,
    /// Hub JSON-RPC base URL (e.g. `http://127.0.0.1:6611`).
    pub hub_url: Option<String>,
    pub poll_interval_secs: u64,
    pub challenge_bond_gross: u64,
}

impl Default for WatchConfig {
    fn default() -> Self {
        Self {
            rollup_address: String::new(),
            vault_address: String::new(),
            dispute_address: None,
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
    fn get_aa_state_var(
        &self,
        address: &str,
        key: &str,
    ) -> Result<Option<serde_json::Value>, String>;
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
        WatchError::BindingMismatch("joint has no inline temp_data payload".into())
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
    let recomputed =
        obyte_hash::get_unit_hash(&da.joint).map_err(|e| WatchError::BindingMismatch(e))?;
    let recomputed_hex = hex::encode(recomputed);
    if recomputed_hex != da.unit_hash {
        return Err(WatchError::BindingMismatch(format!(
            "recorded unit_hash {} != recomputed {}",
            da.unit_hash, recomputed_hex
        )));
    }
    Ok(())
}
/// Assemble a multi-package header's blob: fetch each `packages` hash via
/// `get_joint`, require its `package_blob` string, concat raw bytes, and
/// check hex(sha256(concat)) against `data_root`. Transport errors map to
/// `HubUnavailable` (caller backs off); bad content maps to
/// `BindingMismatch`. No retries here — the poll loop owns backoff.
pub fn assemble_frames<H: HubClient>(
    hub: &H,
    data: &serde_json::Value,
) -> Result<String, WatchError> {
    let hashes = data
        .get("packages")
        .and_then(|v| v.as_array())
        .ok_or_else(|| {
            WatchError::BindingMismatch("header has neither frames_blob nor packages".into())
        })?;
    let want = data
        .get("data_root")
        .and_then(|v| v.as_str())
        .ok_or_else(|| WatchError::BindingMismatch("packages header missing data_root".into()))?;
    use base64::Engine as _;
    let mut concat: Vec<u8> = Vec::new();
    for h in hashes {
        let s = h
            .as_str()
            .ok_or_else(|| WatchError::BindingMismatch("package hash not a string".into()))?;
        let joint = hub.get_joint(s).map_err(WatchError::HubUnavailable)?;
        let payload = extract_temp_data(&joint)
            .ok_or_else(|| WatchError::BindingMismatch("package joint has no temp_data".into()))?;
        let b64 = payload
            .get("package_blob")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                WatchError::BindingMismatch("package joint missing package_blob".into())
            })?;
        let raw = base64::engine::general_purpose::STANDARD
            .decode(b64)
            .map_err(|_| WatchError::BindingMismatch("package_blob not base64".into()))?;
        concat.extend_from_slice(&raw);
    }
    use sha2::{Digest, Sha256};
    let got = hex::encode(Sha256::digest(&concat));
    if got != want {
        return Err(WatchError::BindingMismatch(format!(
            "data_root mismatch: want {want} got {got}"
        )));
    }
    Ok(base64::engine::general_purpose::STANDARD.encode(&concat))
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

/// Rebuild a [`Batch`] from the temp_data header JSON. The new wire stores
/// scalars plus `frames_blob` (single package). Multi-package
/// (`packages`+`data_root`) arrives via `assemble_frames` before this call —
/// legacy `units`-array headers are rejected.
pub fn batch_from_data(data: &serde_json::Value) -> Result<Batch, SettleError> {
    if data.get("units").is_some() {
        return Err(SettleError::RootMismatch);
    }
    let blob = get_str(data, "frames_blob")?;
    use base64::Engine as _;
    let raw = base64::engine::general_purpose::STANDARD
        .decode(blob)
        .map_err(|_| SettleError::RootMismatch)?;
    let text = String::from_utf8(raw).map_err(|_| SettleError::RootMismatch)?;
    let frames: Vec<String> = if text.is_empty() {
        Vec::new()
    } else {
        text.split('\n').map(|s| s.to_string()).collect()
    };
    operp_settle::batch_from_frames(data, &frames)
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
        fn get_aa_state_var(
            &self,
            _addr: &str,
            key: &str,
        ) -> Result<Option<serde_json::Value>, String> {
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
        let hub = MockHub {
            vars: Default::default(),
            joints: Default::default(),
        };
        assert!(fetch_da_unit(&hub, "vault", 9).unwrap().is_none());
    }

    #[test]
    fn fetch_da_unit_no_temp_data_is_binding_mismatch() {
        // Joint carries submit data but no inline temp_data message.
        let joint = serde_json::json!({
            "unit": {
                "version": "1.0",
                "messages": [{ "app": "data", "payload": { "submit": 1, "height": 1 } }],
                "unit": "u-no-td",
            },
            "messages": [{ "app": "data", "payload": { "submit": 1, "height": 1 } }],
        });
        let hub = MockHub {
            vars: std::collections::HashMap::from([(
                "da_unit_1".into(),
                serde_json::json!("u-no-td"),
            )]),
            joints: std::collections::HashMap::from([("u-no-td".into(), joint)]),
        };
        let err = fetch_da_unit(&hub, "vault", 1).unwrap_err();
        assert!(
            matches!(err, WatchError::BindingMismatch(_)),
            "empty DA must be BindingMismatch, not HubUnavailable: {err:?}"
        );
        assert!(!matches!(err, WatchError::HubUnavailable(_)));
    }

    #[test]
    fn verify_da_binding_detects_tampered_recorded_hash() {
        // A joint's recomputed unit hash will not equal a bogus recorded hash.
        let data = serde_json::json!({"height": 1});
        let joint = joint_with(&data, "bogus-hash");
        let da = DaUnit {
            height: 1,
            unit_hash: "bogus-hash".to_string(),
            data,
            joint,
        };
        // get_unit_hash over a minimal joint may error or produce a hash that
        // differs from "bogus-hash"; either way it must not return Ok.
        assert!(verify_da_binding(&da).is_err());
    }

    // ---- real-batch replay tests (mirror crates/operp-settle/examples/export_batch.rs) ----
    use ed25519_dalek::SigningKey;
    use operp_dag::{genesis_id, sign_unit, unit_id, Op};
    use operp_settle::Batch;
    use operp_types::{
        account_id_from_pubkey, OrderType, Side, TimeInForce, BTC_USD, PRICE_SCALE, QTY_SCALE,
        USD_SCALE,
    };

    fn setup_engine() -> Engine {
        let mut eng = Engine::new();
        eng.state
            .markets
            .insert(BTC_USD, operp_types::genesis_params());
        // Pre-fund the two accounts so a deposit-free Place batch passes intake.
        let mut a = operp_state::Account::new(account_id_from_pubkey(
            &SigningKey::from_bytes(&[1u8; 32])
                .verifying_key()
                .to_bytes(),
        ));
        a.collateral = 10_000 * USD_SCALE as i128;
        eng.state.accounts.insert(a.id, a);
        let mut b = operp_state::Account::new(account_id_from_pubkey(
            &SigningKey::from_bytes(&[2u8; 32])
                .verifying_key()
                .to_bytes(),
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
        let alice_id =
            account_id_from_pubkey(&SigningKey::from_bytes(&alice).verifying_key().to_bytes());
        let bob_id =
            account_id_from_pubkey(&SigningKey::from_bytes(&bob).verifying_key().to_bytes());
        let mut applied = Vec::new();
        let mut tip = g;

        let px = 100_000 * PRICE_SCALE as i64;
        let qty = QTY_SCALE;
        let ask = sign_unit(
            vec![tip],
            Op::Place {
                account: bob_id,
                market: BTC_USD,
                side: Side::Ask,
                typ: OrderType::Limit,
                tif: TimeInForce::Gtc,
                price: px,
                qty,
                client_seq: 1,
            },
            &bob,
        );
        tip = unit_id(&ask);
        applied.push(tip);
        eng.ingest(ask).unwrap();

        let bid = sign_unit(
            vec![tip],
            Op::Place {
                account: alice_id,
                market: BTC_USD,
                side: Side::Bid,
                typ: OrderType::Limit,
                tif: TimeInForce::Gtc,
                price: px,
                qty,
                client_seq: 1,
            },
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
        DaUnit {
            height: batch.checkpoint.height,
            unit_hash: String::new(),
            data,
            joint: serde_json::Value::Null,
        }
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
    #[test]
    fn assemble_frames_multi_package_roundtrip() {
        use base64::Engine as _;
        use sha2::{Digest, Sha256};
        let f1 = "{\"u\":1}".to_string();
        let f2 = "{\"u\":2}".to_string();
        let b1 = base64::engine::general_purpose::STANDARD.encode(f1.as_bytes());
        let b2 = base64::engine::general_purpose::STANDARD.encode(f2.as_bytes());
        let r1 = base64::engine::general_purpose::STANDARD
            .decode(&b1)
            .unwrap();
        let r2 = base64::engine::general_purpose::STANDARD
            .decode(&b2)
            .unwrap();
        let mut concat = Vec::new();
        concat.extend_from_slice(&r1);
        concat.extend_from_slice(&r2);
        let root = hex::encode(Sha256::digest(&concat));
        let h1 = hex::encode(Sha256::digest(&r1));
        let h2 = hex::encode(Sha256::digest(&r2));
        let header = serde_json::json!({"packages": [h1, h2], "data_root": root});
        let pkg = |b: &str| {
            serde_json::json!({
                "unit": {"messages": [{"app": "temp_data", "payload": {"data": {"package_blob": b}}}], "unit": "x"},
                "messages": [{"app": "temp_data", "payload": {"data": {"package_blob": b}}}],
            })
        };
        let hub = MockHub {
            vars: Default::default(),
            joints: std::collections::HashMap::from([
                (h1.clone(), pkg(&b1)),
                (h2.clone(), pkg(&b2)),
            ]),
        };
        let got = assemble_frames(&hub, &header).unwrap();
        let raw = base64::engine::general_purpose::STANDARD
            .decode(&got)
            .unwrap();
        assert_eq!(String::from_utf8(raw).unwrap(), format!("{f1}{f2}"));
        let bad = serde_json::json!({"packages": [h1], "data_root": "00".repeat(32)});
        assert!(assemble_frames(&hub, &bad).is_err());
    }
}
