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
    let key = format!("da_unit_{height}");
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
    let recomputed = obyte_hash::get_unit_hash(&da.joint).map_err(WatchError::BindingMismatch)?;
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
/// `get_joint`, require its `package_blob` string (base64(gzip(frames))),
/// gunzip, concat the original package bytes, and check hex(sha256(concat))
/// against `data_root`. Only after that check, add a parse-only LF at package
/// boundaries that have no delimiter (legacy writers emitted none). Returns
/// base64(gzip(parse_stream)) so it splices as `frames_blob`.
/// Transport errors map to `HubUnavailable` (caller backs off); bad content
/// (bad base64, invalid gzip, root mismatch) maps to `BindingMismatch`.
/// No retries here — the poll loop owns backoff.
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
    let mut parse_stream: Vec<u8> = Vec::new();
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
        let gz = base64::engine::general_purpose::STANDARD
            .decode(b64)
            .map_err(|_| WatchError::BindingMismatch("package_blob not base64".into()))?;
        let raw = gunzip_blob(&gz)?;
        append_package_for_decode(&mut parse_stream, &raw);
        concat.extend_from_slice(&raw);
    }
    use sha2::{Digest, Sha256};
    let got = hex::encode(Sha256::digest(&concat));
    if got != want {
        return Err(WatchError::BindingMismatch(format!(
            "data_root mismatch: want {want} got {got}"
        )));
    }
    Ok(base64::engine::general_purpose::STANDARD.encode(operp_settle::gzip_bytes(&parse_stream)))
}

/// Add exactly one LF between non-empty package payloads for parsing. The
/// returned stream is not the `data_root` input: that root is always checked
/// against the untouched concatenation in `assemble_frames`.
fn append_package_for_decode(parse_stream: &mut Vec<u8>, package: &[u8]) {
    if package.is_empty() {
        return;
    }
    if parse_stream.is_empty() {
        parse_stream.extend_from_slice(package);
        return;
    }
    let previous_has_lf = parse_stream.last() == Some(&b'\n');
    let current_has_lf = package.first() == Some(&b'\n');
    if !previous_has_lf && !current_has_lf {
        parse_stream.push(b'\n');
    }
    let skip_duplicate_lf = previous_has_lf && current_has_lf;
    parse_stream.extend_from_slice(if skip_duplicate_lf {
        &package[1..]
    } else {
        package
    });
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
/// scalars plus `frames_blob` (single package, base64(gzip(frames))).
/// Multi-package (`packages`+`data_root`) arrives via `assemble_frames`
/// before this call — legacy `units`-array headers are rejected. `data_root`
/// covers original gunzipped frame bytes, not the gzip wrapper; inline roots
/// are checked here and multi-package roots are checked before normalization.
pub fn gunzip_blob(gz: &[u8]) -> Result<Vec<u8>, WatchError> {
    use flate2::read::GzDecoder;
    use std::io::Read;
    let mut dec = GzDecoder::new(gz);
    let mut out = Vec::new();
    dec.read_to_end(&mut out)
        .map_err(|_| WatchError::BindingMismatch("package_blob not gzip".into()))?;
    Ok(out)
}
pub fn batch_from_data(data: &serde_json::Value) -> Result<Batch, SettleError> {
    if data.get("units").is_some() {
        return Err(SettleError::RootMismatch);
    }
    let blob = get_str(data, "frames_blob")?;
    let raw = operp_settle::decode_package_blob(blob)?;
    if data.get("packages").is_none() {
        let want = get_str(data, "data_root")?;
        use sha2::{Digest, Sha256};
        let got = hex::encode(Sha256::digest(&raw));
        if got != want {
            return Err(SettleError::RootMismatch);
        }
    }
    let text = String::from_utf8(raw).map_err(|_| SettleError::RootMismatch)?;
    let frames: Vec<String> = text.lines().map(str::to_string).collect();
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
                .ok_or_else(|| format!("404: no joint {unit_hash}"))
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

    fn package_fixture(raw_packages: &[Vec<u8>]) -> (serde_json::Value, MockHub) {
        use base64::Engine as _;
        use sha2::{Digest, Sha256};

        let mut all_raw = Vec::new();
        let mut hashes = Vec::new();
        let mut joints = std::collections::HashMap::new();
        for raw in raw_packages {
            let hash = hex::encode(Sha256::digest(raw));
            let blob =
                base64::engine::general_purpose::STANDARD.encode(operp_settle::gzip_bytes(raw));
            let joint = serde_json::json!({
                "messages": [{
                    "app": "temp_data",
                    "payload": {"data": {"package_blob": blob}},
                }],
            });
            hashes.push(serde_json::Value::String(hash.clone()));
            joints.insert(hash, joint);
            all_raw.extend_from_slice(raw);
        }
        let root = hex::encode(Sha256::digest(&all_raw));
        (
            serde_json::json!({"packages": hashes, "data_root": root}),
            MockHub {
                vars: Default::default(),
                joints,
            },
        )
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
                isolated: false,
                margin: 0,
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
                isolated: false,
                margin: 0,
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
    fn assemble_frames_reads_legacy_boundaries_and_preserves_raw_root() {
        use base64::Engine as _;
        use sha2::{Digest, Sha256};
        let frames = [
            "{\"u\":\"one\"}",
            "{\"u\":\"two-β\"}",
            "{\"u\":\"three\"}",
            "{\"u\":\"four\"}",
        ];
        // Legacy writers separated frames inside a package but not package
        // boundaries. Both packages contain multiple frames here.
        let raw1 = format!("{}\n{}", frames[0], frames[1]).into_bytes();
        let raw2 = format!("{}\n{}", frames[2], frames[3]).into_bytes();
        let raw_concat = [raw1.clone(), raw2.clone()].concat();
        let normalized = frames.join("\n");
        let (header, hub) = package_fixture(&[raw1, raw2]);
        assert_eq!(
            header["data_root"],
            hex::encode(Sha256::digest(&raw_concat)),
            "data_root is over the unmodified package bytes"
        );
        assert_ne!(
            header["data_root"],
            hex::encode(Sha256::digest(normalized.as_bytes())),
            "parse-only inserted LF must not change the committed root"
        );

        let assembled = assemble_frames(&hub, &header).unwrap();
        let gz = base64::engine::general_purpose::STANDARD
            .decode(assembled)
            .unwrap();
        let parse_bytes = gunzip_blob(&gz).unwrap();
        assert_eq!(parse_bytes, normalized.as_bytes());
        let text = String::from_utf8(parse_bytes).unwrap();
        let decoded: Vec<_> = text.lines().collect();
        assert_eq!(decoded, frames);
        for frame in decoded {
            serde_json::from_str::<serde_json::Value>(frame).unwrap();
        }

        // A root computed over the normalized parser stream is not accepted
        // in place of the root over the original legacy package bytes.
        let mut wrong_root = header.clone();
        wrong_root["data_root"] =
            serde_json::json!(hex::encode(Sha256::digest(normalized.as_bytes())));
        assert!(assemble_frames(&hub, &wrong_root).is_err());

        // Legacy single-package data already has frame separators internally;
        // it needs no assembly-time boundary insertion.
        let one_raw = frames.join("\n").into_bytes();
        let (one_header, one_hub) = package_fixture(&[one_raw]);
        let one = assemble_frames(&one_hub, &one_header).unwrap();
        let one_gz = base64::engine::general_purpose::STANDARD
            .decode(one)
            .unwrap();
        assert_eq!(gunzip_blob(&one_gz).unwrap(), normalized.as_bytes());

        // A previously proposed trailing-LF package shape also remains
        // readable by the new consumer, including its final frame.
        let trailing_raws = vec![
            format!("{}\n", frames[0]).into_bytes(),
            format!("{}\n{}\n", frames[1], frames[2]).into_bytes(),
        ];
        let (trailing_header, trailing_hub) = package_fixture(&trailing_raws);
        let trailing = assemble_frames(&trailing_hub, &trailing_header).unwrap();
        let trailing_gz = base64::engine::general_purpose::STANDARD
            .decode(trailing)
            .unwrap();
        let trailing_text = String::from_utf8(gunzip_blob(&trailing_gz).unwrap()).unwrap();
        assert_eq!(trailing_text.lines().collect::<Vec<_>>(), &frames[..3]);

        let bad = serde_json::json!({"packages": header["packages"].clone(), "data_root": "00".repeat(32)});
        assert!(assemble_frames(&hub, &bad).is_err());
        // Invalid gzip maps to BindingMismatch, not HubUnavailable.
        let not_gz = base64::engine::general_purpose::STANDARD.encode(b"not-gzip");
        let hub2 = MockHub {
            vars: Default::default(),
            joints: std::collections::HashMap::from([(
                header["packages"][0].as_str().unwrap().to_string(),
                serde_json::json!({"messages": [{"app": "temp_data", "payload": {"data": {"package_blob": not_gz}}}]}),
            )]),
        };
        let hdr2 = serde_json::json!({"packages": [header["packages"][0].clone()], "data_root": header["data_root"].clone()});
        assert!(matches!(
            assemble_frames(&hub2, &hdr2),
            Err(WatchError::BindingMismatch(_))
        ));
    }

    #[test]
    fn legacy_and_new_package_formats_rebuild_a_complete_real_batch() {
        use base64::Engine as _;
        use sha2::{Digest, Sha256};

        let da = build_batch_da(false);
        let expected = batch_from_data(&da.data).unwrap();
        let original = da.data["frames_blob"].as_str().unwrap();
        let original_raw = operp_settle::decode_package_blob(original).unwrap();
        let text = String::from_utf8(original_raw).unwrap();
        let frames: Vec<String> = text.lines().map(str::to_string).collect();
        assert!(frames.len() >= 2, "fixture needs multiple frames");

        // Legacy single package: no terminal LF; root covers exact gunzipped bytes.
        let legacy_single_raw = frames.join("\n").into_bytes();
        let mut legacy_single = da.data.clone();
        legacy_single["frames_blob"] = serde_json::json!(base64::engine::general_purpose::STANDARD
            .encode(operp_settle::gzip_bytes(&legacy_single_raw)));
        legacy_single["data_root"] =
            serde_json::json!(hex::encode(Sha256::digest(&legacy_single_raw)));
        assert_eq!(batch_from_data(&legacy_single).unwrap(), expected);
        let mut tampered_single = legacy_single.clone();
        tampered_single["data_root"] = serde_json::json!("00".repeat(32));
        assert!(batch_from_data(&tampered_single).is_err());

        // Legacy multi-package: no package delimiter is inserted by the old
        // writer. The new assembler verifies this raw root before parse repair.
        let split = frames.len() / 2;
        let legacy_raws = vec![
            frames[..split].join("\n").into_bytes(),
            frames[split..].join("\n").into_bytes(),
        ];
        let (legacy_package_header, legacy_hub) = package_fixture(&legacy_raws);
        let mut legacy_multi = da.data.clone();
        legacy_multi.as_object_mut().unwrap().remove("frames_blob");
        legacy_multi["packages"] = legacy_package_header["packages"].clone();
        legacy_multi["data_root"] = legacy_package_header["data_root"].clone();
        legacy_multi["frames_blob"] =
            serde_json::json!(assemble_frames(&legacy_hub, &legacy_multi).unwrap());
        assert_eq!(batch_from_data(&legacy_multi).unwrap(), expected);

        // Current producer: first package has no prefix, each later package
        // starts with LF, and the full wire stream has no terminal LF. Simulate
        // the pre-PR watcher's split('\n') logic to prove rollback compatibility.
        let new_blobs = operp_settle::pack_frames_with_cap(&frames, 1);
        assert_eq!(new_blobs.len(), frames.len());
        let new_raws: Vec<_> = new_blobs
            .iter()
            .map(|b| operp_settle::decode_package_blob(b).unwrap())
            .collect();
        let new_wire_raw: Vec<u8> = new_raws.iter().flatten().copied().collect();
        assert_eq!(new_wire_raw, frames.join("\n").as_bytes());
        assert_ne!(new_wire_raw.last(), Some(&b'\n'));
        let old_reader_text = String::from_utf8(new_wire_raw.clone()).unwrap();
        let old_reader_frames: Vec<String> =
            old_reader_text.split('\n').map(str::to_string).collect();
        assert_eq!(old_reader_frames, frames);
        assert_eq!(
            operp_settle::batch_from_frames(&da.data, &old_reader_frames).unwrap(),
            expected,
            "new producer output remains readable by the old watcher decoder"
        );

        let (new_package_header, new_hub) = package_fixture(&new_raws);
        let mut new_multi = da.data.clone();
        new_multi.as_object_mut().unwrap().remove("frames_blob");
        new_multi["packages"] = new_package_header["packages"].clone();
        new_multi["data_root"] = new_package_header["data_root"].clone();
        new_multi["frames_blob"] =
            serde_json::json!(assemble_frames(&new_hub, &new_multi).unwrap());
        assert_eq!(batch_from_data(&new_multi).unwrap(), expected);

        // Empty payloads are not batches; malformed UTF-8 is rejected before
        // JSON frame parsing, without relaxing the UTF-8 wire contract.
        let mut empty = da.data.clone();
        let empty_raw: &[u8] = b"";
        empty["frames_blob"] =
            serde_json::json!(base64::engine::general_purpose::STANDARD
                .encode(operp_settle::gzip_bytes(empty_raw)));
        empty["data_root"] = serde_json::json!(hex::encode(Sha256::digest(empty_raw)));
        assert!(batch_from_data(&empty).is_err());
        let invalid_utf8 = [0xff, 0xfe];
        let mut invalid = da.data.clone();
        invalid["frames_blob"] = serde_json::json!(base64::engine::general_purpose::STANDARD
            .encode(operp_settle::gzip_bytes(&invalid_utf8)));
        invalid["data_root"] = serde_json::json!(hex::encode(Sha256::digest(invalid_utf8)));
        assert!(matches!(
            batch_from_data(&invalid),
            Err(SettleError::RootMismatch)
        ));
    }
}
