use operp_book::Fill;
use operp_dag::Unit;
use operp_exec::Engine;
use operp_state::{verify_proof, MerkleProof};
use operp_types::{
    sha256, AccountId, Height, Seq, UnitId, Usd, ASSERTION_VERSION, BATCH_MAX_UNITS, CHAIN_ID,
    PERP_ASSET, VAULT_AA_ADDRESS,
};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

pub mod deposit_verify;
pub mod obyte_hash;
pub use operp_state::obyte_merkle;
/// Test-only vault payee: matches the `payment_joint` fixture payee
/// ("B"*32) so evidence fixtures verify without env manipulation
/// (env mutation is process-global and unsafe under parallel tests).
#[cfg(test)]
pub const TEST_VAULT_ADDRESS: &str = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
/// Expected vault AA payee for deposit evidences. Env `OPERP_VAULT_AA`
/// wins (operator-set at deploy); else the baked `VAULT_AA_ADDRESS` when
/// non-empty; else "" (pre-deploy: batches without evidences skip the
/// check, batches carrying evidences are rejected). Tests fall back to
/// `TEST_VAULT_ADDRESS` instead of "" so fixtures stay deterministic.
pub fn expected_vault() -> String {
    if let Ok(v) = std::env::var("OPERP_VAULT_AA") {
        if !v.is_empty() {
            return v;
        }
    }
    if !VAULT_AA_ADDRESS.is_empty() {
        return VAULT_AA_ADDRESS.to_string();
    }
    #[cfg(test)]
    {
        return TEST_VAULT_ADDRESS.to_string();
    }
    #[cfg(not(test))]
    {
        String::new()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DepositEvidence {
    /// Hex 64 — must equal unit_hash(joint).
    pub aa_unit: String,
    /// false = base deposit, true = PERP deposit. Must match Op kind.
    pub is_perp: bool,
    /// Decimal string as it appears in vault ledger.
    pub amount: String,
    /// Obyte vault AA address that must be the payee.
    pub vault_address: String,
    /// Full Obyte joint as returned by hub getJoint (unit + messages + authors).
    pub joint: serde_json::Value,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Checkpoint {
    pub height: Height,
    pub prev_state_hash: [u8; 32],
    pub state_root: [u8; 32],
    /// 16 per-shard hex-domain merkle roots (Phase 5.2): the operator
    /// concatenates them into the on-chain `aa_forest`; `aa_root` below is
    /// the 64-hex forest hash over that concatenation. Withdrawal proofs
    /// verify within one shard's tree (see operp_state::aa_shard_of).
    pub aa_shard_roots: [String; operp_state::AA_SHARD_COUNT],
    /// 64-hex forest hash: sha256 over the concatenated `aa_shard_roots`.
    pub aa_root: String,
    pub last_unit: UnitId,
    pub seq: Seq,
    pub unit_ids: Vec<UnitId>,
    pub fills_hash: [u8; 32],
    pub fill_count: u32,
    /// Dispute-predicate commitment (rollup v2): always ASSERTION_VERSION.
    pub assertion_version: u32,
    /// Witness root after the last unit (44-char base64, Obyte-merkle domain).
    pub wit_root: String,
    /// Merkle roots over per-unit descriptor strings in batch order
    /// (44-char base64 each): trace = post-unit wit roots, units = unit-id
    /// hex, units_set = same ids sorted, ops = op descriptors, fills = fill
    /// descriptors in execution order.
    pub trace_root: String,
    pub units_root: String,
    pub units_set_root: String,
    pub ops_root: String,
    pub fills_root: String,
    /// Merkle root over per-unit witness-leaf counts (decimal strings, batch
    /// order): makes intermediate pre-tree sizes provable for non-membership.
    pub counts_root: String,
    /// Number of units in the batch (== unit_ids.len()).
    pub unit_count: u32,
    /// Number of witness leaves committed by wit_root (bounds non-membership).
    pub wit_count: u32,
    /// Optional 64-hex validity proof hash (sha256 of validate_against trace).
    /// None on legacy batches; Some(64 hex) when fraud-provable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub validity_proof_hash: Option<String>,
    /// Optional perp burned total audit field (mirrors ChainState.perp_burned).
    /// On the wire (temp_data JSON) it is a decimal string, not a number.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub perp_burned: Option<u128>,
}

/// Max canonical source bytes for one `{"package_blob":...}` temp_data
/// object (OIP-0007 envelope). Must stay comfortably below Obyte's ~5MB
/// unit ceiling; the 10k-node wall is closed by base64 frames, this cap is
/// the remaining DA bound (plus the 24h temp_data purge).
pub const PACK_SOURCE_CAP: usize = 4_000_000;
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Batch {
    pub chain_id: String,
    pub checkpoint: Checkpoint,
    pub units: Vec<Unit>,
    #[allow(dead_code)]
    pub deposit_evidences: Vec<DepositEvidence>,
    /// DA arrays for watchers (AA stores only the roots): per-unit wit roots
    /// in batch order, op descriptors in batch order, fill descriptors in
    /// execution order.
    pub trace: Vec<String>,
    pub ops: Vec<String>,
    pub fills: Vec<String>,
    /// Per-unit fill descriptors in batch order. `fills` stays the
    /// concatenation of these in order — never hand-fill `fills`.
    pub fills_per_unit: Vec<Vec<String>>,
    /// Per-unit witness-leaf counts in batch order (DA for counts_root).
    pub counts: Vec<String>,
    /// Per-unit full witness leaf sets in batch order (DA for watcher
    /// proof building). Empty on oversize batches (>4MB serialized source).
    /// `validate_against` checks each entry against the replay when present.
    pub leaf_trace: Vec<Vec<String>>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TempDataPayload {
    pub data_length: u64,
    /// Obyte-canonical hex hash: sha256 of getJsonSource(data) (Phase 4.1).
    pub data_hash: String,
    pub data: serde_json::Value,
}

#[derive(Clone, Debug)]
pub struct PostedBatch {
    pub batch: Batch,
    pub obyte_unit: [u8; 32],
    pub mci: Option<u64>,
    pub stable: bool,
}

#[derive(Clone, Debug)]
pub struct WithdrawClaim {
    pub account: AccountId,
    pub amount: Usd,
    /// PERP withdrawal amount; 0 = collateral-only claim.
    pub perp: u128,
    pub proof: MerkleProof,
}

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum SettleError {
    #[error("empty batch")]
    Empty,
    #[error("too many units")]
    TooManyUnits,
    #[error("chain id mismatch")]
    ChainMismatch,
    #[error("prev root mismatch")]
    PrevMismatch,
    #[error("state root mismatch")]
    RootMismatch,
    #[error("replay failed")]
    Replay,
    #[error("fills mismatch")]
    FillsMismatch,
    #[error("bad merkle")]
    BadMerkle,
    #[error("amount exceeds collateral")]
    AmountExceedsCollateral,
    #[error("perp exceeds proof")]
    AmountExceedsPerp,
    #[error("deposit anchor missing")]
    DepositAnchorMissing,
    #[error("deposit content mismatch")]
    DepositContentMismatch,
    #[error("deposit kind mismatch")]
    DepositKindMismatch,
    #[error("deposit evidence invalid")]
    DepositEvidence,
    #[error("deposit duplicate anchor")]
    DepositDuplicateAnchor,
    #[error("deposit evidence too large")]
    DepositEvidenceTooLarge,
    #[error("gov wal flush failed")]
    WalFlush,
}

/// Canonical byte encoding of fills shared by batch construction and replay
/// verification. Order: taker_id || maker_id || price_le || qty_le || seq_le.
pub fn fills_bytes(fills: &[Fill]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(fills.len() * (32 + 32 + 8 + 8 + 8));
    for f in fills {
        buf.extend_from_slice(&f.taker_id.0);
        buf.extend_from_slice(&f.maker_id.0);
        buf.extend_from_slice(&f.price.to_le_bytes());
        buf.extend_from_slice(&f.qty.to_le_bytes());
        buf.extend_from_slice(&f.seq.to_le_bytes());
    }
    buf
}
/// Op-descriptor string committed by `ops_root` (dispute predicates parse
/// these; `unit_hex` covers non-financial ops verbatim).
pub fn ops_element(unit_hex: &str, op: &operp_dag::Op) -> String {
    use operp_dag::Op::*;
    match op {
        Deposit {
            account, amount, ..
        } => {
            format!("d:{}:{}", hex::encode(account.0), amount)
        }
        GovDeposit {
            account, amount, ..
        } => {
            format!("D:{}:{}", hex::encode(account.0), amount)
        }
        Withdraw {
            account,
            amount,
            nonce,
        } => {
            format!("w:{}:{}:{}", hex::encode(account.0), amount, nonce)
        }
        GovWithdraw {
            account,
            amount,
            nonce,
        } => {
            format!("W:{}:{}:{}", hex::encode(account.0), amount, nonce)
        }
        Place {
            account,
            market,
            side,
            price,
            qty,
            ..
        } => {
            format!(
                "p:{}:{}:{}:{}:{}",
                hex::encode(account.0),
                market.0,
                side.as_u8(),
                price,
                qty
            )
        }
        Cancel { account, order_id } => {
            format!("c:{}:{}", hex::encode(account.0), hex::encode(order_id.0))
        }
        Liquidate {
            caller,
            target,
            market,
        } => {
            format!(
                "L:{}:{}:{}",
                hex::encode(caller.0),
                hex::encode(target.0),
                market.0
            )
        }
        _ => format!("x:{}", unit_hex),
    }
}
/// Fill-descriptor string committed by `fills_root`. `fill_index_in_unit`
/// starts at 0 per unit.
pub fn fills_element(unit_hex: &str, fill_index_in_unit: usize, fill: &Fill) -> String {
    format!(
        "f:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}",
        unit_hex,
        fill_index_in_unit,
        hex::encode(fill.taker.0),
        hex::encode(fill.maker.0),
        hex::encode(fill.taker_id.0),
        hex::encode(fill.maker_id.0),
        fill.market.0,
        fill.price,
        fill.qty,
        fill.seq,
        fill.taker_side.as_u8()
    )
}

impl Batch {
    pub fn from_applied(
        prev: &operp_state::ChainState,
        engine: &mut Engine,
        applied: &[UnitId],
    ) -> Result<Self, SettleError> {
        if applied.is_empty() {
            return Err(SettleError::Empty);
        }
        if applied.len() > BATCH_MAX_UNITS as usize {
            return Err(SettleError::TooManyUnits);
        }
        let mut units = Vec::with_capacity(applied.len());
        for id in applied {
            let u = engine.dag.get(*id).cloned().ok_or(SettleError::Replay)?;
            units.push(u);
        }
        let applied_set: HashSet<&UnitId> = applied.iter().collect();
        let mut fills_buf = Vec::new();
        let mut fill_count = 0u32;
        let mut per_unit_map: std::collections::HashMap<UnitId, Vec<String>> =
            std::collections::HashMap::new();
        let mut per_unit_counts: std::collections::HashMap<UnitId, usize> =
            std::collections::HashMap::new();
        for ev in &engine.log {
            if let operp_exec::ExecEvent::Applied { unit, fills, .. } = ev {
                if applied_set.contains(unit) {
                    fill_count += fills.len() as u32;
                    fills_buf.extend_from_slice(&fills_bytes(fills));
                    let unit_hex = hex::encode(unit.0);
                    let entry = per_unit_map.entry(*unit).or_default();
                    for f in fills {
                        let idx = per_unit_counts.entry(*unit).or_insert(0);
                        entry.push(fills_element(&unit_hex, *idx, f));
                        *idx += 1;
                    }
                }
            }
        }
        let mut fills_per_unit: Vec<Vec<String>> = Vec::with_capacity(applied.len());
        let mut fill_elements: Vec<String> = Vec::new();
        for id in applied {
            let v = per_unit_map.remove(id).unwrap_or_default();
            fill_elements.extend(v.iter().cloned());
            fills_per_unit.push(v);
        }
        let fills_hash = sha256(&fills_buf);
        if engine.wit_trace.len() < applied.len() || engine.wit_count_trace.len() < applied.len() {
            return Err(SettleError::Replay);
        }
        let trace: Vec<String> =
            engine.wit_trace[engine.wit_trace.len() - applied.len()..].to_vec();
        let wit_root = trace.last().cloned().ok_or(SettleError::Replay)?;
        let counts: Vec<String> = engine.wit_count_trace
            [engine.wit_count_trace.len() - applied.len()..]
            .iter()
            .map(|n| n.to_string())
            .collect();
        let unit_hexes: Vec<String> = applied.iter().map(|id| hex::encode(id.0)).collect();
        let mut units_set_sorted = unit_hexes.clone();
        units_set_sorted.sort();
        let ops: Vec<String> = units
            .iter()
            .zip(unit_hexes.iter())
            .map(|(u, h)| ops_element(h, &u.op))
            .collect();
        let wit_leaves = operp_state::wit_leaves(&engine.state);
        let trace_root = obyte_merkle::root(&trace);
        let units_root = obyte_merkle::root(&unit_hexes);
        let units_set_root = obyte_merkle::root(&units_set_sorted);
        let ops_root = obyte_merkle::root(&ops);
        let fills_root = obyte_merkle::root(&fill_elements);
        let counts_root = obyte_merkle::root(&counts);
        // Height binding: adopt the next height BEFORE hashing state, so
        // meta_leaf commits the batch height and the checkpoint root is only
        // reproducible by a replay that lands on that same height
        // (validate_against enforces exactly that).
        engine.state.height = prev.height + 1;
        let height = engine.state.height;
        // Batch-commit ledger hygiene: withdrawal entries and AA-unit dedup
        // marks only need to block replay across the challenge window
        // (256 legacy, 2048 post-activation); older entries are dropped.
        engine.state.prune_withdrawals(height);
        engine.state.prune_aa_units(height);
        engine.state.prune_deposits_allowed(height);
        engine.state.prune_commits(height);
        // H2: gov-nonce WAL hits disk exactly here, at batch commit — not at
        // ingest. If the batch is abandoned, the buffered nonces are dropped
        // with it (nothing burned on uncommitted batches).
        engine.flush_gov_wal().map_err(|_| SettleError::WalFlush)?;
        // gap 11: persistence hooks fire on the production commit path only
        // (replay validators run store-less engines, where both are no-ops).
        // Best-effort per the design's failure-mode table: a failed snapshot
        // write keeps the in-memory state authoritative and is retried at
        // the next cadence window; journal compaction is likewise non-fatal
        // (the WAL itself is fsynced synchronously inside gov_withdraw).
        let _ = engine.maybe_flush_snapshot();
        let _ = engine.compact_journal_if_needed();
        let last_unit = *applied.last().unwrap();
        let aa_shard_roots = operp_state::aa_sharded_roots_of_state(&engine.state);
        Ok(Self {
            chain_id: CHAIN_ID.to_string(),
            checkpoint: Checkpoint {
                height,
                prev_state_hash: prev.state_root(),
                state_root: engine.state.state_root(),
                aa_root: operp_state::aa_forest_hash(&aa_shard_roots),
                last_unit,
                seq: engine.state.seq,
                unit_ids: applied.to_vec(),
                aa_shard_roots,
                fills_hash,
                fill_count,
                assertion_version: ASSERTION_VERSION,
                wit_root,
                trace_root,
                units_root,
                units_set_root,
                ops_root,
                fills_root,
                counts_root,
                unit_count: applied.len() as u32,
                wit_count: wit_leaves.len() as u32,
                validity_proof_hash: None,
                perp_burned: Some(engine.state.perp_burned),
            },
            units,
            deposit_evidences: Vec::new(),
            trace,
            ops,
            fills: fill_elements,
            fills_per_unit,
            counts,
            leaf_trace: engine.wit_leaf_trace[engine.wit_leaf_trace.len() - applied.len()..]
                .to_vec(),
        })
    }
    pub fn temp_data_payload(&self) -> TempDataPayload {
        let (data, _) = self
            .temp_data_packages()
            .expect("batch must pack within PACK_SOURCE_CAP");
        // Canonical Obyte form (Phase 4.1): data_hash = hex(sha256(getJsonSource(data))),
        // data_length = UTF-8 byte length of that source — same contract as
        // obyte-local/post_batch.js `obyteDataHash`.
        let source = crate::obyte_hash::get_json_source(&data);
        let hash = crate::obyte_hash::get_data_hash(&data);
        TempDataPayload {
            data_length: source.len() as u64,
            data_hash: hex::encode(hash),
            data,
        }
    }
    /// One JSON string per applied unit: `{"u":unit,"t":trace,"o":ops,
    /// "c":counts,"f"?:fills,"l"?:leaves,"e"?:evidence}`. Omit `f` when the
    /// unit has no fills; include `e` iff Deposit/GovDeposit with a matching
    /// evidence by `aa_unit`; omit `l` iff that unit's leaf-trace entry is
    /// empty.
    pub fn frames(&self) -> Vec<String> {
        let mut evidence_by_anchor: HashMap<String, &DepositEvidence> = HashMap::new();
        for ev in &self.deposit_evidences {
            evidence_by_anchor.insert(ev.aa_unit.to_lowercase(), ev);
        }
        let mut out = Vec::with_capacity(self.units.len());
        for (k, u) in self.units.iter().enumerate() {
            let unit_json = serde_json::json!({
                "parents": u.parents.iter().map(|p| hex::encode(p.0)).collect::<Vec<_>>(),
                "op": serde_json::to_value(&u.op).unwrap(),
                "pubkey": hex::encode(u.pubkey),
                "sig": hex::encode(u.sig),
            });
            let mut frame = serde_json::Map::new();
            frame.insert("u".to_string(), unit_json);
            if let Some(t) = self.trace.get(k) {
                frame.insert("t".to_string(), serde_json::Value::String(t.clone()));
            }
            if let Some(o) = self.ops.get(k) {
                frame.insert("o".to_string(), serde_json::Value::String(o.clone()));
            }
            if let Some(c) = self.counts.get(k) {
                frame.insert("c".to_string(), serde_json::Value::String(c.clone()));
            }
            if let Some(f) = self.fills_per_unit.get(k) {
                if !f.is_empty() {
                    frame.insert("f".to_string(), serde_json::to_value(f).unwrap());
                }
            }
            if let Some(l) = self.leaf_trace.get(k) {
                if !l.is_empty() {
                    frame.insert("l".to_string(), serde_json::to_value(l).unwrap());
                }
            }
            let anchor: Option<[u8; 32]> = match &u.op {
                operp_dag::Op::Deposit { aa_unit, .. } => Some(*aa_unit),
                operp_dag::Op::GovDeposit { aa_unit, .. } => Some(*aa_unit),
                _ => None,
            };
            if let Some(a) = anchor {
                if let Some(ev) = evidence_by_anchor.get(&hex::encode(a).to_lowercase()) {
                    frame.insert("e".to_string(), serde_json::to_value(ev).unwrap());
                }
            }
            out.push(serde_json::to_string(&frame).unwrap());
        }
        out
    }
    /// Header scalars for the new wire: per-unit arrays are gone, only
    /// unchanged scalars plus blob/package pointers.
    pub fn header_json(&self) -> serde_json::Value {
        let mut data = serde_json::json!({
            "chain_id": self.chain_id,
            "height": self.checkpoint.height,
            "prev_state_hash": hex::encode(self.checkpoint.prev_state_hash),
            "state_root": hex::encode(self.checkpoint.state_root),
            "aa_root": self.checkpoint.aa_root,
            "aa_shard_roots": self.checkpoint.aa_shard_roots,
            "last_unit": hex::encode(self.checkpoint.last_unit.0),
            "seq": self.checkpoint.seq,
            "fill_count": self.checkpoint.fill_count,
            "fills_hash": hex::encode(self.checkpoint.fills_hash),
            "assertion_version": self.checkpoint.assertion_version,
            "wit_root": self.checkpoint.wit_root,
            "trace_root": self.checkpoint.trace_root,
            "units_root": self.checkpoint.units_root,
            "units_set_root": self.checkpoint.units_set_root,
            "unit_count": self.checkpoint.unit_count,
            "wit_count": self.checkpoint.wit_count,
            "ops_root": self.checkpoint.ops_root,
            "fills_root": self.checkpoint.fills_root,
            "counts_root": self.checkpoint.counts_root,
        });
        if let Some(v) = &self.checkpoint.validity_proof_hash {
            data["validity_proof_hash"] = serde_json::Value::String(v.clone());
        }
        if let Some(v) = self.checkpoint.perp_burned {
            data["perp_burned"] = serde_json::json!(v.to_string());
        }
        data
    }
    /// Frames → packages → header+blobs. Single-package callers inline
    /// `frames_blob`; multi-package headers list the package **unit hashes**
    /// (filled by the poster after posting each package unit — Rust cannot
    /// know them), so watchers can `get_joint` each entry. Here `packages`
    /// is an empty placeholder array of the right length; the poster
    /// replaces it with real unit hashes before submitting the header.
    pub fn temp_data_packages(&self) -> Result<(serde_json::Value, Vec<String>), SettleError> {
        let frames = self.frames();
        let mut blobs = pack_frames(&frames);
        let over = blobs.iter().any(|b| {
            let obj = serde_json::json!({"package_blob": b});
            crate::obyte_hash::get_json_source(&obj).len() > PACK_SOURCE_CAP
        });
        if over {
            let stripped: Vec<String> = frames
                .iter()
                .map(|f| {
                    let mut v: serde_json::Value =
                        serde_json::from_str(f).unwrap_or(serde_json::Value::Null);
                    if let Some(m) = v.as_object_mut() {
                        m.remove("l");
                    }
                    serde_json::to_string(&v).unwrap()
                })
                .collect();
            blobs = pack_frames(&stripped);
            // Still over cap with all leaves stripped: print-only. The
            // oversize package cannot land on-chain (ocore rejects it), so
            // the header's packages can never assemble — watchers back off
            // on the missing joints instead of mis-challenging. Return the
            // data as-is rather than erroring (same posture as the legacy
            // 4MB leaf_trace cap).
        }
        let raw: Vec<Vec<u8>> = blobs
            .iter()
            .map(|b| decode_package_blob(b).unwrap_or_default())
            .collect();
        let root = data_root_hex(&raw);
        let mut header = self.header_json();
        if blobs.len() == 1 {
            header["frames_blob"] = serde_json::Value::String(blobs[0].clone());
            header["data_root"] = serde_json::Value::String(root);
        } else {
            header["packages"] = serde_json::to_value(&vec![String::new(); blobs.len()]).unwrap();
            header["data_root"] = serde_json::Value::String(root);
        }
        Ok((header, blobs))
    }
    pub fn validate_against(
        &self,
        prev_root: [u8; 32],
        replay: &mut Engine,
    ) -> Result<(), SettleError> {
        if self.units.is_empty() {
            return Err(SettleError::Empty);
        }
        // H2: validation replays must never write gov nonces to the WAL —
        // only the committing engine (`from_applied`) persists them.
        replay.validating = true;
        if replay.state.state_root() != prev_root {
            return Err(SettleError::PrevMismatch);
        }
        if self.units.iter().any(|u| {
            matches!(
                u.op,
                operp_dag::Op::Deposit { .. } | operp_dag::Op::GovDeposit { .. }
            )
        }) {
            // H2: deposit anchors are no longer self-attested — every batch
            // carrying Deposit/GovDeposit ops must present independently
            // verifiable evidence (joint pays the vault the claimed amount
            // in the claimed asset). Any failure maps to DepositEvidence.
            // Pre-deploy (empty expected vault) evidence checks skip when
            // there are no evidences; evidences against an empty vault
            // string are rejected.
            let vault = expected_vault();
            if vault.is_empty() && !self.deposit_evidences.is_empty() {
                return Err(SettleError::DepositEvidence);
            }
            deposit_verify::verify_all(&self.units, &self.deposit_evidences, &vault, &PERP_ASSET)
                .map_err(|_| SettleError::DepositEvidence)?;
        }
        for u in &self.units {
            match &u.op {
                operp_dag::Op::Deposit { aa_unit, .. } => {
                    replay.state.deposits_allowed.insert((*aa_unit, false));
                }
                // PERP deposits are backed by the same on-chain AA feed; the
                // bool kind keeps a collateral endorsement from crediting
                // PERP (and vice versa).
                operp_dag::Op::GovDeposit { aa_unit, .. } => {
                    replay.state.deposits_allowed.insert((*aa_unit, true));
                }
                _ => {}
            }
        }
        let pre_len = replay.log.len();
        for u in &self.units {
            replay.ingest(u.clone()).map_err(|_| SettleError::Replay)?;
        }
        // Fill integrity: recompute hash/count/descriptors from replay events.
        let applied_set: HashSet<&UnitId> = self.checkpoint.unit_ids.iter().collect();
        let mut fills_buf = Vec::new();
        let mut fill_count = 0u32;
        let mut fill_elements: Vec<String> = Vec::new();
        let mut per_unit_counts: std::collections::HashMap<UnitId, usize> =
            std::collections::HashMap::new();
        for ev in replay.log.iter().skip(pre_len) {
            if let operp_exec::ExecEvent::Applied { unit, fills, .. } = ev {
                if applied_set.contains(unit) {
                    fill_count += fills.len() as u32;
                    fills_buf.extend_from_slice(&fills_bytes(fills));
                    let unit_hex = hex::encode(unit.0);
                    for f in fills {
                        let idx = per_unit_counts.entry(*unit).or_insert(0);
                        fill_elements.push(fills_element(&unit_hex, *idx, f));
                        *idx += 1;
                    }
                }
            }
        }
        if sha256(&fills_buf) != self.checkpoint.fills_hash
            || fill_count != self.checkpoint.fill_count
        {
            return Err(SettleError::FillsMismatch);
        }
        // Assertion commitment: version gate plus descriptor roots recomputed
        // from the replay (trace from the replay wit_trace, ops/units from
        // the batch units, fills from the replay events above).
        if self.checkpoint.assertion_version != ASSERTION_VERSION {
            return Err(SettleError::RootMismatch);
        }
        if replay.wit_trace.len() < self.units.len()
            || replay.wit_count_trace.len() < self.units.len()
        {
            return Err(SettleError::Replay);
        }
        let replay_trace: Vec<String> =
            replay.wit_trace[replay.wit_trace.len() - self.units.len()..].to_vec();
        let replay_counts: Vec<String> = replay.wit_count_trace
            [replay.wit_count_trace.len() - self.units.len()..]
            .iter()
            .map(|n| n.to_string())
            .collect();
        let unit_hexes: Vec<String> = self
            .checkpoint
            .unit_ids
            .iter()
            .map(|id| hex::encode(id.0))
            .collect();
        let mut units_set_sorted = unit_hexes.clone();
        units_set_sorted.sort();
        let replay_ops: Vec<String> = self
            .units
            .iter()
            .zip(unit_hexes.iter())
            .map(|(u, h)| ops_element(h, &u.op))
            .collect();
        if obyte_merkle::root(&replay_trace) != self.checkpoint.trace_root
            || obyte_merkle::root(&unit_hexes) != self.checkpoint.units_root
            || obyte_merkle::root(&units_set_sorted) != self.checkpoint.units_set_root
            || obyte_merkle::root(&replay_ops) != self.checkpoint.ops_root
            || obyte_merkle::root(&fill_elements) != self.checkpoint.fills_root
            || obyte_merkle::root(&replay_counts) != self.checkpoint.counts_root
        {
            return Err(SettleError::RootMismatch);
        }
        if replay_trace.last().cloned().unwrap_or_default() != self.checkpoint.wit_root {
            return Err(SettleError::RootMismatch);
        }
        if self.checkpoint.unit_count as usize != self.units.len()
            || self.checkpoint.unit_count as usize != self.checkpoint.unit_ids.len()
        {
            return Err(SettleError::RootMismatch);
        }
        // Height + last-unit binding: the replay must land exactly one block
        // below the claimed checkpoint height and end on the same last unit;
        // then it adopts the checkpoint height so meta_leaf — which commits
        // state.height — can match the producer's root.
        if self.checkpoint.height != replay.state.height + 1 {
            return Err(SettleError::RootMismatch);
        }
        replay.state.height = self.checkpoint.height;
        // M3: prune the replay state exactly like `from_applied` does before
        // hashing (same window, same min_height = adopted height), so a
        // replayed state and a produced state carry identical withdrawals /
        // seen_aa_units / deposits_allowed windows.
        replay.state.prune_withdrawals(replay.state.height);
        replay.state.prune_aa_units(replay.state.height);
        replay.state.prune_deposits_allowed(replay.state.height);
        replay.state.prune_commits(replay.state.height);
        if self.checkpoint.last_unit != replay.state.last_unit {
            return Err(SettleError::RootMismatch);
        }
        // Sharded forest check (Phase 5.2): the replay must reproduce all
        // 16 shard roots exactly, and the committed aa_root must be the
        // forest hash over them — catches W divergence (ScoutDeposit) and
        // any per-shard leaf tampering before state_root is compared.
        let replay_shards = operp_state::aa_sharded_roots_of_state(&replay.state);
        if replay_shards != self.checkpoint.aa_shard_roots
            || operp_state::aa_forest_hash(&replay_shards) != self.checkpoint.aa_root
        {
            return Err(SettleError::RootMismatch);
        }
        if replay.state.state_root() != self.checkpoint.state_root {
            return Err(SettleError::RootMismatch);
        }
        // Witness arbor: leaf count matches, and the DA arrays carried for
        // watchers hash back to the committed roots.
        if operp_state::wit_leaves(&replay.state).len() as u32 != self.checkpoint.wit_count
            || obyte_merkle::root(&self.trace) != self.checkpoint.trace_root
            || obyte_merkle::root(&self.ops) != self.checkpoint.ops_root
            || obyte_merkle::root(&self.fills) != self.checkpoint.fills_root
            || obyte_merkle::root(&self.counts) != self.checkpoint.counts_root
        {
            return Err(SettleError::RootMismatch);
        }
        // `leaf_trace` (watcher DA): when present, each entry must equal the
        // replayed witness leaves after that unit — catches a liar post leaf
        // set before the watcher builds a predicate on it.
        if !self.leaf_trace.is_empty() {
            if self.leaf_trace.len() != self.units.len() {
                return Err(SettleError::RootMismatch);
            }
            let base = replay.wit_leaf_trace.len() - self.units.len();
            for (i, leaves) in self.leaf_trace.iter().enumerate() {
                if *leaves != replay.wit_leaf_trace[base + i] {
                    return Err(SettleError::RootMismatch);
                }
            }
        }
        Ok(())
    }
}

/// Recover deposit evidences from a posted `TempDataPayload.data` value.
/// The watcher replay path calls this before `Batch::validate_against` so
/// batches rebuilt from temp_data carry the same evidence set the operator
/// posted. Absent key → empty vec (legacy batches without deposits).
pub fn evidences_from_payload(
    data: &serde_json::Value,
) -> Result<Vec<DepositEvidence>, SettleError> {
    match data.get("deposit_evidences") {
        None | Some(serde_json::Value::Null) => Ok(Vec::new()),
        Some(v) => {
            serde_json::from_value(v.clone()).map_err(|_| SettleError::DepositContentMismatch)
        }
    }
}
/// Greedy pack: each package = base64(gzip(`\n`-joined frames)) with
/// `get_json_source({"package_blob": b64}).len() <= cap`. `data_root` hashes
/// the gunzipped concatenated frame bytes (content, not the gzip wrapper)
/// so JS `zlib.gunzipSync` + concat + sha256 matches.
pub fn gzip_bytes(raw: &[u8]) -> Vec<u8> {
    use flate2::{write::GzEncoder, Compression};
    use std::io::Write;
    let mut enc = GzEncoder::new(Vec::new(), Compression::default());
    enc.write_all(raw).expect("gzip encode");
    enc.finish().expect("gzip finish")
}
pub fn gunzip_bytes(gz: &[u8]) -> Result<Vec<u8>, SettleError> {
    use flate2::read::GzDecoder;
    use std::io::Read;
    let mut dec = GzDecoder::new(gz);
    let mut out = Vec::new();
    dec.read_to_end(&mut out)
        .map_err(|_| SettleError::RootMismatch)?;
    Ok(out)
}
pub fn pack_frames_with_cap(frames: &[String], cap: usize) -> Vec<String> {
    use base64::Engine as _;
    let mut out: Vec<String> = Vec::new();
    let mut cur: Vec<&String> = Vec::new();
    let src_len = |cur: &[&String], extra: Option<&String>| -> usize {
        let mut parts: Vec<&str> = cur.iter().map(|s| s.as_str()).collect();
        if let Some(e) = extra {
            parts.push(e.as_str());
        }
        let joined = parts.join("\n");
        let gz = gzip_bytes(joined.as_bytes());
        let b64 = base64::engine::general_purpose::STANDARD.encode(&gz);
        let obj = serde_json::json!({"package_blob": b64});
        crate::obyte_hash::get_json_source(&obj).len()
    };
    let flush = |cur: &mut Vec<&String>, out: &mut Vec<String>| {
        if cur.is_empty() {
            return;
        }
        let joined = cur
            .iter()
            .map(|s| s.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        let gz = gzip_bytes(joined.as_bytes());
        out.push(base64::engine::general_purpose::STANDARD.encode(&gz));
        cur.clear();
    };
    for f in frames {
        if !cur.is_empty() && src_len(&cur, Some(f)) > cap {
            flush(&mut cur, &mut out);
        }
        cur.push(f);
    }
    flush(&mut cur, &mut out);
    if out.is_empty() {
        out.push(base64::engine::general_purpose::STANDARD.encode(gzip_bytes(b"")));
    }
    out
}
/// Pack with [`PACK_SOURCE_CAP`].
pub fn pack_frames(frames: &[String]) -> Vec<String> {
    pack_frames_with_cap(frames, PACK_SOURCE_CAP)
}
/// `data_root` = hex(sha256 of concatenated gunzipped blob bytes in package order).
pub fn data_root_hex(blobs: &[Vec<u8>]) -> String {
    let mut all = Vec::new();
    for b in blobs {
        all.extend_from_slice(b);
    }
    hex::encode(sha256(&all))
}
/// Decode one package blob: base64 → gunzip → raw frame bytes. Invalid gzip
/// maps to `BindingMismatch` at the caller (`RootMismatch` here).
pub fn decode_package_blob(b64: &str) -> Result<Vec<u8>, SettleError> {
    use base64::Engine as _;
    let gz = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .map_err(|_| SettleError::RootMismatch)?;
    gunzip_bytes(&gz)
}
/// Parse one frame `{"u","t","o","c","f"?,"l"?,"e"?}`. Returns
/// (unit, trace, ops, counts, fills, leaves, evidence).
#[allow(clippy::type_complexity)]
pub fn unit_frame_from_json(
    v: &serde_json::Value,
) -> Result<
    (
        Unit,
        String,
        String,
        String,
        Vec<String>,
        Vec<String>,
        Option<DepositEvidence>,
    ),
    SettleError,
> {
    let obj = v.as_object().ok_or(SettleError::Replay)?;
    let u = obj.get("u").ok_or(SettleError::Replay)?;
    let parents_json = u
        .get("parents")
        .and_then(|x| x.as_array())
        .ok_or(SettleError::Replay)?;
    let mut parents = Vec::with_capacity(parents_json.len());
    for p in parents_json {
        let s = p.as_str().ok_or(SettleError::Replay)?;
        let bytes = hex::decode(s).map_err(|_| SettleError::Replay)?;
        if bytes.len() != 32 {
            return Err(SettleError::Replay);
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        parents.push(UnitId(arr));
    }
    let op: operp_dag::Op =
        serde_json::from_value(u.get("op").cloned().ok_or(SettleError::Replay)?)
            .map_err(|_| SettleError::Replay)?;
    let pubkey_s = u
        .get("pubkey")
        .and_then(|x| x.as_str())
        .ok_or(SettleError::Replay)?;
    let sig_s = u
        .get("sig")
        .and_then(|x| x.as_str())
        .ok_or(SettleError::Replay)?;
    let pubkey_b = hex::decode(pubkey_s).map_err(|_| SettleError::Replay)?;
    let sig_b = hex::decode(sig_s).map_err(|_| SettleError::Replay)?;
    if pubkey_b.len() != 32 || sig_b.len() != 64 {
        return Err(SettleError::Replay);
    }
    let mut pubkey = [0u8; 32];
    let mut sig = [0u8; 64];
    pubkey.copy_from_slice(&pubkey_b);
    sig.copy_from_slice(&sig_b);
    let unit = Unit {
        parents,
        op,
        pubkey,
        sig,
    };
    let t = obj
        .get("t")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();
    let o = obj
        .get("o")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();
    let c = obj
        .get("c")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();
    let f: Vec<String> = match obj.get("f") {
        None => Vec::new(),
        Some(v) => serde_json::from_value(v.clone()).map_err(|_| SettleError::RootMismatch)?,
    };
    let l: Vec<String> = match obj.get("l") {
        None => Vec::new(),
        Some(v) => serde_json::from_value(v.clone()).map_err(|_| SettleError::RootMismatch)?,
    };
    let e: Option<DepositEvidence> = match obj.get("e") {
        None => None,
        Some(v) => Some(
            serde_json::from_value(v.clone()).map_err(|_| SettleError::DepositContentMismatch)?,
        ),
    };
    Ok((unit, t, o, c, f, l, e))
}
/// Rebuild a [`Batch`] from a header JSON plus decoded frame strings.
/// Header carries scalars (no per-unit arrays); frames carry units/trace/
/// ops/counts/fills/leaves/evidences. `unit_ids` are re-derived via
/// `unit_id()`; a legacy header carrying `unit_ids` is cross-checked.
pub fn batch_from_frames(
    header: &serde_json::Value,
    frames: &[String],
) -> Result<Batch, SettleError> {
    let chain_id = header
        .get("chain_id")
        .and_then(|v| v.as_str())
        .ok_or(SettleError::ChainMismatch)?
        .to_string();
    let height = header
        .get("height")
        .and_then(|v| v.as_u64())
        .ok_or(SettleError::RootMismatch)?;
    let prev_state_hash = header
        .get("prev_state_hash")
        .and_then(|v| v.as_str())
        .ok_or(SettleError::RootMismatch)?;
    let prev_bytes = hex::decode(prev_state_hash).map_err(|_| SettleError::RootMismatch)?;
    if prev_bytes.len() != 32 {
        return Err(SettleError::RootMismatch);
    }
    let mut prev_state_hash_arr = [0u8; 32];
    prev_state_hash_arr.copy_from_slice(&prev_bytes);
    let state_root_s = header
        .get("state_root")
        .and_then(|v| v.as_str())
        .ok_or(SettleError::RootMismatch)?;
    let state_root_b = hex::decode(state_root_s).map_err(|_| SettleError::RootMismatch)?;
    if state_root_b.len() != 32 {
        return Err(SettleError::RootMismatch);
    }
    let mut state_root = [0u8; 32];
    state_root.copy_from_slice(&state_root_b);
    let fills_hash_s = header
        .get("fills_hash")
        .and_then(|v| v.as_str())
        .ok_or(SettleError::RootMismatch)?;
    let fills_hash_b = hex::decode(fills_hash_s).map_err(|_| SettleError::RootMismatch)?;
    if fills_hash_b.len() != 32 {
        return Err(SettleError::RootMismatch);
    }
    let mut fills_hash = [0u8; 32];
    fills_hash.copy_from_slice(&fills_hash_b);
    let get_s = |k: &str| {
        header
            .get(k)
            .and_then(|v| v.as_str())
            .ok_or(SettleError::RootMismatch)
            .map(|s| s.to_string())
    };
    let aa_root = get_s("aa_root")?;
    let wit_root = get_s("wit_root")?;
    let trace_root = get_s("trace_root")?;
    let units_root = get_s("units_root")?;
    let units_set_root = get_s("units_set_root")?;
    let ops_root = get_s("ops_root")?;
    let fills_root = get_s("fills_root")?;
    let counts_root = get_s("counts_root")?;
    let get_u = |k: &str| {
        header
            .get(k)
            .and_then(|v| v.as_u64())
            .ok_or(SettleError::RootMismatch)
    };
    let seq = get_u("seq")?;
    let fill_count = get_u("fill_count")? as u32;
    let assertion_version = get_u("assertion_version")? as u32;
    let unit_count = get_u("unit_count")? as u32;
    let wit_count = get_u("wit_count")? as u32;
    let last_unit_s = get_s("last_unit")?;
    let last_unit_b = hex::decode(&last_unit_s).map_err(|_| SettleError::RootMismatch)?;
    if last_unit_b.len() != 32 {
        return Err(SettleError::RootMismatch);
    }
    let mut last_unit_arr = [0u8; 32];
    last_unit_arr.copy_from_slice(&last_unit_b);
    let shards_json = header
        .get("aa_shard_roots")
        .and_then(|v| v.as_array())
        .ok_or(SettleError::RootMismatch)?;
    if shards_json.len() != operp_state::AA_SHARD_COUNT {
        return Err(SettleError::RootMismatch);
    }
    let mut aa_shard_roots: [String; operp_state::AA_SHARD_COUNT] = Default::default();
    for (i, s) in shards_json.iter().enumerate() {
        aa_shard_roots[i] = s.as_str().ok_or(SettleError::RootMismatch)?.to_string();
    }
    let validity_proof_hash = header
        .get("validity_proof_hash")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let perp_burned = header
        .get("perp_burned")
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse::<u128>().ok());
    let mut units = Vec::with_capacity(frames.len());
    let mut trace = Vec::with_capacity(frames.len());
    let mut ops = Vec::with_capacity(frames.len());
    let mut counts = Vec::with_capacity(frames.len());
    let mut fills = Vec::new();
    let mut fills_per_unit: Vec<Vec<String>> = Vec::with_capacity(frames.len());
    let mut leaf_trace: Vec<Vec<String>> = Vec::with_capacity(frames.len());
    let mut deposit_evidences: Vec<DepositEvidence> = Vec::new();
    let mut derived_ids: Vec<UnitId> = Vec::with_capacity(frames.len());
    for f in frames {
        let v: serde_json::Value = serde_json::from_str(f).map_err(|_| SettleError::Replay)?;
        let (unit, t, o, c, uf, l, e) = unit_frame_from_json(&v)?;
        derived_ids.push(operp_dag::unit_id(&unit));
        units.push(unit);
        trace.push(t);
        ops.push(o);
        counts.push(c);
        fills.extend(uf.iter().cloned());
        fills_per_unit.push(uf);
        leaf_trace.push(l);
        if let Some(ev) = e {
            deposit_evidences.push(ev);
        }
    }
    if unit_count as usize != units.len() {
        return Err(SettleError::RootMismatch);
    }
    if let Some(header_ids) = header.get("unit_ids").and_then(|v| v.as_array()) {
        if header_ids.len() != derived_ids.len() {
            return Err(SettleError::RootMismatch);
        }
        for (i, h) in header_ids.iter().enumerate() {
            let s = h.as_str().ok_or(SettleError::RootMismatch)?;
            if s.to_lowercase() != hex::encode(derived_ids[i].0) {
                return Err(SettleError::RootMismatch);
            }
        }
    }
    Ok(Batch {
        chain_id,
        checkpoint: Checkpoint {
            height,
            prev_state_hash: prev_state_hash_arr,
            state_root,
            aa_shard_roots,
            aa_root,
            last_unit: UnitId(last_unit_arr),
            seq,
            unit_ids: derived_ids,
            fills_hash,
            fill_count,
            assertion_version,
            wit_root,
            trace_root,
            units_root,
            units_set_root,
            ops_root,
            fills_root,
            counts_root,
            unit_count,
            wit_count,
            validity_proof_hash,
            perp_burned,
        },
        units,
        deposit_evidences,
        trace,
        ops,
        fills,
        fills_per_unit,
        counts,
        leaf_trace,
    })
}

pub fn pick_stable_winner(height: Height, posts: &[PostedBatch]) -> Option<&PostedBatch> {
    posts
        .iter()
        .filter(|p| p.stable && p.mci.is_some() && p.batch.checkpoint.height == height)
        .min_by(|a, b| {
            a.mci
                .unwrap()
                .cmp(&b.mci.unwrap())
                .then_with(|| a.obyte_unit.cmp(&b.obyte_unit))
        })
}

pub fn check_withdraw(claim: &WithdrawClaim, finalized_root: [u8; 32]) -> Result<(), SettleError> {
    if claim.proof.root != finalized_root {
        return Err(SettleError::BadMerkle);
    }
    if !verify_proof(&claim.proof) {
        return Err(SettleError::BadMerkle);
    }
    if claim.proof.account != claim.account {
        return Err(SettleError::BadMerkle);
    }
    // Bind the claimed amounts to the committed leaf preimage: rebuild the
    // binary account leaf from the proof's own fields and require it to hash
    // to proof.leaf. Without this, a forged-but-internally-consistent proof
    // (e.g. inflated collateral with matching siblings) would verify.
    let mut acct = operp_account::Account::new(claim.proof.account);
    acct.collateral = claim.proof.collateral;
    acct.realized_pnl = claim.proof.realized_pnl;
    acct.positions = claim
        .proof
        .positions
        .iter()
        .map(|(m, (qty, entry))| {
            (
                *m,
                operp_account::Position {
                    market: *m,
                    qty: *qty,
                    entry_price: *entry,
                },
            )
        })
        .collect();
    let leaf = operp_state::account_leaf(&acct, claim.proof.perp, claim.proof.withdrawn);
    if leaf != claim.proof.leaf {
        return Err(SettleError::BadMerkle);
    }
    if claim.amount > claim.proof.collateral {
        return Err(SettleError::AmountExceedsCollateral);
    }
    if claim.amount <= 0 {
        return Err(SettleError::AmountExceedsCollateral);
    }
    // PERP claims are bounded by the proof's declared balance; perp == 0 is a
    // valid collateral-only claim.
    if claim.perp > claim.proof.perp {
        return Err(SettleError::AmountExceedsPerp);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use operp_dag::{genesis_id, sign_unit, unit_id, Op};
    use operp_types::{
        account_id_from_pubkey, ExecStatus, OrderType, Side, TimeInForce, BTC_USD, PRICE_SCALE,
        QTY_SCALE, USD_SCALE,
    };

    fn sk(n: u8) -> [u8; 32] {
        [n; 32]
    }
    fn acct_of(secret: &[u8; 32]) -> AccountId {
        let pk = SigningKey::from_bytes(secret).verifying_key().to_bytes();
        account_id_from_pubkey(&pk)
    }

    /// 32-char uppercase [A-Z2-7] Obyte-style test address, varied by `n`.
    fn test_addr(n: u8) -> String {
        let mut bytes = vec![b'A'; 32];
        bytes[0] = b'A' + (n % 26);
        String::from_utf8(bytes).unwrap()
    }

    /// Minimal Obyte joint paying `amount` of `asset` (None = base collateral).
    /// `n` salts the timestamp so two joints never collide on unit hash.
    fn payment_joint(n: u8, amount: u64, asset: Option<&str>) -> serde_json::Value {
        let outputs = serde_json::json!([{
            "address": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
            "amount": amount,
        }]);
        let payload = match asset {
            None => serde_json::json!({ "outputs": outputs }),
            Some(a) => serde_json::json!({ "outputs": outputs, "asset": a }),
        };
        serde_json::json!({
            "version": "4.0dev",
            "alt": "3",
            "authors": [{ "address": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" }],
            "messages": [{ "app": "payment", "payload": payload }],
            "parent_units": [
                "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
            ],
            "last_ball": "abc",
            "last_ball_unit": "def",
            "timestamp": 1_234_567_890u64 + u64::from(n)
        })
    }

    /// Build an evidence whose aa_unit is the real hash of `joint`.
    fn evidence_from(joint: &serde_json::Value, amount: String, is_perp: bool) -> DepositEvidence {
        let h = obyte_hash::get_unit_hash(joint).unwrap();
        DepositEvidence {
            aa_unit: hex::encode(h),
            is_perp,
            amount,
            vault_address: crate::TEST_VAULT_ADDRESS.to_string(),
            joint: joint.clone(),
        }
    }

    fn seed_trade() -> (Engine, Engine, Vec<UnitId>, [u8; 32], Vec<DepositEvidence>) {
        let mut eng = Engine::new();
        eng.state.deposits_allowed = (0u8..=255)
            .flat_map(|b| [([b; 32], false), ([b; 32], true)])
            .collect();
        eng.state
            .markets
            .insert(BTC_USD, operp_types::genesis_params());
        let prev_root = eng.state.state_root();
        let pre = eng.clone();
        let g = genesis_id();
        let alice = sk(1);
        let bob = sk(2);
        let mut applied = Vec::new();
        // Evidence-consistent deposit anchors: the joint is hashed with the same
        // getUnitHash port the verifier uses, so evidence and op agree by construction.
        let j1 = payment_joint(1, 10_000 * USD_SCALE as u64, None);
        let a1: [u8; 32] = obyte_hash::get_unit_hash(&j1).unwrap();
        // The AA feed endorses exactly these unit hashes (arbitrary bytes, not
        // covered by the blanket [b; 32] preseed below).
        eng.state.deposits_allowed.insert((a1, false));
        let d1 = sign_unit(
            vec![g],
            Op::Deposit {
                account: acct_of(&alice),
                addr: test_addr(1),
                amount: 10_000 * USD_SCALE as i128,
                aa_unit: a1,
            },
            &alice,
        );
        applied.push(unit_id(&d1));
        eng.ingest(d1).unwrap();
        let j2 = payment_joint(2, 10_000 * USD_SCALE as u64, None);
        let a2: [u8; 32] = obyte_hash::get_unit_hash(&j2).unwrap();
        eng.state.deposits_allowed.insert((a2, false));
        let d2 = sign_unit(
            vec![applied[0]],
            Op::Deposit {
                account: acct_of(&bob),
                addr: test_addr(2),
                amount: 10_000 * USD_SCALE as i128,
                aa_unit: a2,
            },
            &bob,
        );
        applied.push(unit_id(&d2));
        eng.ingest(d2).unwrap();
        let px = 100_000 * PRICE_SCALE as i64;
        let ask = sign_unit(
            vec![applied[1]],
            Op::Place {
                account: acct_of(&bob),
                market: BTC_USD,
                side: Side::Ask,
                typ: OrderType::Limit,
                tif: TimeInForce::Gtc,
                price: px,
                qty: QTY_SCALE,
                client_seq: 1,
            },
            &bob,
        );
        applied.push(unit_id(&ask));
        eng.ingest(ask).unwrap();
        let bid = sign_unit(
            vec![applied[2]],
            Op::Place {
                account: acct_of(&alice),
                market: BTC_USD,
                side: Side::Bid,
                typ: OrderType::Limit,
                tif: TimeInForce::Gtc,
                price: px,
                qty: QTY_SCALE,
                client_seq: 1,
            },
            &alice,
        );
        applied.push(unit_id(&bid));
        eng.ingest(bid).unwrap();
        let evidences = vec![
            evidence_from(&j1, (10_000 * USD_SCALE as i128).to_string(), false),
            evidence_from(&j2, (10_000 * USD_SCALE as i128).to_string(), false),
        ];
        (eng, pre, applied, prev_root, evidences)
    }

    #[test]
    fn replay_batch_same_root() {
        let (mut eng, mut pre, applied, prev_root, evidences) = seed_trade();
        let mut batch = Batch::from_applied(&pre.state, &mut eng, &applied).unwrap();
        batch.deposit_evidences = evidences;
        batch.validate_against(prev_root, &mut pre).unwrap();
        assert_eq!(pre.state.state_root(), eng.state.state_root());
    }
    #[test]
    fn assertion_roots_committed_and_verified() {
        let (mut eng, mut pre, applied, prev_root, evidences) = seed_trade();
        let mut batch = Batch::from_applied(&pre.state, &mut eng, &applied).unwrap();
        batch.deposit_evidences = evidences;
        let cp = &batch.checkpoint;
        assert_eq!(cp.assertion_version, operp_types::ASSERTION_VERSION);
        for r in [
            &cp.wit_root,
            &cp.trace_root,
            &cp.units_root,
            &cp.units_set_root,
            &cp.ops_root,
            &cp.fills_root,
        ] {
            assert_eq!(r.len(), operp_types::OBYTE_MERKLE_ROOT_LEN);
        }
        assert_eq!(cp.unit_count as usize, applied.len());
        assert_eq!(cp.unit_count as usize, batch.trace.len());
        assert_eq!(cp.unit_count as usize, batch.ops.len());
        assert_eq!(
            cp.wit_count as usize,
            operp_state::wit_leaves(&eng.state).len()
        );
        assert_eq!(cp.wit_root, *batch.trace.last().unwrap());
        let payload = batch.temp_data_payload();
        for k in [
            "assertion_version",
            "wit_root",
            "trace_root",
            "units_root",
            "units_set_root",
            "unit_count",
            "wit_count",
            "ops_root",
            "fills_root",
            "frames_blob",
            "data_root",
        ] {
            assert!(payload.data.get(k).is_some(), "missing temp_data key {k}");
        }
        batch.validate_against(prev_root, &mut pre).unwrap();
    }
    #[test]
    fn tampered_assertion_roots_are_root_mismatch() {
        for field in ["trace", "wit", "count"] {
            let (mut eng, mut pre, applied, prev_root, evidences) = seed_trade();
            let mut batch = Batch::from_applied(&pre.state, &mut eng, &applied).unwrap();
            batch.deposit_evidences = evidences;
            match field {
                "trace" => batch.checkpoint.trace_root = batch.checkpoint.ops_root.clone(),
                "wit" => batch.checkpoint.wit_root = batch.checkpoint.trace_root.clone(),
                _ => batch.checkpoint.unit_count += 1,
            }
            assert_eq!(
                batch.validate_against(prev_root, &mut pre),
                Err(SettleError::RootMismatch),
                "field {field} must be committed"
            );
        }
    }

    #[test]
    fn mutated_fill_price_mismatches() {
        let (mut eng, mut pre, applied, prev_root, evidences) = seed_trade();
        let mut batch = Batch::from_applied(&pre.state, &mut eng, &applied).unwrap();
        batch.deposit_evidences = evidences;
        batch.checkpoint.state_root[0] ^= 0xff;
        assert_eq!(
            batch.validate_against(prev_root, &mut pre),
            Err(SettleError::RootMismatch)
        );
    }

    #[test]
    fn merkle_and_withdraw() {
        let (eng, _, _, _, _) = seed_trade();
        let alice = acct_of(&sk(1));
        let proof = eng.state.account_proof(alice);
        assert!(verify_proof(&proof));
        let root = eng.state.state_root();
        let claim = WithdrawClaim {
            account: alice,
            amount: 1,
            perp: 0,
            proof: proof.clone(),
        };
        check_withdraw(&claim, root).unwrap();
        let mut bad = claim;
        bad.amount = proof.collateral + 1;
        assert_eq!(
            check_withdraw(&bad, root),
            Err(SettleError::AmountExceedsCollateral)
        );
        let other = acct_of(&sk(9));
        let p2 = eng.state.account_proof(other);
        assert_ne!(p2.leaf, proof.leaf);
        let fail = WithdrawClaim {
            account: other,
            amount: 1,
            perp: 0,
            proof: proof.clone(),
        };
        assert!(check_withdraw(&fail, root).is_err());
    }

    #[test]
    fn pick_stable_winner_rules() {
        let (mut eng, pre, applied, _, _) = seed_trade();
        let batch = Batch::from_applied(&pre.state, &mut eng, &applied).unwrap();
        let a = PostedBatch {
            batch: batch.clone(),
            obyte_unit: [1; 32],
            mci: Some(10),
            stable: false,
        };
        let b = PostedBatch {
            batch: batch.clone(),
            obyte_unit: [2; 32],
            mci: Some(20),
            stable: true,
        };
        let h = batch.checkpoint.height;
        assert_eq!(
            pick_stable_winner(h, &[a.clone(), b.clone()])
                .unwrap()
                .obyte_unit,
            [2; 32]
        );
        let a2 = PostedBatch {
            batch: batch.clone(),
            obyte_unit: [1; 32],
            mci: Some(10),
            stable: true,
        };
        assert_eq!(pick_stable_winner(h, &[a2, b]).unwrap().obyte_unit, [1; 32]);
        let none = PostedBatch {
            batch,
            obyte_unit: [3; 32],
            mci: Some(1),
            stable: false,
        };
        assert!(pick_stable_winner(h, &[none]).is_none());
    }

    #[test]
    fn events_are_optimistic() {
        let (eng, _, _, _, _) = seed_trade();
        for e in &eng.log {
            if let operp_exec::ExecEvent::Applied { status, .. } = e {
                assert_eq!(*status, ExecStatus::Optimistic);
            }
        }
    }

    #[test]
    fn optimistic_then_checkpoint() {
        let (mut eng, mut pre, applied, prev_root, evidences) = seed_trade();
        let alice = acct_of(&sk(1));
        let bob = acct_of(&sk(2));
        let qty = QTY_SCALE as i64;
        assert_eq!(
            eng.state.accounts.get(&alice).unwrap().positions[&BTC_USD].qty,
            qty
        );
        assert_eq!(
            eng.state.accounts.get(&bob).unwrap().positions[&BTC_USD].qty,
            -qty
        );
        assert_eq!(
            *eng.state.marks.get(&BTC_USD).unwrap(),
            100_000 * PRICE_SCALE as i64
        );
        let fills: Vec<_> = eng
            .log
            .iter()
            .filter_map(|e| match e {
                operp_exec::ExecEvent::Applied { fills, status, .. } if !fills.is_empty() => {
                    assert_eq!(*status, ExecStatus::Optimistic);
                    Some(fills.len())
                }
                _ => None,
            })
            .collect();
        assert_eq!(fills.iter().sum::<usize>(), 1);
        let mut batch = Batch::from_applied(&pre.state, &mut eng, &applied).unwrap();
        batch.deposit_evidences = evidences;
        batch.validate_against(prev_root, &mut pre).unwrap();
    }

    #[test]
    fn unbacked_gov_deposit_bounces() {
        // A GovDeposit whose aa_unit was never posted on-chain bounces exactly
        // like a collateral Deposit instead of crediting PERP.
        let mut eng = Engine::new();
        // NOTE: deliberately NOT endorsing [0; 32] — the test asserts the
        // unbacked GovDeposit bounce path.
        eng.state.deposits_allowed = (1u8..=255)
            .flat_map(|b| [([b; 32], false), ([b; 32], true)])
            .collect();
        eng.state
            .markets
            .insert(BTC_USD, operp_types::genesis_params());
        let g = genesis_id();
        let alice = acct_of(&sk(1));
        let d = sign_unit(
            vec![g],
            Op::Deposit {
                account: alice,
                addr: test_addr(1),
                amount: 10_000 * USD_SCALE as i128,
                aa_unit: [1; 32],
            },
            &sk(1),
        );
        let did = unit_id(&d);
        eng.ingest(d).unwrap();
        let gov = sign_unit(
            vec![did],
            Op::GovDeposit {
                account: alice,
                addr: test_addr(1),
                amount: 5_000,
                aa_unit: [0; 32],
            },
            &sk(1),
        );
        let evs = eng.ingest(gov).unwrap();
        assert!(evs.iter().any(|e| matches!(
            e,
            operp_exec::ExecEvent::Rejected {
                reason: operp_exec::RejectReason::UnbackedDeposit,
                ..
            }
        )));
        assert_eq!(eng.state.perp_balances.get(&alice), None);
    }

    #[test]
    fn gov_deposit_replay_requires_carried_unit() {
        // The validator injects aa_units ONLY from GovDeposit units the batch
        // actually carries. Strip the unit and the claimed PERP credit is no
        // longer reproducible: validate_against must fail.
        let (mut eng, mut pre, mut applied, prev_root, mut evidences) = seed_trade();
        let alice = acct_of(&sk(1));
        // PERP joint paying exactly the governed asset id.
        let gj = payment_joint(3, 5_000, Some(&hex::encode(operp_types::PERP_ASSET)));
        let ga: [u8; 32] = obyte_hash::get_unit_hash(&gj).unwrap();
        evidences.push(evidence_from(&gj, 5_000.to_string(), true));
        // Production side: the AA feed endorsed this PERP unit too.
        eng.state.deposits_allowed.insert((ga, true));
        let gov = sign_unit(
            vec![*applied.last().unwrap()],
            Op::GovDeposit {
                account: alice,
                addr: test_addr(1),
                amount: 5_000,
                aa_unit: ga,
            },
            &sk(1),
        );
        let gid = unit_id(&gov);
        applied.push(gid);
        eng.ingest(gov).unwrap();
        let mut batch = Batch::from_applied(&pre.state, &mut eng, &applied).unwrap();
        batch.deposit_evidences = evidences;
        // validate_against consumes the replay engine, so prove the intact
        // batch against a copy and the stripped batch against the original.
        let mut intact = pre.clone();
        batch.validate_against(prev_root, &mut intact).unwrap();
        batch.units.retain(|u| unit_id(u) != gid);
        assert!(batch.validate_against(prev_root, &mut pre).is_err());
    }

    #[test]
    fn aa_root_quad_matches_hand_computed() {
        let pairs: Vec<(String, Usd, u128, i128)> = vec![
            ("ADDRB".to_string(), 700, 30, 5),
            ("ADDRA".to_string(), 500, 20, 0),
        ];
        let root = operp_state::aa_root_of(&pairs);
        // Hand-compute over the same tree the AA reconstructs in Oscript:
        // leaf = sha256_hex("acct:" || addr || ":" || col || ":" || perp
        //                    || ":" || withdrawn),
        // leaves sorted, parent = sha256_hex(left || right).
        let mut leaves: Vec<String> = pairs
            .iter()
            .map(|(a, c, p, w)| {
                hex::encode(sha256(format!("acct:{}:{}:{}:{}", a, c, p, w).as_bytes()))
            })
            .collect();
        leaves.sort();
        let expected = hex::encode(sha256(format!("{}{}", leaves[0], leaves[1]).as_bytes()));
        assert_eq!(root, expected);
    }

    #[test]
    fn tampered_aa_shard_roots_are_root_mismatch() {
        // Phase 5.2: a watcher replay must reproduce all 16 shard roots;
        // flipping one entry of the committed forest fails validation.
        let (mut eng, mut pre, applied, prev_root, evidences) = seed_trade();
        let mut batch = Batch::from_applied(&pre.state, &mut eng, &applied).unwrap();
        batch.deposit_evidences = evidences;
        batch.checkpoint.aa_shard_roots[3] = "0".repeat(64);
        assert_eq!(
            batch.validate_against(prev_root, &mut pre),
            Err(SettleError::RootMismatch)
        );
    }
    #[test]
    fn tampered_aa_root_is_root_mismatch() {
        let (mut eng, mut pre, applied, prev_root, evidences) = seed_trade();
        let mut batch = Batch::from_applied(&pre.state, &mut eng, &applied).unwrap();
        batch.deposit_evidences = evidences;
        batch.checkpoint.aa_root.push('0');
        assert_eq!(
            batch.validate_against(prev_root, &mut pre),
            Err(SettleError::RootMismatch)
        );
    }

    #[test]
    fn forged_proof_fields_fail_leaf_recompute() {
        // A proof whose declared collateral was inflated no longer hashes to
        // its own committed leaf: check_withdraw must reject it before any
        // amount check can pass.
        let (eng, _, _, _, _) = seed_trade();
        // Bind an address so the account enters the AA tree.
        let alice = acct_of(&sk(1));
        assert!(eng.state.aa_addresses.contains_key(&alice));
        let proof = eng.state.account_proof(alice);
        let claim = WithdrawClaim {
            account: alice,
            amount: 1,
            perp: 0,
            proof,
        };
        check_withdraw(&claim, claim.proof.root).unwrap();

        let (eng2, _, _, _, _) = seed_trade();
        let alice2 = acct_of(&sk(1));
        let mut bad_proof = eng2.state.account_proof(alice2);
        bad_proof.collateral += 1; // forge one extra USD of collateral
        let forged = WithdrawClaim {
            account: alice2,
            amount: 1,
            perp: 0,
            proof: bad_proof,
        };
        assert_eq!(
            check_withdraw(&forged, forged.proof.root),
            Err(SettleError::BadMerkle)
        );
    }

    // -----------------------------------------------------------------------
    // Phase 1: pruning consistency (M3) + deposit evidence verification (H2)

    /// Fixture: engine with one endorsed base deposit applied; returns the
    /// pre-ingest snapshot (replay seed), the unit, its id and evidence.
    fn one_deposit_fixture() -> (Engine, Engine, Unit, UnitId, DepositEvidence) {
        let mut eng = Engine::new();
        eng.state
            .markets
            .insert(BTC_USD, operp_types::genesis_params());
        let j = payment_joint(9, 5_000_000_000, None);
        let a: [u8; 32] = obyte_hash::get_unit_hash(&j).unwrap();
        eng.state.deposits_allowed.insert((a, false));
        let pre = eng.clone();
        let secret = sk(4);
        let d = sign_unit(
            vec![genesis_id()],
            Op::Deposit {
                account: acct_of(&secret),
                addr: test_addr(4),
                amount: 5_000_000_000,
                aa_unit: a,
            },
            &secret,
        );
        let id = unit_id(&d);
        eng.ingest(d.clone()).unwrap();
        let ev = evidence_from(&j, 5_000_000_000i128.to_string(), false);
        (eng, pre, d, id, ev)
    }

    #[test]
    fn legal_evidence_passes_validate_against() {
        let (mut eng, pre, _, id, ev) = one_deposit_fixture();
        let batch = Batch::from_applied(&pre.state, &mut eng, &[id]).unwrap();
        let mut batch_with_ev = batch;
        batch_with_ev.deposit_evidences = vec![ev];
        let mut rp = pre.clone();
        batch_with_ev
            .validate_against(pre.state.state_root(), &mut rp)
            .unwrap();
        assert_eq!(rp.state.state_root(), eng.state.state_root());
    }

    #[test]
    fn tampered_amount_is_rejected() {
        let (mut eng, pre, _, id, mut ev) = one_deposit_fixture();
        ev.amount = "5000000001".to_string();
        let mut batch = Batch::from_applied(&pre.state, &mut eng, &[id]).unwrap();
        batch.deposit_evidences = vec![ev];
        assert_eq!(
            batch.validate_against(pre.state.state_root(), &mut pre.clone()),
            Err(SettleError::DepositEvidence)
        );
    }

    #[test]
    fn missing_joint_is_rejected() {
        let (mut eng, pre, _, id, _) = one_deposit_fixture();
        let mut batch = Batch::from_applied(&pre.state, &mut eng, &[id]).unwrap();
        batch.deposit_evidences = vec![]; // no joint at all
        assert_eq!(
            batch.validate_against(pre.state.state_root(), &mut pre.clone()),
            Err(SettleError::DepositEvidence)
        );
    }

    #[test]
    fn payee_mismatch_is_rejected() {
        let (mut eng, pre, _, id, mut ev) = one_deposit_fixture();
        ev.vault_address = "SOMEBODYELSE".to_string(); // != expected vault
        let mut batch = Batch::from_applied(&pre.state, &mut eng, &[id]).unwrap();
        batch.deposit_evidences = vec![ev];
        assert_eq!(
            batch.validate_against(pre.state.state_root(), &mut pre.clone()),
            Err(SettleError::DepositEvidence)
        );
    }

    #[test]
    fn perp_asset_mismatch_is_rejected() {
        // PERP-class evidence whose joint pays some OTHER asset id.
        let mut eng = Engine::new();
        eng.state
            .markets
            .insert(BTC_USD, operp_types::genesis_params());
        let wrong_asset = hex::encode([7u8; 32]); // != PERP_ASSET ([0u8;32])
        let j = payment_joint(8, 5_000, Some(&wrong_asset));
        let a: [u8; 32] = obyte_hash::get_unit_hash(&j).unwrap();
        eng.state.deposits_allowed.insert((a, true));
        let pre = eng.clone();
        let secret = sk(5);
        let g = sign_unit(
            vec![genesis_id()],
            Op::GovDeposit {
                account: acct_of(&secret),
                addr: test_addr(5),
                amount: 5_000,
                aa_unit: a,
            },
            &secret,
        );
        let id = unit_id(&g);
        eng.ingest(g).unwrap();
        let mut batch = Batch::from_applied(&pre.state, &mut eng, &[id]).unwrap();
        batch.deposit_evidences = vec![evidence_from(&j, 5_000i128.to_string(), true)];
        assert_eq!(
            batch.validate_against(pre.state.state_root(), &mut pre.clone()),
            Err(SettleError::DepositEvidence)
        );
    }

    #[test]
    fn evidences_roundtrip_through_payload() {
        let (mut eng, pre, _, id, ev) = one_deposit_fixture();
        let mut batch = Batch::from_applied(&pre.state, &mut eng, &[id]).unwrap();
        batch.deposit_evidences = vec![ev];
        let (header, blobs) = batch.temp_data_packages().unwrap();
        assert_eq!(blobs.len(), 1);
        let raw = decode_package_blob(&blobs[0]).unwrap();
        let text = String::from_utf8(raw).unwrap();
        let frames: Vec<String> = text.split('\n').map(|s| s.to_string()).collect();
        let rebuilt = batch_from_frames(&header, &frames).unwrap();
        assert_eq!(rebuilt.deposit_evidences.len(), 1);
        assert_eq!(
            rebuilt.deposit_evidences[0].aa_unit,
            batch.deposit_evidences[0].aa_unit
        );
        assert_eq!(rebuilt.deposit_evidences[0], batch.deposit_evidences[0]);
        // Absent key → empty vec.
        assert!(evidences_from_payload(&serde_json::json!({}))
            .unwrap()
            .is_empty());
    }

    #[test]
    fn replay_prunes_identically_to_from_applied() {
        // M3: validate_against must prune withdrawals / seen_aa_units /
        // deposits_allowed exactly like from_applied does, else a watcher's
        // replayed state diverges from the operator's committed state once
        // the batch crosses the dedup window.
        use operp_types::{BTC_USD as MKT, PRICE_SCALE};

        let build = || -> (Engine, Engine, Vec<UnitId>, Vec<DepositEvidence>) {
            let mut eng = Engine::new();
            eng.state.deposits_allowed = (0u8..=255)
                .flat_map(|b| [([b; 32], false), ([b; 32], true)])
                .collect();
            eng.state.markets.insert(MKT, operp_types::genesis_params());
            let g = genesis_id();
            let secret = sk(6);
            let acct = acct_of(&secret);
            let j = payment_joint(7, 10_000 * USD_SCALE as u64, None);
            let a: [u8; 32] = obyte_hash::get_unit_hash(&j).unwrap();
            let ev = evidence_from(&j, (10_000 * USD_SCALE as i128).to_string(), false);
            eng.state.deposits_allowed.insert((a, false));
            let pre = eng.clone();
            let d = sign_unit(
                vec![g],
                Op::Deposit {
                    account: acct,
                    addr: test_addr(6),
                    amount: 10_000 * USD_SCALE as i128,
                    aa_unit: a,
                },
                &secret,
            );
            let did = unit_id(&d);
            eng.ingest(d).unwrap();
            let w = sign_unit(
                vec![did],
                Op::Withdraw {
                    account: acct,
                    amount: 100 * USD_SCALE as i128,
                    nonce: 1,
                },
                &secret,
            );
            let wid = unit_id(&w);
            eng.ingest(w).unwrap();
            (eng, pre, vec![did, wid], vec![ev])
        };

        // --- Batch A: records withdrawal + aa-unit entries at height 0. ---
        let (mut eng, pre_a, units_a, evidences_a) = build();
        let prev_root_a = pre_a.state.state_root();
        let mut batch_a = Batch::from_applied(&pre_a.state, &mut eng, &units_a).unwrap();
        batch_a.deposit_evidences = evidences_a;
        let mut rp = pre_a.clone();
        batch_a.validate_against(prev_root_a, &mut rp).unwrap();

        // Producer and replay agree AND actually hold window entries.
        assert!(!eng.state.withdrawals.is_empty());
        assert!(!eng.state.seen_aa_units.is_empty());
        assert_eq!(rp.state.withdrawals.len(), eng.state.withdrawals.len());

        // --- Fast-forward both sides past the 2048-height window. ---
        eng.state.height = 2100;
        rp.state.height = 2100;

        // --- Batch B: one filler order; commit prunes old entries on the
        // producer side (min_height 2101). ---
        let prev_b = eng.clone();
        let prev_root_b = prev_b.state.state_root();
        let f = sign_unit(
            vec![*units_a.last().unwrap()],
            Op::Place {
                account: acct_of(&sk(6)),
                market: BTC_USD,
                side: Side::Bid,
                typ: OrderType::Limit,
                tif: TimeInForce::Gtc,
                price: PRICE_SCALE as i64,
                qty: QTY_SCALE,
                client_seq: 99,
            },
            &sk(6),
        );
        let fid = unit_id(&f);
        eng.ingest(f).unwrap();
        let batch_b = Batch::from_applied(&prev_b.state, &mut eng, &[fid]).unwrap();

        // Replay must prune identically before hashing the final root.
        batch_b.validate_against(prev_root_b, &mut rp).unwrap();

        // The three maps must be key-equal across producer and replay — and
        // demonstrably pruned (old entries dropped on BOTH sides).
        assert_eq!(rp.state.withdrawals.len(), eng.state.withdrawals.len());
        assert_eq!(rp.state.seen_aa_units.len(), eng.state.seen_aa_units.len());
        assert_eq!(
            rp.state.deposits_allowed.len(),
            eng.state.deposits_allowed.len()
        );
        let wk_r: HashSet<_> = rp.state.withdrawals.keys().collect();
        let wk_p: HashSet<_> = eng.state.withdrawals.keys().collect();
        assert_eq!(wk_r, wk_p);
        let ak_r: HashSet<_> = rp.state.seen_aa_units.keys().collect();
        let ak_p: HashSet<_> = eng.state.seen_aa_units.keys().collect();
        assert_eq!(ak_r, ak_p);
        assert!(
            eng.state.withdrawals.is_empty(),
            "height-0 entries must be gone"
        );
        assert!(
            eng.state.seen_aa_units.is_empty(),
            "height-0 entries must be gone"
        );
        assert_eq!(rp.state.state_root(), eng.state.state_root());
    }

    #[test]
    fn commit_reveal_batch_replays_same_root() {
        // v2 (doc 03 §2.3): commit/reveal units flow through the ordinary
        // batch commitment — the pending-commit set lives in meta_leaf, so a
        // watcher replay that diverges on reveal semantics fails RootMismatch
        let mut eng = Engine::new();
        eng.state
            .markets
            .insert(BTC_USD, operp_types::genesis_params());
        eng.state.height = operp_types::COMMIT_REVEAL_ACTIVATION_HEIGHT;
        // Evidence-consistent deposit anchor (same pattern as one_deposit_fixture).
        let j = payment_joint(7, 10_000 * USD_SCALE as u64, None);
        let a: [u8; 32] = obyte_hash::get_unit_hash(&j).unwrap();
        eng.state.deposits_allowed.insert((a, false));
        let prev_root = eng.state.state_root();
        let mut pre = eng.clone();
        let alice = sk(1);
        let mut applied = Vec::new();
        let d1 = sign_unit(
            vec![genesis_id()],
            Op::Deposit {
                account: acct_of(&alice),
                addr: test_addr(1),
                amount: 10_000 * USD_SCALE as i128,
                aa_unit: a,
            },
            &alice,
        );
        applied.push(unit_id(&d1));
        eng.ingest(d1).unwrap();
        let inner = Op::Place {
            account: acct_of(&alice),
            market: BTC_USD,
            side: Side::Bid,
            typ: OrderType::Limit,
            tif: TimeInForce::Gtc,
            price: 100 * PRICE_SCALE as i64,
            qty: QTY_SCALE / 1000,
            client_seq: 1,
        };
        let salt = [5u8; 32];
        let hash = operp_dag::reveal_commit_hash(&inner, &salt);
        let c = sign_unit(
            vec![applied[0]],
            Op::Commit {
                account: acct_of(&alice),
                commit: hash,
                ttl_height: eng.state.height + operp_types::COMMIT_TTL_HEIGHTS,
            },
            &alice,
        );
        applied.push(unit_id(&c));
        eng.ingest(c).unwrap();
        let r = sign_unit(
            vec![applied[1]],
            Op::Reveal {
                account: acct_of(&alice),
                commit_ref: hash,
                op: Box::new(inner),
                salt,
            },
            &alice,
        );
        applied.push(unit_id(&r));
        eng.ingest(r).unwrap();

        let mut batch = Batch::from_applied(&pre.state, &mut eng, &applied).unwrap();
        batch.deposit_evidences = vec![evidence_from(
            &j,
            (10_000 * USD_SCALE as i128).to_string(),
            false,
        )];
        batch.validate_against(prev_root, &mut pre).unwrap();
        assert_eq!(pre.state.state_root(), eng.state.state_root());
        assert!(eng.state.commits[&hash].revealed);
        assert_eq!(
            pre.state.commits[&hash].revealed,
            eng.state.commits[&hash].revealed
        );
    }
    #[test]
    fn frames_roundtrip_batch_equality() {
        let (mut eng, pre, applied, prev_root, evidences) = seed_trade();
        let mut batch = Batch::from_applied(&pre.state, &mut eng, &applied).unwrap();
        batch.deposit_evidences = evidences;
        let frames = batch.frames();
        assert_eq!(frames.len(), batch.units.len());
        let (header, blobs) = batch.temp_data_packages().unwrap();
        assert_eq!(blobs.len(), 1);
        let raw = decode_package_blob(&blobs[0]).unwrap();
        let split: Vec<String> = String::from_utf8(raw)
            .unwrap()
            .split('\n')
            .map(|s| s.to_string())
            .collect();
        assert_eq!(split, frames);
        let rebuilt = batch_from_frames(&header, &split).unwrap();
        assert_eq!(rebuilt.units, batch.units);
        assert_eq!(rebuilt.trace, batch.trace);
        assert_eq!(rebuilt.ops, batch.ops);
        assert_eq!(rebuilt.counts, batch.counts);
        assert_eq!(rebuilt.fills, batch.fills);
        assert_eq!(rebuilt.fills_per_unit, batch.fills_per_unit);
        assert_eq!(rebuilt.leaf_trace, batch.leaf_trace);
        assert_eq!(rebuilt.deposit_evidences, batch.deposit_evidences);
        assert_eq!(rebuilt.checkpoint, batch.checkpoint);
        let mut rp = pre.clone();
        rebuilt.validate_against(prev_root, &mut rp).unwrap();
    }
    #[test]
    fn pack_forced_split_byte_exact() {
        let frames = vec![
            "{\"a\":1}".to_string(),
            "{\"b\":2}".to_string(),
            "{\"c\":3}".to_string(),
        ];
        let packs = pack_frames_with_cap(&frames, 1000);
        assert!(!packs.is_empty());
        let mut seen: Vec<String> = Vec::new();
        for p in &packs {
            let obj = serde_json::json!({"package_blob": p});
            assert!(crate::obyte_hash::get_json_source(&obj).len() <= 1000);
            let raw = decode_package_blob(p).unwrap();
            for line in String::from_utf8(raw).unwrap().split('\n') {
                seen.push(line.to_string());
            }
        }
        assert_eq!(seen, frames);
        let tiny = pack_frames_with_cap(&frames, 30);
        assert!(tiny.len() >= frames.len());
    }
    #[test]
    fn data_root_golden() {
        let blobs = vec![b"ab".to_vec(), b"cd".to_vec()];
        let got = data_root_hex(&blobs);
        let expected = hex::encode(sha256(b"abcd"));
        assert_eq!(got, expected);
    }
}
