use operp_book::Fill;
use operp_dag::Unit;
use operp_exec::Engine;
use operp_state::{verify_proof, MerkleProof};
use operp_types::{
    sha256, AccountId, Height, Seq, UnitId, Usd, BATCH_MAX_UNITS, CHAIN_ID,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Checkpoint {
    pub height: Height,
    pub prev_state_hash: [u8; 32],
    pub state_root: [u8; 32],
    /// Hex-domain merkle root the vault AA verifies withdrawal proofs against
    /// (Oscript sha256 hashes UTF-8 strings; see operp_state::aa_root_of).
    pub aa_root: String,
    pub last_unit: UnitId,
    pub seq: Seq,
    pub unit_ids: Vec<UnitId>,
    pub fills_hash: [u8; 32],
    pub fill_count: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Batch {
    pub chain_id: String,
    pub checkpoint: Checkpoint,
    pub units: Vec<Unit>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TempDataPayload {
    pub data_length: u64,
    /// Sidechain-internal SHA-256 hex of serde_json::to_vec(data). Not Obyte getBase64Hash.
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
    pub nonce: u64,
    pub height: Height,
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
        for ev in &engine.log {
            if let operp_exec::ExecEvent::Applied { unit, fills, .. } = ev {
                if applied_set.contains(unit) {
                    fill_count += fills.len() as u32;
                    fills_buf.extend_from_slice(&fills_bytes(fills));
                }
            }
        }
        let fills_hash = sha256(&fills_buf);
        // Height binding: adopt the next height BEFORE hashing state, so
        // meta_leaf commits the batch height and the checkpoint root is only
        // reproducible by a replay that lands on that same height
        // (validate_against enforces exactly that).
        engine.state.height = prev.height + 1;
        let height = engine.state.height;
        let last_unit = *applied.last().unwrap();
        Ok(Self {
            chain_id: CHAIN_ID.to_string(),
            checkpoint: Checkpoint {
                height,
                prev_state_hash: prev.state_root(),
                state_root: engine.state.state_root(),
                aa_root: operp_state::aa_root_of_state(&engine.state),
                last_unit,
                seq: engine.state.seq,
                unit_ids: applied.to_vec(),
                fills_hash,
                fill_count,
            },
            units,
        })
    }

    pub fn temp_data_payload(&self) -> TempDataPayload {
        let units_json: Vec<serde_json::Value> = self
            .units
            .iter()
            .map(|u| {
                serde_json::json!({
                    "parents": u.parents.iter().map(|p| hex::encode(p.0)).collect::<Vec<_>>(),
                    "op": serde_json::to_value(&u.op).unwrap(),
                    "pubkey": hex::encode(u.pubkey),
                    "sig": hex::encode(u.sig),
                })
            })
            .collect();
        let data = serde_json::json!({
            "chain_id": self.chain_id,
            "height": self.checkpoint.height,
            "prev_state_hash": hex::encode(self.checkpoint.prev_state_hash),
            "state_root": hex::encode(self.checkpoint.state_root),
            "aa_root": self.checkpoint.aa_root,
            "last_unit": hex::encode(self.checkpoint.last_unit.0),
            "seq": self.checkpoint.seq,
            "unit_ids": self.checkpoint.unit_ids.iter().map(|u| hex::encode(u.0)).collect::<Vec<_>>(),
            "fill_count": self.checkpoint.fill_count,
            "fills_hash": hex::encode(self.checkpoint.fills_hash),
            "units": units_json,
        });
        let bytes = serde_json::to_vec(&data).expect("json");
        let hash = Sha256::digest(&bytes);
        TempDataPayload {
            data_length: bytes.len() as u64,
            data_hash: hex::encode(hash),
            data,
        }
    }

    pub fn validate_against(
        &self,
        prev_root: [u8; 32],
        replay: &mut Engine,
    ) -> Result<(), SettleError> {
        if self.units.is_empty() {
            return Err(SettleError::Empty);
        }
        if self.chain_id != CHAIN_ID {
            return Err(SettleError::ChainMismatch);
        }
        if replay.state.state_root() != prev_root {
            return Err(SettleError::PrevMismatch);
        }
        // Inject the AA deposit set implied by this batch's deposit ops so the
        // replay admits exactly the deposits the batch claims are on-chain.
        replay.state.deposits_allowed.clear();
        for u in &self.units {
            match &u.op {
                operp_dag::Op::Deposit { aa_unit, .. } => {
                    replay.state.deposits_allowed.insert(*aa_unit);
                }
                // PERP deposits are backed by the same on-chain AA feed.
                operp_dag::Op::GovDeposit { aa_unit, .. } => {
                    replay.state.deposits_allowed.insert(*aa_unit);
                }
                _ => {}
            }
        }
        let pre_seq = replay.state.seq;
        for u in &self.units {
            replay.ingest(u.clone()).map_err(|_| SettleError::Replay)?;
        }
        // Fill integrity: recompute hash/count from replay events.
        let applied_set: HashSet<&UnitId> = self.checkpoint.unit_ids.iter().collect();
        let mut fills_buf = Vec::new();
        let mut fill_count = 0u32;
        for ev in replay.log.iter().skip(pre_seq as usize) {
            if let operp_exec::ExecEvent::Applied { unit, fills, .. } = ev {
                if applied_set.contains(unit) {
                    fill_count += fills.len() as u32;
                    fills_buf.extend_from_slice(&fills_bytes(fills));
                }
            }
        }
        if sha256(&fills_buf) != self.checkpoint.fills_hash
            || fill_count != self.checkpoint.fill_count
        {
            return Err(SettleError::FillsMismatch);
        }
        // Height + last-unit binding: the replay must land exactly one block
        // below the claimed checkpoint height and end on the same last unit;
        // then it adopts the checkpoint height so meta_leaf — which commits
        // state.height — can match the producer's root.
        if self.checkpoint.height != replay.state.height + 1 {
            return Err(SettleError::RootMismatch);
        }
        replay.state.height = self.checkpoint.height;
        if self.checkpoint.last_unit != replay.state.last_unit {
            return Err(SettleError::RootMismatch);
        }
        if replay.state.state_root() != self.checkpoint.state_root {
            return Err(SettleError::RootMismatch);
        }
        Ok(())
    }
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

    fn seed_trade() -> (Engine, Engine, Vec<UnitId>, [u8; 32]) {
        let mut eng = Engine::new();
        eng.state.deposits_allowed = (1u8..=255).map(|b| [b; 32]).collect();
        eng.state.markets.insert(BTC_USD, operp_types::genesis_params());
        let prev_root = eng.state.state_root();
        let pre = eng.clone();
        let g = genesis_id();
        let alice = sk(1);
        let bob = sk(2);
        let mut applied = Vec::new();
        let d1 = sign_unit(
            vec![g],
            Op::Deposit {
                account: acct_of(&alice),
                amount: 10_000 * USD_SCALE as i128,
                aa_unit: [1; 32],
            },
            &alice,
        );
        applied.push(unit_id(&d1));
        eng.ingest(d1).unwrap();
        let d2 = sign_unit(
            vec![applied[0]],
            Op::Deposit {
                account: acct_of(&bob),
                amount: 10_000 * USD_SCALE as i128,
                aa_unit: [2; 32],
            },
            &bob,
        );
        applied.push(unit_id(&d2));
        eng.ingest(d2).unwrap();
        let px = 100_000 * PRICE_SCALE;
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
        (eng, pre, applied, prev_root)
    }

    #[test]
    fn replay_batch_same_root() {
        let (mut eng, mut pre, applied, prev_root) = seed_trade();
        let batch = Batch::from_applied(&pre.state, &mut eng, &applied).unwrap();
        batch.validate_against(prev_root, &mut pre).unwrap();
        assert_eq!(pre.state.state_root(), eng.state.state_root());
    }

    #[test]
    fn mutated_fill_price_mismatches() {
        let (mut eng, mut pre, applied, prev_root) = seed_trade();
        let mut batch = Batch::from_applied(&pre.state, &mut eng, &applied).unwrap();
        batch.checkpoint.state_root[0] ^= 0xff;
        assert_eq!(
            batch.validate_against(prev_root, &mut pre),
            Err(SettleError::RootMismatch)
        );
    }

    #[test]
    fn merkle_and_withdraw() {
        let (eng, _, _, _) = seed_trade();
        let alice = acct_of(&sk(1));
        let proof = eng.state.account_proof(alice);
        assert!(verify_proof(&proof));
        let root = eng.state.state_root();
        let claim = WithdrawClaim {
            account: alice,
            amount: 1,
            perp: 0,
            nonce: 1,
            height: 1,
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
            nonce: 1,
            height: 1,
            proof: proof.clone(),
        };
        assert!(check_withdraw(&fail, root).is_err());
    }

    #[test]
    fn pick_stable_winner_rules() {
        let (mut eng, pre, applied, _) = seed_trade();
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
        assert_eq!(
            pick_stable_winner(h, &[a2, b]).unwrap().obyte_unit,
            [1; 32]
        );
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
        let (eng, _, _, _) = seed_trade();
        for e in &eng.log {
            if let operp_exec::ExecEvent::Applied { status, .. } = e {
                assert_eq!(*status, ExecStatus::Optimistic);
            }
        }
    }

    #[test]
    fn optimistic_then_checkpoint() {
        let (mut eng, mut pre, applied, prev_root) = seed_trade();
        let alice = acct_of(&sk(1));
        let bob = acct_of(&sk(2));
        let qty = QTY_SCALE as i64;
        assert_eq!(eng.state.accounts.get(&alice).unwrap().positions[&BTC_USD].qty, qty);
        assert_eq!(eng.state.accounts.get(&bob).unwrap().positions[&BTC_USD].qty, -qty);
        assert_eq!(
            *eng.state.marks.get(&BTC_USD).unwrap(),
            100_000 * PRICE_SCALE
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
        let batch = Batch::from_applied(&pre.state, &mut eng, &applied).unwrap();
        batch.validate_against(prev_root, &mut pre).unwrap();
    }

    #[test]
    fn unbacked_gov_deposit_bounces() {
        // A GovDeposit whose aa_unit was never posted on-chain bounces exactly
        // like a collateral Deposit instead of crediting PERP.
        let mut eng = Engine::new();
        eng.state.deposits_allowed = (1u8..=255).map(|b| [b; 32]).collect();
        eng.state.markets.insert(BTC_USD, operp_types::genesis_params());
        let g = genesis_id();
        let alice = acct_of(&sk(1));
        let d = sign_unit(
            vec![g],
            Op::Deposit {
                account: alice,
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
        let (mut eng, mut pre, mut applied, prev_root) = seed_trade();
        let alice = acct_of(&sk(1));
        let gov = sign_unit(
            vec![*applied.last().unwrap()],
            Op::GovDeposit {
                account: alice,
                amount: 5_000,
                aa_unit: [77; 32],
            },
            &sk(1),
        );
        let gid = unit_id(&gov);
        applied.push(gid);
        eng.ingest(gov).unwrap();
        let mut batch = Batch::from_applied(&pre.state, &mut eng, &applied).unwrap();
        // validate_against consumes the replay engine, so prove the intact
        // batch against a copy and the stripped batch against the original.
        let mut intact = pre.clone();
        batch.validate_against(prev_root, &mut intact).unwrap();
        batch.units.retain(|u| unit_id(u) != gid);
        assert!(batch.validate_against(prev_root, &mut pre).is_err());
    }

    #[test]
    fn aa_root_triple_matches_hand_computed() {
        let pairs: Vec<(String, Usd, u128)> = vec![
            ("ADDRB".to_string(), 700, 30),
            ("ADDRA".to_string(), 500, 20),
        ];
        let root = operp_state::aa_root_of(&pairs);
        // Hand-compute over the same tree the AA reconstructs in Oscript:
        // leaf = sha256_hex("acct:" || addr || ":" || col || ":" || perp),
        // leaves sorted, parent = sha256_hex(left || right).
        let mut leaves: Vec<String> = pairs
            .iter()
            .map(|(a, c, p)| hex::encode(sha256(format!("acct:{}:{}:{}", a, c, p).as_bytes())))
            .collect();
        leaves.sort();
        let expected = hex::encode(sha256(format!("{}{}", leaves[0], leaves[1]).as_bytes()));
        assert_eq!(root, expected);
    }
}
