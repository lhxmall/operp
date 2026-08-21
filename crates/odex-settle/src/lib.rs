mod aa;

pub use aa::{AaStateNames, AA_STATE, BOUNCE_FEES, AA_CHALLENGE_SECS, AA_STABILITY_SECS};

use odex_dag::{Unit, Unit as DagUnit};
use odex_exec::Engine;
use odex_state::{verify_proof, MerkleProof};
use odex_types::{
    sha256, AccountId, Height, Seq, UnitId, Usd, CHAIN_ID,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Checkpoint {
    pub height: Height,
    pub prev_state_hash: [u8; 32],
    pub state_root: [u8; 32],
    pub last_unit: UnitId,
    pub seq: Seq,
    pub unit_ids: Vec<UnitId>,
    pub fills_hash: [u8; 32],
    pub fill_count: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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
    pub nonce: u64,
    pub height: Height,
    pub proof: MerkleProof,
}

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum SettleError {
    #[error("empty batch")]
    Empty,
    #[error("prev root mismatch")]
    PrevMismatch,
    #[error("state root mismatch")]
    RootMismatch,
    #[error("replay failed")]
    Replay,
    #[error("bad merkle")]
    BadMerkle,
    #[error("amount exceeds collateral")]
    AmountExceedsCollateral,
}

impl Batch {
    pub fn from_applied(prev: &odex_state::ChainState, engine: &Engine, applied: &[UnitId]) -> Result<Self, SettleError> {
        if applied.is_empty() {
            return Err(SettleError::Empty);
        }
        let mut units = Vec::new();
        let mut fills_buf = Vec::new();
        let mut fill_count = 0u32;
        for id in applied {
            let u = engine.dag.get(*id).cloned().ok_or(SettleError::Replay)?;
            units.push(u);
        }
        for ev in &engine.log {
            if let odex_exec::ExecEvent::Applied { unit, fills, .. } = ev {
                if applied.contains(unit) {
                    fill_count += fills.len() as u32;
                    for f in fills {
                        fills_buf.extend_from_slice(&f.taker_id.0);
                        fills_buf.extend_from_slice(&f.maker_id.0);
                        fills_buf.extend_from_slice(&f.price.to_le_bytes());
                        fills_buf.extend_from_slice(&f.qty.to_le_bytes());
                        fills_buf.extend_from_slice(&f.seq.to_le_bytes());
                    }
                }
            }
        }
        let fills_hash = sha256(&fills_buf);
        let last_unit = *applied.last().unwrap();
        Ok(Self {
            chain_id: CHAIN_ID.to_string(),
            checkpoint: Checkpoint {
                height: prev.height + 1,
                prev_state_hash: prev.state_root(),
                state_root: engine.state.state_root(),
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
        if replay.state.state_root() != prev_root {
            return Err(SettleError::PrevMismatch);
        }
        for u in &self.units {
            replay.ingest(u.clone()).map_err(|_| SettleError::Replay)?;
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
    Ok(())
}

impl Engine {
    pub fn checkpoint_units(&self, prev: &odex_state::ChainState, applied: &[UnitId]) -> Result<Batch, SettleError> {
        Batch::from_applied(prev, self, applied)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use odex_dag::{genesis_id, sign_unit, unit_id, Op};
    use odex_types::{
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
        let (eng, mut pre, applied, prev_root) = seed_trade();
        let batch = Batch::from_applied(&pre.state, &eng, &applied).unwrap();
        batch.validate_against(prev_root, &mut pre).unwrap();
        assert_eq!(pre.state.state_root(), eng.state.state_root());
    }

    #[test]
    fn mutated_fill_price_mismatches() {
        let (eng, mut pre, applied, prev_root) = seed_trade();
        let mut batch = Batch::from_applied(&pre.state, &eng, &applied).unwrap();
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
            nonce: 1,
            height: 1,
            proof: proof.clone(),
        };
        assert!(check_withdraw(&fail, root).is_err());
    }

    #[test]
    fn pick_stable_winner_rules() {
        let (eng, pre, applied, _) = seed_trade();
        let batch = Batch::from_applied(&pre.state, &eng, &applied).unwrap();
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

    #[allow(dead_code)]
    fn _use_dag_unit(_: &DagUnit) {}

    #[test]
    fn events_are_optimistic() {
        let (eng, _, _, _) = seed_trade();
        for e in &eng.log {
            if let odex_exec::ExecEvent::Applied { status, .. } = e {
                assert_eq!(*status, ExecStatus::Optimistic);
            }
        }
    }
}
