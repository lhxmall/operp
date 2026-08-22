use ed25519_dalek::{Signature, VerifyingKey};
use odex_types::{
    account_id_from_pubkey, sha256, AccountId, MarketId, OrderId, OrderType, Price, Qty, Side,
    TimeInForce, UnitId, Usd, MAX_PARENTS,
};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Op {
    Place {
        account: AccountId,
        market: MarketId,
        side: Side,
        typ: OrderType,
        tif: TimeInForce,
        price: Price,
        qty: Qty,
        client_seq: u64,
    },
    Cancel {
        account: AccountId,
        order_id: OrderId,
    },
    Deposit {
        account: AccountId,
        amount: Usd,
        aa_unit: [u8; 32],
    },
    Withdraw {
        account: AccountId,
        amount: Usd,
        nonce: u64,
    },
    /// Keeper-initiated liquidation. `caller` is the keeper requesting it and
    /// receives the keeper reward; signature must belong to `caller`.
    Liquidate {
        caller: AccountId,
        target: AccountId,
        market: MarketId,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Unit {
    pub parents: Vec<UnitId>,
    pub op: Op,
    pub pubkey: [u8; 32],
    pub sig: [u8; 64],
}

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum DagError {
    #[error("missing parent")]
    MissingParent,
    #[error("too many parents")]
    TooManyParents,
    #[error("unsorted or duplicate parents")]
    BadParents,
    #[error("duplicate unit")]
    Duplicate,
    #[error("empty parents")]
    EmptyParents,
}

pub fn genesis_id() -> UnitId {
    UnitId(sha256(b"odex-mvp-1-genesis"))
}

pub fn canonical_bytes(unit: &Unit) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(b"ODX1");
    b.push(unit.parents.len() as u8);
    for p in &unit.parents {
        b.extend_from_slice(&p.0);
    }
    match &unit.op {
        Op::Place {
            account,
            market,
            side,
            typ,
            tif,
            price,
            qty,
            client_seq,
        } => {
            b.push(1);
            b.extend_from_slice(&account.0);
            b.extend_from_slice(&market.0.to_le_bytes());
            b.push(side.as_u8());
            b.push(typ.as_u8());
            b.push(tif.as_u8());
            b.extend_from_slice(&price.to_le_bytes());
            b.extend_from_slice(&qty.to_le_bytes());
            b.extend_from_slice(&client_seq.to_le_bytes());
        }
        Op::Cancel { account, order_id } => {
            b.push(2);
            b.extend_from_slice(&account.0);
            b.extend_from_slice(&order_id.0);
        }
        Op::Deposit {
            account,
            amount,
            aa_unit,
        } => {
            b.push(3);
            b.extend_from_slice(&account.0);
            b.extend_from_slice(&amount.to_le_bytes());
            b.extend_from_slice(aa_unit);
        }
        Op::Withdraw {
            account,
            amount,
            nonce,
        } => {
            b.push(4);
            b.extend_from_slice(&account.0);
            b.extend_from_slice(&amount.to_le_bytes());
            b.extend_from_slice(&nonce.to_le_bytes());
        }
        Op::Liquidate {
            caller,
            target,
            market,
        } => {
            b.push(5);
            b.extend_from_slice(&caller.0);
            b.extend_from_slice(&target.0);
            b.extend_from_slice(&market.0.to_le_bytes());
        }
    }
    b.extend_from_slice(&unit.pubkey);
    b
}

pub fn unit_id(unit: &Unit) -> UnitId {
    UnitId(sha256(&canonical_bytes(unit)))
}

pub fn verify_sig(unit: &Unit) -> bool {
    let vk = match VerifyingKey::from_bytes(&unit.pubkey) {
        Ok(v) => v,
        Err(_) => return false,
    };
    // verify_strict rejects non-canonical s / small-order components
    // (signature malleability), satisfying strict r/s group-order checks.
    let sig = Signature::from_bytes(&unit.sig);
    let id = unit_id(unit);
    vk.verify_strict(&id.0, &sig).is_ok() && account_matches(unit)
}

fn account_matches(unit: &Unit) -> bool {
    let expected = account_id_from_pubkey(&unit.pubkey);
    match &unit.op {
        Op::Place { account, .. }
        | Op::Cancel { account, .. }
        | Op::Deposit { account, .. }
        | Op::Withdraw { account, .. } => *account == expected,
        Op::Liquidate { caller, .. } => *caller == expected,
    }
}


pub fn sign_unit(parents: Vec<UnitId>, op: Op, secret: &[u8; 32]) -> Unit {
    use ed25519_dalek::{Signer, SigningKey};
    let sk = SigningKey::from_bytes(secret);
    let pubkey = sk.verifying_key().to_bytes();
    let mut unit = Unit {
        parents,
        op,
        pubkey,
        sig: [0u8; 64],
    };
    let id = unit_id(&unit);
    unit.sig = sk.sign(&id.0).to_bytes();
    unit
}

#[derive(Clone, Debug, Default)]
pub struct Dag {
    units: HashMap<UnitId, Unit>,
    children: HashMap<UnitId, Vec<UnitId>>,
    executed: HashSet<UnitId>,
    /// non-executed units; keeps ready_linearized O(pending) not O(all units)
    pending: HashSet<UnitId>,
    /// units whose parents are not (yet) known; FIFO-evicted past capacity
    pending_orphans: HashMap<UnitId, (Unit, std::time::Instant)>,
}

/// Max buffered orphan units. Beyond this the oldest orphans are dropped.
const ORPHAN_CAP: usize = 4096;

impl Dag {
    pub fn new() -> Self {
        let mut executed = HashSet::new();
        executed.insert(genesis_id());
        Self {
            units: HashMap::new(),
            children: HashMap::new(),
            executed,
            pending: HashSet::new(),
            pending_orphans: HashMap::new(),
        }
    }

    /// Insert a unit. Unknown parents no longer drop the unit: on first sight
    /// it is buffered as an orphan and `Err(MissingParent)` returned; a retry
    /// of the same unit while still orphaned returns its id without error.
    /// Buffered orphans are linked automatically once their parents arrive
    /// (see `mark_executed` / `insert`), so out-of-order delivery recovers.
    pub fn insert(&mut self, unit: Unit) -> Result<UnitId, DagError> {
        if unit.parents.is_empty() {
            return Err(DagError::EmptyParents);
        }
        if unit.parents.len() > MAX_PARENTS {
            return Err(DagError::TooManyParents);
        }
        let mut sorted = unit.parents.clone();
        sorted.sort();
        sorted.dedup();
        if sorted != unit.parents {
            return Err(DagError::BadParents);
        }
        let id = unit_id(&unit);
        if self.units.contains_key(&id) {
            return Err(DagError::Duplicate);
        }
        let missing: Vec<UnitId> = unit
            .parents
            .iter()
            .copied()
            .filter(|p| !self.known(*p))
            .collect();
        if !missing.is_empty() {
            // Already buffered? Then report acceptance (pending), not an error.
            if self.pending_orphans.contains_key(&id) {
                return Ok(id);
            }
            if self.pending_orphans.len() >= ORPHAN_CAP {
                // FIFO eviction of the oldest orphan.
                let oldest = self
                    .pending_orphans
                    .iter()
                    .min_by_key(|(_, (_, t))| *t)
                    .map(|(k, _)| *k);
                if let Some(k) = oldest {
                    self.pending_orphans.remove(&k);
                }
            }
            self.pending_orphans.insert(id, (unit, std::time::Instant::now()));
            return Err(DagError::MissingParent);
        }
        self.link(id, unit);
        Ok(id)
    }

    /// Attach a validated unit to the DAG structures.
    fn link(&mut self, id: UnitId, unit: Unit) {
        for p in &unit.parents {
            self.children.entry(*p).or_default().push(id);
        }
        self.units.insert(id, unit);
        self.pending.insert(id);
    }

    fn known(&self, id: UnitId) -> bool {
        id == genesis_id() || self.units.contains_key(&id)
    }

    pub fn ready_linearized(&self) -> Vec<UnitId> {
        let mut ready: Vec<UnitId> = self
            .pending
            .iter()
            .copied()
            .filter(|id| {
                self.units
                    .get(id)
                    .map(|u| u.parents.iter().all(|p| self.executed.contains(p)))
                    .unwrap_or(false)
            })
            .collect();
        ready.sort_by(|a, b| a.0.cmp(&b.0));
        ready
    }

    pub fn mark_executed(&mut self, id: UnitId) {
        self.executed.insert(id);
        self.pending.remove(&id);
        // Newly known parent: link any buffered orphans whose parents are now
        // all present. Repeat until fixpoint (orphans may chain).
        loop {
            let ready: Vec<UnitId> = self
                .pending_orphans
                .iter()
                .filter(|(_, (u, _))| u.parents.iter().all(|p| self.known(*p)))
                .map(|(k, _)| *k)
                .collect();
            if ready.is_empty() {
                break;
            }
            for oid in ready {
                if let Some((unit, _)) = self.pending_orphans.remove(&oid) {
                    self.link(oid, unit);
                }
            }
        }
    }

    pub fn get(&self, id: UnitId) -> Option<&Unit> {
        self.units.get(&id)
    }

    pub fn is_executed(&self, id: UnitId) -> bool {
        self.executed.contains(&id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use odex_types::USD_SCALE;

    fn sk(n: u8) -> [u8; 32] {
        [n; 32]
    }

    fn deposit(parents: Vec<UnitId>, secret: &[u8; 32], aa: u8) -> Unit {
        let account = account_id_from_pubkey(&ed25519_dalek::SigningKey::from_bytes(secret).verifying_key().to_bytes());
        sign_unit(
            parents,
            Op::Deposit {
                account,
                amount: 1 * USD_SCALE as i128,
                aa_unit: [aa; 32],
            },
            secret,
        )
    }

    #[test]
    fn two_children_sorted_by_unit_id() {
        let mut dag = Dag::new();
        let g = genesis_id();
        let u1 = deposit(vec![g], &sk(1), 1);
        let u2 = deposit(vec![g], &sk(2), 2);
        let id_a = unit_id(&u1);
        let id_b = unit_id(&u2);
        dag.insert(u2.clone()).unwrap();
        dag.insert(u1.clone()).unwrap();
        let ready = dag.ready_linearized();
        let mut expect = vec![id_a, id_b];
        expect.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(ready, expect);
        let mut dag2 = Dag::new();
        dag2.insert(u1).unwrap();
        dag2.insert(u2).unwrap();
        assert_eq!(dag2.ready_linearized(), expect);
    }

    #[test]
    fn missing_parent_rejected() {
        let mut dag = Dag::new();
        let fake = UnitId([9; 32]);
        let u = deposit(vec![fake], &sk(1), 1);
        assert_eq!(dag.insert(u), Err(DagError::MissingParent));
    }

    #[test]
    fn bad_parent_count_rejected() {
        let mut dag = Dag::new();
        let g = genesis_id();
        let account = account_id_from_pubkey(
            &ed25519_dalek::SigningKey::from_bytes(&sk(1))
                .verifying_key()
                .to_bytes(),
        );
        let u = sign_unit(
            vec![g, g, g],
            Op::Deposit {
                account,
                amount: 1,
                aa_unit: [1; 32],
            },
            &sk(1),
        );
        assert!(matches!(
            dag.insert(u),
            Err(DagError::TooManyParents) | Err(DagError::BadParents)
        ));
        let u2 = sign_unit(
            vec![],
            Op::Deposit {
                account,
                amount: 1,
                aa_unit: [2; 32],
            },
            &sk(1),
        );
        assert_eq!(dag.insert(u2), Err(DagError::EmptyParents));
    }

    #[test]
    fn out_of_order_ingest_recovered() {
        let mut dag = Dag::new();
        let g = genesis_id();
        // child first: parent unknown -> buffered orphan, Err(MissingParent)
        let parent = deposit(vec![g], &sk(1), 1);
        let pid = unit_id(&parent);
        let child = deposit(vec![pid], &sk(1), 2);
        assert_eq!(dag.insert(child.clone()), Err(DagError::MissingParent));
        // retry of the same orphan reports acceptance (still pending)
        assert_eq!(dag.insert(child.clone()), Ok(unit_id(&child)));
        // parent arrives: both become known; after executing the parent the
        // child is linked and ready.
        dag.insert(parent).unwrap();
        assert!(dag.ready_linearized().contains(&pid));
        dag.mark_executed(pid);
        let ready = dag.ready_linearized();
        assert!(ready.contains(&unit_id(&child)), "orphan must be recovered");
    }
}
