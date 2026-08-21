use ed25519_dalek::{Signature, Verifier, VerifyingKey};
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
    Liquidate {
        target: AccountId,
        market: MarketId,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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
        Op::Liquidate { target, market } => {
            b.push(5);
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
    let sig = Signature::from_bytes(&unit.sig);
    let id = unit_id(unit);
    vk.verify(&id.0, &sig).is_ok() && account_matches(unit)
}

fn account_matches(unit: &Unit) -> bool {
    let expected = account_id_from_pubkey(&unit.pubkey);
    match &unit.op {
        Op::Place { account, .. }
        | Op::Cancel { account, .. }
        | Op::Deposit { account, .. }
        | Op::Withdraw { account, .. } => *account == expected,
        Op::Liquidate { .. } => true,
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
}

impl Dag {
    pub fn new() -> Self {
        let mut executed = HashSet::new();
        executed.insert(genesis_id());
        Self {
            units: HashMap::new(),
            children: HashMap::new(),
            executed,
        }
    }

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
        for p in &unit.parents {
            if !self.known(*p) {
                return Err(DagError::MissingParent);
            }
        }
        let id = unit_id(&unit);
        if self.units.contains_key(&id) {
            return Err(DagError::Duplicate);
        }
        for p in &unit.parents {
            self.children.entry(*p).or_default().push(id);
        }
        self.units.insert(id, unit);
        Ok(id)
    }

    fn known(&self, id: UnitId) -> bool {
        id == genesis_id() || self.units.contains_key(&id)
    }

    pub fn ready_linearized(&self) -> Vec<UnitId> {
        let mut ready: Vec<UnitId> = self
            .units
            .keys()
            .copied()
            .filter(|id| !self.executed.contains(id))
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
}
