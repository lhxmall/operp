pub use operp_account::Account;
use operp_book::{Fill, OrderBook};
use operp_types::{
    bps, notional_usd, sha256, AccountId, Height, MarketId, Price, Seq, UnitId, Usd, BTC_USD,
    INSURANCE_ACCOUNT, INSURANCE_SEED, PRICE_SCALE, TAKER_FEE_BPS, USD_SCALE,
};
use std::collections::{BTreeMap, HashMap, HashSet};

#[derive(Clone, Debug)]
pub struct Withdrawal {
    pub amount: Usd,
    pub pending: bool,
}

#[derive(Clone, Debug)]
pub struct ChainState {
    pub height: Height,
    pub last_unit: UnitId,
    pub seq: Seq,
    pub accounts: BTreeMap<AccountId, Account>,
    pub books: BTreeMap<MarketId, OrderBook>,
    pub marks: BTreeMap<MarketId, Price>,
    pub withdrawals: BTreeMap<(AccountId, u64), Withdrawal>,
    pub seen_aa_units: HashSet<[u8; 32]>,
    pub seen_client_seq: HashMap<AccountId, u64>,
    /// AA deposit events observed on-chain for the pending batch window.
    /// Deposit ops referencing units outside this set are rejected.
    pub deposits_allowed: HashSet<[u8; 32]>,
    /// Markets permitted for trading; place() rejects anything else.
    pub allowed_markets: HashSet<MarketId>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MerkleProof {
    pub leaf: [u8; 32],
    pub siblings: Vec<([u8; 32], bool)>,
    pub root: [u8; 32],
    pub account: AccountId,
    pub collateral: Usd,
}

impl Default for ChainState {
    fn default() -> Self {
        Self::new()
    }
}

impl ChainState {
    pub fn new() -> Self {
        let mut books = BTreeMap::new();
        books.insert(BTC_USD, OrderBook::new(BTC_USD));
        let mut marks = BTreeMap::new();
        marks.insert(BTC_USD, 100_000 * PRICE_SCALE);
        let mut accounts = BTreeMap::new();
        // Insurance fund seeded at genesis; absorbs bad debt and pays keepers.
        let mut insurance = Account::new(INSURANCE_ACCOUNT);
        insurance.collateral = INSURANCE_SEED;
        accounts.insert(INSURANCE_ACCOUNT, insurance);
        Self {
            height: 0,
            last_unit: operp_book_genesis(),
            seq: 0,
            accounts,
            books,
            marks,
            withdrawals: BTreeMap::new(),
            seen_aa_units: HashSet::new(),
            seen_client_seq: HashMap::new(),
            deposits_allowed: HashSet::new(),
            allowed_markets: HashSet::new(),
        }
    }

    pub fn book_mut(&mut self, market: MarketId) -> &mut OrderBook {
        self.books
            .entry(market)
            .or_insert_with(|| OrderBook::new(market))
    }

    pub fn account_mut(&mut self, id: AccountId) -> &mut Account {
        self.accounts.entry(id).or_insert_with(|| Account::new(id))
    }

    pub fn apply_fill_pair(&mut self, fill: &Fill) -> Result<(), operp_account::AccountError> {
        {
            let taker = self.account_mut(fill.taker);
            taker.apply_fill(fill.taker_side, true, fill.price, fill.qty, fill.market)?;
        }
        {
            let maker = self.account_mut(fill.maker);
            maker.apply_fill(
                fill.taker_side.opposite(),
                false,
                fill.price,
                fill.qty,
                fill.market,
            )?;
        }
        // Taker fee: bps of notional debited from the taker's collateral and
        // credited to the insurance fund — the fund's income leg, offsetting
        // bad-debt absorption and keeper payouts. The fee flows through the
        // same Account::apply_fill path the withdrawal-proof leaf commits.
        if fill.taker != INSURANCE_ACCOUNT {
            let fee = bps(notional_usd(fill.qty, fill.price), TAKER_FEE_BPS);
            if fee > 0 {
                if let Some(a) = self.accounts.get_mut(&fill.taker) {
                    a.collateral -= fee;
                }
                self.account_mut(INSURANCE_ACCOUNT).collateral += fee;
            }
        }
        // Bad-debt cap: if the taker went bankrupt (equity < 0), its equity is
        // clamped to exactly 0 (collateral absorbs the hole — realized PnL is
        // settled into collateral since the settlement refactor) and the
        // insurance fund takes an equal debit. A negative insurance balance is
        // explicit socialized debt repaid by future fee income. Conservation
        // holds; a repeat fill cannot re-trigger because equity is now 0.
        // Insurance itself is exempt (never clamped).
        if fill.taker != INSURANCE_ACCOUNT {
            let shortfall = {
                let marks = &self.marks;
                let s = match self.accounts.get(&fill.taker) {
                    Some(a) => a.snapshot(marks),
                    None => return Ok(()),
                };
                if s.equity < 0 { -s.equity } else { 0 }
            };
            if shortfall > 0 {
                if let Some(a) = self.accounts.get_mut(&fill.taker) {
                    a.collateral -= shortfall;
                }
                let ins = self.account_mut(INSURANCE_ACCOUNT);
                ins.collateral -= shortfall;
            }
        }
        // Mark oracle guards: only fills with notional >= 100 USD may move the
        // mark, and then at most ±10% from the previous mark (first qualifying
        // fill on an unmarked market sets it unconditionally). Minimal
        // manipulation resistance until a TWAP oracle lands.
        if notional_usd(fill.qty, fill.price) >= 100 * USD_SCALE as i128 {
            let capped = match self.marks.get(&fill.market) {
                Some(&old) if old > 0 => {
                    let dev = (fill.price as i128 - old as i128).abs();
                    if dev <= old as i128 / 10 { fill.price } else { old }
                }
                _ => fill.price,
            };
            self.marks.insert(fill.market, capped);
        }
        Ok(())
    }

    pub fn leaves(&self) -> Vec<[u8; 32]> {
        let mut leaves = Vec::new();
        for acct in self.accounts.values() {
            leaves.push(account_leaf(acct));
        }
        for book in self.books.values() {
            leaves.push(book_leaf(book));
        }
        leaves.push(meta_leaf(self));
        leaves
    }

    pub fn state_root(&self) -> [u8; 32] {
        merkle_root(self.leaves())
    }

    pub fn account_proof(&self, id: AccountId) -> MerkleProof {
        let acct = self
            .accounts
            .get(&id)
            .cloned()
            .unwrap_or_else(|| Account::new(id));
        let leaf = account_leaf(&acct);
        let leaves = self.leaves();
        let (siblings, root) = merkle_proof_for(leaves, leaf);
        MerkleProof {
            leaf,
            siblings,
            root,
            account: id,
            collateral: acct.collateral,
        }
    }
}

fn operp_book_genesis() -> UnitId {
    UnitId(sha256(b"operp-mvp-1-genesis"))
}

pub fn account_leaf(acct: &Account) -> [u8; 32] {
    let mut b = Vec::new();
    b.extend_from_slice(b"acct");
    b.extend_from_slice(&acct.id.0);
    b.extend_from_slice(&acct.collateral.to_le_bytes());
    b.extend_from_slice(&acct.realized_pnl.to_le_bytes());
    b.extend_from_slice(&(acct.positions.len() as u32).to_le_bytes());
    for (m, p) in &acct.positions {
        b.extend_from_slice(&m.0.to_le_bytes());
        b.extend_from_slice(&p.qty.to_le_bytes());
        b.extend_from_slice(&p.entry_price.to_le_bytes());
    }
    sha256(&b)
}

fn book_leaf(book: &OrderBook) -> [u8; 32] {
    let mut b = Vec::new();
    b.extend_from_slice(b"book");
    b.extend_from_slice(&book.market().0.to_le_bytes());
    let bb = book.best_bid().map(|(p, _)| p).unwrap_or(0);
    let ba = book.best_ask().map(|(p, _)| p).unwrap_or(0);
    b.extend_from_slice(&bb.to_le_bytes());
    b.extend_from_slice(&ba.to_le_bytes());
    b.extend_from_slice(&book.order_count().to_le_bytes());
    sha256(&b)
}

fn meta_leaf(state: &ChainState) -> [u8; 32] {
    let mut b = Vec::new();
    b.extend_from_slice(b"meta");
    b.extend_from_slice(&state.height.to_le_bytes());
    b.extend_from_slice(&state.seq.to_le_bytes());
    b.extend_from_slice(&state.last_unit.0);
    sha256(&b)
}

pub fn merkle_root(mut leaves: Vec<[u8; 32]>) -> [u8; 32] {
    if leaves.is_empty() {
        return sha256(b"empty");
    }
    leaves.sort();
    while leaves.len() > 1 {
        if leaves.len() % 2 == 1 {
            leaves.push(*leaves.last().unwrap());
        }
        let mut next = Vec::with_capacity(leaves.len() / 2);
        for chunk in leaves.chunks(2) {
            let mut c = [0u8; 64];
            c[..32].copy_from_slice(&chunk[0]);
            c[32..].copy_from_slice(&chunk[1]);
            next.push(sha256(&c));
        }
        leaves = next;
    }
    leaves[0]
}

pub fn verify_proof(proof: &MerkleProof) -> bool {
    let mut h = proof.leaf;
    for (sib, right) in &proof.siblings {
        let mut c = [0u8; 64];
        if *right {
            c[..32].copy_from_slice(&h);
            c[32..].copy_from_slice(sib);
        } else {
            c[..32].copy_from_slice(sib);
            c[32..].copy_from_slice(&h);
        }
        h = sha256(&c);
    }
    h == proof.root
}

fn merkle_proof_for(mut leaves: Vec<[u8; 32]>, leaf: [u8; 32]) -> (Vec<([u8; 32], bool)>, [u8; 32]) {
    if leaves.is_empty() {
        return (Vec::new(), sha256(b"empty"));
    }
    leaves.sort();
    let mut idx = match leaves.iter().position(|l| *l == leaf) {
        Some(i) => i,
        None => {
            let root = merkle_root(leaves);
            return (Vec::new(), root);
        }
    };
    let mut siblings = Vec::new();
    let mut level = leaves;
    while level.len() > 1 {
        if level.len() % 2 == 1 {
            level.push(*level.last().unwrap());
        }
        let pair = idx ^ 1;
        let sib = level[pair];
        let right = pair > idx;
        siblings.push((sib, right));
        let mut next = Vec::with_capacity(level.len() / 2);
        for chunk in level.chunks(2) {
            let mut c = [0u8; 64];
            c[..32].copy_from_slice(&chunk[0]);
            c[32..].copy_from_slice(&chunk[1]);
            next.push(sha256(&c));
        }
        idx /= 2;
        level = next;
    }

    (siblings, level[0])
}

/// ---- AA-facing merkle tree (hex-string domain) ----
///
/// Oscript's `sha256()` hashes the UTF-8 string of its argument, so the vault
/// AA can only verify proofs whose nodes are hashes of concatenated hex
/// strings. Leaves are keyed by the WITHDRAWAL ADDRESS (an Obyte address
/// string — the same value the AA compares `leaf_account` against):
///   leaf  = sha256_hex("acct:" || address || ":" || collateral_decimal)
///   node  = sha256_hex(left_hex || right_hex)

pub fn aa_account_leaf_str(addr: &str, collateral: Usd) -> String {
    let s = format!("acct:{}:{}", addr, collateral);
    hex::encode(sha256(s.as_bytes()))
}

fn aa_parent(l: &str, r: &str) -> String {
    let mut buf = String::with_capacity(l.len() + r.len());
    buf.push_str(l);
    buf.push_str(r);
    hex::encode(sha256(buf.as_bytes()))
}

/// Root of the hex-domain tree over (address, collateral) pairs.
pub fn aa_root_of(pairs: &[(String, Usd)]) -> String {
    let mut level: Vec<String> = pairs
        .iter()
        .map(|(addr, col)| aa_account_leaf_str(addr, *col))
        .collect();
    if level.is_empty() {
        return hex::encode(sha256(b"empty"));
    }
    level.sort();
    while level.len() > 1 {
        if level.len() % 2 == 1 {
            let last = level.last().unwrap().clone();
            level.push(last);
        }
        level = level.chunks(2).map(|c| aa_parent(&c[0], &c[1])).collect();
    }
    level[0].clone()
}

/// Proof path for one address in the hex-domain tree over `pairs`.
pub fn aa_proof_for(
    pairs: &[(String, Usd)],
    addr: &str,
) -> Option<(Vec<(String, bool)>, String)> {
    let mut level: Vec<String> = pairs
        .iter()
        .map(|(a, c)| aa_account_leaf_str(a, *c))
        .collect();
    let leaf = aa_account_leaf_str(addr, pairs.iter().find(|(a, _)| a == addr)?.1);
    level.sort();
    let mut idx = level.iter().position(|l| *l == leaf)?;
    let mut siblings = Vec::new();
    while level.len() > 1 {
        if level.len() % 2 == 1 {
            let last = level.last().unwrap().clone();
            level.push(last);
        }
        let pair = idx ^ 1;
        siblings.push((level[pair].clone(), pair > idx));
        level = level.chunks(2).map(|c| aa_parent(&c[0], &c[1])).collect();
        idx /= 2;
    }
    Some((siblings, level[0].clone()))
}

/// Root of the hex-domain tree over the sidechain accounts, keyed by each
/// account's id hex (engine-side convenience wrapper).
pub fn aa_root_of_state(state: &ChainState) -> String {
    let pairs: Vec<(String, Usd)> = state
        .accounts
        .values()
        .map(|a| (hex::encode(a.id.0), a.collateral))
        .collect();
    aa_root_of(&pairs)
}

/// Proof path for one sidechain account (id hex key).
pub fn aa_proof_for_account(
    state: &ChainState,
    id: &AccountId,
) -> Option<(Vec<(String, bool)>, String)> {
    let pairs: Vec<(String, Usd)> = state
        .accounts
        .values()
        .map(|a| (hex::encode(a.id.0), a.collateral))
        .collect();
    aa_proof_for(&pairs, &hex::encode(id.0))
}

#[cfg(test)]
mod tests {
    use super::*;
    use operp_types::USD_SCALE;

    #[test]
    fn merkle_proof_roundtrip() {
        let mut s = ChainState::new();
        let id = AccountId([1; 32]);
        s.account_mut(id).credit(10 * USD_SCALE as i128).unwrap();
        let p = s.account_proof(id);
        assert!(verify_proof(&p));
        assert_eq!(p.root, s.state_root());
        let other = AccountId([2; 32]);
        let p2 = s.account_proof(other);
        assert_ne!(p2.leaf, p.leaf);
    }

    #[test]
    fn taker_fee_flows_to_insurance() {
        let mut s = ChainState::new();
        let taker = AccountId([9; 32]);
        let maker = AccountId([8; 32]);
        s.account_mut(taker).credit(1_000_000 * USD_SCALE as i128).unwrap();
        s.account_mut(maker).credit(1_000_000 * USD_SCALE as i128).unwrap();
        let px = 100_000 * operp_types::PRICE_SCALE;
        let fill = Fill {
            taker_id: operp_types::OrderId([0u8; 32]),
            maker_id: operp_types::OrderId([0u8; 32]),
            taker,
            maker,
            market: BTC_USD,
            price: px,
            qty: operp_types::QTY_SCALE,
            seq: 1,
            taker_side: operp_types::Side::Bid,
        };
        s.apply_fill_pair(&fill).unwrap();
        // notional = 100_000 USD → fee @5bps = 50 USD credited to insurance.
        let ins = &s.accounts[&INSURANCE_ACCOUNT];
        assert_eq!(ins.collateral, INSURANCE_SEED + 50 * USD_SCALE as i128);
    }

    #[test]
    fn mark_deviation_cap() {
        let mut s = ChainState::new();
        let taker = AccountId([9; 32]);
        let maker = AccountId([8; 32]);
        for id in [taker, maker] {
            s.account_mut(id).credit(10_000_000 * USD_SCALE as i128).unwrap();
        }
        let mk_fill = |price| Fill {
            taker_id: operp_types::OrderId([0u8; 32]),
            maker_id: operp_types::OrderId([0u8; 32]),
            taker,
            maker,
            market: BTC_USD,
            price,
            qty: operp_types::QTY_SCALE,
            seq: 1,
            taker_side: operp_types::Side::Bid,
        };
        // +200% spike: rejected by the ±10% cap — mark stays at genesis.
        s.apply_fill_pair(&mk_fill(300_000 * operp_types::PRICE_SCALE)).unwrap();
        assert_eq!(*s.marks.get(&BTC_USD).unwrap(), 100_000 * operp_types::PRICE_SCALE);
        // +5% move: within the band — mark updates.
        s.apply_fill_pair(&mk_fill(105_000 * operp_types::PRICE_SCALE)).unwrap();
        assert_eq!(*s.marks.get(&BTC_USD).unwrap(), 105_000 * operp_types::PRICE_SCALE);
    }
}
