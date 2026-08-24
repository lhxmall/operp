pub use operp_account::Account;
use operp_book::{Fill, OrderBook};
use operp_types::{
    bps, genesis_params, notional_usd, sha256, AccountId, Height, MarketId, MarketParams,
    Price, Seq, UnitId, Usd, BTC_USD, INSURANCE_ACCOUNT, INSURANCE_SEED, PRICE_SCALE, USD_SCALE,
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
    /// Per-market parameters (permissionless markets included). BTC_USD is
    /// seeded at genesis; CreateMarket appends.
    pub markets: BTreeMap<MarketId, MarketParams>,
    /// Next market id to allocate (BTC_USD=1 is taken at genesis).
    pub next_market_id: u32,
    pub books: BTreeMap<MarketId, OrderBook>,
    pub marks: BTreeMap<MarketId, Price>,
    /// Latest report per (market, reporter). Only bonded reporters get in
    /// (apply_report ignores everyone else).
    pub oracle_reports: BTreeMap<(MarketId, AccountId), Price>,
    /// PERP oracle bonds currently staked. Presence = reporting eligibility.
    pub oracle_bonds: BTreeMap<AccountId, u128>,
    /// Unclamped median of current reports — the funding-rate index.
    pub last_index: BTreeMap<MarketId, Price>,
    /// Sidechain-mirrored PERP balances (governance token).
    pub perp_balances: BTreeMap<AccountId, u128>,
    /// Redeemable circulating PERP = Σ deposits − withdrawals − burns.
    pub perp_supply: u128,
    /// Cumulative PERP burned (market listing fees, future slashes). The
    /// real tokens stay escrowed in the vault AA forever — claimable
    /// deflation; no on-chain sweep.
    pub perp_burned: u128,
    /// On-chain governance proposals keyed by id.
    pub proposals: BTreeMap<u64, Proposal>,
    /// Next proposal id to allocate.
    pub next_proposal_id: u64,
    pub withdrawals: BTreeMap<(AccountId, u64), Withdrawal>,
    pub seen_aa_units: HashSet<[u8; 32]>,
    pub seen_client_seq: HashMap<AccountId, u64>,
    /// AA deposit events observed on-chain for the pending batch window.
    /// Deposit ops referencing units outside this set are rejected.
    pub deposits_allowed: HashSet<[u8; 32]>,
    /// Consumed GovWithdraw nonces: replay protection for PERP withdrawals.
    pub seen_gov_nonces: HashSet<(AccountId, u64)>,
}

/// An open governance proposal. `deadline_seq` and the quorum denominator
/// snapshot (`supply_at_create`) are fixed at creation so replayed batches
/// finalize identically. Voting weight is the voter's PERP balance at vote
/// execution time (MVP semantics); `supply_at_create` shrinks with burns.
#[derive(Clone, Debug)]
pub struct Proposal {
    pub creator: AccountId,
    pub market: MarketId,
    pub key: operp_types::ParamKey,
    pub value: u64,
    pub created_seq: Seq,
    pub deadline_seq: Seq,
    pub supply_at_create: u128,
    pub yes: u128,
    pub no: u128,
    pub voted: HashSet<AccountId>,
    /// None = open; Some(true) = passed & applied; Some(false) = rejected.
    pub finalized: Option<bool>,
}

#[derive(Debug, thiserror::Error)]
pub enum StateError {
    #[error("insufficient PERP balance")]
    InsufficientPerp,
    #[error("unknown market")]
    UnknownMarket,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MerkleProof {
    pub leaf: [u8; 32],
    pub siblings: Vec<([u8; 32], bool)>,
    pub root: [u8; 32],
    pub account: AccountId,
    pub collateral: Usd,
    /// Mirrored PERP balance committed by the leaf.
    pub perp: u128,
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
        let mut markets = BTreeMap::new();
        markets.insert(BTC_USD, genesis_params());
        Self {
            height: 0,
            last_unit: operp_book_genesis(),
            seq: 0,
            accounts,
            markets,
            next_market_id: 2,
            books,
            marks,
            oracle_reports: BTreeMap::new(),
            oracle_bonds: BTreeMap::new(),
            last_index: BTreeMap::new(),
            perp_balances: BTreeMap::new(),
            perp_supply: 0,
            perp_burned: 0,
            proposals: BTreeMap::new(),
            next_proposal_id: 1,
            withdrawals: BTreeMap::new(),
            seen_aa_units: HashSet::new(),
            seen_client_seq: HashMap::new(),
            deposits_allowed: HashSet::new(),
            seen_gov_nonces: HashSet::new(),
        }
    }

    /// Apply a bonded oracle's report for `market` and recompute the effective
    /// mark as the median of all current bonded reporters, subject to the
    /// ±10% deviation cap vs the previous mark (the first report for a market
    /// sets the mark unconditionally). Fills no longer move the mark for
    /// markets where any bonded reporter has spoken. Zero prices and unbonded
    /// reporters are ignored defensively — the exec layer pre-validates bonds.
    pub fn apply_report(
        &mut self,
        oracle: AccountId,
        market: MarketId,
        price: Price,
    ) -> Result<(), StateError> {
        if price == 0 || !self.oracle_bonds.contains_key(&oracle) {
            return Ok(());
        }
        self.oracle_reports.insert((market, oracle), price);
        // Median over reporters that hold BOTH a bond and a current report
        // for this market. sorted[(len-1)/2] is the exact middle when the
        // count is odd and the smaller middle when even — deterministic in
        // both cases, no rounding drift.
        let mut prices: Vec<Price> = self
            .oracle_reports
            .iter()
            .filter(|((m, o), _)| *m == market && self.oracle_bonds.contains_key(o))
            .map(|(_, p)| *p)
            .collect();
        if prices.is_empty() {
            return Ok(());
        }
        prices.sort();
        let median = prices[(prices.len() - 1) / 2];
        // Funding index: unclamped median, so the premium reflects true
        // reporter consensus even while the spot mark lags behind the cap.
        self.last_index.insert(market, median);
        let capped = match self.marks.get(&market) {
            Some(&old) if old > 0 => {
                let dev = (median as i128 - old as i128).abs();
                if dev <= old as i128 / 10 { median } else { old }
            }
            _ => median,
        };
        self.marks.insert(market, capped);
        // Funding: once at least two valid reports exist, every report tick
        // settles peer-to-peer funding.
        // premium_bps = (spot − index)/index, clamped to ±FUNDING_CAP_BPS.
        // Signed per-position payment: longs (qty>0) pay when spot > index,
        // shorts receive; mirrored when spot < index. Two-phase so that
        // payments can never drive an account's collateral negative and
        // conservation holds exactly:
        //   Phase 1 computes each account's signed payment (unchanged formula).
        //   Phase 2a debits payers min(payment, collateral.max(0)) — no account
        //     goes negative from funding; total debited forms the budget.
        //   Phase 2b credits receivers their computed receipt, capped at the
        //     budget, in ascending AccountId order (BTreeMap iteration order,
        //     so fully deterministic across replays); the last receiver may be
        //     paid partially. Integer arithmetic only, no rounding drift.
        // Insurance participates like any other account (it can hold
        // positions). Truncation residue is sub-unit dust by design.
        if prices.len() >= 2 {
            let index = median as i128;
            let spot = capped as i128;
            if index > 0 {
                let diff_bps = ((spot - index) * 10_000 / index).clamp(
                    -(operp_types::FUNDING_CAP_BPS as i128),
                    operp_types::FUNDING_CAP_BPS as i128,
                );
                if diff_bps != 0 {
                    // Phase 1: signed payments in ascending AccountId order.
                    let payments: Vec<(AccountId, i128)> = self
                        .accounts
                        .iter()
                        .filter_map(|(id, a)| {
                            a.positions.get(&market).map(|pos| {
                                (*id, operp_types::signed_notional_usd(pos.qty, median) * diff_bps / 10_000)
                            })
                        })
                        .filter(|(_, p)| *p != 0)
                        .collect();
                    // Phase 2a: debit payers, clamped at non-negative collateral.
                    let mut budget: i128 = 0;
                    for (id, payment) in &payments {
                        if *payment <= 0 {
                            continue;
                        }
                        if let Some(a) = self.accounts.get_mut(id) {
                            let debit = (*payment).min(a.collateral.max(0));
                            a.collateral -= debit;
                            budget += debit;
                        }
                    }
                    // Phase 2b: credit receivers until the budget is spent.
                    for (id, payment) in &payments {
                        if budget == 0 {
                            break;
                        }
                        if *payment >= 0 {
                            continue;
                        }
                        let want = -*payment;
                        let credit = want.min(budget);
                        if let Some(a) = self.accounts.get_mut(id) {
                            a.collateral += credit;
                        }
                        budget -= credit;
                    }
                }
            }
        }
        Ok(())
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
        // The rate is a per-market parameter since permissionless listing.
        if fill.taker != INSURANCE_ACCOUNT {
            let fee_bps = self.market_params(fill.market).taker_fee_bps;
            let fee = bps(notional_usd(fill.qty, fill.price), fee_bps);
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
        // Mark oracle guards: fills move the mark only for markets where NO
        // bonded reporter has spoken yet (oracles are authoritative once
        // present), the notional is >= 100 USD, and the move is within ±10%
        // of the previous mark (first qualifying fill sets unconditionally).
        if notional_usd(fill.qty, fill.price) >= 100 * USD_SCALE as i128
            && !self
                .oracle_reports
                .keys()
                .any(|(m, o)| *m == fill.market && self.oracle_bonds.contains_key(o))
        {
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
            let perp = self
                .perp_balances
                .get(&acct.id)
                .copied()
                .unwrap_or(0);
            leaves.push(account_leaf(acct, perp));
        }
        for book in self.books.values() {
            leaves.push(book_leaf(book, &self.markets));
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
        let perp = self.perp_balances.get(&id).copied().unwrap_or(0);
        let leaf = account_leaf(&acct, perp);
        let leaves = self.leaves();
        let (siblings, root) = merkle_proof_for(leaves, leaf);
        MerkleProof {
            leaf,
            siblings,
            root,
            account: id,
            collateral: acct.collateral,
            perp,
        }
    }

    /// PERP balance of `who` (0 when the account never deposited).
    pub fn perp_balance(&self, who: AccountId) -> u128 {
        self.perp_balances.get(&who).copied().unwrap_or(0)
    }

    /// Params snapshot for `m`; panics on unknown markets, which cannot
    /// exist for markets created at genesis or via CreateMarket, which exec
    /// guarantees before reaching any state path that needs params.
    pub fn market_params(&self, m: MarketId) -> MarketParams {
        self.markets[&m].clone()
    }
}

pub fn account_leaf(acct: &Account, perp: u128) -> [u8; 32] {
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
    // Mirrored PERP balance: the vault AA's hex-domain leaf commits the same
    // triple (address, collateral, perp), so both trees cover PERP claims.
    b.extend_from_slice(&perp.to_le_bytes());
    sha256(&b)
}

/// Fixed-width per-market params encoding committed by the book leaf:
/// symbol[16] || tick le8 || im le8 || mm le8 || taker_fee le8 ||
/// keeper_reward le8 || delisted byte — 57 bytes total. Books are created
/// lazily only for markets that already have params.
fn market_params_bytes(p: &MarketParams) -> [u8; 57] {
    let mut b = [0u8; 57];
    b[..16].copy_from_slice(&p.symbol);
    b[16..24].copy_from_slice(&p.tick_size.to_le_bytes());
    b[24..32].copy_from_slice(&p.im_bps.to_le_bytes());
    b[32..40].copy_from_slice(&p.mm_bps.to_le_bytes());
    b[40..48].copy_from_slice(&p.taker_fee_bps.to_le_bytes());
    b[48..56].copy_from_slice(&p.keeper_reward_bps.to_le_bytes());
    b[56] = p.delisted as u8;
    b
}

fn book_leaf(book: &OrderBook, markets: &BTreeMap<MarketId, MarketParams>) -> [u8; 32] {
    // Full-book commitment: every level and every live order (see
    // OrderBook::commitment_bytes), not just best bid/ask/count — prefixed
    // with the market's params so the root also commits governance state.
    let p = markets
        .get(&book.market())
        .unwrap_or_else(|| panic!("book without params for market {}", book.market().0));
    let mut b = Vec::with_capacity(57 + book.commitment_bytes().len());
    b.extend_from_slice(&market_params_bytes(p));
    b.extend_from_slice(&book.commitment_bytes());
    sha256(&b)
}

fn meta_leaf(state: &ChainState) -> [u8; 32] {
    let mut b = Vec::new();
    b.extend_from_slice(b"meta");
    b.extend_from_slice(&state.height.to_le_bytes());
    b.extend_from_slice(&state.seq.to_le_bytes());
    b.extend_from_slice(&state.last_unit.0);
    // Governance cursors: committing them removes replay ambiguity between
    // batches that differ only in burn totals or id allocation.
    b.extend_from_slice(&state.perp_burned.to_le_bytes());
    b.extend_from_slice(&state.next_market_id.to_le_bytes());
    b.extend_from_slice(&state.next_proposal_id.to_le_bytes());
    sha256(&b)
}

fn operp_book_genesis() -> UnitId {
    UnitId(sha256(b"operp-mvp-1-genesis"))
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
///   leaf  = sha256_hex("acct:" || address || ":" || collateral_decimal
///                      || ":" || perp_decimal)
///   node  = sha256_hex(left_hex || right_hex)

pub fn aa_account_leaf_str(addr: &str, collateral: Usd, perp: u128) -> String {
    let s = format!("acct:{}:{}:{}", addr, collateral, perp);
    hex::encode(sha256(s.as_bytes()))
}


fn aa_parent(l: &str, r: &str) -> String {
    let mut buf = String::with_capacity(l.len() + r.len());
    buf.push_str(l);
    buf.push_str(r);
    hex::encode(sha256(buf.as_bytes()))
}

/// Root of the hex-domain tree over (address, collateral, perp) triples.
pub fn aa_root_of(pairs: &[(String, Usd, u128)]) -> String {
    let mut level: Vec<String> = pairs
        .iter()
        .map(|(addr, col, perp)| aa_account_leaf_str(addr, *col, *perp))
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
    pairs: &[(String, Usd, u128)],
    addr: &str,
) -> Option<(Vec<(String, bool)>, String)> {
    let mut level: Vec<String> = pairs
        .iter()
        .map(|(a, c, p)| aa_account_leaf_str(a, *c, *p))
        .collect();
    let leaf = aa_account_leaf_str(
        addr,
        pairs.iter().find(|(a, _, _)| a == addr)?.1,
        pairs.iter().find(|(a, _, _)| a == addr)?.2,
    );
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
    let pairs: Vec<(String, Usd, u128)> = state
        .accounts
        .values()
        .map(|a| {
            (
                hex::encode(a.id.0),
                a.collateral,
                state.perp_balances.get(&a.id).copied().unwrap_or(0),
            )
        })
        .collect();
    aa_root_of(&pairs)
}

pub fn aa_proof_for_account(
    state: &ChainState,
    id: &AccountId,
) -> Option<(Vec<(String, bool)>, String)> {
    let pairs: Vec<(String, Usd, u128)> = state
        .accounts
        .values()
        .map(|a| {
            (
                hex::encode(a.id.0),
                a.collateral,
                state.perp_balances.get(&a.id).copied().unwrap_or(0),
            )
        })
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

    #[test]
    fn funding_transfers_long_to_short_and_conserves() {
        let mut s = ChainState::new();
        let long = AccountId([9; 32]);
        let short = AccountId([8; 32]);
        s.account_mut(long).credit(1_000_000 * USD_SCALE as i128).unwrap();
        s.account_mut(short).credit(1_000_000 * USD_SCALE as i128).unwrap();

        // Both open 1 BTC at 100_000 via a fill (spot mark = index initially).
        let px = 100_000 * operp_types::PRICE_SCALE;
        let fill = Fill {
            taker_id: operp_types::OrderId([0u8; 32]),
            maker_id: operp_types::OrderId([0u8; 32]),
            taker: long,
            maker: short,
            market: BTC_USD,
            price: px,
            qty: operp_types::QTY_SCALE,
            seq: 1,
            taker_side: operp_types::Side::Bid,
        };
        s.apply_fill_pair(&fill).unwrap();

        // Bonded oracles report; funding settles once >= 2 reports exist.
        // Tick 1 at spot: single report → median 100k, mark unchanged,
        // no funding yet.
        let oa = AccountId([5; 32]);
        let ob = AccountId([6; 32]);
        s.oracle_bonds.insert(oa, operp_types::ORACLE_BOND_PERP);
        s.oracle_bonds.insert(ob, operp_types::ORACLE_BOND_PERP);
        s.apply_report(oa, BTC_USD, 100_000 * operp_types::PRICE_SCALE)
            .unwrap();
        let pre_funding =
            s.accounts[&long].collateral + s.accounts[&short].collateral;

        // Tick 2: reports {89k, 100k}; median = sorted[(len-1)/2] = 89k
        // (the smaller middle when even). |89k − 100k| = 11k > 10k, so the
        // ±10% cap holds the spot mark at 100k while the index drops to
        // 89k: premium > 0 → long pays short.
        s.apply_report(ob, BTC_USD, 89_000 * operp_types::PRICE_SCALE)
            .unwrap();

        let long_bal = s.accounts[&long].collateral;
        let short_bal = s.accounts[&short].collateral;
        // Long paid, short received (premium > 0).
        assert!(long_bal < short_bal, "long must fund short in premium");
        // Peer-to-peer funding must conserve collateral (sub-unit dust at
        // most): nothing leaks to or from other accounts here.
        assert!(
            pre_funding - (long_bal + short_bal) < USD_SCALE as i128,
            "funding must conserve total collateral"
        );
    }
}
