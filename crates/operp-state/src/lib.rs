pub use operp_account::Account;
use operp_book::{Fill, OrderBook};
use operp_types::{
    bps, genesis_params, notional_usd, sha256, AccountId, ExternalSample, FundingSourceKind,
    Height, MarketId, MarketParams, OracleConfig, Price, ReportSample, Seq, TwapSample, UnitId,
    Usd, BTC_USD, FUNDING_EXTERNAL_MAX_STALENESS, FUNDING_TWAP_MIN_SAMPLES, FUNDING_TWAP_WINDOW,
    INSURANCE_ACCOUNT, INSURANCE_SEED, PRICE_SCALE, USD_SCALE,
};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
pub mod journal;
pub mod obyte_merkle;
pub mod persist;
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Withdrawal {
    pub amount: Usd,
    pub pending: bool,
    /// Batch height at which this withdrawal was signed in; drives the
    /// 256-height replay-protection window enforced by `prune_withdrawals`.
    pub height: Height,
}
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
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
    pub seen_aa_units: HashMap<[u8; 32], Height>,
    pub seen_client_seq: HashMap<AccountId, u64>,
    /// AA deposit events observed on-chain for the pending batch window,
    /// keyed by (unit, is_perp): a unit endorsing USDC collateral and one
    /// endorsing PERP are distinct entries. Deposit ops referencing units
    /// outside this set are rejected.
    pub deposits_allowed: HashSet<([u8; 32], bool)>,
    /// Highest consumed GovWithdraw nonce per account: strict watermark —
    /// nonces must be strictly increasing per account (`nonce <= watermark`
    /// bounces). Bounded by the account count, unlike a spent-nonce set.
    pub seen_gov_nonces: HashMap<AccountId, u64>,
    /// Obyte withdrawal address bound to each account at its first deposit.
    /// The AA-facing tree keys leaves by this address; unbound accounts are
    /// not representable on the AA side and are excluded from it.
    pub aa_addresses: BTreeMap<AccountId, String>,
    /// Cumulative sidechain-signed withdrawal amount per account (i128 to
    /// match Usd). Committed inside the binary account leaf as `W` so the
    /// vault AA can enforce "this claim + prior claims <= W".
    pub withdrawn_total: BTreeMap<AccountId, i128>,
    /// Last finalized AA root (for salted ordering). Genesis = sha256(b"operp-mvp-1-genesis").
    pub last_finalized_root: [u8; 32],
    pub last_finalized_height: Height,
    // -----------------------------------------------------------------------
    // Oracle bonding / TWAP / funding extension (Step5)
    /// Per-market oracle config (empty = default).
    pub oracle_configs: BTreeMap<MarketId, OracleConfig>,
    /// Per (market, reporter) last-K price history for streak detection. Bounded at 8.
    pub oracle_report_history: BTreeMap<(MarketId, AccountId), VecDeque<ReportSample>>,
    /// Per-market median TWAP ring (oracle TWAP).
    pub oracle_twap: BTreeMap<MarketId, VecDeque<TwapSample>>,
    /// Per-market funding TWAP ring (funding index anchor) — v1 mirrors oracle_twap.
    pub funding_twap: BTreeMap<MarketId, VecDeque<TwapSample>>,
    /// Cached funding TWAP per market (mean of funding_twap).
    pub funding_index_twap: BTreeMap<MarketId, Price>,
    /// Funding source selector.
    pub funding_source: FundingSourceKind,
    /// Unbonding queue: reporter -> unlock height.
    pub oracle_unbonding: BTreeMap<AccountId, Height>,
    /// Slash nonce counter for replay/debug (committed in meta leaf).
    pub oracle_slash_nonce: u64,
    /// Pending commit-reveal commits keyed by commit hash (doc 03 §2.3.3).
    pub commits: BTreeMap<[u8; 32], CommitEntry>,
    /// External keeper price ring (doc 06 §2.3). Empty in BondedMedianTwap.
    pub external_price_ring: BTreeMap<MarketId, VecDeque<ExternalSample>>,
    /// Keeper accounts allowed to post `UpdateExternalPrice` (governed).
    pub external_sources: BTreeSet<AccountId>,
}

/// A registered commit-reveal commitment (doc 03 §2.3.3). `commit_unit`
/// records the Commit unit's id so Reveal parent-edge enforcement (doc
/// §2.3.4) can require the reveal to descend from its commit.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CommitEntry {
    pub account: AccountId,
    pub commit_unit: UnitId,
    pub commit_height: Height,
    pub ttl_height: Height,
    pub revealed: bool,
}

/// An open governance proposal. `deadline_seq` and the quorum denominator
/// snapshot (`supply_at_create`) are fixed at creation so replayed batches
/// finalize identically. Voting weight is the voter's PERP balance snapshotted
/// at proposal creation (`weight_snapshot`); burning after creation cannot
/// shrink a committed vote or dodge quorum.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
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
    /// PERP balances cloned when the proposal was created; vote weights read
    /// from here, never from live balances.
    pub weight_snapshot: BTreeMap<AccountId, u128>,
}

#[derive(Debug, thiserror::Error)]
pub enum StateError {
    #[error("insufficient PERP balance")]
    InsufficientPerp,
    #[error("unknown market")]
    UnknownMarket,
    #[error("already bonded")]
    AlreadyBonded,
    #[error("not bonded")]
    NotBonded,
    #[error("unbonding")]
    Unbonding,
    #[error("slash not eligible")]
    SlashNotEligible,
    #[error("not found")]
    NotFound,
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
    /// Cumulative withdrawn amount committed by the leaf (the AA-side `W`).
    pub withdrawn: i128,
    /// Realized PnL committed by the leaf; carried so `check_withdraw` can
    /// recompute the exact leaf preimage from the proof alone.
    pub realized_pnl: Usd,
    /// Open positions committed by the leaf (qty, entry_price per market);
    /// carried for the same leaf-preimage recomputation.
    pub positions: BTreeMap<MarketId, (i64, Price)>,
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
            withdrawals: BTreeMap::new(),
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
            commits: BTreeMap::new(),
            external_price_ring: BTreeMap::new(),
            external_sources: BTreeSet::new(),
            next_proposal_id: 1,
            seen_aa_units: HashMap::new(),
            seen_client_seq: HashMap::new(),
            deposits_allowed: HashSet::new(),
            seen_gov_nonces: HashMap::new(),
            aa_addresses: BTreeMap::new(),
            withdrawn_total: BTreeMap::new(),
            last_finalized_root: sha256(b"operp-mvp-1-genesis"),
            last_finalized_height: 0,
            oracle_configs: BTreeMap::new(),
            oracle_report_history: BTreeMap::new(),
            oracle_twap: BTreeMap::new(),
            funding_twap: BTreeMap::new(),
            funding_index_twap: BTreeMap::new(),
            funding_source: FundingSourceKind::default(),
            oracle_unbonding: BTreeMap::new(),
            oracle_slash_nonce: 0,
        }
    }
    /// General window prune (new path, activation-gated). Legacy wrappers below.
    pub fn prune_withdrawals_at(&mut self, min_height: Height, window: u64) {
        self.withdrawals
            .retain(|_, w| w.height + window > min_height);
    }
    pub fn prune_aa_units_at(&mut self, min_height: Height, window: u64) {
        self.seen_aa_units.retain(|_, h| *h + window > min_height);
    }
    pub fn prune_deposits_allowed_at(&mut self, min_height: Height, window: u64) {
        let seen = &self.seen_aa_units;
        self.deposits_allowed.retain(|(unit, _)| {
            if let Some(h) = seen.get(unit) {
                *h + window > min_height
            } else {
                false
            }
        });
    }
    /// Legacy wrappers for replay determinism pre-activation (window=256)
    pub fn prune_withdrawals(&mut self, min_height: Height) {
        let window = if self.height >= operp_types::REPLAY_ACTIVATION_HEIGHT {
            operp_types::REPLAY_WINDOW
        } else {
            operp_types::REPLAY_WINDOW_LEGACY
        };
        self.prune_withdrawals_at(min_height, window);
    }
    /// Bounded-window cleanup for AA unit dedup: units observed at height
    /// `h` expire once `min_height >= h + window`. Called at batch commit.
    pub fn prune_aa_units(&mut self, min_height: Height) {
        let window = if self.height >= operp_types::REPLAY_ACTIVATION_HEIGHT {
            operp_types::REPLAY_WINDOW
        } else {
            operp_types::REPLAY_WINDOW_LEGACY
        };
        self.prune_aa_units_at(min_height, window);
    }
    pub fn prune_deposits_allowed(&mut self, min_height: Height) {
        let window = if self.height >= operp_types::REPLAY_ACTIVATION_HEIGHT {
            operp_types::REPLAY_WINDOW
        } else {
            operp_types::REPLAY_WINDOW_LEGACY
        };
        // Ensure aa_units pruned first so missing-seen means expired
        self.prune_deposits_allowed_at(min_height, window);
    }
    pub fn note_finalized(&mut self, root: [u8; 32], height: Height) {
        self.last_finalized_root = root;
        self.last_finalized_height = height;
    }

    // -----------------------------------------------------------------------
    // Oracle config / TWAP helpers
    pub fn oracle_config(&self, market: MarketId) -> OracleConfig {
        self.oracle_configs
            .get(&market)
            .copied()
            .unwrap_or_default()
    }

    fn record_twap_sample(&mut self, market: MarketId, median: Price, seq: Seq) {
        let cfg = self.oracle_config(market);
        let window_len = cfg.twap_window as usize;
        // Cap window_len to max to avoid unbounded growth if governance mis-sets
        let cap = window_len.min(operp_types::ORACLE_TWAP_MAX as usize).max(2);
        let q = self.oracle_twap.entry(market).or_default();
        if q.back().map(|s| s.height == self.height).unwrap_or(false) {
            // Same height: overwrite median if different (multiple reporters same batch)
            if q.back().unwrap().median != median {
                let back = q.back_mut().unwrap();
                back.median = median;
                back.seq = seq;
            } else {
                return;
            }
        } else {
            q.push_back(TwapSample {
                seq,
                height: self.height,
                median,
            });
            while q.len() > cap {
                q.pop_front();
            }
        }
        // Mirror into funding_twap and cache funding_index_twap for effective_funding_index.
        // Doc 06 §2.4: dedup same-height-same-median so multiple reporters in one batch
        // don't double-count; a different median at the same height overwrites (last wins).
        let fq = self.funding_twap.entry(market).or_default();
        if fq.back().map(|s| s.height == self.height).unwrap_or(false) {
            if fq.back().unwrap().median != median {
                let back = fq.back_mut().unwrap();
                back.median = median;
                back.seq = seq;
            }
        } else {
            fq.push_back(TwapSample {
                seq,
                height: self.height,
                median,
            });
            while fq.len() > FUNDING_TWAP_WINDOW as usize {
                fq.pop_front();
            }
        }
        if let Some(twap) = self.compute_twap(market) {
            self.funding_index_twap.insert(market, twap);
        }
        if let Some(ftwap) = self.compute_funding_twap(market) {
            self.funding_index_twap.insert(market, ftwap);
        }
    }

    /// Record an external keeper tick (doc 06 §2.6): allowlist + live-market +
    /// positive-price gated by the caller; ring capped at the funding window.
    pub fn apply_external_price(
        &mut self,
        _source: AccountId,
        market: MarketId,
        price: Price,
        source_id: u8,
        seq: Seq,
    ) {
        let q = self.external_price_ring.entry(market).or_default();
        q.push_back(ExternalSample {
            seq,
            height: self.height,
            price,
            source_id,
        });
        while q.len() > FUNDING_TWAP_WINDOW as usize {
            q.pop_front();
        }
    }

    /// TWAP over the external keeper ring (doc 06 §2.6 rule 2): requires
    /// MIN_SAMPLES and freshness within FUNDING_EXTERNAL_MAX_STALENESS so a
    /// dead feed falls back instead of freezing funding.
    pub fn external_twap(&self, market: MarketId) -> Option<Price> {
        let q = self.external_price_ring.get(&market)?;
        if q.len() < FUNDING_TWAP_MIN_SAMPLES {
            return None;
        }
        let last = q.back()?;
        if last.height + FUNDING_EXTERNAL_MAX_STALENESS <= self.height {
            return None;
        }
        let sum: u128 = q.iter().map(|s| s.price as u128).sum();
        Some((sum / q.len() as u128) as Price)
    }

    /// Bounded cleanup for expired commit-reveal commitments: entries whose
    /// reveal deadline has passed are dropped at batch commit (doc 03 §2.3.3
    /// rule 4). Length is additionally bounded by the per-account cap.
    pub fn prune_commits(&mut self, min_height: Height) {
        self.commits.retain(|_, e| e.ttl_height >= min_height);
    }

    pub fn compute_twap(&self, market: MarketId) -> Option<Price> {
        let q = self.oracle_twap.get(&market)?;
        if q.len() < 2 {
            return None;
        }
        let sum: u128 = q.iter().map(|s| s.median as u128).sum();
        Some((sum / q.len() as u128) as Price)
    }

    pub fn compute_funding_twap(&self, market: MarketId) -> Option<Price> {
        let q = self.funding_twap.get(&market)?;
        if q.len() < 2 {
            return None;
        }
        let sum: u128 = q.iter().map(|s| s.median as u128).sum();
        Some((sum / q.len() as u128) as Price)
    }
    pub fn effective_funding_index(&self, market: MarketId, median: Price) -> Price {
        if self.height < operp_types::FUNDING_TWAP_ACTIVATION_HEIGHT {
            return median;
        }
        match self.funding_source {
            FundingSourceKind::BondedMedianTwap => self
                .funding_index_twap
                .get(&market)
                .copied()
                .unwrap_or(median),
            FundingSourceKind::AggregatedExternal => {
                // Doc 06 §2.6 rule 1: external TWAP overrides when fresh and
                // populated; else fall back to bonded-median TWAP, then the
                // instant median — funding never freezes.
                self.external_twap(market).unwrap_or_else(|| {
                    self.funding_index_twap
                        .get(&market)
                        .copied()
                        .unwrap_or(median)
                })
            }
        }
    }

    pub fn recompute_median(&self, market: MarketId) -> Option<Price> {
        let mut prices: Vec<Price> = self
            .oracle_reports
            .iter()
            .filter(|((m, o), _)| *m == market && self.oracle_bonds.contains_key(o))
            .map(|(_, p)| *p)
            .collect();
        if prices.is_empty() {
            return None;
        }
        prices.sort();
        Some(prices[(prices.len() - 1) / 2])
    }

    // -----------------------------------------------------------------------
    // Bonding / unbonding / slashing (height-gated by caller; state helpers assume bonded checks passed)
    pub fn apply_stake(&mut self, account: AccountId) -> Result<(), StateError> {
        // Caller gates height; here enforce bond invariants
        if self.oracle_bonds.contains_key(&account) {
            return Err(StateError::AlreadyBonded);
        }
        if self.oracle_unbonding.contains_key(&account) {
            return Err(StateError::Unbonding);
        }
        let bal = self.perp_balances.get(&account).copied().unwrap_or(0);
        if bal < operp_types::ORACLE_BOND_PERP {
            return Err(StateError::InsufficientPerp);
        }
        self.perp_balances
            .insert(account, bal - operp_types::ORACLE_BOND_PERP);
        self.perp_supply = self.perp_supply.saturating_sub(0); // supply unchanged: bond locked, not burned
        self.oracle_bonds
            .insert(account, operp_types::ORACLE_BOND_PERP);
        Ok(())
    }

    pub fn apply_unstake(&mut self, account: AccountId) -> Result<(), StateError> {
        if !self.oracle_bonds.contains_key(&account) {
            return Err(StateError::NotBonded);
        }
        if self.oracle_unbonding.contains_key(&account) {
            return Err(StateError::Unbonding);
        }
        let unlock = self
            .height
            .saturating_add(operp_types::ORACLE_UNBOND_HEIGHTS);
        self.oracle_unbonding.insert(account, unlock);
        Ok(())
    }

    pub fn apply_slash(
        &mut self,
        challenger: AccountId,
        target: AccountId,
        market: MarketId,
    ) -> Result<(), StateError> {
        if !self.markets.contains_key(&market) {
            return Err(StateError::NotFound);
        }
        if !self.oracle_bonds.contains_key(&target) {
            return Err(StateError::NotBonded);
        }
        // Need TWAP - use compute_twap or funding twap
        let twap = self
            .compute_twap(market)
            .or_else(|| self.compute_funding_twap(market))
            .ok_or(StateError::SlashNotEligible)?;
        if twap == 0 {
            return Err(StateError::SlashNotEligible);
        }
        let hist = self
            .oracle_report_history
            .get(&(market, target))
            .ok_or(StateError::SlashNotEligible)?;
        if hist.len() < operp_types::SLASH_TWAP_STREAK as usize {
            return Err(StateError::SlashNotEligible);
        }
        // Check last N reports are consecutive heights and all deviate > threshold
        let n = operp_types::SLASH_TWAP_STREAK as usize;
        let start = hist.len() - n;
        let cfg = self.oracle_config(market);
        let deviation_bps = cfg.deviation_bps;
        // Also enforce window 256: last report height within window
        let latest_height = hist.back().map(|s| s.height).unwrap_or(0);
        if self.height.saturating_sub(latest_height) > 256 {
            return Err(StateError::SlashNotEligible);
        }
        for i in 0..n {
            let idx = start + i;
            let sample = hist[idx];
            if i > 0 {
                let prev = hist[idx - 1];
                if sample.height != prev.height + 1 {
                    // Require consecutive heights; gaps make streak invalid
                    return Err(StateError::SlashNotEligible);
                }
            }
            let dev = ((sample.price as i128 - twap as i128).abs() * 10_000 / twap as i128) as u64;
            if dev < deviation_bps {
                return Err(StateError::SlashNotEligible);
            }
        }
        // Eligible: execute slash — burn half, reward half
        let bond = self
            .oracle_bonds
            .remove(&target)
            .unwrap_or(operp_types::ORACLE_BOND_PERP);
        self.oracle_unbonding.remove(&target);
        self.oracle_reports.remove(&(market, target));
        self.oracle_report_history.remove(&(market, target));
        let burn = bond * (operp_types::SLASH_REWARD_BPS as u128) / 10_000;
        let reward = bond.saturating_sub(burn);
        self.perp_burned = self.perp_burned.saturating_add(burn);
        if self.perp_supply >= burn {
            self.perp_supply = self.perp_supply.saturating_sub(burn);
        }
        let challenger_bal = self.perp_balances.get(&challenger).copied().unwrap_or(0);
        self.perp_balances
            .insert(challenger, challenger_bal.saturating_add(reward));
        self.oracle_slash_nonce = self.oracle_slash_nonce.wrapping_add(1);
        Ok(())
    }

    pub fn prune_oracle_unbonding(&mut self, current_height: Height) {
        let mut to_release = Vec::new();
        for (acct, unlock) in &self.oracle_unbonding {
            if *unlock <= current_height {
                to_release.push(*acct);
            }
        }
        for acct in to_release {
            self.oracle_unbonding.remove(&acct);
            if let Some(bond) = self.oracle_bonds.remove(&acct) {
                let bal = self.perp_balances.get(&acct).copied().unwrap_or(0);
                self.perp_balances.insert(acct, bal.saturating_add(bond));
                self.oracle_reports.retain(|(_, o), _| *o != acct);
                self.oracle_report_history.retain(|(_, o), _| *o != acct);
            }
        }
    }

    pub fn prune_oracle_twap(&mut self, _min_height: Height) {
        // TWAP is bounded by VecDeque length cap, not height expiry; no-op for v1
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
        caller_seq: Seq,
    ) -> Result<(), StateError> {
        if price == 0 || !self.oracle_bonds.contains_key(&oracle) {
            return Ok(());
        }
        self.oracle_reports.insert((market, oracle), price);
        // Record per-reporter history for slash streak detection (depth 8)
        {
            let q = self
                .oracle_report_history
                .entry((market, oracle))
                .or_insert_with(VecDeque::new);
            // Push new sample; dedup same height by overwriting last
            if q.back().map(|s| s.height == self.height).unwrap_or(false) {
                if let Some(back) = q.back_mut() {
                    back.price = price;
                    back.seq = self.seq;
                }
            } else {
                q.push_back(ReportSample {
                    height: self.height,
                    price,
                    seq: self.seq,
                });
                while q.len() > 8 {
                    q.pop_front();
                }
            }
        }
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
                if dev <= old as i128 / 10 {
                    median
                } else {
                    old
                }
            }
            _ => median,
        };
        self.marks.insert(market, capped);
        // Record TWAP sample after median update
        self.record_twap_sample(market, median, caller_seq);
        // Funding: once at least two valid reports exist, every report tick
        // settles peer-to-peer funding.
        // premium_bps = (spot − funding_index)/funding_index, clamped to ±FUNDING_CAP_BPS.
        // funding_index = twap when height >= activation else median.
        // notional = signed_notional_usd(qty, funding_index)
        if prices.len() >= 2 {
            let funding_index = self.effective_funding_index(market, median);
            let index = funding_index as i128;
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
                                (
                                    *id,
                                    operp_types::signed_notional_usd(pos.qty, funding_index)
                                        * diff_bps
                                        / 10_000,
                                )
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
        // Bad-debt cap: if either side went bankrupt (equity < 0), its equity
        // is clamped to exactly 0 (collateral absorbs the hole — realized PnL
        // is settled into collateral since the settlement refactor) and the
        // insurance fund takes an equal debit. Applied to BOTH fill parties:
        // a maker resting at a stale price can go underwater exactly like a
        // taker crossing. A negative insurance balance is explicit socialized
        // debt repaid by future fee income. Conservation holds; a repeat fill
        // cannot re-trigger because equity is now 0.
        // Insurance itself is exempt (never clamped).
        for party in [fill.taker, fill.maker] {
            if party == INSURANCE_ACCOUNT {
                continue;
            }
            let shortfall = {
                let s = match self.accounts.get(&party) {
                    Some(a) => a.snapshot(&self.marks),
                    None => continue,
                };
                if s.equity < 0 {
                    -s.equity
                } else {
                    0
                }
            };
            if shortfall > 0 {
                if let Some(a) = self.accounts.get_mut(&party) {
                    // equity = collateral + upnl < 0 ⇒ collateral := -upnl,
                    // i.e. credit back |equity| so equity lands on exactly 0
                    // and the insurance debit equals the socialized loss.
                    a.collateral += shortfall;
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
                    if dev <= old as i128 / 10 {
                        fill.price
                    } else {
                        old
                    }
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
            let perp = self.perp_balances.get(&acct.id).copied().unwrap_or(0);
            let withdrawn = self.withdrawn_total.get(&acct.id).copied().unwrap_or(0);
            leaves.push(account_leaf(acct, perp, withdrawn));
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
        let withdrawn = self.withdrawn_total.get(&id).copied().unwrap_or(0);
        let leaf = account_leaf(&acct, perp, withdrawn);
        let leaves = self.leaves();
        let (siblings, root) = merkle_proof_for(leaves, leaf);
        MerkleProof {
            leaf,
            siblings,
            root,
            account: id,
            collateral: acct.collateral,
            perp,
            withdrawn,
            realized_pnl: acct.realized_pnl,
            positions: acct
                .positions
                .values()
                .map(|p| (p.market, (p.qty, p.entry_price)))
                .collect(),
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

pub fn account_leaf(acct: &Account, perp: u128, withdrawn: i128) -> [u8; 32] {
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
    // Cumulative sidechain-signed withdrawals (W): committing it lets the
    // vault AA enforce "this claim + prior claims <= W" against replay.
    b.extend_from_slice(&withdrawn.to_le_bytes());
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
    // Per-market price state: every market's mark and oracle funding index
    // (last_index) are committed in marks' BTreeMap order, so replays cannot
    // diverge on price/funding state outside the account tree.
    for (m, mark) in &state.marks {
        b.extend_from_slice(&m.0.to_le_bytes());
        b.extend_from_slice(&mark.to_le_bytes());
        b.extend_from_slice(&state.last_index.get(m).copied().unwrap_or(0).to_le_bytes());
    }
    // Oracle bonding / TWAP state committed for replay determinism
    b.extend_from_slice(&(state.oracle_bonds.len() as u32).to_le_bytes());
    for (acct, bond) in &state.oracle_bonds {
        b.extend_from_slice(&acct.0);
        b.extend_from_slice(&bond.to_le_bytes());
    }
    b.extend_from_slice(&(state.oracle_unbonding.len() as u32).to_le_bytes());
    for (acct, h) in &state.oracle_unbonding {
        b.extend_from_slice(&acct.0);
        b.extend_from_slice(&h.to_le_bytes());
    }
    b.extend_from_slice(&state.oracle_slash_nonce.to_le_bytes());
    b.extend_from_slice(&(state.oracle_twap.len() as u32).to_le_bytes());
    for (m, window) in &state.oracle_twap {
        b.extend_from_slice(&m.0.to_le_bytes());
        b.extend_from_slice(&(window.len() as u32).to_le_bytes());
        for s in window {
            b.extend_from_slice(&s.seq.to_le_bytes());
            b.extend_from_slice(&s.height.to_le_bytes());
            b.extend_from_slice(&s.median.to_le_bytes());
        }
    }
    b.extend_from_slice(&(state.funding_twap.len() as u32).to_le_bytes());
    for (m, window) in &state.funding_twap {
        b.extend_from_slice(&m.0.to_le_bytes());
        b.extend_from_slice(&(window.len() as u32).to_le_bytes());
        for s in window {
            b.extend_from_slice(&s.seq.to_le_bytes());
            b.extend_from_slice(&s.height.to_le_bytes());
            b.extend_from_slice(&s.median.to_le_bytes());
        }
    }
    b.extend_from_slice(&(state.funding_index_twap.len() as u32).to_le_bytes());
    for (m, v) in &state.funding_index_twap {
        b.extend_from_slice(&m.0.to_le_bytes());
        b.extend_from_slice(&v.to_le_bytes());
    }
    // External keeper price ring (doc 06 §2.3): empty in v1 BondedMedianTwap
    // (zero bytes beyond the length prefix), committed for forward compat.
    b.extend_from_slice(&(state.external_price_ring.len() as u32).to_le_bytes());
    for (m, ring) in &state.external_price_ring {
        b.extend_from_slice(&m.0.to_le_bytes());
        b.extend_from_slice(&(ring.len() as u32).to_le_bytes());
        for s in ring {
            b.extend_from_slice(&s.seq.to_le_bytes());
            b.extend_from_slice(&s.height.to_le_bytes());
            b.extend_from_slice(&s.price.to_le_bytes());
            b.push(s.source_id);
        }
    }
    b.extend_from_slice(&(state.external_sources.len() as u32).to_le_bytes());
    for acct in &state.external_sources {
        b.extend_from_slice(&acct.0);
    }
    // Pending commit-reveal commitments (doc 03 §2.3.3): keyed by commit
    // hash, BTreeMap order is deterministic.
    b.extend_from_slice(&(state.commits.len() as u32).to_le_bytes());
    for (h, e) in &state.commits {
        b.extend_from_slice(h);
        b.extend_from_slice(&e.account.0);
        b.extend_from_slice(&e.commit_unit.0);
        b.extend_from_slice(&e.commit_height.to_le_bytes());
        b.extend_from_slice(&e.ttl_height.to_le_bytes());
        b.push(e.revealed as u8);
    }
    b.extend_from_slice(&[state.funding_source as u8]);
    // oracle_configs
    b.extend_from_slice(&(state.oracle_configs.len() as u32).to_le_bytes());
    for (m, cfg) in &state.oracle_configs {
        b.extend_from_slice(&m.0.to_le_bytes());
        b.extend_from_slice(&cfg.deviation_bps.to_le_bytes());
        b.extend_from_slice(&cfg.twap_window.to_le_bytes());
        b.extend_from_slice(&cfg.slash_reward_bps.to_le_bytes());
    }
    // Latest report per (market, reporter): the effective mark median reads
    // this map, so leaving it uncommitted let replays diverge on marks.
    b.extend_from_slice(&(state.oracle_reports.len() as u32).to_le_bytes());
    for ((m, acct), price) in &state.oracle_reports {
        b.extend_from_slice(&m.0.to_le_bytes());
        b.extend_from_slice(&acct.0);
        b.extend_from_slice(&price.to_le_bytes());
    }
    // Per-reporter last-K report history (slash streak-detection input).
    b.extend_from_slice(&(state.oracle_report_history.len() as u32).to_le_bytes());
    for ((m, acct), q) in &state.oracle_report_history {
        b.extend_from_slice(&m.0.to_le_bytes());
        b.extend_from_slice(&acct.0);
        b.extend_from_slice(&(q.len() as u32).to_le_bytes());
        for s in q {
            b.extend_from_slice(&s.height.to_le_bytes());
            b.extend_from_slice(&s.price.to_le_bytes());
            b.extend_from_slice(&s.seq.to_le_bytes());
        }
    }
    // Open governance proposals (tallies + creation weight snapshots);
    // HashSet membership is committed via sorted iteration for determinism.
    b.extend_from_slice(&(state.proposals.len() as u32).to_le_bytes());
    for (id, p) in &state.proposals {
        b.extend_from_slice(&id.to_le_bytes());
        b.extend_from_slice(&p.creator.0);
        b.extend_from_slice(&p.market.0.to_le_bytes());
        b.push(p.key as u8);
        b.extend_from_slice(&p.value.to_le_bytes());
        b.extend_from_slice(&p.created_seq.to_le_bytes());
        b.extend_from_slice(&p.deadline_seq.to_le_bytes());
        b.extend_from_slice(&p.supply_at_create.to_le_bytes());
        b.extend_from_slice(&p.yes.to_le_bytes());
        b.extend_from_slice(&p.no.to_le_bytes());
        let mut voted: Vec<&AccountId> = p.voted.iter().collect();
        voted.sort();
        b.extend_from_slice(&(voted.len() as u32).to_le_bytes());
        for v in voted {
            b.extend_from_slice(&v.0);
        }
        b.extend_from_slice(&(p.weight_snapshot.len() as u32).to_le_bytes());
        for (a, w) in &p.weight_snapshot {
            b.extend_from_slice(&a.0);
            b.extend_from_slice(&w.to_le_bytes());
        }
    }
    // Mirrored PERP balances and circulating supply.
    b.extend_from_slice(&(state.perp_balances.len() as u32).to_le_bytes());
    for (a, bal) in &state.perp_balances {
        b.extend_from_slice(&a.0);
        b.extend_from_slice(&bal.to_le_bytes());
    }
    b.extend_from_slice(&state.perp_supply.to_le_bytes());
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

fn merkle_proof_for(
    mut leaves: Vec<[u8; 32]>,
    leaf: [u8; 32],
) -> (Vec<([u8; 32], bool)>, [u8; 32]) {
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
///                      || ":" || perp_decimal || ":" || withdrawn_decimal)
///   node  = sha256_hex(left_hex || right_hex)

pub fn aa_account_leaf_str(addr: &str, collateral: Usd, perp: u128, withdrawn: i128) -> String {
    let s = format!("acct:{}:{}:{}:{}", addr, collateral, perp, withdrawn);
    hex::encode(sha256(s.as_bytes()))
}

fn aa_parent(l: &str, r: &str) -> String {
    let mut buf = String::with_capacity(l.len() + r.len());
    buf.push_str(l);
    buf.push_str(r);
    hex::encode(sha256(buf.as_bytes()))
}

/// Root of the hex-domain tree over (address, collateral, perp, withdrawn)
/// quads.
pub fn aa_root_of(pairs: &[(String, Usd, u128, i128)]) -> String {
    let mut level: Vec<String> = pairs
        .iter()
        .map(|(addr, col, perp, w)| aa_account_leaf_str(addr, *col, *perp, *w))
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

/// Proof path for one address in the hex-domain tree over `pairs`. Returns
/// `None` when the path would need more than `MAX_AA_TREE_DEPTH` siblings:
/// the vault AA unrolls exactly 16 reduction steps (and ocore fatally errors
/// on over-long arrays), so a deeper proof could never be evaluated on-chain.
pub fn aa_proof_for(
    pairs: &[(String, Usd, u128, i128)],
    addr: &str,
) -> Option<(Vec<(String, bool)>, String)> {
    let mut level: Vec<String> = pairs
        .iter()
        .map(|(a, c, p, w)| aa_account_leaf_str(a, *c, *p, *w))
        .collect();
    let entry = pairs.iter().find(|(a, ..)| a == addr)?;
    let leaf = aa_account_leaf_str(addr, entry.1, entry.2, entry.3);
    level.sort();
    let mut idx = level.iter().position(|l| *l == leaf)?;
    let mut siblings = Vec::new();
    while level.len() > 1 {
        if siblings.len() >= operp_types::MAX_AA_TREE_DEPTH {
            return None;
        }
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

/// Root of the hex-domain tree over the sidechain accounts that are bound to
/// an Obyte address in `aa_addresses`, keyed by the bound address string.
/// Unbound accounts are excluded — they cannot prove identity on the AA
/// side, so their leaves would be claimable by nobody. The withdrawn leg is
/// the account's cumulative signed withdrawals (0 when never withdrawn).
pub fn aa_root_of_state(state: &ChainState) -> String {
    aa_root_of(&aa_pairs_of(state))
}

pub fn aa_proof_for_account(
    state: &ChainState,
    id: &AccountId,
) -> Option<(Vec<(String, bool)>, String)> {
    let addr = state.aa_addresses.get(id)?;
    aa_proof_for(&aa_pairs_of(state), addr)
}

/// Hex-domain tree entries for every AA-bound account, in account-id order.
fn aa_pairs_of(state: &ChainState) -> Vec<(String, Usd, u128, i128)> {
    state
        .accounts
        .values()
        .filter_map(|a| {
            let addr = state.aa_addresses.get(&a.id)?;
            Some((
                addr.clone(),
                a.collateral,
                state.perp_balances.get(&a.id).copied().unwrap_or(0),
                state.withdrawn_total.get(&a.id).copied().unwrap_or(0),
            ))
        })
        .collect()
}

/// ---- Sharded AA forest (doc 10 §5.2, Phase 5.2 wire change) ----
///
/// The vault AA commits ONE 1024-hex `aa_forest` per batch: the 16 shard
/// roots concatenated (shard i at offset i*64), which fits
/// MAX_STATE_VAR_VALUE_LENGTH=1024 exactly and keeps every AA path a single
/// var operation. Withdrawal proofs stay depth ≤ MAX_AA_TREE_DEPTH *within*
/// their shard; the AA extracts the claimed shard's root via substring.

pub const AA_SHARD_COUNT: usize = 16;

/// Shard of an address: low 4 bits of sha256(address)[0] — deterministic,
/// address-only, uniform (doc 10 §B1(1)). The AA never recomputes it; it
/// trusts the claimed `shard` tag because soundness comes from the leaf
/// preimage (a mis-claimed shard folds to that shard's root and fails).
pub fn aa_shard_of(addr: &str) -> u8 {
    sha256(addr.as_bytes())[0] & 0x0f
}

/// Distinct per-shard sentinel so an empty shard's committed root can never
/// be reused as another empty shard's root (zero-proof cross-shard hopping,
/// doc 10 §5.4). Unforgeable: deriving it requires preimaging sha256.
fn aa_empty_shard_root(shard: usize) -> String {
    hex::encode(sha256(format!("empty:{}", shard).as_bytes()))
}

/// Roots of the 16 per-shard hex-domain trees over `pairs`, bucketed by
/// [`aa_shard_of`]. Each bucket root reuses [`aa_root_of`] verbatim — zero
/// new crypto. Empty shards get distinct sentinels.
pub fn aa_sharded_roots_of(pairs: &[(String, Usd, u128, i128)]) -> [String; AA_SHARD_COUNT] {
    let mut buckets: Vec<Vec<(String, Usd, u128, i128)>> = vec![Vec::new(); AA_SHARD_COUNT];
    for p in pairs {
        buckets[aa_shard_of(&p.0) as usize].push(p.clone());
    }
    std::array::from_fn(|i| {
        if buckets[i].is_empty() {
            aa_empty_shard_root(i)
        } else {
            aa_root_of(&buckets[i])
        }
    })
}

/// 64-hex hash over the concatenated forest — the checkpoint's `aa_root`.
/// Binds the whole forest so watchers can cross-check the 1024-hex string
/// the operator posts on-chain against one length-checked field.
pub fn aa_forest_hash(shards: &[String; AA_SHARD_COUNT]) -> String {
    hex::encode(sha256(shards.concat().as_bytes()))
}

/// Sharded roots over every AA-bound account (same binding rules as
/// [`aa_root_of_state`]: unbound accounts are excluded).
pub fn aa_sharded_roots_of_state(state: &ChainState) -> [String; AA_SHARD_COUNT] {
    aa_sharded_roots_of(&aa_pairs_of(state))
}

/// Proof path for one address within its shard's tree:
/// `(shard, siblings, shard_root)`. Returns `None` when the path would need
/// more than `MAX_AA_TREE_DEPTH` siblings (the AA unrolls exactly that many
/// reduction steps per proof). Also returns `None` when the target's shard
/// bucket holds fewer than 2 leaves: a singleton bucket would need an EMPTY
/// proof array and ocore fatals on empty arrays in trigger data — such a
/// claim can never be posted, so it is refused up front. Register PAD/decoy
/// bindings first (see `gen_withdraw_proof.rs`'s
/// `format!("{:0<32}", format!("PAD{pad}"))` pattern).
pub fn aa_sharded_proof_for(
    pairs: &[(String, Usd, u128, i128)],
    addr: &str,
) -> Option<(u8, Vec<(String, bool)>, String)> {
    let shard = aa_shard_of(addr);
    let bucket: Vec<_> = pairs
        .iter()
        .filter(|(a, ..)| aa_shard_of(a) == shard)
        .cloned()
        .collect();
    if bucket.len() < 2 {
        return None;
    }
    let (siblings, root) = aa_proof_for(&bucket, addr)?;
    Some((shard, siblings, root))
}

/// Sharded proof for an account by sidechain id. See [`aa_sharded_proof_for`]
/// for the singleton-bucket (PAD decoy) requirement.
pub fn aa_sharded_proof_for_account(
    state: &ChainState,
    id: &AccountId,
) -> Option<(u8, Vec<(String, bool)>, String)> {
    let addr = state.aa_addresses.get(id)?;
    aa_sharded_proof_for(&aa_pairs_of(state), addr)
}
/// ---- Rollup witness tree (Obyte-merkle domain, dispute predicates) ----
///
/// Leaves are sorted lexicographically before `obyte_merkle::root`.
/// Decimal strings use `format!("{}", n)` (no scientific notation).
/// Hex is lowercase `hex::encode` of the 32-byte id.
pub fn wit_leaves(state: &ChainState) -> Vec<String> {
    let mut leaves = Vec::new();
    for (id, acct) in &state.accounts {
        let perp = state.perp_balances.get(id).copied().unwrap_or(0);
        let w = state.withdrawn_total.get(id).copied().unwrap_or(0);
        leaves.push(format!(
            "acct:{}:{}:{}:{}",
            hex::encode(id.0),
            acct.collateral,
            perp,
            w
        ));
        for (market, pos) in &acct.positions {
            leaves.push(format!(
                "pos:{}:{}:{}:{}",
                hex::encode(id.0),
                market.0,
                pos.qty,
                pos.entry_price
            ));
        }
    }
    for book in state.books.values() {
        for o in book.live_orders() {
            leaves.push(format!(
                "ord:{}:{}:{}:{}:{}:{}:{}",
                hex::encode(o.id.0),
                o.market.0,
                o.side.as_u8(),
                o.price,
                o.seq,
                o.remaining,
                hex::encode(o.account.0)
            ));
        }
    }
    for (market, params) in &state.markets {
        let mark = state.marks.get(market).copied().unwrap_or(0);
        leaves.push(format!(
            "meta:{}:{}:{}:{}:{}:{}:{}:{}",
            market.0,
            params.tick_size,
            params.im_bps,
            params.mm_bps,
            params.taker_fee_bps,
            params.keeper_reward_bps,
            if params.delisted { 1 } else { 0 },
            mark
        ));
    }
    leaves.sort();
    if leaves.is_empty() {
        leaves.push(operp_types::WIT_EMPTY_ELEMENT.to_string());
    }
    leaves
}
/// Witness root after the current state (Obyte-merkle domain).
pub fn wit_root(state: &ChainState) -> String {
    obyte_merkle::root(&wit_leaves(state))
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
        s.account_mut(taker)
            .credit(1_000_000 * USD_SCALE as i128)
            .unwrap();
        s.account_mut(maker)
            .credit(1_000_000 * USD_SCALE as i128)
            .unwrap();
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
            s.account_mut(id)
                .credit(10_000_000 * USD_SCALE as i128)
                .unwrap();
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
        s.apply_fill_pair(&mk_fill(300_000 * operp_types::PRICE_SCALE))
            .unwrap();
        assert_eq!(
            *s.marks.get(&BTC_USD).unwrap(),
            100_000 * operp_types::PRICE_SCALE
        );
        // +5% move: within the band — mark updates.
        s.apply_fill_pair(&mk_fill(105_000 * operp_types::PRICE_SCALE))
            .unwrap();
        assert_eq!(
            *s.marks.get(&BTC_USD).unwrap(),
            105_000 * operp_types::PRICE_SCALE
        );
    }

    #[test]
    fn funding_transfers_long_to_short_and_conserves() {
        let mut s = ChainState::new();
        let long = AccountId([9; 32]);
        let short = AccountId([8; 32]);
        s.account_mut(long)
            .credit(1_000_000 * USD_SCALE as i128)
            .unwrap();
        s.account_mut(short)
            .credit(1_000_000 * USD_SCALE as i128)
            .unwrap();

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
        s.apply_report(oa, BTC_USD, 100_000 * operp_types::PRICE_SCALE, 1)
            .unwrap();
        let pre_funding = s.accounts[&long].collateral + s.accounts[&short].collateral;

        // Tick 2: reports {89k, 100k}; median = sorted[(len-1)/2] = 89k
        // (the smaller middle when even). |89k − 100k| = 11k > 10k, so the
        // ±10% cap holds the spot mark at 100k while the index drops to
        // 89k: premium > 0 → long pays short.
        s.apply_report(ob, BTC_USD, 89_000 * operp_types::PRICE_SCALE, 2)
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
    #[test]
    fn maker_bad_debt_clamped_to_insurance() {
        let mut s = ChainState::new();
        let taker = AccountId([9; 32]);
        let maker = AccountId([8; 32]);
        s.account_mut(taker)
            .credit(1_000_000 * USD_SCALE as i128)
            .unwrap();
        s.account_mut(maker)
            .credit(50_000 * USD_SCALE as i128)
            .unwrap();
        // Maker is long 1 BTC @ 100k.
        s.account_mut(maker)
            .apply_fill(
                operp_types::Side::Bid,
                false,
                100_000 * operp_types::PRICE_SCALE,
                operp_types::QTY_SCALE,
                BTC_USD,
            )
            .unwrap();
        // Taker dumps at 10k: the maker closes with a 90k realized loss
        // settled into only 50k of collateral → bankrupt.
        s.marks.insert(BTC_USD, 10_000 * operp_types::PRICE_SCALE);
        let fill = Fill {
            taker_id: operp_types::OrderId([0u8; 32]),
            maker_id: operp_types::OrderId([0u8; 32]),
            taker,
            maker,
            market: BTC_USD,
            price: 10_000 * operp_types::PRICE_SCALE,
            qty: operp_types::QTY_SCALE,
            seq: 1,
            taker_side: operp_types::Side::Bid,
        };
        s.apply_fill_pair(&fill).unwrap();
        // Maker clamped to exactly 0. The maker's own 50k collateral absorbs
        // the first leg of the 90k loss; insurance takes only the residual
        // 40k shortfall (plus the taker fee credit).
        assert_eq!(s.accounts[&maker].collateral, 0);
        let fee = bps(notional_usd(fill.qty, fill.price), 5);
        let expected_ins = INSURANCE_SEED + fee - 40_000 * USD_SCALE as i128;
        assert_eq!(s.accounts[&INSURANCE_ACCOUNT].collateral, expected_ins);
    }

    #[test]
    fn aa_proof_for_refuses_over_deep_trees() {
        // 2^16 leaves need exactly MAX_AA_TREE_DEPTH siblings; one more leaf
        // pushes past the AA's fixed 16-step reduce and must yield None.
        let mk = |n: usize| -> Vec<(String, Usd, u128, i128)> {
            (0..n)
                .map(|i| (format!("A{:031}", i), 1, 0u128, 0i128))
                .collect()
        };
        let too_deep = mk((1 << operp_types::MAX_AA_TREE_DEPTH) + 1);
        assert!(aa_proof_for(&too_deep, &format!("A{:031}", 1)).is_none());
    }

    #[test]
    fn external_twap_requires_min_samples_and_freshness() {
        let mut s = ChainState::new();
        let keeper = AccountId([7; 32]);
        // One sample: below FUNDING_TWAP_MIN_SAMPLES → None.
        s.apply_external_price(keeper, BTC_USD, 90_000 * PRICE_SCALE, 0, 1);
        assert_eq!(s.external_twap(BTC_USD), None);
        // Second distinct-height sample: TWAP forms.
        s.height += 1;
        s.apply_external_price(keeper, BTC_USD, 92_000 * PRICE_SCALE, 0, 2);
        assert_eq!(
            s.external_twap(BTC_USD),
            Some((90_000 * PRICE_SCALE + 92_000 * PRICE_SCALE) / 2)
        );
        // Feed dies: past FUNDING_EXTERNAL_MAX_STALENESS the ring reads as
        // stale (None) so effective_funding_index falls back (doc 06 §2.6).
        s.height += operp_types::FUNDING_EXTERNAL_MAX_STALENESS + 1;
        assert_eq!(s.external_twap(BTC_USD), None);
        // Window cap holds the ring bounded at FUNDING_TWAP_WINDOW samples.
        for i in 0..(operp_types::FUNDING_TWAP_WINDOW + 10) {
            s.height += 1;
            s.apply_external_price(keeper, BTC_USD, 50_000 * PRICE_SCALE, 0, i);
        }
        assert_eq!(
            s.external_price_ring[&BTC_USD].len(),
            operp_types::FUNDING_TWAP_WINDOW as usize
        );
    }

    #[test]
    fn prune_commits_drops_expired_entries() {
        let mut s = ChainState::new();
        let acct = AccountId([3; 32]);
        s.commits.insert(
            [1u8; 32],
            CommitEntry {
                account: acct,
                commit_unit: UnitId([9u8; 32]),
                commit_height: 100,
                ttl_height: 116,
                revealed: false,
            },
        );
        s.commits.insert(
            [2u8; 32],
            CommitEntry {
                account: acct,
                commit_unit: UnitId([8u8; 32]),
                commit_height: 110,
                ttl_height: 126,
                revealed: true,
            },
        );
        // At min_height <= ttl the entries stay (reveal still legal).
        s.prune_commits(116);
        assert_eq!(s.commits.len(), 2);
        // Past both TTLs everything expires (doc 03 §2.3.3 rule 4).
        s.prune_commits(127);
        assert!(s.commits.is_empty());
    }

    #[test]
    fn twap_samples_carry_seq_and_dedup_same_height() {
        let mut s = ChainState::new();
        let oa = AccountId([5; 32]);
        let ob = AccountId([6; 32]);
        s.oracle_bonds.insert(oa, operp_types::ORACLE_BOND_PERP);
        s.oracle_bonds.insert(ob, operp_types::ORACLE_BOND_PERP);
        // Two reporters, same height, same median → one funding sample.
        s.apply_report(oa, BTC_USD, 90_000 * PRICE_SCALE, 1)
            .unwrap();
        s.apply_report(ob, BTC_USD, 90_000 * PRICE_SCALE, 2)
            .unwrap();
        assert_eq!(s.funding_twap[&BTC_USD].len(), 1);
        // New height, new median → new sample with that height's seq.
        s.height += 1;
        s.apply_report(oa, BTC_USD, 91_000 * PRICE_SCALE, 7)
            .unwrap();
        let q = &s.funding_twap[&BTC_USD];
        assert_eq!(q.len(), 2);
        assert_eq!(q.back().unwrap().seq, 7);
        assert_eq!(q.back().unwrap().height, 1);
    }
    #[test]
    fn aa_shard_of_is_deterministic_and_bounded() {
        for i in 0..200u32 {
            let addr = format!("ADDR{}", i);
            assert_eq!(aa_shard_of(&addr), aa_shard_of(&addr));
            assert!(aa_shard_of(&addr) < AA_SHARD_COUNT as u8);
        }
    }

    #[test]
    fn empty_shard_sentinels_are_distinct_and_unforgeable() {
        // Every empty shard commits a different sentinel; none equals the
        // plain "empty" root, so a zero-proof cannot hop shards (doc 10 §5.4).
        let roots = aa_sharded_roots_of(&[]);
        for i in 0..AA_SHARD_COUNT {
            let expected = hex::encode(sha256(format!("empty:{}", i).as_bytes()));
            assert_eq!(roots[i], expected);
            if i > 0 {
                assert_ne!(roots[i], roots[i - 1]);
            }
            assert_ne!(roots[i], hex::encode(sha256(b"empty")));
        }
    }

    #[test]
    fn sharded_proof_folds_to_forest_slice() {
        // Replicate the AA fold: proof within a shard's tree must land on
        // exactly the shard's 64-hex slice of the concatenated forest.
        let pairs: Vec<(String, Usd, u128, i128)> = (0..40u32)
            .map(|i| (format!("OBADDR{}X", i), 100 + i as Usd, 0, 0))
            .collect();
        let forest_roots = aa_sharded_roots_of(&pairs);
        let covered: std::collections::HashSet<u8> =
            pairs.iter().map(|(a, ..)| aa_shard_of(a)).collect();
        assert!(covered.len() > 1, "fixture must span several shards");
        for (addr, col, perp, w) in &pairs {
            let (shard, siblings, root) = aa_sharded_proof_for(&pairs, addr).unwrap();
            assert_eq!(root, forest_roots[shard as usize]);
            assert!(siblings.len() <= operp_types::MAX_AA_TREE_DEPTH);
            let mut acc = hex::encode(sha256(
                format!("acct:{}:{}:{}:{}", addr, col, perp, w).as_bytes(),
            ));
            for (sib, right) in &siblings {
                let buf = if *right {
                    format!("{}{}", acc, sib)
                } else {
                    format!("{}{}", sib, acc)
                };
                acc = hex::encode(sha256(buf.as_bytes()));
            }
            assert_eq!(
                acc,
                forest_roots
                    .concat()
                    .get(shard as usize * 64..shard as usize * 64 + 64)
                    .unwrap()
            );
        }
        // Forest hash binds all 16 roots in order.
        assert_eq!(
            aa_forest_hash(&forest_roots),
            hex::encode(sha256(forest_roots.concat().as_bytes()))
        );
    }
}
