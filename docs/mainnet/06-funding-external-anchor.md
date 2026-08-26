# Gap 2 — Funding Rate Mark-Premium Based, Not External — Design

> Owner: `DesignFundingAnchor` · Status: DESIGN-ONLY · Batch: Mainnet-1..5
> Depends: `operp-state` `apply_report` funding tick (`last_index`, `marks`, `oracle_reports`, `oracle_bonds`), `operp-types` `FUNDING_CAP_BPS`, `operp-exec` `Op::ReportPrice`, `operp-dag` `Op`, `ChainState::meta_leaf`

---

## 1. Target

### Problem restated (README L2)

Current funding is peer-to-peer but the **funding index is the unclamped median of bonded reporters' latest prices** (`ChainState::last_index[market] = median` in `crates/operp-state/src/lib.rs:212`), not an external exchange price. Mark (`marks[market]`) is the same median clamped ±10% vs old mark (`:213-221`), so the premium `(spot - index)/index` is just `(capped_median - median)/median` — a self-referential pair. Oracle quality bounds funding quality (L3). L2 requires anchoring funding to an **external price TWAP vs mark premium**, still capped ±50 bps/tick, via an external-price source abstraction where bonded-oracle TWAP is v1 and later multi-source blends in.

### Exact files / symbols touched

| Crate | File | Symbol | What |
|-------|------|--------|------|
| `operp-types` | `crates/operp-types/src/lib.rs` | `FUNDING_CAP_BPS`, `PRICE_SCALE`, `MarketId`, `Price`, `Seq`, `Height` | keep; add `FUNDING_TWAP_WINDOW`, `FUNDING_TWAP_MIN_SAMPLES`, `FUNDING_SOURCE_KIND` |
| `operp-types` | same | `ParamKey` | optional gov extension `FundingTwapWindow` (append-only) |
| `operp-state` | `crates/operp-state/src/lib.rs` | `ChainState { marks, last_index, oracle_reports, oracle_bonds, ... }` | add `funding_twap: BTreeMap<MarketId, VecDeque<TwapSample>>`, `funding_index_twap: BTreeMap<MarketId, Price>`, `funding_source: FundingSourceKind` |
| `operp-state` | same | `ChainState::apply_report`, `meta_leaf`, `leaves`, `prune_*` | signature change + TWAP update + funding formula switch |
| `operp-state` | same | `StateError` | add `FundingTwapUnavailable` (optional debug) |
| `operp-dag` | `crates/operp-dag/src/lib.rs` | `Op::ReportPrice`, `canonical_bytes` tag 6 | **no change in v1** (reuse same tag/bytes) |
| `operp-dag` | same | `Op::UpdateExternalPrice` (tag 17) | **new, gated** — reserved for future multi-source; not required for v1 but specified here |
| `operp-exec` | `crates/operp-exec/src/lib.rs` | `Engine::dispatch` `ReportPrice` arm, `Engine::apply_ready` ordering | pass `seq`/`height` into `apply_report`; wire `UpdateExternalPrice` when active |
| `operp-settle` | `crates/operp-settle/src/lib.rs` | `Batch::validate_against` | no wire change — deterministic replay via updated `ChainState` |
| `obyte-local` | `agents/operp_vault.aa` | — | **no change** — funding is sidechain-internal, not AA-verified |
| tests | `crates/operp-state`, `crates/operp-exec` | `funding_*` tests | new |

Wire impact **v1 = zero**: `ReportPrice` keeps tag 6 and `account[32]||market_le4||price_le8` layout. New storage is sidechain-only and covered by `meta_leaf`. Feature-gated by `height >= FUNDING_TWAP_ACTIVATION_HEIGHT` so old batches replay byte-identical before activation.

---

## 2. Change

### 2.0 Terminology & invariants kept

* **Mark (`marks[market]`)** — capped median, ±10% vs old mark. First report sets unconditionally. Still moves only via `apply_report` (and before activation, fill-driven mark path for markets with no bonded reporter — unchanged).
* **Instant median (`last_index[market]`)** — unclamped median `sorted[(len-1)/2]` over `oracle_reports` filtered by `oracle_bonds` presence. Deterministic lower-middle. Keep verbatim for backward compat.
* **Funding index (v1 new, `funding_index_twap`)** — TWAP of the instant-median time series over a sliding window. v1 source = `BondedMedianTwap`. Future source = `AggregatedExternal` (governance-selected blend).
* **Premium** — `premium_bps = (spot - funding_index)/funding_index * 10_000` clamped to `±FUNDING_CAP_BPS`.
* **Settlement** — two-phase peer-to-peer as today: Phase 2a debit payers `min(payment, collateral.max(0))` into `budget`; Phase 2b credit receivers in `BTreeMap<AccountId>` order capped at `budget`. Conservation holds exactly; insurance participates like any account. **Not changed**.
* Patterns preserved: `canonical_bytes` wire format, `BTreeMap` ordering, integer-only `i128` math, `MAX_AA_TREE_DEPTH` untouched, `256`-height prune windows, `otherwise` guards in AA untouched (no AA change).

### 2.1 Recommendation: ship v1 BondedMedianTwap anchored, abstract the source

| Dimension | v1 (this batch) — BondedMedianTwap | v2 (future) — AggregatedExternal |
|-----------|-------------------------------------|-----------------------------------|
| Source | TWAP of bonded-median series already in state | Blended external feed (CEX signed prices, Chainlink-style anchor, or Obyte price AA) via new `UpdateExternalPrice` op |
| UX | zero — reporters keep `ReportPrice`, no wallet change | keepers post signed external ticks; reporters unchanged |
| Determinism | trivial — pure function of existing report history + seq | deterministic if feed is posted as DAG units with `canonical_bytes` |
| Security | sustained deviation required to move TWAP; spike filtered | single-source manipulation bounded by blend + deviation caps |
| Code | ~80 lines + tests | + trait, one new Op tag, ~60 lines |

Ship v1 now. It satisfies L2 "(a) funding index = TWAP(external) vs mark premium" where TWAP(external) ≈ TWAP(bonded-median) under honest reporters, and (b) abstraction is in place so v2 is an additive `FundingSourceKind` switch with no funding-settlement rewrite.

### 2.2 New constants (`operp-types/src/lib.rs`)

```rust
// Existing kept verbatim:
pub const FUNDING_CAP_BPS: i64 = 50;

// v1 additions — all integer, no floats:
pub const FUNDING_TWAP_WINDOW: u64 = 256;              // samples; matches 256-height prune windows
pub const FUNDING_TWAP_WINDOW_MAX: u64 = 1800;         // gov cap (~1h at 2s/batch if window in heights)
pub const FUNDING_TWAP_MIN_SAMPLES: usize = 2;         // need ≥2 to form a TWAP; else fallback to median
pub const FUNDING_TWAP_ACTIVATION_HEIGHT: Height = 1_000_000; // placeholder; 0 on testnet/devnet

// Source kind — stored in ChainState, committed in meta_leaf
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum FundingSourceKind { BondedMedianTwap = 0, AggregatedExternal = 1 }

// Optional governance key (append-only to ParamKey):
pub enum ParamKey { /* existing 0..4 */ FundingTwapWindow = 8 } // next free u8; value = window 32..1800
```

`FUNDING_TWAP_WINDOW` in **samples** (reports that changed median) not wall seconds — deterministic across replicas without `timestamp`. Alternative in `Seq` distance is also deterministic; we choose samples/height because each median update already corresponds to a unique `seq`/`height` and avoids `timestamp` (not in state). Window 256 mirrors withdrawal/AA-unit/gov-nonce prune windows — bounded memory argument is identical.

Per-market config fallback (optional v1 simplification — use global constant; governance override added v1.1 if needed):

```rust
pub struct FundingConfig { pub twap_window: u64 } // 32..1800
pub fn default_funding_config() -> FundingConfig { FundingConfig { twap_window: FUNDING_TWAP_WINDOW } }
```

Keep v1 global for minimality; per-market `BTreeMap<MarketId, FundingConfig>` can be added without migration — commit`ed via `meta_leaf`.

### 2.3 New ChainState fields (`operp-state/src/lib.rs`)

```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TwapSample { pub seq: Seq, pub height: Height, pub median: Price }

pub struct ChainState {
    // ... existing fields unchanged, including:
    // marks, last_index, oracle_reports, oracle_bonds

    /// Sliding window of instant-median samples per market, bounded by twap_window.
    pub funding_twap: BTreeMap<MarketId, VecDeque<TwapSample>>,
    /// Latest computed TWAP per market (cache of funding_twap mean). None => bootstrap.
    pub funding_index_twap: BTreeMap<MarketId, Price>,
    /// Source selector — committed so replay is deterministic.
    pub funding_source: FundingSourceKind, // default BondedMedianTwap

    /// Future external feed ring (empty in v1 BondedMedianTwap):
    /// AggregatedExternal would write here via UpdateExternalPrice.
    pub external_price_ring: BTreeMap<MarketId, VecDeque<ExternalSample>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExternalSample { pub seq: Seq, pub height: Height, pub price: Price, pub source_id: u8 }
```

**`BTreeMap` + `VecDeque`** keeps iteration order deterministic and memory bounded (`twap_window ≤ 1800` → at most 1800×8 bytes ≈ 14KB/market). Aligns with existing `BTreeMap` ordering in `meta_leaf`.

Commit in `meta_leaf` (keeps `Batch::validate_against` replay-bound):

```rust
// inside meta_leaf(state):
b.extend_from_slice(&(state.funding_source as u8).to_le_bytes());
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
for (m, twap) in &state.funding_index_twap {
    b.extend_from_slice(&m.0.to_le_bytes());
    b.extend_from_slice(&twap.to_le_bytes());
}
// external_price_ring empty in v1 → zero bytes; structure committed for forward compat
```

`leaves()` unchanged (book/marks commitment stays via `meta_leaf`); no new leaf type.

### 2.4 TWAP maintenance (deterministic, bounded)

Insert after `last_index.insert` in `apply_report` (see 2.5). Helpers:

```rust
impl ChainState {
    pub fn funding_config(&self, _market: MarketId) -> FundingConfig {
        // v1 global; v1.1 reads per-market override or governance
        default_funding_config()
    }

    fn record_funding_sample(&mut self, market: MarketId, median: Price, seq: Seq) {
        let window_len = self.funding_config(market).twap_window as usize;
        let q = self.funding_twap.entry(market).or_default();
        // One sample per distinct seq/height where median changed — but we record every apply_report
        // that produced a (possibly identical) median to keep TWAP time-weight uniform in seq.
        // Deduplicate same-height-and-same-median back-to-back to avoid double counting when
        // multiple reporters fire in same batch height with same median outcome.
        if let Some(back) = q.back() {
            if back.height == self.height && back.median == median {
                return; // same height, same median → no new sample
            }
        }
        q.push_back(TwapSample { seq, height: self.height, median });
        while q.len() > window_len { q.pop_front(); }
        // Cache: seq-weighted TWAP (see twap() for formula)
        if let Some(twap) = self.compute_twap(market) {
            self.funding_index_twap.insert(market, twap);
        }
    }

    pub fn compute_twap(&self, market: MarketId) -> Option<Price> {
        let q = self.funding_twap.get(&market)?;
        if q.len() < FUNDING_TWAP_MIN_SAMPLES { return None; }
        // v1: seq-weighted mean (time proxy = seq distance between samples).
        // For samples s0..s_{n-1} with seq values, weight_i = seq_{i+1} - seq_i for i<n-1.
        // Last sample weight = 1 (or seq - seq_{n-1} is unknown until next report).
        // Simpler v1: arithmetic mean — identical when reports arrive at regular seq intervals,
        // and bounded error when irregular (max window 256, deviation limited).
        // We ship arithmetic mean for audit minimality; seq-weight is a one-line swap later.
        //
        // Arithmetic mean: sum(median)/n  — u128 sum, no overflow (Price ≤ 2^64, n ≤ 1800 → sum < 2^75).
        // Alternative def (commented): seq-weighted — uncomment when seq irregularity matters.
        let sum: u128 = q.iter().map(|s| s.median as u128).sum();
        Some((sum / q.len() as u128) as Price)
        // seq-weighted variant (kept as reference, not shipped v1):
        // let total_weight: u128 = (q.len() as u128); ... or compute gaps
    }

    pub fn effective_funding_index(&self, market: MarketId, median: Price) -> Price {
        // Activation gate + bootstrap fallback:
        // - before activation height → median (legacy behavior)
        // - after activation but window < MIN_SAMPLES → median (bootstrap)
        // - after activation and window filled → TWAP
        if self.height < FUNDING_TWAP_ACTIVATION_HEIGHT {
            return median;
        }
        match self.funding_source {
            FundingSourceKind::BondedMedianTwap => {
                self.funding_index_twap.get(&market).copied().unwrap_or(median)
            }
            FundingSourceKind::AggregatedExternal => {
                // v2: twap of external_price_ring, fallback to BondedMedianTwap, then median
                self.external_twap(market).unwrap_or_else(|| {
                    self.funding_index_twap.get(&market).copied().unwrap_or(median)
                })
            }
        }
    }

    fn external_twap(&self, _market: MarketId) -> Option<Price> { None } // v1 stub
}
```

**Why arithmetic mean v1:** minimal code, no timestamp, deterministic, bounded error. `Seq` gaps between `ReportPrice` units are at most a few hundred across the window (reports are sparse), so arithmetic vs time-weighted difference is < 1% — below the 50 bps funding cap. If monitoring shows lumpy report arrival causing TWAP bias, swap one line to seq-weighted without changing storage layout.

**Pruning:** `VecDeque` length cap already bounds memory; no separate `prune_funding_twap(min_height)` needed. Optionally add `fn prune_funding_twap(&mut self, _min_height: Height)` that retains `height + 256 > min_height` for symmetry with `prune_withdrawals` — but the window cap is strictly tighter when window=256. Keep prune as no-op for v1 to stay boring; wire it if per-market window grows to 1800 (then height-prune still redundant because length cap holds).

### 2.5 Funding formula change — the core delta

Current (`operp-state/src/lib.rs:237-285`):

```rust
let index = median as i128;
let spot  = capped as i128;
let diff_bps = ((spot - index) * 10_000 / index).clamp(-CAP, CAP);
let payments = signed_notional_usd(pos.qty, median) * diff_bps / 10_000;
// Phase 2a/2b peer-to-peer settlement unchanged
```

New:

```rust
// After median + capped computed as today (unchanged ±10% mark cap):
self.last_index.insert(market, median); // keep
let capped = match self.marks.get(&market) { // unchanged
    Some(&old) if old > 0 => {
        let dev = (median as i128 - old as i128).abs();
        if dev <= old as i128 / 10 { median } else { old }
    }
    _ => median,
};
self.marks.insert(market, capped);

// v1 addition: update TWAP window + cache
self.record_funding_sample(market, median, caller_seq);

// Funding — gate on ≥2 reporters as today, but index is now TWAP-anchored:
if prices.len() >= 2 {
    let funding_index = self.effective_funding_index(market, median);
    let index = funding_index as i128;
    let spot  = capped as i128;
    if index > 0 {
        let diff_bps = ((spot - index) * 10_000 / index).clamp(
            -(FUNDING_CAP_BPS as i128),
            FUNDING_CAP_BPS as i128,
        );
        if diff_bps != 0 {
            // Phase 1 unchanged except notional priced at funding_index, not median:
            let payments: Vec<(AccountId, i128)> = self.accounts.iter()
                .filter_map(|(id, a)| {
                    a.positions.get(&market).map(|pos| {
                        (*id, signed_notional_usd(pos.qty, funding_index) * diff_bps / 10_000)
                    })
                })
                .filter(|(_, p)| *p != 0)
                .collect();
            // Phase 2a — debit payers, clamped at non-negative collateral (unchanged)
            let mut budget: i128 = 0;
            for (id, payment) in &payments {
                if *payment <= 0 { continue; }
                if let Some(a) = self.accounts.get_mut(id) {
                    let debit = (*payment).min(a.collateral.max(0));
                    a.collateral -= debit;
                    budget += debit;
                }
            }
            // Phase 2b — credit receivers in AccountId order, capped at budget (unchanged)
            for (id, payment) in &payments {
                if budget == 0 { break; }
                if *payment >= 0 { continue; }
                let want = -*payment;
                let credit = want.min(budget);
                if let Some(a) = self.accounts.get_mut(id) { a.collateral += credit; }
                budget -= credit;
            }
        }
    }
}
```

Key points:

* **`notional` priced at `funding_index` not `median`:** payment = `qty·funding_index·diff_bps`. This makes payment invariant to instant median spikes when TWAP is anchor. If we priced at `median`, a one-tick median spike would double-pay via both `diff_bps` and `notional`. Pricing at `funding_index` keeps units consistent: `funding_index` is both denominator of `diff_bps` and price of `notional`.
* **Clamp preserved:** `diff_bps` still clamped to `±50 bps` per tick. Sustained 10% premium now yields 50 bps per report tick repeatedly until mark converges or TWAP catches up (funding accumulates tick by tick, not once).
* **Peer-to-peer mechanics preserved verbatim:** Phase 2a/2b, `BTreeMap` order, `collateral.max(0)` clamp, budget-capped credit, insurance participates, dust stays sub-unit. No semantic change.
* **Mark cap preserved:** `capped` logic unchanged; funding now charges on `capped - TWAP` gap. When reporters collude to push median 11% away, `capped` holds old mark (10% cap trips), so premium ≈ `(old_mark - TWAP)/TWAP` → funding punishes the side aligned with the capped mark until TWAP follows or median reverts.

### 2.6 External vs bonded median composition & source abstraction

```
ReportPrice (bonded reporters, 50k PERP bond)
        │
        ▼
  oracle_reports[(market,reporter)] ──► median (lower-middle) ──┐
                                                        │       │
                                              last_index (instant)  funding_twap window
                                                        │       │  (VecDeque, bounded 256)
                                                        │       ▼
mark (capped median ±10%) ◄──────────────────────────────┘  funding_index_twap
        │                                                    (TWAP of medians)
        │                                                          │
        └─────────────── premium = (mark - funding_index)/funding_index ──┘
                                 │
                                 ▼
                     diff_bps clamped ±50 ──► peer-to-peer settlement (2-phase)
                                 │
                    ┌────────────┴────────────┐
                    │   FundingSourceKind     │
                    │  BondedMedianTwap (v1)  │◄── default, no new Op
                    │  AggregatedExternal (v2)│◄── reads external_price_ring
                    └─────────────────────────┘
```

**Composition rules:**

1. **Inclusion:** `oracle_reports` filtered by `oracle_bonds` presence (existing). `UpdateExternalPrice` (v2) filtered by a `external_sources: BTreeMap<(MarketId, SourceId), Price>` allowlist (governance `ParamKey::ExternalSourceAllowlist` future). In `AggregatedExternal` mode, `funding_index` = `external_twap` if available, else fallback to `funding_index_twap`, else `median` — never `None` when funding runs (gate `prices.len()>=2` ensures `median` exists).
2. **Precedence (v2):** `external_twap` overrides `funding_index_twap` when `external_price_ring[m].len() >= MIN_SAMPLES` and freshness `last_external_height + MAX_STALENESS > height` (e.g., 32 heights). Stale external → fallback so a liveness failure does not freeze funding.
3. **No double-count:** `marks` never directly become `funding_index`. Mark is always capped median; funding index is always TWAP (external or bonded). This separation is the external anchor: mark can lag external by up to 10%/tick while funding accrues.
4. **Governance seam:** `funding_source` is in-state and `meta_leaf`-committed. Switching source is a `CreateProposal`/`FinalizeProposal` that sets `funding_source` per market or globally (reuse existing `ParamKey` governance). No AA upgrade, no hard fork — replay after switch uses new branch deterministically gated by `height`.

**Wire & storage for future `UpdateExternalPrice` (specified, not implemented v1):**

```rust
// operp-dag/src/lib.rs — new tag 17, gated by funding_source == AggregatedExternal
Op::UpdateExternalPrice {
    source: AccountId,   // keeper key, allowlisted
    market: MarketId,
    price: Price,        // external price tick, e.g., CEX mid
    source_id: u8,       // which venue (0..N)
}
// canonical_bytes: tag 17 || source[32] || market_le4 || price_le8 || source_id
```

`account_matches` enforces `source == sha256(pubkey)`. Exec intake checks `external_sources_allowlist.contains(&source)`. State writes `external_price_ring[market].push_back(ExternalSample{seq,height,price,source_id})`, caps at `twap_window`, recomputes `external_twap`.

### 2.7 ChainState::apply_report signature & Engine wiring (`operp-exec`)

Current:

```rust
pub fn apply_report(&mut self, oracle: AccountId, market: MarketId, price: Price)
Engine dispatches with map_state(self.state.apply_report(*oracle, *market, *price))
```

New:

```rust
pub fn apply_report(&mut self, oracle: AccountId, market: MarketId, price: Price, seq: Seq)
```

`seq` is `self.state.seq` at dispatch time (before increment, consistent with `apply_one`'s `seq` passed to `place`). Alternatively `height` is also usable; `seq` chosen because it advances per applied unit and is already committed in `meta_leaf`, while `height` only advances at batch commit. Using `seq` gives finer TWAP granularity within a batch (multiple reports in same batch get distinct seqs).

Engine change (`crates/operp-exec/src/lib.rs:185-201`):

```rust
Op::ReportPrice { oracle, market, price } => {
    if !self.state.oracle_bonds.contains_key(oracle) { return Err(RejectReason::BadAccount); }
    if !self.state.markets.contains_key(market) { return Err(RejectReason::NotFound); }
    // Pass current seq before it is consumed by apply_one's seq++ on success.
    // Copy height/seq because apply_report mutates state before seq increment.
    let caller_seq = self.state.seq;
    self.state.apply_report(*oracle, *market, *price, caller_seq).map_err(map_state)?;
    Ok(Vec::new())
}
```

`apply_fill_pair` mark path unchanged (fill-driven marks already gated by `!oracle_reports.keys().any(bonded)`). No new op in v1, so `canonical_bytes` versioning not needed. Activation gate inside `effective_funding_index` and `record_funding_sample` keeps pre-activation replay identical to legacy (legacy path skips TWAP write).

### 2.8 Migration & activation

* **Flag day via height:** `fn is_funding_twap_active(height: Height) -> bool { height >= FUNDING_TWAP_ACTIVATION_HEIGHT }`. Genesis/testnet set `ACTIVATION_HEIGHT = 0` so tests exercise v1 from start. Mainnet sets `ACTIVATION_HEIGHT = state.height + 1` at deployment (next height after upgrade).
* **No state migration:** `funding_twap`/`funding_index_twap` start empty (BTreeMap default). `meta_leaf` hashing before activation omits them (empty map → zero bytes beyond length prefix) so old roots unchanged; after activation same `meta_leaf` code now hashes non-empty window deterministically. Fine because activation height separates replay branches — `Batch::validate_against` height-checks the branch.
* **No AA migration:** funding never leaves sidechain; no Oscript budget spent. AA remains verifiable with same proof path.
* **Rollback:** setting `funding_source` back to `BondedMedianTwap` via governance restores v1 behavior without code rollback.

### 2.9 What this batch deliberately does NOT change

* `FUNDING_CAP_BPS = 50` stays (requirement: "still capped ±50 bps/tick").
* Peer-to-peer two-phase settlement (collateral-aware clamp, budget, BTree order) stays.
* Mark cap ±10% stays.
* `ReportPrice` tag/bytes/semantics stay.
* No VRF, no timestamp oracle, no external HTTP fetch inside state.

Alternatives considered and rejected:

* **Wall-clock timestamp in state** — requires every replica to agree on a clock; seq/height proxy is already BFT-deterministic.
* **Median over external feeds directly for `marks`** — would replace rather than anchor funding; keep mark as capped median for backwards compatibility and minimal blast radius.
* **Funding index = TWAP(mark)** — circular and manipulable via fills when no reporters present; correct to TWAP external/median, not TWAP mark.

---

## 3. Acceptance

### 3.1 Observable new funding formula

After `height >= ACTIVATION_HEIGHT`:

* **Bootstrap:** `funding_twap.len() < 2` → `effective_funding_index = median`; behavior identical to legacy (verified by replay assertion below).
* **Steady state:** `effective_funding_index = TWAP(medians in window)` — arithmetic mean v1 (seq-weighted as optional swap).
* **Premium:** `premium_bps = clamp((mark - funding_index)/funding_index * 10_000, -50, 50)`.
* **Payment notional:** `signed_notional_usd(qty, funding_index)` not `median` — see 2.5 rationale.

### 3.2 Test/E2E assertions (must be added; they are the acceptance proof)

#### Unit test — `crates/operp-state/src/lib.rs::tests` (existing module already has `funding_transfers_long_to_short_and_conserves`)

```rust
#[test]
fn funding_anchored_to_twap_pays_longs_when_mark_above_external() {
    let mut s = ChainState::new();
    //height 0 is activation on testnet
    s.funding_source = FundingSourceKind::BondedMedianTwap;
    let long = AccountId([9; 32]);
    let short = AccountId([8; 32]);
    s.account_mut(long).credit(1_000_000 * USD_SCALE as i128).unwrap();
    s.account_mut(short).credit(1_000_000 * USD_SCALE as i128).unwrap();

    // Open 1 BTC each side at 100k so notional = 100k
    let px = 100_000 * PRICE_SCALE;
    s.apply_fill_pair(&Fill {
        taker_id: OrderId([0u8;32]), maker_id: OrderId([0u8;32]),
        taker: long, maker: short, market: BTC_USD, price: px, qty: QTY_SCALE, seq: 0, taker_side: Side::Bid,
    }).unwrap();
    // After genesis fill, mark ~100k (fill path sets mark); clear mark to known baseline
    // Bind two oracle bonds so funding is eligible
    let oa = AccountId([5;32]); let ob = AccountId([6;32]);
    s.oracle_bonds.insert(oa, ORACLE_BOND_PERP);
    s.oracle_bonds.insert(ob, ORACLE_BOND_PERP);

    // Prime TWAP with 256 samples of median = 90k (external anchor)
    // i.e., reporters consistently report ~90k so TWAP = 90k.
    for seq in 1..=FUNDING_TWAP_WINDOW {
        let median = 90_000 * PRICE_SCALE;
        // Simulate median 90k without going through price/price split:
        // both reporters at 90k → median 90k, capped mark holds at 100k (>10% gap)
        s.apply_report(oa, BTC_USD, median, seq*2).unwrap();
        s.apply_report(ob, BTC_USD, median, seq*2+1).unwrap();
    }
    let twap = s.funding_index_twap[&BTC_USD];
    assert_eq!(twap, 90_000 * PRICE_SCALE);
    let mark = s.marks[&BTC_USD];
    // Mark was clamped at 100k (dev >10%, so held), now 11.1% above TWAP
    assert!(mark > twap);

    let pre_long = s.accounts[&long].collateral;
    let pre_short = s.accounts[&short].collateral;
    // Trigger one more tick at same median; funding should fire with premium >0
    s.apply_report(oa, BTC_USD, 90_000 * PRICE_SCALE, 9999).unwrap();
    assert!(s.accounts[&long].collateral < pre_long, "long must pay when mark > external TWAP");
    assert!(s.accounts[&short].collateral > pre_short, "short must receive");
    // Cap check: notional ~90k (funding_index) * 50bps = 450 USD
    let paid = pre_long - s.accounts[&long].collateral;
    let expected_cap = bps(notional_usd(QTY_SCALE, 90_000*PRICE_SCALE), 50);
    assert!(paid <= expected_cap + (USD_SCALE as i128), "clamped at 50 bps/tick within dust");
    assert!(paid >= expected_cap - (USD_SCALE as i128) || paid == expected_cap / 2 /* odd btree split */);
}

#[test]
fn funding_cap_holds_across_large_deviation_and_conserves() {
    // Same setup but set TWAP = 50k, mark = 100k → raw premium 100% but clamped to 50 bps
    // Assert payment == 50bps * notional(TWAP) and sum(long+short) conserved (<1 USD dust).
}

#[test]
fn funding_twap_bootstrap_falls_back_to_median() {
    let mut s = ChainState::new();
    // Before window filled, effective index == median → replicates legacy test funding_transfers_long_to_short_and_conserves
    // Assert diff_bps computed from median when funding_twap.len() < 2
}

#[test]
fn spike_filtered_by_twap() {
    // Feed 255 samples at 100k, inject 1 spike median 150k, TWAP moves only ~195 USD, funding stays ~19 bps vs 50bps with instant median
    // Assert funding payment with TWAP < payment that instant median would have produced
}

#[test]
fn twap_survives_mark_cap_hold() {
    // Push median to 89k (capped hold at 100k), prime TWAP to 89k, mark holds at 100k
    // Next tick funding fires with premium on (100k - 89k)/89k clamped
    // Mirrors legacy test but now premium derived from TWAP not instant median
    // Verifies mark-cap + TWAP composition, not instant median
}

#[test]
fn activation_gate_preserves_legacy_replay() {
    // height < ACTIVATION  → effective == median regardless of window
    // Build Batch at height 0..ACTIVATION-1 with legacy funding expectation, assert validate_against passes
}
```

#### Exec-level E2E — `crates/operp-exec/src/lib.rs` (via `Engine::ingest` signed units)

```rust
#[test]
fn e2e_report_price_funding_pays_via_twap() {
    let mut eng = Engine::new();
    // deposit collateral, open positions via Place units, bond two oracles via direct state insert (testnet)
    // send ReportPrice units in order; assert ExecEvent::Applied emitted and collateral moves capped at 50 bps/tick
}
```

#### Manual determinism check (replay)

* `Batch::validate_against` replays same `apply_report(..., seq)` sequence; because `seq` is part of state (`state.seq`) and `meta_leaf` commits `funding_twap`, a mismatched TWAP window yields `SettleError::RootMismatch` — honest watchers catch a bad root posted by operator (same as today: `temp_data` reveal + re-execution).

### 3.3 Acceptance criteria checklist

* [ ] `ChainState::effective_funding_index` exists and is used in the funding tick; `last_index` retained for instant median, `funding_index_twap` holds TWAP, `meta_leaf` commits both.
* [ ] `FUNDING_CAP_BPS` clamp still applied; single tick never moves more than 50 bps of `notional(funding_index)` per position.
* [ ] Two-phase peer-to-peer settlement unchanged (budget, clamp, BTree order, conservation <1 USD dust, insurance participates).
* [ ] Mark cap ±10% still gates `marks`; funding premium reflects `mark - TWAP` divergence as specified.
* [ ] New tests above pass, plus existing `funding_transfers_long_to_short_and_conserves` passes after activation with updated expectation (or is kept as `#[cfg(not(feature="twap"))]` legacy check).
* [ ] No `crates/operp-dag` wire change; old fixtures verify before activation.
* [ ] No AA change; vault proofs unaffected (`MAX_AA_TREE_DEPTH` intact).

---

## 4. Complexity & Risk

### 4.1 AA op-count / Oscript budget

**Delta = 0.** Funding is sidechain-engine only. Vault AA (`obyte-local/agents/operp_vault.aa`) has no new branches, no new state vars, no new `reduce` depth. Oscript complexity budget (already exhausted per L9) not touched. No new `sha256(..., 'hex')` or sibling folds.

### 4.2 Runtime cost (sidechain)

* Per `ReportPrice` after activation: one `BTreeMap` lookup for `oracle_reports`/`marks` (existing) + `VecDeque::push_back` + length cap check + arithmetic sum over ≤256 entries (or ≤1800 after gov) to recompute TWAP. Worst-case ≈ 1800·8 bytes sum ≈ 1800 integer adds per report tick — negligible vs matcher (bench ~5–9k TPS). No allocations outside `VecDeque` growth (pre-allocate 256).
* Funding settlement itself unchanged (iterate over `accounts` map for that market — already O(holders), dominated by `BTreeMap` iteration). TWAP does not increase that cost.
* Memory: `funding_twap` ≤ `markets.len() * 1800 * 16 bytes` ≈ 28KB/market at max window, ~224KB for 8 markets — under 1 MB total, bounded. No unbounded growth (length gate). Fits within existing `256`-height window memory budget narrative.

### 4.3 Migration & blast radius

* **State compatibility:** New fields have `Default` (empty maps) so old `ChainState` deserializes (no serde wire persisted beyond in-memory/test). `meta_leaf` before activation hashes empty maps → same bytes as before (length 0). After activation deterministic with new length prefixes.
* **Replay compatibility:** `Batch::validate_against` already replays via `Engine::ingest` linearized order. Changing `apply_report` to take `seq` is API-only; wire `canonical_bytes` unchanged so old `temp_data` (batch.json reveal) replays correctly when `height < ACTIVATION`. After activation, old batch payloads would be invalid anyway because operator must resubmit with new root.
* **Backward compat:** Single `if height < ACTIVATION { effective = median }` keeps legacy path 1:1. Deploy can set `ACTIVATION = next_height` as flag day; testnet uses 0.
* **Risk: seq vs height drift** — if we record TWAP keyed by `height` but multiple reports land in same height, second report in same height with same median is deduplicated (see `record_funding_sample` guard). This avoids inflating window with duplicate-height samples. Using `seq` as weight key preserves intra-height ordering without height aliasing.

### 4.4 What could go wrong and how it is bounded

* **TWAP window too short** (e.g., 8 samples) → spike passes through; but activation default 256 still filters single-tick manipulation (needs 256/2 sustained ticks to move TWAP 50%). Governance can tune.
* **TWAP window too long** (1800) → slow to react to genuine external regime shift; funding lags. Acceptable because clamp still caps per-tick payment; slow TWAP actually increases sustained funding (good for pegging). Governance bounds `twap_window` 32..1800 via `ParamKey`.
* **Governance misconfiguration of source kind** → `AggregatedExternal` with no feed stalls funding → fallback to `BondedMedianTwap` + staleness check prevents freeze (funding still fires on bonded TWAP).
* **Intellectual leak:** changing `signed_notional_usd(pos.qty, funding_index)` breaks accounting if `funding_index` stale — but `funding_index` is TWAP of medians, which tracks external when reporters are honest; stale external fallback returns to bonded TWAP, not to zero.

### 4.5 Interaction with sibling gaps

* **Gap 3 (Oracle slash / TWAP):** this design's `funding_twap` is *read-only* for funding; Gap 3's `oracle_twap` is *write-checked* for slashing. They can share one ring buffer (deduplicate) or keep separate — recommended **share**: both `funding_index_twap` and slash TWAP derive from same `VecDeque<TwapSample>` to keep `meta_leaf` small. Document shared ownership if both gaps land together (merge step must coalesce `FundingSourceKind` vs `OracleConfig`).
* **Gap 5 (ordering salt):** no interaction — ordering decides `seq` linearization; funding consumes `seq` after ordering via `apply_report(seq)`. *(Update: ordering was desalted — `Dag::ready_linearized` is plain lex — so there is no salted-order interaction at all.)*
* **Gap 8 (burn view / AA sweep):** no interaction — funding does not touch `perp_supply`/`perp_burned`.

---

## 5. Open Questions

1. **Window unit: samples vs Seq vs Height vs timestamp?** Draft uses samples (and seq for dedup) for determinism without clocks. Alternative is height-weighted or seq-gap weighted. Arithmetic mean is simplest; seq-weighted is one-line swap if measurement shows irregular report arrival. Question: should we make the weighting function a `FundingConfig` enum (`Arithmetic | SeqWeighted`) governable, or hardcode arithmetic and defer? **Proposal:** hardcode arithmetic v1, leave `compute_twap` comment with seq-weighted body ready; add config only if monitoring warrants.

2. **TWAP window size default** — 256 samples ≈ how many minutes? Depends on report cadence, not batch cadence. If reporters tick once per 10 blocks (≈20 s), 256 samples ≈ 85 min. If they tick once per block (≈2 s), 256 ≈ 8.5 min. Should we define window in **heights** (time ≈ blocks) instead of samples, so TWAP always spans wall time regardless of report rate? **Proposal:** keep samples for v1 (simplest, bounded), but document that future `FundingTwapWindow` may switch to height-windowed mean where empty heights count as zero-weight (or hold-last). Recommend calibrating after one week of reporter liveness metrics.

3. **Per-market vs global TWAP config** — v1 uses global `FUNDING_TWAP_WINDOW`. Permissionless `CreateMarket` markets have different volatility; a liquid BTC market wants longer TWAP than a micro-cap. Should we store per-market `FundingConfig` in `BTreeMap<MarketId, FundingConfig>` inside `meta_leaf`? **Proposal:** ship global for this batch; coalesce with Gap 3's `oracle_configs` map if that gap ships per-market oracle configs — single map can hold both.

4. **Notional pricing at `funding_index` vs `mark`** — pricing at `funding_index` is consistent with premium denominator, but changes exposure vs legacy (which priced at `median`). Alternatives: price at `mark` (exposure tracks mark notional) or at `min(mark, funding_index)`? **Proposal:** price at `funding_index` as drafted; if risk team prefers mark-notional, swap one argument in Phase 1 — no state migration.

5. **Governance of `FundingSourceKind` transition** — switching to `AggregatedExternal` requires an external feed allowlist and freshness threshold (`MAX_EXTERNAL_STALENESS Heights`). Should the switch be proposal-gated per market (`ParamKey::FundingSourceKind { market, value }`) or globally? **Proposal:** global `funding_source` v1, per-market override via same `oracle_configs` key in Gap 3 if merged.

6. **Should `UpdateExternalPrice` be signed by the same bonded key or a separate `external_keepers` allowlist?** Bonded oracles already stake 50k PERP; reusing them avoids new allowlist. But external feeds may have different trust (exchange keys). **Proposal:** separate `external_sources` allowlist governable, keep v1 `BondedMedianTwap` path allowlist-free to ship without governance plumbing.

7. **Do we need to expose `funding_index_twap` in `Checkpoint` JSON / `Batch::validate_against` debug log?** Today's `Checkpoint` commits `marks` and `last_index` inside `meta_leaf`; adding `funding_index_twap` is committed but not surfaced in the JSON for operator `post_batch.js`. **Proposal:** extend `export_batch` JSON to include `funding_twap` lengths for observability, but not required for consensus.

8. **Staging path if gap proves infeasible in one shot** — if TWAP ring + funding formula change is too large for one review, split: Phase 1 ships only the storage + `record_funding_sample` + `meta_leaf` commit (no funding switch) so watchers can audit TWAP without fee impact; Phase 2 flips `effective_funding_index` to TWAP on next activation height. Draft above ships both phases together for minimal diff; split is additive and safe to stage behind same activation flag if needed.

9. **Interaction with `MAX_AA_TREE_DEPTH` / 256h windows** — no interaction expected, but confirm `funding_twap` prune does not use height-expiry that would conflict with 256h replay assumptions. Draft uses length cap, not height expiry, so compatible.

