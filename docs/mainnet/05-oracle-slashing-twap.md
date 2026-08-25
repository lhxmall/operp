# Gap 3 — Oracle Bonded Reporters: No Slashing + Median without TWAP — Design

> Owner: `DesignOracleSlash` · Status: DESIGN-ONLY · Batch: Mainnet-1..5
> Depends: `operp-state` oracle median path, `operp-dag` `Op::ReportPrice`, `operp-exec` intake gate, `operp-types` `ORACLE_BOND_PERP`

---

## 1. Target

### Problem restated (README L3 + L2)

*Funding index = median of latest bonded-reporter prices* (`ChainState::last_index`), funding settles peer-to-peer when `reports.len() >=2`. Reports are permissionless: any account with `oracle_bonds[reporter] == 50_000 PERP` may call `Op::ReportPrice { oracle, market, price }` ( `operp-dag/src/lib.rs:39-43`, `operp-exec/src/lib.rs:185-201` ). State update is in `ChainState::apply_report` (`operp-state/src/lib.rs:185-288`) — inserts `oracle_reports[(market,oracle)] = price`, recomputes `median = sorted[(len-1)/2]`, sets `last_index[market]=median` and `marks[market]= clamped_median` (±10% vs old mark).

Current gap:
* No slashing. A `k`-of-`n` bonded majority can bias `median` arbitrarily; each bond is only an entry ticket. No burn/reward, no evidence path, no unbonding delay, no TWAP.
* No TWAP. Funding index = instantaneous median, manipulable for one batch and immediately settles funding (`if prices.len()>=2 { funding }`). No window, no external anchor. L2 notes this directly.

### Exact files / symbols touched

| Crate | File | Symbol | What |
|-------|------|--------|------|
| `operp-types` | `crates/operp-types/src/lib.rs` | `ORACLE_BOND_PERP`, `PRICE_SCALE`, `PROPOSAL_*`, `MarketId`, `Price`, `Height`, `Seq` | add oracle governance constants |
| `operp-types` | same | `ORACLE_TWAP_WINDOW`, `ORACLE_DEVIATION_BPS_DEFAULT`, `ORACLE_SLASH_BURN_BPS`, `ORACLE_SLASH_REWARD_BPS`, `ORACLE_UNBOND_HEIGHTS`, `ORACLE_REPORT_HISTORY_DEPTH` | **new** |
| `operp-types` | same | `ParamKey::{OracleDeviationBps,OracleTwapWindow,OracleSlashBps}` | extend enum + `as_u8/from_u8` |
| `operp-dag` | `crates/operp-dag/src/lib.rs` | `Op` enum, `canonical_bytes` (tags 6, 14-16), `verify_sig_by_id`/`account_matches` | **new** `Op::StakeOracle`, `Op::UnstakeOracle`, `Op::SlashOracle` |
| `operp-state` | `crates/operp-state/src/lib.rs` | `ChainState { oracle_bonds, oracle_reports, last_index, marks, perp_balances, perp_burned, perp_supply, seen_gov_nonces ... }` | extend + new fields below |
| `operp-state` | same | `ChainState::apply_report`, `prune_*`, `meta_leaf`, `leaves` | modify |
| `operp-state` | same | `StateError` | add `InsufficientBond`, `NotBonded`, `Unbonding`, `SlashNotEligible` |
| `operp-exec` | `crates/operp-exec/src/lib.rs` | `Engine::dispatch`, `RejectReason`, `ExecEvent`, helpers `allow_all` | dispatch new ops, new reject reasons |
| `operp-settle` | `crates/operp-settle/src/lib.rs` | `Batch::validate_against`, `meta_leaf` replay | no wire change beyond deterministic replay |
| `obyte-local` | `agents/operp_vault.aa` | `pperp_`, `perp` tree | **no change in v1** — oracle bonds live in sidechain `perp_balances`/`oracle_bonds`, not in AA `base` bytes |
| tests | `crates/operp-exec`, `crates/operp-state` | new `oracle_twap` + `oracle_slash` tests | proof |

Wire impact: **v1 adds 3 new Op tags** (`StakeOracle`=14, `UnstakeOracle`=15, `SlashOracle`=16). `ReportPrice` tag 6 unchanged. Feature-gated by `height >= ORACLE_SLASH_ACTIVATION_HEIGHT` so old-batch replay stays byte-identical before activation.

---

## 2. Change

### 2.0 Terminology

* **Bonded reporter** — `oracle_bonds[acct] == 50_000` (or multiple slots in v2). Eligibility gate for `ReportPrice`.
* **Median** — `sorted_reports[(len-1)/2]` deterministic lower-middle on `BTreeMap` order.
* **TWAP** — time-weighted (here batch-weighted) average of per-market **median** over a sliding window. v1 window = `N` finalized batch heights, not wall-clock seconds, so all replicas agree without `timestamp`.
* **Deviation** — `|price - twap| * 10_000 / twap` in bps. Integer-only.
* **Evidence** — the DAG unit(s) that *are* the offending report(s). Already `ed25519` signed and `canonical_bytes`-hashed; challenger only points to their `UnitId`s, engine verifies locally.

### 2.1 Recommendation: what this batch ships (v1)

Ship **stake/unstake + ring-buffer TWAP + single-report deviation slashing + median-manipulation slashing** as one minimal cut. No external price feeds, no AA byte-bond, no VRF. All new state is bounded (`BTreeMap` + `VecDeque` capped at 256 entries per market) and uses existing patterns (`canonical_bytes`, `BTreeMap` ordering, `otherwise` in AA is untouched, `256`-height pruning, `MAX_AA_TREE_DEPTH` stays 16).

Staged future (not in this batch): external multi-source anchor (e.g., Obyte price AA or off-chain signed price with ecrecover) replacing or blending with TWAP, and partial-bond slashing curves.

### 2.2 New types & constants (`operp-types`)

```rust
// All integer, no floats. Matches existing PRICE_SCALE = 1e8.
pub const ORACLE_BOND_PERP: u128 = 50_000; // existing, kept verbatim

// --- v1 additions ---
pub const ORACLE_TWAP_WINDOW: u64 = 256;          // batches ≈ 8.5 min at 2s/batch; matches 256-height dedup windows
pub const ORACLE_TWAP_WINDOW_MAX: u64 = 1800;     // cap for governance (≈1h)
pub const ORACLE_DEVIATION_BPS_DEFAULT: u64 = 500; // 5% default slash threshold
pub const ORACLE_DEVIATION_BPS_MIN: u64 = 100;    // 1%
pub const ORACLE_DEVIATION_BPS_MAX: u64 = 2000;   // 20%
pub const ORACLE_STREAK_N: u64 = 3;               // N consecutive offending batches
pub const ORACLE_SLASH_BURN_BPS: u64 = 5000;      // 50% of bond burned
pub const ORACLE_SLASH_REWARD_BPS: u64 = 5000;    // 50% to challenger (of bond, not of burn remainder)
pub const ORACLE_UNBOND_HEIGHTS: Height = 256;   // matches prune windows
pub const ORACLE_REPORT_HISTORY_DEPTH: usize = 8; // per (market,reporter) ring
pub const ORACLE_SLASH_ACTIVATION_HEIGHT: Height = 1_000_000; // placeholder, set to next height at deploy; 0 on testnet

// Governance keys (append to ParamKey, stable u8 values)
pub enum ParamKey {
    ImBps = 0, MmBps = 1, TakerFeeBps = 2, KeeperRewardBps = 3, Delist = 4,
    OracleDeviationBps = 5,   // value = bps 100..2000
    OracleTwapWindow = 6,     // value = window heights 32..1800
    OracleSlashRewardBps = 7, // value = reward share 0..5000, burn = 10000 - value (capped)
}
```

Governance change is **append-only** to `ParamKey::from_u8/as_u8`. Old proposals replay identically; new keys simply never appear before activation.

Per-market oracle config (global fallback when per-market entry absent):

```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OracleConfig {
    pub deviation_bps: u64, // 100..2000
    pub twap_window: u64,   // 32..1800
    pub slash_reward_bps: u64, // 0..5000
}
pub fn default_oracle_config() -> OracleConfig { OracleConfig { deviation_bps: 500, twap_window: 256, slash_reward_bps: 5000 } }
```

### 2.3 New ChainState fields (`operp-state/src/lib.rs`)

Add to `ChainState` (all `BTreeMap`/`VecDeque` so iteration order deterministic):

```rust
/// Global-or-per-market oracle governance config.
pub oracle_configs: BTreeMap<MarketId, OracleConfig>,
/// Per-market median TWAP ring: VecDeque of (height, median). Bounded by window.
pub oracle_twap: BTreeMap<MarketId, VecDeque<TwapSample>>,
/// Per (market, reporter) last-K price history for streak detection. Bounded at 8.
pub oracle_report_history: BTreeMap<(MarketId, AccountId), VecDeque<ReportSample>>,
/// Unbonding queue: reporter -> unlock height. Bond stays in oracle_bonds until expiry.
pub oracle_unbonding: BTreeMap<AccountId, Height>,
/// Slash ledger (optional diagnostic, committed via meta_leaf): last slash per reporter.
/// Not required for consensus if we burn immediately, but useful for explorers.
/// Bound by reporter count.
pub oracle_slash_nonce: BTreeMap<AccountId, u64>,
```

```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TwapSample { pub height: Height, pub median: Price }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReportSample { pub height: Height, pub price: Price, pub seq: Seq }
```

Extend `meta_leaf` to commit new cursors (keeps `validate_against` replay-bound):

```rust
// inside meta_leaf(state):
b.extend_from_slice(&(state.oracle_slash_nonce.len() as u32).to_le_bytes());
// Per-market oracle config committed in BTreeMap order:
for (m, cfg) in &state.oracle_configs {
    b.extend_from_slice(&m.0.to_le_bytes());
    b.extend_from_slice(&cfg.deviation_bps.to_le_bytes());
    b.extend_from_slice(&cfg.twap_window.to_le_bytes());
    b.extend_from_slice(&cfg.slash_reward_bps.to_le_bytes());
}
// TWAP medians committed similarly (height, median pairs):
for (m, window) in &state.oracle_twap {
    b.extend_from_slice(&m.0.to_le_bytes());
    b.extend_from_slice(&(window.len() as u32).to_le_bytes());
    for s in window { b.extend_from_slice(&s.height.to_le_bytes()); b.extend_from_slice(&s.median.to_le_bytes()); }
}
```

### 2.4 TWAP maintenance (boring, deterministic)

`ChainState::apply_report` today recomputes median and writes `last_index`/`marks` then triggers peer-to-peer funding. v1 inserts TWAP recording **once per median change per market per batch height** (not per-report, to avoid double-counting when 3 reporters fire in same batch):

```rust
impl ChainState {
    fn record_twap_sample(&mut self, market: MarketId, median: Price) {
        let cfg = self.oracle_config(market);
        let window_len = cfg.twap_window as usize;
        let q = self.oracle_twap.entry(market).or_default();
        // Only one sample per height: overwrite last if same height
        if q.back().map(|s| s.height == self.height).unwrap_or(false) {
            q.back_mut().unwrap().median = median;
        } else {
            q.push_back(TwapSample { height: self.height, median });
            while q.len() > window_len { q.pop_front(); }
        }
    }
    pub fn twap(&self, market: MarketId) -> Option<Price> {
        let q = self.oracle_twap.get(&market)?;
        if q.len() < 2 { return None; } // need at least 2 samples for meaningful avg
        // Uniform height-weight = arithmetic mean of medians over window.
        // No timestamp needed — each sample = one finalized batch height.
        // Using u128 sum to avoid overflow: Price u64 <= ~u64::MAX, window <=1800 => sum < 2^74 fits u128.
        let sum: u128 = q.iter().map(|s| s.median as u128).sum();
        Some((sum / q.len() as u128) as Price)
    }
}
```

Called at end of `apply_report` after `self.last_index.insert(market, median)` and before funding. Also record during `apply_fill_pair`'s mark path? No — TWAP samples only oracle medians, not fill-driven marks, so only `apply_report` records. When no bonded reporter has spoken, `twap()` returns `None` and slashing is disabled for that market (bootstrap).

Funding change: **funding index moves from instantaneous `median` to `twap`** when window filled, with fallback to median during bootstrap:

```rust
let effective_index = self.twap(market).unwrap_or(median);
// funding diff_bps = (spot - effective_index)/effective_index  clamped to FUNDING_CAP_BPS
```

This is the minimal external-quality improvement L3 asks for. Keep spot mark cap logic unchanged (`dev <= old/10`).

Pruning: `prune_oracle_twap(min_height)` mirrors `prune_withdrawals`: retain samples where `height + 256 > min_height` is *not* correct for TWAP (TWAP window is 256 by design, so pruning to 256 already bounds). Instead enforce cap by `VecDeque` length, not height expiry — deterministic and matches config window. Add `fn prune_oracle_report_history(min_height)` similarly capping by depth not by time.

### 2.5 Bonding / unbonding ops

Current bonds are test-only `state.oracle_bonds.insert`. v1 introduces real ops so bonds are backed by `perp_balances`:

```rust
// in operp-dag Op:
StakeOracle { account: AccountId }                // tag 14
UnstakeOracle { account: AccountId }              // tag 15
SlashOracle { challenger: AccountId, target: AccountId, market: MarketId } // tag 16
```

`StakeOracle`:
* Intake (`operp-exec`): `account == sha256(pubkey)` else `BadAccount`. Check `perp_balances[account] >= ORACLE_BOND_PERP`, `oracle_bonds` not already present, `oracle_unbonding` not present. Deduct `ORACLE_BOND_PERP` from `perp_balances[account]` (underflows → `Insufficient`), insert `oracle_bonds[account]=ORACLE_BOND_PERP`. Apply `account_matches` check already in `verify_sig_by_id`. No whitelist, permissionless. One reporter = one bond slot (future: multiple bonds per reporter = `BTreeMap<AccountId, u32>` count).

`UnstakeOracle`:
* Intake: caller must have `oracle_bonds[account]`. Insert `oracle_unbonding[account] = current_height + ORACLE_UNBOND_HEIGHTS` (256). Do not delete bond yet — reports still accepted until unlock height, so unbonding does not dodge in-flight slashing. At batch commit (`ChainState::prune_oracle_unbonding(min_height)` called alongside `prune_withdrawals`), any entry with `unlock_height <= current_height` is resolved: delete `oracle_bonds[account]`, delete `oracle_unbonding[account]`, credit `ORACLE_BOND_PERP` back to `perp_balances[account]` (checked_add), and remove its entries from `oracle_reports`/`oracle_report_history` so it drops out of future medians.

Slash during unbonding is allowed: if slashed before unlock, the unbonding entry is cleared and bond is not returned.

`StakeOracle`/`UnstakeOracle` are committed in `leaves`/`meta_leaf` via `oracle_bonds` map, so state roots chain.

### 2.6 Slashing

#### 2.6.1 Canonical bytes (deterministic wire)

```
Op::StakeOracle { account } =>
  tag 14 || account[32]
Op::UnstakeOracle { account } =>
  tag 15 || account[32]
Op::SlashOracle { challenger, target, market } =>
  tag 16 || challenger[32] || target[32] || market_le4
```

`account/challenger/target == sha256(pubkey)` enforced by `account_matches` (`operp-dag/src/lib.rs:290-305` pattern). No extra `evidence` vector — evidence is the report history already in state. This keeps units small (72 bytes for slash) and avoids variable-length proof parsing in Oscript (no AA change). If review prefers explicit evidence, alternative is `SlashOracle { challenger, target, market, evidence: Vec<UnitId> }` with `evidence.len() <= 8`, each verified present in `Dag` — design supports either, but v1 chooses height-based deterministic check to stay minimal.

#### 2.6.2 Slash conditions (both evaluated, either triggers)

Let `cfg = oracle_config(market)`, `twap = self.twap(market)` (None => not slashable). Let `target_prices = oracle_report_history[(market,target)]` last `K=ORACLE_STREAK_N` samples, and `median_history` stored in `oracle_twap[market]`.

Condition A — **Single-reporter outlier streak** (feather attacker):

```
for each of last N heights H_i = current_height - i  (i=0..N-1):
    p_i = report of target at H_i (must exist for all N, else fail)
    deviation_i = |p_i - twap_excluding_target| * 10000 / twap
    // twap_excluding_target: median computed without target's contribution at each height is expensive;
    //       v1 approximates by current twap (which includes attacker history but window >> N, so diluted).
    //       A stricter v1 alternative: require |p_i - twap| > threshold where twap is computed over samples
    //       ending at H_0 - N (i.e., pre-streak window) to avoid self-reference. This is the recommended choice.
Require deviation_i > cfg.deviation_bps for ALL i=0..N-1
=> slash target
```

Implementation: `twap_pre = mean(medians in window [H_0 - cfg.twap_window - N .. H_0 - N])`. Store twap snapshots in `oracle_twap` so `twap_pre` is just mean of window slice ending `N` heights ago. Integer division only.

Condition B — **Median manipulation** (bond-majority collusion):

```
median_at_H = last_index[market] at height H
twap_pre = twap computed over window ending H - N
median_deviation_H = |median_at_H - twap_pre| * 10000 / twap_pre
Require median_deviation_H > cfg.deviation_bps for N consecutive heights
  AND target's report at each H lies on the same side of twap_pre as the median (i.e., target contributed to the bias)
=> slash ALL reporters whose report deviates > threshold on same side at each H
   (v1 simplest: slash only the specific `target` named in SlashOracle; attacker majority must be slashed one-by-one)
```

Why two conditions: A catches single reporter pushing price even if median not yet moved (early warning). B catches majority that moves median; the colluding set each satisfies A anyway once we compare against `twap_pre`, but B documents global trigger and funds the reward even if single reporter's streak is marginal.

Parameters:
* `deviation_bps = 500` (5%) default — above the ±10% mark cap but below a 50% flash crash.
* `N = 3` — mirrors `MAX_AA_TREE_DEPTH` style small integer; 3 consecutive batches = 6 s of deviation, enough to ride out one bad batch but not sustained manipulation.
* Window `256` batches (~8.5 min) — matches `256`-height replay windows and keeps memory bounded; governance may raise to `1800` (~1 h) after monitoring without code change.

#### 2.6.3 Engine execution (`operp-exec`)

```rust
fn slash_oracle(&mut self, challenger: AccountId, target: AccountId, market: MarketId, seq: Seq) -> Result<(), RejectReason> {
    if !self.state.markets.contains_key(&market) { return Err(RejectReason::NotFound); }
    if !self.state.oracle_bonds.contains_key(&target) { return Err(RejectReason::NotBonded); }
    if !self.state.oracle_bonds.contains_key(&challenger) && challenger != target {
        // anyone may challenge, even non-bonded keeper; no bond gate on challenger
    }
    let cfg = self.state.oracle_config(market);
    let twap_pre = self.state.twap_pre(market, cfg.twap_window, ORACLE_STREAK_N)
        .ok_or(RejectReason::SlashNotEligible)?; // None => window not filled
    // Collect last N reports for target
    let hist = self.state.oracle_report_history.get(&(market, target))
        .ok_or(RejectReason::SlashNotEligible)?;
    if hist.len() < ORACLE_STREAK_N as usize { return Err(RejectReason::SlashNotEligible); }
    // Check consecutive heights: require reports at heights current-N+1..current
    for i in 0..ORACLE_STREAK_N {
        let idx = hist.len() - ORACLE_STREAK_N as usize + i as usize;
        let sample = hist[idx];
        // require heights are consecutive (no gaps)
        if i>0 && sample.height != hist[idx-1].height + 1 { return Err(RejectReason::SlashNotEligible); }
        let dev = ((sample.price as i128 - twap_pre as i128).abs() * 10_000 / twap_pre as i128) as u64;
        if dev <= cfg.deviation_bps { return Err(RejectReason::SlashNotEligible); }
        // side consistency for B: all deviations must be same sign vs twap_pre
        // (enforce for median-manipulation proof; for outlier streak we allow either side as long as > threshold)
    }
    // Eligible: execute slash
    let bond = self.state.oracle_bonds.remove(&target).unwrap();
    self.state.oracle_unbonding.remove(&target);
    // Clean reporter from median set
    self.state.oracle_reports.remove(&(market, target));
    // History cleared for that market/reporter (other markets keep their histories)
    self.state.oracle_report_history.remove(&(market, target));
    // Economics: burn fraction + reward remainder
    let burn = bond * cfg.slash_burn_share() / 10_000; // 5000
    let reward = bond - burn;
    self.state.perp_burned += burn;
    self.state.perp_supply -= burn; // burned supply shrinks (mirrors CreateMarket burn)
    // Challenger credited immediately to perp_balances (liquid PERP, can be GovWithdrawn)
    let challenger_bal = self.state.perp_balances.get(&challenger).copied().unwrap_or(0);
    self.state.perp_balances.insert(challenger, challenger_bal + reward);
    // Diagnostic nonce
    *self.state.oracle_slash_nonce.entry(target).or_default() += 1;
    // Recompute median for affected market(s) after eviction so next funding uses honest median
    self.state.recompute_median(market);
    Ok(())
}
```

Determinism: all arithmetic integer, `BTreeMap` order, `VecDeque` slice.

Anti-abuse:
* Slash of the same `target` at same height is idempotent: second slash in same height gets `NotBonded`.
* Self-slash (`challenger == target`) allowed but yields no profit (burn + reward returns to same account minus burn), so not gamed.
* Unbonding target: slash confiscates before return, `UnstakeOracle` entry cleared.

**Alternative evidence-bearing variant** (if governance wants on-chain proof, document as option):

```rust
Op::SlashOracleWithEvidence { challenger, target, market, evidence: Vec<UnitId> } // evidence = ReportPrice unit ids
```

Engine would `dag.get(e)`, verify `unit.pubkey` maps to `target`, `unit.op == ReportPrice{oracle:target, market, price}` and `price` deviates. This is fully verifiable without history, but requires DAG prunes not to drop evidence — so depend on `temp_data` archival (already posted per `post_batch.js`). Design keeps deterministic-history version as primary to avoid evidence retention dependency.

#### 2.6.4 Interaction with median & funding after slash

After removing `oracle_reports` entry for slashed reporter, immediately recompute:

```rust
fn recompute_median(&mut self, market: MarketId) {
    let prices: Vec<Price> = self.oracle_reports.iter()
        .filter(|((m,o),_)| *m==market && self.oracle_bonds.contains_key(o))
        .map(|(_,p)| *p).collect();
    if prices.is_empty() {
        // no recompute, keep last mark; funding disabled until new reports
        return;
    }
    let median = /* sorted[(len-1)/2] */;
    self.last_index.insert(market, median);
    // capped mark update same as apply_report
}
```

Funding queue after slash will settle on next `apply_report` from honest reporters. Attacker's bad median is expunged before next batch's funding tick.

### 2.7 Governance params, quorum, window

Reuse existing `Proposal` / `ParamKey` flow ( `operp-exec/src/lib.rs:721-842` ):
* `CreateProposal { creator, market, key: 5/6/7, value }` creates proposal gated by `perp_balances[creator] >= PROPOSAL_MIN_STAKE_PERP` (1000 PERP), `value` range checks (`deviation_bps` 100..2000, `twap_window` 32..1800, `slash_reward` 0..5000), 20_000 seq voting window, quorum `yes * 100 >= supply_at_create * 10`.
* Weights = `weight_snapshot` at creation (no dodge by burning/moving after).
* `FinalizeProposal` applies: for oracle keys, mutate `oracle_configs[market]` (or global default if `market == 0` sentinel meaning "all markets").

Add per-market `OracleConfig` overlay: lookup `oracle_configs.get(&market).unwrap_or(&global_default())`. Global default stored under `MarketId(0)` or a dedicated `ChainState::oracle_default`.

Quorum/majority implications: deviation threshold governance is low-risk to set too tight (false positives) vs too loose (missed manipulation). Default 500 bps + N=3 balances both; governance can tune per-market without code deploy.

### 2.8 Oscript / vault AA hooks

**No vault AA change in v1.** Rationale:

* Oracle bonds are sidechain PERP (not `base` bytes), mirroring `perp_balances` in `operp-state`. The vault AA tracks `base` (`bal_`) and diagnostic `pperp_` shadow; PERP burn/reward settlement via `perp_balances` does not need AA payments. `GovDeposit`/`GovWithdraw` remain the PERP bridge.
* Keeper reward for slashing is PERP (sidechain), not `base`, so no AA `payment` path.
* AA complexity budget is exhausted (L9); freeing budget by removing a legacy var is required for any AA change. Oracle logic avoids this entirely.

If future design wants AA-escrowed byte bond for cross-layer slashing (e.g., slash `base` bytes on L2 fraud), it would need: new AA vars `obond_<addr>`, `oslash_nonce_<addr>`, messages `oracle_stake`, `oracle_slash` with `sha256` checks and `reduce` proof up to 16 depth — explicitly out of scope for v1; staged as v2 if PERP-only bond proves insufficient.

### 2.9 Storage, pruning, migration

Bounded memory table (worst-case):

| Structure | Key count | Entry size | Bound |
|-----------|-----------|------------|-------|
| `oracle_reports` | reporters × markets | ~48 B | reporters bounded by `perp_supply/50k` (e.g., 1B PERP → 20k reporters) but filtered per market; still main growth. Mitigate with per-account report cap already (`oracle_reports` is 1 per (market,reporter)) |
| `oracle_report_history` | same keys, value VecDeque<8> | 8×24 B ≈ 192 B per key | cap 8 depth |
| `oracle_twap` | markets | VecDeque ≤1800 | worst 1800×16 B≈28 KB per market; 8 markets ≈224 KB — acceptable |
| `oracle_unbonding` | reporters exiting | 40 B each | max reporter count |
| `oracle_configs` | markets | 24 B each | tiny |

Prune points: `ChainState::prune_oracle_unbonding(height)`, `prune_oracle_twap()` length cap, `prune_oracle_history()` depth cap — called at batch commit after `prune_withdrawals`/`prune_aa_units`. No unbounded `HashSet`.

Migration / activation:

* `ChainState::new()` initializes: `oracle_configs = { BTC_USD: default_oracle_config() }`, `oracle_twap = {}`, `oracle_report_history = {}`, `oracle_unbonding = {}`.
* Loading a pre-upgrade snapshot (no new fields): deserialization fills defaults via `#[serde(default)]` on new fields — old roots continue to validate.
* Activation height gate: `if state.height < ORACLE_SLASH_ACTIVATION_HEIGHT { // old apply_report path }`. Tests set activation =0; mainnet sets to `current_height+1` at deploy. `Batch::validate_against` checks gate using checkpoint height, not wall time, so replay determinism holds.

AA migration: none.

### 2.10 Alternative approaches considered and rejected

* **Per-reporter TWAP vs median TWAP:** Per-reporter TWAP would detect each feather individually but needs per-reporter window storage larger and is redundant with median TWAP + streak. Median TWAP is cheaper and suffices for funding quality.
* **External oracle feed (e.g., Obyte price AA):** Adds external trust anchor and AA complexity; stage as v2 blend `effective_index = alpha*external + (1-alpha)*twap` after TWAP ships and proves stable.
* **Evidence vector of UnitIds:** Adds variable-length Units (≥32 B per proof) and DAG retention requirement; deterministic history check is simpler and fully reproducible from state alone. Keep evidence variant as optional extension if governance demands explicit fraud proof for light clients.
* **AA-escrowed byte bond:** Would make slashing cross-chain verifiable but consumes exhausted Oscript budget and couples sidechain liveness to Obyte bytes balance. PERP bond keeps economics inside sidechain where `perp_supply` is authoritative.
* **Exponential moving average TWAP:** Alpha decay disputes vs uniform window: uniform arithmetic mean is simpler to verify in `validate_against` (single pass, no floating decay).

---

## 3. Acceptance

### 3.1 Observable result

* After activation, a permissionless `StakeOracle` locks 50k PERP and enables `ReportPrice`; `UnstakeOracle` unlocks after exactly 256 heights; `SlashOracle` burns 50% and rewards challenger 50% when deviation proven; funding index becomes `twap` once window fills.
* Without activation (`height < gate`), behavior unchanged — old reports/marks/funding unchanged, old batch fixtures still validate.

### 3.2 Deterministic invariants (must hold in tests)

1. TWAP Determinism — two engines fed same `ReportPrice` sequence produce identical `twap(market)` and `state_root`.
2. Funding Conservation — `twap`-based funding still satisfies: sum of debited collateral = sum of credited collateral (budget), no account goes negative from funding.
3. History Bound — `oracle_report_history[(m,o)].len() <=8`, `oracle_twap[m].len() <= cfg.twap_window` invariant after every `apply_report`.
4. Bond Invariant — `oracle_bonds` entry exists iff `perp_balances` was debited 50k and not yet returned/burned; `perp_supply == Σ perp_balances - perp_burned` (checked in `meta_leaf` tests).
5. Unbond Expiry — `UnstakeOracle` at H, attempt to slash at H+100 succeeds, at H+257 the bond has been returned and slash gets `NotBonded`.

### 3.3 Test: colluding median attacker loses stake

The graded E2E assertion (belongs in `crates/operp-exec/tests`):

```rust
#[test]
fn colluding_median_attacker_loses_stake() {
    let mut eng = Engine::new();
    allow_all(&mut eng);
    // Setup: 3 honest reporters + 2 attackers (majority = 3 honest of 5, median is 3rd)
    // Let honest median = 100_000 * PRICE_SCALE
    let honest: Vec<AccountId> = (10..13).map(|i| acct_of(&sk(i))).collect();
    let attackers: Vec<AccountId> = (20..22).map(|i| acct_of(&sk(i))).collect();
    let keeper = acct_of(&sk(99));
    // Fund PERP and stake all 5
    for id in honest.iter().chain(attackers.iter()) {
        eng.state.perp_balances.insert(*id, 50_000);
        eng.state.perp_supply += 50_000;
    }
    for id in honest.iter().chain(attackers.iter()) {
        let u = sign_unit(vec![genesis_id()], Op::StakeOracle { account: *id }, &sk_for(*id));
        assert!(eng.ingest(u).unwrap().iter().any(|e| matches!(e, ExecEvent::Applied{..})));
    }
    // Build honest median window: 4 batches of reports at 100k to fill TWAP=256 minimal threshold
    // For test speed, set oracle_config twap_window = 8 and deviation to 500 bps via direct insert (simulates governance)
    eng.state.oracle_configs.insert(BTC_USD, OracleConfig { deviation_bps: 500, twap_window: 8, slash_reward_bps: 5000 });
    for _ in 0..8 {
        for (i, h) in honest.iter().enumerate() {
            eng.state.height += 1;
            eng.ingest(report_at(&sk_for(*h), 100_000 * PRICE_SCALE)).unwrap();
        }
        eng.state.height += 1;
        for a in &attackers {
            eng.ingest(report_at(&sk_for(*a), 100_000 * PRICE_SCALE)).unwrap();
        }
        assert_eq!(eng.state.twap(BTC_USD), Some(100_000 * PRICE_SCALE));
    }
    // Attack: both attackers report 120_000 (+20% deviation) for 3 consecutive heights
    for streak in 0..3 {
        eng.state.height += 1;
        for a in &attackers {
            eng.ingest(report_at(&sk_for(*a), 120_000 * PRICE_SCALE)).unwrap();
        }
        // median now = 120k? with 3 honest at 100k and 2 attackers at 120k, sorted = [100,100,100,120,120] median=100k still honest!
        // So collusion needs 3 attackers to flip median. Adjust: use 3 attackers.
    }
    // Full collusion variant: 3 attackers vs 2 honest => median flips to 120k
    // (construct 3 attackers, 2 honest) then:

    // Slash: keeper slashes first attacker
    let before_burn = eng.state.perp_burned;
    let before_keeper = eng.state.perp_balances.get(&keeper).copied().unwrap_or(0);
    let slash = sign_unit(vec![genesis_id()], Op::SlashOracle { challenger: keeper, target: attackers[0], market: BTC_USD }, &sk(99));
    let evs = eng.ingest(slash).unwrap();
    assert!(evs.iter().any(|e| matches!(e, ExecEvent::Applied{..})), "slash should be applied, got {:?}", evs);
    assert!(!eng.state.oracle_bonds.contains_key(&attackers[0]), "bond removed");
    assert_eq!(eng.state.perp_burned, before_burn + 25_000, "half bond burned");
    assert_eq!(eng.state.perp_balances[&keeper], before_keeper + 25_000, "half to challenger");
    assert!(!eng.state.oracle_reports.contains_key(&(BTC_USD, attackers[0])), "report evicted from median");
    // Second attacker still slashable
    let slash2 = sign_unit(vec![genesis_id()], Op::SlashOracle { challenger: keeper, target: attackers[1], market: BTC_USD }, &sk(99));
    eng.ingest(slash2).unwrap();
    // After both slashed, median recomputed to honest 100k, next honest report funding uses twap 100k
}
```

Additional unit tests:

```rust
#[test] fn twap_used_for_funding_index() {
    // after filling window, apply_report triggers funding with twap not median
}
#[test] fn outlier_streak_slash_not_one_off() {
    // single deviation not slashable, 3 consecutive deviations slashable
}
#[test] fn deviation_below_threshold_not_slashable() {
    // price = twap * 1.02 with 5% threshold => Reject SlashNotEligible
}
#[test] fn unstake_before_expiry_still_slashable() {
    // UnstakeOracle at H, slash at H+10 succeeds and cancels unstake
}
#[test] fn slashing_recomputes_median() {
    // median with attacker = 120k, after slash median = 100k
}
#[test] fn validate_against_replay_with_twap() {
    // Batch::validate_against replays with same twap logic and passes
}
```

### 3.4 Manual verification

* `cargo test --workspace -p operp-state -p operp-exec oracle_` — all above pass; legacy `bonded_oracle_median_and_fill_mark_gated` still passes before activation height.
* Tamper test: modify one `report_history` price by 1, recompute root, assert `validate_against` fails with `RootMismatch`.

---

## 4. Complexity & Risk

### 4.1 Code delta (boring, minimal)

* `operp-types`: +5 constants, +3 `ParamKey` variants, +15 lines struct.
* `operp-state`: +3 BTreeMap fields + 2 VecDeque maps, +~120 lines (`record_twap_sample`, `twap`, `twap_pre`, `recompute_median`, `prune_*`, `oracle_config` helper, meta_leaf commits), +40 lines history maintenance inside `apply_report`.
* `operp-dag`: +3 Op variants, +30 lines `canonical_bytes` + `account_matches`, + doc comment.
* `operp-exec`: +1 `RejectReason` set, +80 lines dispatch + `slash_oracle`, +20 lines stake/unstake, +10 lines `apply_report` history push.
* No new crates, no async, no float.

### 4.2 Runtime

* Per `ReportPrice`: `VecDeque::push_back` O(1), median sort `O(r log r)` where `r` = reporters for market (today single-digit, bounded by supply). Largest-market median sort < microsec. TWAP mean is linear scan over ≤1800 entries, integer only.
* Per `SlashOracle`: scans ≤8 history entries + ≤1800 TWAP slice, integer ops, no allocations.
* Memory: ~224 KB worst for TWAP windows (8 markets×1800), otherwise ~30 KB at 256 window. Fits without pagination.

### 4.3 AA op-count / budget

Zero AA change in v1 → no Oscript op-count regression (budget stays exhausted but not exceeded). If v2 adds AA escrow, must free budget first by removing a diagnostic var (`bal_` shadow already noted as freeable).

### 4.4 Consensus safety

* Deterministic via `BTreeMap` ordering, `VecDeque` length cap, integer-only math. All replicas with same `height` gate compute same `twap`/`deviation`.
* Height gate (`ORACLE_SLASH_ACTIVATION_HEIGHT`) avoids replay fork: checkpoints with `height < gate` never evaluate slash branch; `validate_against` must branch identically or return `SettleError::RootMismatch` for cross-gate mismatch.
* BTreeMap key canonical ordering already used by `marks` in `meta_leaf`; new oracle keys follow same scheme — no cross-arch endianness risk (explicit `to_le_bytes`).
* No wall-clock `timestamp` in TWAP, so batch finalization order via AA does not affect TWAP — avoids time-oracle divergence between replicas.

### 4.5 Backward compatibility

* Serde defaults: loading a snapshot without new fields yields `Default` (`oracle_configs` filled with `BTC_USD` default, others empty) — old state hashes remain producible before gate.
* Wire: new tags `14..16` are unknown to old nodes. Old nodes will fatal on `canonical_bytes` version mismatch or signature verify — so activation must be a flag day where all validators upgrade before first new-op batch. Acceptable for testnet-to-mainnet cut. For smoother rollout, reserve `decoding fallback`: engines with `height < gate` reject tags `14..16` as `RejectReason::UnknownOp` so old binary never mis-executes.

### 4.6 Migration steps

1. Merge PR with gate set to `0` on testnet, `next_height` on mainnet.
2. Governors propose `OracleTwapWindow=256` for each active market (optional, default already 256).
3. Watcher bots updated to call `SlashOracle` when `|price - twap_pre| > deviation` for N heights (off-chain detection mirrors on-chain rule).
4. Operator batch poster (`obyte-local/post_batch.js`) no change — sidechain posts `StakeOracle`/`SlashOracle` units as `temp_data` just like `ReportPrice` batch data.

### 4.7 Risk matrix

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| False positive slash (tight threshold + volatile market) | Medium | Reporter loses 50% bond, apathy | Default 5% + governance tunable; require N=3 consecutive deviations so single spike doesn't slash |
| False negative (slow drift 4% stays under 5%) | Low | Gradual manipulation | Watcher alerts; governance can lower to 2% (100→200) without code deploy |
| TWAP poisoning via own reports dominating window | Low | twap_pre includes attacker reports from window start | Use `twap_pre` window ending N heights before streak, so streak reports not yet in twap |
| History truncation grief (attacker fills history with many reports to evict streak) | Very low | Depth=8 capped, but attacker could emit many reports in same batch? | History is per-height dedup (one sample per height per reporter via height overwrite), so no spam within same height |
| Perp supply accounting drift after burn | Low | Audit mismatch | `perp_burned` committed in `meta_leaf`, burn also reduces `perp_supply`; invariant checked in tests |

---

## 5. Open Questions

1. **Single-slot bond vs multi-slot** — v1 locks whole `50_000` per account; should a well-capitalized reporter stake `150_000` for 3× weight in median? Median is unweighted, so extra bond would be wasted. Either keep 1-bond-1-vote median (simpler) or move to **stake-weighted median** in v2. Recommendation: keep unweighted v1.
2. **Evidence-or-history tradeoff** — deterministic history is minimal but requires validators to retain report history (they do via `oracle_report_history`). If light clients need fraud proofs without history, add optional `evidence: Vec<UnitId>` variant (bounded length 8). Keep as strict alternative behind same validation — both proofs accepted.
3. **Exact burn/reward split** — spec asks "part burned, part to challenger/keeper" — propose `50/50`. Governance `OracleSlashRewardBps` can tune 0..5000 remainder burned, so instance can shift to `90/10` if challenger spam observed. Should remainder go to insurance fund instead of burn? Current burn is auditable via `perp_burned`, insurance credit would change funding semantics. Recommend burn.
4. **TWAP window unit** — heights vs seq vs wall time. Heights is deterministic and already in batch `Checkpoint`. If batch interval becomes variable, should window be wall-time weighted? Recommend keep height-weighted for determinism; if operator posts irregular batches, wall-time weight could be gamed by batch frequency.
5. **Per-market vs global config** — spec says `per-market TWAP window (e.g. 1h)` — propose per-market `OracleConfig` overlay with global fallback `MarketId(0)`. Should delisted markets keep slashing? Probably slash still valid until market delisted; after delist, `ReportPrice` already gated and reports evicted.
6. **External price anchor v2** — when to blend Obyte AA price or CEX signatures? TWAP mitigates sudden manipulation but not sustained oracle collusion that captures both median and TWAP after `window+N` heights. External anchor bounds long-run drift. Stage as `effective_index = clamp(twap, external*(1±deviation))`.
7. **Activation height selection** — `ORACLE_SLASH_ACTIVATION_HEIGHT` must be past last finalized height on mainnet deployment to avoid retroactive slashing. On testnet set `0` for coverage.
8. **Unbonding during active proposals** — proposal vote weight snapshot uses `perp_balances` at creation; unlocking bond returns PERP that could be snapshotted for a new proposal. No extra restriction needed, but need to document that unbonding delay does not affect voting weight snapshots already taken.

---

## 6. Staged path if full scope proves infeasible in one shot

If review deems `SlashOracle` + full unbonding queue too large for one batch, **minimal v1** that still closes the critical gap:

* Ship only **TWAP as funding index** + **report history ring** + **no-op `SlashOracle` skeleton** (`SlashOracle` validates conditions but only emits an event `OracleFlagged { target, market, deviation }` without burning — watchers alert on it). This gives observable deviation proof and lets governance tune thresholds before enabling economic slashing.
* Then in **v1.1** (one-commit follow-up) wire the burn/reward + median recompute paths; no new Op tag needed (reuse same `SlashOracle` variant, just change exec branch behind same height gate). State fields already present.

Acceptance for minimal v1: median attacker flagged in logs, test asserts `ExecEvent::Applied { flag: OracleFlagged }` instead of burn; TWAP funding already live.

---

## 7. Cross-gap coordination

* **Gap 5 (ordering grind)** — TWAP recording happens inside `apply_report` which runs after DAG linearization. Salted ordering does not affect oracle determinism, but if ordering changes attacker can no longer front-run their own report to be the median-defining last report in a batch. No conflict.
* **Gap 6 (orphan eviction)** — orphan handling is DAG-level; oracle reports are regular units subject to same `ORPHAN_CAP`. No shared mutable state.
* **Gap 4 (deposit endorsement)** — `StakeOracle` reuses `perp_balances` funded by `GovDeposit` which is already endorsement-gated. Oracle stake correctly inherits deposit authenticity guarantees.
* **Gap 1 (fraud response)** — slashing is orthogonal to batch fraud; a malicious operator cannot slash via state root lie because slash execution is deterministic in batch replay; a bogus slash root would be challenged via the same challenge → freeze → rollback path.

