# Gap 11 — Replay-Dedup Windows Bounded at 256 Heights — Design

> Owner: `DesignReplayPersist` · Status: DESIGN-ONLY · Batch: Mainnet-1..5
> Depends on: `crates/operp-state`, `crates/operp-exec`, `crates/operp-settle`, `crates/operp-types`
> No AA change. No wire-format change in v1.

---

## 1. Target

### Problem restated (README L11)

Three dedup / anti-replay structures in `ChainState` are pruned on a **rolling 256-height window**:

| Structure | File | Type | Prune predicate | Current bound |
|-----------|------|------|-----------------|---------------|
| `withdrawals` (collateral Withdraw dedup) | `crates/operp-state/src/lib.rs:49,168` | `BTreeMap<(AccountId,u64), Withdrawal{height}>` | `w.height + 256 > min_height` | `WITHDRAWALS_CAP = 65_536` entries |
| `seen_aa_units` (Deposit / GovDeposit endorse dedup) | `crates/operp-state/src/lib.rs:50,174` | `HashMap<[u8;32], Height>` | `*h + 256 > min_height` | unbounded per-window, deposit-rate × 256 |
| `seen_gov_nonces` (GovWithdraw watermark) | `crates/operp-state/src/lib.rs:60` / `crates/operp-exec/src/lib.rs:654` | `HashMap<AccountId, u64>` watermark (strict `nonce <= watermark → DuplicateNonce`) | **never pruned** (watermark is monotonic) | `|accounts|` entries |

Pruning is invoked exactly once per batch commit inside `crates/operp-settle/src/lib.rs:135-136`:

```rust
engine.state.height = prev.height + 1;
let height = engine.state.height;
engine.state.prune_withdrawals(height);
engine.state.prune_aa_units(height);
```

**Consequence:** a duplicate `(account, nonce)` withdraw or a reused `aa_unit` deposit whose original landed at height `h` and is replayed at `h+257` passes sidechain `Engine::withdraw` / `Engine::deposit` (the entry was pruned). AA-side global `wd_<addr>` / `wp_<addr>` still caps funds — no theft — but the sidechain will **apply** a second debit, inflate `withdrawn_total` (`W`) and `aa_root`, produce a state root that watchers must challenge to freeze the height, and waste batch capacity. Gov nonces escape this via the monotonic watermark, but that watermark today lives only in RAM, so a **node restart** rewinds it to the last snapshot height and re-opens the window.

`validate_against` replays deposits/withdrawals without any height-indexed log: after pruning, a replay from genesis and a replay from a recent snapshot can disagree on whether a late duplicate is rejected, though the `state_root` chain still binds (`meta_leaf` commits `height`).

### Exact files / symbols touched

| Crate | File | Symbol | Action |
|-------|------|--------|--------|
| `operp-types` | `crates/operp-types/src/lib.rs` | `REPLAY_WINDOW_HEIGHTS`, `REPLAY_WINDOW_HEIGHTS_LEGACY` constants | **add** (window constant, was hard-coded `256`) |
| `operp-state` | `crates/operp-state/src/lib.rs:10-16` | `Withdrawal` | add `seq: Seq` optional for index-less pruning (see 2.3) |
| `operp-state` | `crates/operp-state/src/lib.rs:18-69` | `ChainState` | change `seen_aa_units` to `BTreeMap<[u8;32], Height>` (ordered) or keep HashMap + auxiliary BTree index; add `dedup_journal_seq` + persistence trait |
| `operp-state` | `crates/operp-state/src/lib.rs:168-176` | `prune_withdrawals`, `prune_aa_units` | generalize to `prune_at(height, window)`; add `prune_with_window` helper; keep old names as wrappers |
| `operp-state` | `crates/operp-state/src/lib.rs:49` | `withdrawals: BTreeMap<(AccountId,u64), Withdrawal>` | keep type, add height-indexed secondary index for O(k log n) prune instead of O(n) scan (optional) |
| `operp-state` | `crates/operp-state/src/lib.rs:60` | `seen_gov_nonces` | add `persist_gov_nonce_log` module; no type change |
| `operp-exec` | `crates/operp-exec/src/lib.rs:13-16` | `WITHDRAWALS_CAP` | unchanged, but document interaction with window |
| `operp-exec` | `crates/operp-exec/src/lib.rs:648-667` | `gov_withdraw` watermark check | add `GovNonceJournal` write-ahead before `insert` |
| `operp-settle` | `crates/operp-settle/src/lib.rs:98-153` | `Batch::from_applied` | add `prune_cadence` parameter; wire snapshot / journal flush |
| `operp-settle` | `crates/operp-settle/src/lib.rs:190-260` | `Batch::validate_against` | inject `replay_window` param for determinism; no AA interaction |
| new | `crates/operp-state/src/persist.rs` | `DedupStore`, `RocksColumnFamily` enum, `Snapshot` trait | **new file** (or `crates/operp-exec/src/persist.rs`) — abstraction over storage backend |
| new | `crates/operp-exec/src/journal.rs` | `GovNonceJournal` | **new file** — append-only WAL for `seen_gov_nonces` |
| `obyte-local` | `agents/operp_vault.aa` | `wd_` / `wp_` | **no change** — documented as fund-safety invariant |
| `Cargo.toml` | workspace | `rocksdb` optional dep | add as `optional = true` behind `persist-rocksdb` feature |

**Non-goals (this doc):** changing AA `wd_`/`wp_` logic, changing `CHAIN_ID`, changing `BATCH_MAX_UNITS`, changing orphan dedup (Gap 6), changing ordering (Gap 5).

---

## 2. Change

### 2.0 Design principle

Keep the proposal **minimal and boring**:

* Wire format stays `canonical_bytes` + `BTreeMap` ordering — no new op fields.
* `otherwise` guards stay untouched in the AA.
* `MAX_AA_TREE_DEPTH`, `WITHDRAWALS_CAP`, `ORPHAN_CAP` untouched.
* All pruning stays height-indexed (`Height = u64`), deterministic, independent of wall time.
* The fix ships as a **storage choice**, not a mandatory DB migration: operators who accept the larger RAM budget can ship choice B without RocksDB.

### 2.1 Two storage choices (operator picks one)

Both satisfy the acceptance test ("duplicate after 300 heights still rejected after restart"). They differ in memory / operational cost.

#### Choice A — Persistent dedup (recommended for mainnet operators)

Replace the in-memory-only retention with a **durable snapshot + optional RocksDB column families**. The window itself stays at 256 or moves to 2048 (configurable) — persistence, not window size, is what closes the restart gap.

**Why not "just RocksDB" unconditionally:** the current `ChainState` is a single struct replayed from genesis via `Batch::validate_against`. Forcing every validator to run RocksDB adds build complexity (native lib) and complicates deterministic replay tests. The design therefore abstracts storage behind a trait; the default validator uses an in-memory BTree backed by periodic snapshot files, and operators who want crash safety without replay-from-genesis use RocksDB.

```rust
// crates/operp-state/src/persist.rs (new)
pub const REPLAY_WINDOW_HEIGHTS: Height = 2048; // was 256
pub const REPLAY_WINDOW_LEGACY: Height = 256;   // for replay of old checkpoints

pub trait DedupStore {
    fn load_withdrawals(&self) -> BTreeMap<(AccountId,u64), Withdrawal>;
    fn load_aa_units(&self) -> BTreeMap<[u8;32], Height>;
    fn load_gov_nonces(&self) -> HashMap<AccountId, u64>;
    fn load_height(&self) -> Height;
    fn put_withdrawal(&mut self, key: (AccountId,u64), w: Withdrawal);
    fn put_aa_unit(&mut self, unit: [u8;32], h: Height);
    fn put_gov_nonce(&mut self, acct: AccountId, nonce: u64);
    fn prune_before(&mut self, min_height: Height, window: Height);
    fn flush(&mut self) -> std::io::Result<()>;
}
```

Two implementations:

| Backend | When to use | Durability | Complexity |
|---------|-------------|------------|------------|
| `MemoryWithSnapshot` (default, zero new deps) | validators, tests, light operators; replay from snapshot file every N heights | snapshot file `chainstate.<height>.snap` (bincode/serde_json) fsynced; WAL for nonces (see 2.4) | ~150 lines, no native deps |
| `RocksDbStore` (feature `persist-rocksdb`) | production operator that cannot afford full replay from genesis after crash | RocksDB column families `withdrawals`, `aa_units`, `gov_nonces`, `meta` | adds `rocksdb` crate, ~200 lines |

Snapshot cadence: every **64 heights** (~128 s at 2 s/batch) or on every `Batch::from_applied` if `--fsync-every-batch` is set. Snapshots are content-addressed by `state_root`; on restart the engine loads the **latest snapshot whose `height <= last_finalized`** (finalized heights are immutable), then replays `temp_data` batches forward via `validate_against`. This matches the existing `prev.height + 1` binding in `Batch::from_applied:130`.

**Prune cadence under persistence:** unchanged call site — `Batch::from_applied` still calls `prune_withdrawals(height)` and `prune_aa_units(height)` exactly once per committed batch, now routed through the store trait so pruning also deletes from disk. No background thread. No periodic compaction beyond RocksDB's own. The window predicate becomes parametric:

```rust
impl ChainState {
    pub fn prune_withdrawals_at(&mut self, at: Height, window: Height) {
        self.withdrawals.retain(|_, w| w.height + window > at);
    }
    pub fn prune_aa_units_at(&mut self, at: Height, window: Height) {
        self.seen_aa_units.retain(|_, h| *h + window > at);
    }
    // backward-compat wrappers until flag day:
    pub fn prune_withdrawals(&mut self, at: Height) {
        self.prune_withdrawals_at(at, REPLAY_WINDOW_HEIGHTS)
    }
    pub fn prune_aa_units(&mut self, at: Height) {
        self.prune_aa_units_at(at, REPLAY_WINDOW_HEIGHTS)
    }
}
```

For the `BTreeMap` variant a secondary index avoids O(n) scans when maps grow to 65k entries: maintain `BTreeMap<Height, Vec<(AccountId,u64)>>` (height → keys) updated on insert; pruning then iterates heights `< at - window` only. For `HashMap` `seen_aa_units`, switch to `BTreeMap<[u8;32], Height>` (lexicographic order is already deterministic) or keep HashMap and add `BTreeMap<Height, Vec<[u8;32]>>` index. The index is derived state — not persisted separately, rebuilt from the primary map on load.

RocksDB schema (when enabled):

```
CF `meta`       : key "height" -> u64 LE, "state_root" -> [u8;32], "window" -> u64
CF `withdrawals`: key (AccountId 32 || nonce 8 LE) -> value (amount i128 LE || height u64 LE || pending bool)
CF `aa_units`   : key [u8;32] -> value Height u64 LE
CF `gov_nonces` : key AccountId 32 -> value nonce u64 LE
CF `journal`    : key seq u64 LE -> value (AccountId 32 || nonce 8 LE)  // optional WAL
```

All keys use `BTreeMap` ordering so RocksDB iteration order matches `ChainState` iteration order, preserving deterministic `state_root` / `aa_root` computation (both sort leaves / pairs before hashing).

**Restart recovery (Choice A):**

1. Operator starts node with `--state-dir ./data` (or `OPERP_STATE_DIR` env).
2. `Engine::load_or_genesis(dir)` looks for latest `chainstate.<height>.snap` or RocksDB `meta.height`. If found, deserializes `ChainState` (including `withdrawals`, `seen_aa_units`, `seen_gov_nonces`, `aa_addresses`, `withdrawn_total`, `height`, `last_unit`, `seq`, `marks`).
3. Node fetches `temp_data` batches for heights `snapshot.height+1 .. tip` from Obyte (or local `temp_data` cache) and replays each through `Batch::validate_against(&prev_root, &mut replay_engine)` — which re-applies `prune_withdrawals_at(height, window)` deterministically, so the reconstructed dedup maps match the pre-crash state.
4. A duplicate `(account, nonce)` whose original is at height `h` is therefore still present in the store when the duplicate arrives at `h+300`, regardless of an intervening restart, because `h + window > h+300` for `window=2048` (and for `256` if persistence is enabled, the entry is literally still on disk).

If the snapshot is stale (power loss between snapshot and tip), replay fills the gap — no dedup entry is lost.

#### Choice B — Larger in-memory window, no new storage (minimal diff)

Keep everything in RAM, change one constant:

```rust
// crates/operp-state/src/lib.rs (or crates/operp-types/src/lib.rs)
- w.height + 256 > min_height
+ w.height + REPLAY_WINDOW_HEIGHTS > min_height  // = 2048
```

and same for `seen_aa_units`. Gov nonces remain watermark-based (RAM-only) but add a **local append-only journal file** for cross-restart safety (see 2.4) without requiring RocksDB.

**When Choice B is sufficient:** sidechain fund safety does not depend on the window — AA `wd_`/`wp_` are global. The window only gates DoS re-execution (an attacker forcing a second `apply` of the same nonce). If the operator's availability plan includes frequent snapshots (e.g., snapshot every 64 heights to local SSD) and replay from snapshot on restart, the 2048-height window gives ~68 minutes of wall time at 2 s/batch (2048 × 2 s = ~68 min), vs ~8.5 min for 256. That is longer than the 600 s stability window and comparable to the 3600 s challenge window, so an attacker cannot wait out the window without also waiting out the challenge window — the challenge path already handles it.

**Trade-off table:**

| Dimension | Choice A (persistent) | Choice B (2048 in-RAM) |
|-----------|----------------------|------------------------|
| Duplicate after 300h rejected after restart | Yes, durably (disk) | Yes, **only if** journal/snapshot replay covers the gap; cold restart from genesis with pruned log would re-open >256h window unless window=2048 |
| RAM cost at steady state | Same as B (window size dominates), but offloads to RocksDB; optional | Higher than 256, see 2.2 |
| Thru-put impact | Snapshot fsync ~1 ms/64 heights; RocksDB ~5-10 µs per dedup op | None (one integer compare) |
| Build / ops | RocksDB native dep if enabled; snapshot file otherwise | One-line constant change + journal file |
| Determinism risk | Must ensure iteration order identical between stores (BTreeMap ordering) | Trivial |
| Migration | Snapshot at upgrade height; old pruned entries cannot be recovered (acceptable — forward window only) | Flag-day height gate (see 2.5) |

**Recommendation:** Ship **Choice B as v1** (this batch) because it is a 3-line change, reviewable in minutes, and closes the DoS gap for any practical attack (attacker must now wait 2048 heights ≈ 1 h, during which the AA challenge window is still open and the batch is finalized). Ship **Choice A as v1.1** immediately after, behind a `--persist` flag, for operators who need crash safety without holding 2048 heights in RAM or for deployments where restarts are frequent. The design below specifies both so v1.1 is an additive diff.

### 2.2 Memory budget analysis (2048 window)

Assumptions: `BATCH_MAX_UNITS = 512`, batch interval ~2 s, 50% of ops are `Withdraw` in adversarial peak (honest steady state is ~10% withdraws). `AccountId = 32 bytes`, `Withdrawal{amount i128 16 + pending bool 1 + height u64 8 + padding}` ~32 bytes struct + BTreeMap overhead ~48 bytes per node (two pointers + color + alloc). `aa_unit` key 32 bytes + Height 8 bytes + HashMap overhead ~56 bytes per entry.

| Structure | Entries at 256-window (adversarial) | Bytes (256) | Entries at 2048-window | Bytes (2048) | Notes |
|-----------|--------------------------------------|-------------|------------------------|--------------|-------|
| `withdrawals` | `WITHDRAWALS_CAP = 65_536` (hard cap) — window increase does **not** increase cap | ~65k × ~80 B ≈ **5.2 MB** | same cap, same bytes | **5.2 MB** | Cap is the bound, not the window. Window only extends entry lifetime. |
| `withdrawals` (honest, 10% withdraws) | ~256×512×0.1 ≈ 13k entries | ~1 MB | ~2048×512×0.1 ≈ 105k entries but **capped at 65k** → 65k | 5.2 MB worst | Honest path hits cap only under spam; otherwise ~8× growth but still capped. |
| `seen_aa_units` (deposits) | deposit rate ~5% of units → 256×512×0.05 ≈ 6.5k entries | ~6.5k × ~88 B ≈ **0.57 MB** | 2048×512×0.05 ≈ 52k entries | **~4.6 MB** | No cap — this is the growth driver. |
| `seen_aa_units` worst (100% deposits, spam) | 256×512 ≈ 131k entries | ~11.5 MB | 2048×512 ≈ 1M entries | ~88 MB | Spam case triggers `WITHDRAWALS_CAP` path indirectly (spammer limited by AA unit creation cost — each distinct unit costs Obyte fees). |
| `seen_gov_nonces` | `|accounts|` ≤ 10k typical, ≤ 100k at 2^16 tree cap | 10k×40 B ≈ 0.4 MB | same | 0.4 MB | Watermark — window-independent. |
| Total honest steady state | | **~2 MB** | | **~10 MB** | 5× increase, negligible vs account/book state (accounts ~ few MB per 10k accounts). |
| Total adversarial / spam | | **~17 MB** | | **~98 MB** | Fits in 256 MB budget comfortably; no OOM. Pruning keeps it bounded. |

Conclusion: moving from 256 → 2048 costs **~8 MB honest, ~80 MB worst-spam** additional RAM — well within a sidechain operator's typical 1-2 GB allocation. No need for RocksDB purely for memory reasons; persistence is justified for **crash safety**, not RAM.

If RocksDB is used, memory for dedup maps drops to near-zero (only hot keys in block cache, ~4 MB cache). Disk: same entry counts × value sizes; ~20 MB for 1M `aa_units` entries plus overhead.

### 2.3 API / constant changes (step-by-step)

1. **Add window constant** — `crates/operp-types/src/lib.rs` (or `crates/operp-state/src/lib.rs` if types must stay lean):

   ```rust
   /// Replay-dedup window in heights. Duplicates with original height `h`
   /// are rejected while `h + REPLAY_WINDOW_HEIGHTS > current_height`.
   /// 2048 heights ≈ 68 min at 2 s/batch, covering the 3600 s challenge window.
   pub const REPLAY_WINDOW_HEIGHTS: Height = 2048;
   /// Legacy value for replay of checkpoints produced before the flag day.
   pub const REPLAY_WINDOW_LEGACY: Height = 256;
   /// Height at which the new window activates. Checkpoints with
   /// `height < ACTIVATION` use LEGACY; `>= ACTIVATION` use new.
   pub const REPLAY_WINDOW_ACTIVATION: Height = /* set at deploy, e.g. current_tip+1 */;
   ```

   Alternative (simpler, no activation): change `256` → `2048` in both prune predicates and treat old checkpoints as implicitly truncated — replay from genesis would disagree for ~1792 heights of history, but since `meta_leaf` commits `height`, old roots remain valid; only future pruning horizon changes (forward-compatible). The activation gate is only needed if strict replay determinism from genesis is required.

2. **Generalize prune predicates** — `crates/operp-state/src/lib.rs:168-176`:

   ```rust
   pub fn prune_withdrawals_at(&mut self, at: Height, window: Height) {
       self.withdrawals.retain(|_, w| w.height + window > at);
   }
   pub fn prune_aa_units_at(&mut self, at: Height, window: Height) {
       self.seen_aa_units.retain(|_, h| *h + window > at);
   }
   pub fn prune_withdrawals(&mut self, at: Height) {
       let w = if at < REPLAY_WINDOW_ACTIVATION { REPLAY_WINDOW_LEGACY } else { REPLAY_WINDOW_HEIGHTS };
       self.prune_withdrawals_at(at, w)
   }
   pub fn prune_aa_units(&mut self, at: Height) {
       let w = if at < REPLAY_WINDOW_ACTIVATION { REPLAY_WINDOW_LEGACY } else { REPLAY_WINDOW_HEIGHTS };
       self.prune_aa_units_at(at, w)
   }
   ```

   For a minimal v1 without activation, just replace `256` with `REPLAY_WINDOW_HEIGHTS` directly.

3. **Add height-indexed prune optimization** (optional, for Choice B at 2048):

   ```rust
   // inside ChainState, kept in sync on insert
   withdrawals_by_height: BTreeMap<Height, Vec<(AccountId, u64)>>,
   aa_units_by_height: BTreeMap<Height, Vec<[u8;32]>>,
   // prune then becomes:
   // for h in self.withdrawals_by_height.keys().copied().collect::<Vec<_>>()
   //     if h + window <= at { drain h }
   ```

   This is an optimization, not required for correctness — `retain` over 65k entries per batch is ~65k comparisons × ~500 batches/s worst = ~32M compares/s, trivial.

4. **Wire `Batch::from_applied` and `validate_against`** — `crates/operp-settle/src/lib.rs:130-136`:

   ```rust
   // from_applied
   engine.state.height = prev.height + 1;
   let height = engine.state.height;
   engine.state.prune_withdrawals(height); // now parametric
   engine.state.prune_aa_units(height);
   // + flush snapshot/journal if persist enabled
   #[cfg(feature = "persist-rocksdb")]
   engine.state.flush_persist()?;
   ```

   `validate_against` already advances `replay.state.height = checkpoint.height` at 246 — it must also call the same `prune_*` with matching window before the final root check, otherwise a replay that prunes differently would yield a different `state_root` (different `withdrawals` / `aa_units` are not directly in `state_root`, but `withdrawn_total` and `aa_addresses` are — withdrawals map itself is not committed, only its side effects via `withdrawn_total` and account collateral are. So pruning difference does not affect `state_root` determinism — but keeping replay pruning identical avoids log divergence). Document that pruning is **not** part of root commitment.

5. **No AA change** — `obyte-local/agents/operp_vault.aa` `wd_`/`wp_` logic remains global and is the ultimate fund-safety net. Add a comment documenting that sidechain window only affects DoS, not fund safety:

   ```js
   // sidechain dedup window = REPLAY_WINDOW_HEIGHTS (2048); AA wd_/wp_ is global
   // — sidechain replay beyond the window can only waste batch space, never
   // drain funds, because the AA caps `amount + wd_[addr]` at proven collateral.
   ```

### 2.4 Gov nonce watermark — persistent replay log for cross-restart safety

Current `seen_gov_nonces: HashMap<AccountId, u64>` is a **strict watermark**: `nonce <= watermark → DuplicateNonce` (`crates/operp-exec/src/lib.rs:656-657`). This is already unbounded-time (never pruned) and bounded by account count. The gap is **durability across restarts**: if the node crashes after processing nonce `n` and restarts from a snapshot at height `h < current`, the watermark rewinds and nonce `n` can be replayed.

**Design (works with both Choice A and B, no RocksDB required):**

Append-only journal file `gov_nonces.journal` (or RocksDB WAL) in `state_dir`:

```
record := seq:u64 LE || account:32 || nonce:u64 LE || height:u64 LE   (52 bytes)
```

Write path (`crates/operp-exec/src/journal.rs` or inline in `gov_withdraw`):

```rust
fn gov_withdraw(&mut self, account: AccountId, amount: u128, nonce: u64) -> Result<..., RejectReason> {
    let watermark = self.state.seen_gov_nonces.get(&account).copied().unwrap_or(0);
    if nonce <= watermark { return Err(RejectReason::DuplicateNonce); }
    // ... balance checks ...
    // durability: fsync journal BEFORE mutating in-memory watermark,
    // so a crash between journal write and state flush does not lose the nonce.
    self.journal.append_gov_nonce(account, nonce, self.state.height)?;
    self.state.perp_balances.insert(account, bal - amount);
    self.state.perp_supply -= amount;
    self.state.seen_gov_nonces.insert(account, nonce);
    Ok(Vec::new())
}
```

Recovery: on `Engine::load_or_genesis`, if `gov_nonces.journal` exists, replay it after loading the snapshot:

```rust
for rec in journal.read_all()? {
    let cur = state.seen_gov_nonces.get(&rec.account).copied().unwrap_or(0);
    if rec.nonce > cur {
        state.seen_gov_nonces.insert(rec.account, rec.nonce);
    }
}
```

The journal is **idempotent** — replaying the same record twice keeps the max nonce.

Pruning / compaction: the journal is bounded by `|accounts| × avg nonces per account`. With 10k accounts × 10 gov ops each = 100k records × 52 B ≈ 5.2 MB. Compaction triggers when the journal exceeds 1 MB: rewrite it as a snapshot of current `seen_gov_nonces` (one entry per account, the watermark), fsync, then truncate the journal. This is identical to a WAL checkpoint.

Cost: one `fsync` per `GovWithdraw` (rare — governance ops are infrequent, not per-trade). For batch sync paths, `fsync` is amortized across the batch (one fsync after the batch's `prune` + `flush`).

**Why a journal and not just snapshot frequency:** `GovWithdraw` is the only op with a global watermark; losing even one watermark entry re-opens a replay hole. Snapshots every 64 heights could miss a nonce processed 1 height ago if the node crashes before the next snapshot. The journal closes that 1-63 height gap with minimal I/O.

### 2.5 Migration / backward compat / flag day

* **No state migration for pruned history:** entries already pruned under the 256 window cannot be recovered — they are gone. The new window only affects entries from `ACTIVATION` onward, so a replay from genesis of old heights still prunes at 256 (legacy predicate). The `REPLAY_WINDOW_ACTIVATION` gate ensures deterministic replay.
* **Snapshot upgrade:** at `ACTIVATION = tip+1`, the operator writes a fresh snapshot with `window = 2048` in `meta`. Nodes that upgrade before activation still prune at 256 until they cross the gate — no fork.
* **Rollback:** downgrading after activation prunes more aggressively (256) and could accept a duplicate that was previously rejected within 257-2048. That is a DoS re-open, not a fund-safety issue, but operators should not downgrade without resyncing from a pre-activation snapshot.
* **Wire compatibility:** no `canonical_bytes` change. Old units replay identically. `Checkpoint.prev_state_hash` chain is unaffected (pruning is not committed in `state_root` beyond its side effects on `withdrawn_total` etc., which are monotonic).
* **AA compatibility:** none — AA `wd_`/`wp_` unchanged. Sidechain window extension does not require an AA redeploy.

### 2.6 What this batch WOULD ship as v1 (staged path if RocksDB proves infeasible)

If adding RocksDB in one shot is rejected (native dep, build friction):

* **v1 (this batch):** change `256 → 2048` in `prune_withdrawals` / `prune_aa_units` (2 lines), add `REPLAY_WINDOW_HEIGHTS = 2048` constant, add `gov_nonces.journal` WAL (new file `journal.rs`, ~80 lines, `std::fs` only, no new deps), add `MemoryWithSnapshot` snapshot file (`chainstate.<height>.snap` via `serde_json`/`bincode`, flush every 64 heights). This closes the 300-height duplicate gap and the restart gap with zero native deps.
* **v1.1 (next batch):** add `persist-rocksdb` feature gate, `RocksDbStore` impl, column-family schema, and `--state-dir` flag. v1.1 is additive — no v1 logic changes.

If even the journal is infeasible in one shot, the absolute minimal v1 is just the `256 → 2048` constant change — still passes the "duplicate after 300 heights rejected **without restart**" half of the acceptance test, and documents the restart caveat as a known limitation until v1.1.

---

## 3. Acceptance

### Observable result

* After the fix, `Engine::withdraw(account, amount, nonce=7)` at height `h` and a second `Engine::withdraw(account, amount, nonce=7)` at height `h+300` is rejected as `DuplicateNonce` **even after a node restart** between the two calls — verified by loading the persisted state (snapshot + journal / RocksDB) and re-ingesting the duplicate unit.
* `Engine::deposit` / `GovDeposit` with a reused `aa_unit` at `h+300` is rejected as `DuplicateDeposit` after restart for the same reason.
* `GovWithdraw` with `nonce=5` then `nonce=4` is rejected as `DuplicateNonce` (watermark), and after restart the watermark still holds — `nonce=4` still rejected.
* Normal operations within the window continue to be rejected (no regression), and operations outside the new 2048 window are correctly accepted (window is bounded, not infinite — except gov nonces which are watermark-infinite).
* **Fund safety invariant unchanged:** even if sidechain dedup were bypassed, `obyte-local/agents/operp_vault.aa` `wd_`/`wp_` still caps withdrawals at proven `W` / `perp` — demonstrated by existing `test_vault_aa.js` proof-gated withdrawal tests (no change).

### Tests / E2E assertions (new)

```rust
// crates/operp-exec/tests/replay_persist.rs (new)
#[test]
fn duplicate_withdraw_300h_rejected_after_restart() {
    let dir = tempfile::tempdir().unwrap();
    let mut eng = Engine::new();
    // allow_all + seed account + deposit
    // withdraw nonce=7 at height h=10
    eng.state.height = 10;
    eng.ingest(withdraw(&sk(1), 100, 7)).unwrap();
    assert!(eng.state.withdrawals.contains_key(&(acct_of(&sk(1)), 7)));
    // commit batches up to h=310, pruning at each step (window=2048 keeps entry)
    for h in 11..=310 {
        let prev = eng.state.clone();
        let units = vec![noop_unit(&sk(2))];
        for u in &units { eng.ingest(u.clone()).unwrap(); }
        let batch = Batch::from_applied(&prev, &mut eng, &[units[0].id]).unwrap();
        // snapshot every 64 heights
        eng.flush_snapshot(dir.path()).unwrap();
    }
    assert!(eng.state.withdrawals.contains_key(&(acct_of(&sk(1)), 7)),
        "entry must survive 300 heights with window=2048");

    // simulate restart: load from snapshot + journal
    let mut eng2 = Engine::load_or_genesis(dir.path()).unwrap();
    // replay a duplicate withdraw at h=310 — must be rejected
    let dup = withdraw_at_height(&sk(1), 100, 7, 310);
    let res = eng2.ingest(dup);
    assert!(matches!(res, Ok(events) if events.iter().any(|e| matches!(e,
        ExecEvent::Rejected{ reason: RejectReason::DuplicateNonce, .. }))));
}

#[test]
fn gov_nonce_watermark_survives_restart() {
    let dir = tempfile::tempdir().unwrap();
    let mut eng = Engine::new();
    eng.state.height = 50;
    eng.ingest(gov_withdraw(&sk(1), 100, 5)).unwrap();
    eng.journal.flush().unwrap();
    // crash + reload
    let eng2 = Engine::load_or_genesis(dir.path()).unwrap();
    assert_eq!(eng2.state.seen_gov_nonces[&acct_of(&sk(1))], 5);
    // lower nonce must still be rejected
    let res = eng2.clone().ingest(gov_withdraw(&sk(1), 50, 4));
    assert!(is_rejected_duplicate(res));
    // higher nonce must succeed
    let res = eng2.clone().ingest(gov_withdraw(&sk(1), 50, 6));
    assert!(is_applied(res));
}

#[test]
fn aa_unit_reused_after_300h_still_rejected_after_restart() {
    // same structure but for deposits: aa_unit [42;32] at h=20, reuse at h=320
}

#[test]
fn prune_still_bounds_memory() {
    // fill withdrawals to WITHDRAWALS_CAP, advance 2048+1 heights, assert prune freed entries
    // and withdrawals.len() <= cap after prune
}
```

E2E (obyte-local): no change to `test_vault_aa.js` — add a sidechain-only harness `obyte-local/test_replay_persist.js` or Rust integration test that drives `post_batch.js` twice with the same withdraw nonce 300 heights apart and asserts the second batch's `validate_against` rejects the duplicate (or the AA's `withdraw` would bounce on `wd_` if the sidechain mistakenly included it).

Run commands:

```bash
cargo test --workspace -- replay_persist
cargo test -p operp-exec --test replay_persist -- --nocapture
# persistence feature
cargo test --workspace --features persist-rocksdb
```

---

## 4. Complexity & Risk

| Dimension | Assessment |
|-----------|------------|
| **AA op-count delta** | **0** — no AA change. `wd_`/`wp_` remain global; sidechain window is invisible to the AA. |
| **Sidechain code delta** | v1: **~100 lines** (2-line window change + ~80-line journal + ~30-line snapshot helper + tests). v1.1 with RocksDB: +~250 lines behind `persist-rocksdb` feature. All additive, no existing logic deleted except the `256` literal. |
| **State size / RAM** | Honest steady state **+~8 MB** vs today; spam worst **+~80 MB** (still < 100 MB total dedup). See 2.2. RocksDB variant offloads to disk, RAM ~0 for dedup. |
| **Throughput** | `retain` over 65k entries per batch: ~0.02 ms/batch (negligible vs ~5k ops/s engine). Journal fsync: one per `GovWithdraw` batch (rare) or one per snapshot (every 64 heights) — amortized ~0.01 ms/batch. RocksDB: ~5-10 µs per point op, no measurable TPS loss. |
| **Determinism** | Window is height-indexed, not time-indexed — deterministic across replicas regardless of wall-clock skew. Activation gate makes replay from genesis deterministic. `BTreeMap` ordering preserved in both stores. |
| **Migration** | No data migration for already-pruned entries (acceptable — forward window only). Snapshot at activation height is the migration point. Downgrade after activation re-opens DoS window but not fund safety — operator must not downgrade without resync. |
| **Backward compat** | Wire format unchanged. Old batches replay identically (legacy 256 predicate for `height < ACTIVATION`). New batches use 2048. Peers on different versions diverge only on late duplicates (257-2048) — acceptable during rolling upgrade; after activation all peers converge. |
| **Failure modes** | Snapshot write failure: node keeps in-memory state, retries next batch — no data loss (dedup still in RAM). Journal fsync failure: `gov_withdraw` returns `Risk` (or `EngineError::Journal`) and does not insert the nonce — safe to retry. RocksDB corruption: fall back to replay from last good snapshot + `temp_data` (same recovery path as today). |
| **Fund-safety argument** | Even if sidechain dedup is bypassed, `operp_vault.aa: wd_ / wp_ + leaf ownership + Merkle root check` is the **final** gate. The sidechain window only controls whether a duplicate wastes batch space and forces a challenge. This is explicitly documented and not weakened by the change. |

---

## 5. Open Questions

1. **Window size final value: 2048 or infinite for withdrawals?** `withdrawals` is capped at 65k entries — making it infinite-window (never prune) would be bounded by the cap, not by heights. That would give global withdraw dedup on the sidechain, matching the AA's global `wd_`/`wp_`. Should we set `REPLAY_WINDOW_HEIGHTS = u64::MAX` (never prune) for `withdrawals` only, and 2048 for `seen_aa_units`? Proposal: keep 2048 for both in v1 (simpler, one constant), revisit infinite withdrawals in v1.1 after measuring cap pressure.

2. **Snapshot granularity:** every 64 heights vs every batch? Every batch gives minimal replay on crash but fsyncs every 2 s. Every 64 heights gives at most 64 batches of replay (~128 s, ~32k units worst) which is trivial to replay via `validate_against`. **Proposed:** 64 for production, every batch for tests (`--fsync-every-batch`).

3. **Journal vs RocksDB WAL:** should `gov_nonces` use a standalone journal file (simple, portable) or RocksDB's own WAL (fewer files, atomic with other CFs)? **Proposed:** standalone journal file in v1 (no native dep), RocksDB WAL in v1.1 when RocksDB is enabled — journal file is then removed.

4. **Prune obligation on `validate_against` vs `from_applied`:** should a replay validator also prune, or only the batch producer? Both must prune identically to keep `Engine.log` bounded, but pruning does not affect `state_root`. **Proposed:** both prune at the same height predicate; document that pruning is not root-committed.

5. **Activation height coordination:** how is `REPLAY_WINDOW_ACTIVATION` agreed across operators without a hard fork? **Proposed:** set it to `current_tip + 1024` at deploy time, announce in `docs/PROTOCOL.md`, and have `Batch::validate_against` accept either window for a 1024-height grace period (`height < ACTIVATION` uses legacy, `>= ACTIVATION` uses new, but both are accepted during grace). After grace, legacy path can be removed.

6. **RocksDB native dependency in CI:** adding `rocksdb` increases CI build time by ~2-3 min and requires `libclang`. Should the default CI run without `persist-rocksdb` and have a separate `ci-persist` job? **Proposed:** yes — default `cargo test --workspace` stays RocksDB-free; `cargo test --features persist-rocksdb` runs in `ci-persist`.

