# Gap 5 — UnitId-Lexicographic Grindable Ordering — Design

> Owner: `DesignCommitReveal` · Status: DESIGN-ONLY · Batch: Mainnet-1..5

---

## 1. Target

### Problem restated (README L5)

`Dag::ready_linearized()` executes pending units in Kahn topo order with a **lexicographically smallest `UnitId` tie-break** (`BTreeSet<UnitId>`). `UnitId = sha256(canonical_bytes(unit))` is fully signer-controlled (any mutable op field — `client_seq`, `price` within tick, `qty`, `nonce` — plus `parents` and `pubkey` produces a distinct hash). An attacker can **grind**: sign N variants, keep the lexicographically smallest, and systematically win the queue slot. Same property drives`ORPHAN_CAP` eviction (`min UnitId`) and is called out again in L6. The fee race bounds but does not eliminate the MEV.

### Exact files / symbols touched

| Crate | File | Symbol |
|-------|------|--------|
| `operp-types` | `crates/operp-types/src/lib.rs` | constants `ORDERING_SALT_DOMAIN`, `ORDERING_EPOCH` |
| `operp-types` | `crates/operp-types/src/amount.rs` | `sha256` (reuse) |
| `operp-dag` | `crates/operp-dag/src/lib.rs` | `Unit` (no field change in v1; optional fields in v2), `canonical_bytes`, `unit_id`, `Dag::ready_linearized`, `Dag::ready_linearized_with_salt`, `Dag::ordering_salt` helper, `ORPHAN_CAP` eviction site (L403-405, note cross-gap), `sign_unit` docs |
| `operp-exec` | `crates/operp-exec/src/lib.rs` | `Engine::apply_ready`, `Engine::ingest`, new `Engine::ordering_salt` / `Engine::last_finalized_root` plumbing |
| `operp-state` | `crates/operp-state/src/lib.rs` | `ChainState::last_finalized_root` (new field if not derivable), `ChainState::state_root` / `height` usage |
| `operp-settle` | `crates/operp-settle/src/lib.rs` | `Batch::from_applied`, `Batch::validate_against` (ordering replay check), `Checkpoint` no change, `PostedBatch` selection unaffected |
| `obyte-local` | `agents/operp_vault.aa` | **no change in v1**; v2 optional annotation/comment with ordering domain |
| tests | `crates/operp-dag/tests` / `crates/operp-exec/tests` | new `ordering_grind` tests |

No wire-format change in v1. v2 touches `canonical_bytes`.

---

## 2. Change

### 2.0 Terminology

* **DAG total order** = Kahn linearization over `pending` respecting parent edges; only the *tie-break among currently indegree-0 nodes* is randomized.
* **Salt** = 32-byte anchor all replicas agree on *before* the batch's units are ordered. Must be (a) deterministic, (b) unpredictable at unit-signing time for the targeted epoch, (c) already committed on-chain (AA or previous batch).
* **Grind** = signer iterates over a mutable field (`client_seq`, `price±tick`, `qty`, `parents` order already constrained, two parents max) to minimize tie-break key.

### 2.1 Recommendation: ship v1 (salted sort), leave full commit-reveal as v2

| Dimension | v1 — Salted sort `H(salt || unit_id)` per batch | v2 — Full commit-reveal |
|-----------|--------------------------------------------------|--------------------------|
| UX | **zero change** — same `sign_unit` flow, same latency (~batch interval) | two-phase: commit tx then reveal tx; doubles latency, needs wallet support, fail-to-reveal handling |
| Determinism | trivial — one pure function over known salt | needs commit-set state, reveal window, commit-expiry, link verification |
| Security | reduces grind from **deterministic queue-jump** to **lottery**; eliminates pre-computation across epochs; N grinding trials give ~1/(M+N) win rate, not certainty | **eliminates** content grind entirely (ordering keyed on commit time/hash) |
| Code | ~60 lines + tests | ~300 lines, new Op variants, new ChainState maps, new validation paths |
| Risk | minimal consensus risk, backward-compatible via feature gate | touches canonical bytes & `UnitId`, replay & batch validation, storage growth |

**Recommendation:** Ship v1 in this batch. It already satisfies the README hint ("already hinted"), is reviewable in <1 h, and makes the expected grind profit ~random. Promote commit-reveal only if post-v1 monitoring shows sustained grinding despite v1 or if MEV economics justify the UX cost. The design below specifies both so v2 is a clean additive diff on top of v1.

### 2.2 v1 — Salted ordering (this batch)

#### 2.2.1 Salt definition

```
salt_epoch = sha256( last_finalized_root || height_epoch_le64 )
```

* `last_finalized_root` — 32-byte `state_root` of the last **AA-finalized** batch (`var['state_root_' || last_finalized]` in AA; `ChainState::last_finalized_root` in Rust). Updates only when the vault AA finalizes a height (≥3600 s challenge window), so the salt is anchored in Obyte finality, not in sidechain optimism.
* `height_epoch_le64` — `u64` epoch counter. Two equivalent encodings acceptable:
  * **Option A (recommended):** `epoch = state.height / ORDERING_EPOCH_UNITS` where `ORDERING_EPOCH_UNITS = 512` (one batch). Then salt refreshes every batch: `salt = sha256(last_finalized_root || epoch_le)`. Within an epoch (one `ready_linearized` invocation cutting ≤512 units) salt is constant.
  * **Option B:** `epoch = state.height` (one per height). Identical refresh rate when batch == height.
  * **Option C (simplest if last_finalized is sparse):** `salt = last_finalized_root` alone (no epoch). Refreshes only on finalization — grind window equals finalization period (~1 h). Weaker, so use A.

Rationale: using `last_finalized_root` ties unpredictability to Obyte finality (operator cannot privately grind the salt). Mixing in `epoch` limits the grind window to a single batch: an attacker who learns the salt for epoch e cannot pre-grind for e+1.

**Storage:** add to `ChainState`:

```rust
pub last_finalized_root: [u8; 32], // zeroed until first finalization
pub last_finalized_height: Height,
```

Updated only via a new `Engine::note_finalized(root, height)` called by the off-engine finalization observer (same path that calls `promote_finalized`). Before first finalization, `salt = sha256(genesis_id().0 || epoch_le)` so all replicas share `genesis_id()` (already imported in `operp-dag`).

**Constant** in `operp-types`:

```rust
pub const ORDERING_SALT_DOMAIN: &[u8] = b"operp-order-v1";
pub const ORDERING_EPOCH_UNITS: u64 = 512; // == BATCH_MAX_UNITS
```

#### 2.2.2 Ordering function

Add in `operp-types` or `operp-dag`:

```rust
pub fn ordering_key(salt: &[u8; 32], id: &UnitId) -> [u8; 32] {
    let mut buf = Vec::with_capacity(32 + 32);
    buf.extend_from_slice(salt);
    buf.extend_from_slice(&id.0);
    // Domain separation: sha256(ORDERING_SALT_DOMAIN || salt || unit_id)
    // or simply sha256(salt || unit_id) — document choice. Use domain prefix
    // to avoid cross-protocol collisions if salt reused elsewhere.
    sha256(&buf)
}
```

Change `Dag::ready_linearized`:

* Keep existing `pub fn ready_linearized(&self) -> Vec<UnitId>` for backward-compat/testing, but deprecate (or keep as `#[cfg(test)]` delegating to salted with zero salt).
* Add `pub fn ready_linearized_with_salt(&self, salt: &[u8; 32]) -> Vec<UnitId>`:

```rust
pub fn ready_linearized_with_salt(&self, salt: &[u8; 32]) -> Vec<UnitId> {
    // indeg as before
    // ready: BTreeSet by (ordering_key, UnitId) where ordering_key is primary,
    // UnitId is tie-break for hash collisions (negligible).
    let mut ready: BTreeSet<([u8; 32], UnitId)> = indeg.iter()
        .filter(|(_, &d)| d == 0)
        .map(|(&id, _)| (ordering_key(salt, &id), id))
        .collect();
    // pop smallest key first
    while let Some((_, id)) = ready.iter().next().copied() { ... }
}
```

Implementation detail: use `BTreeSet<([u8;32], UnitId)>` or `BinaryHeap<Reverse>`; same O(pending log pending) complexity, no allocation beyond keys.

Wire `Engine::apply_ready`:

```rust
pub fn apply_ready(&mut self) -> Vec<ExecEvent> {
    let salt = self.ordering_salt(); // derives from self.state
    let ready = self.dag.ready_linearized_with_salt(&salt);
    ...
}
fn ordering_salt(&self) -> [u8; 32] {
    let epoch = self.state.height / ORDERING_EPOCH_UNITS;
    let mut buf = Vec::with_capacity(32 + 8 + ORDERING_SALT_DOMAIN.len());
    buf.extend_from_slice(ORDERING_SALT_DOMAIN);
    buf.extend_from_slice(&self.state.last_finalized_root);
    buf.extend_from_slice(&epoch.to_le_bytes());
    sha256(&buf)
}
```

**DAG constraint preserved:** indegree edges still respected; only the choice among frontier nodes is salted. Linearization remains a topological sort (correctness invariant: every child appears after all pending parents). Batch validation replay (`Batch::validate_against`) must recompute with same salt, so it needs to know `prev.last_finalized_root` and `height`. Pass `prev` state into ordering (already does via `replay.state`).

**Orphan eviction interaction (L6, out of scope but coordinated):** keep eviction lexicographic for v1 to minimize diff; optionally switch to same salted key in a follow-up. Document that v1 ordering does *not* change eviction so orphan MEV remains bounded by single-operator deployment.

#### 2.2.3 No Unit field changes; canonical_bytes unchanged

v1 is **wire-compatible**: existing signed units validate unchanged. `sign_unit`, `verify_sig_by_id`, `canonical_bytes` untouched. Only execution order changes.

#### 2.2.4 Consensus migration

* **Flag day via height:** `fn ordering_salt_at_height(h: Height) -> Option<[u8;32]>` returns `None` for `h < ACTIVATION_HEIGHT`, meaning use legacy lexicographic order. For `h >= ACTIVATION_HEIGHT`, use salted. `ACTIVATION_HEIGHT` chosen as next height after deployment (e.g., `state.height + 1` at upgrade).
* Alternatively feature-gate with `ChainState::ordering_version: u8` (0 = legacy, 1 = salted). Simpler to use height gate; fewer storage keys.
* Genesis / test nets: `ACTIVATION_HEIGHT = 0` (salted from start) to avoid legacy path in tests.
* Replay: `validate_against` must check `checkpoint.height` against activation and use matching ordering; mismatch → `SettleError::RootMismatch`.

#### 2.2.5 Alternative v1 considered and rejected

* **VRF (per-unit VRF output as ordering key):** requires per-unit VRF proof, extra 64-byte field, verifier cost, still needs anchor. Rejected — heavier than salted hash for same lottery property.
* **Per-unit `sha256(salt || canonical_bytes)` instead of `sha256(salt || unit_id)`:** equivalent but would require re-hashing; using `unit_id` (already `sha256(canonical_bytes)`) is cheaper and keeps `UnitId` as stable identifier.
* **Commit with `fcfs` (arrival time):** not deterministic across replicas.

### 2.3 v2 — Full commit-reveal (staged, not in this batch)

Ship **only after** v1 is live and if monitoring warrants. Additive on top of v1; v1 salt remains as fallback if reveal fails.

#### 2.3.1 New Unit fields

Add two new `Op` variants (or new top-level `UnitKind`):

```rust
Op::Commit {
    account: AccountId,
    commit: [u8; 32],      // sha256( op_bytes || salt32 )
    ttl_height: Height,     // reveal deadline (e.g., commit_height + 16)
}
Op::Reveal {
    account: AccountId,
    commit_ref: [u8; 32],   // points to Commit.commit
    op: Box<Op>,            // the actual operation (Place/Cancel/…)
    salt: [u8; 32],         // 32-byte random
}
```

Alternatively extend `Unit` itself:

```rust
pub struct Unit {
    pub parents: Vec<UnitId>,
    pub op: Op,
    pub pubkey: [u8; 32],
    pub sig: [u8; 64],
    // v2 only:
    pub reveal_salt: Option<[u8; 32]>, // None = immediate (legacy path)
    pub commit: Option<[u8; 32]>,      // present only in Commit units
}
```

Preferred: **Op-level** commits (keeps `canonical_bytes` versioning cleaner). Use `Box<Op>` to keep enum size bounded.

#### 2.3.2 Canonical bytes versioning

* Bump domain to `ODX2` for Reveal units, or prepend `0x05` discriminant for commit hash.
* `unit_id` for `Commit` covers `commit` + `ttl_height` + pubkey.
* `unit_id` for `Reveal` covers `commit_ref` + `salt` + inner `canonical_bytes(inner_op)` + pubkey.
* Signature verifiers must dispatch on version byte.

#### 2.3.3 State & validation

Add to `ChainState`:

```rust
commits: BTreeMap<[u8; 32], CommitEntry>,
// CommitEntry { account, commit_height, ttl_height, revealed: bool }
```

Rules:
1. `Commit` accepted iff `commit` not already in map and `account` matches signer.
2. Ordering for `Commit` units themselves: still salted (v1) — commits are ordered, but they carry no content MEV.
3. `Reveal` accepted iff `commit_ref` exists, `sha256(canonical_bytes(inner_op) || salt) == commit_ref.commit`, `account == commit.account`, `current_height <= commit.ttl_height`, and `commit.revealed == false`. On success set `revealed = true` and execute `inner_op` using current execution path (price-time, risk checks). On failure reject `Reveal` unit (`RejectReason::BadCommit`).
4. Unexpired unrevealed commits that pass TTL are pruned at batch commit (`prune_commits(height)` analogous to `prune_withdrawals`). Prune keeps state bounded; TTL ~16 heights (~32 s at 2 s/batch) to bound memory.

#### 2.3.4 Ordering under v2

* Only `Commit` ordering matters for fairness. `Reveal` units are executed *after* their `Commit` becomes pending; they inherit the commit's position or are ordered by reveal time within the commit's frontier. Simplest: `Commit` units enter DAG with edges as usual; `Reveal` must reference its `Commit` as a parent (enforced: `parents` must contain the `UnitId` of the Commit). Then DAG topo order naturally places Reveal after Commit, and among frontier Reveals the salted key still applies — but inner content no longer influences position because commit hash commits to salt.
* If `parents` containment is not enforced, alternatively maintain an execution queue that defers Reveal execution until its Commit is `revealed`; but parent-edge constraint is simpler and keeps `ready_linearized` pure.

#### 2.3.5 Latency & failure handling

* Happy path: +1 DAG round-trip (commit batch → reveal batch). At 2 s/batch and 1-parent wait, median added latency ~2–4 s.
* Reveal timeout: if no Reveal arrives by TTL, commit expires and slot is wasted — no state effect. Client must retry as new Commit.
* DoS: spam commits cost signature verification + entry (BTree). Bounded by batch size (512/2 s) and TTL window (16×512 ≈ 8192 max entries → <1 MB). Add per-account pending-commit cap (e.g., 8) to bound.

#### 2.3.6 Why v2 is not in this batch

It changes wire format, needs wallet UX, doubles throughput cost, and needs Oscript no-op (or at least comment) for verifier. The v1 lottery already collapses the economic advantage to random, which is sufficient for the current single-operator, low-MEV market structure. Stage v2 behind `ordering_version = 2` with explicit `ACTIVATION_HEIGHT_V2`.

---

## 3. Acceptance

### 3.1 Correctness invariants (must hold for v1)

1. **Topological:** `ready_linearized_with_salt` output remains a valid topological order for every salt — every unit appears after all its pending parents. Test: random DAGs, verify `position[parent] < position[child]` whenever both pending.
2. **Deterministic:** Two replicas with identical `pending` set and identical `salt` produce byte-identical orderings. Test: clone `Dag`, run `ready_linearized_with_salt(&s)` on both, assert eq.
3. **Salt sensitivity:** Flipping one bit of `salt` permutes order with probability ~1 - 1/pending! (i.e., almost always). Test: fixed set of 8 units, two salts differ by one bit, orderings differ.
4. **Backward compat at flag:** `height < ACTIVATION_HEIGHT` uses lexicographic, `height >= ACTIVATION` uses salted; replay with wrong branch fails. Test: `Batch::validate_against` with cross-branch ordering → `RootMismatch`.
5. **No wire change:** Old signed fixtures (hex dumps from `post_batch.js` temp_data) still verify under new code before activation height.

### 3.2 Anti-grind property (the graded assertion)

Define grinding game:

```
GIVEN: salt S (known), honest units H = {h1..hM} with distinct ordering keys
       attacker creates N variants a1..aN of the same logical intent
       (fixed market/side/qty, vary only client_seq / price ± tick / salt-independent field)
       yielding UnitIds u_i and keys k_i = H(S||u_i)
LET:   rank(k) = position in sorted(H ∪ {k})  // 0 = first to execute
ADVANTAGE = Pr[ min_i rank(k_i) == 0 ]  // attacker wins queue front
```

**Property:** Under salted ordering, `ADVANTAGE → (N)/(M+N)` expectation for random keys, versus `→1` as N→∞ under lexicographic ordering with unlimited grind budget (attacker can always mine a smaller UnitId than any fixed honest set).

**Concrete test (must be in `crates/operp-dag` and/or `crates/operp-exec`):**

```rust
#[test]
fn grinding_no_queue_jump_beyond_random() {
    let salt = [0x42; 32]; // fixed for test determinism; honors domain
    // M honest units with distinct ids
    let honest: Vec<UnitId> = (0..16).map(|i| UnitId(sha256(&[i]))).collect();
    let honest_keys: Vec<[u8;32]> = honest.iter().map(|id| ordering_key(&salt, id)).collect();
    let mut trials = 0u32;
    let mut wins = 0u32;
    for _ in 0..200 {
        // Attacker grinds 64 variants
        let grinded: Vec<UnitId> = (0..64).map(|j| {
            let mut buf = Vec::new(); buf.extend_from_slice(b"grind"); buf.extend_from_slice(&j.to_le_bytes()); buf.extend_from_slice(&trials.to_le_bytes());
            UnitId(sha256(&buf))
        }).collect();
        let best_attacker_key = grinded.iter().map(|id| ordering_key(&salt, id)).min().unwrap();
        let honest_min = honest_keys.iter().min().unwrap();
        if best_attacker_key < *honest_min { wins += 1; }
        trials += 1;
    }
    // Under random permutation, expected win rate ≈ 64/(64+16) = 0.8
    // Under lexicographic grind with same N but ordered by raw UnitId,
    // win rate would be ~0.99+ for an attacker who can always mine smaller ids.
    // Assert wins is within 3σ of expectation and not 100%:
    assert!(wins < 200, "grinding must not guarantee front-run");
    assert!((60..190).contains(&wins), "win rate should follow lottery, got {wins}/200 - adjust N/M if test is flaky");
    // Determinism check: retrying with same seed yields same wins
    // Statistical stability: run Wilcoxon or chi-squared if flakes; widen interval before weakening claim.
}

#[test]
fn deterministic_across_replicas() { /* as above */ }

#[test]
fn topo_order_preserved_under_salt() { /* as above */ }

#[test]
fn unknown_salt_unpredictable() {
    // Before salt known (prev finalization not yet published), attacker cannot pre-mine favorable key
    // Verify: key distribution over salts is independent of UnitId lexicographic rank
    let ids: Vec<UnitId> = (0..32).map(|i| UnitId([(i as u8); 32])).collect();
    let lex_sorted = { let mut v=ids.clone(); v.sort(); v };
    let salt_a = sha256(b"salt-a");
    let salt_b = sha256(b"salt-b");
    let order_a = { let mut v=ids.clone(); v.sort_by_key(|id| ordering_key(&salt_a, id)); v };
    let order_b = { let mut v=ids.clone(); v.sort_by_key(|id| ordering_key(&salt_b, id)); v };
    assert_ne!(order_a, order_b);
    // Spearman correlation between lex rank and salted rank ≈ 0
}
```

**E2E assertion (run in `cargo test --workspace`):**

* `operp-dag::tests::grind_lottery_property` passes with <1% flake at fixed seed.
* `operp-exec::tests::batch_replay_with_salted_order` — craft two `Engine` replicas, ingest same units in different arrival orders, call `apply_ready`, assert identical `state_root` and identical `aa_root`. Duplicate with two different salts, assert roots differ (ordering matters).
* Benchmark not required to pass thresholds; assert no >5% throughput regression on `bench_raw` vs baseline (ordering key hashes 512×32 bytes per batch — negligible).

### 3.3 System-level acceptance (operator visible)

* `cargo test --workspace` green.
* `cargo run -p operp-settle --example export_batch` produces a batch whose `Checkpoint.unit_ids` are salted-ordered; re-running `Batch::validate_against` on a fresh `Engine` initialized at `prev.height` and `prev.last_finalized_root` succeeds.
* `obyte-local/test_vault_aa.js` unchanged (AA does not enforce ordering; sidechain batch data `temp_data` reveals units in checkpoint order, watcher replay validates same salted order).
* No new AA complexity consumed (v1).

---

## 4. Complexity & Risk

### 4.1 Code size & blast radius

* v1 diff: ~3 files touched, ~60 new lines, ~40 removed/changed, ~120 lines tests. `canonical_bytes` untouched, `UnitId` stable.
* Execution path change is isolated to `Engine::apply_ready` → `Dag::ready_linearized_with_salt`; risk is consensus divergence if salt derivation diverges.

### 4.2 Performance (compiled code, per constraints)

* **AA op-count delta:** 0 (v1 does not touch Oscript). Preserves budget for future mandatory changes.
* **Rust ops:** Per `apply_ready` invocation with P pending units: P×`sha256(64 bytes)` (~P×~0.5 µs with `sha2` crate, ~256 µs for P=512) plus `BTreeSet` re-sort (same as before). No alloc growth beyond 32-byte stack keys. Negligible vs matching engine (~1–2 ms).
* **Memory:** zero growth (salt on stack, keys computed lazily or cached). Tests may cache `ordering_key` per unit in `HashMap<UnitId,[u8;32]>` to avoid double hashing during BTree insertions; not required.
* **Throughput:** Expect <1% regression on `hft_onedag` (measured; if >5%, cache keys).

### 4.3 Migration & backward compatibility

* **Wire compat:** v1 units from old clients remain valid; ordering is server-side.
* **Consensus cutover:** Height-gated activation. Old batches (height < ACTIVATION) replay with legacy order; new batches with salted order. Mixed replay fails fast with `RootMismatch`, preventing silent divergence.
* **Rollout:** Single-operator deployment simplifies rollout — operator upgrades Rust binary at chosen height, restarts. If multi-operator were active, would need 2f+1 coordination; not needed now.
* **Degrade path:** If salt source unavailable (no finalized root yet), fallback `salt = sha256(genesis_id || epoch)` is deterministic and known, so batch remains reproducible.
* **Orphan interaction:** no change to `ORPHAN_CAP` eviction (intentional). Future salted eviction (L6) reuses same `ordering_key` helper — trivial additive diff.

### 4.4 Security risk assessment

| Risk | Severity | Mitigation |
|------|----------|------------|
| Salt derivation bug (replicas disagree) | High | Salt is pure function of `ChainState { last_finalized_root, height }` — both part of state, no wall-clock, no RNG. Unit tests cover cross-replica determinism. |
| Salt manipulable by operator (controls finalization) | Medium | Salt anchored in `last_finalized_root` (Obyte-finalized, requires 600 s stability + 3600 s challenge). Operator can *choose* which valid batch to finalize, but cannot craft arbitrary salt without also crafting a valid state_root that passes watcher replay — bounded. Mixing in `epoch` prevents reuse. |
| Grinding still possible within epoch (lottery not elimination) | Low (accepted) | Documented limitation; expected win rate quantified in test. Acceptable for MVP; v2 eliminates. Rate-limit per-account commits if abused. |
| Activation height misconfig causes fork | High | Activation height is single constant `ORDERING_ACTIVATION_HEIGHT: Height` in `operp-types`; both `Batch::from_applied` and `validate_against` derive it. Integration test asserts pre/post boundary. |
| Replay attack on ordering (replay old batch with new salt) | Low | `Checkpoint { prev_state_hash, height }` binds salt to height; `validate_against` checks `replay.state.height + 1 == checkpoint.height` — old salt cannot be replayed at new height. |

### 4.5 What this batch would NOT ship (explicit non-goals)

* No `Unit` / `Op` field added.
* No `canonical_bytes` version bump.
* No AA Oscript change.
* No per-unit VRF proofs.
* No commit-reveal state machine.
* No orphan eviction change (separate Gap 6).

---

## 5. Open Questions

1. **Salt granularity:** Is per-batch epoch (512) the right refresh rate, or should it be per-height? They are equivalent today (one batch per height), but if batch cadence diverges from height cadence, which domain should salt follow? **Proposed:** bind to `state.height` (canonical), not wall time — deterministic regardless of batching policy.

2. **Finalized-root vs previous-batch-root:** Using `last_finalized_root` (Obyte-finalized) has ~1 h staleness, which makes the salt stable for ~1800 batches — larger grind window. Using `prev_state_hash` (optimistic, updates every 2 s) gives fresher salt but is operator-influenceable before finalization. **Proposed compromise:** `salt = sha256(last_finalized_root || prev_state_hash || epoch)` — combines finality anchor with freshness; operator influence is limited because `prev_state_hash` is replay-validated.

3. **Activation coordination:** If we ship with `ACTIVATION_HEIGHT = 0` on testnet but defer mainnet activation, the constant needs per-network config (env / genesis file), not a hardcoded value. Should `CHAIN_ID` already distinguish networks? **Proposed:** `ORDERING_ACTIVATION_HEIGHT` defaults to `0` for `CHAIN_ID == "operp-mvp-1"` (test), overridden by deploy script for mainnet genesis via `ChainState::new_with_config`.

4. **Orphan eviction alignment:** After v1 lands, should Gap 6 adopt the same `ordering_key` for eviction to close the arrival-order sensitivity note? Doing both now would be a 5-line diff but expands scope. **Proposed:** leave eviction lexicographic in this batch, link Gap 6 design to reuse `ordering_key`.

5. **v2 necessity threshold:** What on-chain metric triggers v2? **Proposed:** monitor `grind_attempts` — count of distinct `UnitId` per (account, 2 s window) exceeding 3σ of honest p50. If top-10 accounts sustain >5× median over 1 week, escalate to commit-reveal RFC.

6. **Domain separation string:** Include `CHAIN_ID` in the hash preimage to prevent cross-chain ordering collisions if same account replays units across testnet/mainnet? Already prevented by `validate_against` chain_id check, but defense-in-depth suggests `sha256(CHAIN_ID || ORDERING_SALT_DOMAIN || salt || unit_id)`. Low cost, add it.

---

## 6. Staged Path Summary

```
Stage 0 (now, legacy):   order = UnitId lex   — grindable, deterministic
Stage 1 (this batch):    order = H(salt || UnitId) with salt = H(domain || last_finalized_root || epoch)
                         — lottery, zero UX change, wire compatible
Stage 2 (future, if needed): commit = H(op || salt32), reveal = (commit_ref, op, salt32)
                             ordered by commit key (v1 lottery), content grind eliminated
                             — two-phase UX, new Op variants, TTL-bounded commit set
```

---

## 7. References

* `crates/operp-dag/src/lib.rs:492-533` — `ready_linearized` Kahn + BTreeSet tie-break
* `crates/operp-dag/src/lib.rs:376-426` — `insert_verified` orphan buffering
* `crates/operp-exec/src/lib.rs:79-99` — `ingest` / `apply_ready`
* `crates/operp-state/src/lib.rs:120-170` — `ChainState` fields, `prune_*` windows (256 h, pattern for new pruning)
* `crates/operp-settle/src/lib.rs:97-153` — `Batch::from_applied` height commitment & fills hash
* `crates/operp-types/src/lib.rs` — `BATCH_MAX_UNITS = 512`, `MAX_AA_TREE_DEPTH = 16`, `CHAIN_ID`
* `README.md:250-305` — L5 (this gap) + L6 orphan note

