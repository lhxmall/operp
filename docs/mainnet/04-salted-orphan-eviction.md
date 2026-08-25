# Gap 6 — Salted Orphan Eviction (DESIGN-ONLY)

> Status: **design v1** · no code edits · read authoritative files only.
> Authoritative basis: `README.md` L6, `crates/operp-dag/src/lib.rs` (Dag::insert_verified, waiting index, ORPHAN_CAP=4096), `crates/operp-state/src/lib.rs` (ChainState, merkle_root, state_root, aa_root), `crates/operp-exec/src/lib.rs` (Engine), `crates/operp-types/src/amount.rs` (sha256), `obyte-local/agents/operp_vault.aa` (last_finalized).

## 1. Target

| Crate / file | Symbol / line | Role in this gap |
|---|---|---|
| `operp-types` | `crates/operp-types/src/amount.rs:22` `sha256` | Reuse existing hash primitive; no new dep |
| `operp-types` | `crates/operp-types/src/ids.rs:13` `UnitId([u8;32])` | Eviction key input |
| `operp-dag` | `crates/operp-dag/src/lib.rs:323-336` `Dag { pending_orphans, waiting }` | Only mutating crate |
| `operp-dag` | `...:339` `ORPHAN_CAP: usize = 4096` | Unchanged constant |
| `operp-dag` | `...:375` `Dag::insert_verified` L402-417 eviction block | **Replace** `min()` with salted argmin |
| `operp-dag` | `...:340-432` `Dag::known`, `pending_orphans`, `waiting` | Keep intact; eviction cleans waiting still |
| `operp-dag` | `...:119` `genesis_id()` | Fallback salt pre-finalization |
| `operp-state` | `crates/operp-state/src/lib.rs:18-69` `ChainState { height, last_unit, seq }` | Add field `last_finalized_root: [u8;32]` (+ height) as salt source |
| `operp-state` | `...:401` `ChainState::state_root()` | Canonical root used for `last_finalized_root` |
| `operp-exec` | `crates/operp-exec/src/lib.rs:18-24` `Engine { dag, state, log }` | Wiring: `Engine::note_finalized` updates Dag salt |
| `operp-exec` | `...:111-127` `Engine::promote_finalized` | Sister call-site; same observer invokes `note_finalized` |
| `operp-settle` | `crates/operp-settle/src/lib.rs:97-153` `Batch::from_applied`, `Checkpoint` | Finalization observer provides `(root, height)` to Engine |
| `obyte-local` | `agents/operp_vault.aa:266` `var['last_finalized']` | Ground-truth off-engine signal; no AA change |
| tests | `crates/operp-dag/src/lib.rs:536-706` existing `orphan_*` tests | Extend, not replace |

Non-goals: no AA Oscript edit, no wire-format change, no `ORPHAN_CAP` tuning, no validation logic change.

---

## 2. Change

### 2.1 Problem restated

Current `Dag::insert_verified` at capacity (`>=4096`) evicts `argmin UnitId` lexicographically:

```rust
if let Some(k) = self.pending_orphans.keys().copied().min() { … }
```

This is deterministic **per buffer state** but arrival-order sensitive across replicas: which 4096 units fill the buffer depends on gossip order. An attacker with open gossip can grind `UnitId = sha256(canonical_bytes(unit))` by varying any mutable field (`client_seq`, `price` within tick, `qty` within risk, `parents` ordering is fixed, `sig` needs re-sign) and keep the lexicographically smallest id to bias queuing / eviction toward victim removal or attacker survival. Cost is one ed25519 sign per grind attempt; lexicographic min is publicly grindable offline.

Fix: make eviction victim a **salted pseudorandom function** of the buffered set + a finalized, unpredictable salt, so attacker cannot know victim without knowing salt and cannot control salt without controlling Obyte finality.

### 2.2 Salt definition

```
salted_key(unit_id) = sha256( eviction_salt || unit_id.0 )
victim              = argmin_{id in pending_orphans} salted_key(id)
```

* `eviction_salt: [u8;32]` — 32-byte value stored in `Dag`.
* Source of truth: `ChainState::last_finalized_root` — the `state_root()` of the last **AA-finalized** batch height (same height tracked by `var['last_finalized']` in the vault AA). Anchored in Obyte finality (600 s stability + 3600 s challenge ⇒ ~4200 s unforgeable), not sidechain optimism.
* Update path: off-engine finalization observer (the same process that calls `Engine::promote_finalized`) calls new `Engine::note_finalized(root, height)` which forwards to `Dag::set_eviction_salt(root)`. Dag never reads ChainState directly — keeps dependency one-way and avoids Dag ↔ State cycle.
* Fallback (no finalized root yet): `eviction_salt = genesis_id().0` (which is `sha256(b"operp-mvp-1-genesis")`). Chosen because:
  - Already imported in `operp-dag` and shared across every replica deterministically.
  - Non-zero, collision-free, and distinct from empty-root `sha256(b"empty")` used by `merkle_root(empty)`.
  - Upgrade path: when first batch finalizes, salt atomically flips to that batch's `state_root`.
* Alternative fallback rejected: `[0u8;32]` or `sha256(b"empty")` — would be deterministic too but diverges from genesis lineage and collides with the meta-leaf empty sentinel; genesis_id is the better domain separator.
* No epoch suffix. Eviction salt stays stable for the entire finalization epoch (typically ~1800 batches per hour). This is intentional: eviction churn per insertion with per-batch epoch would make testing nondeterministic and increase hash work. Ordering (Gap 5) needs per-batch epoch; eviction does not. See §5.1 coordination note.

Grind resistance: to predict whether a crafted `UnitId` will survive eviction, attacker must compute `sha256(salt || id)`; salt is unknown until finalization and fixed thereafter. Offline grinding across salts is useless after salt rotation. Within one epoch the attacker *can* grind to minimize `salted_key` (local lottery), but cannot force a chosen victim to be evicted without also minimizing its key relative to the 4096 buffered ids — which requires beating 4096 independent hashes, not a single lexicographic comparison. Expected advantage drops from `1/k` lexicographic to `1/k` random (same nominal but non-grindable without knowing salt at craft time). The fix is not elimination (still a lottery) but grind-resistance: attacker must beat the salt, not just the byte order.

### 2.3 Data model — minimal boring diff

#### 2.3.1 `crates/operp-state/src/lib.rs`

Add to `ChainState`:

```rust
pub last_finalized_root: [u8; 32],   // [0;32] until first finalization, then state_root of finalized height
pub last_finalized_height: Height,   // 0 until first finalization
```

* Default `ChainState::new()`: both zeroed. Genesis does not count as finalized.
* New method:

```rust
impl ChainState {
    pub fn note_finalized(&mut self, root: [u8; 32], height: Height) {
        self.last_finalized_root = root;
        self.last_finalized_height = height;
    }
}
```

No other state change. `state_root()` / `aa_root()` unaffected. Serialization: if `ChainState` is ever persisted (future), these fields serialize naturally via existing derive; old snapshots with missing fields deserialize to zero → fallback path handles it.

#### 2.3.2 `crates/operp-dag/src/lib.rs`

Add to `Dag`:

```rust
pub struct Dag {
    units: HashMap<UnitId, Unit>,
    children: HashMap<UnitId, Vec<UnitId>>,
    executed: HashSet<UnitId>,
    pending: HashSet<UnitId>,
    pending_orphans: HashMap<UnitId, Unit>,
    waiting: HashMap<UnitId, Vec<UnitId>>,
    /// Salted eviction anchor. Defaults to genesis_id().0 until first finalization.
    eviction_salt: [u8; 32],
}
```

* `Dag::new()` — initialize `eviction_salt = genesis_id().0`.
* New public API:

```rust
impl Dag {
    /// Update eviction salt from the finalized state root. Called only by Engine.
    pub fn set_eviction_salt(&mut self, salt: [u8; 32]) {
        self.eviction_salt = salt;
    }
    pub fn eviction_salt(&self) -> [u8; 32] { self.eviction_salt }

    /// Pure function — testable without mutating Dag.
    /// Victim key for `id` under current salt.
    pub fn eviction_key(&self, id: UnitId) -> [u8; 32] {
        let mut buf = [0u8; 64];
        buf[..32].copy_from_slice(&self.eviction_salt);
        buf[32..].copy_from_slice(&id.0);
        sha256(&buf)
    }
    // Optional free function for callers without a Dag instance:
    // pub fn eviction_key_with(salt: [u8;32], id: UnitId) -> [u8;32]
}
```

#### 2.3.3 Replace eviction site in `Dag::insert_verified`

Current (L402-417):

```rust
if self.pending_orphans.len() >= ORPHAN_CAP {
    if let Some(k) = self.pending_orphans.keys().copied().min() {
        if let Some(evicted) = self.pending_orphans.remove(&k) {
            for p in &evicted.parents { /* waiting cleanup */ }
        }
    }
}
```

Proposed:

```rust
if self.pending_orphans.len() >= ORPHAN_CAP {
    // Salted, deterministic, grind-resistant eviction.
    // argmin sha256(salt || unit_id)
    if let Some(k) = self.pending_orphans.keys().copied()
        .min_by_key(|id| self.eviction_key(*id))
    {
        if let Some(evicted) = self.pending_orphans.remove(&k) {
            for p in &evicted.parents {
                if let Some(v) = self.waiting.get_mut(p) {
                    v.retain(|c| *c != k);
                    if v.is_empty() { self.waiting.remove(p); }
                }
            }
        }
    }
}
```

*Waiting index intact*: the `waiting` cleanup loop is unchanged. No new allocation pattern; `retain` + `remove` preserves the "no leak" invariant asserted by `orphan_reverse_index_links_multi_and_chained` test. Complexity per eviction: one `sha256(64 bytes)` per buffered entry to find min → `O(CAP)` = 4096 hashes, only when at capacity and a new orphan arrives (rare path). No per-insert overhead otherwise.

*Hash choice*: reuse `operp_types::sha256` (sha2 crate) — same as `unit_id` derivation, no new crypto primitive. Concatenation is `salt || id.0` (64 bytes), no length prefix needed because both inputs are fixed 32 bytes. Domain separator unnecessary; if reviewers insist, prefix `b"evict"` before salt — but bare `salt||id` is already collision domain-separated from `canonical_bytes` (variable length) and `aa_parent` (hex strings).

#### 2.3.4 `crates/operp-exec/src/lib.rs`

Add to `Engine`:

```rust
impl Engine {
    /// Notify the DAG that height `h` with state_root `root` was finalized
    /// on the vault AA. Call after `promote_finalized` by the off-engine
    /// observer that watches AA `last_finalized` transitions.
    pub fn note_finalized(&mut self, root: [u8; 32], height: Height) {
        self.state.note_finalized(root, height);
        self.dag.set_eviction_salt(root);
    }
    // Optional getter for tests / diagnostics
    pub fn eviction_salt(&self) -> [u8; 32] { self.dag.eviction_salt() }
}
```

Construction: `Engine::new()` sets `eviction_salt = genesis_id().0` via `Dag::new()`; if `ChainState` is later hydrated from a finalized snapshot, caller must call `note_finalized` to sync.

Call-site wiring (off-engine, e.g. `operp-settle` watcher or `post_batch.js` successor):

```rust
// After observing AA finalize height h with root/h pair from `var['root_'||h]` / `var['aa_root_'||h]`:
engine.note_finalized(checkpoint.state_root, checkpoint.height);
engine.promote_finalized(&checkpoint.unit_ids); // existing
```

Ordering matters little (both idempotent), but document as `note_finalized` first so logs reflect new salt before promotion.

#### 2.3.5 No changes to

* `ORPHAN_CAP` value (remains 4096).
* `waiting: HashMap<UnitId, Vec<UnitId>>` schema.
* `canonical_bytes`, `unit_id`, `verify_sig_by_id`, `link`, `mark_executed`, `ready_linearized`.
* `operp_types` constants, `operp-settle` Checkpoint, vault AA Oscript.

### 2.4 Cross-node orphan sync sketch (gossip missing parents on demand)

The README limits L6 to salted eviction **or** cross-node sync; the single-operator deployment has no orphan-storm surface, so sync is a sketch for the future permissionless P2P layer. Design keeps waiting index intact and adds minimal protocol:

#### 2.4.1 Message types (new, not yet implemented)

All messages use existing `canonical_bytes` wire format for units; no new serialization beyond a small envelope. Assume a libp2p/gossip `Topic = "operp/units/v1"` + `Topic = "operp/want/v1"`.

```rust
// Gossip (existing): Unit broadcast
// struct GossipUnit { unit: Unit }  // already sent on insert, verified via verify_sig_by_id

// New (on-demand):
struct WantUnits { missing: Vec<UnitId> }  // request, bounded: len <= 2 * ORPHAN_CAP? but cap at 64 for DoS
struct HaveUnits { units: Vec<Unit> }      // response, bounded similarly
```

#### 2.4.2 Initiation — who sends WantUnits

* In `Engine::ingest` / `Dag::insert_verified`, when `Err(MissingParent)` occurs, the ingest path knows `missing: Vec<UnitId>` (already computed at L391-396). The P2P layer (outside `operp-dag`) observes this error and enqueues `WantUnits { missing }` to a random subset of peers (e.g. 3 peers, fanout 3). Debounce: per-`UnitId` want is rate-limited to once per 500 ms per peer to avoid amplification.
* Alternative: centralize in `Engine` helper `missing_parents(id) -> Vec<UnitId>` that reads `Dag::pending_orphans` + `waiting` — but computing `missing` at ingest time is cheaper and already done.

#### 2.4.3 Response — how peers serve

* On receiving `WantUnits`, peer looks up each `UnitId` in `self.dag.get(id)` (known units) **and** `self.dag.pending_orphans.get(id)` (buffered orphans it hasn't executed yet). If found, include its `Unit` encoding in `HaveUnits`. Rate-limit responses: max 64 units per request, max 1 response per peer per 100 ms, drop oversize requests.
* Received `HaveUnits` units are fed through normal `Engine::ingest` path (signature verified, `insert_verified` again). If they unblock orphans, `mark_executed` fixpoint chains automatically — no special case.

#### 2.4.4 Reconciliation (optional, not v1)

* Periodic (every 30 s) anti-entropy: exchange `pending_orphans` digest — `sha256(sorted(pending_orphans.keys()))` — with peers. If digests differ, exchange `WantUnits` for the difference. This bounds divergence from eviction disagreement during salt rotation (see §4.2).
* DoS guard: orphans whose parents remain unknown after 256 heights (matching `seen_aa_units` prune window) are aged out by the same salted eviction; no permanent leak.

#### 2.4.5 Interaction with salted eviction

* Salted eviction already makes victim deterministic given `eviction_salt`. Cross-node want ensures that even if two replicas evict different victims due to transient salt desync (see risk), the missing parent can be re-fetched on demand, so a victim's child that was orphaned elsewhere can recover once its parent arrives via gossip.
* Salted eviction + on-demand sync are complementary, not alternatives: eviction bounds memory and resists grinding; sync heals divergence. Shipping eviction first (this gap) is safe on single-operator; adding sync later requires no Dag change — only a P2P layer outside the crate.

#### 2.4.6 What this sketch does NOT do (intentionally)

* No full mem-pool sync, no DAG history download — only direct parents of live orphans.
* No new AA message, no `waiting` schema change, no persistent orphan DB — buffer stays in-memory, bounded, deterministic.

---

## 3. Acceptance

### 3.1 Observable result

* Before: inserting the 4097th orphan evicts lexicographically smallest `UnitId` regardless of finalized state; two replicas that received orphan sets in different orders but ending with identical buffer contents evict same victim (lex min), yet attacker can craft victim id by minimizing bytes offline without knowing any secret.
* After: inserting the 4097th orphan evicts `argmin sha256(eviction_salt || id)`. With same `eviction_salt` (same `last_finalized_root`), two replicas with identical final buffers evict identical victim even if arrival orders differed; with different salts they diverge predictably (documented). Attacker grinding lexicographically small ids gains no advantage without knowing salt.

### 3.2 Tests — must pass before merge

#### 3.2.1 Unit test: replica convergence after permutation (acceptance gate)

```rust
#[test]
fn salted_eviction_replicas_converge_despite_arrival_permutation() {
    let salt = [0xAB; 32]; // simulate last_finalized_root
    let ids: Vec<UnitId> = (0..5000).map(|i| { /* deterministic fake ids via sha256(i) */ }).collect();

    // Build buffer contents identically but insert in two different orders
    let (mut dag_a, mut dag_b) = (Dag::new(), Dag::new());
    dag_a.set_eviction_salt(salt);
    dag_b.set_eviction_salt(salt);

    // Helper: make orphan units with parents = [fake_missing_id] (unknown, so always buffered)
    let missing = UnitId([0xFF; 32]);

    // Order A: shuffled via seeded PRNG seed 1, Order B: seed 2
    for id in shuffled(&ids, 1).into_iter().take(4097) { /* make Unit with that id, insert */ }
    for id in shuffled(&ids, 2).into_iter().take(4097) { /* same set, different order */ }

    // After overflow, both buffers have ORPHAN_CAP entries (4096)
    assert_eq!(dag_a.orphan_count(), 4096);
    assert_eq!(dag_b.orphan_count(), 4096);

    // Victim is argmin salted key — must match across replicas
    // Compute expected victim from the 4097-set
    let expected_victim = ids.iter().copied().take(4097)
        .min_by_key(|id| sha256(&[salt, id.0].concat()))
        .unwrap();

    assert!(!dag_a.pending_orphans.contains_key(&expected_victim));
    assert!(!dag_b.pending_orphans.contains_key(&expected_victim));
    assert_eq!(dag_a.pending_orphans.keys().collect::<HashSet<_>>(),
               dag_b.pending_orphans.keys().collect::<HashSet<_>>(),
               "replicas must evict same victim given same salt");
}
```

Variants:
* Same test with `salt = genesis_id().0` (fallback) — passes before first finalization.
* Same test with `salt_a != salt_b` — asserts victims **differ** (or at least that salt changes outcome) with high probability, proving salt matters.
* Permutation of 8192 orphans (two evictions): repeated `min_by_key` still converges per step.

#### 3.2.2 Unit test: salt rotation changes victim

```rust
#[test]
fn salt_rotation_changes_victim() {
    let mut dag = Dag::new();
    let s1 = [0x11; 32];
    let s2 = [0x22; 32];
    // Fill to ORPHAN_CAP with s1
    dag.set_eviction_salt(s1);
    // ... insert 4096 orphans ...
    let victim_s1 = dag.eviction_key(some_id);
    dag.set_eviction_salt(s2);
    assert_ne!(victim_s1, dag.eviction_key(some_id));
    // Evict under s1 vs s2 yields different victim for same buffer in >99% of cases
}
```

#### 3.2.3 Unit test: waiting index no-leak after salted evict

Reuses `orphan_reverse_index_links_multi_and_chained` pattern but forces eviction: insert 4096 orphans all missing `p = [0xFF;32]`, insert one more to trigger eviction, then assert `waiting[&p].len() == ORPHAN_CAP` (evicted entry removed) and `waiting` never contains evicted id.

#### 3.2.4 Integration / E2E (no network)

In `crates/operp-exec/tests` (or new `tests/salted_evict.rs`):

```rust
#[test]
fn engine_note_finalized_updates_dag_salt() {
    let mut eng = Engine::new();
    assert_eq!(eng.eviction_salt(), genesis_id().0);
    let root = [0x99; 32];
    eng.note_finalized(root, 1);
    assert_eq!(eng.eviction_salt(), root);
    assert_eq!(eng.state.last_finalized_root, root);
}

#[test]
fn two_engines_same_finalized_root_evict_same() {
    let root = [0x42; 32];
    let mut e1 = Engine::new(); e1.note_finalized(root, 1);
    let mut e2 = Engine::new(); e2.note_finalized(root, 1);
    // feed both engines same orphan set in different orders (via Engine::ingest handling MissingParent path)
    // assert orphan sets equal after overflow
}
```

#### 3.2.5 Existing tests must remain green

* `two_children_sorted_by_unit_id` — unaffected (pending, not orphan eviction).
* `missing_parent_rejected` — still `MissingParent` for first sight.
* `out_of_order_ingest_recovered` — still links after parent arrives (waiting index unchanged).
* `orphan_reverse_index_links_multi_and_chained` — still passes.
* `cargo test --workspace` — all green.

#### 3.2.6 AA / settle no-reg change

* `cd obyte-local && node test_vault_aa.js` — unchanged (AA never sees orphans).
* `cargo run -p operp-settle --example export_batch` — unchanged.
* `Batch::validate_against` — unchanged (eviction is local mempool policy, not consensus).

### 3.3 Manual E2E sketch (post-implementation)

1. Start two sidechain replica processes with same genesis, finalize height 1 via vault AA, call `note_finalized` on both with same root.
2. Flood both with 5000 orphans (all missing same parent `P`) in different shuffled orders over local gossip.
3. Query `pending_orphans` sizes and key sets via debug RPC — must be identical 4096 sets.
4. Publish parent `P`; both replicas auto-link same 4096 orphans via `mark_executed` fixpoint — no divergence.

---

## 4. Complexity & Risk

### 4.1 Runtime overhead

* **Per-eviction only** (when `len >= 4096` and a new orphan arrives): `O(CAP)` hashes, each `sha256(64 bytes)` ≈ 0.5 µs → 4096 * 0.5 µs ≈ 2 ms worst-case per overflow insertion. At orphan-storm rate (1k orphans/s), ~2 ms every event — acceptable; never on the hot apply path. No overhead when buffer not full. Micro-optimize by caching keys if needed (not v1 — boring).
* **Memory**: +32 bytes per `Dag` (negligible). No new heap allocation per eviction beyond iterator.
* **AA complexity**: zero — no Oscript change, no new `var` keys, no `messages` cases. Complexity budget (effectively exhausted per README L9) untouched.
* **Compiled code size**: one new `sha256` call-site; monomorphization unchanged.

### 4.2 Migration & backward compatibility

* **State**: `ChainState::last_finalized_root/height` are new fields; old serialized snapshots missing them deserialize to zero → fallback to genesis salt. First `note_finalized` after upgrade heals. No migration script needed. If `ChainState` is never persisted (current: in-memory Engine), no migration at all.
* **Wire**: no `Unit` field change, no `canonical_bytes` change, so old clients keep signing identically.
* **Dag**: `Dag::new()` default salt is genesis; existing tests constructing `Dag::new()` without calling `set_eviction_salt` get deterministic genesis-salted eviction (not old lex-min). This is a **behavioral change at upgrade** — document in changelog: eviction victim changes from lex-min to genesis-salted. Impact limited because single-operator deployment rarely hits `ORPHAN_CAP` (≈ never in normal gossip), and determinism is preserved per salt. No consensus fork because eviction is mempool policy, not state root.
* **Rollout**: deploy sidechain binary first (Dag change live), then first batch finalization flips salt from genesis to real root atomically on all replicas that processed the finalize. Replicas that lag seeing finalize temporarily disagree on eviction victim for at most one salt epoch (until they also `note_finalized`). This divergence is bounded and healed by orphan sync fetch (§2.4). No AA upgrade required.

### 4.3 Correctness risks

| Risk | Severity | Mitigation |
|---|---|---|
| Replicas disagree on `eviction_salt` (one saw finalize, other not yet) → evict different victims → temporary orphan set divergence | Medium | Salt source is Obyte-finalized root, propagation delay < few seconds after finalize; divergence window = `note_finalized` lag (seconds). Bounded by `ORPHAN_CAP`; orphan want sync (§2.4) re-fetches missing parent to heal. Acceptance test with divergent salts documents this as expected, not a bug. |
| Salt not updated (operator never finalizes height) → salt stays genesis forever | Low | Genesis-salted eviction is still grind-resistant vs bare lex-min (salt is fixed but unknown to pre-genesis attacker? Actually genesis is public, so grindable from start). Downgrade path: if height stays 0 for days, attacker knows genesis salt. Mitigation: after genesis, salt is weaker until first finalization — acceptable for MVP; first batch should finalize within hours. Document in runbook. |
| Hash DoS: attacker crafts 4096 orphans that all hash to colliding low keys? | Negligible | `sha256` is collision-resistant; finding 4096 colliding low keys costs 2^256 work. No bypass. |
| `min_by_key` allocates / copies UnitId incorrectly / ties | Low | `UnitId` is `Copy([u8;32])`; `min_by_key` clones 32 bytes per compare — no clone bug. Tie (identical salted key) impossible unless ids equal (duplicate), which `Dag::Duplicate` rejects before orphan path. |
| Waiting index leak if eviction removes wrong entry | Low | Existing `retain` loop already tested; new victim selection does not touch that loop. Add test §3.2.3. |
| Performance regression if orphan storm hits 4096 cap continuously | Low | 2 ms per storm unit is still < 500 QPS storm budget; storm itself is the bigger problem — want-rate-limit (§2.4) throttles it. |

### 4.4 What v1 deliberately does NOT do

* No per-batch epoch mixing (ordering Gap 5 will add epoch; keep eviction salt epoch-free for simplicity).
* No persistent orphan store, no disk spill.
* No eviction notification to peers (victim is simply dropped; orphan sync will re-request if needed).
* No weighted eviction (e.g. prefer evicting orphans with fee < X) — keep victim pure function of id+salt.

---

## 5. Open Questions

1. **Fallback salt choice**: `genesis_id().0` vs `sha256(b"empty")` vs `[0;32]`. Proposed `genesis_id`. `sha256(b"empty")` equals `merkle_root(empty)` sentinel — aliasing with empty-tree root could confuse diagnostics (two domains sharing a value). `[0;32]` is clean but less domain-separated. Any of the three is deterministic; reviewers to ratify.
2. **Salt domain separator**: Should `eviction_key` prepend a tag `b"operp-evict-v1"` before `salt||id` to separate from ordering salt `b"operp-order-v1"`? Ordering design uses `last_finalized_root || epoch_le`. Eviction uses `salt || id`. Tags are cheap (one extra copy). Recommendation: add `b"evict:"` prefix (6 bytes) → `sha256(b"evict:" || salt || id)` for hygiene; overhead is 6 bytes. Leave to reviewer — bare `salt||id` already domain-separated by input length (32+32 vs 32+8 vs variable).
3. **Should `pending_orphans` eviction be LRU-aware as well?** Salted random is good for grind resistance but drops uniformly; an attacker flooding with fresh ids still has 4096/5000 survival rate. Rate-limit per-account orphan count (e.g. max 256 orphans per AccountId) would bound Sybil. Out of scope for this gap — propose as follow-up Gap 6b (Sybil quota).
4. **Coordination with Gap 5 (commit-reveal / salted ordering)**: Gap 5 proposes `salt = sha256(last_finalized_root || epoch_le)` refreshed per batch for ordering, while eviction uses `salt = last_finalized_root` stable per finalization. Two salts share `last_finalized_root` source but refresh at different cadences — correct. Should we unify helper `fn eviction_salt(&self) -> [u8;32]` and `fn ordering_salt(&self)->[u8;32]` behind one `ChainState::finalization_anchor()`? Proposed yes — share `note_finalized` entry point, derive each key differently.
5. **Cross-node sync transport**: Which P2P stack? Current deployment is single-operator (no p2p). Sketch assumes libp2p or simple TCP gossip; actual choice deferred. Should sync be incentivized (pay peer for serving missing parent) to avoid free-riding? Leave to P2P design phase.
6. **Metrics**: Should evicted orphan count be exposed via `Engine::metrics()` or Prometheus gauge `operp_orphan_evictions_total`? Cheap and useful for alerting on storm — recommend adding as non-blocking follow-up, not required for correctness.

---

## 6. Staged Path (if one shot proves infeasible)

Gap 6 is feasible in one shot: Dag-only change, no AA, no fork. If review blocks on `ChainState` field addition:

* **Stage 0 (this batch / v1)**: Dag-only salt sourced from `genesis_id().0` plus optional `Dag::set_eviction_salt` setter wired manually (no ChainState field). Tests cover permutation convergence. Ship as grind-resistant vs genesis (known) but still better than lex-min because attacker cannot offline target victim without guessing Dag's runtime salt if operator rotates it manually. Demonstrates wiring without state schema change.
* **Stage 1 (follow-up)**: Add `ChainState::last_finalized_root` and `Engine::note_finalized` as above; Dag salt now tracks finality anchor. Same eviction logic, just source becomes consensus-anchored.
* **Stage 2 (P2P)**: Implement `WantUnits/HaveUnits` gossip per §2.4.

Recommended: ship Stage 0+1 together (single PR) since `ChainState` field is trivial and keeps salt source honest; fall back to Stage 0 only if schema change is contested.

---

## 7. File-Level Checklist (for implementer)

- [ ] `crates/operp-types/src/amount.rs` — no change.
- [ ] `crates/operp-state/src/lib.rs` — add `last_finalized_root: [u8;32]`, `last_finalized_height: Height`, `note_finalized()`.
- [ ] `crates/operp-dag/src/lib.rs` — add `eviction_salt: [u8;32]` to `Dag`, `set_eviction_salt`, `eviction_key`, replace `min()` with `min_by_key(|id| eviction_key(*id))` at L405; keep waiting cleanup.
- [ ] `crates/operp-exec/src/lib.rs` — add `Engine::note_finalized`, `Engine::eviction_salt()` getter; constructor already covers fallback.
- [ ] `crates/operp-settle/src/lib.rs` — no code change; observer calls `note_finalized` (document).
- [ ] `obyte-local/agents/operp_vault.aa` — no change.
- [ ] Tests — extend `crates/operp-dag/src/lib.rs::tests` and `crates/operp-exec/tests` per §3.2.

---

## 8. References

* Prior security plan claim: orphan buffering fixed (4096, deterministic eviction, reverse index) — this proposal hardens that fix from deterministic-lex to deterministic-salted.
* Commit-reveal design doc `local/mainnet-commit-reveal-design.md` — same `last_finalized_root` anchor; eviction deliberately omits epoch for stability.
* Obyte vault `last_finalized` stride: `var['last_finalized']` increments strictly by 1 per `finalize` (§5 in vault AA), so `note_finalized` height monotonicity can be asserted: `height == self.state.last_finalized_height + 1`.
