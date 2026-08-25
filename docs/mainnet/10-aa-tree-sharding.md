# Gap 10 — AA-tree depth cap 2^16 : Scaling Design

> Status: DESIGN ONLY — no code edits. Parent merges after all subagents land.
> Assignment id: `DesignAaSharding`

---

## 1. Target (exact files / symbols)

| Area | File | Symbol / Var |
|------|------|--------------|
| Rust constant (single source of truth) | `crates/operp-types/src/lib.rs:31-36` | `pub const MAX_AA_TREE_DEPTH: usize = 16` |
| Hex-domain leaf / parent helpers | `crates/operp-state/src/lib.rs:604-615` | `aa_account_leaf_str`, `aa_parent` |
| Tree root + proof generation | `crates/operp-state/src/lib.rs:619-669` | `aa_root_of`, `aa_proof_for`, `aa_root_of_state`, `aa_proof_for_account`, `aa_pairs_of` |
| Settle checkpoint commitment | `crates/operp-settle/src/lib.rs:17-19,143-145,255-257` | `Checkpoint.aa_root: String`, `Batch::from_applied`, `Batch::validate_against` |
| Example proof exporter | `crates/operp-settle/examples/gen_withdraw_proof.rs` | proof JSON `proof[]` + `aa_root` |
| Vault AA — withdrawal fold | `obyte-local/agents/operp_vault.aa:319-323` | `$fold`, `reduce(trigger.data.proof, 16, …)` |
| Vault AA — storage keys | `obyte-local/agents/operp_vault.aa:27-40,156-157,254-255` | `aa_root_<h>`, `cand_aa_root_<h>`, `root_<h>`, `stable_at_<h>`; init `if (!$h) bounce` |
| Vault AA base template | `obyte-local/agents/operp_vault_base.aa` (mirror of vault) | same symbols, pre-asset substitution |
| JS E2E test | `obyte-local/test_vault_aa.js:278-489,616-893` | `aaLeafStr`, `sha256Hex`, `claim.proof`, `var['aa_root_'||h]` |
| Operator poster | `obyte-local/post_batch.js:127-128` | payload `aa_root` |
| Ocore limits (read-only reference) | `vendor/ocore/constants.js`, `vendor/ocore/definition.js`, `vendor/ocore/formula/evaluation.js:2345ff` | `MAX_OPS=2000`, `MAX_COMPLEXITY=100`, `reduce(expr,count,fn,init)` fatal if `arrElements.length > count`, overall ops budget |

Out of scope: byte-domain `state_root` merkle tree (`merkle_root`/`verify_proof` at `operp-state:524-595`), risk engine, DAG/orphan logic.

---

## 2. Current Mechanism — why 16 is hard

```
Rust: leaf = hex(sha256("acct:" + addr + ":" + collateral + ":" + perp + ":" + withdrawn))
      sort leaves lexicographically; while len>1 { if odd dup last; parent = hex(sha256(l+r)) }
      proof = siblings along path to root; refuse if siblings.len() >= MAX_AA_TREE_DEPTH (16)

Oscript AA: $fold = ($acc,$i,$sib) => !$acc ? false : ($sib.right ? sha256($acc||$sib.hash,'hex') : sha256($sib.hash||$acc,'hex'))
            $root = reduce(trigger.data.proof, 16, $fold, leaf)
            bounce unless $root == var['aa_root_'||last_finalized]
            plus leaf_account==trigger.address, amount+wd_<=collateral, & perp cap via wp_
```

A tree with N leaves needs depth `ceil(log2 N)` siblings.
- N=65 536 → depth 16 exactly → `MAX_AA_TREE_DEPTH=16` is sufficient.
- N=65 537 → one level duplicates but sibling count stays 16 for most leaves, 17 for at least one leaf → `aa_proof_for` returns `None` and the single-AA-root design cannot prove all accounts.

Ocore `reduce` semantics (`vendor/ocore/formula/evaluation.js:2360`):
`if (arrElements.length > count) return setFatalError("found N elements… only up to M allowed")`. So `reduce(proof, 16, …)` fatals (bounce) the moment the AA receives a 17-element proof — not silent truncation. The cap is enforced on both sides.

---

## 3. Change

### 3.1 Option A — Raise the cap (mono-tree depth bump)

**No new storage keys. Proof format unchanged.**

#### A1. Constants

```rust
// crates/operp-types/src/lib.rs
- pub const MAX_AA_TREE_DEPTH: usize = 16;
+ pub const MAX_AA_TREE_DEPTH: usize = 20; // v1 ships 18; see recommendation 3.3
```

Comment must keep the `vendor/ocore/formula/evaluation.js:2374` note: the fatal now fires at the new bound.

#### A2. Rust side — nothing else to change

`aa_proof_for` already does `if siblings.len() >= MAX_AA_TREE_DEPTH { return None; }`. Bumping the constant is sufficient. `aa_root_of` does not check depth — it builds to root regardless. No change to `merkle_root` (byte tree) which is unrelated.

Callers `aa_proof_for_account` / `gen_withdraw_proof.rs` pick up the new cap automatically.

#### A3. AA side — one integer

```oscript
// obyte-local/agents/operp_vault.aa:319-323  (and same in _base.aa)
- $fold = ...;
- $root = reduce(trigger.data.proof, 16, $fold, sha256('acct:'||..., 'hex'));
+ $fold = ($acc, $i, $sib) => (!$acc OR !$sib.hash) ? false
+         : ($sib.right ? sha256($acc || $sib.hash, 'hex') : sha256($sib.hash || $acc, 'hex'));
+ $root = reduce(trigger.data.proof, 20, $fold, sha256('acct:'||..., 'hex'));
  // (guard `!$sib.hash` already in current file — preserve it)
```

That's the entire AA diff. No new state vars, no migration of stored roots.

#### A4. JS E2E `test_vault_aa.js`

Update the local recheck loop bound comment from 16 to 20 (pure doc). No logic change — JS just iterates `proof.length`.

#### A5. Gas / Oscript budget analysis (Option A)

Measured on current vault AA (`vendor/ocore/definition.js:104-108`):

- `MAX_OPS = 2000` per definition evaluation (address complexity); validator iterates nodes and `count_ops++` per `evaluate` call.
- `MAX_COMPLEXITY = 100` (static definition complexity); formula evaluation also contributes to `count_ops` during runtime.
- Runtime `reduce` cost: `evaluate` is invoked per element: one `callFunction` per iteration plus `sha256` builtin. In `evaluation.js` each `sha256(..., 'hex')` is a single `evaluate` node; `reduce` itself is one `evaluate` node; each iteration's `$fold` body is 1 compare + 1 `sha256` + string concat.

Conservative count per proof step: ~4 `evaluate` calls (branch pick + `sha256` + string ops + bind). For depth 16 → ~64 ops in the hot loop; for depth 20 → ~80 ops. Entire withdrawal formula currently ~30-40 nodes outside the reduce plus one string `sha256` for leaf hash.

Even doubling to 20 stays well below `MAX_OPS 2000` and `MAX_COMPLEXITY 100`. The vault AA's overall complexity is dominated by the many independent `if` cases (9 cases × ~8 nodes each ≈ 25-30 complexity points currently, per `definition.js` counting). Adding 4 reduce steps does not add to definition complexity — `reduce` count arg is a literal, complexity is 1 for the node regardless of count. **Verdict: 20 is safe.**

Upper bound before pressure: empiric Obyte AAs routinely run `reduce(..., 40, …)` for payment splits; 20 is modest. At depth 24 (~16 M leaves) still fits ops, but proof payload hits trigger size limits (see below).

Trigger size: each sibling is 64 hex chars + `{hash,right}` JSON overhead. 16 siblings ≈ ~1.1 KB JSON; 20 ≈ ~1.4 KB; 24 ≈ ~1.7 KB. `MAX_UNIT_LENGTH = 5e6` and `MAX_AA_STRING_LENGTH = 4096` (per-string). A single string var cannot exceed 4096, but `trigger.data.proof` is an *array* of objects, not a single string — each `hash` field is 64 chars (<4096). So trigger size remains fine up to 20-24.

Recommendation's depth 18 (≈262 k accounts) needs +2 steps — negligible delta.

---

### 3.2 Option B — Sharded Forest

Goal: keep per-proof depth at 16 while scaling total accounts to N × 2^16. Proof always ≤16 siblings + a shard tag.

#### B1. Design parameters (proposed)

- **Shard count S = 16** (power-of-two recommended, 1<<4). Rationale: S=16 × 2^16 = 1 048 576 accounts (matches Option A-20 total) yet each proof stays depth 16. S=8 (524 k) also defensible; 16 is chosen because 16 shards align with one base32 char (alphabet `A-Z2-7` = 32 chars, first char `& 0x0F` gives uniform bucket) and keeps AA branching cheap (max 16-way lookup via `if`). S=4 would cap at 262 k which exhausts quickly.
- **Shard function must be deterministic, address-only, and uniform.** Two candidates:
  1) `shard = hex(sha256(address))[0] % S` — best uniform, but forces AA to compute `sha256(address,'hex')` once per withdrawal (1 extra hash). Cheapest uniform.
  2) `shard = index_of_first_char(address) % S` where `index` is `0..31` in `"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"` — zero extra hash, slight non-uniformity if addresses not uniformly distributed (they are chash160-derived, effectively uniform). Prefer (1) for rigor or (2) for cheapest.
  
  **This doc recommends (1)**: `shard = parseInt(sha256(addr,'hex').substr(0,2),16) & (S-1)` for S=16 (low 4 bits). One extra `sha256` is the strongest uniformity guarantee and keeps proofs shift-invariant under address ordering.

- Alternative not recommended: sharding by `collateral` or `position` — leaks biz logic into routing.

#### B2. Rust side

New API (additive; existing mono-tree symbols remain for backward compat during migration):

```rust
// crates/operp-types/src/lib.rs
pub const AA_SHARD_COUNT: usize = 16;
pub const MAX_AA_TREE_DEPTH: usize = 16; // stays 16 under sharding

// crates/operp-state/src/lib.rs
pub fn aa_shard_of(addr: &str) -> u8; // 0..S-1 per chosen function

pub fn aa_sharded_roots_of(pairs: &[(String,Usd,u128,i128)]) -> [String; 16];
  // buckets pairs by shard_of(addr), then aa_root_of(bucket) per shard.
  // Empty shard -> hex(sha256(b"empty:shard-N")) or hex(sha256(b"empty")) — distinct per shard
  // to avoid cross-shard zero proofs. Use hex(sha256(format!("empty:{}", shard))) .

pub struct ShardedProof {
  pub shard: u8,
  pub siblings: Vec<(String,bool)>,
  pub shard_root: String,   // root of the shard this account lives in
  pub all_roots: [String; S], // optional, for off-chain verification
}

pub fn aa_sharded_proof_for(
  pairs: &[(String,Usd,u128,i128)],
  addr:  &str,
) -> Option<(Vec<(String,bool)>, String, u8)>
  // (siblings, shard_root, shard)
  // refuse if any shard exceeds depth 16 (i.e. bucket > 2^16)

pub fn aa_sharded_roots_of_state(state: &ChainState) -> [String; 16];
pub fn aa_sharded_proof_for_account(
  state: &ChainState, id: &AccountId
) -> Option<(Vec<(String,bool)>, String, u8)>;
```

Internal: refactor `aa_pairs_of` bucketed path out so both old `aa_root_of_state` and new `aa_sharded_roots_of_state` share the pair enumeration.

Per-shard root computation reuses `aa_root_of(&bucket)` verbatim — zero new crypto.

Cap enforcement: per-shard `siblings.len() >= 16` → `None`; forest as a whole succeeds iff every shard is ≤16 (equivalently total ≤ S×2^16 and well-distributed; adversarial single-shard pile-up still fails — see Risks).

#### B3. Checkpoint / wire format

Option B1 (recommended — additive fields, boring):

```rust
pub struct Checkpoint {
  // existing unchanged:
  pub state_root: [u8; 32],
  pub aa_root: String,        // keep for backward compat; post-shard height this is aa_forest_root = sha256(roots[0]||…||roots[S-1])
  pub aa_shard_roots: Option<[String; 16]>, // Some from activation height onward; None before
  // ...
}
```

Serialization for `temp_data` (canonical_bytes-like): extend `Batch::temp_data_payload` JSON with `aa_shard_roots` when present. Old validators accept missing field (pre-shard); new validators require it after activation height. This keeps `BTreeMap`-ordered commitment style already used elsewhere.

Option B2 (alternative): keep `aa_root` as the forest root (sha256 over concatenated shard roots) and don't add a field; proof includes shard roots sibling path — rejected: would require a second tree depth (≈4) layered on.

Store `aa_shard_roots` as 16×64hex = 1024 hex chars across one JSON var — fits `MAX_STATE_VAR_VALUE_LENGTH=1024` exactly? 1024 value + JSON overhead would overflow by a few bytes. So storing as 16 separate vars is safer (see AA section). Checkpoint JSON is not bound by state-var length; only AA storage is.

#### B4. AA storage (sharded roots)

`MAX_STATE_VAR_NAME_LENGTH=128` so keys `aa_root_<h>_<s>` (= ~13 chars) are fine. But `MAX_STATE_VAR_VALUE_LENGTH=1024` caps a single var at 1024 bytes — cannot pack 16 roots in one var (needs 1024 + 15 commas ≈ 1040) — so use per-shard vars.

Replace / augment `aa_root_<h>` with `aa_root_<h>_<shard>` (16 vars per height). Keep `aa_root_<h>` for pre-shard heights (backward compat) and optionally as forest hash for diagnostics.

```oscript
// on submit (new behavior after SHARD_ACTIVATION_HEIGHT)
var['aa_root_' || $h || '_0'] = trigger.data.aa_shard_roots[0];
...
var['aa_root_' || $h || '_15'] = trigger.data.aa_shard_roots[15];
var['aa_forest_' || $h] = trigger.data.aa_root; // diagnostic forest hash, optional

// on finalize failure (existing sweep folded in) — clear all 16:
var['aa_root_' || $h || '_0'] = 0; // 0 sentinel clears; repeat 0..15 — or delete pattern
```

Submit handler must branch: if `trigger.data.aa_shard_roots` absent and `h < SHARD_ACTIVATION_HEIGHT` accept mono `aa_root`; if `h >= SHARD_ACTIVATION_HEIGHT` require `aa_shard_roots` length == S and each entry length==64 plus forest `aa_root` length==64. Height check prevents old clients posting shallow trees post-activation.

Lock handler: copies `cand_aa_root_<h>_*` → `aa_root_<h>_*`.

#### B5. AA withdrawal verification (sketch)

```
// trigger.data: { amount, withdrawn, leaf_account, collateral, perp, proof, shard }
// shard is uint 0..S-1; proof is same sibling-array shape as before, depth ≤16

init: "{
  $h = var['last_finalized'];
  if (!$h) bounce('not finalizable');
  if (typeof(trigger.data.shard) == 'boolean') bounce('bad claim'); // missing
  $shard = trigger.data.shard;
  if ($shard < 0 OR $shard > 15) bounce('bad shard');
  // existing presence + leaf ownership + wd_/wp_ caps unchanged
  $perp_claimed = trigger.data.perp - (var['wp_' || trigger.address] otherwise 0);
  if (trigger.data.leaf_account != trigger.address
    OR trigger.data.amount + (var['wd_' || trigger.address] otherwise 0) > trigger.data.collateral
    OR $perp_claimed < 0) bounce('bad claim amount');
  // BUILD expected shard from address: low 4 bits of first byte of sha256(addr,'hex')
  // Oscript: parseInt(sha256(addr,'hex').substr(0,2),16) & 15 — Oscript has no parseInt,
  // so use sha256 4-bit trick: first hex char maps 0..F → value. So shard = hexCharToVal(sha256(addr,'hex')[0]) & 15
  // Simpler: recompute as in Rust but doable inline without parseInt:
  // $expected = sha256(trigger.data.leaf_account,'hex');
  // $hex0 = $expected.substr(0,1);
  // $shard_expected = ($hex0 == '0'?0: ... ) & 15 — verbose but feasible (16 branches).
  // ALTERNATIVE: don't recompute shard in AA — trust claimed shard and just verify against that shard's root.
  //             This is safe because leaf is bound to address via hash preimage; moving shards would still fail proof.
  //             Shard recomputation is defense-in-depth only; skip to save ops.
  $fold = ($acc,$i,$sib) => (!$acc OR !$sib.hash) ? false
        : ($sib.right ? sha256($acc || $sib.hash,'hex') : sha256($sib.hash || $acc,'hex'));
  $root = reduce(trigger.data.proof, 16, $fold,
          sha256('acct:' || trigger.data.leaf_account || ':' || trigger.data.collateral || ':' || trigger.data.perp || ':' || trigger.data.withdrawn,'hex'));
  if ($root != var['aa_root_' || $h || '_' || $shard]) bounce('bad merkle root');
}",
```

Key point: **reduce depth stays 16**. Added cost vs today: one extra `reduce` dispatch? No — same single reduce. Extra vars: we read `var['aa_root_'||$h||'_'||$shard]` instead of `var['aa_root_'||$h]`. String concat `|| '_' || $shard` is one more `||` — negligible.

Shard recomputation branch: recommend NOT recomputing expected shard in AA v1 of sharding (trust claimed shard). Proof soundness does not depend on it: if claimant lies about shard, their leaf's hash path will not reach that shard's root, since leaves are partitioned by shard. An attacker could claim any shard; verification will fail unless leaf actually belongs there. Recomputing buys a slightly better error message at +~15 string compare ops — defer.

`otherwise` guards stay as in current file (`var['...'] otherwise 0`). Amount checks identical.

#### B6. Operator poster & JS test updates

- `post_batch.js`: call `aa_sharded_roots_of_state(&state)` plus forest hash and include `aa_shard_roots` in the `submit` trigger alongside `aa_root` (forest). Dual-write both for transition.
- `gen_withdraw_proof.rs`: add `--sharded` flag path printing `{shard, proof, aa_root, shard_root}`.
- `test_vault_aa.js`: add a second withdrawal helper that exercises sharded proofs after activation height; keep mono path.

---

### 3.3 Recommendation — v1: bump to 18 + sharding design for v2

**Ship as v1:** **Option A at depth 18** (not 16, not 20).

Why 18, not 16 or 20:

| Cap | Accounts (2^n) | Headroom vs today (~few k) | AA delta | Proof size Δ | Reasoning |
|-----|---------------|--------------------------|----------|--------------|-----------|
| 16 | 65 k | 0 — already the ceiling | 0 | 0 | Ships nothing |
| 18 | 262 k | ~4× today; covers 18-24 months of plausible growth without rework | +2 reduce steps | +128 bytes JSON | Smallest boring, safe change; stays far from trigger-size pressure |
| 20 | 1 048 576 | ~16× | +4 steps | +256 bytes | Also safe, but 20 inches closer to the 4096-string-length edge cases if someone naively packs proof as a single string elsewhere; reserve the extra 2 bits for v2 sharding story |

Choosing 18 leaves room to ship sharding (×16 → 4 M) without needing another mono bump. If growth explodes, a follow-up mono bump to 20 is still a one-line patch before sharding lands.

**Why not ship sharding as v1:**

- New storage keys (`aa_root_<h>_<s>` × S) expand per-height AA state from 1 var to 16 vars. That is a migration + gas + snapshot cost that touches every `submit`/`lock`/`finalize` path ordering (recall: only `state` messages must come last; the init/state split that handles `active_bond`/`fee_winner` is subtle). Mono bump touches exactly one literal.
- Sharding needs an activation height governance decision and dual-read logic (`if h < activation use aa_root_<h> else use shard`). That's additional test surface.
- The existing codebase already has the diagnostic `bal_` shadow ledger confusion; adding forest vars before that is stable invites a third ledger class.

**Staged path (proposed):**

```
Stage 0 (today): depth 16, mono root var aa_root_<h>
Stage 1 (v1 this batch): depth 18, mono — one-line Rust + one-line AA bump
                         activation: immediate (no height gate, see migration below)
Stage 2 (v2): shard forest S=16, depth 16 per shard → 4 M capacity
              activation at SHARD_ACTIVATION_HEIGHT = last_finalized + 2*CHALLENGE_SECS buffer
              Stage 2 ships additive fields + per-shard vars, keeps Stage-1 mono path for h < activation.
Stage 3 (future, if needed): content-addressed shards with dynamic S via commitment version byte.
```

**v1 patch summary (Stage 1) — minimal diff:**

```
operp-types/src/lib.rs:  MAX_AA_TREE_DEPTH 16 -> 18
operp_vault.aa:          reduce(...,16,...)->reduce(...,18,...)  [withdraw case only]
operp_vault_base.aa:     same
test_vault_aa.js:        comment update 16->18
docs:                    README Limitations #10 rewrite (see below)
```

That is the entire v1. No new messages, no new vars, no checkpoint field.

---

### 3.4 Detailed file ops (Stage 1 — what reviewer lands)

1. `crates/operp-types/src/lib.rs:31-36`
   - Change `16` → `18`, update doc comment to reference `reduce(...,18,…)` and `vendor/ocore/formula/evaluation.js:2374` fatal on `> 18`.
2. `crates/operp-state/src/lib.rs:638-669`
   - No code change (cap read from constant); optionally update the item doc on `aa_proof_for` from "16 steps" → "MAX_AA_TREE_DEPTH steps".
3. `obyte-local/agents/operp_vault.aa:321-322`
   - Change `reduce(trigger.data.proof, 16, $fold,` → `reduce(trigger.data.proof, 18, $fold,`.
   - Keep the existing `!$acc OR !$sib.hash` guard.
4. `obyte-local/agents/operp_vault_base.aa` — identical change.
5. `obyte-local/test_vault_aa.js:527-530` (comment `depth ≤ 16`) → `depth ≤ 18`.
6. `README.md:298-300` — limitation #10 becomes "cap is 2^18 (262 k) via depth 18; sharded forest design for v2 targets 2^20+ via S shards".
7. `docs/MECHANISMS.md:526-530` — same.
8. (Optional) `crates/operp-settle/examples/gen_withdraw_proof.rs` — doc comment update.

Total: 4 files changed, 1 constant, 1 AA literal. Zero new deps.

### Stage 2 detailed ops (design, not shipped this batch — for parent tracking)

1. `operp-types`: add `AA_SHARD_COUNT: usize = 16`, new helper `aa_shard_of`, keep `MAX_AA_TREE_DEPTH=16` (mono cap stays 16 *inside* each shard after stage 2 ships; but stage 1 currently sets it to 18 — stage 2 will revert mono constant to 16 for per-shard depth, or keep 18 as per-shard max to allow 4 M *with* depth 18 per shard = 4 M×4 — decide at ship). This doc proposes stage 2 keeps per-shard depth 16 (clean reset) to reclaim headroom and force the forest path; mono 18 is a stepping-stone that disappears at stage 2 activation.
2. `operp-state`: add bucketed APIs as in 3.2 B2, reuse `aa_pairs_of` bucketing.
3. `operp-settle/lib.rs`: add `Checkpoint.aa_shard_roots`, extend `Batch::from_applied` to compute both, extend `validate_against` to check shard roots when activation height passed, update `temp_data_payload` JSON.
4. `operp_vault.aa`: add `SHARD_ACTIVATION_HEIGHT` constant comment, branch `submit`/`lock`/`finalize` to store 16 per-shard vars, update `withdraw` to shard-select (3.2 B5). Add sweep loop for 16 vars on failure path (16× `var['aa_root_'||h||'_'||i]=0`). See Complexity 4.3 for budget fix.
5. `post_batch.js` / `test_vault_aa.js`: dual path.

---

## 4. Acceptance (observable result + test / E2E assertion)

### 4.1 Observable result

- **Pre-ship baseline**: `aa_proof_for` over 65 536 leaves returns `Some`; over 65 537 returns `None`; vault AA `reduce(...,16,…)` fatals on a 17-element proof array.
- **Post Stage-1 (depth 18)**: same tree at N=262 144 returns `Some`; at N=262 145 returns `None`; AA verifies 18-deep proofs and rejects 19-deep ones. Existing 65k-batch checkpoints remain valid (they need only depth ≤16, inside the new 18 allowance).

### 4.2 Required tests — Stage 1 (must pass before merge)

#### Rust unit (`crates/operp-state`)

```rust
#[test]
fn aa_proof_for_refuses_at_new_depth() {
    // mirrors existing aa_proof_for_refuses_over_deep_trees, but updated bounds
    let mk = |n: usize| -> Vec<(String,Usd,u128,i128)> {
        (0..n).map(|i| (format!("A{:031}", i), 1, 0u128, 0i128)).collect()
    };
    // 2^18 leaves needs exactly 18 siblings — must succeed
    let ok = mk(1 << 18);
    assert!(aa_proof_for(&ok, &format!("A{:031}", 1)).is_some());
    let (sibs, root) = aa_proof_for(&ok, &format!("A{:031}", 1)).unwrap();
    assert_eq!(sibs.len(), 18);
    assert_eq!(root, aa_root_of(&ok));
    // one more leaf → at least one path needs 19 → must refuse
    let too_deep = mk((1 << 18) + 1);
    assert!(aa_proof_for(&too_deep, &format!("A{:031}", 1)).is_none());
}

#[test]
fn aa_proof_70k_roundtrip() {
    // the acceptance gate named in ticket: 70k tree proves + verifies
    let n = 70_000usize; // >2^16, <2^18 — would have failed pre-ship
    let pairs: Vec<(String,Usd,u128,i128)> = (0..n)
        .map(|i| (format!("ADDR{:028}", i), (i as i128)*1000, i as u128, 0)).collect();
    let root = aa_root_of(&pairs);
    // sample a few addresses across the set
    for idx in [0, 1, 1024, 35000, 69999] {
        let addr = format!("ADDR{:028}", idx);
        let (proof, got_root) = aa_proof_for(&pairs, &addr).expect("must prove 70k shard");
        assert_eq!(got_root, root);
        assert!(proof.len() <= 18);
        // replicate AA fold locally (hex-string domain)
        let mut h = aa_account_leaf_str(&addr, (idx as i128)*1000, idx as u128, 0);
        for (sib, right) in &proof {
            h = if *right { hex::encode(sha256(format!("{}{}", h, sib).as_bytes())) }
                else       { hex::encode(sha256(format!("{}{}", sib, h).as_bytes())) };
        }
        assert_eq!(h, root, "fold must reach root for idx {}", idx);
    }
    // negative: non-member must not get a proof
    assert!(aa_proof_for(&pairs, "ADDR9999999999999999999999999999").is_none());
}
```

These two tests replace/augment the existing `aa_proof_for_refuses_over_deep_trees` (which currently asserts at `1<<16`). Keep the old test name but update expected bound to `1<<MAX_AA_TREE_DEPTH` so it stays meaningful after constant bump.

#### Settle-level

```rust
#[test]
fn batch_with_70k_accounts_issues_valid_checkpoint() {
    // Build a ChainState with 70k bound accounts (accounts + aa_addresses + perp/withdrawn ledgers)
    // run Batch::from_applied or directly aa_root_of_state check
    // then validate_against succeeds
}
```
70k accounts construction: deterministic addresses `format!("A{:031}", i)` bound via `state.aa_addresses.insert(id, addr)`, `state.perp_balances`, small `collateral` — no book/marks needed. Assert `Batch::validate_against(prev_root, &mut replay)` returns `Ok(())` with `checkpoint.aa_root == aa_root_of_state(&state)`.

#### AA E2E (`obyte-local/test_vault_aa.js` — aa-testkit devnet)

Extend the existing `aaLeafStr / sha256Hex` harness (lines 278-283) with a 70k-branch, elected to run as a separate case `HEIGHT=3` after the `70k` synthetic root is submitted:

```js
// synthetic 70k aa_root: reuse the same aa_root_of from test's JS copy, or ingest a JSON fixture
//   produced by `cargo test -- aa_proof_70k_roundtrip` which writes `obyte-local/testdata/aa70k.json`
//   with { pairs_count: 70000, root, sample_proofs: [{addr, collateral, perp, withdrawn, proof}, ...] }
// Then the standard flow:
//   deposit AA (fund it) → submit 3 → timetravel 600 → lock 3 → timetravel 3600 → finalize 3
//   then withdraw via the 70k proof (proof.length == 17 for 70k) and assert wd_ / wp_ / payment.
//   Existing `reduce(...,18,...)` must accept proof length 17/18; a hand-crafted proof length 19 must bounce('bad merkle root') / fatal
```

The existing `test_vault_aa.js` already does `for (const s of claim.proof) lh = sha256Hex(s.right ? lh+s.hash : s.hash+lh)` and checks `lh==aa_root` before triggering — reuse that harness. Add `expectBounce` for a too-deep proof (>18) to show the AA fatals (Ocore's "found 19 elements … only up to 18 allowed") rather than silent truncation.

#### Manual smoke (release gate)

```
cargo test -p operp-state aa_proof_70k_roundtrip aa_proof_for_refuses_at_new_depth -- --nocapture
cargo test -p operp-settle batch_with_70k_accounts_issues_valid_checkpoint
cd obyte-local && node test_vault_aa.js   # full lifecycle still green, plus new 70k case if enabled
```

70k branching is heavy: generate with `format!("A{:031}", i)` / `sha256` 70k × ~log2 path — about 0.2s in Rust per root. Mark the 70k test `#[ignore]` for CI default and run in `--ignored` gate or generate the fixture JSON offline.

### 4.3 Stage 2 acceptance (future)

- Build a forest with `S=16`, each shard ~65k → total ~1 M. For a random address, `aa_sharded_proof_for` returns `Some` with `siblings.len() ≤16`, shard matches `aa_shard_of(addr)`, folding reaches that shard's root, and the `aa_shard_roots[shard]` entry matches the shard root. Overfull single shard (>65k bucket) still refuses — acceptable (uniform shard function caps blast radius).
- JS E2E: submit forest at activation height; withdraw from three different shards; renegade shard claim (proof for shard 3 presented as shard 7) bounces.

---

## 5. Complexity & Risk

### 5.1 AA op-count / complexity delta (Stage 1 — depth 18)

- **Definition complexity (static)**: `reduce` node counts as 1 complexity point irrespective of count literal. Delta **0**. Vault AA stays at current ~25-30 / 100 budget.
- **Runtime ops (dynamic)**: +2 iterations of one `sha256(…, 'hex')` + one string concat + branch. Per earlier estimate ~+8 `evaluate` calls. Well within 2000 `MAX_OPS`. No new `state` writes, so no new `MAX_STATE_VAR_VALUE_LENGTH` pressure.
- **Verdict**: stage 1 is effectively free complexity-wise — the most boring possible change.

### 5.2 AA op-count delta (Stage 2 — sharded forest)

- **Complexity (definition)**: withdraw case adds one extra string concatenation (`'_'||$shard`) → still one node. `submit`/`lock`/`finalize` grow from 1 write to 16 writes. Each `var['…'||$h||'_'||'0']=…` is one assignment node. 16 assignments add ~16 complexity points → vault AA would sit at ~40-46 / 100, still under. However `finalize` sweep clearing 16 vars pushes `finalize` case toward ~18 points — combined file might approach 60-70. Need to measure after authoring; if >100, split `submit` handling into two cases (`submit_sharded` vs `submit_mono`) to halve per-case count.
- **Runtime ops**: withdraw stays single reduce (depth 16) → delta 0 ops for hot path. `submit` writes 16 vars → +16 state assignments per locked height. Each height permanently stores 16×64hex ≈ 1024 bytes plus key overhead — AA state grows ~16× in that var dimension (≈ 16 KB per finalized height at S=16). At 1 height/day this is benign; at 1/2s batches it is catastrophic — but checkpoints are ~512 units / 2 s; Obyte submission is batched per checkpoint and only finalized heights persist. So growth is per Obyte height, not per sidechain batch.
- **Mitigation if complexity exceeds 100**: deploy `operp_vault_sharded.aa` as a new AA instance and migrate funds via the existing withdrawal path (no owner key — migration IS the withdrawal). Or cap S=8 (8 shards → 524 k, complexity ~+8).

### 5.3 Migration & backward compatibility

#### Stage 1 (depth 18 mono)

- **Checkpoint / replay**: tightening vs loosening. Loosening 16→18 is forward-compatible: any root valid at depth 16 is still valid at depth 18 (needs only fewer siblings). `validate_against` does not check depth — it recomputes `aa_root_of` and compares strings. No replay break.
- **Existing AA storage**: `var['aa_root_'||h]` for h ≤ `last_finalized` stays valid. No migration. New heights just store roots built over perhaps larger trees — old proofs remain proven by earlier heights' smaller trees.
- **Activation**: immediate. Old clients posting new heights with depth ≤16 still fit; no height gate needed. A rolling upgrade is safe: Rust side accepts up to 18, AA side accepts up to 18 — if old AA (depth 16) is still the vault, a depth-17 proof would fatal on chain even though Rust permits it — so AA and Rust must deploy together (same PR, same deploy). Countermeasure: deploy AA first (it already accepts 18 but depth-16 proofs still land), then bump Rust — either order works because both are loosening.

#### Stage 2 (sharded forest)

- **Strict migration required.** Two incompatible commitments:
  - Before activation: leaves hashed into one sorted list → `aa_root`.
  - After: leaves bucketed by `shard_of(addr)` → 16 sorted lists → `aa_shard_roots[0..15]`.
  - A proof built under the mono scheme will not verify against any single shard root (leaf sets differ). So activation must not retroactively re-verify old heights.
- **Proposed activation**: governance-height gate.
  - Pick `SHARD_ACTIVATION_HEIGHT = last_finalized + k` where k is large enough for watchers to upgrade (e.g., +100 or timestamp-gated `SHARD_ACTIVATION_TS`).
  - AA `submit`: `if $h < activation use mono aa_root path else require aa_shard_roots`.
  - AA `withdraw`: `if shard field absent then verify against var['aa_root_'||h] else verify against var['aa_root_'||h||'_'||shard]`. This preserves withdrawals for pre-shard heights forever without re-commitment.
  - Rust `validate_against`: same height gate when recomputing.
- **Data on chain**: old `temp_data` batches remain auditable (they carry mono `aa_root`). New batches carry `aa_shard_roots` plus forest hash.
- **Deposit binding**: `aa_pairs_of` bucketing inherits `aa_addresses` first-seen-wins — no new binding semantics. Shard overflow (>65k per shard) not fixable by re-addressing because address binding is sticky. Watchers should alarm if any shard approaches 60k.

### 5.4 Security surface

- **No new replay**: leaf commits `(addr, collateral, perp, W)` plus global `wd_/wp_` caps — sharding does not alter leaf preimage. Proofs remain address-bound.
- **Shard-hopping forgery**: attacker crafts leaf for `addr=VICTIM` but claims `shard=WRONG`. Their leaf hash would not be in that shard's tree → fold misses → `bad merkle root`. Secure.
- **Cross-shard collision**: empty shards must have distinct empty roots (e.g., `"empty:0"`, `"empty:1"`) so a zero-value proof cannot be reused across shards. Proposed `hex(sha256("empty:shard-<n>"))` achieves this.

### 5.5 Throughput / DOS

- Sidechain proof generation at N=262k: sorting 262k hex leaves + building 18 levels → ~262k ×32 bytes hashes, dominates batch building (~0.1-0.2 s). Still under `BATCH_INTERVAL_MS=2000` but should be measured in `bench_raw`. Sharding reduces per-batch build to 16× sorts of ~16k each (for 262k uniform) — faster due to smaller sorts — but total work is similar. Not a DOS concern.

---

## 6. Costed Comparison

| Dimension | Option A18 (v1) | Option A20 | Option B (S=16, D=16) |
|-----------|-----------------|------------|------------------------|
| Total accounts | 262 144 | 1 048 576 | 1 048 576 (16×65k) |
| Proof size (hex JSON) | ≤18×(~70B)=~1.26 KB | ≤20×70=1.4 KB | 16×70=1.12 KB + 1 byte shard |
| AA `reduce` count | 18 | 20 | 16 |
| AA new vars / height | 0 | 0 | 16 |
| AA definition complexity Δ | 0 | 0 | +~16 (submit) + branch |
| Runtime ops Δ (withdraw) | +8 | +16 | 0 |
| Stored bytes / height (AA state) | 64 | 64 | 1024 (+ diag forest 64) |
| Rust code delta | 1 literal | 1 literal | ~120 LOC (new APIs, bucketing, checkpoint) |
| AA code delta | 1 literal | 1 literal | ~60 LOC across 4 handlers |
| Migration | none (loosening) | none | activation height + dual readers |
| Time to ship | <1 day | <1 day | ~1 week incl. E2E |
| Failure mode if mis-sharded | n/a | n/a | one hot shard exceeding 65k locks withdrawals for those addresses only (others unaffected) |

---

## 7. Open Questions

1. **v1 depth choose 18 vs 20** — ticket says "Recommend v1: bump to 18 + sharding design for v2" — this doc follows it. If team prefers a single mono lifetime (no v2 funded), 20 eliminates the need for sharding for ~2× longer; revisit after measuring AA harness pressure post-bump.
2. **Shard function choice**: `sha256(addr,'hex')[0] & 0xF` vs `first_char_index & 0xF`. Former costs 1 sha256 in AA if recomputed; former is more uniform-proof. Decision affects nothing else. Recommend keeping recomputation out of AA v2 initially (trust claimed shard) — then shard function can be pure Rust without AA cost.
3. **Stage 2 reverts mono depth to 16 or retains 18** — retaining 18 per-shard gives 4 M capacity but pushes empty-shard proof allowance to 18; cleaner to reset per-shard depth to 16 and declare "forest depth is 16" as the permanent invariant. Needs explicit decision before stage 2 AA audit.
4. **Empty shard sentinel** — `hex(sha256(b"empty"))` identical across shards is more storage-efficient but enables cross-shard zero proofs to pass on any empty shard (empty proof is just leaf==shard_root, trivial). With distinct sentinels this cannot happen. Should confirm with auditor that distinct sentinels do not break any invariant elsewhere.
5. **Activation governance** — does shard activation require a `ParamKey` proposal vote or an AA upgrade deployment? Since vault AA has no owner key, shard switch needs either a new AA deployed at activation height (canonical migration path) or a version byte inside the AA's `submit` that gates on height. Second option avoids deploying a new AA but still requires AA code freeze window.
6. **`MAX_AA_STRING_LENGTH=4096` for forest value** — 16×64+commas exceeds 1024 value limit, so per-shard vars are mandatory. Confirm Obyte light client sync cost of 16 vars/height is acceptable to watchers storing full state.
7. **Test fixture for 70k**: at 70k pairs × hex leaf, constructing the proof in JS for E2E is heavier than Rust — should generate a static JSON fixture (`obyte-local/testdata/aa70k.json`) from Rust and check it into `testdata/` rather than building 70k leaves live in `test_vault_aa.js` (devnet memory). Agree on fixture path.

---

## 8. Doc & Readme Updates (post-ship)

- `README.md#Limitations 10` — rewrite to reflect new cap (2^18) and that `MAX_AA_TREE_DEPTH` now mirrors `reduce(...,18,…)`. Note that sharded forest is planned for v2 and link this design doc.
- `README.zh-CN.md` — same.
- `docs/MECHANISMS.md` — update the `proof depth ≤ 16` annotation (section around line 526) and hex-tree description (line 432ff).
- `docs/PROTOCOL.md` — same, plus any throughput note if bench changes.
- `obyte-local/agents/operp_vault.aa` header comment block `WITHDRAWALS ARE PROOF-GATED` — update the sibling-list prose to mention depth bound and `MAX_AA_TREE_DEPTH`.
- Add `local://mainnet-DesignAaSharding-design.md` (this doc) to the commit.

---

## 9. Appendix — Withdrawal AA Verification Sketch (Stage-1 exact)

```oscript
// current depth 16 — post-ship depth 18
$fold = ($acc, $i, $sib) => (!$acc OR !$sib.hash) ? false
      : ($sib.right ? sha256($acc || $sib.hash, 'hex') : sha256($sib.hash || $acc, 'hex'));
$root = reduce(trigger.data.proof, 18, $fold,
        sha256('acct:' || trigger.data.leaf_account || ':' || trigger.data.collateral || ':' || trigger.data.perp || ':' || trigger.data.withdrawn, 'hex'));
if ($root != var['aa_root_' || $h]) bounce('bad merkle root');
```

No other handler changes.

---

*End of design — ready for parent merge and Stage-1 implementation.*
