# Gap 1 — Fraud Response: Freeze-and-Rollback → Slashing + Validity-Proof Stub — Design

> Owner: `DesignFraudSlash` · Status: DESIGN-ONLY · Batch: Mainnet-1..5
> Depends: `operp_vault.aa` challenge/respond/finalize, `crates/operp-settle` Batch/Checkpoint, `crates/operp-state` aa_root/state_root

---

## 1. Target

### Problem restated (README L1)

Current vault is **optimistic freeze-and-rollback**: operator posts `temp_data` (full unit batch as JSON) + submits `{height, prev_state_hash, state_root, aa_root}` (60kB gross, 50kB net `SUBMIT_BOND_NET`), locks after 600s stability, can be frozen by any challenger (`challenge` ≥20kB gross / 10kB net) within 3600s. Two terminal branches:

- **Honest challenger + silent operator** → `finalize` after timeout sees `frozen==1 && now >= stable_at+3600` → marks `frozen=2`, clears `root_h/aa_root_h`, rolls `last_locked = h-1`, **confiscates submit bond** (`active_bond_h` cleared, not credited to `sbond`), challenger keeps `bond_addr` claimable via `claim_bond`.
- **Dishonest challenger + live operator** → `respond` (only `cand_who_h` may respond, `root_confirmed == root_h`) → unfreezes (`frozen_h=0`) and **confiscates challenger bond** (`bond_addr`+`bond_height_addr` zeroed, coins remain in AA pot).

Trade data **is** posted on-chain so any watcher can re-execute and detect a bad root (`Batch::validate_against`), but Oscript cannot re-run the matcher. Result: no automatic slashing split, no burn, no validity proof hook, enforcement relies on live watchers + competing operators. Operator stealing is prevented but stalling is free beyond the 50kB bond that is merely trapped (not rewarded).

### Exact files / symbols touched

| Crate | File | Symbol | What |
|-------|------|--------|------|
| `operp-types` | `crates/operp-types/src/lib.rs` | `SUBMIT_BOND_NET=50_000`, `CHALLENGE_SECS=3600`, `OBYTE_STABILITY_SECS=600`, `CHAIN_ID` | add `SLASH_CHALLENGER_SHARE_BPS=5000`, `SLASH_BURN_SHARE_BPS=5000`, `VALIDITY_PROOF_HASH_LEN=64` |
| `operp-settle` | `crates/operp-settle/src/lib.rs` | `Checkpoint { height, prev_state_hash, state_root, aa_root, last_unit, seq, unit_ids, fills_hash, fill_count }`, `Batch::from_applied`, `Batch::validate_against`, `TempDataPayload` | **add** `validity_proof_hash: Option<String>` to `Checkpoint`, wire through `from_applied`/`temp_data_payload`/`validate_against` |
| `operp-state` | `crates/operp-state/src/lib.rs` | `ChainState::state_root()`, `aa_root_of_state()`, `meta_leaf` | no consensus change; only diagnostic exposure of `validity_proof_hash` in meta_leaf if desired (optional) |
| `operp-exec` | `crates/operp-exec/src/lib.rs` | `Engine`, `Batch` | no change; `validate_against` is off-chain watcher primitive |
| `obyte-local` | `agents/operp_vault.aa` | `submit` / `challenge` / `respond` / `finalize` / `claim_bond` / `claim_submit_bond` / `claim_reward` handlers + state vars `active_bond_h`, `sbond_addr`, `bond_addr`, `bond_height_addr`, `challenger_h`, `frozen_h`, `submitted_at_h`, `cand_*`, `root_h`, `aa_root_h`, `stable_at_h`, `last_locked`, `last_finalized`, `reward_addr`, `fee_winner_h` | **core change**: new vars `valid_proof_h`, `slash_reward_addr`, `burned` diagnostic, new handler `claim_slash`, modified `submit`/`finalize`/`respond` economics |
| `obyte-local` | `post_batch.js`, `test_vault_aa.js`, `gen_withdraw_proof` example | operator flow + e2e test | extended to test slash path |
| tests | `crates/operp-settle/tests`, `obyte-local/test_vault_aa.js` | `validate_against` mismatch cases | new `bad_root_challenged_slash` e2e |

No wire-format break before activation height (new checkpoint field is `Option`, omitted = legacy). AA change is backward-compatible: old `submit` payloads without `validity_proof_hash` continue to validate (stored as empty).

---

## 2. Change

### 2.0 Design principles (keep it boring)

* Preserve existing wire format: `canonical_bytes` + `BTreeMap` ordering + `otherwise` guards in Oscript remain. New checkpoint field is optional.
* Preserve determinism: `validate_against` replay still commits `height` before hashing, still checks `prev_root`, `fills_hash`, `aa_root`, `state_root`, `last_unit`, `seq`.
* **Do not try to re-execute the matcher in Oscript.** AA never iterates over units; it only escrows bonds and splits on timeout/explicit outcome. Fraud proof is **off-chain replay mismatch** (any watcher runs `validate_against` locally over the `temp_data` payload).
* Respect AA complexity budget: net new op budget budgeted by deleting no-op diagnostics if needed; all new arithmetic is single `+`/`-`/`>` on u64 bytes.
* Bounded storage: new per-height key `valid_proof_h` (one 64-char string per locked height), per-address `slash_reward_addr` (bounded by challenger count). No unbounded loops.
* Migration: opt-in via `ACTIVATION_HEIGHT`; heights `< ACT` use legacy finalization (submit bond fully confiscated on failure, submit bond fully released on success). No state wipe.

### 2.1 Checkpoint: new stub field `validity_proof_hash`

```rust
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Checkpoint {
    pub height: Height,
    pub prev_state_hash: [u8; 32],
    pub state_root: [u8; 32],
    pub aa_root: String,                 // 64 hex
    pub last_unit: UnitId,
    pub seq: Seq,
    pub unit_ids: Vec<UnitId>,
    pub fills_hash: [u8; 32],
    pub fill_count: u32,
    /// Stub for future ZK/validator validity proof.
    /// None = legacy batch (no proof). Some(64-hex) = content-addressed proof
    /// (e.g. Groth16 verification key hash || public input hash).
    /// AA stores it verbatim, no verification yet (phase 2).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub validity_proof_hash: Option<String>,
}
```

Rules:

* `Batch::from_applied(prev, engine, applied)` sets `validity_proof_hash = None` by default. Operator tooling may call `batch.set_validity_proof_hash(Some(hex64))` before `temp_data_payload` if a proof is available (e.g. validator attestation bundle, later a ZK proof). No engine change.
* `Batch::temp_data_payload` includes `validity_proof_hash` in the JSON when `Some`, omits otherwise. `data_hash = sha256(json_bytes)` still covers it.
* `Batch::validate_against` adds a non-consensus check: if `self.checkpoint.validity_proof_hash` is `Some(s)` then `s.len()==64 && parse_hex64(s).is_ok()` else pass. Does **not** verify proof cryptography — stub only. Mismatch → `SettleError::BadProofHash` (new variant, maps to `RootMismatch` behavior but distinct error for diagnostics).
* `meta_leaf` may optionally commit the proof hash (hash it into state root if we want proofs to be committed). **v1 recommendation: do NOT commit into `meta_leaf`/`state_root`** — keep proof as AA-only commitment so lock semantics unchanged. Document that phase 2 may include it in `meta_leaf` once verification is added, gated by activation height.
* AA stores the hash (see 2.3). Future plug-in: add Oscript `if (var['valid_proof_' || h] && !valid_zk(...)) bounce` — no code now, just storage slot reserved.

Constant in `operp-types`:

```rust
pub const SLASH_CHALLENGER_SHARE_BPS: u64 = 5000; // 50%
pub const SLASH_BURN_SHARE_BPS: u64 = 5000;       // 50%, stays in AA pot
// Bonus: if PERP slash burned, mirrors oracle slash; here bytes stay unassigned = burn.
```

### 2.2 AA state: new vars

Existing vars remain (`boot`, `last_locked`, `last_finalized`, `submitted_at_h`, `cand_root_h`, `cand_aa_root_h`, `cand_who_h`, `active_bond_h`, `sbond_addr`, `root_h`, `stable_at_h`, `aa_root_h`, `frozen_h`, `challenger_h`, `bond_addr`, `bond_height_addr`, `reward_addr`, `fee_winner_h`, `wd_addr`, `wp_addr`, `bal_addr`, `pperp_addr`).

Add:

```
valid_proof_<h>         string(64 hex) | 0  — AA-side copy of checkpoint.validity_proof_hash for height h
                                            stored at lock time; cleared on frozen=2 failure
slash_reward_<addr>     u64 bytes           — accrued challenger slash share from failed heights,
                                            claimable via {claim_slash} (distinct from sbond/reward/bond)
burned                  u64                 — diagnostic cumulative burn (bytes + submit-bond burns).
                                            Never gates payments; informational (helps auditors treat
                                            vault holdings - perp_supply - burned as burn figure).
```

Naming avoids collision with existing `sbond_`/`reward_`/`bond_`. All use `otherwise 0` guard.

Storage bounds: `valid_proof_h` limited to heights `last_finalized+1 .. last_locked` (window ≤ 1 in practice plus 256-history prune not needed). If we keep history beyond finalization for explorer, prune at finalize success (keep last 256 proofs, or clear). v1 keeps only live/locked heights to stay bounded.

### 2.3 AA messages — step-by-step

#### 2.3.1 `submit` (extend to accept optional proof hash)

`init` adds validation for optional field; no bond change.

```
case: trigger.data.submit
init: {
  $h = trigger.data.height;
  $ll = var['last_locked'];
  if (trigger.data.chain_id != 'operp-mvp-1' OR !$h OR $h != $ll + 1
    OR !trigger.data.state_root OR length(...)!=64
    OR !trigger.data.aa_root OR length(...)!=64
    OR !trigger.data.prev_state_hash OR length(...)!=64)
      bounce('bad submit');
  // NEW: optional validity_proof_hash, if present must be 64 hex
  // Oscript: missing fields are boolean false; typeof guards as in withdraw
  $vph = trigger.data.validity_proof_hash;
  if (typeof($vph) != 'boolean' AND (length($vph)!=64 OR $vph == ''))
      bounce('bad proof hash');  // allow '' as absent placeholder; or require absent/64
  // ... existing prev mismatch / already locked / bond checks unchanged
  if (trigger.output[[asset=base]] - 10000 < 50000) bounce('need submit bond');
  $old = (var['active_bond_' || $h] otherwise 0);
  $changed = (trigger.data.aa_root != (var['cand_aa_root_' || $h] otherwise ''));
}
messages: state {
  if ($old AND $old != trigger.address) var['sbond_' || $old] += 50000;
  var['active_bond_' || $h] = trigger.address;
  var['cand_root_' || $h] = trigger.data.state_root;
  var['cand_aa_root_' || $h] = trigger.data.aa_root;
  var['cand_who_' || $h] = trigger.address;
  // NEW: store proof hash (empty string = none). Keep cand_* triple + proof.
  if (typeof(trigger.data.validity_proof_hash) == 'boolean')
      var['cand_proof_' || $h] = '';
  else
      var['cand_proof_' || $h] = trigger.data.validity_proof_hash;
  if ($changed) var['submitted_at_' || $h] = timestamp;
  if (!var['fee_winner_' || $h]) var['fee_winner_' || $h] = trigger.address;
}
```

Design choice: store in `cand_proof_h` pre-lock to avoid extra candidate vars sprawl. At `lock` it is copied to `valid_proof_h`.

Alternative naming `cand_valid_proof_h` — either is fine; spec uses `cand_proof_h` for brevity. Keep consistent.

#### 2.3.2 `lock`

Copies proof hash into finalized slot.

```
case: trigger.data.lock
init: as before (submitted_at + 600, height == last_locked+1, etc.)
messages: state {
  var['root_' || h] = var['cand_root_' || h];
  var['aa_root_' || h] = var['cand_aa_root_' || h];
  // NEW: persist proof hash
  var['valid_proof_' || h] = (var['cand_proof_' || h] otherwise '');
  var['stable_at_' || h] = timestamp;
  var['last_locked'] = h;
  var['frozen_' || h] = 0;
}
```

No validation of proof hash at lock time (stub). Future `respond` or new `prove_validity` message may verify it if non-empty.

#### 2.3.3 `challenge` — unchanged

Keeps current bond accounting. Note: bond minimum documented as 20kB gross / 10kB net; code enforces -10000 < 10000 (i.e. ≥20kB gross incl. 10kB bounce headroom). Recommendation: keep threshold unchanged; slashing reward makes challenging profitable even with 10kB net at stake. Optional v2: raise to 20kB net for sybil resistance — not in this batch (would shrink challenger set).

#### 2.3.4 `respond` — unchanged economics, but annotate burn direction

Current behavior (confiscate challenger bond) already matches "half burned / half to challenger on proven fraud" inverse: when operator is honest, challenger loses everything and it is burned (stays in AA pot). No split needed here — full burn is the slash for false challenge. Keep:

```
case: trigger.data.respond
init: operator identity gate + window + root_confirmed check
messages: state {
  var['frozen_' || h] = 0;
  // challenger bond confiscated = burned (remain in AA pot)
  var['burned'] = (var['burned'] otherwise 0) + (var['bond_' || challenger] otherwise 0);
  var['bond_' || challenger] = 0;
  var['bond_height_' || challenger] = 0;
}
```

If budget allows, increment `burned` diagnostic. If not, omit counter and document coins stay in pot = effective burn.

Do NOT refund any portion to challenger when operator proves innocence — otherwise challenge would be risk-free.

#### 2.3.5 `finalize` — the slashing fork (major change)

Current finalize has two branches: `$failed` vs success. Replace failure branch to split submit bond.

```
case: trigger.data.finalize
init: as before ($frozen, $failed = frozen==1 AND now >= stable_at+3600)
      plus: if (!$failed AND (...height order / window checks...)) bounce
messages: state {
  if ($failed) {
    var['frozen_' || h] = 2;
    var['root_' || h] = 0;
    var['aa_root_' || h] = 0;
    var['last_locked'] = h - 1;
    var['active_bond_' || h] = 0;      // confiscate submit bond
    var['fee_winner_' || h] = 0;
    var['submitted_at_' || h] = timestamp; // restart stability clock
    // --- NEW slashing distribution ---
    $submit_bond = 50000;
    $half = 25000;                      // SUBMIT_BOND_NET / 2  (integer)
    // Challenger is recorded at var['challenger_' || h]
    $ch = var['challenger_' || h];
    if ($ch) {
        // 50% to challenger as slash reward (accrued, not instant payment — avoids AA shortfall bounce)
        var['slash_reward_' || $ch] += $half;
        // 50% burn stays in AA pot; track diagnostically
        var['burned'] = (var['burned'] otherwise 0) + (50000 - $half);
        // challenger's own challenge bond remains in bond_ch (claimable via claim_bond)
        // Do NOT zero bond_ch here — that would confiscate honest challenger's stake.
        // Operator's submit bond is NOT credited to sbond_ch; it's split above.
    } else {
        // No challenger recorded (should not happen in $failed branch), full burn
        var['burned'] = (var['burned'] otherwise 0) + 50000;
    }
    // Clear valid_proof for failed height
    var['valid_proof_' || h] = 0;
    var['cand_proof_' || h] = 0;
  } else {
    var['last_finalized'] = h;
    $ab = var['active_bond_' || h];
    if ($ab) { var['sbond_' || $ab] += 50000; var['active_bond_' || h] = 0; }
    $fw = var['fee_winner_' || h];
    if ($fw) { var['reward_' || $fw] += 20000; }
    // valid_proof_h stays for finalized height (explorer history). No burn.
  }
}
```

Key invariants:

* Failed height: `active_bond_h` is **not** moved to `sbond`. It is split. Challenger's `bond_ch` is untouched (still claimable). Net challenger profit after `claim_bond` + `claim_slash` = `challenge_bond_net + 25_000` minus trigger costs.
* Successful height: unchanged (submit bond released, 20kB race reward to `fee_winner`). No slash.
* `burned` counter is diagnostic only; actual bytes simply remain in AA balance because no payment is emitted for that half. Oscript has no `burn` opcode; retention = burn in this UTXO model.
* Keep `$half = 25000` as integer constant inline (no bps math needed — cheaper AA op-count). If `SUBMIT_BOND_NET` later becomes governance-param, define `SUBMIT_SLASH_REWARD = SUBMIT_BOND_NET / 2`.
* Claim ordering: challenger may call `claim_bond` and `claim_slash` in any order, each requires 10kB fee headroom and pays once (`=0` after).

#### 2.3.6 New `claim_slash` handler

```
case: trigger.data.claim_slash
init: {
  $owed = (var['slash_reward_' || trigger.address] otherwise 0);
  if (!$owed OR trigger.output[[asset=base]] < 10000) bounce('nothing claimable');
  // Optional: if AA balance < owed, bounce (retry later) — same pattern as claim_reward
}
messages: [
  { app: "payment", payload: { asset: "base", outputs: [{ address: "{trigger.address}", amount: "{$owed}" }] } },
  { app: "state", state: "{ var['slash_reward_' || trigger.address] = 0; }" }
]
```

No `bond_height` guard (slash already settled at finalize). One challenge can only yield one slash entry per height (enforced by single challenger per `h`).

#### 2.3.7 Optional future `prove_validity` stub (not in v1, reserved)

Document where ZK/validator proof would plug in, but do not implement verification in v1:

```
case: trigger.data.prove_validity  // stub, v1 just stores hash; phase 2 verifies
init: {
  $h = trigger.data.height;
  if (var['frozen_' || $h] != 1) bounce('not challenged');
  if (!var['valid_proof_' || $h]) bounce('no proof committed');
  // Phase 2: verify proof bytes in trigger.data.proof against var['valid_proof_' || $h]
  // v1: no-op, rely on watcher replay. This init block intentionally not shipped in v1.
  bounce('not implemented');
}
```

Instead, v1 validity_proof_hash is purely **commit-and-observe**: watchers compare the hash to expected hash of attestation bundle produced off-chain; AA only guarantees the hash was committed at submit/lock and remains queryable via `valid_proof_h`. Replacement rule: `valid_proof_h` may be upgraded by re-submit of same height before lock (candidate replacement) if root unchanged? Current stability timer restarts only when `aa_root` differs; extend condition to `(aa_root != old_aa_root OR valid_proof != old_proof)` if we want proof upgrades to restart window. v1 recommendation: treat `valid_proof` as non-stability-affecting (like fee_winner) to avoid extending window for proof attachment.

### 2.4 Watcher fraud proof flow — no Oscript re-execution

```
Obyte DAG:  temp_data unit (JSON payload = Batch::temp_data_payload().data)
                │
                ▼
Watcher:  1) fetch temp_data payload by obyte_unit (post_batch.js data)
         2) reconstruct Batch { checkpoint, units } from payload
         3) load prev state: replay from genesis or cached state at height h-1,
            verify state_root == checkpoint.prev_state_hash (or last_finalized)
         4) Engine::validate_against(prev_root, &mut replay_engine)
            - checks chain_id, prev_root, fills_hash/count, height+1 binding,
              last_unit, state_root, aa_root
            - any mismatch returns SettleError::RootMismatch / FillsMismatch
         5) if validate_against == Err => fraud detected
            -> watcher calls AA: {challenge: {height: h}} with 20kB gross
            -> on timeout, anyone calls {finalize: {height: h}} -> $failed branch
            -> challenger calls {claim_bond} and {claim_slash}
         6) if validate_against == Ok  => batch honest; watcher takes no action
            -> operator may respond if falsely challenged, challenger loses bond
```

No Oscript iterates over `unit_ids` or `canonical_bytes`; all heavy lifting is Rust replay. AA's role is escrow + timeout, not computation.

Data availability guarantee: `post_batch.js` reveals every unit as `temp_data` **before** submit, so AA submission height is never unverifiable. Deterministic `canonical_bytes` + `BTreeMap` ordering + integer-only math ensure all watchers recompute identical `state_root`/`aa_root`/`fills_hash`.

`aa_root` divergence example (invisible to `state_root`): operator binds a deposit to wrong address (`Op::Deposit { addr }`). `state_root` would still verify but `aa_root_of_state` recomputed in `validate_against` step 4 would mismatch `checkpoint.aa_root`, triggering the same `RootMismatch` evidence.

### 2.5 Oscript complexity & storage budgeting

Current AA ~473 lines; complexity budget "effectively exhausted" per README. Proposal is **budget-neutral**:

* New `submit` lateinit for `valid_proof_hash`: +2 lines init, +4 state lines (conditional store). Saves by removing one comment line if needed.
* New `lock` proof copy: +1 line.
* Modified `finalize` failure branch: +8 lines (half split + burned counter) replaces 3-line confiscation comment block — net +5.
* Removed `respond` confiscation comment block shortened: net +1 (burned accounting).
* New `claim_slash` case: +12 lines (reuse `claim_reward` template). Offset by shortening `deposit_perp` shadow comments (3 lines) and `withdraw` leaf comments (2 lines).
* Estimated delta: **~+20 lines Oscript, ~8 new state keys per challenged height**. Under `MAX_AA_TREE_DEPTH` / 256-window regime this is within headroom; if limit hit, increase by pruning `valid_proof_h` for heights `< last_finalized - 256`.
* Rust delta: +1 optional field + 1 error variant + ~15 lines `temp_data_payload`/`validate_against`; no new `MAX` constants besides `SLASH_*` (BPS math not needed if halving is hardcoded).

---

## 3. Acceptance

### 3.1 E2E assertion: bad.root → challenge → slash

```
# test_vault_aa.js extension (pseudo)

-- setup: height 1 genesis ok, height 2 honest batch A (state_root R, aa_root A, last_unit U, fills F)
-- operator posts BAD batch B at height 2: same prev_state_hash, last_unit, unit_ids, seq, but state_root = R ^ 1 (flipped bit), aa_root = A (or also wrong)
   await operator.submit(height=2, prev=R_prev, state_root=bad_R, aa_root=A, proof_hash=null)
   // stable window 600s — test helper advances timestamp
   await timeTravel(601)
   await anyone.lock(height=2)

   // watcher detects fraud off-chain
   const prevRoot = genesisRoot
   const replay = new Engine(prevState)
   const err = batchB.validate_against(prevRoot, replay) // -> RootMismatch
   assert(err == 'RootMismatch')

   // watcher challenges before 3600s
   const challengerPre = await aaBalance(challenger)
   await challenger.challenge(height=2, fee=10_000) // 20kB gross, 10kB net locked as bond_ch

   // operator silence until window closes
   await timeTravel(3601)
   // anyone finalizes the failed height
   await anyone.finalize(height=2)
   assert(await aa.var('frozen_2') == 2)
   assert(await aa.var('last_locked') == 1) // rolled back
   assert(await aa.var('active_bond_2') == 0)
   assert((await aa.var('slash_reward_' + challenger)) == 25000)
   assert((await aa.var('burned') otherwise 0) >= 25000)
   assert((await aa.var('bond_' + challenger)) == 10000) // challenge bond retained, not confiscated

   // challenger claims both pots
   const bal0 = await aaBalance(challenger)
   await challenger.claim_bond()  // pays 10_000 net
   assert((await aa.var('bond_' + challenger)) == 0)
   await challenger.claim_slash() // pays 25_000 net
   assert((await aa.var('slash_reward_' + challenger)) == 0)

   // net assertion: challenger profit = slash_reward - challenge overhead
   // gross flows: -20kB challenge gross +10kB bounce headroom left? net 10k bond + 25k slash = +35k gross of claims
   // cost basis: 20k challenge unit + 10k claim_bond unit + 10k claim_slash unit = 40k gross spent in trigger outputs (10k each is bounce headroom non-refunded)
   // simpler observable: challenger AA ledger net +X where X = MAX(0, 10000 + 25000 - 20000) > 0
   // exact E2E assertion (net after fees in test harness where bounce_fees=10k):
   const profit = (await aaBalance(challenger)) - challengerPre
   assert(profit == 15000) // 10k bond refund + 25k slash - 20k challenger spends = 15k net (if test counts only net transfers)
   // alternatively if counting gross bytes escrowed, assert bal claims == 35000

   // recovery: new honest operator can re-submit height 2 correctly and lock
   await honestResubmit.submit(height=2, prev=R_prev, state_root=R, aa_root=A)
   await timeTravel(601)
   await honestResubmit.lock(height=2)
   assert(await aa.var('root_2') == R_hex)
   assert(await aa.var('frozen_2') == 0)
```

Second assertion — honest operator challenged falsely:

```
await operator.submit(height=3, correct...)
await operator.lock(height=3)
await attacker.challenge(height=3)
await operator.respond(height=3, root_confirmed=correct_R) // identity gate: only cand_who_3
assert(await aa.var('frozen_3') == 0)
assert((await aa.var('bond_' + attacker)) == 0) // confiscated = burned
assert((await aa.var('slash_reward_' + attacker) otherwise 0) == 0)
assert((await aa.var('burned') otherwise 0) >= 10000) // challenger bond burned
```

Third assertion — validity proof stub round-trip:

```
await operator.submit(height=4, ..., validity_proof_hash = 'ab'*32) // 64 hex
await timeTravel(601)
await anyone.lock(height=4)
assert(await aa.var('valid_proof_4') == 'ab'*32)
assert(batch4.checkpoint.validity_proof_hash == 'ab'*32)
assert((await watcherRecomputedBatch).validate_against(prevRoot, replay) == Ok)
// no verification performed; proof hash is just stored
```

### 3.2 Unit-level Rust assertions

```rust
#[test]
fn checkpoint_validity_proof_roundtrip() {
    let mut batch = Batch::from_applied(&prev, &mut engine, &applied).unwrap();
    batch.checkpoint.validity_proof_hash = Some("aa".repeat(32));
    let payload = batch.temp_data_payload();
    // json contains validity_proof_hash
    assert!(payload.data["validity_proof_hash"].as_str().unwrap().len() == 64);
    // replay validates with proof hash present and with None legacy
    let mut replay = Engine::from_state(prev.clone());
    assert!(batch.validate_against(prev.state_root(), &mut replay).is_ok());
    batch.checkpoint.validity_proof_hash = None;
    let mut replay2 = Engine::from_state(prev.clone());
    assert!(batch.validate_against(prev.state_root(), &mut replay2).is_ok());
}

#[test]
fn bad_state_root_is_fraud() {
    let mut bad = honest_batch.clone();
    bad.checkpoint.state_root[0] ^= 1;
    let mut replay = Engine::from_state(prev.clone());
    assert_eq!(bad.validate_against(prev.state_root(), &mut replay), Err(SettleError::RootMismatch));
}

#[test]
fn bad_aa_root_is_fraud_even_when_state_root_ok() {
    // construct batch where sidechain unbound account diverges from AA binding
    // ... ensures validate_against catches aa_root mismatch
    assert_eq!(bad.validate_against(prev.state_root(), &mut replay), Err(SettleError::RootMismatch));
}
```

### 3.3 Explorer / watcher assertions

* `validate_against` still the sole fraud detector — no new trusted party.
* `temp_data` data_hash is `sha256(json_bytes)` with proof hash included; watcher fetches payload by `obyte_unit` and recomputes hash to confirm availability before replay.
* `Batch::pick_stable_winner` unaffected (height-gated stable flag + MCI tie-break). Slash does not affect fee race.

---

## 4. Complexity & Risk

### 4.1 AA op-count delta

* `submit`: +2 comparisons (`typeof`, `length`), +2 assignments (conditional proof store). Cost O(1).
* `lock`: +1 assignment (`valid_proof_h` copy). O(1).
* `finalize:failed`: +4 assignments (slash_reward, burned twice, clear proofs) + conditional. O(1).
* `finalize:success`: unchanged.
* `claim_slash`: one new case, identical to `claim_reward`/`claim_submit_bond` template (payment + zero). O(1).
* Total delta ~20 lines, each line is one Oscript formula evaluation; no loops, no `reduce` beyond existing withdraw depth 16. Mitigate budget pressure by trimming stale comments (deposits self-attested note shortened) or raising `bounce_fees.base` is not needed.

### 4.2 Migration / backward compat

* Checkpoint wire: `Option<String>` with `skip_serializing_if=None` ⇒ old batches serialized without field remain valid JSON; new batches with field are accepted by old watchers that ignore unknown field if they use `serde::Deserialize` with `deny_unknown_fields=false` (current `TempDataPayload.data` is `serde_json::Value`, not typed Checkpoint, so no break).
* AA: `valid_proof_h` read uses `otherwise ''` empty sentinel; legacy heights return empty ⇒ no bounce for old queries.
* Slash activation: define `SLASH_ACTIVATION_HEIGHT = last_finalized + 1` at deploy via AA var `slash_active_from`. `finalize` failure branch: `if (trigger.data.height >= (var['slash_active_from'] otherwise 0)) { split } else { old confiscate }`. Simplifies upgrade without hard fork. Can also deploy as new AA and migrate via withdrawal path (no owner key philosophy preserved).
* No re-indexing of existing `state_root`/`aa_root`; meta_leaf unchanged so finality chain uninterrupted.

### 4.3 Backward compat — downgrade

* Rolling back this design (removing slash) would leave `slash_reward_addr` balances stranded. Provide migration endpoint: if deactivated, auto-credit `slash_reward` into `sbond` on next `claim_slash` fallback, or keep handler indefinitely (harmless, bounded).

### 4.4 Security / griefing

* Challenge bond 10k net is small vs 25k slash reward → profitable to watch. False challenges cost 10k burn (full loss) so not risk-free ⇒ balances watchers vs griefers. If grief rate rises, raise `CHALLENGE_BOND_NET` to 20k (mirrors README 20k intent) making slash reward 25k still > bond.
* Operator cannot avoid slash by `respond` with same bad root — `root_confirmed == root_h` would succeed only if challenger was wrong. Watcher's `validate_against` guarantees bad root is provably wrong over `temp_data` payload; an honest responder cannot fix a bad root without re-submit, so silence is the only path for a lying operator, leading to timeout failure.
* Sybil `claim_slash` on same height not possible: only one `challenger_h` per height (Oscript `frozen_h` gate prevents second challenge while frozen). Race to challenge is first-come; fee race applies.
* `valid_proof_hash` grinding: proof hash is attacker-controlled at submit, but future verification (phase 2) will be cryptographic; stub does not gate lock. Document that proof mismatch should not prevent challenge success — slashing trigger is still replay mismatch, not proof invalidity. Proof invalidity becomes slashable only in phase 2 when verification is active.
* AA shortfall risk in `claim_slash`/`claim_bond`: payments bounce if AA base balance < owed (retry later). No loss, ledger stays accrued.

### 4.5 Performance

* Replay is `O(units log units)` for matching + O(leaves) for Merkle; bounded by `BATCH_MAX_UNITS=512` per height (2s interval). Watchers run one replay per posted batch; <5ms per batch per `bench_raw` (§5.5k ops/s) ⇒ negligible. AA itself does no replay.
* Storage pruning: new `valid_proof_h` pruned after finalize success beyond 256-height window, matching `256h windows` convention for `withdrawals`/`aa_units`/`gov_nonces`.

---

## 5. Open Questions

1. **Burn destination: AA pot retention vs explicit burn asset?** Current Obyte AA byte balance is base (`bytes`) not PERP. Retaining submit-bond bytes in AA pot is effectively burn from user perspective (coins not reclaimable) but still counts toward AA balance for future payments (reward/bond payouts). Should half-burn be *truly* burned (sent to `0` address or to `burned` accounting and never paid out) vs kept as AA liquidity buffer? v1 keeps in pot for simplicity; auditor treatment: `vault holdings - locked bonds - rewards - slash_rewards` is the burn figure. Future: add governance `burn` opcode alternative.
2. **Split ratio: 50/50 vs 80/20 or 100% to challenger?** 50/50 mirrors PERP oracle slash (5000 BPS burn + 5000 reward) and deters challenger collusion with operator. 100% to challenger maximizes watcher incentive but creates incentive to solicit bad roots. Keep 50/50 as default, make governance-param `SLASH_CHALLENGER_SHARE_BPS` (phase 2).
3. **Should `validity_proof_hash` affect stability timer?** If proof is upgraded via replacement submit before lock, should `submitted_at_h` restart? Restarting prevents proof-withholding attack but gives operator extra window. v1 says no restart (proof alone does not affect `submitted_at`), but document alternative `changed = (aa_root != old || proof != oldProof)`.
4. **Attestation vs ZK: what is the first validity proof?** Candidates: (a) validator-set BLS aggregate over `state_root` (cheap, no circuits), (b) Groth16/PLONK over matexee execution trace (heavy, needs circuit for BTree matching + fixed-point math). Which to prioritize? Validator attestation adds trust in set but deploys today; ZK removes trust but is research-grade. v1 stub supports both as `sha256(proof_bytes)` hash; phase 2 chooses verifier.
5. **Multiple challengers at competing heights:** Current vault allows only one pending challenger per address (`bond_addr` one-shot). If attacker spams bad batches at heights 5..10 simultaneously, one honest watcher can only challenge one at a time. Should AA allow bond per height (keyed `bond_addr_h`) instead of single global `bond_addr`? Existing design chose one-at-a-time for simplicity; mainnet with many heights may need per-height bonds. Not needed if operators correct quickly and `CHALLENGE_SECS=3600` is longer than finalization cadence.
6. **Replay data availability fallback:** `temp_data` reveal is EC via `data_hash` byte-length cap? Obyte `temp_data` is not guaranteed permanent. Should watcher fallback be IPFS / sidechain P2P gossip of `Batch.units` canonical_bytes? For mainnet, consider archiving payload in sidechain `PostedBatch` out-of-band and pinning by `data_hash`.
7. **Activation flag storage:** Should `slash_active_from` live in AA `var['slash_active_from']` set via deploy init, or in sidechain `ChainState.height` gate? AA-side gate is authoritative for bond distribution; sidechain gate is irrelevant (watcher logic unchanged). Choose AA init row at boot.

---

## 6. Staged path if one-shot infeasible

**This batch ships as v1:**

* Checkpoint `validity_proof_hash: Option<String>` + `Batch::validate_against` length check + `temp_data` inclusion.
* AA: store `valid_proof_h` / `cand_proof_h`, split failed submit bond 25k/25k into `slash_reward_challenger` + burn (pot retention), add `claim_slash`, add `burned` diagnostic, keep challenge bond burn on honest respond.
* Watcher docs + `test_vault_aa.js` e2e proving `RootMismatch` → `challenge` → `finalize` timeout → `claim_bond` + `claim_slash` = challenger net +15k (net of trigger fees) / +35k gross claims.

**Phase 2 (not in this batch):**

* Add `ParamKey::SlashChallengerShare` governance over split ratio + `submit_bond` amount governance.
* Wire real verification into `finalize` or `respond`: `valid_proof_h` ZK verifier call or validator BLS threshold check; success unfreezes without timeout, failure triggers same slash path but automatically (watcher need not wait 3600s if proof is provided).
* Per-height challenge bonds, challenge window shortening, and AA-side `valid_proof` mandatory after activation height.
* IPFS/p2p archiving for `temp_data` with `data_hash` pinning and `operp-exec` fallback fetcher.
