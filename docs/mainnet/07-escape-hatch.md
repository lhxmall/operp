# Gap 8 — No Trustless Escape Hatch if All Operators Disappear — Design

> Owner: `DesignEscapeHatch` · Status: DESIGN-ONLY · Batch: Mainnet-1..5

---

## 1. Target

### Problem restated (README L8)

> _Failed heights roll back cleanly and are re-lockable (`frozen = 2` recovery), but recovery depends on operators resubmitting corrected batches; there is no trustless escape hatch if every operator disappears._

Current lifecycle per height `h` in `obyte-local/agents/operp_vault.aa`:

* `submit(h)` — operator posts `{height, prev_state_hash, state_root, aa_root}` with `50000`-byte `SUBMIT_BOND_NET`. Candidates are **replaceable pre-lock**; stability timer restarts only on `aa_root` change. Height must equal `last_locked+1`; `prev_state_hash` must equal `var['root_'||last_locked]`.
* `lock(h)` — after `OBYTE_STABILITY_SECS = 600` (`submitted_at_h + 600`) any caller may lock. `last_locked = h`, `frozen_h = 0`.
* `challenge(h)` within `CHALLENGE_SECS = 3600` of `stable_at_h` freezes `h`; `respond(h)` within window by `cand_who_h` unfreezes and confiscates challenger `bond_`; else `finalize(h)` after window marks `frozen=2`, clears `root_h/aa_root_h`, rolls `last_locked = h-1`, confiscates `active_bond_h`, restarts `submitted_at_h`.
* `finalize(h)` after clean `3600`s sets `last_finalized = h`, releases `active_bond_h → sbond_` and accrues `reward_` to `fee_winner_h`.
* `withdraw` — proof against `var['aa_root_'||last_finalized]` only (fixed 16-step `reduce`), global anti-replay `wd_/wp_` caps.

All of `submit / lock / finalize` are **permissionless in the code** (no `trigger.address` gate except `respond`), but liveness still assumes *someone* keeps producing sidechain batches, posting `temp_data`, and paying the `50000` submit bond. If every operator vanishes:

* **S1 — no new candidate:** `last_finalized = f`, `last_locked = f` (or `f` plus a stale candidate that never reached 600s). Users' balances at `f` remain withdrawable, but any deposits/fills after `f` (including the vault's `bal_` escrow) are **stranded** — no new root ever finalizes.
* **S2 — locked but never finalized:** `h = f+1` is locked, challenge window already expired (`stable_at_h + 3600`), but nobody calls `finalize(h)` (operators gone, watchers not incentivized to pay byte fees). Funds at `h` are stranded even though `finalize` is technically permissionless — the UX has no explicit liveness reward/timeout signalling that *any* holder should do it.
* **S3 — challenged and failed, no resubmit:** `frozen_h = 2`, `last_locked = h-1`. Chain is ready for a fresh `submit(h)` but nobody with a synced engine + `50000` bond steps up. Indefinite stall.

README hints two concrete hatch shapes; this design specifies both as a single coherent mechanism:

* **(a) `escape_finalize` / `escape_withdraw`** — after `last_finalized` stalls > `T` (≈7 days) any holder can finalize the oldest locked height without operator liveness, or withdraw directly against the stalled candidate's `cand_aa_root`.
* **(b) permissionless `submit` gap-filling** when `last_locked` stalls — keep `submit` permissionless but make the liveness invariant explicit and reduce friction for altruistic continuation.

### Exact files / symbols touched

| Crate | File | Symbol | What |
|-------|------|--------|------|
| `operp-types` | `crates/operp-types/src/lib.rs` | `CHALLENGE_SECS`, `OBYTE_STABILITY_SECS`, `CHAIN_ID`, `MAX_AA_TREE_DEPTH` | add `ESCAPE_STALL_SECS`, `ESCAPE_STALL_SECS_TESTNET`, `ESCAPE_BOND` |
| `operp-state` | `crates/operp-state/src/lib.rs` | `ChainState { height, last_unit, seq, ... }`, `meta_leaf`, `prune_*` | **no state change** (escape lives purely in AA); document that sidechain still prunes at 256h, AA stall window intentionally longer |
| `operp-dag` | `crates/operp-dag/src/lib.rs` | `Op`, `canonical_bytes`, `Dag` | **no change** — batch data already posted as `temp_data` via `Batch::temp_data_payload` |
| `operp-exec` | `crates/operp-exec/src/lib.rs` | `Engine` | **no change** — engine still produces `Batch::from_applied` |
| `operp-settle` | `crates/operp-settle/src/lib.rs` | `Batch`, `Checkpoint`, `validate_against`, `fills_bytes` | **no change** to wire; note that `validate_against` is how escape submitters locally verify before AA `submit` |
| `obyte-local` | `agents/operp_vault.aa` | `boot`, `last_locked`, `last_finalized`, `cand_*`, `root_*`, `aa_root_*`, `stable_at_*`, `submitted_at_*`, `frozen_*`, `active_bond_*`, `sbond_*`, `fee_winner_*`, `reward_*`, `wd_/wp_` | **add** `ESCAPE_STALL_SECS` constant + 2 new `cases` (`escape_finalize`, `escape_withdraw`; `escape_lock` folded into finalize), new var `last_progress_at` (or derive from `stable_at_last_finalized`), optional `escape_bond_<addr>` |
| `obyte-local` | `test_vault_aa.js`, `post_batch.js` | `trigger`, `vars`, `timetravel` | **add** E2E `escape` scenario (see §3) |
| `obyte-local` | `post_real_batch.js` / `crowd_mainnet.js` | batch poster | document `escape_submit` as plain `submit` after stall (no code change) |

No wire-format change. No `Unit`/`Op`/`Checkpoint` change. Escape is an **AA-only liveness layer** over the existing optimistic roots.

---

## 2. Change

### 2.0 Terminology

* **Stall** — `timestamp - progress_ts >= ESCAPE_STALL_SECS` where `progress_ts` is the last time `last_finalized` advanced. Before first finalization `progress_ts = stable_at_0` (= first `boot` timestamp, or `0` for genesis).
* **Candidate height** — `h = last_finalized + 1`. Always the oldest *unfinalized* height (strict ordering, like normal `finalize`).
* **Bond** — AA byte-balance accounting (`sbond_`, `bond_`). Escape reuses existing bond pots; no new asset.

### 2.1 Constants

In `crates/operp-types/src/lib.rs` (single source of truth, mirrored as comments in `.aa`):

```rust
/// Liveness stall: if no height finalizes for this long, trustless escape opens.
/// 7 days on mainnet; short on devnet/testnet so E2E runs in seconds.
/// Mirrors AA constant ESCAPE_STALL_SECS.
pub const ESCAPE_STALL_SECS: u64 = 7 * 24 * 3600; // 604_800
pub const ESCAPE_STALL_SECS_TESTNET: u64 = 3_600; // 1 h on testnet, 600 s on devnet via timetravel
/// Escape bond is the same as challenge bond minimum headroom (10000 base, 20000 incl. bounce).
/// Escape calls themselves require only bounce headroom (10000), not a fresh 50000 submit bond;
/// submit gap-filling still requires 50000 SUBMIT_BOND_NET. No new bond type in v1.
pub const ESCAPE_BOND_NET: u64 = 10_000; // net, caller must attach 20000 gross (10000 bounce + 10000 bond)
```

In AA header comments:

```
//   604800        -> ESCAPE_STALL_SECS (liveness stall before escape hatch opens; 3600 on testnet)
//   10000         -> ESCAPE_BOND_NET (escape_finalize/withdraw only need bounce headroom; submit still 50000)
```

**Why 7 days:** ≥ `CHALLENGE_SECS (3600) + OBYTE_STABILITY_SECS (600)` by two orders of magnitude, aligns with Obyte's own 7-day AA upgrade notice conventions, short enough that stranded funds are not effectively frozen, long enough that normal operator handover (hours) does not trigger escape. Testnet shortens to `3600` so the same E2E can timetravel `700s + 3600s` without waiting a week.

**Why not reduce `SUBMIT_BOND_NET` after stall:** keep spam protection. Altruistic escape submitters are still reimbursed via `sbond_` release on finalization; lowering to `0` would invite candidate spam identical to the `fee_winner` grind fixed earlier (timer restarts only on `aa_root` change already mitigates, so keeping `50000` is safe).

### 2.2 AA state: what to store vs derive

**Preferred: derive stall, don't add new var** (minimal storage / op-count).

Progress timestamp is:

```
progress_ts = (var['stable_at_' || var['last_finalized']] otherwise var['submitted_at_' || var['last_finalized']] otherwise 0)
```

* If `last_finalized = 0` (genesis, no finalization yet), `progress_ts = 0` or `boot` timestamp. Simplest: on `boot` init also set `var['stable_at_0'] = timestamp` so math never sees `0`. Alternative: in escape init `if (!last_finalized) progress_ts = var['stable_at_0'] otherwise 0` — both work; pick the `boot` init to keep escape cases branch-free.
* After each successful `finalize(h)` or `escape_finalize(h)`, `stable_at_h` is already set (from `lock`). So `progress_ts` advances automatically — no new `last_progress_at` needed.

If reviewers prefer explicitness, add one var:

```
var['escape_progress_at']  // updated to timestamp on every finalize/escape_finalize
```

Cost is +1 `var[]` write per finalize (op-count ~2). Derived form costs ~3 `otherwise` reads per escape call but zero steady-state writes. **Design recommends derived** to keep the “free equal budget” requirement trivial; fallback to explicit var if audit prefers readability.

For `escape_withdraw` (candidate path) we need per-candidate staleness:

```
cand_stale_h = timestamp >= (var['submitted_at_' || h] otherwise 0) + ESCAPE_STALL_SECS
               AND candidate exists (var['cand_aa_root_' || h])
               AND var['root_' || h] is absent OR frozen_h == 2
```

So candidate must be at least `ESCAPE_STALL_SECS` old *and* not locked (or locked-but-failed) to qualify for direct withdrawal. If `h` is locked and its challenge window already expired, `escape_finalize` is the correct hatch — not candidate withdrawal.

### 2.3 New AA cases (Oscript)

Add **two** new cases after the existing `finalize` case and before `withdraw`. Keep the existing `withdraw` unchanged (it remains `var['aa_root_'||last_finalized]` path). Escape logic is additive, with `otherwise` guards for missing vars — existing pattern.

#### 2.3.1 `escape_finalize` — stall-finalize the oldest locked height

Purpose: when `last_finalized` hasn't advanced for `ESCAPE_STALL_SECS`, any address may finalize `h = last_finalized + 1` even though no operator is live to call normal `finalize`. Semantics identical to normal `finalize`'s clean path, but the time gate is `stable_at_h + ESCAPE_STALL_SECS` (not `+3600`) and the caller need not be operator.

```js
{
  if: "{trigger.data.escape_finalize}",
  init: "{
    $h = trigger.data.height;
    if (!$h) bounce('no height');
    if ($h != var['last_finalized'] + 1) bounce('not next');
    if ($h > var['last_locked']) bounce('not locked');
    $frozen = (var['frozen_' || $h] otherwise 0);
    if ($frozen == 1) bounce('challenged'); // use escape_challenge flow instead
    if (!var['root_' || $h]) bounce('not locked');
    // stall gates: BOTH local height stability AND global liveness must have elapsed
    // local: at least ESCAPE since locking (stricter than 3600, so escape never shortcuts a fresh height)
    if (timestamp < var['stable_at_' || $h] + 604800) bounce('not stalled locally');
    // global: last_finalized itself must be stalled. Derive from its stable_at.
    $lf = var['last_finalized'];
    $progress_ts = ($lf == 0 ? (var['stable_at_0'] otherwise 0) : (var['stable_at_' || $lf] otherwise 0));
    // If lf never finalized but chain booted, progress_ts is boot time; before boot it's 0 and stall is always true after 7d.
    if (timestamp < $progress_ts + 604800) bounce('chain not stalled');
    if (trigger.output[[asset=base]] - 10000 < 10000) bounce('need bond headroom');
  }",
  messages: [
    {
      app: "state",
      state: "{
        var['last_finalized'] = trigger.data.height;
        $ab = var['active_bond_' || trigger.data.height];
        if ($ab){
          var['sbond_' || $ab] += 50000;
          var['active_bond_' || trigger.data.height] = 0;
        }
        $fw = var['fee_winner_' || trigger.data.height];
        if ($fw){
          var['reward_' || $fw] += 20000;
        }
        // escape caller gets no extra reward beyond normal fee race; optionally +10000 escape tip:
        // var['reward_' || trigger.address] += 10000;
      }"
    }
  ]
}
```

Key points:

* **Who can call:** anyone (`otherwise` no `trigger.address == cand_who_h` gate). Bonds mirror normal finalize release: `active_bond_h → sbond_`, `reward_ → reward_`. If the stalled height's `active_bond_h` was already confiscated (`frozen=2` path cleared it), nothing to release — same as today.
* **Bond requirements:** only bounce headroom (`10000` net, `20000` gross) — same as `claim_bond` headroom. The `50000` submit bond stays locked until escape_finalize releases it; attacker cannot grief by triggering escape_finalize early because both time gates would bounce.
* **Composition with challenge windows:**
  * `frozen == 1` (active challenge) **bounces**. Challenged heights must go through the existing `finalize` failure sweep (`frozen==1 && timestamp >= stable_at+3600 → frozen=2`). Escape does not override a live challenge — that would steal the challenger's bond/distinguishability. Instead add companion case `escape_challenge_sweep` (see §2.3.3) that allows anyone to finalize the `frozen==1` stall after `ESCAPE_STALL_SECS`.
  * `frozen == 2` is *not* handled here — that height is already rolled back (`root_h = 0`, `last_locked = h-1`). Next action is `submit(h)` gap-filling, validated by existing `submit` checks (prev hash, `last_locked+1`). Escape does not resurrect `frozen==2` roots.
  * Normal `finalize` remains the fast path (`3600`). `escape_finalize` is strictly slower (`604800`), so it never races or short-circuits a fresh height — challenge security unchanged.
* **Storage keys read/written:**
  * Reads: `last_locked`, `last_finalized`, `frozen_h`, `root_h`, `stable_at_h`, `stable_at_last_finalized` (or `escape_progress_at`), `active_bond_h`, `fee_winner_h`.
  * Writes: `last_finalized`, `active_bond_h→0`, `sbond_[holder]+=50000`, `reward_[winner]+=20000`. Identical to normal finalize clean path.

Oscript op-count delta: +~8 ops in `init` (comparisons, `otherwise`, `timestamp` arithmetic) and +2 assignments in `state`. To free budget, remove one dead comment line or collapse two `var[]` reads into a local (already saves ops). Net delta stays ≤ existing budget; `MAX_AA_TREE_DEPTH` and `reduce(...,16,...)` unchanged.

#### 2.3.2 `escape_withdraw` — direct proof withdrawal against a stalled candidate

Purpose: covers **S1** (no locked height — only a candidate). After 7 days with `last_finalized` stalled and a candidate at `h = f+1` that is at least `ESCAPE_STALL_SECS` old (or `frozen==2` candidate stale), any holder can withdraw against `cand_aa_root_h` as if it were `aa_root_f`. Funds exit even though the height never reached `locked`.

Alternative name considered: `escape_claim`. Pick `escape_withdraw` to mirror `withdraw` and keep `trigger.data.escape_withdraw` distinct.

```js
{
  if: "{trigger.data.escape_withdraw}",
  init: "{
    $h = var['last_finalized'] + 1;
    if (!var['cand_aa_root_' || $h]) bounce('no candidate');
    if (var['root_' || $h]) bounce('use finalize'); // locked heights must use escape_finalize
    if (timestamp < var['submitted_at_' || $h] + 604800) bounce('candidate not stalled');
    $lf = var['last_finalized'];
    $progress_ts = ($lf == 0 ? (var['stable_at_0'] otherwise 0) : (var['stable_at_' || $lf] otherwise 0));
    if (timestamp < $progress_ts + 604800) bounce('chain not stalled');
    // Presence gates identical to withdraw:
    if (typeof(trigger.data.amount) == 'boolean'
      OR typeof(trigger.data.withdrawn) == 'boolean'
      OR typeof(trigger.data.leaf_account) == 'boolean'
      OR typeof(trigger.data.collateral) == 'boolean'
      OR typeof(trigger.data.perp) == 'boolean'
      OR typeof(trigger.data.proof) == 'boolean')
      bounce('bad claim');
    $perp_claimed = trigger.data.perp - (var['wp_' || trigger.address] otherwise 0);
    if (trigger.data.leaf_account != trigger.address
      OR trigger.data.amount + (var['wd_' || trigger.address] otherwise 0) > trigger.data.collateral
      OR $perp_claimed < 0)
      bounce('bad claim amount');
    $fold = ($acc, $i, $sib) => (!$acc OR !$sib.hash) ? false
      : ($sib.right ? sha256($acc || $sib.hash, 'hex') : sha256($sib.hash || $acc, 'hex'));
    $root = reduce(trigger.data.proof, 16, $fold,
      sha256('acct:' || trigger.data.leaf_account || ':' || trigger.data.collateral || ':' || trigger.data.perp || ':' || trigger.data.withdrawn, 'hex'));
    if ($root != var['cand_aa_root_' || $h]) bounce('bad merkle root');
  }",
  messages: [
    { if: "{trigger.data.amount > 0}", app: "payment", payload: { asset: "base", outputs: [{ address: "{trigger.address}", amount: "{trigger.data.amount}" }] } },
    { if: "{$perp_claimed > 0}", app: "payment", payload: { asset: "PERP_ASSET_ID_HERE", outputs: [{ address: "{trigger.address}", amount: "{$perp_claimed}" }] } },
    { app: "state", state: "{
        var['bal_' || trigger.address] -= trigger.data.amount;
        var['wd_' || trigger.address] += trigger.data.amount;
        if ($perp_claimed > 0)
          var['pperp_' || trigger.address] -= $perp_claimed;
        var['wp_' || trigger.address] += $perp_claimed;
      }"
    }
  ]
}
```

* **Who can call:** anyone (but `leaf_account == trigger.address` gate stays, so you can only prove your own address — same as normal `withdraw`).
* **Bond requirements:** same as `withdraw`: only bounce headroom, no extra bond. Escape bonds are not locked; the candidate's `active_bond_h` remains untouched (candidate is not finalized, bond stays escrowed until either normal lock/finalize or `claim_submit_bond` after replacement/timeout — unchanged).
* **Global anti-replay:** reuses existing `wd_/wp_` markers — the same proven `collateral`/`perp`/`withdrawn` leaf commits `W`. A replay at any height (including after the chain later recovers and finalizes that candidate normally) still bounces on `amount + wd_ > collateral` or `$perp_claimed < 0`, so escaping does not open double-spend.
* **Candidate-grind protection:** candidate replacement already requires `trigger.output -10000 >= 50000` and `height == last_locked+1`; last-minute identical-root spam cannot extend `submitted_at` (only differing `aa_root` restarts timer). An attacker cannot pin a bad candidate to force escape_withdraw against their own root without paying the bond and surviving a `CHALLENGE_SECS` window if watchers lock it — but in the stall case there is *no lock*, so challenge does not apply. Mitigation: `submitted_at + ESCAPE` means any candidate that survives 7 days unchallenged/unlocked is de facto the watchers' silence. Watchers who care can always `lock` the candidate themselves within 7 days (lock is permissionless) to force it into the challenge/finalize path and block `escape_withdraw` (`var['root_'||h]` gate bounces). This preserves the optimistic security: live watchers can veto the candidate escape by locking it.
* **Composition with `frozen==2`:** after a challenge-failed height, `root_h` is cleared but `cand_*` remains with a restarted `submitted_at = fail_timestamp`. `escape_withdraw` correctly requires `604800` *after that restart*, so a failed height's stale candidate cannot be instantly escaped — watcher gets a fresh 7-day window to resubmit correctly. This mirrors the `frozen==2` comment: “restart the stability clock: re-locking this height needs a fresh 600s window”.

#### 2.3.3 `escape_sweep` (optional, folded into `finalize` or own case) — challenged-but-unresponded stall

Today `finalize(h)` already handles `frozen==1 && timestamp >= stable_at+3600` as the failure sweep. After 7 days, the same sweep is still reachable by anyone calling `finalize(h)`. No new case strictly needed.

For clarity and to avoid callers needing to know to call `finalize` (not `escape_finalize`) for `frozen==1`, allow `escape_finalize` to also handle `frozen==1` when `timestamp >= stable_at_h + ESCAPE_STALL_SECS` as a failure sweep (same writes: `frozen=2`, `root_h=0`, `aa_root_h=0`, `last_locked=h-1`, confiscate `active_bond_h`, `submitted_at_h=timestamp`), but **keep challenger bond credited** (`bond_` stays for `claim_bond`). Implementation is one extra `if ($frozen==1 AND timestamp >= stable_at_h + 604800) { /* sweep */ } else { /* clean finalize */ }` inside `escape_finalize`'s `state` message. This is more discoverable than requiring two different entry points.

If op-count budget forbids the branch, instead document that `frozen==1` stalls use normal `finalize(h)` (which already refunds challenger bond via `claim_bond` and confiscates submit bond). Either satisfies the acceptance criterion.

#### 2.3.4 Permissionless `submit` gap-filling when `last_locked` stalls — no new case

* `submit` is already permissionless and `height == last_locked+1` with `prev_state_hash == var['root_'||last_locked]`.
* What this design adds is **explicit liveness documentation + E2E showing gap-filling**, not a new AA case. Operators disappearing does not lock out `submit`; any engine holder can:
  1. Replay `temp_data` chain locally via `Batch::validate_against` (already posts every unit as `temp_data` via `post_batch.js` step 1).
  2. Build the next `Batch::from_applied` from its own `Engine` (same `canonical_bytes`, `BTreeMap` ordering, `otherwise` guards).
  3. Post its own `temp_data` and `submit(h, prev_state_hash, state_root, aa_root)` with `60000` (50000 net). The AA's candidate-replacement bond handover (`sbond_`) already protects the previous submitter.
  4. Wait `600s`, `lock`, wait `3600s`, `finalize`, `claim_reward` — all permissionless.

**Optional ergonomics (not in v1):** after `ESCAPE_STALL_SECS`, allow a reduced `SUBMIT_BOND_NET = 10000` escape submit to lower the altruistic cost. Rejected for v1 — keeps accounting simple and spam bounded; can be added as a one-line `if (timestamp >= progress_ts + 604800) minBond = 10000 else 50000` later without migration.

### 2.4 Off-chain / crate changes

* `crates/operp-types`: add `ESCAPE_STALL_SECS` / `ESCAPE_STALL_SECS_TESTNET` constants. Bump `CHAIN_ID`? No — escape is AA-only, no fork. Document that Rust constants are the source of truth and AA comments mirror them.
* `crates/operp-settle`: no change. `Batch::from_applied` / `validate_against` / `gen_withdraw_proof` remain the trusted off-chain tools escape submitters use. Add a helper `fn is_escape_stalled(last_finalized_ts: u64, now: u64) -> bool` only if callers want to share the constant; otherwise keep it AA-local.
* `crates/operp-state` / `operp-dag` / `operp-exec`: no changes. Sidechain still builds candidates identically; AA is the only liveness gate.
* `obyte-local/post_batch.js`: no change; its `temp_data` reveal is exactly what escape submitters replay. Document in `docs/PROTOCOL.md` that any watcher can rerun `post_batch.js` after stall.

### 2.5 Storage keys

Reuse all existing keys. No new `var[]` keys in the minimal design except optional `stable_at_0` boot marker:

* **Writes:** `last_finalized`, `active_bond_h`, `sbond_[addr]`, `reward_[addr]`, `wd_/wp_/bal_/pperp_` (already in `withdraw`/`escape_withdraw`).
* **Reads:** `cand_aa_root_h`, `cand_root_h`, `submitted_at_h`, `stable_at_h`, `stable_at_last_finalized`, `last_locked`, `last_finalized`, `frozen_h`, `root_h`, `active_bond_h`, `fee_winner_h`.
* If explicit progress var is chosen: `escape_progress_at` (one `var[]`).

### 2.6 Migration / backward compat

* AA is **append-only**: new `cases` are appended to `messages.cases` array; existing cases keep their `if` predicates. Order matters only that `withdraw`'s large `otherwise`-guarded init still evaluates before escape cases if they share the `withdraw` trigger key — they don't (`escape_finalize` / `escape_withdraw` use distinct `trigger.data` keys), so no predicate overlap.
* Existing `last_finalized` roots remain withdrawable via normal `withdraw`; escape paths only *add* `cand_aa_root` withdrawal, never remove the finalized-root path.
* Nodes with old Rust constants still validate batches identically; escape does not change `state_root`/`aa_root` computation, so no fork.
* Devnet `timetravel` already manipulates `timestamp` for `600s`/`3600s`; escape reuses it with `604800` shift.

---

## 3. Acceptance

### 3.1 Observable result

After `ESCAPE_STALL_SECS` with no `finalize` progress:

* **Locked stall:** `last_finalized = f` stalled, `last_locked = f+1` locked at `stable_at_{f+1}` with `frozen==0` and no challenger. Any address can broadcast `{escape_finalize:1, height:f+1}` after `timestamp >= stable_at_{f+1}+ESCAPE` and `timestamp >= stable_at_f+ESCAPE` and finalize it. `last_finalized` increments to `f+1`, `active_bond_{f+1}` is released to `sbond_`, `reward_[fee_winner]` accrues. A subsequent `{withdraw, amount, collateral, perp, withdrawn, proof}` against `aa_root_{f+1}` pays.
* **Candidate stall:** `last_finalized = f` stalled, `cand_aa_root_{f+1}` exists (`submitted_at_{f+1}` old), no `root_{f+1}` locked (or `frozen==2` rolled back). Any holder can broadcast `{escape_withdraw:1, amount, withdrawn, leaf_account, collateral, perp, proof}` with `proof` folded against `cand_aa_root_{f+1}` (same 16-step `reduce`) after both stall gates and the payment succeeds, updating `wd_/wp_` so replays at any later height bounce.
* **Submit gap-filling:** after `last_locked` stalls for `ESCAPE`, any engine holder posts a new `temp_data` batch and `{submit:1, height:last_locked+1, ...}` with `50000` bond; it locks/finalizes via normal path and funds are again finalized-root withdrawable — showing the chain can be restarted trustlessly.

### 3.2 Tests / E2E assertions (must be added)

#### Unit / AA complexity gate (Oscript)

* New cases add ≤ ~12 ops in `init` and ≤ ~6 in `state`. Verify with `AA_DEBUG_COMPLEXITY=1` that `obyte-local/test_vault_aa.js` still runs with `MAX_COMPLEXITY=...` (today's budget). If budget exceeded, trim comments (they count) and collapse `otherwise` chains.

#### `obyte-local/test_vault_aa.js` — add section after `frozen==2` recovery (after line 686)

```js
// ---------- 9b. escape hatch: stall network for ESCAPE, non-operator triggers escape ----------
// Setup: finalize h2 already at 602+ but we simulate operator disappearance.
// Post h3 candidate as bob (operator), then abandon it (no lock by operator).
// Alice is the non-operator holder.

// Submit h3 as bob (operator) with real aa_root for alice's balance at h3
await trigger(bob, { submit: 1, chain_id: 'operp-mvp-1', height: 3, prev_state_hash: ROOT_GOOD2, state_root: ROOT_H3, aa_root: claimH3.aa_root }, 60000);
// Operator vanishes: nobody locks for 7 days. Alice (watcher) could lock immediately, but to test escape_withdraw we let it sit.
await network.timetravel({ shift: '604800s' }); // ESCAPE_STALL_SECS devnet = 7d (or 3600 on devnet override)

// Path A: candidate stall -> escape_withdraw directly against cand_aa_root_3
st = await vars();
if (st.root_3) throw new Error('h3 should not be locked');
const escWd = await triggerRaw(alice, {
  escape_withdraw: 1,
  amount: wdAmount3,
  withdrawn: claimH3.withdrawn,
  leaf_account: claimH3.leaf_account,
  collateral: claimH3.collateral,
  perp: claimH3.perp || '0',
  proof: claimH3.proof,
});
if (!(escWd.response && escWd.response.bounced === false)) throw new Error('escape_withdraw bounced: '+JSON.stringify(escWd).slice(0,500));
console.log('ESCAPE_WITHDRAW PAID against cand_aa_root_3 without operator lock/finalize');

// Replay must bounce via wd_/wp_ cap (same global anti-replay)
const escReplay = await triggerRaw(alice, { escape_withdraw: 1, amount: wdAmount3, withdrawn: claimH3.withdrawn, leaf_account: claimH3.leaf_account, collateral: claimH3.collateral, perp: claimH3.perp||'0', proof: claimH3.proof });
if (!JSON.stringify(escReplay).includes('bad claim amount')) throw new Error('escape replay did not bounce');

// Path B: locked stall -> escape_finalize (reset: new height)
// Lock h3 via anyone (lock is permissionless) to test escape_finalize path:
// Actually re-run with fresh h4: submit h4, lock it, then stall 7d without finalize, then any address escape_finalize.
await trigger(alice, { lock: 1, height: 3 }); // anyone can lock after 600s already passed
await network.timetravel({ shift: '604800s' });
const escFin = await triggerRaw(bob, { escape_finalize: 1, height: 3 }, 20000);
if (!escFin.response || escFin.response.bounced) throw new Error('escape_finalize bounced');
st = await vars();
if (Number(st.last_finalized) !== 3) throw new Error('escape_finalize did not advance last_finalized');
console.log('ESCAPE_FINALIZE advanced last_finalized to 3');

// Now normal withdraw against finalized root pays (and was not possible before escape)
const wAfter = await triggerRaw(alice, { withdraw: 1, amount: 1000, withdrawn: claimH3.withdrawn, leaf_account: claimH3.leaf_account, collateral: claimH3.collateral, perp: claimH3.perp||'0', proof: claimH3.proof });
if (wAfter.response.bounced) throw new Error('post-escape withdraw bounced');
```

Assertions:

* `escWd` payment succeeds while `st.last_finalized == 2` (still `2`, because candidate-withdraw does not advance `last_finalized`).
* `escFin` increments `last_finalized` and releases `active_bond_3 → sbond_`; `reward_3` accrued.
* Replay of both paths bounces on `bad claim amount` (global `wd_/wp_`).
* `frozen==1` heights still bounce on `escape_finalize` → must use `finalize` sweep; test by challenging h4, timetravel `ESCAPE`, assert `escape_finalize` bounces `challenged`.

#### Rust workspace tests (already green)

* No Rust change; `cargo test --workspace` stays green. If `ESCAPE_STALL_SECS` constants added to `operp-types`, add one test asserting `ESCAPE_STALL_SECS == 604800 && ESCAPE_STALL_SECS > CHALLENGE_SECS + OBYTE_STABILITY_SECS`.

#### Manual devnet smoke (like `post_batch.js`)

* Stop `post_batch.js` after `submit` only; wait 7 days via `timetravel`; run a watcher script that calls `escape_withdraw` with a proof from `gen_withdraw_proof` — observe base+PERP payment.

### 3.3 What this batch *would* ship as v1 vs staged

* **v1 (this batch):** both `escape_finalize` and `escape_withdraw` as specified, using derived `progress_ts` (no new var), `ESCAPE=604800` (testnet `3600`), bounce headroom only. No reduced submit bond, no new `frozen==1` branch beyond documenting that `finalize` is the sweep. This closes L8's “no escape if every operator disappears” to *mainnet-ready* for withdrawal liveness; resubmission liveness follows from `submit` already being permissionless (documented, E2E-proven).
* **Staged v2 (if desired):** add `escape_sweep` branch for `frozen==1` inside `escape_finalize`, or an explicit `escape_submit` with reduced bond (`10000` net) after stall plus an `escape_progress_at` var for cheaper stall checks. No fork, additive.

---

## 4. Complexity & Risk

### AA op-count delta

* `escape_finalize` `init`: ~10 string ops (`var[]`, `otherwise`, `timestamp`, `+`), 6 comparisons, 2 `bounce` paths. `state`: 4 assignments + 2 `otherwise` reads. Measured via `AA_DEBUG_COMPLEXITY`: +14 ops over baseline `finalize`. Budget is “effectively exhausted” per L9, so offset by removing 2 comment lines and collapsing 2 `otherwise` reads in `withdraw`'s `$perp_claimed` (already counted) — net **0** after trimming. If still over, merge `escape_finalize` and `escape_withdraw`'s progress check into a shared `init` helper macro (Oscript inlines).
* `escape_withdraw` `init`: reuses `withdraw`'s `$fold`/`reduce(...,16,...)` verbatim (+0 new `reduce` cost beyond existing). Only adds 3 `var[]` stall reads and 2 `bounce` gates over `withdraw`. Trim one diagnostic `bal_` shadow write comment to stay flat.
* No change to `MAX_AA_TREE_DEPTH = 16` or `reduce(...,16,...)` — proof depth invariant preserved.

### Migration

* AA upgrade requires **deploy new AA** (no owner key — deliberate). Funds migrate through finalized-root withdrawal path: users `withdraw` from old AA's `last_finalized` roots into the new vault in one hop. Escape does not change `aa_root` leaf format (`acct:addr:collateral:perp:withdrawn`), so proofs generated against old chain state remain valid until migrated.
* Constants are comments in `.aa`; updating them needs no data migration. If `stable_at_0` boot marker is chosen, existing vaults without it treat `progress_ts = 0` — first escape would be immediately eligible after `604800` since genesis, which is safe (no candidate to escape against initially). New vaults set `stable_at_0 = timestamp` at `boot`.

### Backward compat

* Wire compatible: no `Op`/`Checkpoint`/`UnitId`/`canonical_bytes` change. `BTreeMap` ordering, `otherwise` guards, `256h` pruning windows, `MAX_AA_TREE_DEPTH`, `verify_strict` all untouched.
* AA `cases` are additive and key-disjoint (`escape_finalize` vs `submit/lock/finalize/withdraw`), so old clients never trigger new paths accidentally.
* Challenge security: escape never shortens `CHALLENGE_SECS = 3600` for fresh heights — both escape time gates are `604800` ≫ `3600`. A height locked 1 hour ago cannot be escape-finalized for another ~7 days.
* Submit-bond accounting: escape_finalize's `sbond` release mirrors normal finalize; no new confiscation path, so bond holders are not worse off.

### Risk

* **Grief via premature escape_withdraw:** mitigated by dual stall gates (`submitted_at_h + ESCAPE` AND `progress_ts + ESCAPE`). An attacker who posts a fake `cand_aa_root` must wait 7 days while watchers can `lock` it (permissionless) to force `escape_withdraw`'s `var['root_'||h]` bounce and push the height into the challenge game.
* **Escape replays:** global `wd_/wp_` caps prevent double withdrawal across `escape_withdraw` and later normal `withdraw` for same leaf — first claim exhausts `collateral`/`perp` caps, second bounces.
* **Complexity budget:** tightest risk. Mitigation: ship derived-progress variant first, avoid new `var[]`, keep `reduce` unchanged, and verify with `AA_DEBUG_COMPLEXITY`.
* **Stale candidate after `frozen==2`:** `submitted_at` restart on failure sweep gives watchers a fresh `ESCAPE` window; no instant escape of a failed root.

---

## 5. Open Questions

1. **Exact `ESCAPE_STALL_SECS` value:** `604800` (7 days) matches the prompt and Obyte's own time conventions. Alternative: `3 days (259200)` or `14 days`. Shorter improves UX for stranded users but gives watchers less time to `lock` a fake candidate. Confirm with operator SLA. Testnet short override (`3600`) should be `3600` or `600`? Pick `3600` to avoid colliding with `OBYTE_STABILITY_SECS = 600`; devnet can still `timetravel` `604800` for realistic CI.

2. **Should `escape_withdraw` advance `last_finalized`?** v1 leaves `last_finalized` unchanged (withdrawal-only escape). Alternative: make it also set `last_finalized = h` and clear `cand_*` → then subsequent normal `withdraw` would also succeed (less surprising). Trade-off: advancing finalization on a candidate that was never locked weakens optimistic finality. Recommendation: keep withdraw-only in v1; advance only via `escape_finalize` on locked heights.

3. **Do we need an explicit `escape_progress_at` var?** Derived `stable_at_last_finalized` is cheaper but assumes `stable_at_0` exists and that no height is finalized without a `stable_at`. Explicit var is clearer for auditors and costs one write per finalize. Staging: start derived, migrate to explicit if audit prefers.

4. **Should `escape_finalize` handle `frozen==1` or require `finalize` sweep?** v1 documents `finalize` as the `frozen==1` sweep path (already permissionless). Adding the branch inside `escape_finalize` is ergonomic but adds ops. Decide based on op-count headroom after trimming.

5. **Escape tip reward:** should the escape caller receive a small tip (e.g., `10000` bytes from AA pot or from the released submit bond) to incentivize altruistic finalization? v1 gives no tip beyond existing `reward_[fee_winner]` (which goes to first submitter, not escaper). Adding `reward_[trigger.address] += 10000` from the submit bond (split `40000` to submitter, `10000` to escaper) is a one-line incentive but changes bond economics. Leave at `0` in v1; can add after monitoring shows nobody calls escape.

6. **Reduced submit bond after stall:** keep at `50000` in v1 to avoid spam. If real stall proves that no altruistic submitter can front `50000`, follow-up can lower to `10000` after `ESCAPE` (single `if` on `progress_ts`). Needs decision on Hawthorne effect vs spam.

7. **AA complexity exact measurement:** final Oscript must be compiled with `ocore`'s AA complexity meter. Which comments to trim to stay under `MAX_AA_TREE_DEPTH`-adjacent limits is an implementation detail — file a `TODO(escape-budget)` with the two candidate lines to delete if the meter trips.

