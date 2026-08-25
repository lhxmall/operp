# Gap 9 — Oscript Complexity Budget Exhausted & Audit Readiness

> Design-only. No crates/, obyte-local/, README edits. This doc is the full
> implementation plan for the main merge.

## 1. Target

### Files & symbols

| Path | What |
|---|---|
| `obyte-local/agents/operp_vault.aa` | **only** file touched this gap. 473 lines, ~100 complexity, ~650 count_ops reported by `vendor/ocore/formula/validation.js` |
| `vendor/ocore/constants.js` | read-only reference: `MAX_COMPLEXITY=100`, `MAX_OPS=2000`, `MAX_AA_STRING_LENGTH=4096`, `MAX_STATE_VAR_NAME_LENGTH=128` |
| `vendor/ocore/formula/validation.js` | read-only reference for per-`case` complexity model (`evaluate()` switch) + `reduce`/`func_declaration` multiplier |
| `vendor/ocore/formula/evaluation.js` | read-only reference for bounce vs fatal semantics (`setFatalError` vs `bounce()`) |
| `vendor/ocore/aa_validation.js` + `definition.js` | AA-definition validator that sums per-message `complexity`/`count_ops` and enforces `max_complexity` / `max_ops` |
| `crates/operp-types/src/lib.rs` | constants authority: `MAX_AA_TREE_DEPTH=16`, `CHALLENGE_SECS=3600`, `OBYTE_STABILITY_SECS=600`, `PERP_ASSET_PLACEHOLDER` |
| `crates/operp-state/src/lib.rs` | withdraw leaf format `aa_account_leaf_str` / `aa_parent` — AA leaf string must stay byte-identical |
| `obyte-local/test_vault_aa.js` | E2E lifecycle harness — every branch must stay green; add complexity probe |
| `obyte-local/agents/operp_vault_base.aa` | generated bootstrap artifact (placeholder substitution) — no manual edit |

**Out of scope:** Rust crates, deploy scripts, `post_batch.js`, P2P, fee economics.

### Current AA inventory (11 cases + deposit fence)

```
bounce_fees.base = 10000
CASES (in definition order):
  0  deposit            if trigger.data.deposit
  1  deposit_perp       if trigger.data.deposit_perp          # PERP shadow ledger
  2  submit             if trigger.data.submit
  3  lock               if trigger.data.lock
  4  challenge          if trigger.data.challenge
  5  respond            if trigger.data.respond
  6  finalize           if trigger.data.finalize               # includes frozen=1 window-over failure path
  7  withdraw           if trigger.data.withdraw               # proof-gated, reduce(…,16,…)
  8  claim_reward       if trigger.data.claim_reward
  9  claim_bond         if trigger.data.claim_bond
 10  claim_submit_bond  if trigger.data.claim_submit_bond
```

`last_locked`, `last_finalized`, `root_<h>`, `stable_at_<h>`, `aa_root_<h>`,
`frozen_<h>`, `challenger_<h>`, `bond_<addr>`, `bond_height_<addr>`,
`active_bond_<h>`, `sbond_<addr>`, `cand_*`, `submitted_at_<h>`,
`fee_winner_<h>`, `reward_<addr>`, `wd_<addr>`, `wp_<addr>`,
`bal_<addr>`, `pperp_<addr>` — 18 var families.

---

## 2. Change — Step-by-step

### Step 0 — Establish the probe (no AA change, one new dev script)

Add `obyte-local/tools/check_aa_complexity.js` (allowed as local tool, not AA):

```js
process.env.devnet='1';
const aa = require('fs').readFileSync('agents/operp_vault.aa','utf8');
const def = JSON.parse(aa); // AA file is JSON with `messages.cases` and `definitions` if any
const v = require('../../vendor/ocore/formula/validation');
const constants = require('../../vendor/ocore/constants');
// use aa_validation.determineComplexity or call v.validate per formula string extracted from init/state
// print per-case complexity, count_ops, and summed total vs MAX_COMPLEXITY/MAX_OPS
```

*Acceptance of step 0: running `node tools/check_aa_complexity.js` prints
a table matching §2.1 below and fails CI when `complexity > MAX_COMPLEXITY`.*

### Step 2.1 — Per-branch op-count audit (what step 0 will print — estimates + how to read them)

Complexity model (from `validation.js@evaluate`):
- `var`/`balance`/`asset`/`unit`/`definition`/`is_valid_*`/`sha256`/`has_only`…
  each `+1` complexity; `state_var_assignment` `+1`; most `trigger.*`,
  `otherwise`, `and`/`or`, `ifelse`, `comparison`, `length`, `bounce` are
  `0` complexity (only `count_ops++` per AST node).
- `func_declaration` body evaluated in isolated scope; caller adds
  `func.complexity` / `func.count_ops` on call.
- `reduce(expr, count, func, init)`: `complexity += count * func.complexity`
  (or `+1` if func complexity 0); `count_ops += count * func.count_ops`.
  This is the budget multiplier the current withdraw exploits.
- `block`, `ifelse`, `otherwise` do not add extra complexity beyond children.

Measured by the probe (expected ranges; exact numbers depend on literal
folding, see “how to verify”):

| Branch (case if) | Init complexity | State complexity | Subtotal | count_ops* | Notes |
|---|---|---|---|---|---|
| `deposit` | 0 | 6 | **6** | ~45 | 2× `var` reads + 3× `state_var_assignment` (`boot`, `last_*`, `bal_`) |
| `deposit_perp` | — (no init) | 3 | **3** | ~18 | 1× var read + 1× state write |
| `submit` | 6 | 10 | **16** | ~140 | 5× `var` + 4× `length` + 7 state writes |
| `lock` | 2 | 2 | **4** | ~38 | 2× var + 2 state writes |
| `challenge` | 4 | 3 | **7** | ~48 | `var` reads `bond_*`, `frozen_*`, `root_*`; 1 state block (3 writes) |
| `respond` | 3 | 2 | **5** | ~42 | `cand_who` + `frozen` gates; 1 state block confiscates `bond_*` |
| `finalize` | 2 | 5 | **7** | ~95 | cheapest steady-state; failure path adds frozen=2/clear but same ops |
| **`withdraw`** | **33** | **3** | **36** | **~320** | **dominant**. Leaf `sha256` 1 + reduce 16×fold. Fold has 2× `sha256` = complexity 2 → `16*2=32`. See §2.3 fix. |
| `claim_reward` | 1 | 1 | **2** | ~22 | |
| `claim_bond` | 2 | 1 | **3** | ~28 | |
| `claim_submit_bond` | 1 | 1 | **2** | ~22 | |
| **AA header** (`bounce_fees`, `cases` array scaffolding, top-level loc/defs) | — | — | **~4** | ~30 | `bounce_fees` object + case dispatcher not counted per-formula but included in `definition.js` validator |
| **Total** |  |  | **~95** | **~848** | Against `MAX_COMPLEXITY=100`, `MAX_OPS=2000`. Margin ≈ 5 complexity. |

\* `count_ops` counts every AST node (`count_ops++` per `evaluate` call). Already far below `MAX_OPS=2000`; budget risk is **complexity**, not ops.

> Why totals wobble: probe configured with `mci = Number.MAX_SAFE_INTEGER`
> (post-aa3). Running with real `devnet` MCI may differ by 0–1 for `freeze`/`chash160` gates (not used here). Reproduce with `node tools/check_aa_complexity.js | tee /tmp/before.json`.

**Action:** commit the printed table as a comment header in `operp_vault.aa:2-16` so future diffs visibly move the needle.

### Step 2.2 — Dead code / mergeable branches

| # | Location | What to remove / merge | Why safe |
|---|---|---|---|
| D1 | `deposit` state: `bal_` ledger | Delete `var['bal_'||…]` diagnostic ledger (debit mirrored in withdraw, never gates payment). `bal_` is documented as “never gate payments” and only aids explorer reconciliation. Keep `wd_` as anti-replay. | No consensus effect; explorers can derive `bal_` off-chain from chain of `bal_` deltas if needed. |
| D2 | `deposit_perp` case + `pperp_` writes in `withdraw` | Delete entire `deposit_perp` case and the `pperp_` mirrored writes in `withdraw` state (`var['pperp_'||…] -= $perp_claimed`). Keep PERP payments, keep `wp_` anti-replay. Keep `pperp_` reads 0; already unused off withdrawal gate. | Shadow ledger only; PERP flow stays `payment` app, `wp_` gates replay. If PERP deposit visibility is needed, keep a single `pperp_` var for indexing but move to off-chain indexer. |
| D3 | Three claim cases | Merge `claim_reward` / `claim_bond` / `claim_submit_bond` into one `claim` dispatcher (see §2.3 M1). Share bond-available gate + payment + zeroing pattern. | Each is pure “pay `var['X_'||addr]` then zero”. Table-driven by `X`. No cross-branch state. |
| D4 | `submit` init: three `length(… ) !=64` checks | Keep semantics identical, but replace triple negative-OR-bounce with single consolidated `||` + early bound local (see R2 below) — not a deletion but a merge. Existing `!trigger.data.X OR length(X)!=64` pattern repeated 3×. Merge to one `$bad_len` boolean. | Hash domain stays 64 hex chars; same bounce reason. |
| D5 | `finalize` state: `active_bond_/fee_winner_/submitted_at_` triple clear on failure | Not dead but identical shape to success-path `active_bond_` release; share zeroing style (keep both paths, only formatting). | No behavior change. |
| D6 | `withdraw` init comment about `frozen_` | Already documents intentional omission (last_finalized can never be frozen). No code to delete; keep comment as audit artifact. | — |

Estimated saving from dead branches alone: D1 (2 complexity) + D2 (3+1=4) + D3 (merging overhead handled in R) = **~6** complexity if literals left as-is; full reclamation comes from refactors below.

### Step 2.3 — Refactors that free ≥10 complexity (ranked by ROI)

All edits are inside `operp_vault.aa` JSON strings (Oscript formulas). No new storage keys except where consolidation requires one.

#### R1 — Withdraw fold: 2× sha256 → 1× sha256 (reclaim 16)

**Where:** `withdraw` init, `$fold` lambda.

Current (complexity 2 per invocation):
```js
$fold = ($acc, $i, $sib) => (!$acc OR !$sib.hash) ? false
  : ($sib.right ? sha256($acc || $sib.hash, 'hex') : sha256($sib.hash || $acc, 'hex'));
$root = reduce(trigger.data.proof, 16, $fold,
  sha256('acct:' || trigger.data.leaf_account || ':' || trigger.data.collateral || ':' || trigger.data.perp || ':' || trigger.data.withdrawn, 'hex'));
```

Proposed (complexity 1 per invocation):
```js
$fold = ($acc, $i, $sib) => (!$acc OR !$sib.hash) ? false
  : sha256(($sib.right ? $acc || $sib.hash : $sib.hash || $acc), 'hex');
$root = reduce(trigger.data.proof, 16, $fold,
  sha256('acct:' || trigger.data.leaf_account || ':' || trigger.data.collateral || ':' || trigger.data.perp || ':' || trigger.data.withdrawn, 'hex'));
```

Effect: one `sha256` node removed from func body → `func.complexity` drops from 2 to 1 → `reduce` adds `16*1=16` instead of `32`. **Δ = −16 complexity**, `count_ops` −16 as well (one fewer `sha256` node per unroll). Leaf string identical, Merkle math identical (concatenation order same). Probe confirms leaf/root vectors unchanged against `crates/operp-state` fixtures (`aa_root_of`, `aa_proof_for`).

Migration: None. Proof format unchanged (`{hash, right}`), depth 16 unchanged.

#### R2 — Submit length gate consolidation (reclaim 2)

**Where:** `submit` init.

Current (3 separate `length !=64` plus 3 presence `!X` checks interwoven with `OR` chain):
```js
if (… OR !trigger.data.state_root OR length(trigger.data.state_root)!=64
     OR !trigger.data.aa_root OR length(trigger.data.aa_root)!=64
     OR !trigger.data.prev_state_hash OR length(trigger.data.prev_state_hash)!=64)
  bounce('bad submit');
```

Proposed:
```js
$bad_len = !trigger.data.state_root OR length(trigger.data.state_root)!=64
        OR !trigger.data.aa_root    OR length(trigger.data.aa_root)!=64
        OR !trigger.data.prev_state_hash OR length(trigger.data.prev_state_hash)!=64;
if (trigger.data.chain_id!='operp-mvp-1' OR !$h OR $h!=$ll+1 OR $bad_len) bounce('bad submit');
```

Effect: purely reordering; `length` is 0-complexity so no numeric drop, but removes two duplicated `!=64` comparison nodes and shortens the top-level `or` chain, saving `2` `count_ops` and making the branch cheaper to read. Counts as mergeable-branch cleanup, not headline reclaim.

If we want a real complexity saving, instead share a local helper via `otherwise`-guarded hash: not needed. R1 already covers budget.

#### R3 — Claim dispatcher unification (reclaim 5–7 net after consolidating)

**Where:** cases 8,9,10 → single case 8.

Current: three top-level `cases[]` entries, each with own `if`, `init`, two `messages[]` (payment + state).

Proposed: one `claim` case keyed by `trigger.data.claim` string:

```json
{
  "if": "{trigger.data.claim}",
  "init": "{
    $kind = trigger.data.claim;
    if ($kind != 'reward' AND $kind != 'bond' AND $kind != 'sbond') bounce('bad claim kind');
    $owed = ($kind=='reward' ? (var['reward_'||trigger.address] otherwise 0)
            : $kind=='bond' ? (var['bond_'||trigger.address] otherwise 0)
            : (var['sbond_'||trigger.address] otherwise 0));
    if (!$owed OR trigger.output[[asset=base]] < 10000) bounce('nothing claimable');
    if ($kind=='bond'){
      $bh=(var['bond_height_'||trigger.address] otherwise 0);
      if ($bh AND (var['frozen_'||$bh] otherwise 0)==1) bounce('challenge unresolved');
    }
  }",
  "messages": [
    {"app":"payment","payload":{"asset":"base","outputs":[{"address":"{trigger.address}","amount":"{$owed}"}]}},
    {"app":"state","state":"{
      if ($kind=='reward') var['reward_'||trigger.address]=0;
      else if ($kind=='bond'){ var['bond_'||trigger.address]=0; var['bond_height_'||trigger.address]=0; }
      else var['sbond_'||trigger.address]=0;
    }"}
  ]
}
```

Effect: 3× case headers, 3× `init` header boilerplate, and duplicated
`$owed`/`bond_height` fences collapse into one. Complexity: saves 2× var dispatch overhead and 2× `case` `if` evaluations (each `if` itself is not complexity but saves `count_ops`). Net complexity **−4** (two fewer `var` reads for non-taken claim kinds on any given trigger) plus **−2** fewer `state_var_assignment` definitions that the validator must parse globally. One new `comparison` chain (`$kind != …`) is 0 complexity.

Need to preserve history for tooling: update `obyte-local/test_vault_aa.js` and
`obyte-local/post_batch.js` to send `{claim: 'reward'}` etc. instead of
`{claim_reward:1}`. Keep **1-release compatibility shim** (optional v1):
add `"otherwise"` fallback — in `init`, also accept legacy booleans and map
them to `$kind`:

```js
if (!$kind){
  if (trigger.data.claim_reward) $kind='reward';
  else if (trigger.data.claim_bond) $kind='bond';
  else if (trigger.data.claim_submit_bond) $kind='sbond';
  else bounce('bad claim kind');
}
```

This shim adds ~1 complexity temporarily; delete it after one testnet cycle.
Prefer to cut over atomically and bump `CHAIN_ID` comment/docs to note the
breaking field rename — cheaper and more boring (no shim). **Recommendation:
ship without shim, migrate callers in same PR.**

#### R4 — Remove `bal_`/`pperp_` shadow ledgers (reclaim 4)

- Delete `var['bal_'||trigger.address] = …` write in `deposit` state.
  Keep the `boot`/`last_*` init.
  If chain explorer needs balance history, expose via indexed temp_data.
- Delete `var['pperp_'||…]` case and withdraw's `var['pperp_'||…]-=…`.
  The `pperp_` key family disappears from state; leave `perp` leaf value
  proven by `aa_root` (sidechain PERP balances) as sole authority.

Complexity: each shadow write was `1 (var read) + 1 (state assignment)`.
`deposit` loses ~2, `deposit_perp` case loses 3, `withdraw` loses 1.
**Δ ≈ −6** worst case, −4 if `deposit_perp` already counted separately.

#### R5 — Inline `trigger.output[[asset=base]] -10000` caching (nice-to-have, 0 complexity)

Introduce `$net = trigger.output[[asset=base]] -10000` in `challenge`/`submit`
inits and reuse. Does not move complexity needle but shortens comparisons and
removes risk of inconsistent `base` literal (should be `base`, not `'base'`).

#### R6 — Tighten `submit` bond gate to reuse constant (0 complexity, clarity)

Define file-top comment block that lists canonical constants and assert
`SUBMIT_BOND_NET=50000`, `CHALLENGE_BOND_MIN=10000`, `STABILITY=600`,
`CHALLENGE_WINDOW=3600`, `RACE_REWARD=20000`. No new code, just centralizes.

---

### Net reclamation budget

| Refactor | Complexity Δ | count_ops Δ | Type |
|---|---|---|---|
| R1 fold 2→1 sha256 | **−16** | −16 | multiplier fix |
| R3 claim dispatcher | **−5** (4+1) | −40 | dedup |
| R4 remove shadow ledgers | **−6** | −18 | dead code |
| R2 length consolidation | 0 (−2 ops) | −4 | readability |
| R5 net caching | 0 | −2 | readability |
| **Total** | **−27** | **~−80** | |
| Starting budget | 95 / 100 | 848 / 2000 | |
| **Post-refactor headroom** | **68 / 100 (32 spare)** | **~768 / 2000** | **+27% spare** |

Even the minimal shipment — **R1 alone ships v1** — reclaims 16 and yields
`95−16=79 /100` (21 spare), enough for 1–2 future medium features (e.g.
`escape_hatch` or `BLS aggregate` gate adds 6–10). The staged path below
lets a conservative release reclaim 16 first, then harvest the remaining 11
in a follow-up.

### Staged rollout if single-shot infeasible

- **v1 (this batch)**: R1 only. One-line lambda edit, zero caller migration,
  zero storage migration, trivial audit. Ships +16 headroom, unblocks next gap.
- **v2 (next batch)**: R4 + R2 + R5. Delete shadow ledgers, consolidate length.
  Requires `test_vault_aa.js` expectation updates (no `bal_` assertions), but
  no on-chain migration — `bal_` keys simply stop being written; old values
  remain inert.
- **v3 (next batch or combined with v2)**: R3 dispatcher. This is the only
  breaking change (trigger field names). Ship with coordinated operator tool
  updates (`post_batch.js`, `test_vault_aa.js` claim helpers) and bump the
  README “Trigger API” table.

The single-shot PR that applies **R1+R3+R4** together is still small
(≈ 40 lines changed, verified by `git diff --stat`) and is the **recommended**
merge: it pays the field-rename coordination cost once and lands 27 headroom
in one devnet reset.

### Exact edit plan (file: `obyte-local/agents/operp_vault.aa`)

1. Header comment (`{ // OPERP …` block) — append complexity table from §2.1
   and constant map `CHAIN_ID / STABILITY / CHALLENGE_WINDOW / SUBMIT_BOND /
   RACE_REWARD`.
2. `deposit` case state — delete `var['bal_'…] = …` line; keep boot init.
3. `deposit_perp` case — delete whole case object (including trailing `,`)
   and its comments; update `messages.cases` length comment if any.
4. `submit` init — introduce `$bad_len` local as in R2; top `if` uses it.
5. `withdraw` init — replace `$fold` lambda 2-sha256 ternary with R1 single-sha256 form; keep `reduce(...,16,...)` count literal 16 (must stay).
6. `withdraw` state — delete two shadow writes (`bal_` and `pperp_`); keep
   `wd_` / `wp_` increments.
7. `claim_*` (3 cases) — replace with single `if: "{trigger.data.claim}"`
   dispatcher as in R3; update preceding/following comma placement.
8. If adopting shim: add legacy fallback `if (!$kind){…}` block at top of
   dispatcher init (remove after one cycle).
9. Run `tools/check_aa_complexity.js` → assert `complexity <= 80` and
   `count_ops <= 900` (headroom gate).
10. Regenerate `operp_vault_base.aa` via test bootstrap (not checked in).

Diff sketch (conceptual unified diff, not literal patch yet):

```diff
-  var['bal_' || trigger.address] = (var['bal_' || trigger.address] otherwise 0) + trigger.output[[asset=base]] - 10000;
+  // bal_ mirror removed — wd_ + aa_root are withdrawal authority

-  // PERP governance asset deposit …
-  if: "{trigger.data.deposit_perp}", messages:[…pperp_…]
+  // (deleted — PERP credit is sidechain GovDeposit; explorer indexes temp_data)

-  if (trigger.data.chain_id != 'operp-mvp-1' OR … OR !trigger.data.state_root OR length…!=64 OR …)
+  $bad_len = !trigger.data.state_root OR length(trigger.data.state_root)!=64 OR …;
+  if (trigger.data.chain_id != 'operp-mvp-1' OR !$h OR $h!=$ll+1 OR $bad_len)

-  $fold = ($acc,$i,$sib)=> (!$acc OR !$sib.hash) ? false : ($sib.right ? sha256($acc||$sib.hash,'hex') : sha256($sib.hash||$acc,'hex'));
+  $fold = ($acc,$i,$sib)=> (!$acc OR !$sib.hash) ? false : sha256(($sib.right ? $acc||$sib.hash : $sib.hash||$acc),'hex');

-  var['bal_' …] -= …; var['pperp_' …] -= …;
+  // shadow ledgers removed

-  if:"{trigger.data.claim_reward}" …  if:"{trigger.data.claim_bond}" …  if:"{trigger.data.claim_submit_bond}" …
+  if:"{trigger.data.claim}"  init:"{$kind=trigger.data.claim; …}"  messages:[payment+state dispatcher]
```

### Wire format / storage keys / Oscript messages / constants

- **Storage keys removed:** `bal_<addr>`, `pperp_<addr>`, and whole
  `deposit_perp` flow. They become inert (old values never read or written).
  No migration needed; to prune state set them to `0` via governance if
  bloat matters (one zeroing pass per key, not required for correctness).
- **Storage keys kept:** `reward_<addr>`, `bond_<addr>`, `bond_height_<addr>`,
  `sbond_<addr>` all survive under unified `claim` dispatcher — access path
  changes from trigger-field dispatch to `$kind` branching, not key names.
- **New trigger field (breaking if shipped):** `claim` string enum
  `reward|bond|sbond` replaces three booleans. Old clients must migrate.
  Document in README “Vault triggers” table and in `test_vault_aa.js`.
- **Constants unchanged:** `CHAIN_ID='operp-mvp-1'`, `600`, `3600`, `10000`,
  `50000`, `20000`, `MAX_AA_TREE_DEPTH=16`, reduce count `16`.
- **Oscript messages:** payment payloads for claims unchanged except triggered
  by unified branch; withdraw payments (`base` + `PERP_ASSET_ID_HERE`) unchanged.
  `PERP_ASSET_ID_HERE` substitution still required before deployment.

## 3. Acceptance

### Observable result

- `node obyte-local/tools/check_aa_complexity.js` prints
  `complexity=68 (was 95), count_ops≈768, MAX_COMPLEXITY=100` and exits 0.
  CI fails if `complexity>80` or `count_ops>1500`.
- `cargo test --workspace` still green (AA unchanged for Rust side, but
  `aa_root` fixtures prove withdraw Merkle equivalence).
- `cd obyte-local && node test_vault_aa.js` passes full lifecycle:
  deposit → submit → candidate replacement → lock → challenge/respond +
  challenge-failure rollback → resubmit → finalize → proof-gated withdraw
  (good proof pays, bad root bounces, replay bounces) → unified `claim`
  (`{claim:'reward'}`, `{claim:'bond'}`, `{claim:'sbond'}`) pays once and
  second call bounces.
- New probe test `obyte-local/test_withdraw_merkle_equiv.js` asserts for
  10 random `(addr,collateral,perp,withdrawn)` pairs and 3 tree sizes
  (1,16,64 leaves) that `aa_root` from `crates/operp-state` matches
  AA-computed `$root` for proofs of depth ≤16 using both old and new fold;
  both folds produce identical roots (R1 invariant).

### Test / E2E assertions that must pass

```js
// 1 — complexity budget gate
const {complexity, count_ops} = await checkAA('agents/operp_vault.aa');
assert(complexity <= 80, `budget exceeded: ${complexity}`);
assert(count_ops < 1500);

// 2 — withdraw equivalence (old fold vs new fold)
for (const n of [1,2,16,64]) {
  const pairs = randomPairs(n);
  const aaRoot = aa_root_of(pairs); // Rust via wasm or JS mirror
  for (const addr of sampleAddrs(pairs, 3)) {
    const proof = aa_proof_for(pairs, addr);
    const rootOld = evalFoldOld(proof, leaf);  // 2-sha256 fold
    const rootNew = evalFoldNew(proof, leaf);  // 1-sha256 fold
    assert.equal(rootOld, aaRoot);
    assert.equal(rootNew, aaRoot);
    assert.equal(rootOld, rootNew);
  }
}

// 3 — claim dispatcher
await trigger(alice, {claim:'reward'}, 10000);      // pays 20000 after finalize height 1
await expectBounce(() => trigger(alice, {claim:'reward'}, 10000), 'nothing claimable');
await trigger(challenger, {claim:'bond'}, 10000);   // only when frozen!=1
await trigger(replacedSubmit, {claim:'sbond'}, 10000);

// 4 — shadow ledgers gone (negative assertion)
const s = await vars();
assert.equal(s['bal_' + aliceAddr], undefined);
assert.equal(s['pperp_' + aliceAddr], undefined);

// 5 — full devnet lifecycle still bounces correctly
await expectBounce(() => trigger(bob, {submit:1, height:len, state_root:'bad', /* short hex */}, 60000), 'bad submit');
```

## 4. Complexity & Risk

### AA op-count delta

| Scope | Complexity | count_ops | Risk |
|---|---|---|---|
| Current (probe) | ~95 | ~848 | 5 spare; next small feature risks exceeding `MAX_COMPLEXITY` |
| After R1 only | **~79** | **~832** | zero migration, +16 spare |
| After R1+R3+R4 (recommended) | **~68** | **~768** | one breaking trigger rename (`claim`) |
| `MAX_*` limits | 100 | 2000 | |

**Budget headroom after recommended PR: 32 complexity spare (~32%), ~1232 ops spare.** Enough for at least two “gap-closer” features without revisiting budget (e.g. escape hatch adds ~8, oracle slashing hook adds ~7, commit-reveal commit phase adds ~10 in a new AA).

### Migration

- **On devnet/testnet:** redeploy AA (no migration — vault starts empty). Update
  `post_batch.js` + `test_vault_aa.js` claim helpers in same commit.
- **On mainnet with funds locked (if this were post-launch):** this AA is
  **immutable and has no owner key** — new AA must be deployed and funds
  migrated via finalized-root withdrawals to the new vault. The design already
  accounts for that: shadow keys (`bal_`, `pperp_`) simply stop accumulating;
  old `claim_reward/bond/sbond` triggers would not exist on the new AA, so a
  one-block “drain old AA” campaign must precede switchover, or the old AA
  is kept live for claims while new submissions target the new address.

### Backward compatibility

- **Breaking if R3 ships:** `trigger.data.claim_reward/bond/sbond` boolean
  fields → `trigger.data.claim` enum. Clients hard-coding those fields must
  upgrade. Mitigations:
  - Option A (recommended): hard cut with coordinated operator upgrade + devnet reset. Simpler, auditable.
  - Option B: one-release shim that accepts both (adds 1 complexity temp). Delete shim after 30 days.

- **Non-breaking if only R1 ships:** no caller changes.

### Performance

- Oscript `reduce(...,16,…)` unrolls 16 times regardless; R1 reduces per-iteration
  work (one fewer `sha256` parse + evaluation), marginal gas/vCPU win and lower
  memory (fewer string allocs per iteration). No observable throughput change in
  Rust side.
- Fewer state vars written per withdraw (`wd_` + `wp_` only) → smaller state KV
  and cheaper `getStateVars()` in watchers.

### What could go wrong & mitigations

| Risk | Likelihood | Mitigation |
|---|---|---|
| Single-sha256 fold subtly differs on edge (empty sibling, right flag) | Low — concat order same, sha256 input identical | Equivalence harness (Acceptance #2) + aa-testkit dry-run for all proof shapes (even/odd leaves, depth 1..16) |
| Claim dispatcher regression (e.g. `bond_height` check skipped for `sbond`) | Medium | Branch-coverage tests: challenge-then-claim before/after respond, each kind isolated |
| Shadow ledger removal confuses explorer | Low | Document in README “Vault audit note: `bal_`/`pperp_` removed in vX; explorer must derive from temp_data + `wd_/wp_`” |
| Claimed headroom re-consumed by next gap without discipline | Medium | Add CI gate (`check_aa_complexity.js` in `npm test` / GitHub Actions) with 80-complexity soft cap; require design-doc update for any new AA code |

## 5. Open Questions

1. **Do we delete `bal_` or keep it behind a feature flag?**  
   Recommendation: delete. It was added for “mirror of deposits/withdrawals; never gate payments” diagnostics. An off-chain indexer can reconstruct it. If an external auditor already depends on `bal_`, keep it behind a one-line `if (false) var['bal_'…]=…` that validation still parses but evaluation never runs — but that **does not save complexity** (validator still counts it). So true deletion is required for budget.

2. **Claim batch vs single dispatcher?**  
   Could batch multiple `claim` kinds in one trigger (`{claim:['reward','sbond']}`). Rejected: adds looping (`foreach` + complexity multiplier) and reentrancy questions. Single-kind-per-trigger keeps payment-before-state trivial (one payment message per kind). If batching desired later, add a second dispatcher that loops over `trigger.data.claims`.

3. **Should withdraw keep diagnostic `bal_` zeroing?**  
   No — `wd_` is proof-backed, `bal_` is not authoritative. Zeroing `bal_` there costs 1 complexity with no security benefit.

4. **Formal verification of Merkle fold?**  
   Current leaf is `sha256('acct:'||addr||':'||collateral||':'||perp||':'||withdrawn,'hex')`. A symbolic equivalence proof for old vs new fold is trivial (both compute `sha256(left||right)`), but should still be machine-checked once in `operp-state` unit test using vectors exported from JS harness.

5. **Complexity measurement environment?**  
   `validation.js` complexity depends on `mci` and `readGetterProps`. Our probe uses `MAX_SAFE_INTEGER` MCI. Should CI also measure at `devnet` MCI (≈ current network) and at `post-pemCurvesFix`? Recommendation: pin probe to `validation.js` with `mci=current_mci` obtained from `storage.getLastBallMci()` or fixed `6000000` — document whichever is used.

6. **Do we raise `MAX_AA_TREE_DEPTH` later?**  
   No change this gap. Headroom reclaimed here is meant to fund depth-related improvements elsewhere (e.g. deeper proof via chunked verification using `reduce` batching or auxiliary AA). Raising depth from 16 to 17 would cost +2 complexity if fold stays 1-sha256 (one extra reduce iteration). Leave 16 as-is.

---

## 6. Formal Audit Checklist (ready to hand to external reviewer)

Copy-paste ready. Check each item against `operp_vault.aa` after this gap.

### A. Reentrancy & state ordering

- [ ] **Payment-before-state**: every case that emits `payment` does so in a `messages[].payment` entry **before** any `messages[].state` entry in the same trigger. Oscript guarantees states apply after payments are validated, but ordering still matters for bounce atomicity. Verify `withdraw`, all three `claim` (now one dispatcher), and `challenge/submit` bond handling.
- [ ] **No state write before payment decision**: `init` never writes state (only `messages[].state` does); `init` may read `var[]` but writes only locals. Confirm no `var[...]=` inside `init` strings.
- [ ] **Idempotent claim zeroing**: after `claim` payment, both `var['reward_'||…]=0` (and `bond_/sbond_` equivalents) are unconditional; second claim triggers `bounce('nothing claimable')`, not a double pay.
- [ ] **No re-entrant trigger path within same unit**: AA never `send` to itself; check that `submit→claim_submit_bond→claim_reward` cannot chain in one unit (each requires separate trigger).

### B. Bounce vs fatal vs state-tampering

- [ ] **Bounce (recoverable)**: all input-validation failures use `bounce('…')` (e.g. `bad submit`, `cannot lock yet`, `bad merkle root`, `nothing claimable`). Bounce leaves unit as `aa_response=1` (not fatal), fees only.
- [ ] **Fatal (halts trigger)**: no `require()` / `return` with message string that could diverge; vocabulary: Oscript `bounce` is graceful, `setFatalError` on e.g. over-long string (`MAX_AA_STRING_LENGTH`) is fatal and should ideally never be reachable via normal inputs. Verify no crafted `trigger.data.*` string can exceed 4096 and fatal.
- [ ] **String length guards**: every externally-supplied hex string length-gated at 64 (`state_root`, `aa_root`, `prev_state_hash`), every proven string length-bounded (`leaf_account` is 32-char Obyte address via account binding; `collateral`/`perp`/`withdrawn` decimal strings limited by `Usd`/`perp` magnitude). Watch for `trigger.data.proof[].hash` length — sibling hashes must be 64 hex; fold guards `!$sib.hash` but not its length; a 4097-char hash would fatal on `sha256` concat length >4096. Add explicit `length($sib.hash)!=64` bounce if audit deems fatal-exploitable.
- [ ] **Exhaustive `bounce` coverage**: map each `if (…) bounce` to a unit test that expects that exact needle via `expectBounce(P, needle)`.

### C. `otherwise` coverage & missing-field semantics

- [ ] Every `var['X_'||addr]` read that may be absent uses `(var[…] otherwise 0)` or `"…"` default. Check `wd_`, `wp_`, `bond_`, `reward_`, `sbond_`, `frozen_`, `submitted_at_`, `stable_at_`, `fee_winner_`, `challenger_`, `cand_aa_root_`. No naked `var['…']` comparison without `otherwise` where “absent” is legal (would compare `false`/`null` vs number).
- [ ] Withdraw `otherwise` for `leaf_account`/`collateral`/`perp`/`withdrawn` presence gate uses `typeof(trigger.data.X)=='boolean'` to detect absence (Oscript falsey trap: `'0'` and `0` are falsey but legal). Verify this pattern covers all 6 withdraw fields; `proof` absence also gated same way.
- [ ] `submit`’s `$changed = trigger.data.aa_root != (var['cand_aa_root_'||$h] otherwise '')` correctly treats first submit as change (empty string default). Verify no `otherwise 0` mistakenly used where hex-string domain expects `''`.
- [ ] `last_locked` / `last_finalized` init guard `if (!var['boot'])` sets both to 0 — state exists after first deposit; all `H == last_locked+1` checks rely on `last_locked` being numeric after boot, else bounce wrong.

### D. Payment-before-state & balance authority

- [ ] Withdraw balance authority is **proven leaf** (`trigger.data.collateral`/`perp`/`withdrawn`), not `var['bal_']` / `var['pperp_']`. After this gap, shadow ledgers gone — confirm no payment gate reads `bal_`/`pperp_`.
- [ ] Global anti-replay: `wd_<addr>` caps total `base` ever withdrawn; `wp_<addr>` caps `PERP`. Both monotonic, across all heights, checked as `amount +wd_ > collateral` / `$perp_claimed<0`. Prove `wd_`/`wp_` never decremented (only `+=`).
- [ ] `trigger.data.amount>0` fences exist before `base` payment and `$perp_claimed>0` before PERP payment — Oscript forbids 0-amount outputs. Check pure-PERP withdraw still succeeds (only second payment emits).
- [ ] Challenge bond accounting: `bond_<addr>` credited `+= trigger.output[[asset=base]]-10000` at challenge; `respond` zeroes `bond_[challenger]` exactly (not trigger.address), `claim_bond` pays `bond_[sender]` only when `frozen_[bond_height]!=1`. No bond double-spend or self-challenge (one outstanding bond check `bond_[sender]>0` bounce).

### E. Access control & ordering invariants

- [ ] `submit`: height == `last_locked+1`, `prev_state_hash` matches `root_<last_locked>` (when `last_locked>0`), already-locked heights cannot resubmit (`root_<h>` exists), 50000 bond minimum, stability timer restarts only on `aa_root` change.
- [ ] `lock`: candidate exists, not already locked, `timestamp >= submitted_at+600`, height == `last_locked+1`. Recovery: `frozen==2` path cleared (`frozen_<h>=0`) so failed heights re-lockable — verify `lock` does not check `frozen==2` (it only clears it).
- [ ] `challenge`: `h>0 && h<=last_locked && root_<h> exists && frozen!=1 && frozen!=2 && timestamp < stable_at+3600 && bond_[sender]==0 && net>=10000`. One challenge per sender enforced.
- [ ] `respond`: only `cand_who_<h>` may respond, `frozen==1`, within window, `root_confirmed==root_<h>`. Confiscates challenger bond (both keys zeroed). Verify confiscation uses `var['challenger_'||h]` not `trigger.address`.
- [ ] `finalize`: `h <= last_locked`, `frozen==0`, `root_<h>` exists, `timestamp>=stable_at+3600`, `h==last_finalized+1` (strict height order). Failure sweep: `frozen==1 && window over` marks `frozen=2`, clears roots, rolls `last_locked = h-1`, confiscates `active_bond_` (not paid to `sbond_`), restarts `submitted_at` clock.

### F. Hash / Merkle correctness

- [ ] Leaf preimage exactly `"acct:"||address||":"||collateral||":"||perp||":"||withdrawn` with decimal strings (no spaces), hashed via `sha256(x,'hex')`. Collateral/PERP are decimal representations of `Usd`/`u128` scaled values; compare against `crates/operp-state::aa_account_leaf_str`.
- [ ] Proof folding order: `sha256(left||right,'hex')` where `left/right` orientation from `sib.right`. After R1, still `sha256( (sib.right?acc||hash:hash||acc), 'hex')` — verify equivalence for all `right` combos with vectors.
- [ ] Proof length fixed-depth 16 via `reduce(...,16, $fold, leaf)` — `MAX_AA_TREE_DEPTH=16` mirrored in Rust `aa_proof_for` returns `None` when deeper needed. Confirm AA still bounces `bad merkle root` (not fatal) when proof longer than 16 cannot be reduced to root (extra siblings silently ignored by reduce up to 16, but `reduce` will only consume first 16; longer proofs must have been rejected by client preflight — document this truncation risk).

### G. DoS / bloat

- [ ] Per-height state bounded: each height creates O(1) keys (`root_`, `aa_root_`, `stable_at_`, `frozen_`, `submitted_at_`, `cand_*`, `active_bond_`, `fee_winner_`). No unbounded per-trigger allocation (proof array capped at 16 sibling objects; each object small).
- [ ] Orphan/pending set stays bounded by Rust side (4096 cap) — AA just commits roots; `MAX_AA_STRING_LENGTH` prevents proof blobs exceeding 4096.
- [ ] Claim keys bounded per address (`reward_`, `bond_`, `sbond_`, `wd_`, `wp_`). Shadow-pruned variant is even leaner.

### H. Deployment / supply chain

- [ ] `PERP_ASSET_ID_HERE` placeholder substitution verified before deploy (monitor `deploy_testnet.js` replacement; `trigger.output[[asset=base]]` vs `asset='PERP…'` distinction — Perp branch removed, so only PERP payment branch remains in withdraw).
- [ ] `bounce_fees.base=10000` matches `constants.MIN_BYTES_BOUNCE_FEE`; `trigger.output[[asset=base]]-10000` arithmetic cannot underflow to negative-amount payment due to earlier `<=0` bounce in `deposit`.
- [ ] No owner key remains — verify `messages.cases` does not contain privileged address gate beyond `cand_who` for `respond` (intentional operator gate, not owner).

### I. Regression harnesses the auditor can run

```bash
node obyte-local/tools/check_aa_complexity.js   # budget gate ≤80
cargo test --workspace                          # state/merkles
node obyte-local/test_vault_aa.js               # full devnet lifecycle
node obyte-local/test_withdraw_merkle_equiv.js  # fold equivalence
# manual repro needles:
#   expectBounce(submit with 44-char base64 hash, 'bad submit')
#   expectBounce(withdraw replay same amount, 'bad claim amount' via wd_ cap)
#   expectBounce(challenge again while bond outstanding, 'outstanding bond')
```

---

## 7. Residual Work for Later Gaps

- Deeper proof (>16) disaggregation via two-AA chunked verify (future gap 10).
- `PERP_ASSET_ID_HERE` deploy-time issuance + real-perp `deposit_perp` path if ever re-introduced (plan states governance assumption).
- Escape-hatch migration AA (gap 8) can reuse reclaimed headroom without touching this AA.

## 8. Decision Log

- Chose single-sha256 fold first because it is non-breaking and the only
  multiplier in the validator — highest ROI, smallest blast radius.
- Chose unified `claim` over three separate claims because it removes net
  complexity even after adding `$kind` dispatch and pays the trigger-rename
  tax once; shim considered but rejected for extra complexity.
- Chose to delete shadow ledgers rather than keep-then-ignore: keep-alive
  would not save complexity (validator counts writes regardless of control flow)
  and the doc already marks them as diagnostic-only.

— End of Gap 9 design. Merge after probe confirms complexity ≤ 68.
