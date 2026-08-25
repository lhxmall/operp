# Mainnet Gap 7 — Burned PERP Stranded / Auditable Burn Accounting

> **Design-only**. No code edits in this batch. Parent merges after all 11 designs land.
> Owner: `DesignBurnView` — Gap 7: *Burned PERP stays stranded in the vault AA* (README L7).

---

## 1. Target

### Exact files / symbols touched in implementation

| File | Symbols / vars | Role |
|------|---------------|------|
| `crates/operp-state/src/lib.rs` | `ChainState::perp_burned: u128` (existing), `ChainState::perp_supply: u128`, `ChainState::perp_balances`, `ChainState::burn_perp()` *(new helper)*, `meta_leaf()` | Cumulative counter + helper extraction; already committed in leaf |
| `crates/operp-types/src/lib.rs` | `CREATE_MARKET_FEE_PERP: u128 = 10_000`, `PERP_ASSET`, `PERP_ASSET_PLACEHOLDER` | Constants unchanged; docs added |
| `crates/operp-exec/src/lib.rs` | `Engine::create_market()` (burn site), future burn sites (`slash_oracle`, `confiscate` — stubs), tests `create_market_burns_exact_fee_and_allocates_ids` | Unify burn path through helper |
| `crates/operp-dag/src/lib.rs` | `Op::CreateMarket` | No wire change (canonical_bytes untouched); comment clarifies burn semantics |
| `crates/operp-settle/src/lib.rs` | `Checkpoint` struct — optional `perp_burned: u128` audit field (or derived via `state.perp_burned`), `Batch::from_applied`, `Batch::validate_against`, `TempDataPayload` | Expose counter for off-chain audit; no consensus break if optional |
| `obyte-local/agents/operp_vault.aa` | State vars `var['perp_burned']` (global), `var['perp_burned_'||h]` (per-height), `var['cand_perp_burned_'||h]` (candidate), messages `{submit}`, `{finalize}`, `{get_burn}`, `{sweep_burn}` *(v2 optional)*, shadow vars `bal_`, `pperp_` untouched | AA-side queryable counter + optional sweep |
| `obyte-local/test_vault_aa.js` | `makePerpEngine()` shim, `post_batch.js` submit flow | E2E assertion `cumulative_burn == 10k` + view |
| `docs/PROTOCOL.md`, `docs/MECHANISMS.md`, `README.md` | Auditor section “vault holdings − perp_supply = perp_burned” | Explicit audit recipe |

**Non-goals:** no actual PERP token movement in v1; no new crypto; no canonical_bytes or BTreeMap ordering changes; no change to `MAX_AA_TREE_DEPTH` / 256-height windows / `otherwise` guard style.

---

## 2. Change — Step by Step

### 2.1 Rust — `crates/operp-state`

**Step 1 — Canonicalize the counter name.**

- Keep `perp_burned: u128` as canonical. Add alias doc comment `/// Cumulative PERP burned — also referred to as cumulative_burn / burned_PERP in AA/docs.` No rename to avoid churn. Optionally expose `pub fn cumulative_burn(&self) -> u128 { self.perp_burned }` as ergonomic getter.

**Step 2 — Extract `burn_perp` helper (boring, single call-site today, N tomorrow).**

```rust
impl ChainState {
    /// Debit `amount` from `who`'s PERP balance, shrink `perp_supply`,
    /// grow `perp_burned`. Checked; returns Err(InsufficientPerp) if bal < amount.
    /// Conservation: perp_balances + perp_burned invariant preserved w.r.t. deposits+withdrawals.
    pub fn burn_perp(&mut self, who: AccountId, amount: u128) -> Result<(), StateError> {
        let bal = self.perp_balances.get(&who).copied().unwrap_or(0);
        if bal < amount { return Err(StateError::InsufficientPerp); }
        self.perp_balances.insert(who, bal - amount);
        // perp_supply is Σ deposits − withdrawals − burns; burn shrinks it.
        self.perp_supply = self.perp_supply.checked_sub(amount).expect("supply >= burn");
        self.perp_burned = self.perp_burned.checked_add(amount).expect("burn fits u128");
        Ok(())
    }
}
```

- `meta_leaf()` already commits `perp_burned` (line `b.extend_from_slice(&state.perp_burned.to_le_bytes())` + next cursors). No change needed; add comment linking AA var.
- `ChainState::new()` already zeroes `perp_burned`. Keep.
- Storage keys: in-memory `BTreeMap`s — no disk keys; commitment via meta_leaf ensures replay binding.

### 2.2 Rust — `crates/operp-exec`

**Step 3 — Route `create_market` through helper.**

Before (current `lib.rs:699-703`):
```rust
self.state.perp_balances.insert(creator, bal - CREATE_MARKET_FEE_PERP);
self.state.perp_supply -= CREATE_MARKET_FEE_PERP;
self.state.perp_burned += CREATE_MARKET_FEE_PERP;
```

After:
```rust
self.state.burn_perp(creator, CREATE_MARKET_FEE_PERP).map_err(map_state)?;
```

- Preserve existing guards: `bal < CREATE_MARKET_FEE_PERP => Insufficient`, `tick_size==0 || bps==0 || >10_000 => Risk` stay before burn.
- `next_market_id` bump + `markets.insert` unchanged.
- Future burn sites (oracle slashing, governance confiscation) MUST call `burn_perp` — add `// BURN_SITE` comment convention.

**Step 4 — No wire-format change.** `Op::CreateMarket` canonical_bytes stays `parents || op_tag || ...` via `canonical_bytes()` — adding helper does not alter serialized form.

### 2.3 Rust — `crates/operp-settle`

**Step 5 — Expose burn counter for audit (non-consensus optional field).**

Option A (minimal, preferred for v1): *derive, don't serialize.* `Checkpoint` stays byte-identical; auditors derive `perp_burned` by replaying batch or reading `engine.state.perp_burned` after `from_applied`. `temp_data_payload` already includes the full `units` array, so replay can recompute burn total. Add helper:

```rust
impl Batch {
    pub fn perp_burned(&self) -> u128 { /* after from_applied, engine.state.perp_burned */ }
}
```

Option B (explicit, if AA needs to read it without replay): add `pub perp_burned: u128` to `Checkpoint`, include in `temp_data_payload` JSON, and assert in `validate_against` that `replay.state.perp_burned == self.checkpoint.perp_burned`. This is a *hard fork* of the checkpoint hash — only choose if AA submit must carry `perp_burned`. Recommendation: **ship Option A for v1** (no fork), add Option B later if sweep needs height-bound burn proof.

### 2.4 Obyte Vault AA — `obyte-local/agents/operp_vault.aa`

AA is at complexity budget limit (README L9). Every new op must be offset by simplification elsewhere, or be trivial. Burn accounting can be added with ~4 string ops + 1 integer var per height (<30 Oscript ops).

**Step 6 — Global and per-height burn vars.**

- `var['perp_burned']` — global cumulative burn, queryable. Alias `var['burned_PERP']` for assignment's naming (set both together to avoid confusion).
- `var['perp_burned_' || h]` — snapshot at finalization of `h` (audit history).
- `var['cand_perp_burned_' || h]` — candidate burn during submit window (replaceable, like `cand_aa_root_`).

**Step 7 — Extend `submit` to carry `perp_burned` (optional, backward compatible).**

In `trigger.data.submit` init block, after existing checks:
```
$cand_burn = trigger.data.perp_burned otherwise 0; // decimal string, 0 if absent (pre-upgrade batches)
if (typeof($cand_burn) == 'boolean') $cand_burn = 0;
if ($cand_burn != (var['cand_perp_burned_' || $h] otherwise 0)) $changed = 1; // extend timer-reset
```

State message then:
```
var['cand_perp_burned_' || trigger.data.height] = $cand_burn;
```

For backward compat, `perp_burned` is `otherwise 0` — old batches submit `0` and still finalize. New operator binaries send the true `engine.state.perp_burned` (decimal string). No bounce on mismatch in v1; mismatch is advisory. In v2, enforce `cand_perp_burned` monotonically non-decreasing vs `var['perp_burned']`.

**Step 8 — Promote at `finalize` (clean path).**

Inside the `else { // clean window` branch of `finalize` state message, after `sbond`/`reward`:
```
$cb = (var['cand_perp_burned_' || trigger.data.height] otherwise 0);
var['perp_burned'] = $cb;
var['burned_PERP'] = $cb; // alias per spec
var['perp_burned_' || trigger.data.height] = $cb;
```

On the `$failed` (frozen==1) branch, clear candidate: `var['cand_perp_burned_' || h] = 0;`.

**Step 9 — View function (explicit query).**

Add new case before final `claim_*` cases:

```
{
  if: "{trigger.data.get_burn}",
  init: "{ $b = (var['perp_burned'] otherwise 0); }",
  messages: [
    { app: "state", state: "{ var['burn_query_' || trigger.address] = $b; }" }
  ]
}
```

- This is *observable* via the AA response unit's stateVars diff + bounce content. Alternatively, a pure `bounce('burn:' || $b)` works, but state diff is easier for an E2E test to assert without parsing bounce strings. Keep `otherwise 0` guard (existing pattern).
- Budget: 1 `otherwise` + 1 concat + 1 state write = ~5 ops.
- Alternative zero-cost view: auditors can just call the Obyte node API `getAAStateVars(aa_address)` and read `var['perp_burned']` without a trigger. The `{get_burn}` trigger is convenience / explicit per assignment's “view function” phrasing; it can be omitted if AA budget is tight and docs point to the API. Recommendation: **ship the state var; `{get_burn}` is optional sugar**.

**Step 10 — Optional `sweep_burn` (v2, NOT v1).**

Assignment says “optional `sweep_burn` governance proposal that provably burns AA-held PERP to unspendable or reports holdings−supply = burn invariant. No token movement needed for v1.”

- v1: no sweep. Document invariant `vault_perp_holdings - perp_supply == perp_burned` as auditor check (see §2.5).
- v2 design (staged, no v1 code):
  - Define burn sink address: `PERP_BURN_ADDRESS = 'BURN'.padEnd(32,'0')` or `PERP_ASSET` issuer's `define` with burn capability. Obyte assets have no native burn opcode; “burn” = send to an unspendable address (e.g., all-zero) or issuer reclaim if PERP is capped. Research Obyte asset `is_private`/`is_transferrable` flags before committing.
  - New trigger `{sweep_burn: 1}` callable by anyone post-finalize; computes `holdings = trigger.output[[asset='PERP_ASSET_ID_HERE']]`? No — AA balance not readable in Oscript except via `var`. So sweep needs an oracle: operator posts `perp_burned` snapshot (already finalized) and the node API provides holdings externally. The AA cannot atomically read its own asset balance in Oscript. Therefore **sweep cannot be trustless inside the AA alone** — it requires an external attestation or a governance proposal that voters approve after off-chain audit. Model it as a `CreateProposal { key: SweepBurn, value: amount }` that, on passing, authorizes the AA to send `amount` to burn address. The AA case then is permissioned by proposal finalization, not by self-knowledge.
  - Consequence: v1 explicitly defers sweep; the AA stays over-collateralized by design. The “report” variant (`holdings − perp_supply == perp_burned`) is the auditable primitive.

### 2.5 Docs — Auditor Recipe

Add to `README.md`, `docs/PROTOCOL.md`, `docs/MECHANISMS.md` a new subsection “Burn Audit”:

```
Auditor invariant (at any finalized height h):
  vault_perp_holdings(h) == Σ GovDeposit PERP to vault AA
                           − Σ GovWithdraw PERP claimed from vault AA
  // vault_perp_holdings read via Obyte API: getBalances([aa_address])[PERP_ASSET]
  assert vault_perp_holdings - chainState.perp_supply == chainState.perp_burned
  // chainState.perp_supply / perp_burned from sidechain meta_leaf or AA var['perp_burned']
  // AA var readable via getAAStateVars(aa_address)['perp_burned']
If equality fails, either a deposit was unbacked (operator minted fake GovDeposit),
a withdrawal proof double-spent, or a burn site forgot to update perp_burned.
```

Add alias note: `burned_PERP == perp_burned == cumulative_burn`.

---

## 3. APIs, Storage Keys, Constants, Oscript Messages

### Rust APIs

| API | Signature | Notes |
|-----|-----------|-------|
| `ChainState::burn_perp` | `fn burn_perp(&mut self, who: AccountId, amount: u128) -> Result<(), StateError>` | Single burn entry point; checked |
| `ChainState::cumulative_burn` | `fn cumulative_burn(&self) -> u128` | Alias getter |
| `Engine::create_market` | unchanged sig, internals call `burn_perp` | |
| `Batch::perp_burned` | `fn perp_burned(&self) -> u128` (if Option A) | Derived |

### Storage Keys

- Rust: `ChainState.perp_burned` (u128) + `perp_supply` + `perp_balances` (all committed via `meta_leaf` + `account_leaf` W). No new persistent keys.
- AA: `var['perp_burned']`, `var['burned_PERP']` (mirror), `var['perp_burned_'||h]`, `var['cand_perp_burned_'||h]`. All `otherwise 0` when absent — follows existing `bal_`/`pperp_`/`sbond_` pattern.

### Oscript Messages (AA)

| Trigger | Required data | Validation | Effect |
|---------|---------------|------------|--------|
| `{submit:1, height:h, state_root:64hex, aa_root:64hex, prev_state_hash:64hex, chain_id:'operp-mvp-1', perp_burned:"<decimal string>"}` | `perp_burned` optional (new) | `otherwise 0` default; stored as candidate | `cand_perp_burned_<h> = perp_burned` |
| `{finalize:1, height:h}` | — | existing stability + frozen checks | `perp_burned = cand_perp_burned_<h>`; also `burned_PERP` and `perp_burned_<h>` |
| `{get_burn:1}` | — | none | bounce/state diff exposes `perp_burned` |
| `{sweep_burn:1, amount:"..."}` | v2 only, governance-gated | proposal passing check | send `amount` PERP to burn sink |

### Constants

- `CREATE_MARKET_FEE_PERP = 10_000` (unchanged)
- No new numeric constants in v1. Future `PERP_BURN_ADDRESS` constant deferred to v2.
- Wire format: `canonical_bytes` unchanged; `BTreeMap` ordering preserved; `price.to_le_bytes` style for burn amount stays decimal string in AA (Oscript has no u128) — same pattern as `bal_`/`pperp_` amounts.

---

## 4. Acceptance

### Observable Result

After a market creation fee of 10k PERP is burned:

- Sidechain: `chainState.perp_burned == 10_000`, `chainState.cumulative_burn() == 10_000`, `meta_leaf` commits it, `state_root` changes, and `perp_supply` is exactly 10k less than Σ deposits − Σ withdrawals.
- AA: `var['perp_burned'] == 10_000` (and alias `var['burned_PERP'] == 10_000`) queryable via `getAAStateVars` or `{get_burn}` trigger.
- Audit: `vault_perp_holdings - perp_supply == perp_burned` holds at every finalized height.

### Test / E2E Assertions

#### Rust unit test (extend `create_market_burns_exact_fee_and_allocates_ids`)

```rust
#[test]
fn cumulative_burn_view_after_market_creation() {
    let mut eng = Engine::new();
    allow_all(&mut eng); // inject deposits_allowed for GovDeposit
    let g = genesis_id();
    let d = gov_dep(vec![g], &sk(1), CREATE_MARKET_FEE_PERP, 7);
    eng.ingest(d).unwrap();
    assert_eq!(eng.state.perp_burned, 0);
    assert_eq!(eng.state.cumulative_burn(), 0);
    assert_eq!(eng.state.perp_supply, CREATE_MARKET_FEE_PERP);

    let cm = list_market(vec![unit_id(&d)], &sk(1));
    eng.ingest(cm).unwrap();

    // Core invariant
    assert_eq!(eng.state.perp_burned, CREATE_MARKET_FEE_PERP);
    assert_eq!(eng.state.cumulative_burn(), CREATE_MARKET_FEE_PERP);
    assert_eq!(eng.state.perp_supply, 0);
    // meta_leaf commits burn, so state_root is burn-sensitive
    let root_with_burn = eng.state.state_root();
    // Audit identity: holdings would be CREATE_MARKET_FEE_PERP on AA,
    // supply 0, so holdings - supply == burned
    assert_eq!(CREATE_MARKET_FEE_PERP - eng.state.perp_supply, eng.state.perp_burned);
}
```

#### AA E2E (extend `obyte-local/test_vault_aa.js` section 10)

After the existing `MARKET CREATED (id=2)` assertion:

```js
// New assertion: sidechain counter
if (eng.perp_burned !== 10000n) throw new Error("cumulative_burn != 10k");
if (eng.perp_supply !== 0n) throw new Error("supply not shrunk");

// Post batch + submit carrying perp_burned, lock, finalize, then query AA
await postBatchWithBurn(batch, "10000"); // submit.data.perp_burned = "10000"
await lock(height); await finalize(height);
const vars = await getAAStateVars(aaAddress);
if (vars.perp_burned !== "10000" && vars.perp_burned !== 10000) throw new Error("AA burned_PERP view mismatch");
if (vars.burned_PERP !== vars.perp_burned) throw new Error("burned_PERP alias mismatch");

// Auditor check: vault PERP holdings - perp_supply == burned
const balances = await getBalances(aaAddress);
const holdings = BigInt(balances[PERP_ASSET] || 0);
const perpSupply = await getSidechainSupply(height); // or eng.perp_supply
if (holdings - perpSupply !== BigInt(vars.perp_burned)) throw new Error("audit invariant failed");

// Explicit view trigger alternative
const burnQueryUnit = await triggerAA({ get_burn: 1 });
const diff = await getAAResponseVars(burnQueryUnit);
if (BigInt(diff.burn_query) !== 10000n) throw new Error("get_burn view failed");
```

- For pre-upgrade batches, `submit` without `perp_burned` must still finalize and `vars.perp_burned` stays `0` — asserts backward compat.
- Repeated `get_burn` triggers must be idempotent and not mutate `perp_burned`.

---

## 5. Complexity & Risk

### AA Op-Count Delta

| Added code | Est. ops |
|------------|----------|
| `submit` candidate burn store (`otherwise`, `!=`, concat) | ~8 |
| `finalize` promotion (`otherwise`, 3 stores) | ~6 |
| `{get_burn}` view (1 state write) | ~5 |
| **Total v1** | **~19 ops** |

Budget context: the vault AA is “effectively exhausted” (README L9) but recent hardening freed headroom by removing consolation prizes. 19 ops is well within the margin recovered. If budget is tighter, drop `{get_burn}` and rely on `getAAStateVars` (saves 5 ops) → **~14 ops net**. A compensating simplification (e.g., collapsing a comment-only branch) easily offsets this.

### Migration & Backward Compatibility

- **Rust state:** `perp_burned` already exists — no migration, no serialization bump. Existing DBs/snapshots replay identically because `burn_perp` is semantically identical to the three-line inline burn. `meta_leaf` already commits `perp_burned`, so old checkpoints validate.
- **Checkpoint wire:** Option A (preferred) is wire-compatible. Option B (explicit field) would fork checkpoints — not needed for v1.
- **AA:** New vars default to `otherwise 0`. Old `submit` payloads without `perp_burned` finalize with burn=0 (correct for history where no burn occurred). New submits with non-zero burn are accepted by old AA code (unknown trigger fields ignored in Oscript) — but the var will not be set, so upgrade is **forward compatible**; after AA redeploy the var catches up on next finalized height. To avoid a gap, operator SHOULD re-submit the latest height after AA upgrade.
- **Dashboards/indexers:** Must switch from computing `holdings − supply` ad-hoc to reading `var['perp_burned']` as canonical, while still asserting the derived invariant.
- **No p2p / gossip impact:** Burn counter is internal state, not a unit field (except optional submit). No `orphan` or `MAX_AA_TREE_DEPTH` interaction.

### Risk Register

| Risk | Severity | Mitigation |
|------|----------|------------|
| AA var and sidechain `perp_burned` diverge (operator lies) | **High** | `Batch::validate_against` replay check in watchers; auditor script asserts `vault_perp_holdings − perp_supply == AA perp_burned == sidechain perp_burned` at each finalized height. Future strict check: bounce `submit` if `perp_burned < var['perp_burned']` (monotonic). |
| Future burn site forgets to call `burn_perp` | Med | Single helper + `#[deny(unused)]` + `// BURN_SITE` search; code review checklist |
| AA complexity budget overflow | Med | Count ops before merge; fallback: drop `{get_burn}` sugar, keep var-only view |
| PERP asset not yet issued — holdings query returns null | Low | Docs note `PERP_ASSET_ID_HERE` placeholder; audit script handles `undefined → 0n` until issuance |
| Sweep temptation (premature token movement) | Low | Explicit v1 decision: no sweep. v2 sweep gated by governance proposal finalization, not self-serve |

### Alternatives Considered (rejected for v1)

- **Real on-chain sweep (send to `0x00…00`):** Requires knowing AA holdings inside Oscript — not possible without an oracle. Adds trust and fails closed if holdings insufficient. Deferred.
- **SS58 burn address with issuer reclaim:** Obyte asset model does not guarantee issuer burn authority; adds deployment coupling. Deferred.
- **Emitting burn as an Obyte `definition` change:** Over-engineered; simple vars suffice.

---

## 6. Staged Path (if gap proves infeasible in one shot)

**This batch WOULD ship as v1 (no sweep, accounting only):**

1. `ChainState::burn_perp` helper + `cumulative_burn()` alias (2-file Rust change, zero wire break).
2. AA globals `perp_burned` / `burned_PERP` + per-height snapshots; `submit`/`finalize` carry candidate burn; `get_burn` view optional if budget allows.
3. E2E test asserting `cumulative_burn == 10k` and AA view == 10k.
4. Docs patch: explicit auditor recipe `vault_perp_holdings - perp_supply == perp_burned`.

**v1.1 (next train, no AA redeploy needed):** indexer adds Prometheus gauge `perp_burned` and Grafana panel comparing AA holdings vs supply vs burn.

**v2 (requires AA redeploy + governance):**

- Strict monotonic enforcement in `submit`: `bounce if perp_burned < var['perp_burned']`.
- Governance proposal `ParamKey::SweepBurn` → on passing, AA sends `min(proposal.value, holdings - perp_supply)` PERP to `PERP_BURN_ADDRESS` via payment message. Requires Obyte asset burn address research and an external holdings attestation.
- Checkpoint hard-forks to include `perp_burned` explicitly; `validate_against` enforces it.

If even v1 AA var is deemed too expensive, the **minimal v0 fallback** is:
- No AA change at all; expose `cumulative_burn` purely as sidechain `meta_leaf` commitment + `getAAStateVars` derivation `holdings − supply` with docs. This closes the auditability gap without touching the AA, at the cost of no explicit AA-side counter. The E2E would then assert `holdings − supply == 10k` via `getBalances` instead of `getAAStateVars`. This is strictly inferior but still satisfies “no token movement, explicit accounting + E2E assertion” if the AA budget is truly zero.

---

## 7. Open Questions

1. **Canonical name:** spec says `cumulative_burn` (assignment), `burned_PERP` (assignment view), Rust has `perp_burned`. Proposal uses all three with alias; should we rename Rust to `cumulative_burn` for spec alignment? → **Recommendation: keep `perp_burned` canonical** (less churn), expose `cumulative_burn()` alias, document `burned_PERP == perp_burned`.
2. **AA string encoding of u128:** Oscript integers are IEEE doubles (53-bit). `perp_burned` can exceed 2⁵³ over long lifetime. Must be stored as decimal string, not number. Current `bal_`/`pperp_` store integers — do they already face this? Confirm max PERP supply fits 53-bit or adopt string convention uniformly for burn.
3. **PERP asset issuance timing:** `PERP_ASSET_ID_HERE` placeholder is still present in AA. Until issuance, `getBalances(aa)[PERP_ASSET]` is meaningless. Audit script should handle “asset not yet issued” gracefully and the burn invariant vacuously holds (holdings = 0, supply = 0, burn = 0 until GovDeposit occurs).
4. **Submit `perp_burned` validation strictness:** Should v1 bounce on `perp_burned < var['perp_burned']` (non-monotonic lie) or stay permissive? Permissive is safer for backward compat; strict catches operator lying sooner. **Propose permissive in v1, strict in v2.**
5. **Per-height history depth:** Storing `perp_burned_<h>` for every height grows AA state unbounded. Obyte AA state is not pruned. At 1 batch/2s, 1 var/height ≈ 500k vars/year. Is per-height history worth it, or should we keep only global? **Proposal keeps it for audit trail**; if state bloat is a concern, keep only global and rely on temp_data replay for history.
6. **Future burn sites:** Oracle slashing was planned but not implemented. Should the `burn_perp` helper be `pub(crate)` or `pub`? Keep `pub` so future `operp-exec` slash path can call it without refactor.

---

## 8. Checklist for Implementer

- [ ] Add `ChainState::burn_perp` + `cumulative_burn()` in `crates/operp-state/src/lib.rs`; commit via `meta_leaf` already done.
- [ ] Refactor `Engine::create_market` to call `burn_perp`; keep `CREATE_MARKET_FEE_PERP` guard order.
- [ ] AA: add `cand_perp_burned_<h>` in submit, `perp_burned`/`burned_PERP`/`perp_burned_<h>` in finalize, optional `{get_burn}` view.
- [ ] Bump no wire format for v1 (canonical_bytes, BTreeMap, 256h, MAX_AA_TREE_DEPTH untouched).
- [ ] Tests: Rust `cumulative_burn_view_after_market_creation` + extended `create_market_burns_exact_fee…` + AA E2E `holdings − supply == burned`.
- [ ] Docs: README/PROTOCOL/MECHANISMS burn-audit subsection with the exact invariant and API names.
- [ ] Count AA ops before/after; drop `{get_burn}` sugar if over budget.
