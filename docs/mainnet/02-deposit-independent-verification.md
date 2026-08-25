# Gap 4 — Deposit Endorsements Self-Attested  •  DesignDoc (DesignDepositIndep)

## 1. Target

### Exact files & symbols (read-only — this doc edits nothing)

| Area | Path | Symbol / key |
|---|---|---|
| Sidechain state | `crates/operp-state/src/lib.rs` | `ChainState { deposits_allowed: HashSet<([u8;32],bool)> , seen_aa_units, aa_addresses, perp_balances, … }`, `Withdrawal`, `proposals` |
| Intake gate | `crates/operp-exec/src/lib.rs` | `Engine::deposit`, `Engine::gov_deposit` (both check `deposits_allowed.contains(&(aa_unit,kind))`), `RejectReason::UnbackedDeposit / DuplicateDeposit`, `Dispatch::Deposit/GovDeposit` |
| DAG wire type | `crates/operp-dag/src/lib.rs` | `Op::Deposit{account,addr,amount,aa_unit}` tag `3`, `Op::GovDeposit{…}` tag `8`, `canonical_bytes`, `unit_id = sha256(canonical_bytes)` |
| Batch + replay | `crates/operp-settle/src/lib.rs` | `Batch::from_applied`, `Batch::validate_against(prev_root,&mut Engine)`, `TempDataPayload {data,data_hash,data_length}`, `fills_bytes`, `SettleError::{Replay,RootMismatch,FillsMismatch}` |
| Vault AA (Oscript) | `obyte-local/agents/operp_vault.aa` | `trigger.data.deposit` → `var['bal_'||addr]`, `trigger.data.deposit_perp` → `var['pperp_'||addr]`, `bounce_fees`, `chain_id='operp-mvp-1'`, `PERP_ASSET_ID_HERE` placeholder |
| Posting | `obyte-local/post_batch.js` | `tempDataMessage(batchData)`, `trigger(...,{submit:{height,prev_state_hash,state_root,aa_root}})` |
| Reference | `vendor/ocore/validation.js`, `validation_utils.js`, `object_hash.js`, `chash.js` | `objectHash.getUnitHash(unit)`, `getBase64Hash`, `validateLight` (bLight), `isValidAddress` |

### Current gap (README L4 restated)

`validate_against` self-whitelists:

```rust
for u in &self.units {
  match &u.op {
    Op::Deposit{aa_unit,..} => replay.state.deposits_allowed.insert((*aa_unit,false)),
    Op::GovDeposit{aa_unit,..} => replay.state.deposits_allowed.insert((*aa_unit,true)),
    _=>{}
  }
}
```

A lying operator can mint any `(aa_unit,amount,addr)` — watchers must fetch every `aa_unit` from an Obyte hub out-of-band and compare. No cryptographic binding between theAA-side `bal_/pperp_` shadow ledgers and the sidechain `Op`. Kind separation (`(unit,bool)` so collateral ≠ PERP) already shipped, but **content-hash** (did that Obyte unit actually pay `amount` of `asset` to the vault AA?) is unchecked.

---

## 2. Change — Watcher-Independent Verification

### 2.1 Recommendation: staged path, v1 ships now

| Approach | Temp_data cost | Rust cost | Trust | Oscript budget | Verdict |
|---|---|---|---|---|---|
| **A. Full light client in Rust** (verify header chain + witness MCIs against Obyte genesis) | large (headers+BIP) | ~2k LOC port of `object_hash` + `validation::validateLight` | trustless | none | gold standard, but 2–3 sprints, large audit surface. Defer to v2. |
| **B. Committee attestation** (n-of-m hub signatures over `(aa_unit,amount,asset)`) | tiny (one sig) | small | adds committee trust, deviates from "any watcher can audit" | none | rejected for MVP — recentralises. Useful only as interim oracle for non-Byzantine testnet. |
| **C. Inclusion proof carried in `temp_data`, verified in Rust replay (chosen v1)** | `O(deposits × joint JSON ≈ 2–8 KB each)` | ~300 LOC deterministic hash + field checks | watchers need no hub at replay time; forgery of a *real* Obyte-stable unit still needs hub to disprove, but naive `aa_unit`-mint and kind/amount mismatch now fail deterministically | none if AA unchanged; optional `+3` ops/unit if we add per-unit AA var | **Ship C as v1**, pave the road to A. |

**v1 (this batch) = C-minimal**: operator must post the originating Obyte joint JSON for every `Deposit`/`GovDeposit` in the batch. `validate_against` recomputes the Obyte unit hash and asserts that the joint actually paid the vault AA the claimed `(amount,asset)` . No Oscript change, no hub call at replay time. A completely fabricated `aa_unit` (no joint) → `DepositAnchorMissing` → `validate_against` fails. A fabricated joint with wrong amount/kind/address → `DepositContentMismatch`. A fabricated joint whose hash was invented locally still passes C-v1; that residual is closed either by (i) live watchers querying a hub, or (ii) v2 light-proof.

**v2** promotes each `DepositEvidence.joint` to `DepositAnchor { joint, mci, ball, parent_hashes, witness sigs }` and `validate_against` verifies `objectHash` + ball-chain + `ball == sha256(headers)` + stable MCI > 0. Only then is even a locally-forged well-formed joint rejected offline.

### 2.2 Temp-data schema extension

Extend `crates/operp-settle/src/lib.rs` — additive only, existing JSON keys untouched.

New types (all `Serialize/Deserialize`, `deny_unknown_fields` off to keep forward compat):

```rust
/// One Obyte deposit evidence carried alongside temp_data.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DepositEvidence {
    /// Hex 64 — must equal unit_hash(joint).
    pub aa_unit: String,              // hex::encode([u8;32])
    /// false = base deposit, true = PERP deposit. Must match Op kind.
    pub is_perp: bool,
    /// Decimal string as it appears in bal_/pperp_ ledger (mirrors AA).
    /// For base: bytes (1e9 * bytes? no — same Usd i128·1e6 scale). Stored as decimal string
    /// to avoid JS number precision; Rust parses to i128/u128.
    pub amount: String,
    /// Obyte vault AA address that must be the payee.
    pub vault_address: String,
    /// Full Obyte joint as returned by hub `getJoint` (unit + messages + authors).
    /// Value is raw JSON object, not stringified again.
    pub joint: serde_json::Value,
    /// Optional v2 anchor: MC index + ball. Absent in v1.
    #[serde(skip_serializing_if="Option::is_none", default)]
    pub mci: Option<u32>,
    #[serde(skip_serializing_if="Option::is_none", default)]
    pub ball: Option<String>,
}

/// Batch-level wrapper — added as a top-level key to the object currently built in
/// Batch::temp_data_payload().
```

**Payload shape** — current object (`chain_id,height,prev_state_hash,state_root,aa_root,last_unit,seq,unit_ids,fill_count,fills_hash,units`) gains one sibling key:

```json
{
  "chain_id":"operp-mvp-1",
  "height": 42,
  ...
  "units": [ {parents,op,pubkey,sig}, ... ],
  "deposit_evidences": [ {aa_unit,is_perp,amount,vault_address,joint,mci?,ball?}, ... ]
}
```

Ordering: `deposit_evidences` is sorted by `aa_unit` lexicographically (BTreeMap order) to keep `data_hash = Sha256(canonical_json_bytes)` deterministic. `units` order already matches `checkpoint.unit_ids` (application total order).

`Batch` in-memory shape: add field `pub deposit_evidences: Vec<DepositEvidence>` (default `vec![]` for old batches). `from_applied` populates it from the operator's hub fetches (outside consensus). `temp_data_payload()` serialises it. `validate_against` consumes it.

**Constants** — add to `operp-types`:

```rust
pub const VAULT_AA_ADDRESS: &str = ""; // filled at deploy; checked against joint payee
pub const DEPOSIT_EVIDENCE_MAX_BYTES: usize = 1_048_576; // per-batch cap (~1 MiB)
```

### 2.3 Rust verification hook

`operp-settle/src/lib.rs`:

```rust
pub enum SettleError {
    // existing …
    DepositAnchorMissing,   // op references aa_unit with no evidence
    DepositContentMismatch, // joint hash != aa_unit, or payee != vault, or amount/asset != op
    DepositKindMismatch,    // evidence.is_perp != op kind
    DepositDuplicateAnchor, // two evidences claim same aa_unit
    EvidenceTooLarge,
}
```

New module `deposit_verify.rs` (or inline):

```rust
fn obyte_unit_hash(joint: &serde_json::Value) -> Result<[u8;32], SettleError>
fn verify_one(op: &Op, ev: &DepositEvidence) -> Result<(), SettleError>
fn verify_all(checkpoint: &Checkpoint, evidences: &[DepositEvidence]) -> Result<HashMap<[u8;32], DepositEvidence>, SettleError>
```

Verification steps inside `Batch::validate_against`, *before* `deposits_allowed` injection:

1. **Size gate** `evidences.len() <= units.iter().filter(Deposit|GovDeposit).count()` and total JSON bytes < `DEPOSIT_EVIDENCE_MAX_BYTES`, else `EvidenceTooLarge` (DoS bound).
2. **Dedup** — `HashMap<aa_unit,bool>` of evidences; duplicate `aa_unit` → `DepositDuplicateAnchor`.
3. **For each `Deposit/GovDeposit` op**, find `ev` where `ev.aa_unit == hex(aa_unit)`; absent → `DepositAnchorMissing`. If `ev.is_perp != is_gov_kind` → `DepositKindMismatch`.
4. **`obyte_unit_hash(ev.joint) == aa_unit`** — port of `vendor/ocore/object_hash.js:getUnitHash`. Must replicate exact field order and hash (blake2b? chash?). Reuse the JS implementation as reference test vector: add fixture of a real devnet unit from `test_vault_aa.js` and assert Rust hash equals base64 id. On mismatch → `DepositContentMismatch`.
5. **Content check** — inspect `ev.joint["unit"]["messages"]` (or `ev.joint["messages"]` depending on hub encoding):
   - Must contain a `trigger` / `payment` message whose `payload`/`outputs` pay `VAULT_AA_ADDRESS` with `asset = base` (for `is_perp==false`) or `asset == PERP_ASSET` (for `is_perp==true`). Amount after subtracting AA bounce headroom (`trigger.output[[asset=base]] - 10000`) must equal `op.amount` string-parsed. Use the same `PERP_ASSET` constant the AA was deployed with (share via `operp-types::PERP_ASSET`, substituted at build).
   - The `joint.unit.authors[0].address` (or `unit.authors`) must correspond to the depositor's Obyte address — but sidechain `Op` does not carry that; we only bind `addr` (withdrawal leaf key). No check on depositor identity at this layer; per-unit AA var would add it in v2.
   - For `GovDeposit`, additionally assert `ev.joint` includes `trigger.data.deposit_perp` field.
   - If any field mismatched → `DepositContentMismatch`.
6. **Vault address check** — `ev.vault_address == VAULT_AA_ADDRESS` (evidence self-declares expected payee; prevents operator pointing at a different AA).
7. **(v2 only)** If `ev.mci.is_some()`, verify ball chain + witness signatures via light validation; v1 ignores `mci/ball` if present (forward compat).
8. **Atomically populate** `replay.state.deposits_allowed` *only from verified evidences* instead of blindly from `self.units`:
   ```rust
   let verified = verify_all(&self.checkpoint, &self.deposit_evidences)?;
   for (aa_unit,is_perp) in verified.keys() { replay.state.deposits_allowed.insert((*aa_unit,*is_perp)); }
   // then ingest as before; UnbackedDeposit now only fires for ops whose evidence was missing/invalid
   ```
   This is the core behavioural change: the whitelist is no longer self-attested — it is the image of `verify_all`.

**`obyte_unit_hash` porting notes** (boring, minimal):

- Copy `vendor/ocore/object_hash.js` + `chash.js` logic into `crates/operp-settle/src/obyte_hash.rs` (pure Rust, no deps beyond `blake2`, `sha2`). Keep function signatures identical to JS for test-vector parity.
- Alternative shortcut for v1: delegate hashing to bundled JS via `boa`/`quickjs` is *not* minimal — port is ~120 LOC and avoids runtime.
- Add `#[cfg(test)]` vectors: one base deposit joint captured from a `Network.create()` run in `obyte-local/test_vault_aa.js`, with known `aa_unit` base64→hex; assert `obyte_unit_hash(json) == aa_unit`.

### 2.4 Vault AA — v1: no change required (recommended); v2 optional

**v1 keeps the AA untouched** to stay inside the exhausted Oscript budget. Rationale given in the prompt — `(a) AA stores deposit unit hash -> amount map (already bal_/pperp_ shadow ledgers)` — the existing `bal_<addr>` and `pperp_<addr>` are sufficient shadow ledgers; the cryptographic binding is moved to the `temp_data` + Rust layer.

Optional **AA per-unit commitment** (defer to v2 if budget allows):

```oscript
// inside `if (trigger.data.deposit)` handler, after bal_ credit:
var['d_' || trigger.unit] = trigger.output[[asset=base]] - 10000;
// inside deposit_perp:
var['pd_' || trigger.unit] = trigger.output[[asset='PERP_ASSET_ID_HERE']];
```

Cost: `+1 var write + 1 concat per deposit` ≈ 3 Oscript ops per deposit. With 600-deposit bursts this exhausts the AA complexity budget (≈15k steps). Therefore gate v2 on a budget-freeing refactor (e.g., collapse `bal_/pperp_` into a single map, or raise Obyte formula limit). If shipped later, `validate_against` gains an extra optional check: query AA state vars `d_<hex>`/`pd_<hex>` via hub and assert they equal `ev.amount`.

**If per-unit vars ship**, pruning: never prune (AA storage is permanent); the 256h sidechain pruning (`prune_aa_units`) remains independent. Document that AA var growth is `O(total deposits)`, bounded by Obyte state rent, not sidechain memory.

### 2.5 Operator & watcher flows

**Operator (`post_batch.js` / `export_batch.rs`)**

```
for op in batch.units where op is Deposit/GovDeposit:
  joint = await hub.getJoint(aa_unit_base64)   // ocore light hub
  evidences.push({ aa_unit: hex, is_perp, amount: op.amount.toString(),
                   vault_address: VAULT, joint })
evidences.sort_by(aa_unit)
batch.deposit_evidences = evidences
payload = batch.temp_data_payload() // now includes evidences
poster.sendMulti({ messages:[tempDataMessage(payload)] })
```

**Watcher / challenger**

```
posted = hub.getTempData(batchHeight)
batch = Batch::from_temp_data_payload(posted.data) // deserialize + hash check
prev_root = chain[height-1].state_root
replay = Engine::from_genesis(prev_root)
batch.validate_against(prev_root, &mut replay) // fails with Deposit* if fake
if err == DepositContentMismatch => challenge via vault AA {challenge:1,height}
```

No hub query needed in the happy-path replay; hub query only needed to *prove* a locally-forged joint is not on the Obyte DAG when escalating a challenge on-chain (out of scope for v1).

### 2.6 Exact file deltas

| File | Add | Modify | Remove |
|---|---|---|---|
| `crates/operp-types/src/lib.rs` | `VAULT_AA_ADDRESS`, `PERP_ASSET` re-export already, `DEPOSIT_EVIDENCE_MAX_BYTES` | — | — |
| `crates/operp-settle/src/lib.rs` | `DepositEvidence`, `SettleError::Deposit*`, `Batch.deposit_evidences`, `mod obyte_hash`, `mod deposit_verify` | `TempDataPayload` gains `deposit_evidences` field (with `#[serde(default)]` for back-compat), `Batch::from_applied`/`temp_data_payload`/`validate_against` | nothing |
| `crates/operp-settle/src/obyte_hash.rs` | **new** — `obyte_unit_hash` port of `object_hash.js` | — | — |
| `crates/operp-settle/src/deposit_verify.rs` | **new** — `verify_all` / `verify_one` | — | — |
| `crates/operp-state/src/lib.rs` | doc comment for `deposits_allowed` clarifying it is now populated from verified evidences, not blindly | — | — |
| `obyte-local/post_batch.js` | fetch `getJoint` loop, populate `deposit_evidences` | `tempDataMessage` data shape | — |
| `obyte-local/agents/operp_vault.aa` | *v1: none* ; v2 optional `d_||trigger.unit`/`pd_||...` vars | — | — |
| `vendor/ocore/object_hash.js` | reference only | — | — |
| `crates/operp-settle/examples/export_batch.rs` | populate `deposit_evidences` with stub joints in tests | — | — |

Patterns respected: `canonical_bytes` stays wire authority for sidechain units; `BTreeMap` ordering for evidence sort; `otherwise` guards remain in Oscript; `MAX_AA_TREE_DEPTH=16` untouched; 256-height windows for `seen_aa_units` remain — verified `deposits_allowed` entries are transient (cleared per `validate_against` call, not persisted across batches) so no pruning change needed.

---

## 3. Acceptance

### Observable result

- A batch containing `Op::Deposit { aa_unit = 0xDEAD… , amount = 1_000_000 }` with **no** `deposit_evidences` entry for that `aa_unit` is rejected by any honest watcher replaying the posted `temp_data` — `validate_against` returns `Err(SettleError::DepositAnchorMissing)` before any state mutation.
- A batch where the evidence's `joint` pays a different amount (e.g., `500_000`) or different vault address, or whose `joint` hash != `aa_unit`, or whose `is_perp` mismatches the op kind, returns `Err(SettleError::DepositContentMismatch)` / `DepositKindMismatch`.
- A correct batch (real devnet joint fetched from hub, matching amount/kind/address) passes `validate_against` and the subsequent `fills_hash / state_root / aa_root` checks exactly as today.
- Old batches without `deposit_evidences` (pre-upgrade) are treated as valid only if `checkpoint.height < ACTIVATION_HEIGHT` (see migration); post-activation they are rejected — no silent downgrade.

### Test / E2E assertions

**Unit tests (`crates/operp-settle`):**

```rust
#[test] fn deposit_anchor_missing_fails() {
  let (prev_root, mut batch) = make_batch_with_one_deposit(1_000_000, false);
  batch.deposit_evidences.clear();
  let mut replay = Engine::from_prev_root(prev_root);
  assert_eq!(batch.validate_against(prev_root, &mut replay), Err(SettleError::DepositAnchorMissing));
}
#[test] fn deposit_kind_mismatch_fails() {
  // collateral op with is_perp=true evidence
}
#[test] fn deposit_content_amount_mismatch_fails() {
  // evidence.amount = "500000" but op.amount = 1_000_000
}
#[test] fn deposit_hash_mismatch_fails() {
  // tamper one byte of joint, hash != aa_unit
}
#[test] fn valid_deposit_passes() {
  // real joint fixture from test_vault_aa.js vector
  let batch = batch_with_real_joint_fixture();
  assert!(batch.validate_against(prev_root, &mut replay).is_ok());
}
#[test] fn obyte_unit_hash_vector() {
  let joint: Value = serde_json::from_str(include_str!("fixtures/deposit_joint.json")).unwrap();
  assert_eq!(hex::encode(obyte_unit_hash(&joint).unwrap()), "ab12…");
}
```

**E2E (devnet, `obyte-local/test_vault_aa.js` extension):**

```js
// 1. Do a real deposit via vault AA, capture aaUnit and joint via hub.
// 2. Build a sidechain batch with GovDeposit referencing that aaUnit but amount +1.
// 3. Post temp_data with mismatched evidence → watcher script calls
//    Batch.validate_against and asserts DepositContentMismatch.
// 4. Rebuild with matching evidence → watcher asserts ok, then submit/lock/finalize.
```

CI gate: `cargo test -p operp-settle -- --nocapture` must show the `Deposit*` tests green; `node test_vault_aa.js` extended scenario must exit 0 only when first (fake) batch is rejected and second (real) batch finalizes.

---

## 4. Complexity & Risk

### AA op-count delta

- **v1: 0**. Intentionally no AA change, so the already-exhausted Oscript budget is untouched.
- **v2 per-unit var (optional)**: `+3` ops per deposit (`concat + var write`). At 10 deposits/batch this is +30 steps (~0.2% of limit); at 500 deposits it is +1500 steps and will OOM the AA. Hence v2 must be paired with a budget-freeing refactor or a per-batch cap on deposits (`MAX_DEPOSITS_PER_BATCH = 64`).

### Migration & backward compatibility

- Wire: new `deposit_evidences` key is additive. Old `temp_data` (without the key) deserialises with `#[serde(default)]` → `vec![]`. Consensus rule activates at `DEPOSIT_VERIFY_HEIGHT: Height = <governance-chosen>` (e.g., `height 0` on new devnet, `height = last_finalized+1` on testnet reset). Pre-activation `validate_against` skips `verify_all`; post-activation it enforces it. One flag, no fork of `canonical_bytes`.
- No state migration: `deposits_allowed` remains transient (recomputed per `validate_against` from evidences). `seen_aa_units` pruning (256h) unchanged.
- Vault AA address constant: `VAULT_AA_ADDRESS` must be set at deploy time. Until issuance, `PERP_ASSET = [0;32]` checks are skipped for `is_perp==true` (or compare placeholder string). Document that PERP-deposit verification becomes fully strict only after `PERP_ASSET_ID_HERE` substitution.

### Storage & DoS

- `temp_data` size: each evidence carries a full joint JSON (~3–6 KB). 64 deposits → ~256 KB, still under Obyte `MAX_TEMP_DATA_SIZE` (approx 1 MiB). Enforce `DEPOSIT_EVIDENCE_MAX_BYTES` to prevent OOM on watcher deserialize.
- CPU: `obyte_unit_hash` is `blake2b-256` + JSON canonicalisation, ~5 µs per deposit, negligible vs. 5k ops/s engine throughput.
- Replay determinism: evidence sort order + `BTreeMap` insertion order keeps `deposits_allowed` iteration deterministic; `fills_bytes` ordering unchanged.

### Failure modes

- Hub unavailable at operator posting time → operator cannot build evidence; batch cannot be posted. Acceptable: deposits are liveness-dependent on the operator's hub, not on watchers.
- Hub lie (hub serves a fake joint for a fake `aa_unit`): v1 still accepts it (joint is well-formed and hash matches). This is the residual trust gap closed by v2 light proof. Document explicitly as "v1 requires a live honest hub to challenge a well-formed forgery; v2 removes even that".
- Evidence equivocation (operator posts two different joints for same `aa_unit` in two competing batches): both batches' `aa_unit` tie to the same Obyte unit; only one can have the correct amount/asset — the other fails `DepositContentMismatch`. No state split.

---

## 5. Open Questions

1. **Unit hash algorithm pinning.** `object_hash.js` uses `chash` (RIPEMD160 + base32) for addresses but `getUnitHash` is `sha256` over a specific JSON stringification (sorted keys, no whitespace, `version`/`alt` handling). We must pin the exact hub version (`vendor/ocore` at commit `X`). Should we vendor the hash function or depend on a published crate? Decision needed before porting.
2. **PERP asset id availability.** Until PERP issuance, `is_perp==true` content checks cannot assert `asset == PERP_ASSET`; they only check `trigger.data.deposit_perp` presence. Acceptable for devnet, but mainnet activation must require real asset id substitution in both AA and `operp-types`.
3. **Vault AA address source of truth.** In `obyte-local` the vault address is derived deterministically from the AA definition hash. Should `VAULT_AA_ADDRESS` be computed at `Batch::verify_all` time from the AA definition, or injected as a constant? Computing avoids constant drift but needs the definition JSON in the verifier.
4. **DoS via large joints.** Should the watcher fetch joints itself rather than trust the operator's `joint` blob? Hybrid: v1 trusts the blob for determinism but watchers *may* re-fetch from their own hub and compare `joint` equality; mismatch is also a challenge trigger. Specify whether equality check is mandatory or advisory.
5. **Deposit ordering vs DAG total order.** Today `deposits_allowed` injection runs before `ingest` in lexical `unit_id` order. If two deposits share the same `aa_unit` (duplicate), `seen_aa_units` dedup already rejects the second. No change needed, but confirm that `verify_all` must also deduplicate evidences before ingest to preserve deterministic `DuplicateDeposit` vs `DepositDuplicateAnchor` error priority.
6. **Activation height governance.** Who sets `DEPOSIT_VERIFY_HEIGHT`? Simplest: hardcode at next unstable devnet deploy and wipe chain. For testnet with live state, propose a `CreateProposal`-style height flag or just coordinate an off-chain flag day.

---

## Appendix — Minimal v1 Code Sketch

```rust
// crates/operp-settle/src/lib.rs (diff)
pub struct Batch {
    pub chain_id: String,
    pub checkpoint: Checkpoint,
    pub units: Vec<Unit>,
    #[serde(default)]
    pub deposit_evidences: Vec<DepositEvidence>,
}

impl Batch {
    pub fn validate_against(&self, prev_root: [u8;32], replay: &mut Engine) -> Result<(), SettleError> {
        // ... chain_id, prev_root checks unchanged ...
        let verified = deposit_verify::verify_all(&self.units, &self.deposit_evidences)?;
        for (k,v) in verified { replay.state.deposits_allowed.insert((k,v)); }
        // ... ingest, fills_hash, height/root/aa_root checks unchanged ...
    }
}
```

**What this batch ships as v1:** §2.2 + §2.3 fully (evidence type, hash port, `verify_all`, `validate_against` hook, size/kind/hash/content checks, tests). No AA edit. Operator tooling updated to include evidences. E2E `fake aa_unit → validate_against fails` green.

**Staged v2 follow-up:** add `mci/ball/witness` light proof, optional AA `d_/pd_` per-unit vars, and `DEPOSIT_VERIFY_HEIGHT` activation governance — tracked as separate ticket.
