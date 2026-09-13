# Gap 12 — Clamp / Deposit-Evidence / Oracle-majority / DA-hardening — As Built

> Owner: `DesignClampEvidenceDA` · Status: SHIPPED · Batch: Mainnet-6
> Implements `local://12-clamp-evidence-da-plan.md` (design) with one
> documented deviation (§5 D4: no `dispute_da.aa` — Oscript cannot gunzip).
> Breaking changes applied throughout (mainnet undeployed):
> `state_root`/`wit` leaves, op encoding, AA set 4→5, `deployment.json` shape.

---

## 1. What shipped

| # | Hole | Fix | Files |
|---|------|-----|-------|
| A | Insurance clamp unverifiable on-chain | Cumulative `clamp_paid` per account → `clamp:<hex>:<total>` wit leaf + `meta_leaf` commitment; NEW `pred='clamp'` in `operp_dispute_clamp.aa` (33/100); watcher builds clamp proofs, fill_math guard routes clamped sides | `operp-state` (`ChainState.clamp_paid`, `apply_fill_pair`, `wit_leaves`, `meta_leaf`), `operp_dispute_clamp.aa`, `operp_rollup.aa` (`set_dispute_clamp` + verdict), `operp-watch/prove.rs` + `main.rs` (`--clamp`), `post_challenge.js` (`--clamp`), `deploy_mainnet/testnet.js`, CI gate |
| B | Bond-weighted oracle majority steers median | `ORACLE_MIN_REPORTERS_MARK=3` count gate; `REPORT_MAX_STEP_BPS=2000` speed limit vs long TWAP; slash baseline pinned to long TWAP; stale-external mark freeze (funding still falls back) | `operp-types` (2 consts), `operp-state` (`apply_report`, `apply_fill_pair` mark gate, `apply_slash` comment) |
| C | Deposit self-mint not killable on-chain | Op descriptors carry `:{anchor_b64}`; vault persists `dep_<unit>`/`pdep_<unit>`; NEW `pred='dep_evidence'` in `operp_dispute.aa` (18/100) with `VAULT_AA_HERE` cross-AA read; watcher receipt callback; poster waits for receipts | `operp-settle::ops_element`, `operp_vault.aa`, `operp_dispute.aa`, `operp-watch` (`build_proof` 5th arg, `main.rs` closure), `post_batch.js`, dispute AA `deposit` case requires anchors |
| D | DA is a social convention | `PackageOverCap` hard error; `data_root/data_len/pkg_count` committed + submit gates (`data_len ≤ pkg_count×4M`, `pkg_count ≤ 1024`); missing-package LOUD alert; `--archive-dir` | `operp-settle` (`PackageOverCap`, `data_len`), `operp_rollup.aa` submit, `post_batch.js`, `operp-watch/main.rs`, e2e submits |

## 2. Verification

* `cargo test --workspace`: all green (state 25 incl. 4 oracle + 2 clamp-receipt tests; exec 45 incl. 3-reporter rewrites + pair test; settle 31 incl. `header_carries_data_len_and_root`; watch 13 incl. clamp honest/liar + dep_evidence shapes).
* `check_aa_complexity.js` (5 AAs): vault 21, rollup 20, dispute 18, fill 21, clamp 33 — all ≤ 100.
* E2E (`test_settlement_aa.js`, CI ubuntu): 13b/13c clamp kill + honest, 13d/13e/13e2 dep_evidence kill + honest + bookkeeping freeze, 13f refreeze; `test_pool_occupancy.js` submits carry DA fields.
* E2E scenario chain (h3): 13a F → 13d F → 13e H → 13e2 F → 13b F → 13c H → 13f F → 14.

## 3. Protocol constraints introduced (governance docs must carry)

* `pos ≤ 4` markets per challenged side for `pred='clamp'` (xp0..xp2 + fill market); richer accounts must reduce first. Watcher returns print-only beyond the bound.
* Deposit ops without a 44-char anchor bounce `bad op` (breaking, pre-mainnet).
* Vault receipt state grows one key per deposit (`dep_`/`pdep_`) — bounded by deposit count, accepted.
* `pkg_count ≤ 1024` per submit (trigger-data bound).

## 4. Complexity & Risk (as built)

* Equity recompute: Oscript Decimal `floor`/`ceil` mirrors Rust trunc-toward-zero per leg (same idiom as fill_math); entry ±1 VWAP tolerance kept. Side-independent fee leg: insurance always receives the fill taker fee regardless of challenged side.
* Oscript single-assignment: `$pos_bad` flag pattern convicts pos-leg divergence (never `no fraud` on a divergent pos leg — honest heights replay deterministically).
* `deploy_mainnet.js` vault-first ordering (dispute needs the vault address); testnet precomputes via chash; e2e likewise. `deployment.json` gains `dispute_clamp_aa_address`.
* Watcher `build_proof` 5th arg (`vault_receipt` closure); `None` in unit tests preserves old paths.

## 5. Deviations from design

* D4 — NO `operp_dispute_da.aa` / `pred='da_frame'`: Oscript has no base64-decode, no gzip, and `is_valid_sig` needs PEM keys (sidechain uses raw ed25519) — package-content conviction is inexpressible on-chain. Delivered instead: hard error + on-chain DA commitments + submit gates + loud withheld-package alert + `--archive-dir` + dual-watcher ops note. Revisit only if Oscript gains binary builtins.
* OQ1 (spike): Oscript has NO `to_hex`/`base64` — op carries base64 anchor (breaking, allowed). Cross-AA `var[VAULT][key]` confirmed working (vault precedent: `var[ROLLUP][...]`).
* OQ2: `dep_evidence` FIT in `operp_dispute.aa` (18/100) — no `dispute2` rename needed.
* OQ3: clamp at pos=4 measures 33/100 — headroom ample, bound kept at 4.
