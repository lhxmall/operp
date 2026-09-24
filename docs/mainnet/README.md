# Mainnet Roadmap — 11 Gap Designs (2026-08-25)

> **HISTORICAL DESIGN RECORD (pre-v2).** These 11 docs were written against
> the original `operp-mvp-1` single-vault-AA settlement (submit/lock/
> challenge/respond/finalize/withdraw all inside `operp_vault.aa`,
> `SUBMIT_BOND_NET = 50 000` bytes, 64-hex `aa_root`). The code has since
> been restructured to **settlement v2**: `chain_id = 'operp-v2'`, four AAs
> (`operp_rollup` assertion log + `operp_dispute`/`operp_dispute_fill`
> one-shot predicates + pure-custody `operp_vault`), standing pool
> (`pool >= 1e12`), no lock / no pay-to-kill, and a 1024-hex sharded
> `aa_forest`. File:line references, AA variable names, bond amounts and
> E2E file names in the docs below describe the OLD architecture — treat
> them as design rationale, not as current-code documentation. For the
> current state machine see [`docs/MECHANISMS.md`](../MECHANISMS.md)
> (§10 结算 AA 状态机) and `README.md` §"Settlement AAs".

| # | Gap (README) | Design doc | One-line (as proposed in 2026-08 — not current behaviour) |
|---|---|---|---|
| 1 | Fraud is freeze-and-rollback | [01-fraud-slashing.md](01-fraud-slashing.md) | Slashing split (50% burn / 50% challenger) + `validity_proof_hash` plug, no matcher re-execution in Oscript |
| 2 | Deposit self-attested | [02-deposit-independent-verification.md](02-deposit-independent-verification.md) | `temp_data.deposit_evidences` carries Obyte joint JSON, `object_hash.js` recomputed in `validate_against` (0 AA ops v1) |
| 3 | UnitId grindable | [03-commit-reveal-ordering.md](03-commit-reveal-ordering.md) | v1 `sha256(salt‖unit_id)` salted ordering per epoch (`last_finalized_root/512`), v2 commit-reveal additive |
| 4 | Orphan eviction arrival-sensitive | [04-salted-orphan-eviction.md](04-salted-orphan-eviction.md) | `argmin sha256(salt‖unit_id)` replaces `.min()`, `note_finalized` mirrors `last_finalized_root`, optional `WantUnits` gossip |
| 5 | Oracle no slashing + median | [05-oracle-slashing-twap.md](05-oracle-slashing-twap.md) | 50k PERP stake, TWAP ring 256 batches, 500 bps ×3-streak double condition, `SlashOracle` tag 16, per-market `OracleConfig` |
| 6 | Funding not external | [06-funding-external-anchor.md](06-funding-external-anchor.md) | Funding index = TWAP(external) vs mark premium, `FundingSourceKind` abstraction, caps preserved |
| 7 | No escape hatch | [07-escape-hatch.md](07-escape-hatch.md) | `escape_finalize` + `escape_withdraw` after 7 d stall (`stable_at`/`submitted_at` + `progress_ts`), permissionless, bond-preserving |
| 8 | Burn stranded | [08-burn-accounting.md](08-burn-accounting.md) | `perp_burned`/`burned_PERP` cumulative, `burn_perp()` helper, meta_leaf + Checkpoint audit field, invariant `holdings−supply==burned` |
| 9 | No audit, budget exhausted | [09-complexity-audit.md](09-complexity-audit.md) | Per-branch op-count (~95/100, withdraw 36), 6 merges, R1 single-sha256 fold saves 16, total −27 → 68/100 (+32 headroom) + 9-section audit checklist |
| 10 | aa-tree 2¹⁶ cap | [10-aa-tree-sharding.md](10-aa-tree-sharding.md) | v1 bump 16→18 (262 k accounts, 0 new vars), v2 sharded forest S=16×D16=1 M, activation-height migration |
| 11 | Replay window 256h | [11-replay-persistence.md](11-replay-persistence.md) | Choice A persistent BTree/RocksDB vs B `256→2048` in-RAM + journal (v1 ship), `REPLAY_WINDOW=2048` (~68 min) |

**How to read:** each doc has Target / Change (step-by-step, file:line) /
Acceptance (E2E assertion) / Complexity & Risk / Open Questions.

**Current implementation status (as of 2026-09, post-v2 refactor; the
authoritative narrative lives in `README.md` "Mainnet Roadmap"):**

| # | Status in today's code |
|---|---|
| 01 Fraud slashing | ✅ shipped — dispute verdict path: proven predicate → rollup slashes `5e11` off the operator's standing pool into `slash_reward_<challenger>`, height reopens. `Checkpoint.validity_proof_hash` exists but is carried as an optional header field (not AA-gated). Doc's failed-finalize 50/50 bond split / `claim_slash` handler is the old model |
| 02 Deposit verification | ✅ shipped — per-frame `e` carries FULL Obyte joint units; `unit_hash(joint)` recomputed in `validate_against` via `operp_settle::obyte_hash::get_unit_hash`; post_batch.js builds the joints. Doc's AA-side deposit gates superseded (vault AA is pure custody) |
| 03 Ordering | ✅ shipped, **desalted** — deterministic lex execution; **commit-reveal v2 landed** (`Op::Commit` tag 18 / `Op::Reveal` tag 19, `COMMIT_TTL_HEIGHTS = 16`, ≤ 8 live commits/account, live at height 0) |
| 04 Salted eviction + gossip | ✅ shipped — `argmin sha256(salt‖unit_id)` eviction, epoch-rotated salt via `Engine::note_finalized`; WantUnits gossip in `crates/operp-gossip` |
| 05 Oracle slashing/TWAP | ✅ shipped — stake/unstake (256-height unbond)/slash, TWAP rings, 500 bps ×3-streak + 256-height freshness, `SlashOracle` tag 16; per-market `OracleConfig` |
| 06 Funding anchor | ✅ shipped — funding-index abstraction live at height 0; operator wiring landed (`Op::UpdateExternalPrice` tag 17, allowlist, staleness fallback) |
| 07 Escape hatch | ✅ partially shipped — `{escape_finalize: 1}` rides the rollup finalize case (`submitted_at + 604800`, frozen≠0 bounces 'challenged'); **`{escape_withdraw}` was dropped** (vault AA is pure custody; no such case) |
| 08 Burn accounting | ✅ Rust/checkpoint shipped (`perp_burned` in meta_leaf/Checkpoint); AA-side mirror vars dropped for budget (doc's AA handler is the old model) |
| 09 Complexity audit | ✅ probe `check_aa_complexity.js` shipped; today's numbers: per-formula max complexity 18–21 (≤100 ocore gate enforced in CI), Σops 524–1513 per AA (≤2000) |
| 10 Tree depth/sharding | ✅ shipped — v2 sharded forest: one 1024-hex `aa_forest` = 16 shard roots, depth stays 16, ~1M accounts/batch; v1 depth-18 path superseded |
| 11 Replay window | ✅ v1 shipped — `REPLAY_WINDOW = 2048` from genesis + generalized pruning + `GovNonceJournal` WAL + versioned bincode snapshots; RocksDB (`persist-rocksdb`) remains v1.1 backlog |

**Verification of the current tree:** `cargo test --workspace` **147
passed**; complexity probe reports per-formula max 18–21 (CI gate:
`> 100` fails) with Σops 524–1513 (≤ 2000); golden vector check; devnet
E2E is `node test_settlement_aa.js` (Linux/CI; win32 skips).
