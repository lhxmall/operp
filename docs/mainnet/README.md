# Mainnet Roadmap — 11 Gap Designs (2026-08-25)

> Each gap from `README.md#Limitations` now has a concrete, file-accurate design doc (no code edits yet). The 37-item security-fix batch is shipped (`53106c2`); these 11 close the remaining testnet→mainnet distance.

| # | Gap (README) | Design doc | One-line |
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

**Staging recommendation:** ship v1 boring changes first (salted ordering + salted eviction + `perp_burned` + depth 18 + 2048 window + escape hatch + deposit evidences + slashing/TWAP scaffolding), keep commit-reveal/sharding/RocksDB/validity-ZK as v2.

**How to read:** each doc has Target / Change (step-by-step, file:line) / Acceptance (E2E assertion) / Complexity & Risk / Open Questions. All respect existing patterns (`otherwise` guards, `BTreeMap` ordering, `MAX_AA_TREE_DEPTH`, 256h→2048h gating).

**Verification of this batch:** design-only, no `cargo`/`node` run. Next phase: implement per doc in isolated worktrees, then `cargo test --workspace` + `AA_DEBUG_COMPLEXITY=1 node test_vault_aa.js` + `bench_raw` as final gate (same as 37-item batch).
