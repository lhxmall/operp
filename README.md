English | [简体中文](README.zh-CN.md)

# OPERP — Optimistic DAG Sidechain Perpetual DEX settling to Obyte

OPERP is a research/MVP implementation of a **perpetual futures exchange** that
executes trades on a high-throughput optimistic DAG sidechain and settles
periodic state roots to the [Obyte](https://obyte.org) ledger through an
autonomous agent (AA) vault. Withdrawals from the vault are **proof-gated**:
users must present a Merkle proof of their balance against a finalized root.

> **Status: testnet-ready MVP.** All workspace tests pass; the full AA
> lifecycle (deposit → submit → lock → challenge → finalize → proof withdrawal)
> is verified end-to-end on an aa-testkit devnet. Mainnet deployment requires
> closing the gaps listed in [Limitations](#limitations--mainnet-readiness).

```
cargo test --workspace          # all green
cargo run --release -p operp-exec --example bench_raw        # ~5.5k ops/s
cargo run --release -p operp-exec --example hft_onedag -- 20000 8 4   # ~9k TPS, 0 rejects
cd obyte-local && node test_vault_aa.js    # full AA lifecycle on devnet
cd obyte-local && node deploy_testnet.js   # deploy vault AA to Obyte testnet
```

## Architecture

```
                    ┌─────────────────────────────────────────────┐
 users (ed25519)    │            SIDECHAIN (Rust)                 │
 ──── Place ───────►│  DAG (units, 2 parents max)                 │
 ──── Cancel ──────►│   └─ deterministic top-order execution      │
 ──── Deposit ─────►│       ├─ CLOB order book (price-time FIFO)  │
 ──── Withdraw ────►│       ├─ cross margin + IM/MM risk engine   │
 ──── Liquidate ───►│       └─ insurance fund + keeper rewards    │
                    │  every batch:                               │
                    │   checkpoint = {height, prev_state_hash,    │
                    │                 state_root, aa_root, ...}   │
                    └────────────────┬────────────────────────────┘
                                     │ temp_data unit (batch data on-chain)
                                     ▼
                    ┌─────────────────────────────────────────────┐
                    │         OBYTE VAULT AA (Oscript)            │
                    │  submit → candidate (replaceable pre-lock)  │
                    │  lock    → after 600 s stability window     │
                    │  challenge → freeze (bond ≥ 20000 bytes)    │
                    │  respond  → operator defense, bond confiscated│
                    │  finalize → root becomes withdrawal basis   │
                    │  withdraw → Merkle PROOF against aa_root    │
                    └─────────────────────────────────────────────┘
```

### Workspace crates

| Crate | Role |
|---|---|
| `operp-types` | Constants (single source of truth), ids (`AccountId = sha256(pubkey)`), fixed-point math |
| `operp-book` | Central limit order book: price-time priority, partial fills, IOC/GTC, self-trade block |
| `operp-account` | Per-account collateral/positions, VWAP entry price, realized PnL, risk snapshot |
| | `liquidatable` at equity·10000 ≤ mm·10500, `reduce_only` at ≤ 12000 |
| `operp-state` | ChainState: accounts/books/marks/withdrawals, byte-level Merkle tree (`state_root`) + hex-string tree (`aa_root`) for the AA |
| `operp-dag` | Unit DAG with signature verification (`verify_strict`), orphan buffer (4096 cap, deterministic eviction), deterministic linearization by unit id |
| `operp-exec` | The engine: ingest → apply → events; place/cancel/deposit/withdraw/liquidate with full intake validation |
| `operp-settle` | Batch checkpoints, `validate_against` replay verification, `temp_data` payloads, proof generation |

## Protocol principles

### 1. One DAG, one total order

Every user action is a signed **unit** referencing up to 2 parent units. The
engine executes pending units in ascending `unit_id` order — a canonical,
deterministic total order any replica can reproduce without consensus
traffic. Out-of-order delivery is tolerated: units whose parents are unknown
are buffered (cap 4096, evicted deterministically by smallest unit id) and
linked automatically once parents arrive.

Signatures use ed25519 **strict verification** (rejects malleable
signatures). Every op binds its owner's key: deposits, orders and cancels
must be signed by their account; liquidations must be signed by the *keeper*
(`Op::Liquidate { caller, .. }`), which makes self-liquidation impossible.

### 2. Deterministic matching, integer-only math

The book is a classic price-time CLOB over `BTreeMap` levels. All money math
is integer fixed-point:

- `Price`, `Qty`: u64 scaled by `1e8`
- `Usd` (collateral/PnL): i128 scaled by `1e6`
- notional = qty·price / PRICE_SCALE · USD_SCALE / QTY_SCALE

Intake guards reject before any arithmetic can wrap: `qty > i64::MAX` or
`qty·price` overflowing i128 → rejected as `Risk`. A per-price-level
incremental `visible_qty` cache keeps best-bid/best-ask at O(log depth).

### 3. Risk model (cross margin)

Each fill updates both legs (VWAP entry for opens); **realized PnL settles
into collateral immediately at close time**, so winners can withdraw profits
and the withdrawal-proof leaf (which commits `collateral`) reflects true
solvency. Snapshots compute maintenance margin (5% of abs notional) and
initial margin (10%). Liquidation is keeper-initiated and pays the keeper 1%
of filled notional from the insurance fund; if the liquidated account still
goes negative, its equity is clamped to exactly 0 and the shortfall is
debited from the insurance fund's collateral — never leaked to
counterparties. Insurance is seeded at genesis (10 000 USD), can never be
liquidated itself, and never self-liquidates.

Mark prices only move on fills with notional ≥ 100 USD **and within ±10% of
the previous mark** (the first qualifying fill on an unmarked market sets it)
- minimal manipulation resistance; full TWAP oracle is future work.

### 4. Settlement: two roots per batch

Every batch (~512 units / 2 s) produces a `Checkpoint`:

```text
{ height, prev_state_hash, state_root, aa_root, last_unit, seq,
  unit_ids, fills_hash, fill_count }
```

- `state_root` — Merkle tree over account leaves, book leaves and a meta leaf
  (which includes `height`, so roots chain across batches and reorgs break
  the hash chain visibly).
- `aa_root` — a second tree over hex strings,
  `leaf = sha256("acct:" + address + ":" + collateral + ":" + perp)`,
  `node = sha256(left ‖ right)`. This exists because Oscript's `sha256()`
  hashes UTF-8 text; it lets the vault AA verify withdrawals (collateral and
  PERP governance asset alike) with pure string operations while committing
  exactly the same balances.
- `fills_hash`/`fill_count` — commitment to executed trade flow.

`Batch::validate_against` replays the posted units through a fresh engine and
asserts chain id, previous root, recomputed fills hash/count, final root —
any honest replica can audit the operator.

### 5. The vault AA: optimistic finality + proof-gated exits

Lifecycle per height *h*:

1. **submit** — operator posts `{height: h, prev_state_hash, state_root,
   aa_root, fills_hash}`. Height must equal `last_locked + 1`; the previous
   root must match. Candidates are **replaceable until locked**, so a
   front-run broken submission cannot brick the chain.
2. **lock** — allowed only after the 600 s stability window
   (`OBYTE_STABILITY_SECS`). Locks are immutable.
3. **challenge** — within 3600 s of locking, anyone can freeze height *h*
   with a ≥ 20 000 byte bond.
4. **respond** — the operator defends inside the window; success unfreezes
   and confiscates exactly the recorded challenger bond (zeroing it). If
   nobody responds in time, finalize marks the height permanently failed
   (`frozen = 2`), clears its roots, and rolls `last_locked` back to h−1;
   no automatic refund happens — the challenger recovers the recorded bond
   through a separate `claim_bond` claim.
5. **finalize** — after a clean 3600 s window the root becomes the withdrawal
   basis (`last_finalized`), strictly in height order.
   - claim carries `{amount, leaf_account, collateral, perp, proof[]}`;
   - the AA recomputes `sha256("acct:"‖address‖":"‖collateral‖":"‖perp)` and
     folds the sibling path, requiring the result to equal
     `var['aa_root_' ‖ h]`;
   - `leaf_account == trigger.address` (you can only prove your own address);
   - the sibling path folds via a fixed-depth `reduce(..., 16, ...)`, so
     proofs cover trees of up to 2^16 accounts;
   - withdrawals are **anti-replay**: a cumulative marker
     `wd_<h>_<address>` caps the total withdrawn at height *h* across all
     claims at the proven leaf collateral.
   
   Balance authority is the **proven leaf**, never mutable AA variables.

Proofs are generated off-chain by
`crates/operp-settle/examples/gen_withdraw_proof.rs` (JSON consumed by the JS
tooling).

There is deliberately **no owner key**: upgrading means deploying a new AA
and migrating funds through the same finalized-root withdrawal path. All
protocol constants in the AA are annotated with their Rust counterparts
(`CHAIN_ID`, `OBYTE_STABILITY_SECS`, `CHALLENGE_SECS`, …) since Rust is the
single source of truth.

## Repository layout

```
crates/                  Rust workspace (7 crates, see table above)
obyte-local/
  agents/operp_vault.aa   the vault autonomous agent (security-hardened)
  test_vault_aa.js       full lifecycle integration test (devnet via aa-testkit)
  deploy_testnet.js      testnet deployment script (+ smoke deposit)
  post_batch.js          operator submission flow (temp_data reveal,
                         submit, lock, finalize, claim)
  gen_withdraw_proof     see crates/operp-settle/examples
vendor/aa-testkit/       Obyte autonomous-agent testkit (vendored)
docs/PROTOCOL.md         protocol design narrative
  docs/MECHANISMS.md     full mechanism reference (zh): every rule, constant,
                         edge case, and the threat-model matrix
```

## Running

```bash
# engine tests (no network needed)
cargo test --workspace

# single-node throughput probe
cargo run --release -p operp-exec --example bench_raw
# one-DAG multi-market stress: <run_ms> <markets> <generators>
cargo run --release -p operp-exec --example hft_onedag -- 60000 8 4

# export a real batch payload
cargo run -p operp-settle --example export_batch

# AA lifecycle on local devnet (needs node; uses vendored aa-testkit)
cd obyte-local && node test_vault_aa.js

# deploy the vault AA to Obyte testnet
cd obyte-local && node deploy_testnet.js

# operator flow: post full batch as temp_data + submit + lock +
# finalize + claim race reward (the complete mainnet sequence)
cd obyte-local && node post_batch.js
```

Measured on this machine: `bench_raw` ≈ 5 500 ops/s; `hft_onedag` (8 markets,
4 generators) ≈ 9 000–9 200 TPS aggregate with zero rejections.

## Limitations & mainnet readiness

This codebase meets the plan's bar of *"deployable to Obyte testnet"*. It is
**not mainnet-ready**. Known gaps, roughly in priority order:

1. **Fraud response is freeze-and-rollback, not on-chain re-execution.**
   Full trade data IS posted on-chain (`post_batch.js` reveals every unit as
   `temp_data`, so any watcher can re-execute and detect a bad root), and a
   detected fraud triggers challenge → freeze → height rollback, after
   which the challenger recovers its recorded bond via `claim_bond` — a
   lying operator cannot steal funds, only
   stall its own height while honest operators (fee race) resubmit correctly.
   What remains out of reach: Oscript cannot re-run the matcher on-chain, so
   there is no automatic slashing or validity proof; enforcement relies on
   live watchers plus competing operators.
2. **Funding rate is mark-premium based.** Longs pay shorts when the trade
   mark runs above the funding index and vice versa (capped at ±50 bps
   per tick), but the index is the **median of bonded reporters' latest
   prices**, not an external exchange price — oracle quality bounds funding
   quality.
3. **Oracle quality depends on bonded reporters.** Reporting is permissionless
   (a 50 000 PERP bond per reporter) but there is no slashing yet, so a
   bond-majority collusion can still bias the median mark; TWAP or external
   multi-source pricing remains future work.
4. **A fully failed challenge permanently wedges the height chain.** When a
   challenge succeeds (operator never responds), the height is marked
   `frozen = 2` and `last_locked` rolls back — but `submit` requires
   `h == last_locked + 1` and there is no skip mechanism, so every later
   deposit/withdrawal stalls until a fresh AA is deployed. This is a
   deliberate liveness attack anyone can trigger.
5. **Large inline `temp_data` payloads crash ocore's validator** (double
   callback in the inline-path check). The JS E2E skips the on-chain batch
   reveal for this reason; operator publication needs an ocore fix or
   chunked reveals first.
6. **Governance vote weight is balance at vote time.** PERP deposited via
   `GovDeposit` counts immediately, so a large holder can concentrate votes
   shortly before the deadline; the only mitigation is the quorum snapshot
   denominator taken at proposal creation.
7. **Burned PERP stays stranded in the vault AA.** Burns decrement
   `perp_supply` but the corresponding tokens remain escrowed (the AA is
   permanently over-collateralized) — auditors must treat
   `vault holdings − perp_supply` as the cumulative burn figure.
8. Failed heights roll back cleanly, but recovery depends on operators
   resubmitting corrected batches; there is no trustless escape hatch if
   every operator disappears.
9. The AA has had no formal security audit; Oscript's complexity budget is
   effectively exhausted (99/100), so every further change must free equal
   budget first.

Recently closed: deposit whitelisting, overflow guards, market whitelist,
strict signatures, orphan recovery with deterministic eviction, bounded
logs, realized-PnL settlement into collateral (profitable withdrawals),
bond-registered oracle medians with deviation caps, peer-to-peer funding with
collateral-aware clamps, multi-operator fee race with consolation payments,
operator identity gate on `respond`, Final-status promotion, on-chain
batch data poster, non-head cancel depth correctness, maker-queue pop
regression, proof-withdrawal decoupled from the diagnostic `bal_` ledger,
height-bound `state_root` (meta leaf commits the batch height), full book
commitment (every price level and resting order), withdraw anti-replay
marker (`wd_<h>_<addr>`), bond recovery via `claim_bond`, a bounded
(65 536-entry) withdrawals map, and PERP governance — sidechain-mirrored
PERP deposits/withdrawals (perp fields in both Merkle leaves), permissionless
market listing with burned listing fees (per-market risk params), and
on-chain parameter proposals with balance-weighted voting, snapshot quorum,
and bond-registered oracle reporting.

See the commit history for the full security-audit remediation this repo
went through (proof-gated withdrawals, deposit whitelisting, overflow
guards, market whitelist, strict signatures, orphan recovery, bounded logs,
keeper rewards, bad-debt socialization).

## License

MIT
