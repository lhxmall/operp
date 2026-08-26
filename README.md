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
                    │  resubmit → operator answers a challenge (unfreeze)│
                    │  finalize → root becomes withdrawal basis   │
                    │  withdraw → Merkle PROOF against aa_root    │
                    └─────────────────────────────────────────────┘
```

### Workspace crates

| Crate | Role |
|---|---|
| `operp-types` | Constants (single source of truth), ids (`AccountId = sha256(pubkey)`), fixed-point math |
| `operp-book` | Central limit order book: price-time priority, partial fills, IOC/GTC, self-trade cancel-maker protection |
| `operp-account` | Per-account collateral/positions, VWAP entry price, realized PnL, risk snapshot |
| | `liquidatable` at equity·10000 ≤ mm·10500, `reduce_only` at ≤ 12000 |
| `operp-state` | ChainState: accounts/books/marks/withdrawals, byte-level Merkle tree (`state_root`) + hex-string tree (`aa_root`) for the AA |
| `operp-dag` | Unit DAG with signature verification (`verify_strict`), orphan buffer (4096 cap, salted eviction), salted deterministic linearization (`ready_linearized_with_salt`) |
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
Self-trades never fill: when a taker meets its own resting order, the maker
order is canceled (`canceled_maker`) and matching continues against the
next order with the remaining taker quantity.

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
  (which includes `height`, every market's `(mark, last funding index)` and the
  oracle's last index, so roots chain across batches and reorgs break
  the hash chain visibly).
  Only *applied* units advance the global `seq`; rejected ops do not consume
  sequence numbers.
  - `aa_root` — a second tree over hex strings,
  `leaf = sha256("acct:" + address + ":" + collateral + ":" + perp + ":" + withdrawn)`,
  `node = sha256(left ‖ right)`. This exists because Oscript's `sha256()`
  hashes UTF-8 text; it lets the vault AA verify withdrawals with pure string
  operations while committing exactly the same balances — including `W`, the
  account's cumulative sidechain-withdrawal total that backs the AA-side
  anti-replay cap. Only accounts bound to an Obyte address (via
  `Op::Deposit { addr }` / `Op::GovDeposit { addr }`) enter this tree; the
  binding is first-seen-wins and enforced at intake.
  `Batch::validate_against` additionally verifies the recomputed `aa_root`
  against the checkpoint.
- `fills_hash`/`fill_count` — commitment to executed trade flow.

`Batch::validate_against` replays the posted units through a fresh engine and
asserts chain id, previous root, recomputed fills hash/count, final root —
any honest replica can audit the operator.

### 5. The vault AA: optimistic finality + proof-gated exits

Lifecycle per height *h*:

1. **submit** — operator posts `{height: h, prev_state_hash, state_root,
   aa_root}` with ≥ 60 000 bytes attached: 10 000 bounce headroom plus a
   **50 000-byte `SUBMIT_BOND_NET`** locked per live candidate. Height must
   equal `last_locked + 1`; the previous root must match; all three hash
   fields must be exactly 64 hex chars. Candidates are **replaceable until
   locked**: a replacing submitter takes the height over and the displaced
   candidate's bond moves to `sbond_<addr>` for reclaim via
   `{claim: "sbond"}` (failed finalizations confiscate it instead). The
   sitting operator re-submitting keeps its bond (no double charge) and the
   stability timer restarts on every submit — identical-root spam only
   costs the attacker a fresh bond each round.
2. **lock** — allowed only after the 600 s stability window
   (`OBYTE_STABILITY_SECS`). Locking clears a previous permanent-failure
   mark, so a challenge-failed (`frozen = 2`) height recovers by fresh
   submission instead of wedging the chain. Locked roots are immutable.
3. **challenge** — within 3600 s of locking, anyone can freeze height *h*
   with a ≥ 20 000 byte bond; a sender with an outstanding bond cannot open
   a second challenge, and `{claim: "bond"}` refuses payout while the
   challenged height is still frozen.
4. **respond (by resubmit)** — there is no separate respond trigger: the
   operator answers a challenge by re-submitting the identical root inside
   the window (bond waived for the sitting candidate owner). Success
   unfreezes and confiscates exactly the recorded challenger bond (zeroing
   both its ledger keys); an impostor resubmit bounces `not operator`. If
   nobody responds in time, finalize marks the height permanently failed
   (`frozen = 2`), clears its roots, rolls `last_locked` back to h−1,
   confiscates the submit bond — split **50/50**: half accrues to the
   challenger as `{claim: "slash"}`, half stays burned in the pot — and
   restarts the stability clock; the challenger also recovers its own bond
   through `{claim: "bond"}`.
5. **finalize** — after a clean 3600 s window the root becomes the withdrawal
   basis (`last_finalized`), strictly in height order; the submit bond is
   released to its holder and a 20 000-byte race reward accrues to the
   first-stable submitter (`{claim: "reward"}` pays once and zeroes the
   ledger).
   - a withdrawal carries `{amount, withdrawn, leaf_account, collateral,
     perp, proof[], perp_amount?}`;
   - `perp_amount` (optional) claims LESS than the full unclaimed PERP
     remainder — collateral-only exits no longer force-drain the proven
     balance; default remains the full remainder;
   - the AA recomputes
     `sha256("acct:"‖address‖":"‖collateral‖":"‖perp‖":"‖withdrawn)` and
     folds the sibling path, requiring the result to equal
     `var['aa_root_' ‖ last_finalized]`;
   - `leaf_account == trigger.address` (you can only prove your own address);
   - the sibling path folds via a fixed-depth `reduce(..., 16, ...)`, so
     proofs cover trees of up to 2^16 accounts;
   - withdrawals are **anti-replay via the proven W**: global cumulative
     markers `wd_<addr>` / `wp_<addr>` cap total collateral / PERP ever
     withdrawn (across ALL heights) at the leaf's committed `W` /
     `perp` balance — replays at any height bounce.
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
   which the challenger recovers its recorded bond via `{claim: "bond"}` — a
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
4. **Deposit endorsements are self-attested on the replay path.** The
   operator's batch replay injects `deposits_allowed` entries keyed by the
   Obyte deposit unit; a watcher replaying `temp_data` cannot independently
   verify that each credited unit actually paid the vault AA. A lying
   operator can mint fake deposits, but this is detectable by watchers (the
   unit ids are on-chain) and punishable through challenge — detection
   relies on live watchers, not cryptography.
5. **Execution order is UnitId-lexicographic, hence grindable.** Users can
   sign many candidate units and pick the id that lands first in the total
   order (queue-jumping MEV). Commit-reveal ordering is future work; the
   fee race and deterministic matching bound but do not eliminate it.
6. **Orphan eviction is arrival-order sensitive under open gossip.** The
   smallest-id eviction rule is deterministic per replica, but a future
   permissionless P2P layer should switch to salted eviction
   (`argmin(sha256(last_finalized_root ‖ id))`) or cross-node orphan sync;
   today's single-operator deployment has no orphan-storm attack surface.
7. **Burned PERP stays stranded in the vault AA.** Burns decrement
   `perp_supply` but the corresponding tokens remain escrowed (the AA is
   permanently over-collateralized) — auditors must treat
   `vault holdings − perp_supply` as the cumulative burn figure.
8. Failed heights roll back cleanly and are re-lockable (`frozen = 2`
   recovery), but recovery depends on operators resubmitting corrected
   batches; there is no trustless escape hatch if every operator disappears.
9. The AA has had no formal security audit; Oscript's complexity budget is
   effectively exhausted, so every further change must free equal budget
   first.
10. **The aa-tree depth cap bounds withdrawals to 2^16 accounts** per tree
   (`MAX_AA_TREE_DEPTH = 16`, mirroring the AA's `reduce(..., 16, ...)`);
   beyond that, proof generation refuses rather than truncate silently.
11. **Replay-dedup windows are bounded at 256 heights.** Withdrawal-ledger,
   seen-AA-unit and gov-nonce pruning keep memory bounded; a duplicate op
   arriving more than 256 heights after its original escapes sidechain dedup
   (AA-side global `wd_`/`wp_` caps still hold). Gov nonces additionally use
   a strict watermark: an out-of-order lower nonce is rejected permanently.

Recently closed: deposit whitelisting, overflow guards, market whitelist,
strict signatures, orphan recovery with deterministic eviction plus a
missing-parent reverse index, bounded logs, realized-PnL settlement into
collateral (profitable withdrawals), bond-registered oracle medians with
deviation caps, peer-to-peer funding with collateral-aware clamps,
multi-operator fee race hardened with transferable submit bonds (consolation
prizes removed), operator identity gate on `respond`, Final-status promotion,
on-chain batch data poster, non-head cancel depth correctness **and deque
ghost removal**, maker-queue pop regression, proof-withdrawal decoupled from
the diagnostic `bal_` ledger, height-bound `state_root` (meta leaf commits
the batch height, marks and funding indices), full book commitment, global
cumulative withdraw anti-replay (`W` committed inside every aa-tree leaf),
bond recovery via claim (frozen-height gating), bounded withdrawals/
AA-unit/gov-nonce ledgers (256-height replay window), flip-order initial-margin
gate on open quantity, create-market bps ceilings, tick-size enforcement,
applied-only `seq` accounting, self-trade cancel-maker continuation,
taker AND maker bad-debt clamping into the insurance fund, proposal cleanup
with creation-time voting-weight snapshots, Obyte-address binding on
deposits (`addr` field, first-seen-wins), asset-kind-bound deposit
endorsements, `MAX_AA_TREE_DEPTH` proof cap, AA-side claim-reward zeroing,
single-outstanding challenge bonds, and `frozen == 2` height recovery —
plus PERP governance: sidechain-mirrored PERP deposits/withdrawals (perp
fields in both Merkle leaves), permissionless market listing with burned
listing fees (per-market risk params), and on-chain parameter proposals with
snapshot quorum and snapshot-weighted voting.
## Mainnet Roadmap (designs ready)

The 11 gaps above each have a concrete design in [`docs/mainnet/`](docs/mainnet/) (516–591 lines each, 5.2k lines total) — no code edits yet, staged as v1 boring + v2 extensions:

 - [x] **01 Fraud slashing** — `01-fraud-slashing.md`: 50%/50% burn/reward split + `validity_proof_hash` plug, no matcher re-execution in Oscript *(Gate2: `Checkpoint.validity_proof_hash`, AA failed-finalize splits the submit bond into `slash_reward_` + burned half)*
 - [x] **02 Deposit independent verification** — `02-deposit-independent-verification.md`: `temp_data.deposit_evidences` carries Obyte joints, `object_hash.js` recomputed in `validate_against` via `operp-settle::obyte_hash` (`getUnitHash` port) *(Gate2)*
 - [x] **03 Commit-reveal ordering (v1)** — salted ordering `sha256(salt‖unit_id)` shipped; v2 commit-reveal additive remains open *(Gate3: `ready_linearized_with_salt`)*
 - [x] **04 Salted orphan eviction** — `argmin sha256(salt‖unit_id)` + `Engine::note_finalized` rotating `Dag::set_eviction_salt`; WantUnits gossip deferred *(Gate3)*
 - [x] **05 Oracle slashing + TWAP** — 50k PERP stake/unstake(256-height unbond)/slash, TWAP rings, 500 bps ×3-streak double condition, `SlashOracle` tag 16, height-gated *(Gate2)*
 - [x] **06 Funding external anchor (mechanism)** — funding-index abstraction with activation gate (`FUNDING_TWAP_ACTIVATION_HEIGHT`); external source feed wiring is operator-side and remains open *(Gate2)*
 - [ ] **07 Escape hatch** — **deferred to v2**: Oscript complexity budget (94/100 after Steps 6–8) cannot fit `escape_finalize`/`escape_withdraw`; requires the lock-merge refactor below first
 - [x] **08 Burn accounting (Rust + checkpoint)** — `perp_burned` in `meta_leaf`, emitted via `Checkpoint.perp_burned` / `temp_data`; AA-side mirror vars dropped for budget, `holdings−supply==burned` stays watcher-verifiable
 - [x] **09 Complexity audit** — R1 single-sha256 fold, unified claim dispatcher (`claim:'kind'`), `bal_`/`pperp_` ledgers deleted; probe: `node tools/check_aa_complexity.js`. Current **94/100** (ops 967/2000)
 - [ ] **10 AA-tree sharding** — `10-aa-tree-sharding.md`: v1 16→18 (262k accounts, 0 new vars), v2 S=16×D16=1M sharded forest
- [x] **11 Replay persistence (v1)** — `11-replay-persistence.md`: `256→2048` constants + generalized pruning *(Gate1)*; **now** `GovNonceJournal` WAL — fsync-before-watermark in `gov_withdraw`, max-merge on restart — plus bincode snapshots `chainstate.<height>.snap` via `Engine::load_or_genesis` / `flush_snapshot` / `maybe_flush_snapshot` (every 64 heights). RocksDB (`persist-rocksdb`) stays v1.1

**Gate2/3 known deviations (v2 backlog):**
- **Replay window 256→2048**: constants shipped (`REPLAY_WINDOW`,
  `REPLAY_ACTIVATION_HEIGHT`) and pruning generalized to `prune_*_at(window)`;
  activation height stays at `1_000_000` so existing tests replay legacy
  determinism. Flip the constant at deploy.
- **Escape hatch**: deferred (see gap 07). The respond path is now
  *respond-by-resubmit* — the operator answers a challenge by re-submitting
  the identical root; impostors bounce `not operator` in submit init.
- **Claim API break**: `{claim_reward|claim_bond|claim_submit_bond}` booleans
  are replaced by a single `{claim: "reward"|"bond"|"sbond"|"slash"}` field;
  `post_batch.js` / `test_vault_aa.js` migrated in-tree.
- **AA tree depth stays 16** (65k accounts/tree); the planned 16→18 bump was
  reverted to fit the complexity budget — pair it with sharding (10-v2).
- **Proposal table capped at 64 concurrent** (`create_proposal` → `Risk`),
  closing the unbounded-state DoS.

See [`docs/mainnet/README.md`](docs/mainnet/README.md) for the 11-doc index and staging plan. Next: implement per doc in isolated worktrees, gated by the same `cargo test` + `test_vault_aa.js` + `bench_raw` as the security-fix batch (`53106c2`).

See the commit history for the full security-audit remediation this repo
went through (proof-gated withdrawals, deposit whitelisting, overflow
guards, market whitelist, strict signatures, orphan recovery, bounded logs,
keeper rewards, bad-debt socialization).


## License

MIT
