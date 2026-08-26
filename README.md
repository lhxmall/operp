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
| `operp-gossip` | WantUnits/HaveUnits on-demand orphan sync between operators (pure P2P layer, transport-agnostic, never consensus) |

## Protocol principles

### 1. One DAG, one total order

Every user action is a signed **unit** referencing up to 2 parent units. The
engine executes pending units in ascending `unit_id` order — a canonical,
deterministic total order any replica can reproduce without consensus
traffic. Out-of-order delivery is tolerated: units whose parents are unknown
are buffered (cap 4096, evicted in salted order `argmin(sha256(salt ‖ id))`
— the salt derives from the last finalized root and rotates each ordering
epoch), duplicate retries carrying different canonical bytes under one id
are rejected (`DagError::RetryMismatch`), and Deposit/GovDeposit addresses
are capped at 128 chars (`DagError::AddrTooLong`) before any buffering.
Missing units can be recovered on demand through the WantUnits/HaveUnits
gossip layer (`operp-gossip`), which serves both linked units and buffered
orphans without touching consensus.

Signatures use ed25519 **strict verification** (rejects malleable
signatures). Every op binds its owner's key: deposits, orders and cancels
must be signed by their account; liquidations must be signed by the *keeper*
(`Op::Liquidate { caller, .. }`), which makes self-liquidation impossible.

Default ordering stays UnitId-lexicographic; an additive v2 commit-reveal
path (`Op::Commit` / `Op::Reveal`, activation-gated) lets users blind-order
to dodge MEV once enabled — see [Limitations](#limitations--mainnet-readiness).

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
- minimal manipulation resistance; oracle/funding TWAP rings and
deviation-streak slashing are live (activation-gated), external anchors are
opt-in.

### 4. Settlement: two roots per batch

Every batch (~512 units / 2 s) produces a `Checkpoint`:

```text
{ height, prev_state_hash, state_root, aa_root, last_unit, seq,
  unit_ids, fills_hash, fill_count }
```

  - `state_root` — Merkle tree over account leaves, book leaves and a meta leaf
  that commits `height`, `seq`, `last_unit`, governance cursors, every
  market's `(mark, funding index)` plus its TWAP rings, the full oracle set
  (bonds, unbonding queue, latest reports, per-reporter history, slash
  nonce, per-market configs), open proposals with their voting snapshots,
  mirrored PERP balances/supply/burns, pending commit-reveal commitments,
  the external-price ring and allowlist, and the funding-source selector —
  replays cannot diverge on any consensus state outside the account tree.
  Roots chain across batches and reorgs break the hash chain visibly.
  Only *applied* units advance the global `seq`; rejected ops do not consume
  sequence numbers.
  - `aa_root` — a second commitment over hex strings, packaged as a
  **16-tree sharded forest**: accounts are partitioned into 16 shards by
  address; within a shard
  `leaf = sha256("acct:" + address + ":" + collateral + ":" + perp + ":" +
  withdrawn)`, `node = sha256(left ‖ right)`; each batch posts all 16 shard
  roots concatenated into ONE 1024-hex `aa_forest` string that fits
  Oscript's `MAX_STATE_VAR_VALUE_LENGTH` exactly. This exists because
  Oscript's `sha256()` hashes UTF-8 text; the vault AA folds a withdrawal
  proof inside its claimed shard and extracts that shard's root via
  substring — committing exactly the same balances, including `W`, the
  account's cumulative sidechain-withdrawal total that backs the AA-side
  anti-replay cap. Empty shards commit a sentinel root
  (`hex(sha256("empty:<shard>"))`) so zero-proofs cannot hop shards. Only
  accounts bound to an Obyte address (via `Op::Deposit { addr }` /
  `Op::GovDeposit { addr }`, ≤ 128 chars) enter the forest; the binding is
  first-seen-wins and enforced at intake.
  `Batch::validate_against` additionally verifies the recomputed forest
  against the checkpoint.
- `fills_hash`/`fill_count` — commitment to executed trade flow.

`Batch::validate_against` replays the posted units through a fresh engine
and asserts chain id, previous root, recomputed fills hash/count, final
root. It also **verifies deposit evidences independently**: any
Deposit/GovDeposit in the batch must carry evidence whose Obyte joint is
re-hashed (`get_unit_hash`) and checked to have actually paid the expected
vault address the claimed amount in the claimed asset (`verify_all` with
the vault address and PERP asset id as caller-supplied bindings; watchers
recover evidences from the revealed `temp_data` via
`evidences_from_payload`). The replayed state is pruned with the same
window rules as batch application before roots are compared — any honest
replica can audit the operator.

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
   (`OBYTE_STABILITY_SECS`) and only while the candidate's submit-bond
   holder record (`active_bond_<h>`) is present: a failed finalize
   confiscates and zeroes it, so a rolled-back height cannot be re-locked
   until a fresh bonded submit recreates the candidate. Locking clears a
   previous permanent-failure mark, so a challenge-failed (`frozen = 2`)
   height recovers by fresh submission instead of wedging the chain. Locked
   roots are immutable.
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
     perp, shard, proof[], perp_amount?}`;
   - `perp_amount` (optional) claims LESS than the full unclaimed PERP
     remainder — collateral-only exits no longer force-drain the proven
     balance; default remains the full remainder;
   - `shard` (0..15) selects which committed shard root the proof must fold
     to; the AA extracts it from the 1024-hex forest via
     `substring(shard*64, 64)` and trusts only the leaf preimage — a
     mis-claimed shard folds to the wrong root;
   - the AA recomputes
     `sha256("acct:"‖address‖":"‖collateral‖":"‖perp‖":"‖withdrawn)` and
     folds the sibling path, requiring the result to equal the claimed
     shard's root of `var['aa_root_' ‖ last_finalized]`;
   - `leaf_account == trigger.address` (you can only prove your own address);
   - the sibling path folds via a fixed-depth `reduce(..., 16, ...)`, so each
     proof covers a shard tree of up to 2^16 accounts (16 shards ≈ 1M
     accounts per batch commitment); empty-shard sentinel roots keep
     zero-proofs from hopping shards.
   - withdrawals are **anti-replay via the proven W**: global cumulative
     markers `wd_<addr>` / `wp_<addr>` cap total collateral / PERP ever
     withdrawn (across ALL heights) at the leaf's committed `W` /
     `perp` balance — replays at any height bounce.
   Balance authority is the **proven leaf**, never mutable AA variables.
6. **escape hatch** — if finalization stalls entirely (every operator
   disappears), `{escape_finalize: 1}` stall-finalizes the oldest locked
   height after `ESCAPE_STALL_SECS` (7 days mainnet, timetravel on devnet;
   any caller; never overrides a live challenge — frozen heights must go
   through the normal failure sweep so the challenger is refunded), and
   `{escape_withdraw: 1, ...claim fields}` pays a proof against the *stale
   candidate's* forest at `h = last_finalized + 1` when that height was
   never locked or was rolled back `frozen = 2`. Both entries share the
   withdraw path's `wd_`/`wp_` anti-replay keys. Per the doc 07 §4 waiver,
   escape_finalize enforces only the local stall gate.

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
crates/                  Rust workspace (8 crates, see table above)
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

## Build prerequisites

- Rust >= **1.85** (the workspace pins `rust-version = "1.85"`; install via
  [rustup](https://rustup.rs): `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`)

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
   detected fraud triggers challenge → freeze → height rollback with the
   50/50 submit-bond slash (`{claim: "slash"}` half, burned half). Deposit
   endorsements are now verified cryptographically inside
   `validate_against`, not taken on faith. What remains out of reach:
   Oscript cannot re-run the matcher on-chain and there is no validity
   proof, so enforcement of non-deposit state still relies on live watchers
   plus competing operators.
2. **Funding quality is bounded by its price anchor.** Funding stays
   mark-premium based (capped ±50 bps/tick). The default
   `BondedMedianTwap` index derives from bonded reporters' prices; the
   external-anchor wiring has landed (`Op::UpdateExternalPrice`, tag 17,
   allowlist-gated, `AggregatedExternal` mode with staleness fallback
   external TWAP → bonded-median TWAP → instant median), but it only helps
   once governance enables the mode and allowlisted keepers actually feed
   it.
3. **Oracle manipulation needs a bond majority.** Reporting is
   permissionless against a 50 000 PERP bond; slashing for TWAP-streak
   deviations has shipped (height-gated), but a colluding bond majority can
   still bias the median mark between slashes; TWAP smoothing dampens, not
   removes, this.
4. **Default execution order is UnitId-lexicographic, hence grindable**
   (queue-jumping MEV). The v2 commit-reveal path has landed additively
   (`Op::Commit`/`Op::Reveal`, tags 18/19, TTL 16 heights, 8 live commits
   per account, `reveal_commit_hash = sha256(op_bytes ‖ salt)`), but it is
   activation-gated like the other v2 paths — until the activation height
   flips, ordering is unchanged. The fee race and deterministic matching
   bound what grinding can extract either way.
5. **Orphan eviction leaves a transient fork window across replicas.**
   Eviction salts rotate per epoch from `(finalized_root, epoch)`, but
   replicas that observe finalization at different times may evict
   different buffered orphans before converging; the DA layer self-heals —
   a `temp_data` full replay reconstructs missing units deterministically,
   and WantUnits gossip fetches them peer-to-peer. (The salt deliberately
   does NOT order execution anymore — see #13.)
6. **Burned PERP stays stranded in the vault AA.** Burns decrement
   `perp_supply` but the corresponding tokens remain escrowed (the AA is
   permanently over-collateralized) — auditors must treat
   `vault holdings − perp_supply` as the cumulative burn figure.
7. **The sitting operator resets the stability timer for free.** Every
   resubmit restarts the 600 s clock at zero cost to the incumbent
   (`active_bond_` stays theirs). This is an accepted liveness tradeoff:
   it delays only their own height, and any competitor can spend the
   50 000-byte bond to take the height over.
8. The AA has had no formal security audit. The Oscript complexity gate
   sits exactly at its ceiling (**85/100**, ops 1075/2000 — run
   `node tools/check_aa_complexity.js`), so every further AA change must
   free equal budget first.
9. **Replay-dedup windows are height-bounded** — legacy 256 heights,
   expanding to `REPLAY_WINDOW = 2048` once `state.height ≥
   REPLAY_ACTIVATION_HEIGHT` (1 000 000; flip at deploy). A duplicate op
   arriving outside the window escapes sidechain dedup (AA-side global
   `wd_`/`wp_` caps still hold). Gov nonces additionally use a strict
   watermark journalled to disk at batch commit (see #14), so an
   out-of-order lower nonce is rejected permanently — including across
   restarts.
10. AA enforces `amount + wd_ <= min(collateral, withdrawn)`, and leaf
    numeric fields are capped at 15 decimal digits (< 2^53).
11. Single-account shard proof generation requires registering PAD decoy
    bindings first, else `aa_sharded_proof_for_account` returns `None`.
12. Batch JSON `perp_burned` is a decimal string.
13. Execution order is currently deterministic lex order; the salt is used
    only for orphan eviction. Salted execution order returns after the
    finalize-batch determinization design lands.
14. Gov nonce WAL persists at batch commit (`from_applied`); uncommitted
    batches do not burn nonces.
15. Snapshots carry a format version header (currently v1); cross-version
    snapshots/journals are incompatible (no migration pre-mainnet).

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

This round closed the remaining audit findings and roadmap gaps: pruning
parity in `validate_against` (withdrawals / seen-AA-units / deposits_allowed
pruned exactly like `from_applied`), independent deposit-evidence
verification inside `validate_against`, epoch-salted orphan eviction
(salt = `sha256(ORDERING_SALT_DOMAIN ‖ root ‖ epoch_le)`; execution order
desalted to deterministic lex — Limitations #13), multiply-before-divide
PnL scaling, `RetryMismatch`/`AddrTooLong` DAG guards, meta-leaf
commitment expansion over all consensus maps (a breaking `state_root`
format change), canonical `data_hash`/`data_length` unified across Rust and
JS via ocore `getJsonSource`, deposit evidences carrying the full joint
unit, fail-fast on unset `PERP_ASSET_ID`, the lock bond gate
(`active_bond_` presence), the sharded aa-forest, `escape_finalize`/
`escape_withdraw`, commit-reveal v2, WantUnits gossip, and the funding
external-anchor wiring.

Post-audit follow-ups restored `{deposit_perp}` crediting (the vault
retains PERP and mirrors it into `pperp_<addr>`; the proven leaf stays the
sole withdrawal authority) and lifted raw engine throughput from 5199 to
7316 ops/s via cached ed25519 key setup plus release LTO.

## Mainnet Roadmap (implemented)

All eleven designs in [`docs/mainnet/`](docs/mainnet/) are now implemented
(staged as v1 boring + v2 extensions; deviations and deferred backlogs are
noted below):

- [x] **01 Fraud slashing** — `01-fraud-slashing.md`: 50%/50% burn/reward split + `validity_proof_hash` plug, no matcher re-execution in Oscript *(AA failed-finalize splits the submit bond into `slash_reward_` + burned half)*
- [x] **02 Deposit independent verification** — `temp_data.deposit_evidences` carries FULL Obyte joint units; `unit_hash(joint)` recomputed inside `validate_against` via `operp_settle::obyte_hash::get_unit_hash`; payee/asset checked against caller-supplied `expected_vault`/`perp_asset`, failures map to `SettleError::DepositEvidence`; watchers rehydrate via `evidences_from_payload`
- [x] **03 Commit-reveal ordering** — v1 salted sort shipped earlier and **desalted this round** (execution order is deterministic lex; the salt remains for orphan eviction only — Limitations #13); **v2 additive landed this round**: `Op::Commit` (tag 18) / `Op::Reveal` (tag 19), TTL `COMMIT_TTL_HEIGHTS = 16`, ≤ 8 live commits/account, `reveal_commit_hash = sha256(inner_op_bytes ‖ salt)`, activation-gated at 1 000 000
- [x] **04 Salted orphan eviction + WantUnits gossip** — `argmin sha256(salt‖unit_id)` with `Engine::note_finalized` rotating the salt per epoch (`sha256(ORDERING_SALT_DOMAIN ‖ root ‖ epoch_le)`); **gossip landed this round**: new `crates/operp-gossip` (WantUnits/HaveUnits, debounced fanout, bounded requests/responses) as a pure operator/P2P layer — wire transport per doc OQ5
- [x] **05 Oracle slashing + TWAP** — 50k PERP stake/unstake (256-height unbond)/slash, TWAP rings, 500 bps ×3-streak double condition, `SlashOracle` tag 16, height-gated
- [x] **06 Funding external anchor** — funding-index abstraction + activation gate shipped earlier; **operator wiring landed this round**: `Op::UpdateExternalPrice` (tag 17), source allowlist, `AggregatedExternal` mode, staleness fallback external TWAP → bonded-median TWAP → instant median (`FUNDING_EXTERNAL_MAX_STALENESS = 32`)
- [x] **07 Escape hatch** — **landed this round**, folded into existing cases for budget: `{escape_finalize: 1}` rides the finalize handler (any caller, `ESCAPE_STALL_SECS = 604800` mainnet / 3600 testnet), `{escape_withdraw: 1}` rides withdraw against the stale candidate's forest at `last_finalized + 1`; deviation per doc07 §4 waiver: escape_finalize enforces only the LOCAL stall gate
- [x] **08 Burn accounting (Rust + checkpoint)** — `perp_burned` in `meta_leaf`, emitted via `Checkpoint.perp_burned` / `temp_data`; AA-side mirror vars dropped for budget, `holdings−supply==burned` stays watcher-verifiable
- [x] **09 Complexity audit** — single-sha256 fold, unified claim dispatcher (`claim:'kind'`), lock-merge refactor; probe: `node tools/check_aa_complexity.js`. Current **85/100** (ops 1075/2000) — exactly at the gate
- [x] **10 AA-tree sharding (v2)** — clean cutover this round: ONE 1024-hex `aa_forest` var = 16 concatenated shard roots (fits `MAX_STATE_VAR_VALUE_LENGTH` exactly), empty-shard sentinel roots, depth stays 16 → ~1M accounts/batch; the doc's v1 depth-18 path is superseded per its own OpenQ3
- [x] **11 Replay persistence (v1)** — `256→2048` constants + generalized pruning; `GovNonceJournal` WAL — flushed at batch commit (`Batch::from_applied`), max-merge on restart — plus versioned bincode snapshots `chainstate.<height>.snap` via `Engine::load_or_genesis` / `flush_snapshot` / `maybe_flush_snapshot` (every 64 heights). RocksDB (`persist-rocksdb`) stays doc-declared v1.1 backlog

**Known deviations / deferred backlog:**

- **Replay window 256→2048**: shipped but activation-gated
  (`REPLAY_WINDOW`, `REPLAY_ACTIVATION_HEIGHT` at 1 000 000) so existing
  tests replay legacy determinism. Flip the constant at deploy.
- **Escape hatch**: shipped (see 07). The respond path remains
  *respond-by-resubmit* — the operator answers a challenge by re-submitting
  the identical root; impostors bounce `not operator` in submit init.
- **Claim API break**: `{claim_reward|claim_bond|claim_submit_bond}` booleans
  are replaced by a single `{claim: "reward"|"bond"|"sbond"|"slash"}` field;
  `post_batch.js` / `test_vault_aa.js` migrated in-tree.
- **Per-shard depth stays 16**: sharding v2 delivers ~1M accounts/batch at
  depth 16 per shard; the planned global 16→18 bump stays superseded.
- **Proposal table capped at 64 concurrent** (`create_proposal` → `Risk`),
  closing the unbounded-state DoS.

See [`docs/mainnet/README.md`](docs/mainnet/README.md) for the 11-doc index.
Validation gates for every item above: `cargo test --workspace`,
`cd obyte-local && node tools/check_aa_complexity.js` (≤85),
`node test_vault_aa.js`, and `cargo run --release -p operp-exec --example
bench_raw`.

See the commit history for the full security-audit remediation this repo
went through (proof-gated withdrawals, deposit whitelisting, overflow
guards, market whitelist, strict signatures, orphan recovery, bounded logs,
keeper rewards, bad-debt socialization).


## License

MIT
