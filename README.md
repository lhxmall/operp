English | [简体中文](README.zh-CN.md)

# OPERP — Optimistic DAG Sidechain Perpetual DEX settling to Obyte

OPERP is a research/MVP implementation of a **perpetual futures exchange** that
executes trades on a high-throughput optimistic DAG sidechain and settles
periodic state roots to the [Obyte](https://obyte.org) ledger through an
autonomous agent (AA) vault. Withdrawals from the vault are **proof-gated**:
users must present a Merkle proof of their balance against a finalized root.

> **Status: settlement v2 landed, mainnet not yet deployed.** Workspace tests
> green; devnet E2E (`test_settlement_aa.js`) covers submit → predicate fraud
> → finalize → proof withdrawal. Mainnet script: `deploy_mainnet.js`
> (mnemonic required); fund users only after an AA audit and an independent watcher.

```
cargo test --workspace          # all green
cargo run --release -p operp-exec --example bench_raw        # ~5.5k ops/s
cargo run --release -p operp-exec --example hft_onedag -- 20000 8 4   # ~9k TPS, 0 rejects
cd obyte-local && node test_settlement_aa.js  # Linux/CI: three-AA lifecycle (win32 skips)
cd obyte-local && node deploy_mainnet.js      # deploy the four AAs (needs OPERP_DEPLOY_MNEMONIC)
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
                    │  OBYTE SETTLEMENT (Oscript, CHAIN_ID=operp-v2)│
                    │  rollup  submit/finalize/force/verdict      │
                    │  dispute one-shot predicates (deposits/     │
                    │  omissions/fills/ghost/skip)                │
                    │  vault   custody only: deposit / withdraw   │
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
| `operp-dag` | Unit DAG with signature verification (`verify_strict`), orphan buffer (4096 cap, salted eviction), lexicographic linearization (`ready_linearized`; salt is eviction-only) |
| `operp-exec` | The engine: ingest → apply → events; place/cancel/deposit/withdraw/liquidate with full intake validation |
| `operp-settle` | Batch checkpoints, `validate_against` replay verification, `temp_data` payloads, proof generation |
| `operp-gossip` | WantUnits/HaveUnits on-demand orphan sync between operators (pure P2P layer, transport-agnostic, never consensus) |
| `operp-watch` | Independent rollup watcher: replays `da_unit_<h>`, builds predicate `proof.json`, posts via `post_challenge.js` (separate key from the poster) |

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

### 5. Settlement AAs: optimistic finality + proof-gated exits

Three AAs (`CHAIN_ID=operp-v2`). **No lock, no pay-to-kill.** Collateral is GBYTE.

1. **submit (rollup)** — combined unit `temp_data` + `{submit, height, roots,
   trace/units/ops/fills roots}` with the 1000 GBYTE submit bond.
   `h == last_submitted+1`; an occupied, un-failed height bounces
   `height taken`. Window: `submitted_at + 3600 s`.
2. **Fraud (dispute / dispute_fill)** — inside the window anyone submits a
   one-shot predicate (deposit/withdraw/omit/fill_math/ghost/skip). Failing
   predicates bounce `no fraud` and leave the height alone; a proven one
   forwards `{verdict:'fraud'}` and the rollup slashes half the submit bond
   and reopens the height. No response rounds.
3. **finalize (rollup)** — after `submitted_at+3600` with no verdict:
   `last_finalized=h`, bond released, 20 000-byte race reward.
   `{escape_finalize}` remains the 7-day stall hatch.
4. **withdraw (vault)** — reads `var[ROLLUP]['aa_forest_'||last_finalized]`;
   the 16-deep Merkle fold and the W anti-replay cap are unchanged.
   `{escape_withdraw}` still bounces `no escape withdraw`.
5. **force (rollup inbox)** — `{force, unit_id}` censorship escape; omission
   is provable via P-omit.

| Gate | Origin | Duration |
|---|---|---|
| fraud / finalize | `submitted_at_<h>` | 3600 s |
| escape_finalize | `submitted_at_<h>` | 604800 s |

No owner key. Upgrading = deploy new AAs + migrate funds through the same
finalized-root withdrawal path.


## Repository layout

```
crates/                  Rust workspace (9 crates, see table above)
obyte-local/
  agents/operp_vault.aa          custody (deposit/withdraw)
  agents/operp_rollup.aa         assertion chain
  agents/operp_dispute.aa        deposit/withdraw/omit predicates
  agents/operp_dispute_fill.aa   fill predicates
  test_settlement_aa.js          three-AA E2E (Linux/CI; win32 skips)
  deploy_mainnet.js / issue_perp.js  mainnet AA deploy / PERP issuance
  post_batch.js                  combined temp_data+submit → finalize → claim
  post_challenge.js              predicate CLI (`--pred --proof`)
docs/PROTOCOL.md / MECHANISMS.md / ROLLUP-UPGRADE.md
```

## Build prerequisites

- Rust >= **1.85** (the workspace pins `rust-version = "1.85"`; install via
  [rustup](https://rustup.rs): `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`)
- Node.js >= 20 (for `obyte-local` scripts and AA devnet E2E)
- On Windows, a C++ toolchain for native `rocksdb`/`sqlite3` (required by
  the vendored aa-testkit): install [Visual Studio Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/)
  with the **"Desktop development with C++"** workload, then `npm install`
  in `obyte-local` and `vendor/aa-testkit` will succeed; without it
  `node-gyp` reports `find VS` failure and the E2E cannot run

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

# AA lifecycle on local devnet (needs node + a C++ toolchain for the
# vendored aa-testkit's native rocksdb/sqlite3; see Verification status)
cd obyte-local && node test_vault_aa.js

# deploy the vault AA to Obyte testnet
cd obyte-local && node deploy_testnet.js

# operator flow: post ONE combined temp_data+submit unit + lock +
# finalize + claim race reward (the complete mainnet sequence)
cd obyte-local && node post_batch.js
Measured on this machine: `bench_raw` ≈ 5 500 ops/s; `hft_onedag` (8 markets,
4 generators) ≈ 9 000–9 200 TPS aggregate with zero rejections.

## Limitations & mainnet readiness

This codebase meets the plan's bar of *"deployable to Obyte testnet"*. It is
**not mainnet-ready**. Known gaps, roughly in priority order:

1. ~~**Money can kill an honest root.**~~ **RESOLVED (settlement v2).** Fraud
   must pass a dispute predicate; `{challenge:1}` has no case on rollup or
   vault. Bogus proofs bounce `no fraud`. Still open: the insurance clamp is
   not on-chain verifiable; fill_math carries a ±1 tolerance; `temp_data`
   bodies vanish after 24 h; deposit joints are mainly checked off-chain in
   `validate_against` (an empty `OPERP_VAULT_AA` with evidences present is
   rejected).
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
   deviations has shipped (live at height 0), but a colluding bond majority can
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
7. ~~**The sitting operator resets the stability timer for free.**~~
   **RESOLVED**: single-candidate combined units; further submits bounce
   `height taken`; only a proven fraud reopens the height.
8. No formal AA audit. Every AA must stay ≤100 complexity (fill AA ≈ 21).
   Probe: `node obyte-local/tools/check_aa_complexity.js agents/*.aa`.
9. **Replay-dedup window is 2048** (`REPLAY_ACTIVATION_HEIGHT = 0`).
   Duplicates outside the window escape sidechain dedup; AA-side `wd_`/`wp_`
   caps still hold.
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
- [x] **03 Commit-reveal ordering** — v1 salted sort shipped earlier and **desalted this round** (execution order is deterministic lex; the salt remains for orphan eviction only — Limitations #13); **v2 additive landed this round**: `Op::Commit` (tag 18) / `Op::Reveal` (tag 19), TTL `COMMIT_TTL_HEIGHTS = 16`, ≤ 8 live commits/account, `reveal_commit_hash = sha256(inner_op_bytes ‖ salt)`, live at height 0
- [x] **04 Salted orphan eviction + WantUnits gossip** — `argmin sha256(salt‖unit_id)` with `Engine::note_finalized` rotating the salt per epoch (`sha256(ORDERING_SALT_DOMAIN ‖ root ‖ epoch_le)`); **gossip landed this round**: new `crates/operp-gossip` (WantUnits/HaveUnits, debounced fanout, bounded requests/responses) as a pure operator/P2P layer — wire transport per doc OQ5
- [x] **05 Oracle slashing + TWAP** — 50k PERP stake/unstake (256-height unbond)/slash, TWAP rings, 500 bps ×3-streak double condition, `SlashOracle` tag 16, live at height 0
- [x] **06 Funding external anchor** — funding-index abstraction + activation height 0 (live at genesis); **operator wiring landed this round**: `Op::UpdateExternalPrice` (tag 17), source allowlist, `AggregatedExternal` mode, staleness fallback external TWAP → bonded-median TWAP → instant median (`FUNDING_EXTERNAL_MAX_STALENESS = 32`)
- [x] **07 Escape hatch** — **landed this round**, folded into existing cases for budget: `{escape_finalize: 1}` rides the finalize handler (any caller, `ESCAPE_STALL_SECS = 604800` mainnet / 3600 testnet), `{escape_withdraw}` removed (bounces `no escape withdraw`); deviation per doc07 §4 waiver: escape_finalize enforces only the LOCAL stall gate
- [x] **08 Burn accounting (Rust + checkpoint)** — `perp_burned` in `meta_leaf`, emitted via `Checkpoint.perp_burned` / `temp_data`; AA-side mirror vars dropped for budget, `holdings−supply==burned` stays watcher-verifiable
- [x] **09 Complexity audit** — single-sha256 fold, unified claim dispatcher (`claim:'kind'`), lock-merge refactor; probe: `node tools/check_aa_complexity.js`. Current **76/100** (ops 976/2000) — ≤85 gate
- [x] **10 AA-tree sharding (v2)** — clean cutover this round: ONE 1024-hex `aa_forest` var = 16 concatenated shard roots (fits `MAX_STATE_VAR_VALUE_LENGTH` exactly), empty-shard sentinel roots, depth stays 16 → ~1M accounts/batch; the doc's v1 depth-18 path is superseded per its own OpenQ3
- [x] **11 Replay persistence (v1)** — `256→2048` constants + generalized pruning; `GovNonceJournal` WAL — flushed at batch commit (`Batch::from_applied`), max-merge on restart — plus versioned bincode snapshots `chainstate.<height>.snap` via `Engine::load_or_genesis` / `flush_snapshot` / `maybe_flush_snapshot` (every 64 heights). RocksDB (`persist-rocksdb`) stays doc-declared v1.1 backlog

**Known deviations / deferred backlog:**

- **Replay window 2048** is live from height 0 (`REPLAY_ACTIVATION_HEIGHT = 0`).
- **Settlement v2**: no lock / no pay-to-kill; predicate fraud; claims live on
  the rollup AA (`reward|sbond|slash`).
- **Per-shard depth stays 16**; the proposal table is capped at 64 concurrent.

See [`docs/mainnet/`](docs/mainnet/) (historical 11 docs) and
[ROLLUP-UPGRADE.md](docs/ROLLUP-UPGRADE.md). Validation:
`cargo test --workspace`, `check_aa_complexity.js`,
`node test_settlement_aa.js` (Linux/CI).

## Verification status

* **CI** runs workspace tests, the four-AA complexity gate, the golden vector,
  and `test_settlement_aa.js` (win32 skips).
* **Watcher:** `operp-watch` builds `proof.json` and posts to the dispute AA
  (`--pred --proof`; requires `OPERP_WATCH_MNEMONIC`, `--vault` and
  `--rollup`). Without a mnemonic it prints alerts only. Use a key separate
  from the poster.

## License

MIT

