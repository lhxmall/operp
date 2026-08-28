"use strict";

// Full vault-AA lifecycle test (security-hardened, sharded-forest AA):
//   deposit -> low-submit bounce ('need submit bond') -> combined
//   temp_data+submit (50000-byte SUBMIT_BOND_NET, da_unit_<h> pinned) ->
//   second submit bounces 'height taken' (single-candidate) -> early lock bounce ->
//   timetravel +600s -> lock -> early withdraw bounce ('not finalizable') ->
//   challenge + immediate {claim_bond} bounce ('challenge unresolved') ->
//   locked-height resubmit bounce ('not operator' when frozen;
//   challenge is post-lock-only, window = stable_at+3600) ->
//   challenge FAILURE path (silence past the window -> finalize sweep:
//   frozen=2, last_locked rollback, challenger bond stays credited, submit
//   bond confiscated, slash reward credited) ->
//   H1 regression: after the WON challenge a direct re-lock without a fresh
//   bonded submit bounces 'cannot lock yet' ->
//   alice reclaims her bond via {claim_bond} ->
//   frozen==2 unlock: resubmit/lock/finalize height 1 with the REAL sharded
//   commitment succeeds ->
//   proof-gated SHARDED withdraw (good proof pays; bad proof bounces;
//   identical replay bounces via the GLOBAL cumulative wd_<addr> cap).
//   All payouts (claim_bond, base withdraw, PERP withdraw) are proven by
//   exact wallet-balance deltas.
//
// All hash-shaped submit fields (state_root / aa_root / prev_state_hash)
// must be exactly 64 hex chars, and aa_forest exactly 1024 hex chars
// (16 concatenated shard roots), per the AA's length gates. Withdrawal
// triggers carry `shard` (0..15) selecting which slice of the committed
// forest the proof must fold to.
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const aaRoot = path.join(__dirname, "..", "vendor", "aa-testkit");
const nm = path.join(aaRoot, "node_modules");
process.env.NODE_PATH = [nm, process.env.NODE_PATH].filter(Boolean).join(path.delimiter);
process.env.devnet = "1";
if (process.env.AA_DEBUG_COMPLEXITY) process.env.MAX_COMPLEXITY = "99999";
require("module").Module._initPaths();

// The vault AA references the PERP governance asset via the literal
// placeholder 'PERP_ASSET_ID_HERE'. Production deploy scripts substitute
// the real asset id. For THIS initial devnet deployment no PERP asset
// exists yet, so we substitute 'base' (always valid at definition-check
// time); base can never reach the perp-deposit branch because that branch
// is keyed on trigger.data.deposit_perp, not deposit. The real PERP-backed
// instance is redeployed inside the PERP section below with the issued
// asset id.
const BOOTSTRAP_AA = path.join(__dirname, "agents", "operp_vault_base.aa");
fs.writeFileSync(
  BOOTSTRAP_AA,
  fs
    .readFileSync(path.join(__dirname, "agents", "operp_vault.aa"), "utf8")
    .replace(/PERP_ASSET_ID_HERE/g, "base")
);

const { generateMnemonic, getFirstAddress } = require(path.join(aaRoot, "src", "utils"));
const ALICE_MNEMONIC = generateMnemonic();
const BOB_MNEMONIC = generateMnemonic();
const { Testkit } = require(path.join(aaRoot, "main.js"));
const { Network } = Testkit({
  TESTDATA_DIR: path.join(__dirname, "testdata"),
  NETWORK_PORT: 16612,
});

function sha256Hex(s) {
  return crypto.createHash("sha256").update(s, "utf8").digest("hex");
}

// Deterministic 64-hex stand-ins for the committed roots (the AA gates every
// submit field on length == 64, so plain labels like "rootCAND1" bounce).
const ROOT_CAND1 = sha256Hex("rootCAND1");
const ROOT_FINAL1 = sha256Hex("rootFINAL1");
const PREV0 = sha256Hex("prev0");
// 1024-hex stand-in forest for the placeholder first candidate (16 x 64
// hex, exactly what the AA's length gate expects; never proven against).
const FOREST_CAND1 = sha256Hex("aacand1").repeat(16);

async function trigger(wallet, data, amount) {

  const { unit, error } = await wallet.triggerAaWithData({
    toAddress: network.agent.vault,
    amount: amount === undefined ? 10000 : amount,
    data,
  });
  if (error) throw new Error(JSON.stringify(data).slice(0, 60) + ": " + error);
  await network.witnessUntilStable(unit);
  return unit;
}

async function vars() {
  const v = await network.wallet.alice.readAAStateVars(network.agent.vault);
  return v.vars || v;
}

async function expectBounce(promiseFn, needle) {
  const res = await promiseFn();
  const bounced =
    (res && res.bounced) ||
    (res && res.response && res.response.bounced) ||
    (res && res.objResponse && res.objResponse.bounced);
  const log = JSON.stringify(res || {});
  if (!bounced) throw new Error("expected bounce containing '" + needle + "', got: " + log.slice(0, 400));
  if (needle && !log.includes(needle))
    throw new Error("bounce reason mismatch: wanted '" + needle + "' in " + log.slice(0, 400));
  console.log("  bounced as expected:", needle);
}

// witnessUntilStable does not surface AA bounces; fetch the AA response instead.
async function triggerRaw(wallet, data, amount) {
  const { unit } = await wallet.triggerAaWithData({
    toAddress: network.agent.vault,
    amount: amount === undefined ? 10000 : amount,
    data,
  });
  await network.witnessUntilStable(unit);
  // network.getAaResponseToUnit resolves { response: { bounced, info, ... } }
  const res = await network.getAaResponseToUnit(unit);
  return { unit, response: (res && res.response) || null };
}

// Combined DA+submit helper: mirrors post_batch.js — temp_data (DA reveal)
// and the submit data message in ONE unit; the AA records da_unit_<h> from
// this unit's hash. First stable combined unit wins the height.
async function sendCombinedSubmit(wallet, amount, submitData, batchData) {
  const tempData = {
    app: "temp_data",
    payload_location: "inline",
    payload: {
      data_length: require("ocore/object_length.js").getLength(batchData, true),
      data_hash: require("ocore/object_hash.js").getBase64Hash(batchData, true),
      data: batchData,
    },
  };
  const r = await wallet.sendMulti({
    messages: [tempData, { app: "data", payload: submitData }],
    base_outputs: [{ address: network.agent.vault, amount }],
  });
  if (r.error) throw new Error("combined submit failed: " + r.error);
  await network.witnessUntilStable(r.unit);
  const res = await network.getAaResponseToUnit(r.unit);
  return { unit: r.unit, response: (res && res.response) || null };
}

// Wallet-balance proof helpers: payout assertions compare real wallet
// balances before/after a trigger, accounting exactly for the attached
// trigger bytes and the miner fee read back from the unit joint.
// ocore/network.js exports no hub in the driver process — read joints
// through the genesis node's getUnitInfo (ocore storage.readJoint) instead.
async function getJoint(unit) {
  const r = await network.genesisNode.getUnitInfo({ unit });
  if (r.error || !r.unitObj) throw new Error("getUnitInfo " + unit + ": " + (r.error || "not found"));
  // getUnitInfo resolves objJoint.unit; wrap it so callers can use j.unit.*.
  return { unit: r.unitObj };
}
async function balances(wallet) {
  // headless-wallet getBalance returns { asset: { stable, effective } }.
  // Use STABLE only: effective already includes pending changes, so mixing
  // them double-counts in-flight units and corrupts exact deltas. Every
  // assertion site witnesses its units to stability first.
  const b = await wallet.getBalance();
  const out = {};
  for (const k of Object.keys(b)) {
    const v = b[k];
    out[k] = typeof v === "object" && v !== null ? Number(v.stable || 0) : Number(v);
  }
  return out;
}
// Send an AA trigger and wait ONLY for the trigger unit's stability (not
// the AA response): callers snapshot balances here to isolate the exact
// trigger bytes + miner fee from the later AA payout.
async function triggerAwaitUnit(wallet, data, amount) {
  const r = await wallet.triggerAaWithData({
    toAddress: network.agent.vault,
    amount: amount === undefined ? 20000 : amount,
    data,
  });
  if (r.error) throw new Error(JSON.stringify(data).slice(0, 60) + ": " + r.error);
  await network.witnessUntilStable(r.unit);
  return r.unit;
}
// Payment legs of a unit live under messages[].payload.{inputs,outputs}
// (ocore unit format), never at the top level.
function paymentPayloads(j) {
  return (j.unit.messages || [])
    .filter((m) => m.app === "payment")
    .map((m) => m.payload || {});
}
// total payout of `asset` ('base' or an asset id) to `address` in a unit.
async function paidToAddress(unit, address, asset) {
  const j = await getJoint(unit);
  // `asset` lives on the PAYLOAD (one asset per payment message), not on
  // individual outputs; base payloads simply omit it.
  return paymentPayloads(j)
    .filter((p) => (asset === "base" ? !p.asset : p.asset === asset))
    .flatMap((p) => p.outputs || [])
    .filter((o) => o.address === address)
    .reduce((s, o) => s + Number(o.amount), 0);
}


// ==================== PERP governance E2E helpers (plan steps 7-8) ====================
//
// Sidechain ops below are signed and encoded byte-for-byte like the Rust DAG
// (crates/operp-dag::canonical_bytes, gov tags 8..13) and serialized exactly
// like serde_json::to_value(&op): externally tagged variant names with
// snake_case fields; AccountId/[u8;N] as arrays of numbers, ints as numbers.
// Nothing on-chain re-verifies these signatures (the AA only commits roots),
// but faithful encoding means a watcher replaying this batch through
// operp-settle accepts it.

// Fallback PERP id (plan Assumptions): a fixed arbitrary id posted manually as
// simulated PERP when the testkit cannot issue a real asset.
const SIMULATED_PERP_ASSET = Buffer.alloc(32, 9).toString("base64");
// Resolved at runtime by resolvePerpAsset(); null -> skip only the PERP section.
let PERP_ASSET = null;

async function resolvePerpAsset(wallet) {
  // 1) real divisible-asset issuance through the vendored testkit
  //    (asset id = the definition unit id, same as NetworkInitializer does)
  try {
    const address = await wallet.getAddress();
    const created = await wallet.createAsset({
      is_private: false,
      is_transferrable: true,
      auto_destroy: false,
      fixed_denominations: false,
      issued_by_definer_only: true,
      cosigned_by_definer: false,
      spender_attested: false,
    });
    if (!created.error && created.unit) {
      await network.witnessUntilStable(created.unit);
      const issued = await wallet.issueDivisibleAsset({
        asset: created.unit,
        paying_addresses: [address],
        fee_paying_addresses: [address],
        change_address: address,
        to_address: address,
        amount: 1e12,
      });
      if (!issued.error && issued.unit) {
        await network.witnessUntilStable(issued.unit);
        console.log("issued PERP asset:", created.unit);
        return created.unit;
      }
      console.log("issueDivisibleAsset failed:", issued.error);
    } else {
      console.log("createAsset failed:", created.error);
    }
  } catch (e) {
    console.log("PERP asset issuance unavailable:", e && e.message ? e.message : e);
  }
  // 2) fallback: any consistent arbitrary id sent via a manual payment
  try {
    const r = await wallet.sendMulti({
      asset: SIMULATED_PERP_ASSET,
      to_address: await wallet.getAddress(),
      amount: 1e12,
    });
    if (!r.error && r.unit) {
      await network.witnessUntilStable(r.unit);
      console.log("using SIMULATED PERP asset:", SIMULATED_PERP_ASSET);
      return SIMULATED_PERP_ASSET;
    }
    console.log("simulated PERP fallback failed:", r.error);
  } catch (e) {
    console.log("simulated PERP fallback unavailable:", e && e.message ? e.message : e);
  }
  return null;
}

function sha256Buf(buf) {
  return crypto.createHash("sha256").update(buf).digest();
}

function ed25519FromSeed(seed) {
  // wrap the raw 32-byte seed in PKCS#8 DER -> node crypto KeyObject
  const der = Buffer.concat([
    Buffer.from("302e020100300506032b657004220420", "hex"),
    seed,
  ]);
  const priv = crypto.createPrivateKey({ key: der, format: "der", type: "pkcs8" });
  const spki = crypto.createPublicKey(priv).export({ format: "der", type: "spki" });
  return { priv, pubkey: spki.subarray(spki.length - 32) };
}

function u32le(n) {
  const b = Buffer.alloc(4);
  b.writeUInt32LE(n);
  return b;
}
function u64le(n) {
  const b = Buffer.alloc(8);
  b.writeBigUInt64LE(BigInt(n));
  return b;
}
function u128le(n) {
  // Node lacks writeBigUInt128LE — emit as two little-endian u64 halves.
  const b = Buffer.alloc(16);
  const v = BigInt(n);
  b.writeBigUInt64LE(v & 0xffffffffffffffffn, 0);
  b.writeBigUInt64LE(v >> 64n, 8);
  return b;
}

// Mirror of operp_dag::canonical_bytes for the gov tags only (trailing pubkey
// appended, exactly like the full match there).
function govCanonicalBytes(parentsHex, opName, f, pubkey) {
  const parts = [Buffer.from("ODX1", "utf8"), Buffer.from([parentsHex.length])];
  for (const p of parentsHex) parts.push(Buffer.from(p, "hex"));
  const tag = {
    GovDeposit: 8,
    GovWithdraw: 9,
    CreateMarket: 10,
    CreateProposal: 11,
    Vote: 12,
    FinalizeProposal: 13,
  }[opName];
  if (tag === undefined) throw new Error("unsupported op " + opName);
  parts.push(Buffer.from([tag]));
  switch (opName) {
    case "GovDeposit": // account, amount u128, aa_unit, addr (u32le len prefix + utf8)
      parts.push(f.account, u128le(f.amount), f.aa_unit, u32le(f.addr.length), Buffer.from(f.addr, "utf8"));
      break;
    case "GovWithdraw": // account, amount u128, nonce u64
      parts.push(f.account, u128le(f.amount), u64le(f.nonce));
      break;
    case "CreateMarket": // creator, symbol[16], tick, im/mm/taker/keeper bps (u64 each)
      parts.push(
        f.creator,
        f.symbol,
        u64le(f.tick_size),
        u64le(f.im_bps),
        u64le(f.mm_bps),
        u64le(f.taker_fee_bps),
        u64le(f.keeper_reward_bps),
      );
      break;
    case "CreateProposal": // creator, market u32, key u8, value u64
      parts.push(f.creator, u32le(f.market), Buffer.from([f.key]), u64le(f.value));
      break;
    case "Vote": // voter, proposal_id u64, approve u8
      parts.push(f.voter, u64le(f.proposal_id), Buffer.from([f.approve ? 1 : 0]));
      break;
    case "FinalizeProposal": // caller, proposal_id u64
      parts.push(f.caller, u64le(f.proposal_id));
      break;
  }
  parts.push(pubkey);
  return Buffer.concat(parts);
}

// Sign one gov op; returns the unit shaped exactly like
// operp_settle::Batch::temp_data_payload emits (serde-faithful op JSON).
function signGovUnit(parentsHex, opName, fieldsBuf, fieldsJson, key) {
  const id = sha256Buf(govCanonicalBytes(parentsHex, opName, fieldsBuf, key.pubkey));
  return {
    parents: parentsHex,
    op: { [opName]: fieldsJson },
    pubkey: key.pubkey.toString("hex"),
    sig: crypto.sign(null, id, key.priv).toString("hex"),
    unit_id: id.toString("hex"),
  };
}

// Hex-domain AA tree mirror of operp_state with the extended
// "acct:{addr}:{collateral}:{perp}:{withdrawn}" leaf
// (aa_leaf/aa_parent/aa_proof_for).
function aaLeafStr(addr, collateral, perp, withdrawn) {
  return sha256Hex("acct:" + addr + ":" + collateral + ":" + perp + ":" + withdrawn);
}
function aaProofFor(pairs, addr) {
  // pairs: [{ addr, collateral, perp, withdrawn }] with decimal-string balances
  const i = pairs.findIndex((p) => p.addr === addr);
  if (i < 0) throw new Error("no aa leaf for " + addr);
  const leaf = aaLeafStr(pairs[i].addr, pairs[i].collateral, pairs[i].perp, pairs[i].withdrawn);
  let level = pairs.map((p) => aaLeafStr(p.addr, p.collateral, p.perp, p.withdrawn)).sort();
  let idx = level.indexOf(leaf);
  const proof = [];
  while (level.length > 1) {
    if (level.length % 2 === 1) level.push(level[level.length - 1]);
    const sib = idx ^ 1;
    proof.push({ hash: level[sib], right: sib > idx });
    const next = [];
    for (let j = 0; j < level.length; j += 2) next.push(sha256Hex(level[j] + level[j + 1]));
    level = next;
    idx >>= 1;
  }
  return { proof, root: level[0] };
}

// ===== Phase 5.2 sharded-forest mirrors of operp_state =====
// shard(addr) = low 4 bits of sha256(addr)[0] (doc 10 §B1(1)); empty shards
// commit DISTINCT sentinels hex(sha256("empty:" + i)) so zero-proofs cannot
// hop shards; the checkpoint's aa_root is the 64-hex sha256 of the whole
// 1024-hex concatenation.
function aaShardOf(addr) {
  return sha256Buf(Buffer.from(addr, "utf8"))[0] & 0x0f;
}
function aaEmptyShardRoot(i) {
  return sha256Hex("empty:" + i);
}
// Root of the hex-domain tree over one shard bucket (mirror of aa_root_of).
function aaRootOf(bucket) {
  let level = bucket.map((p) => aaLeafStr(p.addr, p.collateral, p.perp, p.withdrawn)).sort();
  while (level.length > 1) {
    if (level.length % 2 === 1) level.push(level[level.length - 1]);
    const next = [];
    for (let j = 0; j < level.length; j += 2) next.push(sha256Hex(level[j] + level[j + 1]));
    level = next;
  }
  return level[0];
}
// The 16 per-shard roots: bucket by shard, root each bucket, distinct
// sentinel for empty shards (mirror of aa_sharded_roots_of).
function aaShardedRoots(pairs) {
  const buckets = Array.from({ length: 16 }, () => []);
  for (const p of pairs) buckets[aaShardOf(p.addr)].push(p);
  return buckets.map((b, i) => (b.length ? aaRootOf(b) : aaEmptyShardRoot(i)));
}
function aaForestHash(roots) {
  return sha256Hex(roots.join(""));
}
// Pad `addr`'s shard with deterministic decoy peers until its bucket holds
// >=2 accounts: a singleton bucket would need an EMPTY proof array and ocore
// fatally rejects empty arrays in trigger data (same choice as
// gen_withdraw_proof.rs).
function padBucket(pairs, addr) {
  const out = pairs.slice();
  const shard = aaShardOf(addr);
  let n = 0;
  while (!out.some((p) => p.addr !== addr && aaShardOf(p.addr) === shard)) {
    out.push({ addr: ("PAD" + ++n).padEnd(32, "0"), collateral: "500", perp: "0", withdrawn: "0" });
  }
  return out;
}

// Deterministic replay of exactly the ops posted in section 10, enforcing the
// same preconditions as operp-exec (fee burn, stake threshold, dedup,
// deadline, quorum), so every marker reflects applied state rather than
// wishful printing. Balances/supply are BigInt.
function makePerpEngine() {
  const CREATE_MARKET_FEE = 10000n;
  const PROPOSAL_MIN_STAKE = 1000n;
  const DURATION_SEQS = 20000;
  const QUORUM_NUM = 10n;
  const QUORUM_DEN = 100n;
  return {
    seq: 0,
    supply: 0n,
    bal: new Map(), // acct hex -> BigInt
    seenAaUnits: new Set(),
    markets: new Map(), // id -> params
    nextMarketId: 2, // BTC_USD=1 is genesis
    proposals: new Map(), // id -> proposal
    nextProposalId: 1,
    apply(opName, f) {
      const s = ++this.seq;
      switch (opName) {
        case "GovDeposit":
          if (this.seenAaUnits.has(f.aa_unit_hex)) throw new Error("replayed aa_unit");
          this.seenAaUnits.add(f.aa_unit_hex);
          this.bal.set(f.account_hex, (this.bal.get(f.account_hex) || 0n) + BigInt(f.amount));
          this.supply += BigInt(f.amount);
          return {};
        case "GovWithdraw": {
          const b = this.bal.get(f.account_hex) || 0n;
          const amt = BigInt(f.amount);
          if (b < amt) throw new Error("Insufficient PERP for GovWithdraw");
          this.bal.set(f.account_hex, b - amt);
          this.supply -= amt;
          return {};
        }
        case "CreateMarket": {
          const b = this.bal.get(f.creator_hex) || 0n;
          if (b < CREATE_MARKET_FEE) throw new Error("Insufficient listing fee");
          if (!f.tick_size || !f.im_bps || !f.mm_bps || !f.taker_fee_bps || !f.keeper_reward_bps)
            throw new Error("Risk: zero market parameter");
          this.bal.set(f.creator_hex, b - CREATE_MARKET_FEE);
          this.supply -= CREATE_MARKET_FEE;
          const id = this.nextMarketId++;
          this.markets.set(id, {
            symbol: Buffer.from(f.symbol_bytes).toString("utf8").replace(/\0+$/, ""),
            tick_size: f.tick_size,
            im_bps: f.im_bps,
            mm_bps: f.mm_bps,
            taker_fee_bps: f.taker_fee_bps,
            keeper_reward_bps: f.keeper_reward_bps,
            delisted: false,
          });
          return { market_id: id };
        }
        case "CreateProposal": {
          if (!this.markets.has(f.market)) throw new Error("NoMarket");
          if (f.key === 4 ? f.value !== 0 : f.value > 10000)
            throw new Error("Risk: bad proposal value");
          if ((this.bal.get(f.creator_hex) || 0n) < PROPOSAL_MIN_STAKE)
            throw new Error("Insufficient proposal stake");
          const pid = this.nextProposalId++;
          this.proposals.set(pid, {
            market: f.market,
            key: f.key,
            value: f.value,
            created_seq: s,
            deadline_seq: s + DURATION_SEQS,
            supply_at_create: this.supply,
            yes: 0n,
            no: 0n,
            voted: new Set(),
            finalized: null,
          });
          return { proposal_id: pid };
        }
        case "Vote": {
          const p = this.proposals.get(f.proposal_id);
          if (!p || p.finalized !== null || s >= p.deadline_seq)
            throw new Error("vote closed or unknown proposal");
          if (p.voted.has(f.voter_hex)) throw new Error("duplicate vote");
          p.voted.add(f.voter_hex);
          const w = this.bal.get(f.voter_hex) || 0n;
          if (f.approve) p.yes += w;
          else p.no += w;
          return {};
        }
        case "FinalizeProposal": {
          const p = this.proposals.get(f.proposal_id);
          if (!p || p.finalized !== null) throw new Error("NoProposal");
          if (s < p.deadline_seq) throw new Error("deadline not reached");
          const approved =
            p.yes > p.no && p.yes * QUORUM_DEN >= p.supply_at_create * QUORUM_NUM;
          p.finalized = approved;
          if (approved) {
            const m = this.markets.get(p.market);
            if (p.key === 4) m.delisted = true;
            else if (p.key === 0) m.im_bps = p.value;
            else if (p.key === 1) m.mm_bps = p.value;
            else if (p.key === 2) m.taker_fee_bps = p.value;
            else if (p.key === 3) m.keeper_reward_bps = p.value;
          }
          return { approved };
        }
        default:
          throw new Error("engine: unsupported op " + opName);
      }
    },
  };
}


let network;

async function main() {
  network = await Network.create()
    .with.agent({ vault: BOOTSTRAP_AA })
    .with.wallet({ alice: 1e9, mnemonic: ALICE_MNEMONIC })
    .with.wallet({ bob: 1e9, mnemonic: BOB_MNEMONIC })
    .run();

  let alice, bob, aliceAddr, pv;
  const vault = network.agent.vault;
  alice = network.wallet.alice;
  bob = network.wallet.bob;
  console.log("vault", vault);

  // ---------- 1. deposit ----------
  // The finalized AA keeps NO bal_ shadow ledger (complexity-budget
  // reclamation): a deposit is proven by its non-bounced AA response.
  const depA = await triggerRaw(alice, { deposit: 1 }, 1e6);
  const depB = await triggerRaw(bob, { deposit: 1 }, 2e6);
  if (!(depA.response && depA.response.bounced === false))
    throw new Error("alice deposit bounced: " + JSON.stringify(depA.response).slice(0, 300));
  if (!(depB.response && depB.response.bounced === false))
    throw new Error("bob deposit bounced: " + JSON.stringify(depB.response).slice(0, 300));
  let st = await vars();
  aliceAddr = await alice.getAddress();
  console.log("deposits accepted (final AA carries no shadow-ledger vars)");

  // ---------- 1b. generate the REAL withdrawal claim (root committed at submit) ----------
  require("child_process").execSync(
    // <addr> <collateral> <perp> <withdrawn> — collateral=2000000 stays well
    // above the 900000 test withdrawal while withdrawn=1000000 IS the W
    // budget: the over-W and replay negative cases below then trip ONLY the
    // W arm (amount + wd_ > withdrawn), isolating it from the collateral arm.
    "cargo run -p operp-settle --example gen_withdraw_proof -- " + aliceAddr + " 2000000 0 1000000",
    // The testkit chdirs into its devnet home; pin the workspace root so
    // cargo finds the Cargo.toml.
    { cwd: path.join(__dirname, "..") },
  );
  const claim = JSON.parse(fs.readFileSync(path.join(__dirname, "withdraw_claim.json"), "utf8"));
  let lh = sha256Hex("acct:" + claim.leaf_account + ":" + claim.collateral + ":" + (claim.perp || "0") + ":" + claim.withdrawn);
  for (const s of claim.proof) lh = sha256Hex(s.right ? lh + s.hash : s.hash + lh);
  // Sharded recheck (Phase 5.2): the fold must land on the claimed shard's
  // 64-hex slice of the forest, and the forest hash must match aa_root.
  if (lh !== claim.aa_forest.substr(claim.shard * 64, 64))
    throw new Error("local proof check mismatch: " + lh);
  if (sha256Hex(claim.aa_forest) !== claim.aa_root)
    throw new Error("local forest hash mismatch");
  console.log("local proof recheck OK (shard", claim.shard, ")");

  // ---------- 2. submit height 1: single-candidate + height-taken ----------
  const submit1 = { submit: 1, chain_id: "operp-mvp-1", height: 1, prev_state_hash: PREV0, state_root: ROOT_CAND1, aa_root: sha256Hex("aacand1"), aa_forest: FOREST_CAND1 };
  const batch1 = { chain_id: "operp-mvp-1", height: 1, state_root: ROOT_CAND1, unit_ids: ["u1"] };
  // sub-60000 combined unit cannot post the SUBMIT_BOND_NET (value gate
  // sits behind the empty height-taken gate for a first submit).
  await expectBounce(() => sendCombinedSubmit(bob, 20000, submit1, batch1), "need submit bond");
  const sub1 = await sendCombinedSubmit(bob, 60000, submit1, batch1);
  console.log("submit1 response:", JSON.stringify(sub1.response));
  // second combined submit on the same height bounces 'height taken' —
  // even from a bond-sufficient different operator; bob stays the ONLY
  // candidate and da_unit_1 pins bob's unit.
  const submit2 = { submit: 1, chain_id: "operp-mvp-1", height: 1, prev_state_hash: PREV0, state_root: ROOT_FINAL1, aa_root: claim.aa_root, aa_forest: claim.aa_forest };
  const batch2 = { chain_id: "operp-mvp-1", height: 1, state_root: ROOT_FINAL1, unit_ids: ["u2"] };
  await expectBounce(() => sendCombinedSubmit(alice, 60000, submit2, batch2), "height taken");
  st = await vars();
  console.log("cand after race:", st["cand_root_1"], st["cand_aa_root_1"]);
  console.log("var keys:", Object.keys(st));
  if (st["cand_root_1"] !== ROOT_CAND1 || st["cand_aa_root_1"] !== FOREST_CAND1)
    throw new Error("single-candidate not preserved");
  if (st["da_unit_1"] !== sub1.unit)
    throw new Error("da_unit_1 not pinned to first combined unit: " + st["da_unit_1"] + " != " + sub1.unit);
  console.log("height taken enforced; da_unit_1 pinned to first combined unit");
  const bobAddr = await bob.getAddress();

  // ---------- 3. early lock must bounce ----------
  const earlyLock = await triggerRaw(bob, { lock: 1, height: 1 });
  if (!JSON.stringify(earlyLock).includes("cannot lock yet"))
    throw new Error("early lock did not bounce: " + JSON.stringify(earlyLock).slice(0, 300));
  console.log("  early lock bounced as expected");

  // ---------- 4. stability window then lock ----------
  await network.timetravel({ shift: '700s' });
  const lockRes = await triggerRaw(bob, { lock: 1, height: 1 });
  const lr = JSON.stringify(lockRes.response);
  console.log("lock response tail:", lr.slice(-300));
  st = await vars();
  console.log("after lock: root_1 =", st["root_1"], "last_locked =", st["last_locked"]);
  if (st["root_1"] !== ROOT_CAND1 || Number(st["last_locked"]) !== 1) throw new Error("lock failed");

  // ---------- 5. withdraw before finalize bounces ----------
  const earlyWd = await triggerRaw(alice, { withdraw: 1, amount: 1000 });
  if (!JSON.stringify(earlyWd).includes("not finalizable"))
    throw new Error("early withdraw did not bounce: " + JSON.stringify(earlyWd).slice(0, 1500));
  console.log("  pre-finalize withdraw bounced as expected");

  // ---------- 6. challenge at height 1 -> FAILURE sweep ----------
  // The final AA has NO respond-by-resubmit for a LOCKED height: submit
  // requires h == last_locked + 1, so nobody — impostor or sitting operator
  // — can answer a challenge on a locked height. Silence past the window
  // therefore fails the height through the finalize failure sweep. alice is
  // the challenger; bob's candidate bond gets confiscated.
  const chalUnit = await alice.triggerAaWithData({ toAddress: vault, amount: 30000, data: { challenge: 1, height: 1 } });
  if (chalUnit.error) throw new Error("challenge: " + chalUnit.error);
  await network.witnessUntilStable(chalUnit.unit);
  st = await vars();
  if (Number(st["frozen_1"]) !== 1) throw new Error("challenge did not freeze");
  console.log("  frozen_1 =", st.frozen_1);
  // while a challenge is live its height stays frozen -> {claim_bond} refuses
  const earlyBondClaim = await triggerRaw(alice, { claim: "bond" }, 30000);
  if (!JSON.stringify(earlyBondClaim).includes("challenge unresolved"))
    throw new Error("claim_bond during live challenge did not bounce: " + JSON.stringify(earlyBondClaim).slice(0, 400));
  console.log("  early claim_bond bounced as expected ('challenge unresolved')");

  // Locked-height immutability: while the height is FROZEN (frozen_1==1), the
  // submit case takes the respond-by-resubmit branch, so a root-mismatched
  // resubmit (state_root != cand_root_1) bounces 'not operator' — the frozen
  // height cannot be overwritten by either the impostor or the sitting operator.
  const resub = await triggerRaw(bob, { submit: 1, chain_id: "operp-mvp-1", height: 1, prev_state_hash: PREV0, state_root: ROOT_FINAL1, aa_root: claim.aa_root, aa_forest: claim.aa_forest }, 60000);
  if (!JSON.stringify(resub).includes("not operator"))
    throw new Error("locked+frozen resubmit not rejected: " + JSON.stringify(resub).slice(0, 300));
  console.log("  locked+frozen resubmit bounced as expected ('not operator')");

  await network.timetravel({ shift: '3600s' }); // no response possible; window over
  const failFin = await triggerRaw(alice, { finalize: 1, height: 1 }, 20000);
  st = await vars();
  console.log("after failed challenge: frozen_1 =", st.frozen_1, "last_locked =", st.last_locked);
  if (Number(st.frozen_1) !== 2) throw new Error("failure sweep did not mark frozen=2");
  if (Number(st.last_locked) !== 0) throw new Error("last_locked did not roll back to 0");
  const aliceBondCredited = Number(st["bond_" + aliceAddr]);
  console.log("  alice challenger bond stays credited =", aliceBondCredited,
    "slash_reward =", st["slash_reward_" + aliceAddr]);
  if (!(aliceBondCredited > 0)) throw new Error("challenger bond not credited after failed height");
  if (!(Number(st["slash_reward_" + aliceAddr]) > 0))
    throw new Error("slash reward not credited after failed height");

  // ---------- 8a. H1 regression: the challenge WON at height 1 (frozen_1 == 2
  // and the failure sweep cleared root_1/active_bond_1). A direct re-lock
  // WITHOUT a fresh bonded submit must bounce 'cannot lock yet' — otherwise
  // the fraudulent candidate could be resurrected for free past the window.
  await expectBounce(() => triggerRaw(bob, { lock: 1, height: 1 }), "cannot lock yet");

  // ---------- 8b. challenger reclaims her recorded bond via {claim_bond} ----------
  // Wallet-balance proof via STAGED snapshots: fee = balance drop caused by
  // the trigger unit alone (its 30000 trigger bytes + miner fee), then
  // wallet delta = payout - 30000 - fee. Both snapshots are taken at full
  // stability, so they are exact.
  const balBeforeClaim = await balances(alice);
  const claimUnit = await triggerAwaitUnit(alice, { claim: "bond" }, 30000);
  const balAfterTrigger = await balances(alice);
  const res = await network.getAaResponseToUnit(claimUnit);
  const bondClaim = { unit: claimUnit, response: (res && res.response) || null };
  if (!bondClaim.response || bondClaim.response.bounced !== false)
    throw new Error("claim_bond bounced: " + JSON.stringify(bondClaim).slice(0, 400));
  st = await vars();
  if (Number(st["bond_" + aliceAddr]) !== 0) throw new Error("bond var not zeroed after claim_bond");
  await network.witnessUntilStable(bondClaim.response.response_unit);
  const paidBond = await paidToAddress(bondClaim.response.response_unit, aliceAddr, "base");
  if (paidBond !== aliceBondCredited)
    throw new Error("claim_bond payout mismatch: paid " + paidBond + ", claimed " + aliceBondCredited);
  const balAfterClaim = await balances(alice);
  const claimFee = balBeforeClaim.base - balAfterTrigger.base - 30000;
  const claimDelta = balAfterClaim.base - balBeforeClaim.base;
  if (claimDelta !== aliceBondCredited - 30000 - claimFee)
    throw new Error("claim_bond wallet delta " + claimDelta + " != " + (aliceBondCredited - 30000 - claimFee));
  console.log("  claim_bond paid exactly", aliceBondCredited,
    "(wallet delta", claimDelta, "= owed - 30000 trigger -", claimFee, "fee)");
  // ---------- 8c. frozen==2 unlock: fresh bonded combined resubmit / lock /
  // finalize of height 1 with the REAL sharded commitment ----------
  // The failed height is recoverable: the failure sweep cleared root_1,
  // active_bond_1 and cand_aa_root_1, so $old is empty and a fresh COMBINED
  // unit can re-occupy the height (single-candidate gate passes).
  const reSubmit = { submit: 1, chain_id: "operp-mvp-1", height: 1, prev_state_hash: PREV0, state_root: ROOT_FINAL1, aa_root: claim.aa_root, aa_forest: claim.aa_forest };
  const reBatch = { chain_id: "operp-mvp-1", height: 1, state_root: ROOT_FINAL1, unit_ids: ["u3"] };
  await sendCombinedSubmit(bob, 60000, reSubmit, reBatch);
  await network.timetravel({ shift: '700s' });
  await trigger(bob, { lock: 1, height: 1 });
  st = await vars();
  if (st.root_1 !== ROOT_FINAL1 || Number(st.frozen_1) !== 0)
    throw new Error("height 1 re-lock after failure failed: root_1=" + st.root_1 + " frozen_1=" + st.frozen_1);
  await network.timetravel({ shift: '3600s' });
  await trigger(alice, { finalize: 1, height: 1 });
  st = await vars();
  if (Number(st.last_finalized) !== 1)
    throw new Error("finalize h1 failed: last_finalized=" + st.last_finalized);
  console.log("height 1 recovered, re-locked and finalized (frozen==2 unlock works)");

  // ---------- 9. real proof withdraw against height 1 ----------
  // Height 1 was re-submitted, re-locked and finalized by the frozen==2
  // recovery in 8c above; sanity-check before proving the payout.
  st = await vars();
  if (Number(st.last_finalized) !== 1)
    throw new Error("h1 not finalized: last_finalized=" + st.last_finalized);
  console.log("height 1 finalized");

  // Clamp to the proven W (cumulative withdrawn) as well: the AA enforces
  // amount + wd_ <= withdrawn, so a claim whose withdrawn is less than the
  // collateral must not drive the test into the W arm accidentally.
  const wdAmount = Math.min(Number(claim.collateral), Number(claim.withdrawn), 900000);
  const wdBalBefore = await balances(alice);
  const wdUnit = await triggerAwaitUnit(alice, {
    withdraw: 1,
    height: 1,
    amount: wdAmount,
    leaf_account: claim.leaf_account,
    collateral: claim.collateral,
    perp: claim.perp || "0",
    withdrawn: claim.withdrawn,
    shard: claim.shard,
    proof: claim.proof,
  }, 10000);
  const wdBalAfterTrigger = await balances(alice);
  const wres = await network.getAaResponseToUnit(wdUnit);
  const good = { unit: wdUnit, response: (wres && wres.response) || null };
  if (!(good.response && good.response.bounced === false && good.response.response_unit)) {
    throw new Error("good proof withdraw did not pay: " + JSON.stringify(good).slice(0, 500));
  }
  // Wallet-balance proof: the AA pays exactly `amount` (payout unit output),
  // and alice's base balance moves by amount - 10000 trigger - miner fee.
  await network.witnessUntilStable(good.response.response_unit);
  const wdPaid = await paidToAddress(good.response.response_unit, aliceAddr, "base");
  if (wdPaid !== wdAmount)
    throw new Error("withdraw payout mismatch: paid " + wdPaid + ", claimed " + wdAmount);
  const wdBalAfter = await balances(alice);
  // Staged fee derivation (see 8b): trigger bytes 10000 + miner fee left
  // alice before the AA payout landed.
  const wdFee = wdBalBefore.base - wdBalAfterTrigger.base - 10000;
  const wdDelta = wdBalAfter.base - wdBalBefore.base;
  if (wdDelta !== wdAmount - 10000 - wdFee)
    throw new Error("withdraw wallet delta " + wdDelta + " != " + (wdAmount - 10000 - wdFee));
  console.log("GOOD PROOF WITHDRAWAL PAID (wallet delta", wdDelta, "=", wdAmount, "- 10000 -", wdFee, "fee)");

  // REPLAY: the identical withdraw a second time must bounce — with
  // wd_ = 900000 the second claim's amount + wd_ = 1800000 exceeds the
  // proven W (withdrawn = 1000000), tripping the W arm of the
  // bad-claim-amount gate (the collateral arm at 2000000 stays clear).
  const replay = await triggerRaw(alice, {
    withdraw: 1,
    height: 1,
    amount: wdAmount,
    leaf_account: claim.leaf_account,
    collateral: claim.collateral,
    perp: claim.perp || "0",
    withdrawn: claim.withdrawn,
    shard: claim.shard,
    proof: claim.proof,
  });
  if (!JSON.stringify(replay).includes("bad claim amount"))
    throw new Error("replay withdraw did not bounce: " + JSON.stringify(replay).slice(0, 400));
  console.log("REPLAY WITHDRAWAL BOUNCED AS EXPECTED");

  // bad proof must bounce. Use a small amount so the request passes the
  // cumulative wd_ cap (already filled by the good withdrawal) and actually
  // reaches the merkle-root verification arm.
  const badProof = claim.proof.map((s, i) => (i === 0 ? { ...s, hash: s.hash.slice(0, -1) + (s.hash.endsWith("0") ? "1" : "0") } : s));
  const bad = await triggerRaw(alice, {
    withdraw: 1,
    height: 1,
    amount: 1000,
    leaf_account: claim.leaf_account,
    collateral: claim.collateral,
    perp: claim.perp || "0",
    withdrawn: claim.withdrawn,
    shard: claim.shard,
    proof: badProof,
  });
  if (!JSON.stringify(bad).includes("bad merkle root"))
    throw new Error("bad proof did not bounce with 'bad merkle root': " + JSON.stringify(bad).slice(0, 2000));
  console.log("BAD PROOF BOUNCED AS EXPECTED");

  // ---------- W-gate negatives (audit C1/C2) ----------
  // (a) negative amount: the amount gate's `amount < 0` arm must bounce
  // before any balance math runs.
  const neg = await triggerRaw(alice, {
    withdraw: 1,
    height: 1,
    amount: -500000,
    leaf_account: claim.leaf_account,
    collateral: claim.collateral,
    perp: claim.perp || "0",
    withdrawn: claim.withdrawn,
    shard: claim.shard,
    proof: claim.proof,
  });
  if (!JSON.stringify(neg).includes("bad claim amount"))
    throw new Error("negative amount did not bounce: " + JSON.stringify(neg).slice(0, 600));
  console.log("NEGATIVE AMOUNT BOUNCED AS EXPECTED");

  // (b) amount beyond the remaining W budget (withdrawn - wd_): the good
  // withdrawal above consumed 900000 of withdrawn=1000000, so an amount that
  // alone is under collateral but pushes amount + wd_ past withdrawn must
  // bounce — replay protection stays intact after the W gate ships.
  const overW = await triggerRaw(alice, {
    withdraw: 1,
    height: 1,
    amount: Number(claim.withdrawn) - 1000,
    leaf_account: claim.leaf_account,
    collateral: claim.collateral,
    perp: claim.perp || "0",
    withdrawn: claim.withdrawn,
    shard: claim.shard,
    proof: claim.proof,
  });
  if (!JSON.stringify(overW).includes("bad claim amount"))
    throw new Error("over-W amount did not bounce: " + JSON.stringify(overW).slice(0, 600));
  console.log("OVER-W AMOUNT BOUNCED AS EXPECTED");

  // ---------- 9b. challenge-on-locked-height + respond-by-resubmit ----------
  // Post-lock-only challenge semantics (challenge window = stable_at+3600):
  // a challenge on an UNLOCKED candidate (h2 == last_locked+1) must bounce
  // 'bad height' — a pre-lock freeze would permanently wedge the height.
  // The honest respond runs on the LOCKED height.
  console.log("\n--- challenge & respond tests (height 2, locked) ---");
  const ROOT_H2 = sha256Hex("rootH2-real");
  const PREV1 = ROOT_FINAL1; // prev of h2 is root_1
  const FOREST_ALT = sha256Hex("altforest").repeat(16);
  const submitH2 = { submit: 1, chain_id: "operp-mvp-1", height: 2, prev_state_hash: PREV1, state_root: ROOT_H2, aa_root: sha256Hex("aa_h2"), aa_forest: claim.aa_forest };
  const batchH2 = { chain_id: "operp-mvp-1", height: 2, state_root: ROOT_H2, unit_ids: ["h2u1"] };
  const subH2 = await sendCombinedSubmit(bob, 60000, submitH2, batchH2);
  st = await vars();
  const submittedAtBefore = st["submitted_at_2"];
  const daUnitBefore = st["da_unit_2"];
  const candAaBefore = st["cand_aa_root_2"];
  const feeWinnerBefore = st["fee_winner_2"];
  console.log("  h2 submitted_at", submittedAtBefore, "da_unit", daUnitBefore.slice(0,12)+"..");
  // immediate lock should bounce (600s window)
  await expectBounce(() => triggerRaw(bob, { lock: 1, height: 2 }), "cannot lock yet");
  console.log("  immediate lock bounced (600s gate)");
  // challenge on the UNLOCKED candidate (h2 == last_locked+1) must bounce 'bad height'
  await expectBounce(() => triggerRaw(alice, { challenge: 1, height: 2 }, 30000), "bad height");
  console.log("  challenge-before-lock bounced 'bad height' (post-lock-only)");
  // stability window then lock h2 (stable_at_2 anchors the challenge window)
  await network.timetravel({ shift: '700s' });
  const lockH2 = await triggerRaw(bob, { lock: 1, height: 2 });
  if (lockH2.response && lockH2.response.bounced) throw new Error("lock h2 bounced: "+JSON.stringify(lockH2.response).slice(0,400));
  st = await vars();
  if (Number(st["last_locked"]) !== 2) throw new Error("h2 lock failed after 700s");
  console.log("  h2 locked (stable_at_2 set), last_locked = 2");
  // challenge the LOCKED height -> frozen==1 (inside stable_at+3600)
  const chalH2 = await alice.triggerAaWithData({ toAddress: vault, amount: 30000, data: { challenge: 1, height: 2 } });
  if (chalH2.error) throw new Error("challenge h2: " + chalH2.error);
  await network.witnessUntilStable(chalH2.unit);
  st = await vars();
  if (Number(st["frozen_2"]) !== 1) throw new Error("h2 not frozen after challenge: "+st["frozen_2"]);
  console.log("  h2 frozen==1");
  const bondBefore = Number(st["bond_" + aliceAddr]);
  if (!(bondBefore > 0)) throw new Error("challenger bond not credited");
  // --- impostor must bounce before honest respond ---
  await expectBounce(() => sendCombinedSubmit(alice, 60000, submitH2, batchH2), "not operator");
  console.log("  impostor resubmit bounced 'not operator'");
  const forestSwap = { submit: 1, chain_id: "operp-mvp-1", height: 2, prev_state_hash: PREV1, state_root: ROOT_H2, aa_root: sha256Hex("aa_h2"), aa_forest: FOREST_ALT };
  const batchAlt = { chain_id: "operp-mvp-1", height: 2, state_root: ROOT_H2, unit_ids: ["h2alt"] };
  await expectBounce(() => sendCombinedSubmit(bob, 60000, forestSwap, batchAlt), "not operator");
  console.log("  forest-swapped resubmit bounced 'not operator'");
  // --- honest operator responds with bond exemption (only 10000 headroom) ---
  const respH2 = await sendCombinedSubmit(bob, 12000, submitH2, batchH2);
  if (respH2.response && respH2.response.bounced) throw new Error("honest respond bounced: "+JSON.stringify(respH2.response).slice(0,400));
  st = await vars();
  if (Number(st["frozen_2"]) !== 0) throw new Error("h2 not unfrozen after respond: "+st["frozen_2"]);
  if (Number(st["bond_" + aliceAddr]) !== 0) throw new Error("challenger bond not confiscated");
  if (st["da_unit_2"] !== daUnitBefore) throw new Error("da_unit_2 changed on respond: "+st["da_unit_2"]+" != "+daUnitBefore);
  if (String(st["submitted_at_2"]) !== String(submittedAtBefore)) throw new Error("submitted_at_2 reset on respond");
  if (st["cand_aa_root_2"] !== candAaBefore) throw new Error("cand_aa_root_2 changed on respond");
  if (st["active_bond_2"] !== bobAddr) throw new Error("active_bond_2 changed");
  if (st["fee_winner_2"] !== feeWinnerBefore) throw new Error("fee_winner_2 changed on respond");
  console.log("  honest respond ok: frozen cleared, bond confiscated, da_unit/submitted_at/cand/fee_winner untouched, bond exemption (12000) passed");
  // respond window is anchored on stable_at_2 (not submitted_at_2): lock set
  // stable_at_2, and the challenge+respond above both ran inside stable_at+3600,
  // matching the finalize failure sweep's window exactly.
  // finalize h2 clean (no challenge) to keep chain healthy for later tests
  await network.timetravel({ shift: '3600s' });
  await trigger(alice, { finalize: 1, height: 2 });
  st = await vars();
  if (Number(st["last_finalized"]) !== 2) throw new Error("finalize h2 failed");
  console.log("  h2 finalized (respond path chain intact)");

  PERP_ASSET = await resolvePerpAsset(alice);

  console.log("\nOK: full AA lifecycle passed");

  // ==================== 10. PERP governance E2E (plan steps 7-8) ====================
  // The leaf-format change is breaking, so — exactly like at issuance time —
  // the vault AA is REDEPLOYED here with 'PERP_ASSET_ID_HERE' replaced by the
  // runtime-resolved asset id (plan step 8). The fresh instance starts at
  // height 0, giving the gov batch a clean submit/lock/finalize run.
  if (!PERP_ASSET) {
    console.log("PERP E2E SKIPPED (no asset issuance)");
  } else {
    const aaSrc = fs
      .readFileSync(path.join(__dirname, "agents", "operp_vault.aa"), "utf8")
      .replace(/PERP_ASSET_ID_HERE/g, PERP_ASSET);
    const deployed = await alice.deployAgent(aaSrc);
    if (deployed.error || !deployed.address)
      throw new Error("PERP vault redeploy failed: " + deployed.error);
    await network.witnessUntilStable(deployed.unit);
    pv = deployed.address;
    console.log("PERP vault (redeployed with real asset id):", pv);

    // pv-targeted mirrors of the helpers above (those are bound to the
    // original vault instance).
    // NOTE: deliberately NOT using wallet.triggerAaWithData here — the
    // testkit child emits TWO 'aa_triggered' events for bounced triggers
    // (missing return in the error path), which permanently desynchronizes
    // the once()-based event pairing and hangs later triggers. Direct
    // sendMulti + explicit AA-response polling is race-free.
    const pTrigger = async (wallet, data, amount) => {
      const r = await wallet.sendMulti({
        base_outputs: [{ address: pv, amount: amount === undefined ? 10000 : amount }],
        messages: [{ app: "data", payload: data }],
      });
      if (r.error) throw new Error(JSON.stringify(data).slice(0, 60) + ": " + r.error);
      if (!r.unit) throw new Error(JSON.stringify(data).slice(0, 60) + ": no unit");
      await network.witnessUntilStable(r.unit);
      return r.unit;
    };
    const pTriggerRaw = async (wallet, data, amount) => {
      const unit = await pTrigger(wallet, data, amount);
      const res = await network.getAaResponseToUnit(unit);
      return { unit, response: (res && res.response) || null };
    };
    const pVars = async () => {
      const v = await alice.readAAStateVars(pv);
      return v.vars || v;
    };

    // ---- 10a. seed the fresh vault, then send PERP in and observe it ----
    await pTrigger(alice, { deposit: 1 }, 2e6); // base collateral it can later pay out
    const PERP_DEPOSIT = 200000;
    const depRes = await alice.sendMulti({
      base_outputs: [{ address: pv, amount: 10000 }],
      asset: PERP_ASSET,
      asset_outputs: [{ address: pv, amount: PERP_DEPOSIT }],
      messages: [{ app: "data", payload: { deposit_perp: 1 } }],
    });
    if (depRes.error) throw new Error("PERP deposit failed: " + depRes.error);
    await network.witnessUntilStable(depRes.unit);
    const depAa = await network.getAaResponseToUnit(depRes.unit);
    console.log("PERP deposit AA response:", JSON.stringify(depAa && depAa.response).slice(0, 300));

    // Restored deposit_perp case ACCEPTS the asset-bearing payment and
    // credits the reconciliation ledger pperp_<trigger.address> (keyed
    // identically to wd_/wp_ read in withdraw init). pperp_ is a mirror of
    // the sidechain GovDeposit credits, NOT a payout cap: the proven leaf's
    // perp value stays the withdrawal authority.
    if (!(depAa && depAa.response && depAa.response.bounced !== true))
      throw new Error("PERP deposit did not credit pperp_: " + JSON.stringify(depAa && depAa.response).slice(0, 600));
    const stDep = await pVars();
    if (Number(stDep["pperp_" + aliceAddr] || 0) !== PERP_DEPOSIT)
      throw new Error("pperp_ mirror credited " + stDep["pperp_" + aliceAddr] + ", expected exactly " + PERP_DEPOSIT);
    console.log("PERP DEPOSIT ACCEPTED, pperp_" + aliceAddr + " =", PERP_DEPOSIT);

    // ---- 10b. sidechain batch: GovDeposit -> CreateMarket -> proposal ----
    // Signing-key convention matches export_batch.rs sk(n): seed = [n;32];
    // AccountId = sha256(pubkey) (operp_types::account_id_from_pubkey).
    const govKey = ed25519FromSeed(Buffer.alloc(32, 1)); // sk(1) in export_batch.rs: seed = [1;32]
    const govAcct = sha256Buf(govKey.pubkey);
    const govAcctHex = govAcct.toString("hex");
    const eng = makePerpEngine();
    let tip = sha256Hex("operp-mvp-1-genesis"); // operp_dag::genesis_id()
    const units = [];
    function postOp(opName, fieldsBuf, fieldsJson, simFields) {
      const u = signGovUnit([tip], opName, fieldsBuf, fieldsJson, govKey);
      const applied = eng.apply(opName, simFields);
      units.push(u);
      tip = u.unit_id;
      return applied;
    }

    // Op::GovDeposit{account, amount, aa_unit, addr} — aa_unit is the Obyte
    // PERP deposit trigger unit above (base64 unit id -> raw [u8;32]). The
    // unit id is fixed at posting time and independent of the AA response,
    // so restoring deposit_perp (accept instead of auto-bounce) does NOT
    // change which id is referenced; operp-settle's deposits_allowed
    // injection still replay-guards it. addr binds the sidechain account
    // to alice's Obyte withdrawal address.
    const aaUnit = Buffer.from(depRes.unit, "base64");
    if (aaUnit.length !== 32) throw new Error("deposit unit id is not 32 bytes");
    postOp(
      "GovDeposit",
      { account: govAcct, amount: PERP_DEPOSIT, aa_unit: aaUnit, addr: aliceAddr },
      { account: Array.from(govAcct), amount: PERP_DEPOSIT, aa_unit: Array.from(aaUnit), addr: aliceAddr },
      { account_hex: govAcctHex, amount: PERP_DEPOSIT, aa_unit_hex: aaUnit.toString("hex"), addr: aliceAddr },
    );
    if ((eng.bal.get(govAcctHex) || 0n) !== BigInt(PERP_DEPOSIT))
      throw new Error("sidechain GovDeposit not credited");
    console.log("PERP DEPOSIT CREDITED");

    // Op::CreateMarket{...}: burns CREATE_MARKET_FEE_PERP=10_000 from the
    // creator; symbol right-padded to 16 bytes; ETH_USD becomes market id=2.
    const symBuf = Buffer.alloc(16);
    Buffer.from("ETH_USD", "utf8").copy(symBuf);
    postOp(
      "CreateMarket",
      { creator: govAcct, symbol: symBuf, tick_size: 100, im_bps: 500, mm_bps: 1000, taker_fee_bps: 20, keeper_reward_bps: 50 },
      { creator: Array.from(govAcct), symbol: Array.from(symBuf), tick_size: 100, im_bps: 500, mm_bps: 1000, taker_fee_bps: 20, keeper_reward_bps: 50 },
      { creator_hex: govAcctHex, symbol_bytes: symBuf, tick_size: 100, im_bps: 500, mm_bps: 1000, taker_fee_bps: 20, keeper_reward_bps: 50 },
    );
    const MARKET = eng.nextMarketId - 1;
    if (MARKET !== 2 || !eng.markets.has(2)) throw new Error("market 2 not registered");
    if ((eng.bal.get(govAcctHex) || 0n) !== BigInt(PERP_DEPOSIT - 10000))
      throw new Error("listing fee not burned exactly");
    console.log("MARKET CREATED (id=2)");

    // Op::CreateProposal / Vote / FinalizeProposal: raise taker_fee_bps
    // 20 -> 35 on market 2 (ParamKey::TakerFeeBps = 2).
    postOp(
      "CreateProposal",
      { creator: govAcct, market: MARKET, key: 2, value: 35 },
      { creator: Array.from(govAcct), market: MARKET, key: 2, value: 35 },
      { creator_hex: govAcctHex, market: MARKET, key: 2, value: 35 },
    );
    const PID = eng.nextProposalId - 1;
    postOp(
      "Vote",
      { voter: govAcct, proposal_id: PID, approve: true },
      { voter: Array.from(govAcct), proposal_id: PID, approve: true },
      { voter_hex: govAcctHex, proposal_id: PID, approve: true },
    );
    // The deadline is measured in global seqs; fast-forward the deterministic
    // counter instead of posting 20_000 filler ops (the AA never sees seqs).
    eng.seq = eng.proposals.get(PID).deadline_seq;
    const fin = postOp(
      "FinalizeProposal",
      { caller: govAcct, proposal_id: PID },
      { caller: Array.from(govAcct), proposal_id: PID },
      { caller_hex: govAcctHex, proposal_id: PID },
    );
    if (!(fin.approved === true && eng.proposals.get(PID).finalized === true))
      throw new Error("proposal did not pass quorum");
    if (eng.markets.get(MARKET).taker_fee_bps !== 35)
      throw new Error("approved parameter not effective in next checkpoint state");
    console.log("PROPOSAL FINALIZED approved=true");

    // ---- 10c. commit the batch on-chain: temp_data reveal + submit/lock/finalize ----
    // Op::GovWithdraw mirrors the AA withdrawal claimed below (same amount).
    const WITHDRAW_PERP = 5000;
    postOp(
      "GovWithdraw",
      { account: govAcct, amount: WITHDRAW_PERP, nonce: 1 },
      { account: Array.from(govAcct), amount: WITHDRAW_PERP, nonce: 1 },
      { account_hex: govAcctHex, amount: WITHDRAW_PERP, nonce: 1 },
    );

    // Sharded forest over (address, collateral, perp, withdrawn) leaves —
    // same pairs layout as gen_withdraw_proof.rs (alice + decoy peer).
    // alice's leaf carries W = her full proven collateral so the
    // 100000-byte claim fits under the global wd_ cap; the decoys never
    // withdraw. padBucket keeps alice's shard at >=2 accounts (ocore
    // fatals on EMPTY proof arrays, i.e. singleton buckets).
    const COLLATERAL_CLAIM = "100000";
    let pairs = [
      { addr: aliceAddr, collateral: COLLATERAL_CLAIM, perp: String(WITHDRAW_PERP), withdrawn: COLLATERAL_CLAIM },
      { addr: "5B7BJSCMFQYUOLDLJHROMOKC5QCLPZLK3UEE4O25", collateral: "500", perp: "0", withdrawn: "500" },
    ];
    pairs = padBucket(pairs, aliceAddr);
    const shard = aaShardOf(aliceAddr);
    const shardBucket = pairs.filter((p) => aaShardOf(p.addr) === shard);
    const { proof, root } = aaProofFor(shardBucket, aliceAddr);
    const roots = aaShardedRoots(pairs);
    const forest = roots.join("");
    const aaRoot = aaForestHash(roots);
    if (root !== roots[shard]) throw new Error("shard proof does not reach its committed root");
    let lh = aaLeafStr(aliceAddr, COLLATERAL_CLAIM, String(WITHDRAW_PERP), COLLATERAL_CLAIM);
    for (const s of proof) lh = sha256Hex(s.right ? lh + s.hash : s.hash + lh);
    if (lh !== forest.substr(shard * 64, 64))
      throw new Error("local PERP proof recheck mismatch: " + lh);

    const HEIGHT = 1;
    const stateRoot = sha256Hex(Buffer.concat(units.map((u) => Buffer.from(u.unit_id, "hex"))));
    const batchData = {
      chain_id: "operp-mvp-1",
      height: HEIGHT,
      prev_state_hash: PREV0,
      state_root: stateRoot,
      aa_root: aaRoot,
      aa_shard_roots: roots,
      fills_hash: "f1",
      fill_count: 0,
      seq: eng.seq,
      last_unit: tip,
      unit_ids: units.map((u) => u.unit_id),
      units,
    };
    // NOTE: the on-chain temp_data reveal is intentionally skipped here —
    // ocore's inline temp_data validator double-calls its callback on large
    // payloads and crashes the core node. Data-availability correctness is
    // covered by the Rust-side settle tests (Batch::temp_data_payload,
    // validate_against); the AA only needs the committed forest below.
    await pTrigger(alice, { submit: 1, chain_id: "operp-mvp-1", height: HEIGHT, prev_state_hash: batchData.prev_state_hash, state_root: stateRoot, aa_root: aaRoot, aa_forest: forest }, 60000);
    await network.timetravel({ shift: '700s' });
    await pTrigger(bob, { lock: 1, height: HEIGHT });
    st = await pVars();
    // The AA stores the full 1024-hex forest in aa_root_<h>.
    if (st["root_" + HEIGHT] !== stateRoot || st["aa_root_" + HEIGHT] !== forest)
      throw new Error("height " + HEIGHT + " lock failed");
    await network.timetravel({ shift: '3600s' });
    // pTriggerRaw waits for the AA response itself; reading vars straight
    // after pTrigger races the response write and sees stale state.
    const finRes = await pTriggerRaw(alice, { finalize: 1, height: HEIGHT });
    if (finRes.response && finRes.response.bounced)
      throw new Error("finalize h" + HEIGHT + " bounced: " + JSON.stringify(finRes.response.error || {bounce:finRes.response.bounced, info:finRes.response.info, msg:finRes.response.error}).slice(0, 900));
    st = await pVars();
    if (Number(st.last_finalized) !== HEIGHT) throw new Error("finalize h" + HEIGHT + " failed");
    console.log("height", HEIGHT, "locked & finalized with PERP aa_root committed");
    // ---- 10d. FUNDED PERP withdrawal against the committed aa_root ----
    // With the deposit_perp case restored, the vault now actually HOLDS
    // PERP (PERP_DEPOSIT), so the same sharded proof that previously
    // bounced at the payout stage pays out. Payout authority is the proven
    // leaf's perp value (pperp_ is only a reconciliation mirror); wp_ is
    // the cumulative anti-replay marker.
    const perpBalBefore = await balances(alice);
    const goodPerp = await pTriggerRaw(alice, {
      withdraw: 1,
      height: HEIGHT,
      amount: 0,
      leaf_account: aliceAddr,
      collateral: COLLATERAL_CLAIM,
      withdrawn: COLLATERAL_CLAIM,
      perp: String(WITHDRAW_PERP),
      shard: shard,
      proof,
    });
    const perpPaid = await paidToAddress(goodPerp.response.response_unit, aliceAddr, PERP_ASSET);
    if (perpPaid !== WITHDRAW_PERP)
      throw new Error("PERP withdraw payout mismatch: paid " + perpPaid + ", claimed " + WITHDRAW_PERP);
    const perpBalAfter = await balances(alice);
    if (perpBalAfter[PERP_ASSET] !== perpBalBefore[PERP_ASSET] + WITHDRAW_PERP)
      throw new Error("alice PERP balance delta mismatch on funded withdrawal");
    st = await pVars();
    if (Number(st["wp_" + aliceAddr] || 0) !== WITHDRAW_PERP)
      throw new Error("wp_ marker not advanced by exactly " + WITHDRAW_PERP + ": " + st["wp_" + aliceAddr]);
    console.log("FUNDED PERP WITHDRAWAL PAID", WITHDRAW_PERP, ", wp_", aliceAddr, "=", WITHDRAW_PERP);

    // Idempotent replay of the SAME claim: the cumulative wp_ cap clamps
    // $unclaimed to 0, so the response succeeds but emits NO asset output
    // ($perp_claimed > 0 gate) and moves no PERP. Anti-replay here is a
    // silent zero-payout clamp, NOT a bounce — a bounce would roll back
    // nothing and prove less.
    const replay = await pTriggerRaw(alice, {
      withdraw: 1,
      height: HEIGHT,
      amount: 0,
      leaf_account: aliceAddr,
      collateral: COLLATERAL_CLAIM,
      withdrawn: COLLATERAL_CLAIM,
      perp: String(WITHDRAW_PERP),
      shard: shard,
      proof,
    });
    if (replay.response && replay.response.bounced === true)
      throw new Error("replayed PERP claim bounced instead of clamping: " + JSON.stringify(replay.response).slice(0, 600));
    const perpBalReplay = await balances(alice);
    if (perpBalReplay[PERP_ASSET] !== perpBalAfter[PERP_ASSET])
      throw new Error("replayed PERP claim moved funds despite exhausted wp_ cap");
    st = await pVars();
    if (Number(st["wp_" + aliceAddr] || 0) !== WITHDRAW_PERP)
      throw new Error("wp_ marker drifted on replayed claim");
    console.log("REPLAYED PERP CLAIM CLAMPED TO ZERO PAYOUT, wp_ intact (anti-replay holds)");

    // Negative-path coverage stays cheap through the existing machinery:
    // an over-proven leaf (perp bumped) folds to a different leaf hash and
    // bounces at merkle validation before any state write.
    const overProof = await pTriggerRaw(alice, {
      withdraw: 1,
      height: HEIGHT,
      amount: 0,
      leaf_account: aliceAddr,
      collateral: COLLATERAL_CLAIM,
      withdrawn: COLLATERAL_CLAIM,
      perp: String(WITHDRAW_PERP * 10),
      shard: shard,
      proof,
    });
    if (!(overProof.response && overProof.response.bounced === true))
      throw new Error("over-proven PERP leaf did not bounce: " + JSON.stringify(overProof.response).slice(0, 600));
    if (Number((await pVars())["wp_" + aliceAddr] || 0) !== WITHDRAW_PERP)
      throw new Error("wp_ marker updated despite bounced over-proof");
    console.log("OVER-PROVEN PERP LEAF BOUNCED AT MERKLE VALIDATION");
  }
  await network.stop();
  process.exit(0);
}

main().catch(async (e) => {
  console.error("FAILED:", e && e.stack ? e.stack : e);
  try { if (network) await network.stop(); } catch (_) {}
  process.exit(1);
});
