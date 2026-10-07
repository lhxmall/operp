"use strict";

// OPERP settlement E2E — three-agent lifecycle (rollup + dispute + vault).
//
// This is the settlement-v2 harness. The vault is pure custody (no submit /
// lock / challenge / finalize), the rollup AA stores bonded assertions,
// and the dispute AA is the only party that can fail a height — via
// one-shot Oscript-verified fraud predicates, never a pay-to-kill bond.
//
// Agent addresses are deterministic (chash160 of the definition), so the
// rollup address is precomputed with the same ocore call the testkit uses
// (objectHash.getChash160(['autonomous agent', def])) and substituted into
// the dispute/vault sources BEFORE Network.create — a single network start.
//
// Scenarios:
//  1.  bind dispute + fill → rollup dispute_aa/_fill set; double bind bounces
//  2.  pool gate: no pool → 'need pool'; {pool:1} funds standing pool
//  3.  combined submit height 1 (10000 fee) → last_submitted=1; resubmit 'bad submit'
//  4.  {lock:1} / {challenge:1} have NO cases → auto-bounce, nothing frozen
//  5.  finalize before 3600s → 'cannot finalize'; after → last_finalized=1, no sbond credit
//  6. omit (forced id missing) now bounces 'no fraud' (#23: force pins a
//      timestamp only, never an existence claim)
//  7. dishonest post collateral → verdict fires: frozen=2, last_submitted
//      rolls back, slash_reward_ 500000000000 claimable, pool slashed 5e11
//  8. honest deposit → 'no fraud', height stays live
//  9-13. fill_math/ghost/skip predicates on h3 chain (unit-bound via
//      units_proof; a fake unit hex bounces 'bad unit')
//  14. two-package (gzip) height deposit fraud → frozen=3
//  15. re-submit + finalize after fraud works
//  16. pipeline h4+h5 with no inter-finalize, then finalize in order
//  17. pool claim: 'pool busy' while live, full claim when idle

// Windows: aa-testkit's runChild replaces the child env wholesale and never
// sets APPDATA, which ocore's desktop_app reads on win32 — the genesis node
// crashes before the network starts. The plan gates e2e on CI (ubuntu);
// skip gracefully on win32 rather than fail.
if (process.platform === "win32") {
  console.log("SKIP: e2e requires a POSIX env (aa-testkit child env omits APPDATA on win32); see CI e2e job.");
  process.exit(0);
}

const fs = require("fs");
const crypto = require("crypto");
const zlib = require("zlib");
const path = require("path");
const aaRoot = path.join(__dirname, "..", "vendor", "aa-testkit");
const nm = path.join(aaRoot, "node_modules");
process.env.NODE_PATH = [nm, process.env.NODE_PATH].filter(Boolean).join(path.delimiter);
require("module").Module._initPaths();
const { Testkit } = require(path.join(aaRoot, "main.js"));
const { Network } = Testkit({
  TESTDATA_DIR: path.join(__dirname, "testdata-settlement"),
  NETWORK_PORT: 16615,
});
const objectHash = require("ocore/object_hash.js");
const parseOjson = require("ocore/formula/parse_ojson").parse;

const PERP_ASSET = "base"; // devnet: no issued asset; deposit_perp branch keyed by data, not asset

function sha256Hex(s) {
  return crypto.createHash("sha256").update(s, "utf8").digest("hex");
}
const merkle = require("ocore/merkle.js");

// ---- agent bootstrap ------------------------------------------------------

function readDef(file) {
  const src = fs.readFileSync(path.join(__dirname, "agents", file), "utf8");
  return src;
}

function chashOf(aaSource) {
  let parsed = null;
  parseOjson(aaSource, (err, res) => {
    if (err) throw err;
    parsed = res[1];
  });
  return objectHash.getChash160(["autonomous agent", parsed]);
}

function writeResolved(file, subs, out) {
  let src = readDef(file);
  for (const [k, v] of Object.entries(subs)) src = src.split(k).join(v);
  const p = path.join(__dirname, "agents", out);
  fs.writeFileSync(p, src);
  return p;
}

// Precompute the rollup address from its definition (no placeholders).
// #13: the rollup hardcodes both dispute addresses (anti-hijack), so they
// hash FIRST. Dispute/fill carry no rollup address in their definitions —
// binds and challenges pass it in trigger data — which is what breaks the
// chash cycle (each address would otherwise be a hash input of the other).
const DISPUTE_SRC = writeResolved("operp_dispute.aa", {}, ".e2e_dispute.aa");
const FILL_SRC = writeResolved("operp_dispute_fill.aa", {}, ".e2e_fill.aa");
const DISPUTE_ADDR = chashOf(fs.readFileSync(DISPUTE_SRC, "utf8"));
const FILL_ADDR = chashOf(fs.readFileSync(FILL_SRC, "utf8"));
const ROLLUP_SRC = writeResolved("operp_rollup.aa", {
  DISPUTE_AA_HERE: DISPUTE_ADDR,
  DISPUTE_FILL_AA_HERE: FILL_ADDR,
}, ".e2e_rollup.aa");
const ROLLUP_ADDR = chashOf(fs.readFileSync(ROLLUP_SRC, "utf8"));
const VAULT_SRC = writeResolved("operp_vault.aa", { ROLLUP_AA_HERE: ROLLUP_ADDR, PERP_ASSET_ID_HERE: PERP_ASSET }, ".e2e_vault.aa");
const POOL_FUND_GROSS = 50000000010000; // 50x POOL_MIN net: survives all fraud slashes in this run
const SUBMIT_FEE = 10000; // submits pay only the bounce fee; pool gates
const RACE_REWARD = 20000;
const SLASH_HALF = 500000000000;

let network;
let failures = 0;
async function trigger(wallet, to, data, amount) {
  const r = await wallet.triggerAaWithData({ toAddress: to, amount, data });
  if (r.error) throw new Error(`trigger ${JSON.stringify(data).slice(0, 60)}: ${r.error}`);
  await network.witnessUntilStable(r.unit);
  return r;
}

async function triggerBounce(wallet, to, data, amount, needle) {
  const r = await wallet.triggerAaWithData({ toAddress: to, amount, data });
  if (r.error) {
    // Direct composer/wallet error already carries the bounce reason.
    if (String(r.error).includes(needle)) {
      console.log(`bounce ok: '${needle}'`);
      return r;
    }
    failures++;
    console.error(`FAIL: expected bounce '${needle}' got error ${r.error} for ${JSON.stringify(data).slice(0, 80)}`);
    return r;
  }
  await network.witnessUntilStable(r.unit);
  // Bounces surface on the AA response unit, not the trigger result.
  const res = await network.getAaResponseToUnit(r.unit).catch(() => null);
  const log = JSON.stringify(res || {});
  if (log.includes(needle)) {
    console.log(`bounce ok: '${needle}'`);
    return r;
  }
  failures++;
  console.error(`FAIL: expected bounce '${needle}' got response ${log.slice(0, 200)} for ${JSON.stringify(data).slice(0, 80)}`);
  console.error(`FULL RESPONSE: ${log.slice(0, 2000)}`);
  return r;
}

async function vars(aa) {
  const v = await (network.wallet.operator || network.wallet.challenger).readAAStateVars(aa);
  return v.vars || v;
}

// Full bounce diagnostics: reason first, then the response (never sliced
// short — CI failures must be diagnosable from one log line).
function bounceDetail(res) {
  const r = (res && res.response) || {};
  const reason = r.bounce_message || r.response_error || "";
  return (reason ? reason + " :: " : "") + JSON.stringify(r).slice(0, 1500);
}

// Genesis witness tree: the height-1 submit commits WIT_ROOT, so every
// k==0 predicate (pre_wit == wit_root_1) proves leaves against this tree.
// Deposit scenario uses DEP_ACCT (old account, pre col 1000000); fill
// scenarios use FILL_TAKER (flat) + META1. All proofs below are real
// merkle.getMerkleProof paths — no dummy self-proofs.
const DEP_ACCT = "a".repeat(64);
const DEP_PRE = `acct:${DEP_ACCT}:1000000:0:0`;
const FILL_TAKER = "b".repeat(64);
const FILL_TAKER_PRE = `acct:${FILL_TAKER}:0:0:0`;
const META1 = `meta:1:1:1000:500:5:100:0:100:0:0`;
const META2 = `meta:2:1:1000:500:5:100:0:100:0:0`;
const POS2 = `pos:${FILL_TAKER}:2:50000000:90000000:0:0`;
const GENESIS_LEAVES = [DEP_PRE, FILL_TAKER_PRE, META1, META2, POS2].sort();
const WIT_ROOT = merkle.getMerkleRoot(GENESIS_LEAVES);
const GEN_WIT_COUNT = GENESIS_LEAVES.length;
// ocore canonical JSON bans empty arrays: a single-leaf merkle proof has
// `"siblings":[]` and the whole trigger is uncomposable. Pad every proof
// array to >= 2 leaves so every proof carries >= 1 sibling. 'pad:' sorts
// after all leaf domains (acct/f/meta/ord), keeping after-max geometry.
function pad2(arr, tag) {
  if (arr.length >= 2) return arr;
  return arr.concat([`pad:${tag}:${"z".repeat(16)}`]);
}
// fills_root tree (mirrors Rust fills_root_elements): the raw fills plus
// one trailing length sentinel `n:{len}` — the trailing fill's right
// neighbor. The sentinel also guarantees >= 2 leaves, so fills proofs
// always carry >= 1 sibling (canonical JSON bans empty sibling arrays).
const fillsTree = (a) => a.concat("n:" + a.length);
function b6444(seed) {
  const h = crypto.createHash("sha256").update(seed, "utf8").digest("base64");
  return h; // exactly 44 chars
}

const TRACE_ROOT = b6444("trace-root");
const UNITS_ROOT = b6444("units-root");
const UNITS_SET_ROOT = b6444("units-set-root");
const OPS_ROOT = b6444("ops-root");
const FILLS_ROOT = b6444("fills-root");
const COUNTS_ROOT = b6444("counts-root");
const STATE_ROOT = sha256Hex("state-1");
const PREV_ROOT = sha256Hex("genesis");
const FOREST = sha256Hex("f0").repeat(16); // 1024 hex

function submitData(height, stateRoot, prev) {
  return {
    submit: 1,
    chain_id: "operp-v2",
    assertion_version: 1,
    height,
    state_root: stateRoot,
    prev_state_hash: prev,
    aa_forest: FOREST,
    // #37-4: real fold binding — forest hash must equal sha256(forest).
    aa_root: sha256Hex(FOREST),
    wit_root: WIT_ROOT,
    trace_root: TRACE_ROOT,
    units_root: UNITS_ROOT,
    units_set_root: UNITS_SET_ROOT,
    ops_root: OPS_ROOT,
    fills_root: FILLS_ROOT,
    counts_root: COUNTS_ROOT,
    unit_count: 1,
    wit_count: GEN_WIT_COUNT,
    fill_count: 0,
  };
}
// Single-package inline DA: full header scalars + frames_blob (gzip of the
// `\n`-joined frames, base64). Derived from the submit so header roots match
// the commitment; the AA only reads the submit, but the blob path is exercised.
function headerFromSubmit(sd, frameOp) {
  const frame = JSON.stringify({ u: { op: "x" }, t: sd.trace_root, o: frameOp || "x", c: "1" });
  const blob = zlib.gzipSync(Buffer.from(frame, "utf8")).toString("base64");
  const raw = zlib.gunzipSync(Buffer.from(blob, "base64"));
  return {
    chain_id: sd.chain_id || "operp-v2",
    height: sd.height,
    prev_state_hash: sd.prev_state_hash,
    state_root: sd.state_root,
    aa_root: sha256Hex(sd.aa_forest || ""),
    aa_shard_roots: Array(16).fill(sha256Hex("shard")),
    last_unit: sha256Hex("last"),
    seq: sd.height,
    fill_count: sd.fill_count || 0,
    fills_hash: sha256Hex("fills"),
    assertion_version: sd.assertion_version || 1,
    wit_root: sd.wit_root,
    trace_root: sd.trace_root,
    units_root: sd.units_root,
    units_set_root: sd.units_set_root,
    unit_count: sd.unit_count,
    wit_count: sd.wit_count,
    ops_root: sd.ops_root,
    fills_root: sd.fills_root,
    counts_root: sd.counts_root,
    frames_blob: blob,
    data_root: crypto.createHash("sha256").update(raw).digest("hex"),
  };
}
function tempDataMsg(data) {
  return {
    app: "temp_data",
    payload_location: "inline",
    payload: {
      data_length: require("ocore/object_length.js").getLength(data, true),
      data_hash: require("ocore/object_hash.js").getBase64Hash(data, true),
      data,
    },
  };
}
async function sendCombinedSubmit(wallet, height, stateRoot, prev) {
  const sd = submitData(height, stateRoot, prev);
  const header = headerFromSubmit(sd);
  const r = await wallet.sendMulti({
    messages: [
      tempDataMsg(header),
      { app: "data", payload: sd },
    ],
    base_outputs: [{ address: ROLLUP_ADDR, amount: SUBMIT_FEE }],
  });
  if (r.error) throw new Error("combined submit failed: " + r.error);
  await network.witnessUntilStable(r.unit);
  // sendMulti reports composer errors only; the AA bounce surfaces on the
  // response unit — fail fast here instead of cascading 'no height' later.
  const res = await network.getAaResponseToUnit(r.unit).catch(() => null);
  const log = JSON.stringify(res || {});
  if (log.includes('"bounced":true')) {
    throw new Error("combined submit bounced: " + log.slice(0, 1500));
  }
  return r;
}

async function main() {
  console.log("rollup address (precomputed):", ROLLUP_ADDR);
  console.log("dispute address (precomputed):", DISPUTE_ADDR);
  console.log("fill address (precomputed):", FILL_ADDR);

  network = await Network.create()
    .with.agent({ rollup: ROLLUP_SRC })
    .with.agent({ dispute: DISPUTE_SRC })
    .with.agent({ fill: FILL_SRC })
    .with.agent({ vault: VAULT_SRC })
    .with.wallet({ operator: 2e14 })
    .with.wallet({ challenger: 1e13 })
    .with.wallet({ challenger2: 2e13 })
    .run();
  const { operator, challenger, challenger2 } = network.wallet;
  const rollup = network.agent.rollup;
  const dispute = network.agent.dispute;
  const fill = network.agent.fill;
  const vault = network.agent.vault;
  if (rollup !== ROLLUP_ADDR) throw new Error(`rollup address mismatch: ${rollup} != ${ROLLUP_ADDR}`);
  console.log("network up:", { rollup, dispute, fill, vault });

  // ---- 1. bind dispute + fill ------------------------------------------------
  await trigger(operator, dispute, { bind: 1, rollup: ROLLUP_ADDR }, 20000);
  await trigger(operator, fill, { bind_fill: 1, rollup: ROLLUP_ADDR }, 20000);
  let st = await vars(rollup);
  if (String(st.dispute_aa) !== dispute) throw new Error("dispute_aa not set: " + JSON.stringify(st.dispute_aa));
  if (String(st.dispute_fill_aa) !== fill) throw new Error("dispute_fill_aa not set: " + JSON.stringify(st.dispute_fill_aa));
  console.log("1. bind ok — dispute_aa + dispute_fill_aa set");
  // #13: a foreign sender (wallet or any other AA) cannot set_dispute —
  // the rollup only accepts the two addresses hardcoded into its def.
  await triggerBounce(operator, rollup, { set_dispute: 1 }, 20000, "not authorized");
  await triggerBounce(operator, rollup, { set_dispute_fill: 1 }, 20000, "not authorized");
  // A second bind succeeds on the dispute AA (it just re-forwards), but the
  // rollup bounces the secondary 'not authorized' verdict — dispute_aa var
  // must be unchanged afterwards.
  await trigger(operator, dispute, { bind: 1, rollup: ROLLUP_ADDR }, 20000);
  st = await vars(rollup);
  if (String(st.dispute_aa) !== dispute) throw new Error("double bind overwrote dispute_aa!");

  // ---- 2. pool gate: no pool → 'need pool'; fund {pool:1} → gate passes ----
  const sd = submitData(1, STATE_ROOT, PREV_ROOT);
  await triggerBounce(operator, rollup, Object.assign({}, sd, { height: 1 }), 20000, "need pool");
  await trigger(operator, rollup, { pool: 1 }, POOL_FUND_GROSS);
  st = await vars(rollup);
  if (Number(st["pool_" + (await operator.getAddress())] || 0) < 1000000000000)
    throw new Error("pool not funded: " + JSON.stringify(st["pool_" + (await operator.getAddress())]));
  console.log("2. pool gate ok — funded standing pool");

  // ---- 3. combined submit height 1 --------------------------------------
  await sendCombinedSubmit(operator, 1, STATE_ROOT, PREV_ROOT);
  st = await vars(rollup);
  if (Number(st.last_submitted) !== 1) throw new Error("last_submitted != 1: " + st.last_submitted);
  if (st.state_root_1 !== STATE_ROOT) throw new Error("state_root_1 mismatch");
  if (st.da_unit_1 === undefined) throw new Error("da_unit_1 not pinned");
  // resubmit same height → 'bad submit' (h != last_submitted+1; the
  // 'height taken' gate only applies to a fresh h == last_submitted+1)
  await triggerBounce(operator, rollup, submitData(1, STATE_ROOT, PREV_ROOT), SUBMIT_FEE, "bad submit");
  console.log("3. combined submit ok, resubmit rejected");

  // ---- 4. lock/challenge are dead paths ---------------------------------
  await triggerBounce(operator, rollup, { lock: 1, height: 1 }, 20000, "neither case is true in messages");
  await triggerBounce(operator, rollup, { challenge: 1, height: 1 }, 1000000000000, "neither case is true in messages");
  st = await vars(rollup);
  if (Number(st.frozen_1 || 0) !== 0) throw new Error("height 1 frozen by dead path!");
  console.log("4. lock/challenge have no cases — assertion untouched");

  // ---- 5. finalize windows ----------------------------------------------
  await triggerBounce(operator, rollup, { finalize: 1, height: 1 }, 20000, "cannot finalize");
  await network.timetravel({ shift: "3600s" });
  await trigger(operator, rollup, { finalize: 1, height: 1 }, 20000);
  st = await vars(rollup);
  if (Number(st.last_finalized) !== 1) throw new Error("last_finalized != 1");
  if (Number(st["reward_" + (await operator.getAddress())] || 0) !== RACE_REWARD)
    throw new Error("operator race reward not accrued");
  console.log("5. finalize ok, race reward accrued, no sbond credit");
  if (Number(st["sbond_" + (await operator.getAddress())] || 0) !== 0)
    throw new Error("finalize must not credit sbond under pool model");

  // ---- 6. honest deposit predicate bounces 'no fraud' --------------------
  // All proofs are real merkle.getMerkleProof paths. post_wit commits a
  // single-leaf post tree [postLeaf]; pre leaves prove in GENESIS_LEAVES.
  const acct = DEP_ACCT;
  const opD = "d:" + acct + ":100000";
  const preLeaf = DEP_PRE;
  const postLeaf = `acct:${acct}:1100000:0:0`;
  const OPS1 = pad2([opD], "ops1");
  const POST1 = pad2([postLeaf], "post1");
  const POST_WIT1 = merkle.getMerkleRoot(POST1);
  const TRACE1 = pad2([POST_WIT1], "trace1");
  const OPS_ROOT1 = merkle.getMerkleRoot(OPS1);
  const TRACE_ROOT1 = merkle.getMerkleRoot(TRACE1);
  // Height 2 submit carrying the REAL roots the predicates stale-check.
  // Each scenario needs a FRESH height-2 candidate: a second submit to the
  // same live height bounces 'height taken' and the AA keeps the ORIGINAL
  // committed roots, so every predicate would stale-root. Pattern: submit →
  // prove fraud (frozen=2, height reopens) → next scenario re-submits.
  async function submitH2(opsRoot, traceRoot, unitsSetRoot, fillsRoot, witRoot, witCount) {
    const sd = submitData(2, STATE_ROOT, STATE_ROOT);
    sd.ops_root = opsRoot;
    sd.trace_root = traceRoot;
    sd.units_root = UNITS_SET_ROOT;
    sd.units_set_root = unitsSetRoot;
    sd.fills_root = fillsRoot;
    sd.unit_count = 1;
    sd.wit_root = witRoot || WIT_ROOT;
    sd.wit_count = witCount || GEN_WIT_COUNT;
    const h2header = headerFromSubmit(sd);
    const r = await operator.sendMulti({
      messages: [
        tempDataMsg(h2header),
        { app: "data", payload: sd },
      ],
      base_outputs: [{ address: rollup, amount: SUBMIT_FEE }],
    });
    if (r.error) throw new Error("h2 submit failed: " + r.error);
    await network.witnessUntilStable(r.unit);
    const res = await network.getAaResponseToUnit(r.unit).catch(() => null);
    if (res && res.response && res.response.bounced)
      throw new Error("h2 submit bounced: " + bounceDetail(res));
  }
  // H3 pre-tree (genesis leaves + two live orders) is hoisted here because
  // scenario 8's honest h2 submit must ALREADY commit it as wit_root_2:
  // every h3 k=0 predicate anchors pre_wit on wit_root_2.
  const MAKER_ORD = `ord:${"d".repeat(64)}:1:1:100000000:7:5:${"c".repeat(64)}:0:0`;
  const BETTER_ORD = `ord:${"e".repeat(63)}f:1:1:90000000:6:9:${"c".repeat(64)}:0:0`;
  const H3_PRE = [DEP_PRE, FILL_TAKER_PRE, META1, META2, POS2, MAKER_ORD, BETTER_ORD].sort();
  const H3_PRE_WIT = merkle.getMerkleRoot(H3_PRE);
  const H3_PRE_IDX = {};
  H3_PRE.forEach((l, i) => { H3_PRE_IDX[l] = i; });
  // h3 commits ONE real unit: fill predicates bind $F[1] to units_root via
  // units_proof (index == k), so the committed root must be a genuine
  // merkle root over a unit-hex array, not a seed hash.
  const H3_UNIT_HEX = sha256Hex("h3-unit");
  const UNITS3 = pad2([H3_UNIT_HEX], "units3");
  const UNITS3_ROOT = merkle.getMerkleRoot(UNITS3);
  const UNITS3_PROOF = merkle.getMerkleProof(UNITS3, 0);
  async function triggerVerdict(wallet, to, data, amount, what) {
    const t = await trigger(wallet, to, data, amount);
    const r = await network.getAaResponseToUnit(t.unit).catch(() => null);
    const inner = r && r.response && (r.response.response || r.response);
    if (r && r.response && r.response.bounced)
      throw new Error(what + " bounced: " + bounceDetail(r));
    await network.witnessUntilStable(r.response.response_unit);
  }
  const forcedOmit = sha256Hex("forced-unit");
  await trigger(operator, rollup, { force: 1, unit_id: forcedOmit }, 20000);
  await network.timetravel({ shift: "60s" }); // force ts strictly < inbox_upto_2
  const otherId = sha256Hex("other-unit");
  const SET1 = pad2([otherId], "set1");
  const SET_ROOT1 = merkle.getMerkleRoot(SET1);
  // ---- 6. omit: force empty hole (#23) → 'no fraud', height stays live ----
  // The LIAR trace commits here once: scenario 6 cannot freeze, and 7 must
  // not re-submit the same live height ('height taken').
  const LIAR_POST1 = pad2([`acct:${acct}:1000000:0:0`], "liar1");
  const LIAR_WIT1 = merkle.getMerkleRoot(LIAR_POST1);
  const LIAR_TRACE1 = pad2([LIAR_WIT1], "liartrace1");
  const LIAR_TRACE_ROOT1 = merkle.getMerkleRoot(LIAR_TRACE1);
  await submitH2(OPS_ROOT1, LIAR_TRACE_ROOT1, SET_ROOT1, FILLS_ROOT);
  const omitProof = {
    rollup: ROLLUP_ADDR,
    trace_root: LIAR_TRACE_ROOT1,
    ops_root: OPS_ROOT1,
    units_root: UNITS_SET_ROOT,
    units_set_root: SET_ROOT1,
    fills_root: FILLS_ROOT,
    unit_id: forcedOmit,
    left: otherId,
    left_proof: merkle.getMerkleProof(SET1, 0),
  };
  await triggerBounce(challenger, dispute, Object.assign({ pred: "omit", height: 2 }, omitProof), 20000, "no fraud");
  st = await vars(rollup);
  if (Number(st.frozen_2 || 0) !== 0) throw new Error("omit force-hole froze the height!");
  console.log("6. omit force-hole bounced 'no fraud' — height live");

  const depPreIdx = GENESIS_LEAVES.indexOf(preLeaf);

  // ---- 7. deposit fraud on the committed LIAR trace → verdict, slash ----
  const fraudProof = {
    rollup: ROLLUP_ADDR,
    k: 0,
    op: opD,
    ops_proof: merkle.getMerkleProof(OPS1, 0),
    trace_root: LIAR_TRACE_ROOT1,
    ops_root: OPS_ROOT1,
    units_root: UNITS_SET_ROOT,
    units_set_root: SET_ROOT1,
    fills_root: FILLS_ROOT,
    pre_wit: WIT_ROOT,
    post_wit: LIAR_WIT1,
    post_proof: merkle.getMerkleProof(LIAR_TRACE1, 0),
    pre_leaf: preLeaf,
    post_leaf: LIAR_POST1[0], // col unchanged despite +100 deposit
    pre_leaf_proof: merkle.getMerkleProof(GENESIS_LEAVES, depPreIdx),
    post_leaf_proof: merkle.getMerkleProof(LIAR_POST1, 0),
  };
  await triggerVerdict(challenger, dispute, Object.assign({ pred: "deposit", height: 2 }, fraudProof), 20000, "deposit fraud predicate");
  st = await vars(rollup);
  const chAddr = await challenger.getAddress();
  // First verdict of the run (scenario 6 no longer pays out).
  if (Number(st["slash_reward_" + chAddr] || 0) !== SLASH_HALF)
    throw new Error("slash reward wrong: " + JSON.stringify(st["slash_reward_" + chAddr]));
  // Verdict slashes the standing pool by 5e11 per fraud (1 so far).
  const opAddr = await operator.getAddress();
  const poolNet = POOL_FUND_GROSS - 10000; // {pool:1} credits net of bounce fee
  if (Number(st["pool_" + opAddr] || 0) !== Number(poolNet - SLASH_HALF))
    throw new Error("pool not slashed by fraud: " + JSON.stringify(st["pool_" + opAddr]));
  // Challenger withdraws the banked slash: payout + zeroed key (no double-claim).
  await trigger(challenger, rollup, { claim: "slash" }, 20000);
  st = await vars(rollup);
  if (Number(st["slash_reward_" + chAddr] || 0) !== 0) throw new Error("slash not paid out");
  console.log("7. deposit fraud verdict: height failed, slashed, challenger paid");

  // ---- 8. honest deposit → 'no fraud' (height stays live) ------------------
  // This assertion ALSO commits wit_root_2 = H3_PRE_WIT: every h3 k=0
  // predicate anchors pre_wit on it.
  await submitH2(OPS_ROOT1, TRACE_ROOT1, SET_ROOT1, FILLS_ROOT, H3_PRE_WIT, H3_PRE.length);
  const honestProof = {
    rollup: ROLLUP_ADDR,
    k: 0,
    op: opD,
    ops_proof: merkle.getMerkleProof(OPS1, 0),
    trace_root: TRACE_ROOT1,
    ops_root: OPS_ROOT1,
    units_root: UNITS_SET_ROOT,
    units_set_root: SET_ROOT1,
    fills_root: FILLS_ROOT,
    pre_wit: WIT_ROOT, // k=0, h=2 -> wit_root_1 (genesis tree)
    post_wit: POST_WIT1,
    post_proof: merkle.getMerkleProof(TRACE1, 0),
    pre_leaf: preLeaf,
    post_leaf: postLeaf,
    pre_leaf_proof: merkle.getMerkleProof(GENESIS_LEAVES, depPreIdx),
    post_leaf_proof: merkle.getMerkleProof(POST1, 0),
  };
  await triggerBounce(challenger, dispute, Object.assign({ pred: "deposit", height: 2 }, honestProof), 20000, "no fraud");
  st = await vars(rollup);
  if (Number(st.frozen_2 || 0) !== 0) throw new Error("honest predicate froze the height!");
  console.log("8. honest deposit predicate bounced 'no fraud' — height live");

  // ---- 9. finalize h2, proceed on h3 with real trees -----------------------
  await network.timetravel({ shift: "3600s" });
  await trigger(operator, rollup, { finalize: 1, height: 2 }, 20000);
  st = await vars(rollup);
  // ---- 10. submit h3 committing the honest post tree (taker col -500) ----
  // exp = -500 (flat pre col 0, 5 bps fee on the 1e6 notional): a negative
  // expected post is exactly the claw-bail shape — a committed lie at this
  // shape is deliberately unchallengeable (an honest loser can stay
  // negative when the winner cannot pay the claw); verdict coverage for
  // provable lies moved to 19a (isolated) and 19b (cross, empty range).
  const takerH = FILL_TAKER;
  const fillStr = `f:${H3_UNIT_HEX}:0:${takerH}:${"c".repeat(64)}:${"d".repeat(64)}:${"e".repeat(64)}:1:100000000:100000000:9:0:0:0`;
  const FILLS1 = [fillStr];
  const FILLS1_TREE = fillsTree(FILLS1);
  const FILLS_ROOT1 = merkle.getMerkleRoot(FILLS1_TREE);
  // h3 heights commit a PLACE op at k (cross): the fill_math taker leg
  // proves the unit op is this fill's own p: Place and reads its isolated
  // flag; deposit heights (h2) keep OPS_ROOT1's d: op.
  const FILL_OP = `p:${takerH}:1:0:100000000:100000000:0:0:0`;
  const OPS3 = pad2([FILL_OP], "ops3");
  const OPS3_ROOT = merkle.getMerkleRoot(OPS3);
  const OPS3_PROOF = merkle.getMerkleProof(OPS3, 0);
  const POST_H = [`acct:${takerH}:-500:0:0`, META1, `pos:${takerH}:1:100000000:100000000:0:0`].sort();
  const POST_H_WIT = merkle.getMerkleRoot(POST_H);
  const TRACE_H = pad2([POST_H_WIT], "traceh");
  const TRACE_H_ROOT = merkle.getMerkleRoot(TRACE_H);
  const sd3 = submitData(3, STATE_ROOT, STATE_ROOT);
  sd3.wit_root = H3_PRE_WIT;
  sd3.wit_count = H3_PRE.length;
  sd3.trace_root = TRACE_H_ROOT;
  sd3.fills_root = FILLS_ROOT1;
  sd3.ops_root = OPS3_ROOT;
  sd3.units_root = UNITS3_ROOT;
  sd3.fill_count = 1;
  {
    const h3data = { chain_id: "operp-v2", height: 3 };
    const r = await operator.sendMulti({
      messages: [
        { app: "temp_data", payload_location: "inline", payload: {
          data_length: require("ocore/object_length.js").getLength(h3data, true),
          data_hash: require("ocore/object_hash.js").getBase64Hash(h3data, true),
          data: h3data } },
        { app: "data", payload: sd3 },
      ],
      base_outputs: [{ address: rollup, amount: SUBMIT_FEE }],
    });
    if (r.error) throw new Error("h3 submit failed: " + r.error);
    await network.witnessUntilStable(r.unit);
    const res = await network.getAaResponseToUnit(r.unit).catch(() => null);
    if (res && res.response && res.response.bounced)
      throw new Error("h3 submit bounced: " + bounceDetail(res));
  }

  // ---- 11. fill_math honest cross (bail: exp < 0) ------------------------
  // price=1e8 qty=1e8 -> notional 1e6, fee 5bps=500 -> exp col -500.
  // The committed leaves are honest AND the shape is the claw-bail one:
  // the AA bounces 'no fraud' before any identity comparison (an honest
  // loser can remain negative when the winner cannot pay the claw —
  // operp-state::claw_cannot_cover_leaves_both_negative).
  const fillBase = {
    rollup: ROLLUP_ADDR,
    k: 0,
    trace_root: TRACE_H_ROOT,
    fills_root: FILLS_ROOT1,
    ops_root: OPS3_ROOT,
    units_root: UNITS3_ROOT,
    units_proof: UNITS3_PROOF,
    fill: fillStr,
    fill_proof: merkle.getMerkleProof(FILLS1_TREE, 0),
    op: FILL_OP,
    ops_proof: OPS3_PROOF,
    right: FILLS1_TREE[1],
    right_proof: merkle.getMerkleProof(FILLS1_TREE, 1),
    pre_wit: H3_PRE_WIT,
    post_wit: POST_H_WIT,
    post_proof: merkle.getMerkleProof(TRACE_H, 0),
    pre_acct: FILL_TAKER_PRE,
    pre_acct_proof: merkle.getMerkleProof(H3_PRE, H3_PRE_IDX[FILL_TAKER_PRE]),
    post_acct: `acct:${takerH}:-500:0:0`, // engine identity: 0 - 500 fee
    post_acct_proof: merkle.getMerkleProof(POST_H, POST_H.indexOf(`acct:${takerH}:-500:0:0`)),
    post_pos: `pos:${takerH}:1:100000000:100000000:0:0`,
    post_pos_proof: merkle.getMerkleProof(POST_H, POST_H.indexOf(`pos:${takerH}:1:100000000:100000000:0:0`)),
    pre_meta: META1,
    pre_meta_proof: merkle.getMerkleProof(H3_PRE, H3_PRE_IDX[META1]),
    pos_absent: true,
    // Claimed-absent pre pos (market 1): prefix-range neighbors over H3_PRE —
    // BETTER_ORD < pos:{taker}:1: < POS2(market 2)? No: ord < pos always
    // ('o'<'p'), and the pos range sits between BETTER_ORD and POS2.
    pleft: BETTER_ORD,
    pleft_proof: merkle.getMerkleProof(H3_PRE, H3_PRE_IDX[BETTER_ORD]),
    pright: POS2,
    pright_proof: merkle.getMerkleProof(H3_PRE, H3_PRE_IDX[POS2]),
    who: "taker",
  };
  await triggerBounce(challenger, fill, Object.assign({ pred: "fill_math", height: 3 }, fillBase), 20000, "no fraud");
  st = await vars(rollup);
  if (Number(st.frozen_3 || 0) !== 0) throw new Error("honest fill_math froze h3!");
  console.log("11. fill_math (exp<0) bounced 'no fraud' — height live");

  async function submitH3(traceRoot, fillsRoot) {
    const s = submitData(3, STATE_ROOT, STATE_ROOT);
    s.wit_root = H3_PRE_WIT;
    s.wit_count = H3_PRE.length;
    s.trace_root = traceRoot;
    s.fills_root = fillsRoot;
    s.ops_root = OPS3_ROOT;
    s.units_root = UNITS3_ROOT;
    s.fill_count = 1;
    const h3header = headerFromSubmit(s);
    const r = await operator.sendMulti({
      messages: [
        tempDataMsg(h3header),
        { app: "data", payload: s },
      ],
      base_outputs: [{ address: rollup, amount: SUBMIT_FEE }],
    });
    if (r.error) throw new Error("h3 submit failed: " + r.error);
    await network.witnessUntilStable(r.unit);
    const res = await network.getAaResponseToUnit(r.unit).catch(() => null);
    if (res && res.response && res.response.bounced)
      throw new Error("h3 submit bounced: " + bounceDetail(res));
  }

  // ---- 12. ghost: maker order absent → fraud -------------------------------
  // maker id "e"*64 has no ord leaf in H3_PRE. Sorted H3_PRE runs
  // ... MAKER_ORD(ord:d, idx4), BETTER_ORD(ord:eee..f, idx5), POS2(idx6):
  // the whole ord:{e*64}: range sits between MAKER_ORD and BETTER_ORD.
  const ghostOrd = `ord:${"e".repeat(64)}:1:1:100000000:9:3:${"c".repeat(64)}:0:0`;
  const gSorted = H3_PRE;
  const gMaker = gSorted.indexOf(MAKER_ORD);
  const gBetter = gSorted.indexOf(BETTER_ORD);
  if (gBetter !== gMaker + 1) throw new Error("ghost fixture not adjacent");
  const ghostLo = `ord:${"e".repeat(64)}:`;
  const ghostHi = `ord:${"e".repeat(64)};`;
  if (!(gSorted[gMaker] < ghostLo && ghostHi <= gSorted[gBetter])) throw new Error("ghost fixture not straddling");
  const ghostProof = {
    rollup: ROLLUP_ADDR,
    k: 0,
    trace_root: TRACE_H_ROOT,
    fills_root: FILLS_ROOT1,
    ops_root: OPS3_ROOT,
    units_root: UNITS3_ROOT,
    units_proof: UNITS3_PROOF,
    fill: fillStr,
    fill_proof: merkle.getMerkleProof(FILLS1_TREE, 0),
    pre_wit: H3_PRE_WIT,
    maker_ord: ghostOrd,
    left: gSorted[gMaker],
    left_proof: merkle.getMerkleProof(gSorted, gMaker),
    right: gSorted[gBetter],
    right_proof: merkle.getMerkleProof(gSorted, gBetter),
  };
  await triggerVerdict(challenger, dispute, Object.assign({ pred: "ghost", height: 3 }, ghostProof), 20000, "ghost predicate");
  st = await vars(rollup);
  if (Number(st.frozen_3) !== 2) throw new Error("ghost fraud did not freeze height");
  console.log("12. ghost (absent maker) → frozen=3");

  // ---- 13. skip: better live order ignored → fraud -------------------------
  const SKIP_TRACE4 = pad2([`skip-post-wit`], "skiptrace4");
  const SKIP_TRACE4_ROOT = merkle.getMerkleRoot(SKIP_TRACE4);
  const SKIP_FILLS = [`f:${H3_UNIT_HEX}:0:${FILL_TAKER}:${"c".repeat(64)}:${"d".repeat(64)}:${"d".repeat(64)}:1:100000000:50000000:7:0:0:0`];
  const SKIP_FILLS_TREE = fillsTree(SKIP_FILLS);
  const SKIP_FILLS_ROOT = merkle.getMerkleRoot(SKIP_FILLS_TREE);
  // h3 was frozen by ghost: re-submit carrying the skip assertion's roots.
  await submitH3(SKIP_TRACE4_ROOT, SKIP_FILLS_ROOT);
  const skipProof = {
    rollup: ROLLUP_ADDR,
    k: 0,
    trace_root: SKIP_TRACE4_ROOT,
    fills_root: SKIP_FILLS_ROOT,
    ops_root: OPS3_ROOT,
    units_root: UNITS3_ROOT,
    units_proof: UNITS3_PROOF,
    fill: SKIP_FILLS[0],
    fill_proof: merkle.getMerkleProof(SKIP_FILLS_TREE, 0),
    pre_wit: H3_PRE_WIT,
    maker_ord: MAKER_ORD,
    maker_proof: merkle.getMerkleProof(H3_PRE, H3_PRE.indexOf(MAKER_ORD)),
    better_ord: BETTER_ORD,
    better_proof: merkle.getMerkleProof(H3_PRE, H3_PRE.indexOf(BETTER_ORD)),
  };
  await triggerVerdict(challenger, dispute, Object.assign({ pred: "skip", height: 3 }, skipProof), 20000, "skip predicate");
  st = await vars(rollup);
  if (Number(st.frozen_3) !== 2) throw new Error("skip fraud did not freeze height");
  console.log("13. skip (better order ignored) → frozen=3");
  // ---- 13a. fill with a FAKE unit hex → 'bad unit', no verdict (#1) -------
  // NEG_FILL's unit hex is u*64, not the h3 unit committed in units_root:
  // units_proof cannot verify it, so the predicate must bounce before any
  // math. This is the exact class the old AA let through to a verdict.
  const NEG_FILL = `f:${"u".repeat(64)}:0:${takerH}:${"c".repeat(64)}:${"d".repeat(64)}:${"e".repeat(64)}:1:-100000000:100000000:9:0:0:0`;
  const NEG_FILLS = [NEG_FILL];
  const NEG_FILLS_TREE = fillsTree(NEG_FILLS);
  const NEG_FILLS_ROOT = merkle.getMerkleRoot(NEG_FILLS_TREE);
  const NEG_POST_LIAR = [`acct:${takerH}:-499:0:0`, META1, `pos:${takerH}:1:100000000:-100000000:0:0`].sort();
  const NEG_POST_LIAR_WIT = merkle.getMerkleRoot(NEG_POST_LIAR);
  const NEG_TRACE = pad2([NEG_POST_LIAR_WIT], "negtrace");
  const NEG_TRACE_ROOT = merkle.getMerkleRoot(NEG_TRACE);
  await submitH3(NEG_TRACE_ROOT, NEG_FILLS_ROOT);
  const negBase = Object.assign({}, fillBase, {
    trace_root: NEG_TRACE_ROOT,
    fills_root: NEG_FILLS_ROOT,
    fill: NEG_FILL,
    fill_proof: merkle.getMerkleProof(NEG_FILLS_TREE, 0),
    right: NEG_FILLS_TREE[1],
    right_proof: merkle.getMerkleProof(NEG_FILLS_TREE, 1),
    post_wit: NEG_POST_LIAR_WIT,
    post_proof: merkle.getMerkleProof(NEG_TRACE, 0),
    post_acct: `acct:${takerH}:-499:0:0`,
    post_acct_proof: merkle.getMerkleProof(NEG_POST_LIAR, NEG_POST_LIAR.indexOf(`acct:${takerH}:-499:0:0`)),
    post_pos: `pos:${takerH}:1:100000000:-100000000:0:0`,
    post_pos_proof: merkle.getMerkleProof(NEG_POST_LIAR, NEG_POST_LIAR.indexOf(`pos:${takerH}:1:100000000:-100000000:0:0`)),
  });
  await triggerBounce(challenger, fill, Object.assign({ pred: "fill_math", height: 3 }, negBase), 20000, "bad unit");
  console.log("13a. fake unit hex bounced 'bad unit' — no verdict");

  // ---- 14. two-package height: deposit-fraud predicate fires, height fails --
  // 13a's NEG submit left last_submitted=3 (a bounce rolls nothing back), so
  // the two-package assertion goes to h4: prev=STATE_ROOT == state_root_3.
  // Two 1-unit packages post first (JS join+base64, no helper binary), then
  // the da_unit header nails the real package hashes + data_root. The fraud
  // verdict proves the multi-package DA reveal feeds the same predicate path
  // as single-package inline.
  const PKG_OP = "d:" + DEP_ACCT + ":100000";
  const PKG_OPS = pad2([PKG_OP], "pkgops");
  const PKG_OPS_ROOT = merkle.getMerkleRoot(PKG_OPS);
  const PKG_POST = pad2([`acct:${DEP_ACCT}:1000000:0:0`], "pkgpost");
  const PKG_WIT = merkle.getMerkleRoot(PKG_POST);
  const PKG_TRACE = pad2([PKG_WIT], "pkgtrace");
  const PKG_TRACE_ROOT = merkle.getMerkleRoot(PKG_TRACE);
  const frameA = JSON.stringify({ u: { op: "a" }, t: PKG_TRACE_ROOT, o: PKG_OP, c: "1" });
  const frameB = JSON.stringify({ u: { op: "b" }, t: PKG_TRACE_ROOT, o: PKG_OP, c: "1" });
  const blobA = zlib.gzipSync(Buffer.from(frameA, "utf8")).toString("base64");
  const blobB = zlib.gzipSync(Buffer.from(frameB, "utf8")).toString("base64");
  const rawA = zlib.gunzipSync(Buffer.from(blobA, "base64"));
  const rawB = zlib.gunzipSync(Buffer.from(blobB, "base64"));
  const shaHex = (b) => crypto.createHash("sha256").update(b).digest("hex");
  const sd4pkg = submitData(4, STATE_ROOT, STATE_ROOT);
  sd4pkg.ops_root = PKG_OPS_ROOT;
  sd4pkg.trace_root = PKG_TRACE_ROOT;
  sd4pkg.units_root = UNITS_SET_ROOT;
  sd4pkg.units_set_root = SET_ROOT1;
  // Full header scalars from the submit (same helper as single-package),
  // then packages = REAL package unit hashes (pr.unit) so watchers can
  // get_joint each entry; data_root = sha256 of concatenated blob bytes.
  const h4pkg = headerFromSubmit(sd4pkg, PKG_OP);
  h4pkg.data_root = shaHex(Buffer.concat([rawA, rawB]));
  {
    const pkgMsg = (blob) => ({ app: "temp_data", payload_location: "inline", payload: {
      data_length: require("ocore/object_length.js").getLength({ package_blob: blob }, true),
      data_hash: require("ocore/object_hash.js").getBase64Hash({ package_blob: blob }, true),
      data: { package_blob: blob } } });
    const pr1 = await operator.sendMulti({
      messages: [pkgMsg(blobA)],
      base_outputs: [{ address: await operator.getAddress(), amount: 10000 }],
    });
    if (pr1.error) throw new Error("package 1 post failed: " + pr1.error);
    await network.witnessUntilStable(pr1.unit);
    const pr2 = await operator.sendMulti({
      messages: [pkgMsg(blobB)],
      base_outputs: [{ address: await operator.getAddress(), amount: 10000 }],
    });
    if (pr2.error) throw new Error("package 2 post failed: " + pr2.error);
    await network.witnessUntilStable(pr2.unit);
    delete h4pkg.frames_blob;
    h4pkg.packages = [pr1.unit, pr2.unit];
    const r3p = await operator.sendMulti({
      messages: [
        tempDataMsg(h4pkg),
        { app: "data", payload: sd4pkg },
      ],
      base_outputs: [{ address: rollup, amount: SUBMIT_FEE }],
    });
    if (r3p.error) throw new Error("h4 2-package submit failed: " + r3p.error);
    await network.witnessUntilStable(r3p.unit);
    const res3p = await network.getAaResponseToUnit(r3p.unit).catch(() => null);
    if (res3p && res3p.response && res3p.response.bounced)
      throw new Error("h4 2-package submit bounced: " + bounceDetail(res3p));
  }
  const pkgFraud = {
    rollup: ROLLUP_ADDR,
    k: 0,
    op: PKG_OP,
    ops_proof: merkle.getMerkleProof(PKG_OPS, 0),
    trace_root: PKG_TRACE_ROOT,
    ops_root: PKG_OPS_ROOT,
    units_root: UNITS_SET_ROOT,
    units_set_root: SET_ROOT1,
    fills_root: FILLS_ROOT,
    pre_wit: H3_PRE_WIT,
    post_wit: PKG_WIT,
    post_proof: merkle.getMerkleProof(PKG_TRACE, 0),
    pre_leaf: DEP_PRE,
    post_leaf: PKG_POST[0],
    pre_leaf_proof: merkle.getMerkleProof(H3_PRE, H3_PRE_IDX[DEP_PRE]),
    post_leaf_proof: merkle.getMerkleProof(PKG_POST, 0),
  };
  await triggerVerdict(challenger, dispute, Object.assign({ pred: "deposit", height: 4 }, pkgFraud), 20000, "2-package deposit fraud predicate");
  st = await vars(rollup);
  if (Number(st.frozen_4) !== 2) throw new Error("2-package fraud did not freeze height");
  console.log("14. 2-package height deposit fraud → frozen=4");
  // ---- 15. re-submit + finalize after fraud works -------------------------
  await sendCombinedSubmit(operator, 4, STATE_ROOT, STATE_ROOT);
  await network.timetravel({ shift: "3600s" });
  // Heights finalize in order: h3 (the NEG-submit height, never frauded
  // away) first, then the re-submitted h4.
  await trigger(operator, rollup, { finalize: 1, height: 3 }, 20000);
  await trigger(operator, rollup, { finalize: 1, height: 4 }, 20000);
  st = await vars(rollup);
  if (Number(st.last_finalized) !== 4) throw new Error("re-finalize after fraud failed");
  console.log("15. re-submit + finalize after fraud ok");
  // ---- 16. pipeline: h5 + h6 with no finalize between ---------------------
  // Occupancy is last_submitted-last_finalized = 2 < 50, so the second submit
  // must NOT bounce. Then timetravel once, finalize in order.
  await sendCombinedSubmit(operator, 5, STATE_ROOT, STATE_ROOT);
  await sendCombinedSubmit(operator, 6, STATE_ROOT, STATE_ROOT);
  st = await vars(rollup);
  if (Number(st.last_submitted) !== 6) throw new Error("pipeline submits failed: " + st.last_submitted);
  if (Number(st.last_finalized) !== 4) throw new Error("pipeline must not finalize early");
  console.log("16. pipeline h5+h6 submitted with no inter-finalize");
  await network.timetravel({ shift: "3600s" });
  await trigger(operator, rollup, { finalize: 1, height: 5 }, 20000);
  await trigger(operator, rollup, { finalize: 1, height: 6 }, 20000);
  st = await vars(rollup);
  if (Number(st.last_finalized) !== 6) throw new Error("pipelined finalize failed");
  console.log("16a. pipelined h5+h6 finalized in order");
  // ---- 17. pool claim when chain idle; pool busy otherwise -----------------
  // Chain idle (ls==lf==6): operator claims the standing pool back.
  const poolBefore = Number(st["pool_" + (await operator.getAddress())] || 0);
  if (!(poolBefore >= 1000000000000)) throw new Error("pool below floor after slashes: " + poolBefore);
  await sendCombinedSubmit(operator, 7, STATE_ROOT, STATE_ROOT);
  await triggerBounce(operator, rollup, { claim: "pool" }, 20000, "pool busy");
  await network.timetravel({ shift: "3600s" });
  await trigger(operator, rollup, { finalize: 1, height: 7 }, 20000);
  await trigger(operator, rollup, { claim: "pool" }, 20000);
  st = await vars(rollup);
  if (Number(st["pool_" + (await operator.getAddress())] || 0) !== 0)
    throw new Error("pool not zeroed after claim");
  console.log("17. pool claim ok when idle, busy otherwise");
  // ---- 18. depleted pool: drained operator bounces 'need pool' --------------
  // Scenario 17 claimed the operator pool to zero — the same state a
  // slash-depleted operator lands in. Its next submit must bounce
  // 'need pool' until a fresh {pool:1} top-up; then the gate reopens.
  await triggerBounce(operator, rollup, submitData(8, STATE_ROOT, STATE_ROOT), 20000, "need pool");
  await trigger(operator, rollup, { pool: 1 }, POOL_FUND_GROSS);
  await sendCombinedSubmit(operator, 8, STATE_ROOT, STATE_ROOT);
  st = await vars(rollup);
  if (Number(st.last_submitted) !== 8) throw new Error("re-submit after pool top-up failed");
  console.log("18. depleted pool bounces 'need pool'; top-up reopens submit");

  // ---- 19. PR 33 residuals: exact identity + sentinel right neighbor ----
  // Fresh heights 9-11 (k=0, pre_wit anchored on wit_root_8 = WIT_ROOT):
  //  19a. isolated taker open that escrowed margin, INFLATED post col
  //       -> verdict (the old >= branch accepted any larger post);
  //  19b. cross taker, post range proven empty, post col = exp + 1
  //       -> verdict (exact empty-range identity);
  //  19c. honest isolated open -> 'no fraud': single-fill completeness
  //       rides the right neighbor, which for the sole fill is the
  //       fills_root length sentinel `n:1`.
  const isoUnit = sha256Hex("iso-unit");
  const isoTOrd = "7".repeat(64);
  const isoMOrd = "3".repeat(64);
  const isoPos = `pos:${DEP_ACCT}:1:100000000:100000000:1:500000`;
  // Engine identity for the isolated open: 1000000 (pre col) - 500000
  // (margin escrowed at place, moved to the bucket, never returned to
  // collateral) - 500 (5bps taker fee on the 1e6 notional) = 499500.
  const isoFill = `f:${isoUnit}:0:${DEP_ACCT}:${"c".repeat(64)}:${isoTOrd}:${isoMOrd}:1:100000000:100000000:9:0:0:500000`;
  const ISO_FILLS = [isoFill];
  const ISO_FILLS_TREE = fillsTree(ISO_FILLS);
  const ISO_FILLS_ROOT = merkle.getMerkleRoot(ISO_FILLS_TREE);
  const isoOp = `p:${DEP_ACCT}:1:0:100000000:100000000:1:500000:0`;
  const ISO_OPS = pad2([isoOp], "isoops");
  const ISO_OPS_ROOT = merkle.getMerkleRoot(ISO_OPS);
  const ISO_UNITS = pad2([isoUnit], "isounits");
  const ISO_UNITS_ROOT = merkle.getMerkleRoot(ISO_UNITS);
  const ISO_UNITS_PROOF = merkle.getMerkleProof(ISO_UNITS, 0);
  const isoPostTree = (col) => [`acct:${DEP_ACCT}:${col}:0:0`, META1, isoPos].sort();
  const ISO_POST = isoPostTree(499500);
  const ISO_POST_WIT = merkle.getMerkleRoot(ISO_POST);
  const ISO_TRACE = pad2([ISO_POST_WIT], "isotrace");
  const ISO_TRACE_ROOT = merkle.getMerkleRoot(ISO_TRACE);
  const ISO_LIAR = isoPostTree(499501);
  const ISO_LIAR_WIT = merkle.getMerkleRoot(ISO_LIAR);
  const ISO_LIAR_TRACE = pad2([ISO_LIAR_WIT], "isoliartrace");
  const ISO_LIAR_TRACE_ROOT = merkle.getMerkleRoot(ISO_LIAR_TRACE);
  // Isolated open payload: single-fill completeness rides the right
  // neighbor — for this sole fill the fills_root length sentinel `n:1` —
  // plus op + ord absence proofs over the post tree.
  const isoFillPayload = (traceRoot, traceArr, postWit, postTree, col) => {
    const acctLeaf = `acct:${DEP_ACCT}:${col}:0:0`;
    return {
      rollup: ROLLUP_ADDR,
      k: 0,
      trace_root: traceRoot,
      fills_root: ISO_FILLS_ROOT,
      ops_root: ISO_OPS_ROOT,
      units_root: ISO_UNITS_ROOT,
      units_proof: ISO_UNITS_PROOF,
      fill: isoFill,
      fill_proof: merkle.getMerkleProof(ISO_FILLS_TREE, 0),
      right: ISO_FILLS_TREE[1],
      right_proof: merkle.getMerkleProof(ISO_FILLS_TREE, 1),
      op: isoOp,
      ops_proof: merkle.getMerkleProof(ISO_OPS, 0),
      pre_wit: WIT_ROOT,
      post_wit: postWit,
      post_proof: merkle.getMerkleProof(traceArr, 0),
      pre_acct: DEP_PRE,
      pre_acct_proof: merkle.getMerkleProof(GENESIS_LEAVES, GENESIS_LEAVES.indexOf(DEP_PRE)),
      post_acct: acctLeaf,
      post_acct_proof: merkle.getMerkleProof(postTree, postTree.indexOf(acctLeaf)),
      post_pos: isoPos,
      post_pos_proof: merkle.getMerkleProof(postTree, postTree.indexOf(isoPos)),
      pre_meta: META1,
      pre_meta_proof: merkle.getMerkleProof(GENESIS_LEAVES, GENESIS_LEAVES.indexOf(META1)),
      pos_absent: true,
      pleft: META2,
      pleft_proof: merkle.getMerkleProof(GENESIS_LEAVES, GENESIS_LEAVES.indexOf(META2)),
      pright: POS2,
      pright_proof: merkle.getMerkleProof(GENESIS_LEAVES, GENESIS_LEAVES.indexOf(POS2)),
      // Taker-ord absence: META1 < ord:7*64: < isoPos straddle post tree.
      oleft: META1,
      oleft_proof: merkle.getMerkleProof(postTree, postTree.indexOf(META1)),
      oright: isoPos,
      oright_proof: merkle.getMerkleProof(postTree, postTree.indexOf(isoPos)),
      who: "taker",
    };
  };
  // A fraud verdict rolls last_submitted back (h-1), so all three run as
  // re-submits of height 9: liar → verdict, cross → verdict, honest →
  // bounce (the only shape that leaves the height live).
  async function submitIsoH(traceRoot, fillsRoot, opsRoot, witCount) {
    const s = submitData(9, STATE_ROOT, STATE_ROOT);
    s.wit_root = WIT_ROOT; // k=0 pre anchors on wit_root_8 (scenario 18)
    s.wit_count = witCount;
    s.trace_root = traceRoot;
    s.fills_root = fillsRoot;
    s.ops_root = opsRoot;
    s.units_root = ISO_UNITS_ROOT;
    s.fill_count = 1;
    const hdr = headerFromSubmit(s);
    const r = await operator.sendMulti({
      messages: [tempDataMsg(hdr), { app: "data", payload: s }],
      base_outputs: [{ address: rollup, amount: SUBMIT_FEE }],
    });
    if (r.error) throw new Error("h9 submit failed: " + r.error);
    await network.witnessUntilStable(r.unit);
    const res = await network.getAaResponseToUnit(r.unit).catch(() => null);
    if (res && res.response && res.response.bounced)
      throw new Error("h9 submit bounced: " + bounceDetail(res));
  }
  // 19a. LIAR isolated open: col 499501 (identity + 1) -> verdict.
  await submitIsoH(ISO_LIAR_TRACE_ROOT, ISO_FILLS_ROOT, ISO_OPS_ROOT, 3);
  await triggerVerdict(
    challenger,
    fill,
    Object.assign(
      { pred: "fill_math", height: 9 },
      isoFillPayload(ISO_LIAR_TRACE_ROOT, ISO_LIAR_TRACE, ISO_LIAR_WIT, ISO_LIAR, 499501)
    ),
    20000,
    "isolated exact-identity predicate"
  );
  st = await vars(rollup);
  if (Number(st.frozen_9) !== 2) throw new Error("inflated isolated post col did not freeze h9");
  console.log("19a. isolated escrow identity: inflated post col -> frozen=9");

  // 19b. Cross taker, empty range, post col = exp + 1 -> verdict.
  const crossFill = `f:${isoUnit}:0:${DEP_ACCT}:${"c".repeat(64)}:${"8".repeat(64)}:${isoMOrd}:1:100000000:100000000:9:0:0:0`;
  const CROSS_FILLS = [crossFill];
  const CROSS_FILLS_TREE = fillsTree(CROSS_FILLS);
  const CROSS_FILLS_ROOT = merkle.getMerkleRoot(CROSS_FILLS_TREE);
  const crossOp = `p:${DEP_ACCT}:1:0:100000000:100000000:0:0:0`;
  const CROSS_OPS = pad2([crossOp], "crossops");
  const CROSS_OPS_ROOT = merkle.getMerkleRoot(CROSS_OPS);
  const CROSS_POST = [`acct:${DEP_ACCT}:999501:0:0`, META1].sort();
  const CROSS_POST_WIT = merkle.getMerkleRoot(CROSS_POST);
  const CROSS_TRACE = pad2([CROSS_POST_WIT], "crosstrace");
  const CROSS_TRACE_ROOT = merkle.getMerkleRoot(CROSS_TRACE);
  await submitIsoH(CROSS_TRACE_ROOT, CROSS_FILLS_ROOT, CROSS_OPS_ROOT, 2);
  const crossPayload = {
    rollup: ROLLUP_ADDR,
    k: 0,
    trace_root: CROSS_TRACE_ROOT,
    fills_root: CROSS_FILLS_ROOT,
    ops_root: CROSS_OPS_ROOT,
    units_root: ISO_UNITS_ROOT,
    units_proof: ISO_UNITS_PROOF,
    fill: crossFill,
    fill_proof: merkle.getMerkleProof(CROSS_FILLS_TREE, 0),
    right: CROSS_FILLS_TREE[1],
    right_proof: merkle.getMerkleProof(CROSS_FILLS_TREE, 1),
    op: crossOp,
    ops_proof: merkle.getMerkleProof(CROSS_OPS, 0),
    pre_wit: WIT_ROOT,
    post_wit: CROSS_POST_WIT,
    post_proof: merkle.getMerkleProof(CROSS_TRACE, 0),
    pre_acct: DEP_PRE,
    pre_acct_proof: merkle.getMerkleProof(GENESIS_LEAVES, GENESIS_LEAVES.indexOf(DEP_PRE)),
    post_acct: `acct:${DEP_ACCT}:999501:0:0`,
    post_acct_proof: merkle.getMerkleProof(CROSS_POST, CROSS_POST.indexOf(`acct:${DEP_ACCT}:999501:0:0`)),
    pre_meta: META1,
    pre_meta_proof: merkle.getMerkleProof(GENESIS_LEAVES, GENESIS_LEAVES.indexOf(META1)),
    pos_absent: true,
    pleft: META2,
    pleft_proof: merkle.getMerkleProof(GENESIS_LEAVES, GENESIS_LEAVES.indexOf(META2)),
    pright: POS2,
    pright_proof: merkle.getMerkleProof(GENESIS_LEAVES, GENESIS_LEAVES.indexOf(POS2)),
    // Empty post range (final tree, k+1==n): only a left neighbor below.
    eleft: META1,
    eleft_proof: merkle.getMerkleProof(CROSS_POST, CROSS_POST.indexOf(META1)),
    who: "taker",
  };
  await triggerVerdict(
    challenger,
    fill,
    Object.assign({ pred: "fill_math", height: 9 }, crossPayload),
    20000,
    "cross exact-identity predicate"
  );
  st = await vars(rollup);
  if (Number(st.frozen_9) !== 2) throw new Error("cross exp+1 empty-range col did not freeze h9");
  console.log("19b. cross empty-range exact identity: exp+1 -> frozen=9");

  // 19c. HONEST isolated open: same payload shape, matching post col —
  // completeness rides the `n:1` sentinel right neighbor, then the exact
  // identity bounces 'no fraud'.
  await submitIsoH(ISO_TRACE_ROOT, ISO_FILLS_ROOT, ISO_OPS_ROOT, 3);
  await triggerBounce(
    challenger,
    fill,
    Object.assign(
      { pred: "fill_math", height: 9 },
      isoFillPayload(ISO_TRACE_ROOT, ISO_TRACE, ISO_POST_WIT, ISO_POST, 499500)
    ),
    20000,
    "no fraud"
  );
  st = await vars(rollup);
  if (Number(st.frozen_9 || 0) !== 0) throw new Error("honest isolated open froze h9!");
  if (Number(st.last_submitted) !== 9) throw new Error("honest h9 re-submit did not land");
  console.log("19c. honest isolated open bounced 'no fraud' via sentinel right neighbor");

  // ===== Batch B (#37): 4 aa_root binding / 6 slash debt cap / 7 ls pins //
  // ===== + pool drain / 11 vault balance formula + freshness lock       //
  // ---- 20. aa_root fold binding: bogus (forest, root) pair bounces -----
  // The 1024-hex forest is bound to one sha256 fold the operator cannot
  // decouple (pre-fix the submit gate only length-checked aa_root and
  // stored any pair; finalize/vault trusted the stored 1024-hex forest,
  // letting a detached corpus pay the vault — #37-4's exploit).
  {
    const sdWrong = submitData(10, STATE_ROOT, STATE_ROOT);
    sdWrong.aa_root = sha256Hex("wrong-fold"); // length ok, fold wrong
    await triggerBounce(operator, rollup, sdWrong, SUBMIT_FEE, "bad submit");
    // The right fold stays the same FOREST everywhere else: every other
    // submit in this run (helper submitData) already carries the real
    // fold — assert a correct one is ACCEPTED here, h10 fresh.
    st = await vars(rollup);
    if (Number(st.last_submitted) !== 9) throw new Error("h10 wrong-fold submit must not advance ls: " + st.last_submitted);
    await sendCombinedSubmit(operator, 10, STATE_ROOT, STATE_ROOT);
    st = await vars(rollup);
    if (Number(st.last_submitted) !== 10) throw new Error("h10 honest submit failed");
    if (st.aa_root_10 !== sha256Hex(FOREST)) throw new Error("aa_root_10 fold not stored");
  }
  console.log("20. aa_root fold bound at submit: bogus pair bounces, honest pair lands");

  // ---- 21. slash debt is bounded by the ACTUALLY-seized pool (#37-6) ----
  // Verdict credit must be exactly min(5e11, pool-before-verdict):
  //  21a. pool 49e12 → v(h11) seizes 5e11 (debt 5e11, pool 48.5e12);
  //  21b. drain-by-claim: resubmit h11 honestly (frozen branch), finalize
  //       9..11 so the chain turns idle, {claim:'pool'} drains to 0;
  //  21c. verdict against the EMPTY pool: debt must NOT move (pre-fix
  //       minted 5e11 per verdict regardless of the pool);
  //  21d. top the pool to exactly 1e12 → v(h12) seizes 5e11 (boundary:
  //       pool 5e11 afterwards, debt semantics still 1:1);
  //  21e. v(h13) seizes the residual 5e11 EXACTLY (pool 0, debt 2e12).
  let debt = 0;
  let pool = 49e12;
  async function oneFraud(hh, preDebt, prePool) {
    await sendCombinedSubmit(operator, hh, STATE_ROOT, STATE_ROOT);
    await triggerVerdict(
      challenger,
      dispute,
      Object.assign({ pred: "deposit", height: hh }, fraudProof),
      20000,
      "deposit fraud predicate h" + hh
    );
    st = await vars(rollup);
    if (Number(st["frozen_" + hh]) !== 2) throw new Error("h" + hh + " verdict did not freeze");
    const seized = Math.min(SLASH_HALF, prePool);
    const afterDebt = Number(st["slash_reward_" + chAddr] || 0);
    const afterPool = Number(st["pool_" + opAddr] || 0);
    if (afterDebt !== preDebt + seized)
      throw new Error(`h${hh} debt ${afterDebt} != banked ${preDebt} + seized ${seized} (pool was ${prePool})`);
    if (afterPool !== prePool - seized)
      throw new Error(`h${hh} pool ${afterPool} != ${prePool} - ${seized}`);
    console.log(`21. h${hh}: seized ${seized}, debt ${afterDebt}, pool ${afterPool}`);
    return [afterDebt, afterPool];
  }
  [debt, pool] = await oneFraud(11, 0, 49e12);
  // 21b. resubmit h11 honestly, finalize 9..11, claim the pool to 0.
  await sendCombinedSubmit(operator, 11, STATE_ROOT, STATE_ROOT);
  st = await vars(rollup);
  if (Number(st["frozen_11"] || 0) !== 0) throw new Error("h11 resubmit did not un-freeze");
  await network.timetravel({ shift: "3600s" });
  await trigger(operator, rollup, { finalize: 1, height: 9 }, 20000);
  await trigger(operator, rollup, { finalize: 1, height: 10 }, 20000);
  await trigger(operator, rollup, { finalize: 1, height: 11 }, 20000);
  await trigger(operator, rollup, { claim: "pool" }, 20000);
  st = await vars(rollup);
  pool = Number(st["pool_" + opAddr] || 0);
  if (pool !== 0) throw new Error("pool not drained by claim: " + pool);
  console.log("21. pool drained to 0 via idle-chain claim");
  // 21c. verdict on an empty pool must mint NOTHING.
  [debt, pool] = await oneFraud(12, debt, 0);
  if (debt !== 5e11) throw new Error("empty-pool verdict minted debt: " + debt);
  console.log("21. empty-pool verdict: seize 0, debt stays " + debt);
  // resubmit h12 honestly (needs the pool floor: top up first).
  await trigger(operator, rollup, { pool: 1 }, 10000000010000);
  pool += 1e12;
  await sendCombinedSubmit(operator, 12, STATE_ROOT, STATE_ROOT);
  // 21d/21e. boundary verdicts against a 1e12 pool.
  [debt, pool] = await oneFraud(13, debt, pool);
  await trigger(operator, rollup, { pool: 1 }, 10000000010000);
  pool += 1e12;
  await sendCombinedSubmit(operator, 13, STATE_ROOT, STATE_ROOT);
  [debt, pool] = await oneFraud(14, debt, pool);
  if (pool !== 0) throw new Error("residual verdict did not hit the boundary: " + pool);
  console.log("21. slash debt == cumulative seizure at every verdict (cap + boundary + empty)");

  // ---- 22. failed height pins the pool; stale heights are dead (#37-7) ---
  // Prep: h14 sits frozen from scenario 21 — resubmit it honestly (frozen
  // branch), finalize 12..14 so lf == 14 == h15-1, then prove:
  //  22a. verdict at h15 keeps last_submitted = 15 (no rollback);
  //  22b. {claim:'pool'} BOUNCES 'pool busy' while the top height is
  //       fraud-failed (pre-fix: ls rolled back to 14 == lf, gate passed,
  //       the pool backing the chain was drained);
  //  22c. a fresh FORWARD submit at h16 is refused while h15 is failed
  //       (pre-fix let a submit chain resume past the failed top);
  //  22d. honest h15 resubmit un-freezes, finalizes, and pool claims work
  //       again.
  await trigger(challenger, rollup, { claim: "slash" }, 20000); // bank 2e12 debt
  await trigger(operator, rollup, { pool: 1 }, POOL_FUND_GROSS); // fund for resubmits
  await sendCombinedSubmit(operator, 14, STATE_ROOT, STATE_ROOT);
  await network.timetravel({ shift: "3600s" });
  await trigger(operator, rollup, { finalize: 1, height: 12 }, 20000);
  await trigger(operator, rollup, { finalize: 1, height: 13 }, 20000);
  await trigger(operator, rollup, { finalize: 1, height: 14 }, 20000);
  await trigger(operator, rollup, { claim: "pool" }, 20000); // idle chain: drain
  st = await vars(rollup);
  if (Number(st.last_finalized) !== 14) throw new Error("prep finalize failed: " + st.last_finalized);
  await trigger(operator, rollup, { pool: 1 }, 10000000010000); // exact 1e12
  // h15 commits the LIAR fixture → verdict.
  await sendCombinedSubmit(operator, 15, STATE_ROOT, STATE_ROOT);
  await triggerVerdict(challenger, dispute, Object.assign({ pred: "deposit", height: 15 }, fraudProof), 20000, "h15 verdict");
  st = await vars(rollup);
  if (Number(st["frozen_15"]) !== 2) throw new Error("h15 verdict did not freeze");
  if (Number(st.last_submitted) !== 15) throw new Error("verdict must PIN last_submitted at 15, got " + st.last_submitted);
  // 22b. pool claim refused while the failed top stands.
  await triggerBounce(operator, rollup, { claim: "pool" }, 20000, "pool busy");
  // 22c. forward submit past the failed top is refused.
  await triggerBounce(operator, rollup, submitData(16, STATE_ROOT, STATE_ROOT), SUBMIT_FEE, "prev mismatch");
  // 22d. resubmit h15 honestly (frozen branch, prev == state_root_14).
  await sendCombinedSubmit(operator, 15, STATE_ROOT, STATE_ROOT);
  st = await vars(rollup);
  if (Number(st["frozen_15"] || 0) !== 0) throw new Error("h15 resubmit did not un-freeze");
  if (Number(st.last_submitted) !== 15) throw new Error("h15 resubmit lost the height");
  await network.timetravel({ shift: "3600s" });
  await trigger(operator, rollup, { finalize: 1, height: 15 }, 20000);
  await trigger(operator, rollup, { claim: "pool" }, 20000);
  st = await vars(rollup);
  if (Number(st.last_finalized) !== 15) throw new Error("h15 finalize failed");
  if (Number(st["pool_" + opAddr] || 0) !== 0) throw new Error("pool claim after recovery failed");
  console.log("22. failed top pins ls, blocks pool drain and forward submits; resubmit recovers");

  // ---- 23. vault withdraw: W-watermark gate (#37-11) + fold binding (#37-4)
  // Real sharded forest (hex domain) over the WITHDRAWER address, built in
  // JS with the SAME fold the AA runs (leaf=sha256('acct:a:c:p:w'), node=
  // sha256_hex(left||right), odd level duplicates its last element). Three
  // finals (h17/h18/h19 each commit the heights' forest):
  //   F@17: (col=1000000, W=0)               → claim 700000 (issue shape:
  //        pre-fix needing col<=amount<=min(col,W) bricked here since the
  //        sidechain had ALREADY debited the 700000)
  //   F@18: (col=300000, W=700000), claim 700000 → wd_=700000
  //   F@19: (col=0, W=1000000), claim 300000 → wd_=1000000 (no dead-end)
  //   replay of the h17 leaf (W=0, amount=0) after wd_ advanced → the
  //   watermark bounces it (clamped by amount+wd_ <= W).
  // Decoy peer keeps the withdrawer's shard bucket >= 2 members (empty
  // proof arrays are illegal in trigger data) and carries no address
  // binding (nobody can claim it).
  const wdShard = (addr) => {
    const h = sha256Hex(addr);
    return parseInt(h.slice(0, 2), 16) & 15;
  };
  const hexLeafOf = (addr, col, perp, w) => sha256Hex(`acct:${addr}:${col}:${perp}:${w}`);
  const foldLR = (l, r) => sha256Hex(l + r);
  function shardRoot(bucket, addr) {
    let level = bucket.map(([a, c, p, w]) => hexLeafOf(a, c, p, w)).sort();
    // Sibling path for addr inside this bucket (same walk as the AA).
    const leaf = hexLeafOf(addr, ...bucket.find(([a]) => a === addr).slice(1));
    let idx = level.indexOf(leaf);
    let sibs = [];
    while (level.length > 1) {
      if (level.length % 2 === 1) level.push(level[level.length - 1]);
      const pairIdx = idx ^ 1;
      sibs.push({ hash: level[pairIdx], right: pairIdx > idx });
      const nxt = [];
      for (let j = 0; j < level.length; j += 2) nxt.push(foldLR(level[j], level[j + 1]));
      level = nxt;
      idx = idx >> 1;
    }
    return [level[0], sibs];
  }
  function buildForest(pairs, wdAddr) {
    const buckets = Array.from({ length: 16 }, () => []);
    for (const pr of pairs) buckets[wdShard(pr[0])].push(pr);
    const wdBucket = buckets[wdShard(wdAddr)];
    const [wdRoot, sibs] = shardRoot(wdBucket, wdAddr);
    const roots = [];
    for (let i = 0; i < 16; i++) {
      if (buckets[i].length === 0) { roots[i] = sha256Hex("empty:" + i); continue; }
      const [r] = shardRoot(buckets[i], buckets[i][0][0]);
      roots[i] = r;
    }
    roots[wdShard(wdAddr)] = wdRoot;
    return { roots, sibs, shard: wdShard(wdAddr) };
  }
  const DECOY = "5B7BJSCMFQYUOLDLJHROMOKC5QCLPZLK3UEE4O25";
  async function vaultWithdrawTrigger(wdAddr, forest, amount, withdrawn, col, proof) {
    return operator.triggerAaWithData({
      toAddress: vault,
      amount: 20000,
      data: {
        withdraw: 1, amount, withdrawn, leaf_account: wdAddr,
        collateral: String(col), perp: "0", shard: forest.shard, proof,
      },
    });
  }
  // Seed the vault: 1 USD deposit (1_000_000 micro) + bounce fee headroom.
  const dep1 = await operator.triggerAaWithData({
    toAddress: vault, amount: 1000000 + 10000, data: { deposit: 1 },
  });
  if (dep1.error) throw new Error("vault deposit failed: " + dep1.error);
  await network.witnessUntilStable(dep1.unit);
  // Heights 17/18/19 commit the withdrawer's REAL forests. sendCombined
  // submits carry the FAKE FOREST; here we pass our own submit objects
  // (trigger(sd) path used elsewhere also hands the sd as data — reuse it).
  const forest17 = buildForest([[wdAcct, 1000000, 0, 0], [DECOY, 500, 0, 0]], wdAcct);
  const sd17 = submitData(17, STATE_ROOT, STATE_ROOT);
  sd17.aa_forest = forest17.roots.join("");
  sd17.aa_root = sha256Hex(sd17.aa_forest);
  await trigger(operator, rollup, sd17, SUBMIT_FEE);
  await network.timetravel({ shift: "3600s" });
  await trigger(operator, rollup, { finalize: 1, height: 17 }, 20000);
  // h17 leaf (col=1e6, W=0): W=0 authorizes ZERO vault payout.
  await triggerBounce(operator, vault, {
    withdraw: 1, amount: 700000, withdrawn: 0, leaf_account: wdAcct,
    collateral: "1000000", perp: "0", shard: forest17.shard, proof: forest17.sibs,
  }, 20000, "bad claim amount");
  // h18: sidechain withdraw 700000 → leaf (col=300000, W=700000).
  const forest18 = buildForest([[wdAcct, 300000, 0, 700000], [DECOY, 500, 0, 0]], wdAcct);
  const sd18 = submitData(18, STATE_ROOT, STATE_ROOT);
  sd18.aa_forest = forest18.roots.join("");
  sd18.aa_root = sha256Hex(sd18.aa_forest);
  await trigger(operator, rollup, sd18, SUBMIT_FEE);
  await network.timetravel({ shift: "3600s" });
  await trigger(operator, rollup, { finalize: 1, height: 18 }, 20000);
  const res18 = await vaultWithdrawTrigger(wdAcct, forest18, 700000, 700000, 300000, forest18.sibs);
  if (res18.error) throw new Error("h18 withdraw trigger failed: " + res18.error);
  await network.witnessUntilStable(res18.unit);
  const rr18 = await network.getAaResponseToUnit(res18.unit).catch(() => null);
  const log18 = JSON.stringify(rr18 || {});
  if (log18.includes('"bounced":true')) throw new Error("h18 withdraw bounced: " + bounceDetail(rr18));
  st = await vars(vault);
  if (Number(st["wd_" + wdAcct] || 0) !== 700000) throw new Error("wd_ not advanced: " + JSON.stringify(st["wd_" + wdAcct]));
  console.log("23. issue example (col=300k, W=700k) pays the pending 700k — no brick");
  // Old-leaf replay: h17's leaf (W=0, amount 0) — watermark bounces it.
  await triggerBounce(operator, vault, {
    withdraw: 1, amount: 0, withdrawn: 0, leaf_account: wdAcct,
    collateral: "1000000", perp: "0", shard: forest17.shard, proof: forest17.sibs,
  }, 20000, "bad claim amount");
  // h19: residual (col=0, W=1000000) — pays the last 300000 (no dead-end).
  const forest19 = buildForest([[wdAcct, 0, 0, 1000000], [DECOY, 500, 0, 0]], wdAcct);
  const sd19 = submitData(19, STATE_ROOT, STATE_ROOT);
  sd19.aa_forest = forest19.roots.join("");
  sd19.aa_root = sha256Hex(sd19.aa_forest);
  await trigger(operator, rollup, sd19, SUBMIT_FEE);
  await network.timetravel({ shift: "3600s" });
  await trigger(operator, rollup, { finalize: 1, height: 19 }, 20000);
  const res19 = await vaultWithdrawTrigger(wdAcct, forest19, 300000, 1000000, 0, forest19.sibs);
  if (res19.error) throw new Error("h19 residual withdraw trigger failed: " + res19.error);
  await network.witnessUntilStable(res19.unit);
  const rr19 = await network.getAaResponseToUnit(res19.unit).catch(() => null);
  const log19 = JSON.stringify(rr19 || {});
  if (log19.includes('"bounced":true')) throw new Error("h19 residual withdraw bounced: " + bounceDetail(rr19));
  st = await vars(vault);
  if (Number(st["wd_" + wdAcct] || 0) !== 1000000) throw new Error("residual claim failed: " + JSON.stringify(st["wd_" + wdAcct]));
  // Post-drain replay of the h19 leaf with amount 1 — watermark stops it.
  await triggerBounce(operator, vault, {
    withdraw: 1, amount: 1, withdrawn: 1000000, leaf_account: wdAcct,
    collateral: "0", perp: "0", shard: forest19.shard, proof: forest19.sibs,
  }, 20000, "bad claim amount");
  console.log("23. sequential withdrawals drain the deposit with no dead-end; replays bounce");

  process.exit(failures === 0 ? 0 : 1);
}

// Oscript is_valid_merkle_proof accepts object proofs {root, siblings, index}.
function mkProof(element, index, root) {
  return { root, index, siblings: [] };
}

main().catch(async (e) => {
  console.error("E2E FAILED:", e && e.stack ? e.stack : e);
  try { if (network) await network.stop(); } catch (_) {}
  process.exit(1);
});
