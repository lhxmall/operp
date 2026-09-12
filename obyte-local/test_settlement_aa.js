"use strict";

// OPERP settlement E2E — three-agent lifecycle (rollup + dispute + vault).
//
// Replaces test_vault_aa.js: the vault is now pure custody (no submit /
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
//  2.  submit bond gate: 20000 → 'need submit bond'
//  3.  combined submit height 1 → last_submitted=1; resubmit 'height taken'
//  4.  {lock:1} / {challenge:1} have NO cases → auto-bounce, nothing frozen
//  5.  finalize before 3600s → 'cannot finalize'; after → last_finalized=1
//  6.  honest deposit predicate → 'no fraud', height still live
//  7.  dishonest post collateral → verdict fires: frozen=2, last_submitted
//      rolls back, slash_reward_ 500000000000 claimable
//  8.  omit fraud (forced id missing) → frozen=2
//  9.  omit honest (id present) → 'no fraud'
//  10. fill_math dishonest → fill AA verdict, frozen=2
//  11. fill_math honest → 'no fraud'
//  12. ghost (absent maker) → frozen=2
//  13. skip (better order ignored) → frozen=2 (heights 3-4 chain)
//  14. re-submit + finalize after fraud works

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
const ROLLUP_ADDR = chashOf(readDef("operp_rollup.aa"));
const DISPUTE_SRC = writeResolved("operp_dispute.aa", { ROLLUP_AA_HERE: ROLLUP_ADDR }, ".e2e_dispute.aa");
const FILL_SRC = writeResolved("operp_dispute_fill.aa", { ROLLUP_AA_HERE: ROLLUP_ADDR }, ".e2e_fill.aa");
const VAULT_SRC = writeResolved("operp_vault.aa", { ROLLUP_AA_HERE: ROLLUP_ADDR, PERP_ASSET_ID_HERE: PERP_ASSET }, ".e2e_vault.aa");
// dispute AA address is also deterministic — compute AFTER substitution.
const DISPUTE_ADDR = chashOf(fs.readFileSync(DISPUTE_SRC, "utf8"));
const FILL_ADDR = chashOf(fs.readFileSync(FILL_SRC, "utf8"));

const SUBMIT_GROSS = 10000000010000; // SUBMIT_BOND_NET + 10000 headroom
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

// Genesis witness tree: the height-1 submit commits WIT_ROOT, so every
// k==0 predicate (pre_wit == wit_root_1) proves leaves against this tree.
// Deposit scenario uses DEP_ACCT (old account, pre col 1000000); fill
// scenarios use FILL_TAKER (flat) + META1. All proofs below are real
// merkle.getMerkleProof paths — no dummy self-proofs.
const DEP_ACCT = "a".repeat(64);
const DEP_PRE = `acct:${DEP_ACCT}:1000000:0:0`;
const FILL_TAKER = "b".repeat(64);
const FILL_TAKER_PRE = `acct:${FILL_TAKER}:0:0:0`;
const META1 = `meta:1:1:1000:500:5:100:0:100`;
const META2 = `meta:2:1:1000:500:5:100:0:100`;
const POS2 = `pos:${FILL_TAKER}:2:50000000:90000000`;
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
    wit_root: WIT_ROOT,
    trace_root: TRACE_ROOT,
    units_root: UNITS_ROOT,
    units_set_root: UNITS_SET_ROOT,
    ops_root: OPS_ROOT,
    fills_root: FILLS_ROOT,
    counts_root: COUNTS_ROOT,
    unit_count: 1,
    wit_count: GEN_WIT_COUNT,
  };
}
// Single-package inline DA: full header scalars + frames_blob (JS join+base64,
// no helper binary). Derived from the submit so header roots match the
// commitment; the AA only reads the submit, but the blob path is exercised.
function headerFromSubmit(sd, frameOp) {
  const frame = JSON.stringify({ u: { op: "x" }, t: sd.trace_root, o: frameOp || "x", c: "1" });
  const blob = Buffer.from(frame, "utf8").toString("base64");
  const raw = Buffer.from(blob, "base64");
  return {
    chain_id: sd.chain_id || "operp-v2",
    height: sd.height,
    prev_state_hash: sd.prev_state_hash,
    state_root: sd.state_root,
    aa_root: sha256Hex("aa"),
    aa_shard_roots: Array(16).fill(sha256Hex("shard")),
    last_unit: sha256Hex("last"),
    seq: sd.height,
    fill_count: 0,
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
    base_outputs: [{ address: ROLLUP_ADDR, amount: SUBMIT_GROSS }],
  });
  if (r.error) throw new Error("combined submit failed: " + r.error);
  await network.witnessUntilStable(r.unit);
  // sendMulti reports composer errors only; the AA bounce surfaces on the
  // response unit — fail fast here instead of cascading 'no height' later.
  const res = await network.getAaResponseToUnit(r.unit).catch(() => null);
  const log = JSON.stringify(res || {});
  if (log.includes('"bounced":true')) {
    throw new Error("combined submit bounced: " + log.slice(0, 500));
  }
  return r;
}

async function main() {
  console.log("rollup address (precomputed):", ROLLUP_ADDR);
  console.log("dispute address (precomputed):", DISPUTE_ADDR);
  console.log("fill address (precomputed):", FILL_ADDR);

  network = await Network.create()
    .with.agent({ rollup: path.join(__dirname, "agents", "operp_rollup.aa") })
    .with.agent({ dispute: DISPUTE_SRC })
    .with.agent({ fill: FILL_SRC })
    .with.agent({ vault: VAULT_SRC })
    .with.wallet({ operator: 2e14 })
    .with.wallet({ challenger: 1e13 })
    .run();
  const { operator, challenger } = network.wallet;
  const rollup = network.agent.rollup;
  const dispute = network.agent.dispute;
  const fill = network.agent.fill;
  const vault = network.agent.vault;
  if (rollup !== ROLLUP_ADDR) throw new Error(`rollup address mismatch: ${rollup} != ${ROLLUP_ADDR}`);
  console.log("network up:", { rollup, dispute, fill, vault });

  // ---- 1. bind dispute --------------------------------------------------
  await trigger(operator, dispute, { bind: 1 }, 20000);
  await trigger(operator, fill, { bind_fill: 1 }, 20000);
  let st = await vars(rollup);
  if (String(st.dispute_aa) !== dispute) throw new Error("dispute_aa not set: " + JSON.stringify(st.dispute_aa));
  if (String(st.dispute_fill_aa) !== fill) throw new Error("dispute_fill_aa not set: " + JSON.stringify(st.dispute_fill_aa));
  console.log("1. bind ok — dispute_aa + dispute_fill_aa set");
  // A second bind succeeds on the dispute AA (it just re-forwards), but the
  // rollup bounces the secondary 'not authorized' verdict — dispute_aa var
  // must be unchanged afterwards.
  await trigger(operator, dispute, { bind: 1 }, 20000);
  st = await vars(rollup);
  if (String(st.dispute_aa) !== dispute) throw new Error("double bind overwrote dispute_aa!");

  // ---- 2. submit bond gate ----------------------------------------------
  const sd = submitData(1, STATE_ROOT, PREV_ROOT);
  await triggerBounce(operator, rollup, Object.assign({}, sd, { height: 1 }), 20000, "need submit bond");
  console.log("2. submit bond gate ok");

  // ---- 3. combined submit height 1 --------------------------------------
  await sendCombinedSubmit(operator, 1, STATE_ROOT, PREV_ROOT);
  st = await vars(rollup);
  if (Number(st.last_submitted) !== 1) throw new Error("last_submitted != 1: " + st.last_submitted);
  if (st.state_root_1 !== STATE_ROOT) throw new Error("state_root_1 mismatch");
  if (st.da_unit_1 === undefined) throw new Error("da_unit_1 not pinned");
  // resubmit same height → 'bad submit' (h != last_submitted+1; the
  // 'height taken' gate only applies to a fresh h == last_submitted+1)
  await triggerBounce(operator, rollup, submitData(1, STATE_ROOT, PREV_ROOT), SUBMIT_GROSS, "bad submit");
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
  console.log("5. finalize ok, race reward accrued");

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
      base_outputs: [{ address: rollup, amount: SUBMIT_GROSS }],
    });
    if (r.error) throw new Error("h2 submit failed: " + r.error);
    await network.witnessUntilStable(r.unit);
    const res = await network.getAaResponseToUnit(r.unit).catch(() => null);
    if (res && res.response && res.response.bounced)
      throw new Error("h2 submit bounced: " + JSON.stringify(res.response).slice(0, 200));
  }
  async function triggerVerdict(wallet, to, data, amount, what) {
    const t = await trigger(wallet, to, data, amount);
    const r = await network.getAaResponseToUnit(t.unit).catch(() => null);
    const inner = r && r.response && (r.response.response || r.response);
    if (r && r.response && r.response.bounced)
      throw new Error(what + " bounced: " + JSON.stringify(inner).slice(0, 500));
    await network.witnessUntilStable(r.response.response_unit);
  }
  // ---- 6. omit fraud on a REAL committed tree → verdict freezes h2 --------
  await submitH2(OPS_ROOT1, TRACE_ROOT1, SET_ROOT1, FILLS_ROOT);
  const omitProof = {
    trace_root: TRACE_ROOT1,
    ops_root: OPS_ROOT1,
    units_root: UNITS_SET_ROOT,
    units_set_root: SET_ROOT1,
    fills_root: FILLS_ROOT,
    unit_id: forcedOmit,
    left: otherId,
    left_proof: merkle.getMerkleProof(SET1, 0),
  };
  await triggerVerdict(challenger, dispute, Object.assign({ pred: "omit", height: 2 }, omitProof), 20000, "omit predicate");
  st = await vars(rollup);
  if (Number(st.frozen_2) !== 2) throw new Error("omit fraud did not freeze height");
  console.log("6. omit fraud: missing forced id failed the height");

  const depPreIdx = GENESIS_LEAVES.indexOf(preLeaf);

  // ---- 7. deposit fraud on a LIAR trace (h2 reopened) → verdict, slash ----
  const LIAR_POST1 = pad2([`acct:${acct}:1000000:0:0`], "liar1");
  const LIAR_WIT1 = merkle.getMerkleRoot(LIAR_POST1);
  const LIAR_TRACE1 = pad2([LIAR_WIT1], "liartrace1");
  const LIAR_TRACE_ROOT1 = merkle.getMerkleRoot(LIAR_TRACE1);
  await submitH2(OPS_ROOT1, LIAR_TRACE_ROOT1, SET_ROOT1, FILLS_ROOT);
  const fraudProof = {
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
  // Cumulative: scenario 6's omit verdict already banked one half.
  if (Number(st["slash_reward_" + chAddr] || 0) !== SLASH_HALF * 2)
    throw new Error("slash reward wrong: " + JSON.stringify(st["slash_reward_" + chAddr]));
  await trigger(challenger, rollup, { claim: "slash" }, 20000);
  st = await vars(rollup);
  if (Number(st["slash_reward_" + chAddr] || 0) !== 0) throw new Error("slash not paid out");
  console.log("7. deposit fraud verdict: height failed, slashed, challenger paid");

  // ---- 8. honest deposit → 'no fraud' (height stays live) ------------------
  // This assertion ALSO commits wit_root_2 = H3_PRE_WIT: every h3 k=0
  // predicate anchors pre_wit on it.
  await submitH2(OPS_ROOT1, TRACE_ROOT1, SET_ROOT1, FILLS_ROOT, H3_PRE_WIT, H3_PRE.length);
  const honestProof = {
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
  // ---- 10. submit h3 committing a LIAR post tree (taker col 0, real -500) --
  const takerH = FILL_TAKER;
  const fillStr = `f:${"u".repeat(64)}:0:${takerH}:${"c".repeat(64)}:${"d".repeat(64)}:${"e".repeat(64)}:1:100000000:100000000:9:0`;
  const FILLS1 = pad2([fillStr], "fills1");
  const FILLS_ROOT1 = merkle.getMerkleRoot(FILLS1);
  const POST_LIAR = [`acct:${takerH}:0:0:0`, META1, `pos:${takerH}:1:100000000:100000000`].sort();
  const POST_LIAR_WIT = merkle.getMerkleRoot(POST_LIAR);
  const TRACE_LIAR = pad2([POST_LIAR_WIT], "traceliar");
  const TRACE_LIAR_ROOT = merkle.getMerkleRoot(TRACE_LIAR);
  const sd3 = submitData(3, STATE_ROOT, STATE_ROOT);
  sd3.wit_root = H3_PRE_WIT;
  sd3.wit_count = H3_PRE.length;
  sd3.trace_root = TRACE_LIAR_ROOT;
  sd3.fills_root = FILLS_ROOT1;
  sd3.ops_root = OPS_ROOT1;
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
      base_outputs: [{ address: rollup, amount: SUBMIT_GROSS }],
    });
    if (r.error) throw new Error("h3 submit failed: " + r.error);
    await network.witnessUntilStable(r.unit);
    const res = await network.getAaResponseToUnit(r.unit).catch(() => null);
    if (res && res.response && res.response.bounced)
      throw new Error("h3 submit bounced: " + JSON.stringify(res.response).slice(0, 200));
  }

  // ---- 11. fill_math dishonest (taker col 0 instead of -500) → fraud -------
  // price=1e8 qty=1e8 -> notional 1e6, fee 5bps=500 -> exp col -500.
  const fillBase = {
    k: 0,
    trace_root: TRACE_LIAR_ROOT,
    fills_root: FILLS_ROOT1,
    ops_root: OPS_ROOT1,
    fill: fillStr,
    fill_proof: merkle.getMerkleProof(FILLS1, 0),
    pre_wit: H3_PRE_WIT,
    post_wit: POST_LIAR_WIT,
    post_proof: merkle.getMerkleProof(TRACE_LIAR, 0),
    pre_acct: FILL_TAKER_PRE,
    pre_acct_proof: merkle.getMerkleProof(H3_PRE, H3_PRE_IDX[FILL_TAKER_PRE]),
    post_acct: `acct:${takerH}:0:0:0`, // liar: col 0, expected -500
    post_acct_proof: merkle.getMerkleProof(POST_LIAR, POST_LIAR.indexOf(`acct:${takerH}:0:0:0`)),
    post_pos: `pos:${takerH}:1:100000000:100000000`,
    post_pos_proof: merkle.getMerkleProof(POST_LIAR, POST_LIAR.indexOf(`pos:${takerH}:1:100000000:100000000`)),
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
  await triggerVerdict(challenger, fill, Object.assign({ pred: "fill_math", height: 3 }, fillBase), 20000, "fill_math predicate");
  st = await vars(rollup);
  if (Number(st.frozen_3) !== 2) throw new Error("fill_math fraud did not freeze height");
  if (String(st.dispute_fill_aa) !== fill) throw new Error("verdict not from fill AA");
  console.log("11. fill_math dishonest → frozen=3 via fill AA");

  // ---- 11a. fill_math honest → 'no fraud' ---------------------------------
  // h3 reopened by scenario 11's verdict: re-submit with the HONEST post
  // tree (col -500) and prove honest math bounces.
  const POST_H = [`acct:${takerH}:-500:0:0`, META1, `pos:${takerH}:1:100000000:100000000`].sort();
  const POST_H_WIT = merkle.getMerkleRoot(POST_H);
  const TRACE_H = pad2([POST_H_WIT], "traceh");
  const TRACE_H_ROOT = merkle.getMerkleRoot(TRACE_H);
  async function submitH3(traceRoot, fillsRoot) {
    const s = submitData(3, STATE_ROOT, STATE_ROOT);
    s.wit_root = H3_PRE_WIT;
    s.wit_count = H3_PRE.length;
    s.trace_root = traceRoot;
    s.fills_root = fillsRoot;
    s.ops_root = OPS_ROOT1;
    const h3header = headerFromSubmit(s);
    const r = await operator.sendMulti({
      messages: [
        tempDataMsg(h3header),
        { app: "data", payload: s },
      ],
      base_outputs: [{ address: rollup, amount: SUBMIT_GROSS }],
    });
    if (r.error) throw new Error("h3 submit failed: " + r.error);
    await network.witnessUntilStable(r.unit);
    const res = await network.getAaResponseToUnit(r.unit).catch(() => null);
    if (res && res.response && res.response.bounced)
      throw new Error("h3 submit bounced: " + JSON.stringify(res.response).slice(0, 200));
  }
  await submitH3(TRACE_H_ROOT, FILLS_ROOT1);
  const fillHonest2 = Object.assign({}, fillBase, {
    trace_root: TRACE_H_ROOT,
    post_wit: POST_H_WIT,
    post_proof: merkle.getMerkleProof(TRACE_H, 0),
    post_acct: `acct:${takerH}:-500:0:0`,
    post_acct_proof: merkle.getMerkleProof(POST_H, POST_H.indexOf(`acct:${takerH}:-500:0:0`)),
    post_pos: `pos:${takerH}:1:100000000:100000000`,
    post_pos_proof: merkle.getMerkleProof(POST_H, POST_H.indexOf(`pos:${takerH}:1:100000000:100000000`)),
  });
  await triggerBounce(challenger, fill, Object.assign({ pred: "fill_math", height: 3 }, fillHonest2), 20000, "no fraud");
  console.log("11a. fill_math honest bounced 'no fraud'");

  // ---- 12. ghost: maker order absent → fraud -------------------------------
  // maker id "e"*64 has no ord leaf in H3_PRE. Sorted H3_PRE runs
  // ... MAKER_ORD(ord:d, idx4), BETTER_ORD(ord:eee..f, idx5), POS2(idx6):
  // the whole ord:{e*64}: range sits between MAKER_ORD and BETTER_ORD.
  const ghostOrd = `ord:${"e".repeat(64)}:1:1:100000000:9:3:${"c".repeat(64)}`;
  const gSorted = H3_PRE;
  const gMaker = gSorted.indexOf(MAKER_ORD);
  const gBetter = gSorted.indexOf(BETTER_ORD);
  if (gBetter !== gMaker + 1) throw new Error("ghost fixture not adjacent");
  const ghostLo = `ord:${"e".repeat(64)}:`;
  const ghostHi = `ord:${"e".repeat(64)};`;
  if (!(gSorted[gMaker] < ghostLo && ghostHi <= gSorted[gBetter])) throw new Error("ghost fixture not straddling");
  const ghostProof = {
    k: 0,
    trace_root: TRACE_H_ROOT,
    fills_root: FILLS_ROOT1,
    ops_root: OPS_ROOT1,
    fill: fillStr,
    fill_proof: merkle.getMerkleProof(FILLS1, 0),
    pre_wit: H3_PRE_WIT,
    maker_ord: ghostOrd,
    left: gSorted[gMaker],
    left_proof: merkle.getMerkleProof(gSorted, gMaker),
    right: gSorted[gBetter],
    right_proof: merkle.getMerkleProof(gSorted, gBetter),
  };
  await triggerVerdict(challenger, fill, Object.assign({ pred: "ghost", height: 3 }, ghostProof), 20000, "ghost predicate");
  st = await vars(rollup);
  if (Number(st.frozen_3) !== 2) throw new Error("ghost fraud did not freeze height");
  console.log("12. ghost (absent maker) → frozen=3");

  // ---- 13. skip: better live order ignored → fraud -------------------------
  const SKIP_TRACE4 = pad2([`skip-post-wit`], "skiptrace4");
  const SKIP_TRACE4_ROOT = merkle.getMerkleRoot(SKIP_TRACE4);
  const SKIP_FILLS = pad2([`f:${"u".repeat(64)}:0:${FILL_TAKER}:${"c".repeat(64)}:${"d".repeat(64)}:${"d".repeat(64)}:1:100000000:50000000:7:0`], "skipfills");
  const SKIP_FILLS_ROOT = merkle.getMerkleRoot(SKIP_FILLS);
  // h3 was frozen by ghost: re-submit carrying the skip assertion's roots.
  await submitH3(SKIP_TRACE4_ROOT, SKIP_FILLS_ROOT);
  const skipProof = {
    k: 0,
    trace_root: SKIP_TRACE4_ROOT,
    fills_root: SKIP_FILLS_ROOT,
    ops_root: OPS_ROOT1,
    fill: SKIP_FILLS[0],
    fill_proof: merkle.getMerkleProof(SKIP_FILLS, 0),
    pre_wit: H3_PRE_WIT,
    maker_ord: MAKER_ORD,
    maker_proof: merkle.getMerkleProof(H3_PRE, H3_PRE.indexOf(MAKER_ORD)),
    better_ord: BETTER_ORD,
    better_proof: merkle.getMerkleProof(H3_PRE, H3_PRE.indexOf(BETTER_ORD)),
  };
  await triggerVerdict(challenger, fill, Object.assign({ pred: "skip", height: 3 }, skipProof), 20000, "skip predicate");
  st = await vars(rollup);
  if (Number(st.frozen_3) !== 2) throw new Error("skip fraud did not freeze height");
  console.log("13. skip (better order ignored) → frozen=3");
  // ---- 13a. fill_math with NEGATIVE price (signed fills) → fraud --------
  // price=-1e8 qty=1e8 -> |notional| 1e6, fee 5bps=500 -> exp col -500.
  // Liar posts -499: proves Oscript string math holds for negatives.
  // Market stays 1 (no pre pos -> exact expectation, no averaging division).
  const NEG_FILL = `f:${"u".repeat(64)}:0:${takerH}:${"c".repeat(64)}:${"d".repeat(64)}:${"e".repeat(64)}:1:-100000000:100000000:9:0`;
  const NEG_FILLS = pad2([NEG_FILL], "negfills");
  const NEG_FILLS_ROOT = merkle.getMerkleRoot(NEG_FILLS);
  const NEG_POST_LIAR = [`acct:${takerH}:-499:0:0`, META1, `pos:${takerH}:1:100000000:-100000000`].sort();
  const NEG_POST_LIAR_WIT = merkle.getMerkleRoot(NEG_POST_LIAR);
  const NEG_TRACE = pad2([NEG_POST_LIAR_WIT], "negtrace");
  const NEG_TRACE_ROOT = merkle.getMerkleRoot(NEG_TRACE);
  await submitH3(NEG_TRACE_ROOT, NEG_FILLS_ROOT);
  const negBase = Object.assign({}, fillBase, {
    trace_root: NEG_TRACE_ROOT,
    fills_root: NEG_FILLS_ROOT,
    fill: NEG_FILL,
    fill_proof: merkle.getMerkleProof(NEG_FILLS, 0),
    post_wit: NEG_POST_LIAR_WIT,
    post_proof: merkle.getMerkleProof(NEG_TRACE, 0),
    post_acct: `acct:${takerH}:-499:0:0`, // liar: col -499, expected -500
    post_acct_proof: merkle.getMerkleProof(NEG_POST_LIAR, NEG_POST_LIAR.indexOf(`acct:${takerH}:-499:0:0`)),
    post_pos: `pos:${takerH}:1:100000000:-100000000`,
    post_pos_proof: merkle.getMerkleProof(NEG_POST_LIAR, NEG_POST_LIAR.indexOf(`pos:${takerH}:1:100000000:-100000000`)),
  });
  await triggerVerdict(challenger, fill, Object.assign({ pred: "fill_math", height: 3 }, negBase), 20000, "negative-price fill_math predicate");
  st = await vars(rollup);
  if (Number(st.frozen_3) !== 2) throw new Error("negative-price fill_math fraud did not freeze height");
  console.log("13a. fill_math negative-price dishonest → frozen=3 via fill AA");

  // ---- 14. two-package height: deposit-fraud predicate fires, height fails --
  // h3 was frozen by 13a, so last_submitted=2 and a fresh h3 submit is legal.
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
  const blobA = Buffer.from(frameA, "utf8").toString("base64");
  const blobB = Buffer.from(frameB, "utf8").toString("base64");
  const rawA = Buffer.from(blobA, "base64");
  const rawB = Buffer.from(blobB, "base64");
  const shaHex = (b) => crypto.createHash("sha256").update(b).digest("hex");
  const sd3pkg = submitData(3, STATE_ROOT, STATE_ROOT);
  sd3pkg.ops_root = PKG_OPS_ROOT;
  sd3pkg.trace_root = PKG_TRACE_ROOT;
  sd3pkg.units_root = UNITS_SET_ROOT;
  sd3pkg.units_set_root = SET_ROOT1;
  // Full header scalars from the submit (same helper as single-package),
  // then packages = REAL package unit hashes (pr.unit) so watchers can
  // get_joint each entry; data_root = sha256 of concatenated blob bytes.
  const h3pkg = headerFromSubmit(sd3pkg, PKG_OP);
  h3pkg.data_root = shaHex(Buffer.concat([rawA, rawB]));
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
    delete h3pkg.frames_blob;
    h3pkg.packages = [pr1.unit, pr2.unit];
    const r3p = await operator.sendMulti({
      messages: [
        tempDataMsg(h3pkg),
        { app: "data", payload: sd3pkg },
      ],
      base_outputs: [{ address: rollup, amount: SUBMIT_GROSS }],
    });
    if (r3p.error) throw new Error("h3 2-package submit failed: " + r3p.error);
    await network.witnessUntilStable(r3p.unit);
    const res3p = await network.getAaResponseToUnit(r3p.unit).catch(() => null);
    if (res3p && res3p.response && res3p.response.bounced)
      throw new Error("h3 2-package submit bounced: " + JSON.stringify(res3p.response).slice(0, 200));
  }
  const pkgFraud = {
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
  await triggerVerdict(challenger, dispute, Object.assign({ pred: "deposit", height: 3 }, pkgFraud), 20000, "2-package deposit fraud predicate");
  st = await vars(rollup);
  if (Number(st.frozen_3) !== 2) throw new Error("2-package fraud did not freeze height");
  console.log("14. 2-package height deposit fraud → frozen=3");
  // ---- 15. re-submit + finalize after fraud works -------------------------
  await sendCombinedSubmit(operator, 3, STATE_ROOT, STATE_ROOT);
  await network.timetravel({ shift: "3600s" });
  await trigger(operator, rollup, { finalize: 1, height: 3 }, 20000);
  st = await vars(rollup);
  if (Number(st.last_finalized) !== 3) throw new Error("re-finalize after fraud failed");
  console.log("15. re-submit + finalize after fraud ok");
  console.log(failures === 0 ? "\nALL SETTLEMENT E2E CHECKS PASSED" : `\n${failures} FAILURES`);
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
