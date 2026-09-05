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
const GENESIS_LEAVES = [DEP_PRE, FILL_TAKER_PRE, META1].sort();
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

async function sendCombinedSubmit(wallet, height, stateRoot, prev) {
  const batchData = {
    chain_id: "operp-v2",
    height,
    state_root: stateRoot,
    unit_ids: ["u" + height],
  };
  const r = await wallet.sendMulti({
    messages: [
      {
        app: "temp_data",
        payload_location: "inline",
        payload: {
          data_length: require("ocore/object_length.js").getLength(batchData, true),
          data_hash: require("ocore/object_hash.js").getBase64Hash(batchData, true),
          data: batchData,
        },
      },
      { app: "data", payload: submitData(height, stateRoot, prev) },
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
    .with.wallet({ operator: 1e14 })
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
  // resubmit same height → 'height taken'
  await triggerBounce(operator, rollup, submitData(1, STATE_ROOT, PREV_ROOT), SUBMIT_GROSS, "height taken");
  console.log("3. combined submit ok, resubmit rejected");

  // ---- 4. lock/challenge are dead paths ---------------------------------
  await triggerBounce(operator, rollup, { lock: 1, height: 1 }, 20000, "formula");
  await triggerBounce(operator, rollup, { challenge: 1, height: 1 }, 1000000000000, "formula");
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
  async function submitH2(opsRoot, traceRoot, unitsSetRoot, fillsRoot) {
    const sd = submitData(2, STATE_ROOT, STATE_ROOT);
    sd.ops_root = opsRoot;
    sd.trace_root = traceRoot;
    sd.units_root = UNITS_SET_ROOT;
    sd.units_set_root = unitsSetRoot;
    sd.fills_root = fillsRoot;
    sd.unit_count = 1;
    sd.wit_count = GEN_WIT_COUNT;
    const h2data = { chain_id: "operp-v2", height: 2 };
    const r = await operator.sendMulti({
      messages: [
        {
          app: "temp_data",
          payload_location: "inline",
          payload: {
            data_length: require("ocore/object_length.js").getLength(h2data, true),
            data_hash: require("ocore/object_hash.js").getBase64Hash(h2data, true),
            data: h2data,
          },
        },
        { app: "data", payload: sd },
      ],
      base_outputs: [{ address: rollup, amount: SUBMIT_GROSS }],
    });
    if (r.error) throw new Error("h2 submit failed: " + r.error);
    await network.witnessUntilStable(r.unit);
  }
  await submitH2(OPS_ROOT1, TRACE_ROOT1, UNITS_SET_ROOT, FILLS_ROOT);
  const depPreIdx = GENESIS_LEAVES.indexOf(preLeaf);
  const honestProof = {
    k: 0,
    op: opD,
    ops_proof: merkle.getMerkleProof(OPS1, 0),
    trace_root: TRACE_ROOT1,
    ops_root: OPS_ROOT1,
    units_root: UNITS_SET_ROOT,
    units_set_root: UNITS_SET_ROOT,
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
  console.log("6. honest deposit predicate bounced 'no fraud' — height live");

  // ---- 7. dishonest deposit → fraud verdict -------------------------------
  // Liar post tree carries the UNCHANGED col; its root is committed as
  // post_wit so post_proof + post_leaf_proof verify, but col math fails.
  const LIAR_POST1 = pad2([`acct:${acct}:1000000:0:0`], "liar1");
  const LIAR_WIT1 = merkle.getMerkleRoot(LIAR_POST1);
  const LIAR_TRACE1 = pad2([LIAR_WIT1], "liartrace1");
  const LIAR_TRACE_ROOT1 = merkle.getMerkleRoot(LIAR_TRACE1);
  await submitH2(OPS_ROOT1, LIAR_TRACE_ROOT1, UNITS_SET_ROOT, FILLS_ROOT);
  const fraudProof = {
    k: 0,
    op: opD,
    ops_proof: merkle.getMerkleProof(OPS1, 0),
    trace_root: LIAR_TRACE_ROOT1,
    ops_root: OPS_ROOT1,
    units_root: UNITS_SET_ROOT,
    units_set_root: UNITS_SET_ROOT,
    fills_root: FILLS_ROOT,
    pre_wit: WIT_ROOT,
    post_wit: LIAR_WIT1,
    post_proof: merkle.getMerkleProof(LIAR_TRACE1, 0),
    pre_leaf: preLeaf,
    post_leaf: LIAR_POST1[0], // col unchanged despite +100 deposit
    pre_leaf_proof: merkle.getMerkleProof(GENESIS_LEAVES, depPreIdx),
    post_leaf_proof: merkle.getMerkleProof(LIAR_POST1, 0),
  };
  await trigger(challenger, dispute, Object.assign({ pred: "deposit", height: 2 }, fraudProof), 20000);
  st = await vars(rollup);
  if (Number(st.frozen_2) !== 2) throw new Error("fraud verdict did not freeze height: " + JSON.stringify(st.frozen_2));
  if (Number(st.last_submitted) !== 1) throw new Error("last_submitted did not roll back");
  const chAddr = await challenger.getAddress();
  if (Number(st["slash_reward_" + chAddr] || 0) !== SLASH_HALF)
    throw new Error("slash reward wrong: " + JSON.stringify(st["slash_reward_" + chAddr]));
  await trigger(challenger, rollup, { claim: "slash" }, 20000);
  st = await vars(rollup);
  if (Number(st["slash_reward_" + chAddr] || 0) !== 0) throw new Error("slash not paid out");
  console.log("7. fraud verdict: height failed, slashed, challenger paid");

  // ---- 8. P-omit fraud: forced id missing from units_set ------------------
  // forcedOmit < otherId here, so the missing id lies BEFORE the set min:
  // before-min branch (left index 0, pad leaf sorts last, harmless).
  await trigger(operator, rollup, { force: 1, unit_id: forcedOmit }, 20000);
  const otherId = sha256Hex("other-unit");
  // Pad keeps after-max geometry: pad leaf sorts last, left stays index 0
  // with unit_count 1 (AA checks index == n-1 == 0).
  const SET1 = pad2([otherId], "set1");
  const SET_ROOT1 = merkle.getMerkleRoot(SET1);
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
  await trigger(challenger, dispute, Object.assign({ pred: "omit", height: 2 }, omitProof), 20000);
  st = await vars(rollup);
  if (Number(st.frozen_2) !== 2) throw new Error("omit fraud did not freeze height");
  console.log("8. omit fraud: missing forced id failed the height");

  // ---- 9. P-omit honest: forced id IS in the set → 'no fraud' -------------
  const SET2 = [forcedOmit, otherId].sort();
  const SET_ROOT2 = merkle.getMerkleRoot(SET2);
  await submitH2(OPS_ROOT1, TRACE_ROOT1, SET_ROOT2, FILLS_ROOT);
  const omitHonest = {
    trace_root: TRACE_ROOT1,
    ops_root: OPS_ROOT1,
    units_root: UNITS_SET_ROOT,
    units_set_root: SET_ROOT2,
    fills_root: FILLS_ROOT,
    unit_id: forcedOmit,
    left: SET2[0],
    left_proof: merkle.getMerkleProof(SET2, 0),
    right: SET2[1],
    right_proof: merkle.getMerkleProof(SET2, 1),
  };
  await triggerBounce(challenger, dispute, Object.assign({ pred: "omit", height: 2 }, omitHonest), 20000, "no fraud");
  console.log("9. omit honest (id present, no geometry hit) bounced 'no fraud'");

  // ---- 10. fill_math dishonest → fill AA verdict --------------------------
  // Pre leaves are GENESIS members (FILL_TAKER_PRE + META1): real proofs.
  // price=1e8 qty=1e8 -> notional 1e6, fee 5bps=500 -> exp col -500.
  // Liar posts col 0.
  const takerH = FILL_TAKER;
  const fillStr = `f:${"u".repeat(64)}:0:${takerH}:${"c".repeat(64)}:${"d".repeat(64)}:${"e".repeat(64)}:1:100000000:100000000:9:0`;
  const FILLS1 = pad2([fillStr], "fills1");
  const FILLS_ROOT1 = merkle.getMerkleRoot(FILLS1);
  const takerPreIdx = GENESIS_LEAVES.indexOf(FILL_TAKER_PRE);
  const metaPreIdx = GENESIS_LEAVES.indexOf(META1);
  const POST_LEAVES = [`acct:${takerH}:0:0:0`, META1, `pos:${takerH}:1:100000000:100000000`].sort();
  const POST_WIT = merkle.getMerkleRoot(POST_LEAVES);
  const TRACE_F = pad2([POST_WIT], "tracef");
  const TRACE_F_ROOT = merkle.getMerkleRoot(TRACE_F);
  await submitH2(OPS_ROOT1, TRACE_F_ROOT, UNITS_SET_ROOT, FILLS_ROOT1);
  const fillBase = {
    k: 0,
    trace_root: TRACE_F_ROOT,
    fills_root: FILLS_ROOT1,
    ops_root: OPS_ROOT1,
    fill: fillStr,
    fill_proof: merkle.getMerkleProof(FILLS1, 0),
    pre_wit: WIT_ROOT,
    post_wit: POST_WIT,
    post_proof: merkle.getMerkleProof(TRACE_F, 0),
    pre_acct: FILL_TAKER_PRE,
    pre_acct_proof: merkle.getMerkleProof(GENESIS_LEAVES, takerPreIdx),
    post_acct: `acct:${takerH}:0:0:0`, // liar: col 0, expected -500
    post_acct_proof: merkle.getMerkleProof(POST_LEAVES, POST_LEAVES.indexOf(`acct:${takerH}:0:0:0`)),
    post_pos: `pos:${takerH}:1:100000000:100000000`,
    post_pos_proof: merkle.getMerkleProof(POST_LEAVES, POST_LEAVES.indexOf(`pos:${takerH}:1:100000000:100000000`)),
    pre_meta: META1,
    pre_meta_proof: merkle.getMerkleProof(GENESIS_LEAVES, metaPreIdx),
    pos_absent: true,
  };
  await trigger(challenger, fill, Object.assign({ pred: "fill_math", height: 2 }, fillBase), 20000);
  st = await vars(rollup);
  if (Number(st.frozen_2) !== 2) throw new Error("fill_math fraud did not freeze height");
  if (String(st.dispute_fill_aa) !== fill) throw new Error("verdict not from fill AA");
  console.log("10. fill_math dishonest → frozen=2 via fill AA");

  // ---- 11. fill_math honest → 'no fraud' -----------------------------------
  const POST_H = [`acct:${takerH}:-500:0:0`, META1, `pos:${takerH}:1:100000000:100000000`].sort();
  const POST_H_WIT = merkle.getMerkleRoot(POST_H);
  const TRACE_H = pad2([POST_H_WIT], "traceh");
  const TRACE_H_ROOT = merkle.getMerkleRoot(TRACE_H);
  await submitH2(OPS_ROOT1, TRACE_H_ROOT, UNITS_SET_ROOT, FILLS_ROOT1);
  const fillHonest2 = Object.assign({}, fillBase, {
    trace_root: TRACE_H_ROOT,
    post_wit: POST_H_WIT,
    post_proof: merkle.getMerkleProof(TRACE_H, 0),
    post_acct: `acct:${takerH}:-500:0:0`,
    post_acct_proof: merkle.getMerkleProof(POST_H, POST_H.indexOf(`acct:${takerH}:-500:0:0`)),
    post_pos: `pos:${takerH}:1:100000000:100000000`,
    post_pos_proof: merkle.getMerkleProof(POST_H, POST_H.indexOf(`pos:${takerH}:1:100000000:100000000`)),
  });
  await triggerBounce(challenger, fill, Object.assign({ pred: "fill_math", height: 2 }, fillHonest2), 20000, "no fraud");
  console.log("11. fill_math honest bounced 'no fraud'");

  // ---- 12. ghost: maker order absent → fraud --------------------------------
  // 'ord:' sorts after every genesis leaf -> after-max shape: left is the
  // last genesis leaf (index GEN_WIT_COUNT-1 == wit_count_1-1), no right.
  await submitH2(OPS_ROOT1, TRACE_F_ROOT, UNITS_SET_ROOT, FILLS_ROOT1);
  const ghostOrd = `ord:${"e".repeat(64)}:1:1:100:9:3:${"c".repeat(64)}`;
  const gSorted = GENESIS_LEAVES.slice().sort();
  const gLast = gSorted.length - 1;
  if (!(ghostOrd > gSorted[gLast])) throw new Error("ghost fixture not after-max");
  const ghostProof = {
    k: 0,
    trace_root: TRACE_F_ROOT,
    fills_root: FILLS_ROOT1,
    ops_root: OPS_ROOT1,
    fill: fillStr,
    fill_proof: merkle.getMerkleProof(FILLS1, 0),
    pre_wit: WIT_ROOT,
    maker_ord: ghostOrd,
    left: gSorted[gLast],
    left_proof: merkle.getMerkleProof(gSorted, gLast),
  };
  await trigger(challenger, fill, Object.assign({ pred: "ghost", height: 2 }, ghostProof), 20000);
  st = await vars(rollup);
  if (Number(st.frozen_2) !== 2) throw new Error("ghost fraud did not freeze height");
  console.log("12. ghost (absent maker) → frozen=2");

  // ---- 13. skip: better live order ignored → fraud ---------------------------
  // Pre tree needs TWO live orders: the filled maker (worse) + a strictly
  // better one. Genesis has no orders, so commit a dedicated pre tree for
  // this height: PRE_SKIP leaves [takerPre, meta, makerOrd, betterOrd].
  // h=2 k=0 still anchors on wit_root_1... which is the GENESIS tree, not
  // PRE_SKIP. So this height submits its own post tree but the AA checks
  // pre-member proofs against trigger-supplied pre_wit == wit_root_1.
  // Resolution: extend the GENESIS tree with both orders from the start.
  // (GENESIS2 below replaces GENESIS for heights submitted after this
  // point — but wit_root_1 is already committed. Instead: run skip on a
  // FRESH height chain is overkill; simpler: prove skip against the
  // genesis-anchored pre tree by adding the two orders INTO genesis.)
  // => Genesis already lacks orders, so skip runs here against a
  // standalone pre tree committed via a new height-3 chain:
  // finalize h=2 first, then h=3 with wit_root_2 = SKIP_PRE root.
  await sendCombinedSubmit(operator, 2, STATE_ROOT, STATE_ROOT);
  await network.timetravel({ shift: "3600s" });
  await trigger(operator, rollup, { finalize: 1, height: 2 }, 20000);
  const MAKER_ORD = `ord:${"d".repeat(64)}:1:1:100:7:5:${"c".repeat(64)}`;
  const BETTER_ORD = `ord:${"e".repeat(63)}f:1:1:90:6:9:${"c".repeat(64)}`;
  const SKIP_PRE = [FILL_TAKER_PRE, META1, MAKER_ORD, BETTER_ORD].sort();
  const SKIP_PRE_WIT = merkle.getMerkleRoot(SKIP_PRE);
  const SKIP_TRACE = pad2([SKIP_PRE_WIT], "skiptrace");
  const SKIP_TRACE_ROOT = merkle.getMerkleRoot(SKIP_TRACE);
  const SKIP_FILLS = pad2([`f:${"u".repeat(64)}:0:${FILL_TAKER}:${"c".repeat(64)}:${"d".repeat(64)}:${"d".repeat(64)}:1:100:5:9:0`], "skipfills");
  const SKIP_FILLS_ROOT = merkle.getMerkleRoot(SKIP_FILLS);
  const sd3 = submitData(3, STATE_ROOT, STATE_ROOT);
  sd3.trace_root = SKIP_TRACE_ROOT;
  sd3.fills_root = SKIP_FILLS_ROOT;
  sd3.wit_root = SKIP_PRE_WIT;
  sd3.wit_count = SKIP_PRE.length;
  {
    const h3data = { chain_id: "operp-v2", height: 3 };
    const r = await operator.sendMulti({
      messages: [
        {
          app: "temp_data",
          payload_location: "inline",
          payload: {
            data_length: require("ocore/object_length.js").getLength(h3data, true),
            data_hash: require("ocore/object_hash.js").getBase64Hash(h3data, true),
            data: h3data,
          },
        },
        { app: "data", payload: sd3 },
      ],
      base_outputs: [{ address: rollup, amount: SUBMIT_GROSS }],
    });
    if (r.error) throw new Error("h3 submit failed: " + r.error);
    await network.witnessUntilStable(r.unit);
  }
  // h=4 k=0 anchors pre_wit on wit_root_3 = SKIP_PRE_WIT; post tree is a
  // padded single leaf (proof needs a sibling).
  const SKIP_TRACE4 = pad2([`skip-post-wit`], "skiptrace4");
  const SKIP_TRACE4_ROOT = merkle.getMerkleRoot(SKIP_TRACE4);
  const sd4 = submitData(4, STATE_ROOT, STATE_ROOT);
  sd4.trace_root = SKIP_TRACE4_ROOT;
  sd4.fills_root = SKIP_FILLS_ROOT;
  sd4.ops_root = OPS_ROOT1;
  {
    const h4data = { chain_id: "operp-v2", height: 4 };
    const r = await operator.sendMulti({
      messages: [
        {
          app: "temp_data",
          payload_location: "inline",
          payload: {
            data_length: require("ocore/object_length.js").getLength(h4data, true),
            data_hash: require("ocore/object_hash.js").getBase64Hash(h4data, true),
            data: h4data,
          },
        },
        { app: "data", payload: sd4 },
      ],
      base_outputs: [{ address: rollup, amount: SUBMIT_GROSS }],
    });
    if (r.error) throw new Error("h4 submit failed: " + r.error);
    await network.witnessUntilStable(r.unit);
  }
  const skipProof = {
    k: 0,
    trace_root: SKIP_TRACE4_ROOT,
    fills_root: SKIP_FILLS_ROOT,
    ops_root: OPS_ROOT1,
    fill: SKIP_FILLS[0],
    fill_proof: merkle.getMerkleProof(SKIP_FILLS, 0),
    pre_wit: SKIP_PRE_WIT,
    maker_ord: MAKER_ORD,
    maker_proof: merkle.getMerkleProof(SKIP_PRE, SKIP_PRE.indexOf(MAKER_ORD)),
    better_ord: BETTER_ORD,
    better_proof: merkle.getMerkleProof(SKIP_PRE, SKIP_PRE.indexOf(BETTER_ORD)),
  };
  await trigger(challenger, fill, Object.assign({ pred: "skip", height: 4 }, skipProof), 20000);
  st = await vars(rollup);
  if (Number(st.frozen_4) !== 2) throw new Error("skip fraud did not freeze height");
  console.log("13. skip (better order ignored) → frozen=2");
  // ---- 14. re-submit + finalize after fraud works -------------------------
  await sendCombinedSubmit(operator, 4, STATE_ROOT, STATE_ROOT);
  await network.timetravel({ shift: "3600s" });
  await trigger(operator, rollup, { finalize: 1, height: 4 }, 20000);
  st = await vars(rollup);
  if (Number(st.last_finalized) !== 4) throw new Error("re-finalize after fraud failed");
  console.log("14. re-submit + finalize after fraud ok");
  console.log(failures === 0 ? "\nALL SETTLEMENT E2E CHECKS PASSED" : `\n${failures} FAILURES`);
  await network.stop();
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
