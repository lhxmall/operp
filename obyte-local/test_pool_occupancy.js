"use strict";

// OPERP pool occupancy gate — standalone e2e (rollup AA only).
//
// Fills the in-flight window: fund {pool:1}, submit heights 1..50 with no
// finalize between (no timetravel needed — submit has no time gate), then
// height 51 must bounce 'pool occupancy'. Complements test_settlement_aa.js
// scenario 16, which only covers the allow side (2 in flight, no bounce).
//
// Cost: 1 fund + 50 submits + 1 bounce ≈ 52 stable units, ~2-4 min on CI.
// Runs inside the same 20min e2e job as the settlement suite.

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
  TESTDATA_DIR: path.join(__dirname, "testdata-occupancy"),
  NETWORK_PORT: 16616,
});
const objectHash = require("ocore/object_hash.js");
const parseOjson = require("ocore/formula/parse_ojson").parse;

function sha256Hex(s) {
  return crypto.createHash("sha256").update(s, "utf8").digest("hex");
}
function readDef(file) {
  return fs.readFileSync(path.join(__dirname, "agents", file), "utf8");
}
function chashOf(aaSource) {
  let parsed = null;
  parseOjson(aaSource, (err, res) => {
    if (err) throw err;
    parsed = res[1];
  });
  return objectHash.getChash160(["autonomous agent", parsed]);
}
const ROLLUP_ADDR = chashOf(readDef("operp_rollup.aa"));
// AA gates witness roots at 44 chars (base64), state roots at 64 hex.
// Values need not be real trees here — no predicates run in this file.
const b64root = (s) => Buffer.from(sha256Hex(s), "hex").toString("base64");
const FOREST = sha256Hex("f0").repeat(16);
const WIT_ROOT = b64root("wit");
const TRACE_ROOT = b64root("trace");
const UNITS_ROOT = b64root("units");
const UNITS_SET_ROOT = b64root("set");
const OPS_ROOT = b64root("ops");
const FILLS_ROOT = b64root("fills");
const COUNTS_ROOT = b64root("counts");
const GENESIS = sha256Hex("genesis");

function submitData(h, prev) {
  return {
    submit: 1,
    chain_id: "operp-v2",
    assertion_version: 1,
    height: h,
    state_root: sha256Hex("state-" + h),
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
    wit_count: 1,
  };
}

let network;
async function trigger(wallet, to, data, amount) {
  const r = await wallet.triggerAaWithData({ toAddress: to, amount, data });
  if (r.error) throw new Error(`trigger h=${data.height}: ${r.error}`);
  await network.witnessUntilStable(r.unit);
  const res = await network.getAaResponseToUnit(r.unit).catch(() => null);
  const log = JSON.stringify(res || {});
  if (log.includes('"bounced":true')) {
    throw new Error(`trigger h=${data.height} bounced: ` + log.slice(0, 300));
  }
  return r;
}
async function vars(aa) {
  const v = await network.wallet.operator.readAAStateVars(aa);
  return v.vars || v;
}

async function main() {
  network = await Network.create()
    .with.agent({ rollup: path.join(__dirname, "agents", "operp_rollup.aa") })
    .with.wallet({ operator: 2e14 })
    .run();
  const { operator } = network.wallet;
  const rollup = network.agent.rollup;
  if (rollup !== ROLLUP_ADDR) throw new Error(`rollup address mismatch: ${rollup} != ${ROLLUP_ADDR}`);

  await trigger(operator, rollup, { pool: 1 }, POOL_FUND_GROSS);
  let prev = GENESIS;
  for (let h = 1; h <= 50; h++) {
    const sd = submitData(h, prev);
    await trigger(operator, rollup, sd, SUBMIT_FEE);
    prev = sd.state_root;
    if (h % 10 === 0) console.log(`submitted h=${h}`);
  }
  let st = await vars(rollup);
  if (Number(st.last_submitted) !== 50) throw new Error("last_submitted != 50: " + st.last_submitted);
  if (Number(st.last_finalized || 0) !== 0) throw new Error("nothing should be finalized");

  // 51st submit: in flight = 50 - 0 >= 50 → must bounce 'pool occupancy'.
  const r = await operator.triggerAaWithData({
    toAddress: rollup,
    amount: SUBMIT_FEE,
    data: submitData(51, prev),
  });
  if (r.error && String(r.error).includes("pool occupancy")) {
    console.log("bounce ok: 'pool occupancy' (composer-level)");
  } else {
    if (r.error) throw new Error("h51 submit failed unexpectedly: " + r.error);
    await network.witnessUntilStable(r.unit);
    const res = await network.getAaResponseToUnit(r.unit).catch(() => null);
    const log = JSON.stringify(res || {});
    if (!log.includes("pool occupancy")) throw new Error("h51 did not bounce occupancy: " + log.slice(0, 300));
    console.log("bounce ok: 'pool occupancy' (AA response)");
  }
  st = await vars(rollup);
  if (Number(st.last_submitted) !== 50) throw new Error("h51 must not advance last_submitted");
  console.log("\nOCCUPANCY GATE OK: 50 in flight accepted, 51st bounced");
  await network.stop();
  process.exit(0);
}

main().catch(async (e) => {
  console.error("OCCUPANCY FAILED:", e && e.stack ? e.stack : e);
  try { if (network) await network.stop(); } catch (_) {}
  process.exit(1);
});
