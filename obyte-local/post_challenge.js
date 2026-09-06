"use strict";

// OPERP dispute prover — posts a one-shot fraud predicate to the dispute AA
// instead of the legacy pay-to-kill {challenge:1}. A failed predicate
// bounces ('no fraud') and coins return; a proven one forwards
// {verdict:'fraud', height, challenger} to the rollup AA which fails the
// height and slashes half the submit bond to the challenger.
//
// Usage: cd obyte-local && node post_challenge.js \
//          --height 1 --pred deposit --proof proof.json
//
// proof.json carries everything the predicate needs: k, op, ops_proof,
// pre_wit, pre_proof (k>0), post_wit, post_proof, pre_leaf, post_leaf,
// pre_leaf_proof, post_leaf_proof (shape per agents/operp_dispute.aa).
// The watcher builds these from the temp_data DA package.

const path = require("path");
const fs = require("fs");

const aaRoot = path.join(__dirname, "..", "vendor", "aa-testkit");
const nm = path.join(aaRoot, "node_modules");
process.env.NODE_PATH = [nm, process.env.NODE_PATH].filter(Boolean).join(path.delimiter);
require("module").Module._initPaths();

const { Testkit } = require(path.join(aaRoot, "main.js"));
const { Network } = Testkit({
  TESTDATA_DIR: path.join(__dirname, "testdata-challenger"),
});

function arg(name, def) {
  const i = process.argv.indexOf("--" + name);
  return i > -1 && process.argv[i + 1] ? process.argv[i + 1] : def;
}
function flag(name) {
  return process.argv.indexOf("--" + name) > -1;
}

let network;

async function main() {
  const deploy = JSON.parse(fs.readFileSync(path.join(__dirname, "deployment.json"), "utf8"));
  const useFill = flag("fill");
  const dispute = useFill
    ? deploy.dispute_fill_aa_address || process.env.OPERP_DISPUTE_FILL_AA
    : deploy.dispute_aa_address || process.env.OPERP_DISPUTE_AA;
  const rollup = deploy.rollup_aa_address || process.env.OPERP_ROLLUP_AA;
  if (!dispute || !rollup) throw new Error("deployment.json dispute_aa_address/rollup_aa_address missing");
  const height = Number(arg("height"));
  const pred = arg("pred", "deposit");
  const proofFile = arg("proof");
  if (!height || !proofFile) throw new Error("usage: node post_challenge.js --height N --pred deposit --proof proof.json [--fill]");

  network = await Network.create()
    .with.wallet({ challenger: 1e7 })
    .run();
  const challenger = network.wallet.challenger;
  console.log("dispute", dispute, "height", height, "pred", pred);

  // Bind only when the rollup has no dispute AA registered yet (double
  // bind bounces 'not authorized' — the rollup keeps the first binder).
  const rv = await challenger.readAAStateVars(rollup);
  const rvars = rv.vars || rv;
  const boundKey = useFill ? "dispute_fill_aa" : "dispute_aa";
  if (!rvars[boundKey]) {
    const bind = await challenger.triggerAaWithData({
      toAddress: dispute,
      amount: 20000,
      data: useFill ? { bind_fill: 1 } : { bind: 1 },
    });
    if (bind.error) throw new Error("bind failed: " + bind.error);
    await network.witnessUntilStable(bind.unit);
    console.log("dispute bound");
  } else {
    console.log("dispute already bound:", rvars[boundKey]);
  }

  const data = Object.assign({ height, pred }, proof);
  const r = await challenger.triggerAaWithData({
    toAddress: dispute,
    amount: 20000,
    data,
  });
  if (r.error) throw new Error("challenge failed: " + r.error);
  await network.witnessUntilStable(r.unit);
  await new Promise((res) => setTimeout(res, 3000));
  const v = await challenger.readAAStateVars(rollup);
  const vars_ = v.vars || v;
  const frozen = vars_["frozen_" + height];
  console.log("challenge posted:", r.unit, "frozen_" + height + "=", frozen);
  if (Number(frozen) === 2) {
    console.log("VERDICT: fraud accepted, height failed. slash_reward_ claimable by challenger.");
  } else {
    console.log("predicate bounced ('no fraud' path) — assertion stands, coins returned.");
  }
  await network.stop();
  process.exit(0);
}

main().catch(async (e) => {
  console.error("CHALLENGE FAILED:", e && e.stack ? e.stack : e);
  try { if (network) await network.stop(); } catch (_) {}
  process.exit(1);
});
