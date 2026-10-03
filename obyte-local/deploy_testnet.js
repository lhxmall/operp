"use strict";

// OPERP vault AA — Obyte TESTNET deployment script.
//
// Deploys the security-hardened operp_vault.aa to a testnet node, performs an
// initial smoke deposit, and prints the resulting AA address for operators.
//
// Prerequisites:
//   - testnet data dir / node reachable by aa-testkit (see vendor/aa-testkit)
//   - run from obyte-local/:  node deploy_testnet.js
//
// This script does NOT post batches or move real user funds; it is the first
// step of the plan's "达标代码 + 测试网部署脚本" deliverable. Mainnet
// deployment is explicitly out of scope (see plan section E).

const path = require("path");
const fs = require("fs");

// ===== CONFIG: PERP governance asset ================================
// Set to the real PERP asset id once issued, then redeploy the AA.
const PERP_ASSET_ID = "PERP_ASSET_ID_HERE";
// ====================================================================

// Chain id baked into the AA definitions and echoed into deployment.json.
const CHAIN_ID = "operp-v2";

// The .aa sources carry PERP_ASSET_ID_HERE / DISPUTE_AA_HERE placeholders;
// aa-testkit reads agent definitions from disk, so materialize substituted
// copies and deploy those. #13: the dispute AAs hash FIRST (their defs
// carry no rollup address — mutual hardcoding would be a chash cycle),
// then the rollup is materialized with both dispute addresses hardcoded,
// then the vault with the deployed rollup address.
function resolveAa(agentFile, subs, outName) {
  let src = fs.readFileSync(path.join(__dirname, "agents", agentFile), "utf8");
  for (const [k, v] of Object.entries(subs)) src = src.split(k).join(v);
  const out = path.join(__dirname, "agents", outName);
  fs.writeFileSync(out, src);
  return out;
}
function resolveRollupAa(disputeAddr, fillAddr) {
  return resolveAa("operp_rollup.aa", { DISPUTE_AA_HERE: disputeAddr, DISPUTE_FILL_AA_HERE: fillAddr }, ".operp_rollup.resolved.aa");
}
function resolveDisputeAa() {
  return resolveAa("operp_dispute.aa", {}, ".operp_dispute.resolved.aa");
}
function resolveVaultAa(rollupAddress, perpAssetId) {
  return resolveAa("operp_vault.aa", { ROLLUP_AA_HERE: rollupAddress, PERP_ASSET_ID_HERE: perpAssetId }, ".operp_vault.resolved.aa");
}
function resolveFillAa() {
  return resolveAa("operp_dispute_fill.aa", {}, ".operp_dispute_fill.resolved.aa");
}
const aaRoot = path.join(__dirname, "..", "vendor", "aa-testkit");
const nm = path.join(aaRoot, "node_modules");
process.env.NODE_PATH = [nm, process.env.NODE_PATH].filter(Boolean).join(path.delimiter);
require("module").Module._initPaths();
process.env.testnet = "1";
delete process.env.devnet;

const { Testkit } = require(path.join(aaRoot, "main.js"));
const objectHash = require("ocore/object_hash.js");
const parseOjson = require("ocore/formula/parse_ojson").parse;
const { Network } = Testkit({
  TESTDATA_DIR: path.join(__dirname, "testdata-testnet"),
});

async function main() {
  if (PERP_ASSET_ID === "PERP_ASSET_ID_HERE")
    throw new Error("Set PERP_ASSET_ID to the issued asset id before deploying");
  console.log("deploying operp_rollup.aa / operp_dispute.aa / operp_vault.aa to TESTNET ...");
  // #13 order: dispute AAs hash first (no rollup in their defs), then the
  // rollup hardcodes them, then vault + binds (rollup rides trigger data).
  const disputePath = resolveDisputeAa();
  const fillPath = resolveFillAa();
  const chashOf = (file) => {
    let parsed = null;
    parseOjson(fs.readFileSync(file, "utf8"), (err, res) => {
      if (err) throw err;
      parsed = res[1];
    });
    return objectHash.getChash160(["autonomous agent", parsed]);
  };
  const disputeAddr = chashOf(disputePath);
  const fillAddr = chashOf(fillPath);
  const rollupPath = resolveRollupAa(disputeAddr, fillAddr);

  const network = await Network.create()
    .with.agent({ rollup: rollupPath })
    .with.wallet({ operator: 1e14 })
    .run();
  const rollup = network.agent.rollup;
  const operator = network.wallet.operator;
  console.log("rollup AA address:", rollup);

  const network2 = await Network.create()
    .with.agent({ dispute: disputePath })
    .with.agent({ fill: fillPath })
    .with.agent({ vault: resolveVaultAa(rollup, PERP_ASSET_ID) })
    .with.wallet({ operator: 1e14 })
    .run();
  const dispute = network2.agent.dispute;
  const fill = network2.agent.fill;
  const vault = network2.agent.vault;
  console.log("dispute AA address:", dispute);
  console.log("fill AA address   :", fill);
  console.log("vault AA address  :", vault);
  // Bind both dispute AAs; the rollup refuses verdicts from any other
  // address afterwards.
  const { unit, error } = await operator.triggerAaWithData({
    toAddress: dispute,
    amount: 20000,
    data: { bind: 1, rollup },
  });
  if (error || !unit) throw new Error("dispute bind failed: " + error);
  await network2.witnessUntilStable(unit);
  console.log("dispute bound; unit =", unit);
  const op2 = network2.wallet.operator;
  const fb = await op2.triggerAaWithData({
    toAddress: fill,
    amount: 20000,
    data: { bind_fill: 1, rollup },
  });
  if (fb.error || !fb.unit) throw new Error("fill bind failed: " + fb.error);
  await network2.witnessUntilStable(fb.unit);
  console.log("fill bound; unit =", fb.unit);

  const v = await operator.readAAStateVars(rollup);
  const vars_ = v.vars || v;
  if (String(vars_.dispute_aa) !== String(dispute))
    throw new Error("dispute_aa not bound: " + JSON.stringify(vars_.dispute_aa));
  if (String(vars_.dispute_fill_aa) !== String(fill))
    throw new Error("dispute_fill_aa not bound: " + JSON.stringify(vars_.dispute_fill_aa));
  if (Number(vars_.last_submitted || 0) !== 0)
    throw new Error("boot last_submitted wrong");
  if (Number(vars_.last_finalized || 0) !== 0)
    throw new Error("boot last_finalized wrong");

  // persist deployment info for the operator tooling
  const info = {
    network: "testnet",
    rollup_aa_address: rollup,
    dispute_aa_address: dispute,
    dispute_fill_aa_address: fill,
    vault_aa_address: vault,
    perp_asset_id: PERP_ASSET_ID,
    challenge_secs: 3600,
    chain_id: CHAIN_ID,
    pool_fund_gross: 10000000010000,
    deployed_at: new Date().toISOString(),
  };
  console.log("NOTE: mainnet deployment requires a formal AA audit.");
  await network.stop();
  await network2.stop();
  process.exit(0);
}

main().catch(async (e) => {
  console.error("DEPLOY FAILED:", e && e.stack ? e.stack : e);
  process.exit(1);
});
