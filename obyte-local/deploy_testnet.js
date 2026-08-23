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

const aaRoot = path.join(__dirname, "..", "vendor", "aa-testkit");
const nm = path.join(aaRoot, "node_modules");
process.env.NODE_PATH = [nm, process.env.NODE_PATH].filter(Boolean).join(path.delimiter);
require("module").Module._initPaths();
process.env.testnet = "1";
delete process.env.devnet;

const { Testkit } = require(path.join(aaRoot, "main.js"));
const { Network } = Testkit({
  TESTDATA_DIR: path.join(__dirname, "testdata-testnet"),
});

async function main() {
  console.log("deploying operp_vault.aa to TESTNET ...");
  const network = await Network.create()
    .with.agent({ vault: path.join(__dirname, "agents/operp_vault.aa") })
    .with.wallet({ operator: 1e9 })
    .run();

  const vault = network.agent.vault;
  const operator = network.wallet.operator;
  console.log("\n=== DEPLOYED ===");
  console.log("vault AA address:", vault);
  console.log("operator wallet :", await operator.getAddress());

  // smoke deposit: proves the AA accepts triggers on the deployed definition
  const { unit, error } = await operator.triggerAaWithData({
    toAddress: vault,
    amount: 1e6,
    data: { deposit: 1 },
  });
  if (error) throw new Error("smoke deposit failed: " + error);
  await network.witnessUntilStable(unit);

  const v = await operator.readAAStateVars(vault);
  const vars_ = v.vars || v;
  const opAddr = await operator.getAddress();
  if (!(vars_["bal_" + opAddr] > 0)) throw new Error("smoke deposit not credited");
  if (vars_.chain_id !== "operp-mvp-1") throw new Error("boot vars missing");
  if (Number(vars_.last_locked) !== 0 || Number(vars_.last_finalized) !== 0)
    throw new Error("boot heights wrong");
  console.log("smoke deposit OK; bal =", vars_["bal_" + opAddr]);

  // persist deployment info for the operator tooling
  const info = {
    network: "testnet",
    vault_aa_address: vault,
    chain_id: "operp-mvp-1",
    stability_secs: 600,
    challenge_secs: 3600,
    bounce_fee_base: 10000,
    challenge_bond_min: 20000,
    deployed_at: new Date().toISOString(),
  };
  fs.writeFileSync(path.join(__dirname, "deployment.json"), JSON.stringify(info, null, 2));
  console.log("\nwrote deployment.json — pass this address to batch-posting tooling.");
  console.log("NOTE: mainnet deployment requires closing plan-section-E gaps");
  console.log("(fee model, real fraud proofs, TWAP oracle) and a formal AA audit.");
  await network.stop();
  process.exit(0);
}

main().catch(async (e) => {
  console.error("DEPLOY FAILED:", e && e.stack ? e.stack : e);
  process.exit(1);
});
