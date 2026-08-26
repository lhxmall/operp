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

// Chain id baked into the AA definition and echoed into deployment.json.
const CHAIN_ID = "operp-mvp-1";

// The .aa source carries the PERP_ASSET_ID_HERE placeholder; aa-testkit
// reads agent definitions from disk, so materialize a substituted copy
// and deploy that instead of the raw source.
function resolveVaultAa() {
  const src = fs.readFileSync(path.join(__dirname, "agents/operp_vault.aa"), "utf8");
  const out = path.join(__dirname, "agents", ".operp_vault.resolved.aa");
  fs.writeFileSync(out, src.replace(/PERP_ASSET_ID_HERE/g, PERP_ASSET_ID));
  return out;
}
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
  if (PERP_ASSET_ID === "PERP_ASSET_ID_HERE")
    throw new Error("Set PERP_ASSET_ID to the issued asset id before deploying");
  console.log("deploying operp_vault.aa to TESTNET ...");
  const network = await Network.create()
    .with.agent({ vault: resolveVaultAa() })
    .with.wallet({ operator: 1e9 })
    .run();

  const vault = network.agent.vault;
  const operator = network.wallet.operator;
  console.log("\n=== DEPLOYED ===");
  console.log("vault AA address:", vault);
  console.log("operator wallet :", await operator.getAddress());

  // smoke deposit: proves the AA accepts triggers on the deployed definition.
  // Success criterion is simply that the trigger did not bounce — the AA
  // returns { unit, error }; a bounce surfaces as error (or missing unit).
  const { unit, error } = await operator.triggerAaWithData({
    toAddress: vault,
    amount: 1e6,
    data: { deposit: 1 },
  });
  if (error || !unit) throw new Error("smoke deposit failed: " + error);
  await network.witnessUntilStable(unit);
  console.log("smoke deposit OK; unit =", unit);

  // boot heights are zero until the first submit; assert only when the vars
  // exist at all.
  const v = await operator.readAAStateVars(vault);
  const vars_ = v.vars || v;
  if (vars_.last_locked !== undefined && Number(vars_.last_locked) !== 0)
    throw new Error("boot last_locked wrong");
  if (vars_.last_finalized !== undefined && Number(vars_.last_finalized) !== 0)
    throw new Error("boot last_finalized wrong");

  // persist deployment info for the operator tooling
  const info = {
    network: "testnet",
    vault_aa_address: vault,
    stability_secs: 600,
    perp_asset_id: PERP_ASSET_ID,
    challenge_secs: 3600,
    chain_id: CHAIN_ID,
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
