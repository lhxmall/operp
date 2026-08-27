"use strict";

// OPERP batch poster — local devnet drill by default; pass testnet/mainnet
// env explicitly (process.env.testnet / process.env.mainnet) to target a
// real network.
//
// Reads an exported batch (obyte-local/batch.json from
// `cargo run -p operp-settle --example export_batch` or stress tooling),
// then against the deployed vault AA:
//   1. posts the FULL batch as OIP-0007 temp_data PLUS the AA submit data
//      message in ONE combined unit (data availability for watchers AND
//      the submit in the same unit — the AA records da_unit_<h>; joins
//      the operator fee race),
//   2. travels the 600s stability window, locks,
//   3. travels the 3600s challenge window, finalizes,
//   4. claims the operator race reward.
// Usage: cd obyte-local && node post_batch.js [batch.json]

const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
// ===== CONFIG: PERP governance asset ================================
// Set to the real PERP asset id once issued; must match deploy_testnet.js.
// devnet (default) has no issued asset: fall back to 'base' exactly like
// test_vault_aa.js's bootstrap substitution — the perp-deposit branch is
// keyed on trigger.data.deposit_perp, so base can never reach it here.
let PERP_ASSET_ID = "PERP_ASSET_ID_HERE";
// ====================================================================

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
// Network selection: devnet drill by default; pass testnet/mainnet env
// explicitly to target a real network.
if (process.env.testnet) {
  process.env.testnet = "1";
  delete process.env.devnet;
} else if (process.env.mainnet) {
  process.env.mainnet = "1";
} else {
  process.env.devnet = "1";
  // devnet has no issued asset: fall back to 'base' exactly like
  // test_vault_aa.js's bootstrap substitution — the perp-deposit branch is
  // keyed on trigger.data.deposit_perp, so base can never reach it here.
  PERP_ASSET_ID = "base";
}

const { Testkit } = require(path.join(aaRoot, "main.js"));
const { Network } = Testkit({
  TESTDATA_DIR: path.join(__dirname, "testdata-poster"),
});

// H3 — single canonical definition of the batch data hash/length, matching
// Rust operp_settle::obyte_hash::get_data_hash: the canonical source is
// ocore's recursively key-sorted minified JSON (string_utils.getJsonSourceString),
// data_hash is its SHA-256 in HEX, data_length its UTF-8 byte length.
const { getJsonSourceString } = require("ocore/string_utils.js");

function obyteDataLength(data) {
  return Buffer.byteLength(getJsonSourceString(data));
}

function obyteDataHash(data) {
  return crypto.createHash("sha256").update(getJsonSourceString(data), "utf8").digest("hex");
}

function tempDataMessage(data) {
  // The ON-CHAIN OIP-0007 envelope must satisfy ocore's temp_data validator
  // (validation.js pins data_hash to base64 getBase64Hash(data, true) and
  // data_length to objectLength.getLength(data, true)), so both wire fields
  // are delegated to ocore itself instead of hand-rolled copies. Watchers
  // ignore them and recompute the canonical hex pair above from payload.data.
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

// Step4 — deposit independent verification: for every Deposit/GovDeposit
// op in the batch, fetch the endorsing Obyte joint and build a
// DepositEvidence sorted lexicographically by aa_unit. Watchers re-derive
// unit_hash(joint) and compare against the sidechain deposit's aa_unit, so
// a deposit endorsement is verifiable without trusting the operator.
const { hub } = require(path.join(aaRoot, "node_modules", "ocore", "network.js"));
async function buildDepositEvidences(batchData, vaultAddress) {
  const evidences = [];
  const seen = new Set();
  const units = batchData.units || [];
  for (const u of units) {
    const op = u.op || {};
    const isPerp = op.GovDeposit !== undefined;
    const dep = isPerp ? op.GovDeposit : op.Deposit;
    if (!dep) continue;
    const rawUnit = dep.aa_unit;
    // serde emits aa_unit as a numeric byte array; accept both it and hex.
    const aaUnit = Array.isArray(rawUnit)
      ? Buffer.from(rawUnit).toString("hex")
      : rawUnit;
    if (typeof aaUnit !== "string" || aaUnit.length !== 64) continue;
    if (seen.has(aaUnit)) continue;
    seen.add(aaUnit);
    let joint;
    try {
      joint = await new Promise((resolve, reject) => {
        hub.getJoint(Buffer.from(aaUnit, "hex").toString("base64"), (err, j) => (err ? reject(err) : resolve(j)));
      });
    } catch (e) {
      throw new Error("deposit anchor missing on Obyte: " + aaUnit.slice(0, 16));
    }
    if (!joint || !joint.unit) throw new Error("no joint for " + aaUnit.slice(0, 16));
    // joint carries the FULL joint unit object: the watcher recomputes
    // unit_hash(joint.unit) via operp_settle::obyte_hash::get_unit_hash and
    // compares against the sidechain deposit's aa_unit.
    evidences.push({
      aa_unit: aaUnit,
      is_perp: isPerp,
      amount: String(dep.amount),
      vault_address: vaultAddress,
      joint: joint.unit,
    });
  }
  evidences.sort((a, b) => (a.aa_unit < b.aa_unit ? -1 : 1));
  return evidences;
}

async function trigger(wallet, data, amount) {
  const r = await wallet.triggerAaWithData({
    toAddress: network.agent.vault,
    amount: amount === undefined ? 20000 : amount,
    data,
  });
  if (r.error) throw new Error(JSON.stringify(data).slice(0, 60) + ": " + r.error);
  await network.witnessUntilStable(r.unit);
  return r.unit;
}

let network;

async function main() {
  if (PERP_ASSET_ID === "PERP_ASSET_ID_HERE")
    throw new Error("Set PERP_ASSET_ID to the issued asset id before posting (testnet/mainnet)");
  const batchFile = process.argv[2] || path.join(__dirname, "batch.json");
  const batchData = JSON.parse(fs.readFileSync(batchFile, "utf8"));
  // H3 contract visibility: the canonical pair watchers recompute from
  // payload.data (Rust operp_settle::obyte_hash::get_data_hash).
  console.log("canonical data_hash:", obyteDataHash(batchData),
    "data_length:", obyteDataLength(batchData));
  console.log("batch:", batchData.chain_id, "height", batchData.height,
    "units", (batchData.unit_ids || []).length);

  network = await Network.create()
    .with.agent({ vault: resolveVaultAa() })
    .with.wallet({ poster: 5e9 })
    .run();
  const vault = network.agent.vault;
  const poster = network.wallet.poster;
  console.log("vault", vault);

  // Step4: build deposit_evidences BEFORE posting so the temp_data reveal
  // carries them (watchers verify unit_hash(joint) == aa_unit independently).
  batchData.deposit_evidences = await buildDepositEvidences(batchData, vault);
  if (batchData.deposit_evidences.length) {
    console.log("deposit_evidences:", batchData.deposit_evidences.length);
  }

  // 1+2 COMBINED: DA reveal + submit in ONE unit — block order = this
  // unit's order. The AA records var['da_unit_<h>'] = this unit's hash, so
  // the root provably points at exactly this temp_data package. First
  // stable combined unit wins the height ('height taken' otherwise).
  const shardRoots = batchData.aa_shard_roots;
  if (!Array.isArray(shardRoots) || shardRoots.length !== 16 ||
      !shardRoots.every((r) => typeof r === "string" && /^[0-9a-f]{64}$/.test(r)))
    throw new Error("batch.json is missing a valid 16-entry aa_shard_roots array");
  const aaForest = shardRoots.join("");
  const submitData = {
    submit: 1,
    chain_id: batchData.chain_id || "operp-mvp-1",
    height: batchData.height,
    prev_state_hash: batchData.prev_state_hash,
    state_root: batchData.state_root,
    aa_root: batchData.aa_root,
    aa_forest: aaForest,
    fills_hash: batchData.fills_hash,
  };
  if (batchData.validity_proof_hash) submitData.validity_proof_hash = batchData.validity_proof_hash;
  if (batchData.perp_burned !== undefined) submitData.perp_burned = String(batchData.perp_burned);
  // 60000 = 50000 SUBMIT_BOND_NET + 10000 bounce fee headroom.
  const r = await poster.sendMulti({
    messages: [tempDataMessage(batchData), { app: "data", payload: submitData }],
    base_outputs: [{ address: vault, amount: 60000 }],
  });
  if (r.error) throw new Error("combined da_unit failed: " + r.error);
  const daUnit = r.unit;
  await network.witnessUntilStable(daUnit);
  console.log("combined da_unit posted & stable:", daUnit);
  console.log("da_unit:", daUnit);
  // 3. stability window then lock
  await network.timetravel({ shift: "700s" });
  await trigger(poster, { lock: 1, height: batchData.height });

  // 4. challenge window then finalize
  await network.timetravel({ shift: "3600s" });
  await trigger(poster, { finalize: 1, height: batchData.height });

  // 5. claim the operator race reward
  const claim = await poster.triggerAaWithData({
    toAddress: vault,
    amount: 20000,
    data: { claim: "reward" },
  });
  if (claim.error) throw new Error("claim failed: " + claim.error);
  await network.witnessUntilStable(claim.unit);
  await new Promise(r => setTimeout(r, 3000));
  const v = await poster.readAAStateVars(vault);
  const vars_ = v.vars || v;
  const owed = vars_["reward_" + (await poster.getAddress())];
  if (owed !== undefined && Number(owed) !== 0) {
    throw new Error("reward_ not zeroed after claim: " + owed);
  }
  console.log("post-claim accrued reward remaining: 0 (paid out, var cleared)");
  console.log("\nOK: batch posted, locked, finalized, reward claimed.");
  console.log("Watchers re-executing this temp_data within 1 day can detect any");
  console.log("root mismatch and freeze/rollback the height via challenge.");
  await network.stop();
  process.exit(0);
}

main().catch(async (e) => {
  console.error("POST FAILED:", e && e.stack ? e.stack : e);
  try { if (network) await network.stop(); } catch (_) {}
  process.exit(1);
});
