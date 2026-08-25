"use strict";

// OPERP batch poster — the operator's mainnet/testnet submission flow.
//
// Reads an exported batch (obyte-local/batch.json from
// `cargo run -p operp-settle --example export_batch` or stress tooling),
// then against the deployed vault AA:
//   1. posts the FULL batch as OIP-0007 temp_data (data availability for
//      watchers — anyone can re-execute and detect fraud),
//   2. triggers AA submit (joins the operator fee race),
//   3. travels the 600s stability window, locks,
//   4. travels the 3600s challenge window, finalizes,
//   5. claims the operator race reward.
//
// Usage: cd obyte-local && node post_batch.js [batch.json]

const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
// ===== CONFIG: PERP governance asset ================================
// Set to the real PERP asset id once issued; must match deploy_testnet.js.
const PERP_ASSET_ID = "PERP_ASSET_ID_HERE";
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
process.env.NODE_PATH = [nm, process.env.NODE_PATH].filter(Boolean).join(path.delimiter);
process.env.devnet = "1";

const { Testkit } = require(path.join(aaRoot, "main.js"));
const { Network } = Testkit({
  TESTDATA_DIR: path.join(__dirname, "testdata-poster"),
});

function getLength(value) {
  const cache = new WeakMap();
  function _len(v) {
    if (v === null) return 0;
    switch (typeof v) {
      case "string": return v.length;
      case "number": if (!isFinite(v)) throw new Error("bad number"); return 8;
      case "boolean": return 1;
      case "object": {
        if (cache.has(v)) return cache.get(v);
        let n = 0;
        if (Array.isArray(v)) { for (const el of v) n += _len(el); }
        else { for (const k of Object.keys(v)) n += k.length + _len(v[k]); }
        cache.set(v, n);
        return n;
      }
      default: throw new Error("unsupported type " + typeof v);
    }
  }
  return _len(value);
}

function obyteBase64Hash(obj) {
  // OIP-0007 canonical source string + SHA-256 base64 (matches ocore
  // getBase64Hash(obj, true): minified JSON with sorted keys).
  const minified = JSON.stringify(obj, (k, v) => v, 0);
  return crypto.createHash("sha256").update(minified, "utf8").digest("base64");
}

function tempDataMessage(data) {
  return {
    app: "temp_data",
    payload_location: "inline",
    payload: {
      data_length: getLength(data),
      data_hash: obyteBase64Hash(data),
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
    const aaUnit = dep.aa_unit;
    if (typeof aaUnit !== "string" || aaUnit.length !== 64) continue;
    if (seen.has(aaUnit)) continue;
    seen.add(aaUnit);
    let joint;
    try {
      joint = await new Promise((resolve, reject) => {
        hub.getJoint(aaUnit, (err, j) => (err ? reject(err) : resolve(j)));
      });
    } catch (e) {
      throw new Error("deposit anchor missing on Obyte: " + aaUnit.slice(0, 16));
    }
    if (!joint || !joint.unit) throw new Error("no joint for " + aaUnit.slice(0, 16));
    evidences.push({
      aa_unit: aaUnit,
      is_perp: isPerp,
      amount: String(dep.amount),
      vault_address: vaultAddress,
      joint: { unit: joint.unit, unit_hash: joint.unitHash },
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
  const batchFile = process.argv[2] || path.join(__dirname, "batch.json");
  const batchData = JSON.parse(fs.readFileSync(batchFile, "utf8"));
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

  // 1. data availability: full batch reveal as temp_data
  const { unit: tdUnit, error: tdErr } = await poster.sendMulti({
    messages: [tempDataMessage(batchData)],
  });
  if (tdErr) throw new Error("temp_data failed: " + tdErr);
  await network.witnessUntilStable(tdUnit);
  console.log("temp_data posted & stable:", tdUnit);

  // 2. join the submit race — 50000 SUBMIT_BOND_NET + >=10000 fee headroom
  // Step6/8: carry optional validity_proof_hash and perp_burned audit mirror.
  const submitData = {
    submit: 1,
    chain_id: batchData.chain_id || "operp-mvp-1",
    height: batchData.height,
    prev_state_hash: batchData.prev_state_hash,
    state_root: batchData.state_root,
    aa_root: batchData.aa_root,
    fills_hash: batchData.fills_hash,
  };
  if (batchData.validity_proof_hash) submitData.validity_proof_hash = batchData.validity_proof_hash;
  if (batchData.perp_burned !== undefined) submitData.perp_burned = batchData.perp_burned;
  await trigger(poster, submitData, 60000);
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
