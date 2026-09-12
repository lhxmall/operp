"use strict";

// OPERP batch poster — local devnet drill by default; pass testnet/mainnet
// env explicitly (process.env.testnet / process.env.mainnet) to target a
// real network.
//
// Reads an exported batch (obyte-local/batch.json from
// `cargo run -p operp-settle --example export_batch` or stress tooling),
// then against the deployed ROLLUP AA (deployment.json rollup_aa_address):
//   1. posts the FULL batch as OIP-0007 temp_data PLUS the AA submit data
//      message in ONE combined unit (data availability for watchers AND
//      the assertion submit in the same unit — the rollup AA records
//      da_unit_<h>; joins the operator fee race),
//   2. travels the 3600s challenge window, finalizes,
//   3. claims the operator race reward.
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
process.env.NODE_PATH = [nm, process.env.NODE_PATH].filter(Boolean).join(path.delimiter);
require("module").Module._initPaths();
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
  const frameUnits = Array.isArray(batchData.frames)
    ? batchData.frames.map((f) => { try { return JSON.parse(f).u; } catch (_) { return null; } }).filter(Boolean)
    : [];
  const units = (batchData.units && batchData.units.length ? batchData.units : frameUnits) || [];
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
      if (process.env.devnet && !process.env.testnet && !process.env.mainnet) {
        console.log("devnet fixture: evidence skipped for missing joint", aaUnit.slice(0, 16));
        continue;
      }
      throw new Error("deposit anchor missing on Obyte: " + aaUnit.slice(0, 16));
    }
    if (!joint || !joint.unit) {
      if (process.env.devnet && !process.env.testnet && !process.env.mainnet) {
        console.log("devnet fixture: evidence skipped for empty joint", aaUnit.slice(0, 16));
        continue;
      }
      throw new Error("no joint for " + aaUnit.slice(0, 16));
    }
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

async function trigger(wallet, data, amount, toAddress) {
  const r = await wallet.triggerAaWithData({
    toAddress: toAddress || network.agent.vault,
    amount: amount === undefined ? 20000 : amount,
    data,
  });
  if (r.error) throw new Error(JSON.stringify(data).slice(0, 60) + ": " + r.error);
  await network.witnessUntilStable(r.unit);
  return r.unit;
}

let network;

async function main() {
  const deploy = JSON.parse(fs.readFileSync(path.join(__dirname, "deployment.json"), "utf8"));
  const rollup = deploy.rollup_aa_address
    || process.env.OPERP_ROLLUP_AA;
  if (!rollup) throw new Error("deployment.json rollup_aa_address (or OPERP_ROLLUP_AA) missing");
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
    .with.wallet({ poster: 1e13 })
    .run();
  const poster = network.wallet.poster;
  const vault = network.agent.vault;
  process.env.OPERP_VAULT_AA = vault;
  console.log("rollup", rollup, "vault", vault);
  // Frames come from export_batch (`frames` array). Embed evidences into
  // their Deposit/GovDeposit frames, pack so each package source <= 4MB,
  // post each package unit first, then the header da_unit nails the hash list.
  const frames = Array.isArray(batchData.frames) ? batchData.frames.slice() : [];
  if (!frames.length) throw new Error("batch.json is missing the frames array (re-run export_batch)");
  const evByAnchor = new Map();
  for (const e of await buildDepositEvidences(batchData, vault)) evByAnchor.set(String(e.aa_unit).toLowerCase(), e);
  const stamped = frames.map((f) => {
    let o;
    try { o = JSON.parse(f); } catch (_) { return f; }
    const dep = (o.u && o.u.op && (o.u.op.Deposit || o.u.op.GovDeposit)) || null;
    if (dep) {
      const raw = dep.aa_unit;
      const hex = Array.isArray(raw) ? Buffer.from(raw).toString("hex") : raw;
      const ev = evByAnchor.get(String(hex || "").toLowerCase());
      if (ev) o.e = ev;
    }
    return JSON.stringify(o);
  });
  const PACK_CAP = 4000000;
  const srcLen = (b64) => Buffer.byteLength(getJsonSourceString({ package_blob: b64 }), "utf8");
  const packages = [];
  let cur = [];
  const flush = () => {
    if (!cur.length) return;
    packages.push(Buffer.from(cur.join("\n"), "utf8").toString("base64"));
    cur = [];
  };
  for (const f of stamped) {
    const trial = cur.length ? cur.join("\n") + "\n" + f : f;
    const b64 = Buffer.from(trial, "utf8").toString("base64");
    if (cur.length && srcLen(b64) > PACK_CAP) flush();
    cur.push(f);
  }
  flush();
  const rawBlobs = packages.map((b) => Buffer.from(b, "base64"));
  const dataRoot = crypto.createHash("sha256").update(Buffer.concat(rawBlobs)).digest("hex");
  const header = Object.assign({}, batchData);
  delete header.frames;
  delete header.frames_blob;
  delete header.packages;
  delete header.data_root;
  delete header.units;
  delete header.unit_ids;
  delete header.trace;
  delete header.ops;
  delete header.counts;
  delete header.fills;
  delete header.leaf_trace;
  delete header.deposit_evidences;
  // Multi-package: post each package unit FIRST, then the header nails the
  // real Obyte unit hashes (base64 unit ids as the hub returns them) so
  // watchers can get_joint each entry. Single package inlines frames_blob.
  const pkgUnits = [];
  for (let i = 0; i < packages.length; i++) {
    if (packages.length > 1) {
      const pr = await poster.sendMulti({
        messages: [tempDataMessage({ package_blob: packages[i] })],
        base_outputs: [{ address: await poster.getAddress(), amount: 10000 }],
      });
      if (pr.error) throw new Error("package post failed: " + pr.error);
      await network.witnessUntilStable(pr.unit);
      pkgUnits.push(pr.unit);
      console.log("package posted:", pr.unit);
    }
  }
  if (packages.length === 1) {
    header.frames_blob = packages[0];
    header.data_root = dataRoot;
  } else {
    header.packages = pkgUnits;
    header.data_root = dataRoot;
  }
  // 1+2 COMBINED: header DA reveal + submit in ONE unit — block order = this
  // unit's order. The AA records var['da_unit_<h>'] = this unit's hash, so
  // the root provably points at exactly this temp_data package. First
  // stable combined unit wins the height ('height taken' otherwise).
  const shardRoots = header.aa_shard_roots;
  if (!Array.isArray(shardRoots) || shardRoots.length !== 16 ||
      !shardRoots.every((r) => typeof r === "string" && /^[0-9a-f]{64}$/.test(r)))
    throw new Error("batch.json is missing a valid 16-entry aa_shard_roots array");
  const aaForest = shardRoots.join("");
  const submitData = {
    submit: 1,
    chain_id: header.chain_id || "operp-v2",
    height: header.height,
    prev_state_hash: header.prev_state_hash,
    state_root: header.state_root,
    aa_forest: aaForest,
    assertion_version: header.assertion_version || 1,
    wit_root: header.wit_root,
    trace_root: header.trace_root,
    units_root: header.units_root,
    units_set_root: header.units_set_root,
    ops_root: header.ops_root,
    fills_root: header.fills_root,
    counts_root: header.counts_root,
    unit_count: header.unit_count,
    wit_count: header.wit_count,
  };
  if (header.validity_proof_hash) submitData.validity_proof_hash = header.validity_proof_hash;
  if (header.perp_burned !== undefined) submitData.perp_burned = String(header.perp_burned);
  // 10000000010000 = 1000000000000 SUBMIT_BOND_NET + 10000 bounce fee headroom.
  const r = await poster.sendMulti({
    messages: [tempDataMessage(header), { app: "data", payload: submitData }],
    base_outputs: [{ address: rollup, amount: 10000000010000 }],
  });
  if (r.error) throw new Error("combined da_unit failed: " + r.error);
  const daUnit = r.unit;
  await network.witnessUntilStable(daUnit);
  console.log("combined da_unit posted & stable:", daUnit);
  console.log("da_unit:", daUnit);
  // 2. challenge window then finalize (no lock in operp-v2)
  await network.timetravel({ shift: "3600s" });
  await trigger(poster, { finalize: 1, height: header.height }, undefined, rollup);

  // 3. claim the operator race reward
  const claim = await poster.triggerAaWithData({
    toAddress: rollup,
    amount: 20000,
    data: { claim: "reward" },
  });
  if (claim.error) throw new Error("claim failed: " + claim.error);
  await network.witnessUntilStable(claim.unit);
  await new Promise(r => setTimeout(r, 3000));
  const v = await poster.readAAStateVars(rollup);
  const vars_ = v.vars || v;
  const owed = vars_["reward_" + (await poster.getAddress())];
  if (owed !== undefined && Number(owed) !== 0) {
    throw new Error("reward_ not zeroed after claim: " + owed);
  }
  console.log("post-claim accrued reward remaining: 0 (paid out, var cleared)");
  console.log("\nOK: assertion submitted, finalized, reward claimed.");
  console.log("Watchers re-executing this temp_data within the 3600s window can");
  console.log("prove fraud to the dispute AA and fail the height before finalize.");
  await network.stop();
  process.exit(0);
}

main().catch(async (e) => {
  console.error("POST FAILED:", e && e.stack ? e.stack : e);
  try { if (network) await network.stop(); } catch (_) {}
  process.exit(1);
});
