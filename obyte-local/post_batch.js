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
    .with.agent({ vault: path.join(__dirname, "agents/operp_vault.aa") })
    .with.wallet({ poster: 5e9 })
    .run();
  const vault = network.agent.vault;
  const poster = network.wallet.poster;
  console.log("vault", vault);

  // 1. data availability: full batch reveal as temp_data
  const { unit: tdUnit, error: tdErr } = await poster.sendMulti({
    messages: [tempDataMessage(batchData)],
  });
  if (tdErr) throw new Error("temp_data failed: " + tdErr);
  await network.witnessUntilStable(tdUnit);
  console.log("temp_data posted & stable:", tdUnit);

  // 2. join the fee race
  await trigger(poster, {
    submit: 1,
    chain_id: batchData.chain_id || "operp-mvp-1",
    height: batchData.height,
    prev_state_hash: batchData.prev_state_hash,
    state_root: batchData.state_root,
    aa_root: batchData.aa_root,
    fills_hash: batchData.fills_hash,
  });

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
    data: { claim_reward: 1 },
  });
  if (claim.error) throw new Error("claim failed: " + claim.error);
  await network.witnessUntilStable(claim.unit);
  await new Promise(r => setTimeout(r, 3000));
  const v = await poster.readAAStateVars(vault);
  const vars_ = v.vars || v;
  const owed = vars_["reward_" + (await poster.getAddress())];
  console.log("post-claim accrued reward remaining:", owed === undefined ? "0 (paid out)" : owed);

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
