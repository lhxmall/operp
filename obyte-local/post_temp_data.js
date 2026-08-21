"use strict";

/**
 * Spin up a local Obyte DAG (aa-testkit: genesis + hub + witnesses),
 * post an odex-style batch as OIP-0007 temp_data, wait until it is
 * stable on the local main chain, print unit + MCI.
 */

const path = require("path");
const crypto = require("crypto");
const aaRoot = path.join(__dirname, "..", "vendor", "aa-testkit");
const nm = path.join(aaRoot, "node_modules");
process.env.NODE_PATH = [nm, process.env.NODE_PATH].filter(Boolean).join(path.delimiter);
process.env.devnet = "1";

const { Testkit } = require(path.join(aaRoot, "main.js"));

const { Network } = Testkit({
  TESTDATA_DIR: path.join(__dirname, "testdata"),
  NETWORK_PORT: 16611,
});

function getLength(value, bWithKeys) {
  const cache = new WeakMap();
  function _getLength(v) {
    if (v === null) return 0;
    switch (typeof v) {
      case "string":
        return v.length;
      case "number":
        if (!isFinite(v)) throw new Error("invalid number: " + v);
        return 8;
      case "boolean":
        return 1;
      case "object": {
        if (cache.has(v)) return cache.get(v);
        let len = 0;
        if (Array.isArray(v)) {
          for (const el of v) len += _getLength(el);
        } else {
          for (const key of Object.keys(v)) {
            if (bWithKeys) len += key.length;
            len += _getLength(v[key]);
          }
        }
        cache.set(v, len);
        return len;
      }
      default:
        throw new Error("unknown type=" + typeof v);
    }
  }
  return _getLength(value);
}

function getJsonSourceString(obj) {
  const cache = new WeakMap();
  function stringify(variable) {
    if (variable === null) throw new Error("null value");
    switch (typeof variable) {
      case "string":
        return JSON.stringify(variable);
      case "number":
        if (!isFinite(variable)) throw new Error("invalid number");
        return variable.toString();
      case "boolean":
        return variable.toString();
      case "object": {
        if (cache.has(variable)) return cache.get(variable);
        let result;
        if (Array.isArray(variable)) {
          result = "[" + variable.map(stringify).join(",") + "]";
        } else {
          const keys = Object.keys(variable).sort();
          result =
            "{" +
            keys
              .map((key) => JSON.stringify(key) + ":" + stringify(variable[key]))
              .join(",") +
            "}";
        }
        cache.set(variable, result);
        return result;
      }
      default:
        throw new Error("unknown type " + typeof variable);
    }
  }
  return stringify(obj);
}

function getBase64Hash(obj) {
  return crypto.createHash("sha256").update(getJsonSourceString(obj), "utf8").digest("base64");
}

function odexBatchData() {
  return {
    chain_id: "odex-mvp-1",
    height: 1,
    prev_state_hash: "00".repeat(32),
    state_root: "11".repeat(32),
    last_unit: "22".repeat(32),
    seq: 4,
    unit_ids: ["aa".repeat(32), "bb".repeat(32)],
    fill_count: 1,
    fills_hash: "cc".repeat(32),
    note: "odex local-devnet temp_data smoke",
  };
}

function tempDataMessage(data) {
  const data_length = getLength(data, true);
  const data_hash = getBase64Hash(data);
  return {
    app: "temp_data",
    payload_location: "inline",
    payload: { data_length, data_hash, data },
  };
}

async function main() {
  console.log("starting local Obyte DAG (genesis + hub + witnesses)...");
  const network = await Network.create()
    .with.wallet({ poster: 1e9 })
    .run();
  const genesis = await network.getGenesisNode().ready();
  const poster = network.wallet.poster;
  const posterAddress = await poster.getAddress();
  const posterBal = await poster.getBalance();
  console.log("poster address", posterAddress);
  console.log("poster balance", posterBal);

  const data = odexBatchData();
  const message = tempDataMessage(data);
  console.log("temp_data data_length", message.payload.data_length);
  console.log("temp_data data_hash", message.payload.data_hash);

  const { unit, error } = await poster.sendMulti({
    messages: [message],
  });
  if (error) {
    throw new Error("sendMulti failed: " + error);
  }
  console.log("posted unit", unit);
  console.log("waiting until stable on local main chain...");
  await network.witnessUntilStable(unit);

  const { unitObj, error: infoErr } = await genesis.getUnitInfo({ unit });
  if (infoErr) {
    throw new Error("getUnitInfo failed: " + infoErr);
  }
  const temp = (unitObj.messages || []).find((m) => m.app === "temp_data");
  const mci = unitObj.main_chain_index;
  console.log("stable unit", unit);
  console.log("main_chain_index (MCI)", mci);
  console.log("parent_units", unitObj.parent_units);
  console.log("temp_data app present", !!temp);
  if (temp) {
    console.log("on-chain data_hash", temp.payload.data_hash);
    console.log("on-chain data_length", temp.payload.data_length);
    console.log("on-chain data.chain_id", temp.payload.data && temp.payload.data.chain_id);
    console.log("on-chain data.height", temp.payload.data && temp.payload.data.height);
  }
  if (mci === undefined || mci === null) {
    throw new Error("unit has no main_chain_index after witnessing");
  }
  if (!temp) {
    throw new Error("posted unit has no temp_data message");
  }
  console.log("OK: odex batch posted as temp_data and is on the local main chain");
  await network.stop();
}

main().catch((err) => {
  console.error("FAILED:", err && err.stack ? err.stack : err);
  process.exit(1);
});
