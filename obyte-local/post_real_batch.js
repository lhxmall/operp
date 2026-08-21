"use strict";

const fs = require("fs");
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
        throw new Error("unknown type");
    }
  }
  return _getLength(value);
}

function getJsonSourceString(obj) {
  const cache = new WeakMap();
  function stringify(variable) {
    if (variable === null) throw new Error("null");
    switch (typeof variable) {
      case "string":
        return JSON.stringify(variable);
      case "number":
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
            keys.map((k) => JSON.stringify(k) + ":" + stringify(variable[k])).join(",") +
            "}";
        }
        cache.set(variable, result);
        return result;
      }
      default:
        throw new Error("unknown type");
    }
  }
  return stringify(obj);
}

function getBase64Hash(obj) {
  return crypto.createHash("sha256").update(getJsonSourceString(obj), "utf8").digest("base64");
}

function tempDataMessage(data) {
  return {
    app: "temp_data",
    payload_location: "inline",
    payload: {
      data_length: getLength(data, true),
      data_hash: getBase64Hash(data),
      data,
    },
  };
}

async function post(wallet, data) {
  const { unit, error } = await wallet.sendMulti({
    messages: [tempDataMessage(data)],
  });
  if (error) throw new Error("sendMulti: " + error);
  return unit;
}

async function info(node, unit) {
  const { unitObj, error } = await node.getUnitInfo({ unit });
  if (error) throw new Error("getUnitInfo: " + error);
  const temp = (unitObj.messages || []).find((m) => m.app === "temp_data");
  const d = temp && temp.payload && temp.payload.data;
  return {
    unit,
    mci: unitObj.main_chain_index,
    height: d && d.height,
    fill_count: d && d.fill_count,
    state_root: d && d.state_root,
    chain_id: d && d.chain_id,
  };
}

async function main() {
  const batchPath = path.join(__dirname, "batch.json");
  const data = JSON.parse(fs.readFileSync(batchPath, "utf8"));
  console.log("loaded", batchPath);
  console.log("chain_id", data.chain_id, "height", data.height, "fill_count", data.fill_count);
  console.log("state_root", data.state_root);
  console.log("units", (data.unit_ids || []).length);

  const network = await Network.create()
    .with.wallet({ alice: 1e9 })
    .with.wallet({ bob: 1e9 })
    .run();
  const genesis = await network.getGenesisNode().ready();
  const alice = network.wallet.alice;
  const bob = network.wallet.bob;
  console.log("alice", await alice.getAddress());
  console.log("bob", await bob.getAddress());

  console.log("\n--- parallel post same real batch ---");
  const [uA, uB] = await Promise.all([post(alice, data), post(bob, data)]);
  console.log("alice unit", uA);
  console.log("bob unit  ", uB);
  await network.witnessUntilStable(uA);
  await network.witnessUntilStable(uB);
  const ia = await info(genesis, uA);
  const ib = await info(genesis, uB);
  console.log("alice", JSON.stringify(ia));
  console.log("bob  ", JSON.stringify(ib));

  if (ia.fill_count !== data.fill_count || ib.fill_count !== data.fill_count) {
    throw new Error("on-chain fill_count mismatch");
  }
  if (ia.state_root !== data.state_root || ib.state_root !== data.state_root) {
    throw new Error("on-chain state_root mismatch");
  }

  const winner = ia.mci < ib.mci ? ia : ib.mci < ia.mci ? ib : ia.unit < ib.unit ? ia : ib;
  const who = winner.unit === ia.unit ? "alice" : "bob";
  console.log("winner", who, "mci", winner.mci, "unit", winner.unit);
  console.log("OK: real engine batch on local main chain, first MCI wins");
  await network.stop();
}

main().catch((err) => {
  console.error("FAILED:", err && err.stack ? err.stack : err);
  process.exit(1);
});
