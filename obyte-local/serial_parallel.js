"use strict";

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
        throw new Error("unknown type=" + typeof v);
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

function batch(height, submitter) {
  return {
    chain_id: "odex-mvp-1",
    height,
    submitter,
    prev_state_hash: "00".repeat(32),
    state_root: "11".repeat(32),
    note: "serial-parallel race",
  };
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

async function post(wallet, height, submitter) {
  const { unit, error } = await wallet.sendMulti({
    messages: [tempDataMessage(batch(height, submitter))],
  });
  if (error) throw new Error("sendMulti " + submitter + " h=" + height + ": " + error);
  return unit;
}

async function info(node, unit) {
  const { unitObj, error } = await node.getUnitInfo({ unit });
  if (error) throw new Error("getUnitInfo: " + error);
  const temp = (unitObj.messages || []).find((m) => m.app === "temp_data");
  return {
    unit,
    mci: unitObj.main_chain_index,
    parents: unitObj.parent_units,
    height: temp && temp.payload.data && temp.payload.data.height,
    submitter: temp && temp.payload.data && temp.payload.data.submitter,
  };
}

async function main() {
  console.log("=== local DAG serial + parallel temp_data ===");
  const network = await Network.create()
    .with.wallet({ alice: 1e9 })
    .with.wallet({ bob: 1e9 })
    .run();
  const genesis = await network.getGenesisNode().ready();
  const alice = network.wallet.alice;
  const bob = network.wallet.bob;
  console.log("alice", await alice.getAddress());
  console.log("bob", await bob.getAddress());

  console.log("\n--- SERIAL height 1 then 2 (alice) ---");
  const s1 = await post(alice, 1, "alice");
  await network.witnessUntilStable(s1);
  const i1 = await info(genesis, s1);
  console.log("h1", JSON.stringify(i1));

  const s2 = await post(alice, 2, "alice");
  await network.witnessUntilStable(s2);
  const i2 = await info(genesis, s2);
  console.log("h2", JSON.stringify(i2));
  if (!(i2.mci > i1.mci)) {
    throw new Error("serial MCI did not increase");
  }

  console.log("\n--- PARALLEL same height 10 (alice vs bob) ---");
  const [pAlice, pBob] = await Promise.all([
    post(alice, 10, "alice"),
    post(bob, 10, "bob"),
  ]);
  console.log("posted alice", pAlice);
  console.log("posted bob", pBob);
  await network.witnessUntilStable(pAlice);
  await network.witnessUntilStable(pBob);
  const ia = await info(genesis, pAlice);
  const ib = await info(genesis, pBob);
  console.log("alice", JSON.stringify(ia));
  console.log("bob  ", JSON.stringify(ib));

  const winner =
    ia.mci < ib.mci ? ia : ib.mci < ia.mci ? ib : ia.unit < ib.unit ? ia : ib;
  console.log(
    "winner submitter=%s unit=%s mci=%s (lowest MCI, then unit bytes)",
    winner.submitter,
    winner.unit,
    winner.mci
  );
  if (ia.mci == null || ib.mci == null) {
    throw new Error("parallel posts missing MCI");
  }
  console.log("OK: serial MCI increased; parallel both stable; winner picked");
  await network.stop();
}

main().catch((err) => {
  console.error("FAILED:", err && err.stack ? err.stack : err);
  process.exit(1);
});
