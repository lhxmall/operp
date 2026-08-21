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

function batch(height, submitter) {
  return {
    chain_id: "odex-mvp-1",
    height,
    submitter,
    prev_state_hash: "00".repeat(32),
    state_root: "11".repeat(32),
    note: "crowd + 5m OP",
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

async function confirm(network, unit, label) {
  const wall0 = Date.now();
  const travel = await network.timetravel({ shift: "5m" });
  await network.witnessUntilStable(unit);
  console.log(
    label,
    "unit=" + unit,
    "op_shift=5m",
    "chain_ts=" + (travel && travel.timestamp),
    "wall_ms=" + (Date.now() - wall0)
  );
}

async function info(node, unit) {
  const { unitObj, error } = await node.getUnitInfo({ unit });
  if (error) throw new Error("getUnitInfo: " + error);
  const temp = (unitObj.messages || []).find((m) => m.app === "temp_data");
  return {
    unit,
    mci: unitObj.main_chain_index,
    ts: unitObj.timestamp,
    height: temp && temp.payload.data && temp.payload.data.height,
    submitter: temp && temp.payload.data && temp.payload.data.submitter,
  };
}

async function main() {
  console.log("=== crowd mainnet: 4 posters, OP +5m per confirm ===");
  const network = await Network.create()
    .with.wallet({ alice: 1e9 })
    .with.wallet({ bob: 1e9 })
    .with.wallet({ carol: 1e9 })
    .with.wallet({ dave: 1e9 })
    .run();
  const genesis = await network.getGenesisNode().ready();
  const names = ["alice", "bob", "carol", "dave"];
  const wallets = {};
  for (const n of names) {
    wallets[n] = network.wallet[n];
    console.log(n, await wallets[n].getAddress());
  }

  console.log("\n--- SERIAL 4 heights, 5m OP between ---");
  const serial = [];
  for (let h = 1; h <= 4; h++) {
    const who = names[h - 1];
    const unit = await post(wallets[who], h, who);
    await confirm(network, unit, "serial h" + h + " " + who);
    const inf = await info(genesis, unit);
    console.log("  ", JSON.stringify(inf));
    serial.push(inf);
  }
  for (let i = 1; i < serial.length; i++) {
    if (!(serial[i].mci > serial[i - 1].mci)) {
      throw new Error("serial MCI not increasing");
    }
  }

  console.log("\n--- PARALLEL height 10, 4 submitters ---");
  const posted = await Promise.all(
    names.map((n) => post(wallets[n], 10, n))
  );
  posted.forEach((u, i) => console.log("posted", names[i], u));
  await network.timetravel({ shift: "5m" });
  for (const u of posted) {
    await network.witnessUntilStable(u);
  }
  const rows = [];
  for (let i = 0; i < names.length; i++) {
    const inf = await info(genesis, posted[i]);
    rows.push(inf);
    console.log("  ", JSON.stringify(inf));
  }
  rows.sort((a, b) => a.mci - b.mci || (a.unit < b.unit ? -1 : 1));
  const winner = rows[0];
  console.log(
    "winner submitter=%s mci=%s unit=%s",
    winner.submitter,
    winner.mci,
    winner.unit
  );
  console.log("OK: 4-party serial + parallel with 5m OP jumps");
  await network.stop();
}

main().catch((err) => {
  console.error("FAILED:", err && err.stack ? err.stack : err);
  process.exit(1);
});
