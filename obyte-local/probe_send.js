"use strict";
/* minimal: boot network, one sendMulti with temp_data, print result or hang-diagnose */
const path = require("path");
const aaRoot = path.join(__dirname, "..", "vendor", "aa-testkit");
const nm = path.join(aaRoot, "node_modules");
process.env.NODE_PATH = [nm, process.env.NODE_PATH].filter(Boolean).join(path.delimiter);
process.env.devnet = "1";
const { Testkit } = require(path.join(aaRoot, "main.js"));
const { Network } = Testkit({
  TESTDATA_DIR: path.join(__dirname, "testdata-probe"),
  NETWORK_PORT: 16619,
});

setTimeout(() => { console.log("TIMEOUT: sendMulti never resolved in 120s"); process.exit(2); }, 120000).unref();

(async () => {
  const network = await Network.create()
    .with.wallet({ t: 1e9 })
    .run();
  console.log("network up");
  const w = network.wallet.t;
  // if batch.json exists, post the COMPACT summary (what provider posts)
  const fs = require("fs");
  const bf = path.join(__dirname, "stress-out/batch.json");
  let data;
  if (fs.existsSync(bf)) {
    const full = JSON.parse(fs.readFileSync(bf, "utf8"));
    data = { chain_id: full.chain_id, height: full.height, prev_state_hash: full.prev_state_hash, state_root: full.state_root, last_unit: full.last_unit, seq: full.seq, fill_count: full.fill_count, fills_hash: full.fills_hash, unit_ids: full.unit_ids };
  } else {
    data = { probe: 1, t: Date.now() };
  }
  console.log("payload bytes:", JSON.stringify(data).length);
  // proper obyte object rules (same as post_real_batch.js)
  function getLength(value) {
    const cache = new WeakMap();
    function _len(v) {
      if (v === null) return 0;
      switch (typeof v) {
        case "string": return v.length;
        case "number": return 8;
        case "boolean": return 1;
        case "object": {
          if (cache.has(v)) return cache.get(v);
          let n = 0;
          if (Array.isArray(v)) for (const el of v) n += _len(el);
          else for (const k of Object.keys(v)) { n += k.length; n += _len(v[k]); }
          cache.set(v, n);
          return n;
        }
        default: throw new Error("bad type");
      }
    }
    return _len(value);
  }
  function srcString(obj) {
    const cache = new WeakMap();
    function s(v) {
      if (typeof v === "string") return JSON.stringify(v);
      if (typeof v === "number") return String(v);
      if (typeof v === "boolean") return String(v);
      if (cache.has(v)) return cache.get(v);
      let out;
      if (Array.isArray(v)) out = "[" + v.map(s).join(",") + "]";
      else out = "{" + Object.keys(v).sort().map((k) => JSON.stringify(k) + ":" + s(v[k])).join(",") + "}";
      cache.set(v, out);
      return out;
    }
    return s(obj);
  }
  const crypto = require("crypto");
  const msg = {
    app: "temp_data",
    payload_location: "inline",
    payload: {
      data_length: getLength(data),
      data_hash: crypto.createHash("sha256").update(srcString(data), "utf8").digest("base64"),
      data,
    },
  };
  const r = await w.sendMulti({ messages: [msg] });
  console.log("RESULT:", JSON.stringify(r));
  await network.stop();
  process.exit(0);
})().catch((e) => { console.error("CAUGHT:", e.message); process.exit(1); });
